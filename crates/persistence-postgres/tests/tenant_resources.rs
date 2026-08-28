use chrono::{Duration, Utc};
use diesel::{QueryResult, QueryableByName, sql_query, sql_types};
use diesel_async::{AsyncConnection as _, AsyncPgConnection, RunQueryDsl as _};
use nazo_identity::{TenantId, ports::RepositoryError};
use nazo_postgres::{
    NewStoredOpenid4vcTrustPolicy, NewTenantResourceBinding, Openid4vcTrustPolicyClientBind,
    Openid4vcTrustPolicyForClient, Openid4vcTrustPolicyRevoke, Openid4vcTrustPolicyWrite,
    OperatorManagedTrustAnchor, TenantResourceBinding, TenantResourceBindingDeactivate,
    TenantResourceRepository, create_pool, delete_operator_managed_dataset_on_connection, get_conn,
    insert_operator_managed_trust_anchor_on_connection, protect_dataset_claims,
    revoke_operator_managed_trust_anchor_on_connection, run_pending_migrations,
    unprotect_dataset_claims, upsert_operator_managed_dataset_on_connection,
};
use serde_json::json;
use uuid::Uuid;

#[derive(Debug)]
enum TestTransactionError {
    Diesel(diesel::result::Error),
    Repository(RepositoryError),
    Assertion(String),
    Rollback,
}

impl From<diesel::result::Error> for TestTransactionError {
    fn from(error: diesel::result::Error) -> Self {
        Self::Diesel(error)
    }
}

impl From<RepositoryError> for TestTransactionError {
    fn from(error: RepositoryError) -> Self {
        Self::Repository(error)
    }
}

impl std::fmt::Display for TestTransactionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Diesel(error) => write!(formatter, "database error: {error}"),
            Self::Repository(error) => write!(formatter, "repository error: {error}"),
            Self::Assertion(message) => formatter.write_str(message),
            Self::Rollback => formatter.write_str("intentional rollback"),
        }
    }
}

impl std::error::Error for TestTransactionError {}

fn database_url() -> String {
    std::env::var("NAZO_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .expect("tenant-resource persistence tests require NAZO_TEST_DATABASE_URL or DATABASE_URL")
}

async fn insert_tenant(connection: &mut AsyncPgConnection, tenant_id: Uuid) -> QueryResult<()> {
    sql_query(
        "INSERT INTO tenants (id, slug, display_name, status)
         VALUES ($1, $2, 'tenant resource test', 'active')",
    )
    .bind::<sql_types::Uuid, _>(tenant_id)
    .bind::<sql_types::Varchar, _>(format!("tenant-resource-{}", tenant_id.simple()))
    .execute(connection)
    .await
    .map(|_| ())
}

async fn upsert_binding_in_transaction(
    connection: &mut AsyncPgConnection,
    tenant_id: Uuid,
    resource_kind: &str,
    resource_id: &str,
    resource_digest: &str,
    locator: &str,
) -> Result<TenantResourceBinding, TestTransactionError> {
    connection
        .transaction::<_, TestTransactionError, _>(async move |connection| {
            Ok(TenantResourceRepository::upsert_binding_on_connection(
                connection,
                NewTenantResourceBinding {
                    tenant_id,
                    resource_kind,
                    resource_id,
                    resource_digest,
                    active: true,
                    locator,
                },
            )
            .await?)
        })
        .await
}

async fn deactivate_binding_in_transaction(
    connection: &mut AsyncPgConnection,
    tenant_id: Uuid,
    resource_kind: &str,
    resource_id: &str,
    expected_digest: &str,
) -> Result<TenantResourceBindingDeactivate, TestTransactionError> {
    connection
        .transaction::<_, TestTransactionError, _>(async move |connection| {
            Ok(TenantResourceRepository::deactivate_binding_on_connection(
                connection,
                tenant_id,
                resource_kind,
                resource_id,
                expected_digest,
            )
            .await?)
        })
        .await
}

#[derive(QueryableByName)]
struct DatasetProbe {
    #[diesel(sql_type = sql_types::Binary)]
    claims_ciphertext: Vec<u8>,
    #[diesel(sql_type = sql_types::Text)]
    source: String,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn operator_managed_mtls_and_dataset_helpers_preserve_provenance_and_idempotency() {
    let database_url = database_url();
    run_pending_migrations(&database_url)
        .await
        .expect("pending migrations should apply");
    let pool = create_pool(&database_url, 2).expect("test pool should build");
    let tenant_uuid = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
    let realm_id = Uuid::parse_str("00000000-0000-0000-0000-000000000002").unwrap();
    let organization_id = Uuid::parse_str("00000000-0000-0000-0000-000000000003").unwrap();
    let tenant_id = TenantId::new(tenant_uuid).unwrap();
    let user_id = Uuid::now_v7();
    let client_id = Uuid::now_v7();
    let suffix = Uuid::now_v7().simple().to_string();
    let mut connection = get_conn(&pool)
        .await
        .expect("test connection should acquire");
    sql_query(
        "INSERT INTO users
            (id, tenant_id, realm_id, organization_id, username, email, password_hash)
         VALUES ($1, $2, $3, $4, $5, $6, 'test-only')",
    )
    .bind::<sql_types::Uuid, _>(user_id)
    .bind::<sql_types::Uuid, _>(tenant_uuid)
    .bind::<sql_types::Uuid, _>(realm_id)
    .bind::<sql_types::Uuid, _>(organization_id)
    .bind::<sql_types::Varchar, _>(format!("operator-resource-{suffix}"))
    .bind::<sql_types::Varchar, _>(format!("operator-resource-{suffix}@example.test"))
    .execute(&mut connection)
    .await
    .expect("operator resource subject should insert");
    sql_query(
        "INSERT INTO oauth_clients
            (id, tenant_id, realm_id, organization_id, client_id, client_name,
             client_type, redirect_uris, scopes, grant_types,
             token_endpoint_auth_method, require_mtls_bound_tokens, security_policy)
         VALUES ($1, $2, $3, $4, $5, 'operator resource client', 'confidential',
                 '[]'::JSONB, '[\"openid\"]'::JSONB,
                 '[\"authorization_code\"]'::JSONB, 'private_key_jwt', TRUE, $6)",
    )
    .bind::<sql_types::Uuid, _>(client_id)
    .bind::<sql_types::Uuid, _>(tenant_uuid)
    .bind::<sql_types::Uuid, _>(realm_id)
    .bind::<sql_types::Uuid, _>(organization_id)
    .bind::<sql_types::Varchar, _>(format!("operator-resource-{suffix}"))
    .bind::<sql_types::Jsonb, _>(
        serde_json::to_value(nazo_auth::ClientSecurityPolicy::default())
            .expect("current client security policy should serialize"),
    )
    .execute(&mut connection)
    .await
    .expect("operator resource client should insert");

    let certificate_pem = "-----BEGIN CERTIFICATE-----\ncHVibGlj\n-----END CERTIFICATE-----\n";
    let certificate_sha256 = "a".repeat(64);
    let now = Utc::now();
    let request_id = insert_operator_managed_trust_anchor_on_connection(
        &mut connection,
        OperatorManagedTrustAnchor {
            tenant_id,
            client_id,
            certificate_pem,
            certificate_sha256: &certificate_sha256,
            subject_dn: "CN=operator-managed",
            not_before: now - Duration::minutes(1),
            not_after: now + Duration::hours(1),
        },
    )
    .await
    .expect("operator-managed anchor should insert");
    assert!(
        insert_operator_managed_trust_anchor_on_connection(
            &mut connection,
            OperatorManagedTrustAnchor {
                tenant_id,
                client_id,
                certificate_pem,
                certificate_sha256: &certificate_sha256,
                subject_dn: "CN=operator-managed",
                not_before: now - Duration::minutes(1),
                not_after: now + Duration::hours(1),
            },
        )
        .await
        .is_err(),
        "a duplicate operator anchor must not create a second generation"
    );
    assert!(
        insert_operator_managed_trust_anchor_on_connection(
            &mut connection,
            OperatorManagedTrustAnchor {
                tenant_id,
                client_id,
                certificate_pem: "not-a-certificate",
                certificate_sha256: &certificate_sha256,
                subject_dn: "CN=invalid",
                not_before: now,
                not_after: now + Duration::hours(1),
            },
        )
        .await
        .is_err()
    );
    assert!(
        revoke_operator_managed_trust_anchor_on_connection(&mut connection, tenant_id, request_id,)
            .await
            .expect("operator anchor should revoke")
    );
    assert!(
        !revoke_operator_managed_trust_anchor_on_connection(
            &mut connection,
            tenant_id,
            request_id,
        )
        .await
        .expect("operator anchor revoke replay should be idempotent")
    );

    let data_key = rand::random::<[u8; 32]>();
    let configuration_id = "operator-credential";
    let claims = json!({"given_name": "Nazo", "generation": 1});
    let protected =
        protect_dataset_claims(&data_key, tenant_uuid, user_id, configuration_id, &claims)
            .expect("dataset claims should encrypt");
    assert_eq!(
        upsert_operator_managed_dataset_on_connection(
            &mut connection,
            tenant_uuid,
            user_id,
            configuration_id,
            protected,
            Some(now),
            Some(now + Duration::hours(1)),
        )
        .await
        .expect("operator dataset should insert"),
        1
    );
    let probe = sql_query(
        "SELECT claims_ciphertext, source
         FROM openid4vci_credential_datasets
         WHERE tenant_id = $1 AND subject_id = $2
           AND credential_configuration_id = $3",
    )
    .bind::<sql_types::Uuid, _>(tenant_uuid)
    .bind::<sql_types::Uuid, _>(user_id)
    .bind::<sql_types::Text, _>(configuration_id)
    .get_result::<DatasetProbe>(&mut connection)
    .await
    .expect("operator dataset should be readable");
    assert_eq!(probe.source, "operator-managed");
    assert_eq!(
        unprotect_dataset_claims(
            &data_key,
            tenant_uuid,
            user_id,
            configuration_id,
            &probe.claims_ciphertext,
        )
        .expect("operator dataset should decrypt"),
        claims
    );
    let updated_claims = json!({"given_name": "Nazo", "generation": 2});
    let updated = protect_dataset_claims(
        &data_key,
        tenant_uuid,
        user_id,
        configuration_id,
        &updated_claims,
    )
    .expect("updated dataset claims should encrypt");
    assert_eq!(
        upsert_operator_managed_dataset_on_connection(
            &mut connection,
            tenant_uuid,
            user_id,
            configuration_id,
            updated,
            None,
            None,
        )
        .await
        .expect("operator dataset should update"),
        1
    );
    assert!(
        delete_operator_managed_dataset_on_connection(
            &mut connection,
            tenant_uuid,
            user_id,
            configuration_id,
        )
        .await
        .expect("operator dataset should delete")
    );
    assert!(
        !delete_operator_managed_dataset_on_connection(
            &mut connection,
            tenant_uuid,
            user_id,
            configuration_id,
        )
        .await
        .expect("operator dataset delete replay should be idempotent")
    );

    sql_query(
        "DELETE FROM openid4vci_credential_dataset_events WHERE tenant_id = $1 AND subject_id = $2",
    )
    .bind::<sql_types::Uuid, _>(tenant_uuid)
    .bind::<sql_types::Uuid, _>(user_id)
    .execute(&mut connection)
    .await
    .expect("dataset events should clean up");
    sql_query("DELETE FROM oauth_client_mtls_trust_anchor_events WHERE tenant_id = $1 AND request_id = $2")
        .bind::<sql_types::Uuid, _>(tenant_uuid)
        .bind::<sql_types::Uuid, _>(request_id)
        .execute(&mut connection)
        .await
        .expect("mTLS events should clean up");
    sql_query(
        "DELETE FROM oauth_client_mtls_trust_anchor_requests WHERE tenant_id = $1 AND id = $2",
    )
    .bind::<sql_types::Uuid, _>(tenant_uuid)
    .bind::<sql_types::Uuid, _>(request_id)
    .execute(&mut connection)
    .await
    .expect("mTLS request should clean up");
    sql_query("DELETE FROM oauth_clients WHERE tenant_id = $1 AND id = $2")
        .bind::<sql_types::Uuid, _>(tenant_uuid)
        .bind::<sql_types::Uuid, _>(client_id)
        .execute(&mut connection)
        .await
        .expect("operator client should clean up");
    sql_query("DELETE FROM users WHERE tenant_id = $1 AND id = $2")
        .bind::<sql_types::Uuid, _>(tenant_uuid)
        .bind::<sql_types::Uuid, _>(user_id)
        .execute(&mut connection)
        .await
        .expect("operator subject should clean up");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn inactive_tenant_resource_binding_is_replaced_in_place_and_reactivation_is_serialized() {
    let database_url = database_url();
    run_pending_migrations(&database_url)
        .await
        .expect("pending migrations should apply");
    let pool = create_pool(&database_url, 4).expect("test pool should build");
    let tenant_id = Uuid::now_v7();
    let resource_kind = "user";
    let resource_id = format!("replacement-{}", Uuid::now_v7().simple());
    let first_digest = "1".repeat(64);
    let second_digest = "2".repeat(64);
    let third_digest = "3".repeat(64);
    let fourth_digest = "4".repeat(64);
    let mut connection = get_conn(&pool)
        .await
        .expect("test connection should acquire");
    insert_tenant(&mut connection, tenant_id)
        .await
        .expect("tenant should insert");

    let inserted = upsert_binding_in_transaction(
        &mut connection,
        tenant_id,
        resource_kind,
        &resource_id,
        &first_digest,
        "user:first",
    )
    .await
    .expect("first binding should insert");
    let replayed = upsert_binding_in_transaction(
        &mut connection,
        tenant_id,
        resource_kind,
        &resource_id,
        &first_digest,
        "user:first",
    )
    .await
    .expect("identical active binding should replay");
    assert_eq!(replayed, inserted);

    let active_conflict = upsert_binding_in_transaction(
        &mut connection,
        tenant_id,
        resource_kind,
        &resource_id,
        &second_digest,
        "user:second",
    )
    .await;
    assert!(matches!(
        active_conflict,
        Err(TestTransactionError::Repository(RepositoryError::Conflict))
    ));

    let deactivated = deactivate_binding_in_transaction(
        &mut connection,
        tenant_id,
        resource_kind,
        &resource_id,
        &first_digest,
    )
    .await
    .expect("first binding should deactivate");
    assert!(matches!(
        deactivated,
        TenantResourceBindingDeactivate::Deactivated(_)
    ));
    let same_digest_reapplied = upsert_binding_in_transaction(
        &mut connection,
        tenant_id,
        resource_kind,
        &resource_id,
        &first_digest,
        "user:first-replacement",
    )
    .await
    .expect("inactive binding should reactivate with a replacement locator");
    assert_eq!(same_digest_reapplied.id, inserted.id);
    assert_eq!(same_digest_reapplied.created_at, inserted.created_at);
    assert_eq!(same_digest_reapplied.resource_digest, first_digest);
    assert_eq!(same_digest_reapplied.locator, "user:first-replacement");
    assert!(same_digest_reapplied.active);

    deactivate_binding_in_transaction(
        &mut connection,
        tenant_id,
        resource_kind,
        &resource_id,
        &first_digest,
    )
    .await
    .expect("same-digest replacement should deactivate");
    let new_digest_reapplied = upsert_binding_in_transaction(
        &mut connection,
        tenant_id,
        resource_kind,
        &resource_id,
        &second_digest,
        "user:second",
    )
    .await
    .expect("inactive binding should accept a new digest");
    assert_eq!(new_digest_reapplied.id, inserted.id);
    assert_eq!(new_digest_reapplied.created_at, inserted.created_at);
    assert_eq!(new_digest_reapplied.resource_digest, second_digest);
    assert_eq!(new_digest_reapplied.locator, "user:second");
    assert!(new_digest_reapplied.active);

    deactivate_binding_in_transaction(
        &mut connection,
        tenant_id,
        resource_kind,
        &resource_id,
        &second_digest,
    )
    .await
    .expect("new-digest replacement should deactivate");

    let reapply = |pool, resource_id: String, digest: String, locator: &'static str| async move {
        let mut connection = get_conn(&pool)
            .await
            .expect("concurrent test connection should acquire");
        upsert_binding_in_transaction(
            &mut connection,
            tenant_id,
            resource_kind,
            &resource_id,
            &digest,
            locator,
        )
        .await
    };
    let (third, fourth) = tokio::join!(
        reapply(
            pool.clone(),
            resource_id.clone(),
            third_digest.clone(),
            "user:third"
        ),
        reapply(
            pool.clone(),
            resource_id.clone(),
            fourth_digest.clone(),
            "user:fourth"
        )
    );
    let winner = match (third, fourth) {
        (Ok(winner), Err(TestTransactionError::Repository(RepositoryError::Conflict)))
        | (Err(TestTransactionError::Repository(RepositoryError::Conflict)), Ok(winner)) => winner,
        outcomes => panic!("exactly one concurrent replacement must win: {outcomes:?}"),
    };
    assert_eq!(winner.id, inserted.id);
    assert!(winner.active);
    let active =
        TenantResourceRepository::active_bindings_on_connection(&mut connection, tenant_id)
            .await
            .expect("active bindings should load");
    assert_eq!(active, vec![winner]);

    sql_query("DELETE FROM tenant_resource_bindings WHERE tenant_id = $1")
        .bind::<sql_types::Uuid, _>(tenant_id)
        .execute(&mut connection)
        .await
        .expect("binding should clean up");
    sql_query("DELETE FROM tenants WHERE id = $1")
        .bind::<sql_types::Uuid, _>(tenant_id)
        .execute(&mut connection)
        .await
        .expect("tenant should clean up");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn openid4vc_trust_policy_is_tenant_scoped_digest_fenced_and_transactional() {
    let database_url = database_url();
    run_pending_migrations(&database_url)
        .await
        .expect("pending migrations should apply");
    let pool = create_pool(&database_url, 2).expect("test pool should build");
    let tenant_id = Uuid::now_v7();
    let other_tenant_id = Uuid::now_v7();
    let mut connection = get_conn(&pool)
        .await
        .expect("test connection should acquire");
    insert_tenant(&mut connection, tenant_id)
        .await
        .expect("tenant should insert");
    insert_tenant(&mut connection, other_tenant_id)
        .await
        .expect("other tenant should insert");
    let realm_id = Uuid::now_v7();
    let organization_id = Uuid::now_v7();
    let oauth_client_id = Uuid::now_v7();
    let public_client_id = format!("trust-client-{}", oauth_client_id.simple());
    sql_query(
        "INSERT INTO realms (id, tenant_id, slug, display_name)
         VALUES ($1, $2, $3, 'tenant resource trust realm')",
    )
    .bind::<sql_types::Uuid, _>(realm_id)
    .bind::<sql_types::Uuid, _>(tenant_id)
    .bind::<sql_types::Varchar, _>(format!("trust-realm-{}", realm_id.simple()))
    .execute(&mut connection)
    .await
    .expect("trust realm should insert");
    sql_query(
        "INSERT INTO organizations (id, tenant_id, slug, display_name)
         VALUES ($1, $2, $3, 'tenant resource trust organization')",
    )
    .bind::<sql_types::Uuid, _>(organization_id)
    .bind::<sql_types::Uuid, _>(tenant_id)
    .bind::<sql_types::Varchar, _>(format!("trust-org-{}", organization_id.simple()))
    .execute(&mut connection)
    .await
    .expect("trust organization should insert");
    sql_query(
        "INSERT INTO oauth_clients
            (id, tenant_id, realm_id, organization_id, client_id, client_name,
             client_type, redirect_uris, scopes, grant_types,
             token_endpoint_auth_method, security_policy)
         VALUES ($1, $2, $3, $4, $5, 'trust policy client', 'public',
                 '[]'::JSONB, '[\"openid\"]'::JSONB,
                 '[\"authorization_code\"]'::JSONB, 'none', $6)",
    )
    .bind::<sql_types::Uuid, _>(oauth_client_id)
    .bind::<sql_types::Uuid, _>(tenant_id)
    .bind::<sql_types::Uuid, _>(realm_id)
    .bind::<sql_types::Uuid, _>(organization_id)
    .bind::<sql_types::Varchar, _>(&public_client_id)
    .bind::<sql_types::Jsonb, _>(
        serde_json::to_value(nazo_auth::ClientSecurityPolicy::default())
            .expect("current client security policy should serialize"),
    )
    .execute(&mut connection)
    .await
    .expect("trust policy client should insert");
    assert_eq!(
        TenantResourceRepository::openid4vc_trust_policy_for_client_on_connection(
            &mut connection,
            tenant_id,
            &public_client_id,
        )
        .await
        .expect("unbound trust client lookup should succeed"),
        Openid4vcTrustPolicyForClient::Unbound
    );

    let material = json!({
        "schema": 1,
        "client_attestation_issuer": "https://wallet.example/",
        "client_attestation_jwks": {"keys": [{"kty": "EC", "kid": "client"}]},
        "key_attestation_jwks": {"keys": [{"kty": "EC", "kid": "holder"}]},
        "credential_trust_anchor_pem": "-----BEGIN CERTIFICATE-----\npublic\n-----END CERTIFICATE-----\n"
    });
    let first_digest = "a".repeat(64);
    let second_digest = "b".repeat(64);
    let wallet_origins = vec!["https://wallet.example/".to_owned()];
    connection
        .transaction::<(), TestTransactionError, _>(async |connection| {
            let applied = TenantResourceRepository::apply_openid4vc_trust_policy_on_connection(
                connection,
                NewStoredOpenid4vcTrustPolicy {
                    tenant_id,
                    resource_id: "wallet-trust",
                    resource_digest: &first_digest,
                    public_material: &material,
                    wallet_origins: &wallet_origins,
                },
            )
            .await?;
            assert!(matches!(applied, Openid4vcTrustPolicyWrite::Applied(_)));

            let bound = TenantResourceRepository::bind_openid4vc_trust_policy_client_on_connection(
                connection,
                tenant_id,
                "wallet-trust",
                &first_digest,
                oauth_client_id,
            )
            .await?;
            let Openid4vcTrustPolicyClientBind::Bound { binding_id } = bound else {
                return Err(TestTransactionError::Assertion(format!(
                    "initial trust client binding returned {bound:?}"
                )));
            };
            assert!(matches!(
                TenantResourceRepository::bind_openid4vc_trust_policy_client_on_connection(
                    connection,
                    tenant_id,
                    "wallet-trust",
                    &first_digest,
                    oauth_client_id,
                )
                .await?,
                Openid4vcTrustPolicyClientBind::Replayed {
                    binding_id: replayed_id
                } if replayed_id == binding_id
            ));
            assert!(matches!(
                TenantResourceRepository::openid4vc_trust_policy_for_client_on_connection(
                    connection,
                    tenant_id,
                    &public_client_id,
                )
                .await?,
                Openid4vcTrustPolicyForClient::Active(ref policy)
                    if policy.resource_id == "wallet-trust"
                        && policy.resource_digest == first_digest
            ));

            let alternate = TenantResourceRepository::apply_openid4vc_trust_policy_on_connection(
                connection,
                NewStoredOpenid4vcTrustPolicy {
                    tenant_id,
                    resource_id: "alternate-trust",
                    resource_digest: &second_digest,
                    public_material: &material,
                    wallet_origins: &wallet_origins,
                },
            )
            .await?;
            assert!(matches!(alternate, Openid4vcTrustPolicyWrite::Applied(_)));
            assert!(matches!(
                TenantResourceRepository::bind_openid4vc_trust_policy_client_on_connection(
                    connection,
                    tenant_id,
                    "alternate-trust",
                    &second_digest,
                    oauth_client_id,
                )
                .await?,
                Openid4vcTrustPolicyClientBind::Conflict {
                    binding_id: current_id
                } if current_id == binding_id
            ));

            let replay = TenantResourceRepository::apply_openid4vc_trust_policy_on_connection(
                connection,
                NewStoredOpenid4vcTrustPolicy {
                    tenant_id,
                    resource_id: "wallet-trust",
                    resource_digest: &first_digest,
                    public_material: &material,
                    wallet_origins: &wallet_origins,
                },
            )
            .await?;
            assert!(matches!(replay, Openid4vcTrustPolicyWrite::Replayed(_)));

            let cross_tenant = TenantResourceRepository::get_openid4vc_trust_policy_on_connection(
                connection,
                other_tenant_id,
                "wallet-trust",
            )
            .await?;
            assert!(
                cross_tenant.is_none(),
                "tenant trust must not cross boundaries"
            );

            let drift = TenantResourceRepository::apply_openid4vc_trust_policy_on_connection(
                connection,
                NewStoredOpenid4vcTrustPolicy {
                    tenant_id,
                    resource_id: "wallet-trust",
                    resource_digest: &second_digest,
                    public_material: &material,
                    wallet_origins: &wallet_origins,
                },
            )
            .await?;
            match drift {
                Openid4vcTrustPolicyWrite::Conflict(current) => {
                    assert_eq!(current.resource_digest, first_digest);
                }
                other => {
                    return Err(TestTransactionError::Assertion(format!(
                        "digest drift returned {other:?}"
                    )));
                }
            }

            let stale = TenantResourceRepository::revoke_openid4vc_trust_policy_on_connection(
                connection,
                tenant_id,
                "wallet-trust",
                &second_digest,
            )
            .await?;
            assert!(matches!(stale, Openid4vcTrustPolicyRevoke::Conflict(_)));
            let revoked = TenantResourceRepository::revoke_openid4vc_trust_policy_on_connection(
                connection,
                tenant_id,
                "wallet-trust",
                &first_digest,
            )
            .await?;
            let Openid4vcTrustPolicyRevoke::Revoked(revoked) = revoked else {
                return Err(TestTransactionError::Assertion(
                    "exact trust policy revoke did not revoke".to_owned(),
                ));
            };
            assert_eq!(
                TenantResourceRepository::openid4vc_trust_policy_for_client_on_connection(
                    connection,
                    tenant_id,
                    &public_client_id,
                )
                .await?,
                Openid4vcTrustPolicyForClient::BoundInactive
            );
            assert!(
                TenantResourceRepository::get_openid4vc_trust_policy_on_connection(
                    connection,
                    tenant_id,
                    "wallet-trust",
                )
                .await?
                .is_none()
            );
            let absent = TenantResourceRepository::revoke_openid4vc_trust_policy_on_connection(
                connection,
                tenant_id,
                "wallet-trust",
                &first_digest,
            )
            .await?;
            assert_eq!(absent, Openid4vcTrustPolicyRevoke::AlreadyAbsent);
            let reapplied = TenantResourceRepository::apply_openid4vc_trust_policy_on_connection(
                connection,
                NewStoredOpenid4vcTrustPolicy {
                    tenant_id,
                    resource_id: "wallet-trust",
                    resource_digest: &first_digest,
                    public_material: &material,
                    wallet_origins: &wallet_origins,
                },
            )
            .await?;
            let Openid4vcTrustPolicyWrite::Applied(reapplied) = reapplied else {
                return Err(TestTransactionError::Assertion(
                    "revoked trust policy did not create a new generation".to_owned(),
                ));
            };
            assert_ne!(reapplied.id, revoked.id, "revoked binding IDs stay frozen");
            assert!(
                TenantResourceRepository::active_openid4vc_trust_policy_binding_on_connection(
                    connection, tenant_id, revoked.id,
                )
                .await?
                .is_none(),
                "reapply must not reactivate an old frozen binding ID"
            );
            Ok(())
        })
        .await
        .expect("trust policy transaction should commit");

    let rolled_back = connection
        .transaction::<(), TestTransactionError, _>(async |connection| {
            TenantResourceRepository::apply_openid4vc_trust_policy_on_connection(
                connection,
                NewStoredOpenid4vcTrustPolicy {
                    tenant_id,
                    resource_id: "rolled-back-trust",
                    resource_digest: &second_digest,
                    public_material: &material,
                    wallet_origins: &wallet_origins,
                },
            )
            .await?;
            Err(TestTransactionError::Rollback)
        })
        .await;
    assert!(matches!(rolled_back, Err(TestTransactionError::Rollback)));
    assert!(
        TenantResourceRepository::get_openid4vc_trust_policy_on_connection(
            &mut connection,
            tenant_id,
            "rolled-back-trust",
        )
        .await
        .expect("rolled-back policy lookup should succeed")
        .is_none()
    );

    let unknown_tenant = Uuid::now_v7();
    assert!(
        TenantResourceRepository::apply_openid4vc_trust_policy_on_connection(
            &mut connection,
            NewStoredOpenid4vcTrustPolicy {
                tenant_id: unknown_tenant,
                resource_id: "unknown-tenant",
                resource_digest: &first_digest,
                public_material: &material,
                wallet_origins: &wallet_origins,
            },
        )
        .await
        .is_err(),
        "trust policy must reference an existing tenant"
    );
    assert!(
        sql_query(
            "INSERT INTO openid4vc_trust_policies
                (tenant_id, resource_id, resource_digest, public_material,
                 wallet_origins, source)
             VALUES ($1, 'wrong-source', $2, '{}', '[\"https://wallet.example/\"]',
                     'admin-session')",
        )
        .bind::<sql_types::Uuid, _>(tenant_id)
        .bind::<sql_types::Varchar, _>(&first_digest)
        .execute(&mut connection)
        .await
        .is_err(),
        "trust policy source must remain operator-managed"
    );
    let oversized = json!({"value": "x".repeat(33 * 1024)});
    assert!(
        TenantResourceRepository::apply_openid4vc_trust_policy_on_connection(
            &mut connection,
            NewStoredOpenid4vcTrustPolicy {
                tenant_id,
                resource_id: "oversized",
                resource_digest: &first_digest,
                public_material: &oversized,
                wallet_origins: &wallet_origins,
            },
        )
        .await
        .is_err(),
        "public material must be bounded"
    );

    sql_query("DELETE FROM openid4vc_trust_policy_clients WHERE tenant_id IN ($1, $2)")
        .bind::<sql_types::Uuid, _>(tenant_id)
        .bind::<sql_types::Uuid, _>(other_tenant_id)
        .execute(&mut connection)
        .await
        .expect("trust policy client bindings should clean up");
    sql_query("DELETE FROM openid4vc_trust_policies WHERE tenant_id IN ($1, $2)")
        .bind::<sql_types::Uuid, _>(tenant_id)
        .bind::<sql_types::Uuid, _>(other_tenant_id)
        .execute(&mut connection)
        .await
        .expect("trust policy rows should clean up");
    sql_query("DELETE FROM oauth_clients WHERE id = $1")
        .bind::<sql_types::Uuid, _>(oauth_client_id)
        .execute(&mut connection)
        .await
        .expect("trust policy client should clean up");
    sql_query("DELETE FROM realms WHERE id = $1")
        .bind::<sql_types::Uuid, _>(realm_id)
        .execute(&mut connection)
        .await
        .expect("trust realm should clean up");
    sql_query("DELETE FROM organizations WHERE id = $1")
        .bind::<sql_types::Uuid, _>(organization_id)
        .execute(&mut connection)
        .await
        .expect("trust organization should clean up");
    sql_query("DELETE FROM tenants WHERE id IN ($1, $2)")
        .bind::<sql_types::Uuid, _>(tenant_id)
        .bind::<sql_types::Uuid, _>(other_tenant_id)
        .execute(&mut connection)
        .await
        .expect("test tenants should clean up");
}
