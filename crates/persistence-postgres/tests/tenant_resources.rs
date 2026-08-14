use diesel::{QueryResult, sql_query, sql_types};
use diesel_async::{
    AsyncConnection, AsyncPgConnection, RunQueryDsl as _, SimpleAsyncConnection as _,
};
use nazo_identity::ports::RepositoryError;
use nazo_postgres::{
    NewStoredOpenid4vcTrustPolicy, NewTenantResourceBinding, NewTenantResourceOperation,
    Openid4vcTrustPolicyRevoke, Openid4vcTrustPolicyWrite, TenantResourceBindingDeactivate,
    TenantResourceOperationWrite, TenantResourceRepository, TenantResourceStateCas, create_pool,
    get_conn, run_pending_migrations,
};
use serde_json::json;
use std::sync::Arc;
use tokio::sync::Barrier;
use uuid::Uuid;

const RESOURCE_UP: &str =
    include_str!("../../../migrations/20260814000100_tenant_resource_management/up.sql");
const RESOURCE_DOWN: &str =
    include_str!("../../../migrations/20260814000100_tenant_resource_management/down.sql");

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

    sql_query("DELETE FROM openid4vc_trust_policies WHERE tenant_id IN ($1, $2)")
        .bind::<sql_types::Uuid, _>(tenant_id)
        .bind::<sql_types::Uuid, _>(other_tenant_id)
        .execute(&mut connection)
        .await
        .expect("trust policy rows should clean up");
    sql_query("DELETE FROM tenants WHERE id IN ($1, $2)")
        .bind::<sql_types::Uuid, _>(tenant_id)
        .bind::<sql_types::Uuid, _>(other_tenant_id)
        .execute(&mut connection)
        .await
        .expect("test tenants should clean up");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tenant_resource_repository_guards_revision_and_jti_replay_on_one_connection() {
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
        .expect("second tenant should insert");

    let rolled_back = connection
        .transaction::<(), TestTransactionError, _>(async |connection| {
            let initial_manifest = "a".repeat(64);
            let first = TenantResourceRepository::compare_and_set_state_on_connection(
                connection,
                tenant_id,
                0,
                1,
                &initial_manifest,
            )
            .await?;
            let TenantResourceStateCas::Applied(first) = first else {
                return Err(TestTransactionError::Assertion(
                    "initial state CAS did not apply".to_owned(),
                ));
            };
            assert_eq!(first.revision, 1);

            let stale_manifest = "b".repeat(64);
            let overflow_manifest = "c".repeat(64);
            let stale = TenantResourceRepository::compare_and_set_state_on_connection(
                connection,
                tenant_id,
                0,
                1,
                &stale_manifest,
            )
            .await?;
            match stale {
                TenantResourceStateCas::Conflict(Some(state)) => {
                    assert_eq!(state.revision, 1);
                    assert_eq!(state.resource_manifest_sha256, initial_manifest.as_str());
                }
                other => {
                    return Err(TestTransactionError::Assertion(format!(
                        "stale state CAS returned {other:?}"
                    )));
                }
            }

            let skipped = TenantResourceRepository::compare_and_set_state_on_connection(
                connection,
                tenant_id,
                1,
                3,
                &stale_manifest,
            )
            .await;
            assert!(matches!(
                skipped,
                Err(nazo_identity::ports::RepositoryError::Consistency(message))
                    if message.contains("exactly one")
            ));
            let backwards = TenantResourceRepository::compare_and_set_state_on_connection(
                connection,
                tenant_id,
                1,
                1,
                &stale_manifest,
            )
            .await;
            assert!(matches!(
                backwards,
                Err(nazo_identity::ports::RepositoryError::Consistency(message))
                    if message.contains("exactly one")
            ));

            let overflow = TenantResourceRepository::compare_and_set_state_on_connection(
                connection,
                tenant_id,
                u64::MAX,
                u64::MAX,
                &overflow_manifest,
            )
            .await;
            assert!(matches!(
                overflow,
                Err(nazo_identity::ports::RepositoryError::Consistency(message))
                    if message.contains("u64::MAX")
            ));
            let bigint_overflow = TenantResourceRepository::compare_and_set_state_on_connection(
                connection,
                tenant_id,
                i64::MAX as u64,
                (i64::MAX as u64) + 1,
                &overflow_manifest,
            )
            .await;
            assert!(matches!(
                bigint_overflow,
                Err(nazo_identity::ports::RepositoryError::Consistency(message))
                    if message.contains("BIGINT")
            ));

            let receipt = json!({"status":"succeeded","revision":2});
            let request_digest = "d".repeat(64);
            let change_set_digest = "1".repeat(64);
            let operation = NewTenantResourceOperation {
                deployment_id: "deployment-a",
                tenant_id,
                jti: "jti-1",
                change_set_id: "change-set-1",
                change_set_sha256: &change_set_digest,
                request_sha256: &request_digest,
                operation: "apply",
                expected_revision: 1,
                result_revision: 2,
                receipt_json: &receipt,
                receipt_jws: "signed-receipt-a",
            };
            let inserted =
                TenantResourceRepository::record_operation_on_connection(connection, operation)
                    .await?;
            assert!(matches!(
                inserted,
                TenantResourceOperationWrite::Inserted(_)
            ));

            let replay_receipt = json!({"status":"succeeded","revision":999});
            let replay = TenantResourceRepository::record_operation_on_connection(
                connection,
                NewTenantResourceOperation {
                    deployment_id: "deployment-a",
                    tenant_id,
                    jti: "jti-1",
                    change_set_id: "change-set-1",
                    change_set_sha256: &change_set_digest,
                    request_sha256: &request_digest,
                    operation: "apply",
                    expected_revision: 1,
                    result_revision: 2,
                    receipt_json: &replay_receipt,
                    receipt_jws: "must-not-replace",
                },
            )
            .await?;
            match replay {
                TenantResourceOperationWrite::Replayed(record) => {
                    assert_eq!(record.receipt_jws, "signed-receipt-a");
                    assert_eq!(record.receipt_json, receipt);
                }
                other => {
                    return Err(TestTransactionError::Assertion(format!(
                        "same-digest replay returned {other:?}"
                    )));
                }
            }

            let conflict_digest = "e".repeat(64);
            let conflict_receipt = json!({"status":"failed"});
            let conflict = TenantResourceRepository::record_operation_on_connection(
                connection,
                NewTenantResourceOperation {
                    deployment_id: "deployment-a",
                    tenant_id,
                    jti: "jti-1",
                    change_set_id: "change-set-1",
                    change_set_sha256: &change_set_digest,
                    request_sha256: &conflict_digest,
                    operation: "revoke",
                    expected_revision: 1,
                    result_revision: 2,
                    receipt_json: &conflict_receipt,
                    receipt_jws: "must-not-replace",
                },
            )
            .await?;
            assert!(matches!(
                conflict,
                TenantResourceOperationWrite::Conflict(_)
            ));
            let change_set_reuse = TenantResourceRepository::record_operation_on_connection(
                connection,
                NewTenantResourceOperation {
                    deployment_id: "deployment-a",
                    tenant_id,
                    jti: "jti-2",
                    change_set_id: "change-set-1",
                    change_set_sha256: &change_set_digest,
                    request_sha256: &request_digest,
                    operation: "apply",
                    expected_revision: 1,
                    result_revision: 2,
                    receipt_json: &receipt,
                    receipt_jws: "must-not-reuse-change-set",
                },
            )
            .await?;
            assert!(matches!(
                change_set_reuse,
                TenantResourceOperationWrite::Conflict(_)
            ));

            let cross_tenant_receipt = json!({"status":"succeeded"});
            let cross_tenant = TenantResourceRepository::record_operation_on_connection(
                connection,
                NewTenantResourceOperation {
                    deployment_id: "deployment-a",
                    tenant_id: other_tenant_id,
                    jti: "jti-1",
                    change_set_id: "change-set-cross",
                    change_set_sha256: &change_set_digest,
                    request_sha256: &request_digest,
                    operation: "enumerate",
                    expected_revision: 0,
                    result_revision: 0,
                    receipt_json: &cross_tenant_receipt,
                    receipt_jws: "signed-receipt-b",
                },
            )
            .await?;
            assert!(matches!(
                cross_tenant,
                TenantResourceOperationWrite::Inserted(_)
            ));

            let binding_digest = "f".repeat(64);
            let binding = TenantResourceRepository::upsert_binding_on_connection(
                connection,
                NewTenantResourceBinding {
                    tenant_id,
                    resource_kind: "oauth-client",
                    resource_id: "client-a",
                    resource_digest: &binding_digest,
                    change_set_id: "change-set-1",
                    change_set_sha256: &change_set_digest,
                    active: true,
                    locator: "oauth-client/client-a",
                },
            )
            .await?;
            assert!(binding.active);
            assert_eq!(binding.resource_id, "client-a");
            let same_binding = TenantResourceRepository::upsert_binding_on_connection(
                connection,
                NewTenantResourceBinding {
                    tenant_id,
                    resource_kind: "oauth-client",
                    resource_id: "client-a",
                    resource_digest: &binding_digest,
                    change_set_id: "change-set-1",
                    change_set_sha256: &change_set_digest,
                    active: true,
                    locator: "oauth-client/client-a",
                },
            )
            .await?;
            assert_eq!(same_binding.id, binding.id);
            let drifted_binding = TenantResourceRepository::upsert_binding_on_connection(
                connection,
                NewTenantResourceBinding {
                    tenant_id,
                    resource_kind: "oauth-client",
                    resource_id: "client-a",
                    resource_digest: &conflict_digest,
                    change_set_id: "change-set-1",
                    change_set_sha256: &change_set_digest,
                    active: true,
                    locator: "oauth-client/client-a-drifted",
                },
            )
            .await;
            assert!(matches!(
                drifted_binding,
                Err(nazo_identity::ports::RepositoryError::Conflict)
            ));
            let active =
                TenantResourceRepository::active_bindings_on_connection(connection, tenant_id)
                    .await?;
            assert_eq!(active.len(), 1);
            let stale_digest = "0".repeat(64);
            let stale_revoke = TenantResourceRepository::deactivate_binding_on_connection(
                connection,
                tenant_id,
                "oauth-client",
                "client-a",
                &stale_digest,
            )
            .await?;
            match stale_revoke {
                TenantResourceBindingDeactivate::Conflict(Some(binding)) => {
                    assert!(binding.active);
                    assert_eq!(binding.resource_digest, binding_digest);
                }
                other => {
                    return Err(TestTransactionError::Assertion(format!(
                        "stale binding revoke returned {other:?}"
                    )));
                }
            }
            let deactivated = TenantResourceRepository::deactivate_binding_on_connection(
                connection,
                tenant_id,
                "oauth-client",
                "client-a",
                &binding_digest,
            )
            .await?;
            match deactivated {
                TenantResourceBindingDeactivate::Deactivated(binding) => {
                    assert!(!binding.active);
                }
                other => {
                    return Err(TestTransactionError::Assertion(format!(
                        "binding revoke returned {other:?}"
                    )));
                }
            }
            Err(TestTransactionError::Rollback)
        })
        .await;
    assert!(matches!(rolled_back, Err(TestTransactionError::Rollback)));
    sql_query("DELETE FROM tenants WHERE id IN ($1, $2)")
        .bind::<sql_types::Uuid, _>(tenant_id)
        .bind::<sql_types::Uuid, _>(other_tenant_id)
        .execute(&mut connection)
        .await
        .expect("test tenants should clean up after resource evidence");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tenant_resource_operation_lock_serializes_same_jti() {
    let database_url = database_url();
    run_pending_migrations(&database_url)
        .await
        .expect("pending migrations should apply");
    let pool = create_pool(&database_url, 2).expect("test pool should build");
    let repository = TenantResourceRepository::new(pool.clone());
    let schema = format!("tenant_resource_lock_{}", Uuid::now_v7().simple());
    let tenant_id = Uuid::now_v7();
    let mut setup = get_conn(&pool)
        .await
        .expect("test connection should acquire");
    setup
        .batch_execute(&format!(
            r#"CREATE SCHEMA "{schema}";
               CREATE TABLE "{schema}".tenant_resource_operations
                   (LIKE public.tenant_resource_operations INCLUDING ALL);"#
        ))
        .await
        .expect("isolated operation table should create");
    insert_tenant(&mut setup, tenant_id)
        .await
        .expect("tenant should insert");
    drop(setup);

    async fn attempt(
        repository: TenantResourceRepository,
        barrier: Arc<Barrier>,
        schema: String,
        tenant_id: Uuid,
    ) -> Result<TenantResourceOperationWrite, TestTransactionError> {
        let mut connection = repository
            .connection()
            .await
            .map_err(TestTransactionError::from)?;
        connection
            .batch_execute(&format!(r#"SET search_path TO "{schema}", public"#))
            .await
            .map_err(TestTransactionError::from)?;
        barrier.wait().await;
        let result = connection
            .transaction::<TenantResourceOperationWrite, TestTransactionError, _>(
                async |connection| {
                    TenantResourceRepository::lock_operation_identity_on_connection(
                        connection,
                        "deployment-concurrent",
                        tenant_id,
                        "jti-concurrent",
                        "change-set-concurrent",
                    )
                    .await?;
                    let receipt = json!({"status":"succeeded"});
                    let request_digest = "a".repeat(64);
                    TenantResourceRepository::record_operation_on_connection(
                        connection,
                        NewTenantResourceOperation {
                            deployment_id: "deployment-concurrent",
                            tenant_id,
                            jti: "jti-concurrent",
                            change_set_id: "change-set-concurrent",
                            change_set_sha256: &request_digest,
                            request_sha256: &request_digest,
                            operation: "apply",
                            expected_revision: 0,
                            result_revision: 1,
                            receipt_json: &receipt,
                            receipt_jws: "concurrent-receipt",
                        },
                    )
                    .await
                    .map_err(TestTransactionError::from)
                },
            )
            .await;
        connection
            .batch_execute("SET search_path TO public")
            .await
            .map_err(TestTransactionError::from)?;
        result
    }

    let barrier = Arc::new(Barrier::new(2));
    let (left, right) = tokio::join!(
        attempt(
            repository.clone(),
            barrier.clone(),
            schema.clone(),
            tenant_id
        ),
        attempt(repository, barrier, schema.clone(), tenant_id),
    );
    let writes = [
        left.expect("first concurrent transaction should commit"),
        right.expect("second concurrent transaction should commit"),
    ];
    assert_eq!(
        writes
            .iter()
            .filter(|write| matches!(write, TenantResourceOperationWrite::Inserted(_)))
            .count(),
        1,
        "same JTI must have one insertion"
    );
    assert_eq!(
        writes
            .iter()
            .filter(|write| matches!(write, TenantResourceOperationWrite::Replayed(_)))
            .count(),
        1,
        "same digest must replay the committed receipt"
    );

    let mut connection = get_conn(&pool)
        .await
        .expect("test connection should acquire");
    connection
        .batch_execute(&format!(r#"SET search_path TO "{schema}", public"#))
        .await
        .expect("isolated operation search path should set");
    let count = sql_query(
        "SELECT COUNT(*)::BIGINT AS count
         FROM tenant_resource_operations
         WHERE deployment_id = 'deployment-concurrent'
           AND tenant_id = $1 AND jti = 'jti-concurrent'",
    )
    .bind::<sql_types::Uuid, _>(tenant_id)
    .get_result::<CountRow>(&mut connection)
    .await
    .expect("operation count should load");
    assert_eq!(count.count, 1, "concurrent entry point must leave one row");
    connection
        .batch_execute("SET search_path TO public")
        .await
        .expect("public search path should restore");
    connection
        .batch_execute(&format!(r#"DROP SCHEMA "{schema}" CASCADE"#))
        .await
        .expect("isolated operation schema should clean up");
    sql_query("DELETE FROM tenants WHERE id = $1")
        .bind::<sql_types::Uuid, _>(tenant_id)
        .execute(&mut connection)
        .await
        .expect("test tenant should clean up");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tenant_resource_down_refuses_machine_rows_and_receipt_evidence() {
    let database_url = database_url();
    let schema = format!("tenant_resource_down_{}", Uuid::now_v7().simple());
    let mut connection = AsyncPgConnection::establish(&database_url)
        .await
        .expect("test database should connect");
    connection
        .batch_execute(&format!(
            r#"
            CREATE SCHEMA "{schema}";
            SET search_path TO "{schema}";
            CREATE TABLE tenants (id UUID PRIMARY KEY);
            CREATE TABLE users (
                id UUID PRIMARY KEY, tenant_id UUID NOT NULL,
                mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE,
                updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE oauth_clients (
                id UUID PRIMARY KEY, tenant_id UUID NOT NULL,
                client_id VARCHAR(128) NOT NULL DEFAULT 'fixture-client',
                is_active BOOLEAN NOT NULL DEFAULT TRUE,
                updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE openid4vp_transactions (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                tenant_id UUID NOT NULL,
                conformance_lease_id UUID
            );
            CREATE TABLE oauth_client_mtls_trust_anchor_requests (
                id UUID PRIMARY KEY, tenant_id UUID NOT NULL, user_id UUID NOT NULL,
                client_id UUID NOT NULL, certificate_pem TEXT NOT NULL,
                certificate_sha256 VARCHAR(64) NOT NULL, subject_dn TEXT NOT NULL,
                not_before TIMESTAMPTZ NOT NULL, not_after TIMESTAMPTZ NOT NULL,
                status SMALLINT NOT NULL, source VARCHAR(32) NOT NULL DEFAULT 'admin-session',
                resolved_by_user_id UUID, resolved_at TIMESTAMPTZ,
                revoked_by_user_id UUID, revoked_at TIMESTAMPTZ,
                CONSTRAINT ck_mtls_trust_anchor_source
                    CHECK (source IN ('admin-session', 'operator-conformance')),
                CONSTRAINT ck_mtls_trust_anchor_state CHECK (
                    status IN (0, 1, 2, 3)
                )
            );
            CREATE TABLE oauth_client_mtls_trust_anchor_events (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                tenant_id UUID NOT NULL, request_id UUID NOT NULL,
                actor_user_id UUID, action SMALLINT NOT NULL, note TEXT,
                CONSTRAINT ck_mtls_trust_anchor_event_action CHECK (action IN (0, 1, 2, 3))
            );
            CREATE FUNCTION nazo_oauth_validate_mtls_trust_event_actor()
            RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END; $$;
            CREATE TRIGGER trg_mtls_trust_event_actor
            BEFORE INSERT OR UPDATE ON oauth_client_mtls_trust_anchor_events
            FOR EACH ROW EXECUTE FUNCTION nazo_oauth_validate_mtls_trust_event_actor();
            CREATE TABLE openid4vci_credential_dataset_events (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                tenant_id UUID NOT NULL, subject_id UUID NOT NULL,
                credential_configuration_id VARCHAR(255) NOT NULL,
                action SMALLINT NOT NULL, actor_user_id UUID NOT NULL,
                source VARCHAR(64) NOT NULL,
                CONSTRAINT ck_openid4vci_dataset_event_source
                    CHECK (source = 'admin-session')
            );
            "#
        ))
        .await
        .expect("migration fixture should create");
    connection
        .batch_execute(RESOURCE_UP)
        .await
        .expect("tenant resource up migration should apply");

    let tenant_id = Uuid::now_v7();
    let request_id = Uuid::now_v7();
    sql_query("INSERT INTO tenants (id) VALUES ($1)")
        .bind::<sql_types::Uuid, _>(tenant_id)
        .execute(&mut connection)
        .await
        .expect("fixture tenant should insert");
    sql_query(
        "INSERT INTO openid4vc_trust_policies
            (tenant_id, resource_id, resource_digest, public_material, wallet_origins)
         VALUES ($1, 'down-evidence', $2, '{}', '[\"https://wallet.example/\"]')",
    )
    .bind::<sql_types::Uuid, _>(tenant_id)
    .bind::<sql_types::Varchar, _>("d".repeat(64))
    .execute(&mut connection)
    .await
    .expect("trust policy rollback evidence should insert");
    let oversized_receipt_digest = "c".repeat(64);
    assert!(
        sql_query(
            "INSERT INTO tenant_resource_operations
                (deployment_id, tenant_id, jti, change_set_id, change_set_sha256,
                 request_sha256, operation,
                 expected_revision, result_revision, receipt_json, receipt_jws)
             VALUES ('deployment', $1, 'oversized-json', 'change-set-oversized-json', $2,
                     $2, 'apply', 0, 1,
                     jsonb_build_object('blob', repeat('x', 1048576)), 'jws')",
        )
        .bind::<sql_types::Uuid, _>(tenant_id)
        .bind::<sql_types::Varchar, _>(&oversized_receipt_digest)
        .execute(&mut connection)
        .await
        .is_err(),
        "receipt JSON must be bounded by its UTF-8 evidence size"
    );
    assert!(
        sql_query(
            "INSERT INTO tenant_resource_operations
                (deployment_id, tenant_id, jti, change_set_id, change_set_sha256,
                 request_sha256, operation,
                 expected_revision, result_revision, receipt_json, receipt_jws)
             VALUES ('deployment', $1, 'oversized-jws', 'change-set-oversized-jws', $2,
                     $2, 'apply', 0, 1,
                     '{\"status\":\"succeeded\"}', repeat('j', 65537))",
        )
        .bind::<sql_types::Uuid, _>(tenant_id)
        .bind::<sql_types::Varchar, _>(&oversized_receipt_digest)
        .execute(&mut connection)
        .await
        .is_err(),
        "receipt JWS must be bounded by its UTF-8 evidence size"
    );
    assert!(
        sql_query(
            "INSERT INTO tenant_resource_operations
                (deployment_id, tenant_id, jti, change_set_id, change_set_sha256,
                 request_sha256, operation, expected_revision, result_revision,
                 receipt_json, receipt_jws)
             VALUES ('deployment', $1, 'invalid-enumerate', 'change-set-invalid-enumerate',
                     $2, $2, 'enumerate', 0, 1, '{\"status\":\"succeeded\"}', 'jws')",
        )
        .bind::<sql_types::Uuid, _>(tenant_id)
        .bind::<sql_types::Varchar, _>(&oversized_receipt_digest)
        .execute(&mut connection)
        .await
        .is_err(),
        "enumerate receipts must retain the expected revision"
    );
    assert!(
        sql_query(
            "INSERT INTO tenant_resource_operations
                (deployment_id, tenant_id, jti, change_set_id, change_set_sha256,
                 request_sha256, operation, expected_revision, result_revision,
                 receipt_json, receipt_jws)
             VALUES ('deployment', $1, 'invalid-apply', 'change-set-invalid-apply',
                     $2, $2, 'apply', 0, 2, '{\"status\":\"succeeded\"}', 'jws')",
        )
        .bind::<sql_types::Uuid, _>(tenant_id)
        .bind::<sql_types::Varchar, _>(&oversized_receipt_digest)
        .execute(&mut connection)
        .await
        .is_err(),
        "apply receipts must advance exactly one revision"
    );
    sql_query(
        "INSERT INTO oauth_client_mtls_trust_anchor_requests
            (id, tenant_id, user_id, client_id, certificate_pem, certificate_sha256,
             subject_dn, not_before, not_after, status, source, resolved_at)
         VALUES ($1, $2, NULL, $3, '-----BEGIN CERTIFICATE-----x-----END CERTIFICATE-----',
                 $4, 'CN=machine', CURRENT_TIMESTAMP - INTERVAL '1 minute',
                 CURRENT_TIMESTAMP + INTERVAL '1 hour', 1, 'operator-managed', CURRENT_TIMESTAMP)",
    )
    .bind::<sql_types::Uuid, _>(request_id)
    .bind::<sql_types::Uuid, _>(tenant_id)
    .bind::<sql_types::Uuid, _>(Uuid::now_v7())
    .bind::<sql_types::Varchar, _>("a".repeat(64))
    .execute(&mut connection)
    .await
    .expect("machine trust request should satisfy source/actor closure");
    sql_query(
        "INSERT INTO oauth_client_mtls_trust_anchor_events
            (tenant_id, request_id, actor_user_id, action)
         VALUES ($1, $2, NULL, 1)",
    )
    .bind::<sql_types::Uuid, _>(tenant_id)
    .bind::<sql_types::Uuid, _>(request_id)
    .execute(&mut connection)
    .await
    .expect("machine trust event should allow a null user actor");
    sql_query(
        "INSERT INTO openid4vci_credential_dataset_events
            (tenant_id, subject_id, credential_configuration_id, action, actor_user_id, source)
         VALUES ($1, $2, 'config', 1, NULL, 'operator-managed')",
    )
    .bind::<sql_types::Uuid, _>(tenant_id)
    .bind::<sql_types::Uuid, _>(Uuid::now_v7())
    .execute(&mut connection)
    .await
    .expect("machine dataset event should allow a null user actor");
    sql_query(
        "INSERT INTO tenant_resource_operations
            (deployment_id, tenant_id, jti, change_set_id, change_set_sha256,
             request_sha256, operation,
             expected_revision, result_revision, receipt_json, receipt_jws)
         VALUES ('deployment', $1, 'jti', 'change-set-down', $2, $2, 'apply', 0, 1,
                 '{\"status\":\"succeeded\"}', 'jws')",
    )
    .bind::<sql_types::Uuid, _>(tenant_id)
    .bind::<sql_types::Varchar, _>("b".repeat(64))
    .execute(&mut connection)
    .await
    .expect("receipt evidence should insert");

    assert!(
        sql_query(
            "UPDATE tenant_resource_operations
             SET receipt_jws = 'rewritten'
             WHERE tenant_id = $1 AND jti = 'jti'",
        )
        .bind::<sql_types::Uuid, _>(tenant_id)
        .execute(&mut connection)
        .await
        .is_err(),
        "receipt rows must reject UPDATE"
    );
    assert!(
        sql_query(
            "DELETE FROM tenant_resource_operations
             WHERE tenant_id = $1 AND jti = 'jti'",
        )
        .bind::<sql_types::Uuid, _>(tenant_id)
        .execute(&mut connection)
        .await
        .is_err(),
        "receipt rows must reject DELETE"
    );
    assert!(
        sql_query("DELETE FROM tenants WHERE id = $1")
            .bind::<sql_types::Uuid, _>(tenant_id)
            .execute(&mut connection)
            .await
            .is_err(),
        "tenant deletion must preserve resource receipt evidence"
    );
    let receipt_count = sql_query(
        "SELECT COUNT(*)::BIGINT AS count
         FROM tenant_resource_operations
         WHERE tenant_id = $1 AND jti = 'jti'",
    )
    .bind::<sql_types::Uuid, _>(tenant_id)
    .get_result::<CountRow>(&mut connection)
    .await
    .expect("receipt count should load after rejected tenant deletion");
    assert_eq!(receipt_count.count, 1);

    let refused = connection
        .transaction::<(), diesel::result::Error, _>(async |connection| {
            connection.batch_execute(RESOURCE_DOWN).await
        })
        .await;
    assert!(
        refused.is_err(),
        "down must refuse machine and receipt rows"
    );

    connection
        .batch_execute(
            "-- Test-only cleanup: production append-only trigger is removed only by down after evidence is empty.
             DROP TRIGGER trg_tenant_resource_operations_append_only
                 ON tenant_resource_operations;
             DELETE FROM tenant_resource_operations;
             DELETE FROM openid4vc_trust_policy_clients;
             DELETE FROM openid4vc_trust_policies;
             DELETE FROM openid4vci_credential_dataset_events;
             DELETE FROM oauth_client_mtls_trust_anchor_events;
             DELETE FROM oauth_client_mtls_trust_anchor_requests;
             DELETE FROM tenants;",
        )
        .await
        .expect("operator cleanup should remove evidence before down");
    connection
        .batch_execute(RESOURCE_DOWN)
        .await
        .expect("down should succeed after explicit operator cleanup");
    assert!(
        sql_query("SELECT to_regclass('tenant_resource_operations') IS NULL AS absent")
            .get_result::<AbsentRow>(&mut connection)
            .await
            .expect("catalog probe should run")
            .absent
    );
    assert!(
        sql_query(
            "INSERT INTO oauth_client_mtls_trust_anchor_requests
                (id, tenant_id, user_id, client_id, certificate_pem, certificate_sha256,
                 subject_dn, not_before, not_after, status, source)
             VALUES (gen_random_uuid(), gen_random_uuid(), gen_random_uuid(), gen_random_uuid(),
                     'x', 'x', 'x', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 0, 'operator-managed')",
        )
        .execute(&mut connection)
        .await
        .is_err(),
        "down must restore the prior machine-source constraint"
    );
    assert!(
        sql_query(
            "INSERT INTO openid4vci_credential_dataset_events
                (tenant_id, subject_id, credential_configuration_id, action,
                 actor_user_id, source)
             VALUES (gen_random_uuid(), gen_random_uuid(), 'config', 1,
                     gen_random_uuid(), 'operator-managed')",
        )
        .execute(&mut connection)
        .await
        .is_err(),
        "down must restore the dataset machine-source constraint"
    );
    connection
        .batch_execute(&format!(
            "SET search_path TO public; DROP SCHEMA \"{schema}\" CASCADE;"
        ))
        .await
        .expect("test schema should drop");
}

#[derive(diesel::QueryableByName)]
struct AbsentRow {
    #[diesel(sql_type = sql_types::Bool)]
    absent: bool,
}

#[derive(diesel::QueryableByName)]
struct CountRow {
    #[diesel(sql_type = sql_types::BigInt)]
    count: i64,
}
