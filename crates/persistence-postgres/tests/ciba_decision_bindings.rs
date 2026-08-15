use chrono::{Duration, Utc};
use diesel::{sql_query, sql_types};
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl, SimpleAsyncConnection};
use nazo_identity::ports::RepositoryError;
use nazo_postgres::{
    CIBA_DECISION_CLAIM_SECONDS, CibaDecisionBindingRepository, CibaDecisionBindingRevoke,
    CibaDecisionBindingWrite, CibaDecisionClaimOutcome, NewCibaDecisionBinding, create_pool,
    get_conn, run_pending_migrations,
};
use uuid::Uuid;

const MIGRATION_UP: &str =
    include_str!("../../../migrations/20260815000100_ciba_decision_bindings/up.sql");
const MIGRATION_DOWN: &str =
    include_str!("../../../migrations/20260815000100_ciba_decision_bindings/down.sql");
const DEFAULT_TENANT: &str = "00000000-0000-0000-0000-000000000001";
const DEFAULT_REALM: &str = "00000000-0000-0000-0000-000000000002";
const DEFAULT_ORGANIZATION: &str = "00000000-0000-0000-0000-000000000003";

fn database_url() -> String {
    std::env::var("NAZO_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .expect("CIBA binding persistence tests require NAZO_TEST_DATABASE_URL or DATABASE_URL")
}

async fn insert_subject_and_client(connection: &mut AsyncPgConnection) -> (Uuid, Uuid, String) {
    let tenant_id = Uuid::parse_str(DEFAULT_TENANT).expect("default tenant UUID is valid");
    let realm_id = Uuid::parse_str(DEFAULT_REALM).expect("default realm UUID is valid");
    let organization_id =
        Uuid::parse_str(DEFAULT_ORGANIZATION).expect("default organization UUID is valid");
    let user_id = Uuid::now_v7();
    let oauth_client_id = Uuid::now_v7();
    let suffix = Uuid::now_v7().simple().to_string();
    let public_client_id = format!("ciba-binding-{suffix}");
    sql_query(
        "INSERT INTO users
            (id, tenant_id, realm_id, organization_id, username, email, password_hash)
         VALUES ($1, $2, $3, $4, $5, $6, 'test-only')",
    )
    .bind::<sql_types::Uuid, _>(user_id)
    .bind::<sql_types::Uuid, _>(tenant_id)
    .bind::<sql_types::Uuid, _>(realm_id)
    .bind::<sql_types::Uuid, _>(organization_id)
    .bind::<sql_types::Varchar, _>(format!("ciba-binding-{suffix}"))
    .bind::<sql_types::Varchar, _>(format!("ciba-binding-{suffix}@example.test"))
    .execute(&mut *connection)
    .await
    .expect("CIBA binding subject should insert");
    sql_query(
        "INSERT INTO oauth_clients
            (id, tenant_id, realm_id, organization_id, client_id, client_name,
             client_type, redirect_uris, scopes, grant_types,
             token_endpoint_auth_method)
         VALUES ($1, $2, $3, $4, $5, 'CIBA binding test', 'confidential',
                 '[]'::JSONB, '[\"openid\"]'::JSONB,
                 '[\"urn:openid:params:grant-type:ciba\"]'::JSONB,
                 'private_key_jwt')",
    )
    .bind::<sql_types::Uuid, _>(oauth_client_id)
    .bind::<sql_types::Uuid, _>(tenant_id)
    .bind::<sql_types::Uuid, _>(realm_id)
    .bind::<sql_types::Uuid, _>(organization_id)
    .bind::<sql_types::Varchar, _>(&public_client_id)
    .execute(connection)
    .await
    .expect("CIBA binding client should insert");
    (user_id, oauth_client_id, public_client_id)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ordinary_ciba_binding_is_digest_fenced_claimed_and_revoked_linearly() {
    let database_url = database_url();
    run_pending_migrations(&database_url)
        .await
        .expect("pending migrations should apply");
    let pool = create_pool(&database_url, 3).expect("test pool should build");
    let tenant_id = Uuid::parse_str(DEFAULT_TENANT).expect("default tenant UUID is valid");
    let mut connection = get_conn(&pool)
        .await
        .expect("test connection should acquire");
    let (user_id, oauth_client_id, public_client_id) =
        insert_subject_and_client(&mut connection).await;
    let generation = Uuid::now_v7();
    let now = Utc::now();
    let expires_at = now + Duration::minutes(10);
    let resource_digest = "a".repeat(64);
    let token_sha256 = "b".repeat(64);

    let applied = connection
        .transaction::<_, anyhow::Error, _>(async |connection| {
            CibaDecisionBindingRepository::apply_on_connection(
                connection,
                NewCibaDecisionBinding {
                    generation,
                    tenant_id,
                    resource_id: "ciba-decision:primary",
                    resource_digest: &resource_digest,
                    oauth_client_id,
                    user_id,
                    token_sha256: &token_sha256,
                    expires_at,
                },
            )
            .await
            .map_err(anyhow::Error::from)
        })
        .await
        .expect("binding apply transaction should commit");
    let CibaDecisionBindingWrite::Applied(binding) = applied else {
        panic!("first apply must create a generation: {applied:?}");
    };
    let debug = format!("{binding:?}");
    assert!(!debug.contains(&token_sha256));
    assert!(!debug.contains(&resource_digest));
    assert!(debug.contains("[REDACTED]"));

    let replay = connection
        .transaction::<_, anyhow::Error, _>(async |connection| {
            CibaDecisionBindingRepository::apply_on_connection(
                connection,
                NewCibaDecisionBinding {
                    generation,
                    tenant_id,
                    resource_id: "ciba-decision:primary",
                    resource_digest: &resource_digest,
                    oauth_client_id,
                    user_id,
                    token_sha256: &token_sha256,
                    expires_at,
                },
            )
            .await
            .map_err(anyhow::Error::from)
        })
        .await
        .expect("exact apply replay should commit");
    assert!(matches!(replay, CibaDecisionBindingWrite::Replayed(_)));

    assert!(
        CibaDecisionBindingRepository::active_for_oauth_client_on_connection(
            &mut connection,
            tenant_id,
            oauth_client_id,
        )
        .await
        .expect("client dependency lookup should succeed")
        .is_some()
    );
    assert!(
        CibaDecisionBindingRepository::active_for_user_on_connection(
            &mut connection,
            tenant_id,
            user_id,
        )
        .await
        .expect("user dependency lookup should succeed")
        .is_some()
    );

    let duplicate_token = connection
        .transaction::<_, anyhow::Error, _>(async |connection| {
            CibaDecisionBindingRepository::apply_on_connection(
                connection,
                NewCibaDecisionBinding {
                    generation: Uuid::now_v7(),
                    tenant_id,
                    resource_id: "ciba-decision:duplicate-token",
                    resource_digest: &"c".repeat(64),
                    oauth_client_id,
                    user_id,
                    token_sha256: &token_sha256,
                    expires_at,
                },
            )
            .await
            .map_err(anyhow::Error::from)
        })
        .await;
    assert!(
        matches!(
            duplicate_token,
            Err(error)
                if error.downcast_ref::<RepositoryError>() == Some(&RepositoryError::Conflict)
        ),
        "one client cannot have two active bindings for a token digest"
    );

    let (second_user_id, second_oauth_client_id, second_public_client_id) =
        insert_subject_and_client(&mut connection).await;
    let second_generation = Uuid::now_v7();
    let shared_token = connection
        .transaction::<_, anyhow::Error, _>(async |connection| {
            CibaDecisionBindingRepository::apply_on_connection(
                connection,
                NewCibaDecisionBinding {
                    generation: second_generation,
                    tenant_id,
                    resource_id: "ciba-decision:second-client",
                    resource_digest: &"d".repeat(64),
                    oauth_client_id: second_oauth_client_id,
                    user_id: second_user_id,
                    token_sha256: &token_sha256,
                    expires_at,
                },
            )
            .await
            .map_err(anyhow::Error::from)
        })
        .await
        .expect("one run token may bind a second independently fenced client");
    assert!(matches!(
        shared_token,
        CibaDecisionBindingWrite::Applied(binding)
            if binding.generation == second_generation
    ));
    assert!(
        CibaDecisionBindingRepository::lookup_active_on_connection(
            &mut connection,
            tenant_id,
            &token_sha256,
            &second_public_client_id,
            second_user_id,
            now,
        )
        .await
        .expect("shared token lookup for the second client should succeed")
        .is_some()
    );
    assert!(
        CibaDecisionBindingRepository::lookup_active_on_connection(
            &mut connection,
            tenant_id,
            &token_sha256,
            &public_client_id,
            second_user_id,
            now,
        )
        .await
        .expect("cross-client lookup should remain opaque")
        .is_none()
    );

    let repository = CibaDecisionBindingRepository::new(pool.clone());
    let first_claim_id = Uuid::now_v7();
    let first = repository
        .claim_active(
            tenant_id,
            &token_sha256,
            &public_client_id,
            user_id,
            first_claim_id,
            now,
        )
        .await
        .expect("first decision claim should execute");
    let CibaDecisionClaimOutcome::Acquired {
        binding: claimed,
        claim_expires_at: first_deadline,
        ..
    } = first
    else {
        panic!("first claim must acquire the binding: {first:?}");
    };
    assert_eq!(claimed.generation, generation);
    assert_eq!(
        first_deadline.timestamp_micros(),
        (now + Duration::seconds(CIBA_DECISION_CLAIM_SECONDS)).timestamp_micros()
    );

    let replayed_claim = repository
        .claim_active(
            tenant_id,
            &token_sha256,
            &public_client_id,
            user_id,
            first_claim_id,
            now + Duration::seconds(1),
        )
        .await
        .expect("same claim should replay");
    assert!(matches!(
        replayed_claim,
        CibaDecisionClaimOutcome::Acquired {
            claim_expires_at,
            ..
        } if claim_expires_at == first_deadline
    ));
    let second_claim_id = Uuid::now_v7();
    assert!(matches!(
        repository
            .claim_active(
                tenant_id,
                &token_sha256,
                &public_client_id,
                user_id,
                second_claim_id,
                now + Duration::seconds(2),
            )
            .await
            .expect("competing claim should classify"),
        CibaDecisionClaimOutcome::Busy { claim_expires_at }
            if claim_expires_at == first_deadline
    ));

    let busy_revoke = connection
        .transaction::<_, anyhow::Error, _>(async |connection| {
            CibaDecisionBindingRepository::revoke_on_connection(
                connection,
                tenant_id,
                generation,
                "ciba-decision:primary",
                &resource_digest,
                now + Duration::seconds(3),
            )
            .await
            .map_err(anyhow::Error::from)
        })
        .await
        .expect("busy revoke should classify");
    assert!(matches!(
        busy_revoke,
        CibaDecisionBindingRevoke::Busy { claim_expires_at }
            if claim_expires_at == first_deadline
    ));
    assert!(
        !repository
            .release_claim(tenant_id, generation, Uuid::now_v7())
            .await
            .expect("wrong release should execute")
    );
    assert!(
        repository
            .release_claim(tenant_id, generation, first_claim_id)
            .await
            .expect("exact release should execute")
    );

    let reclaimed = repository
        .claim_active(
            tenant_id,
            &token_sha256,
            &public_client_id,
            user_id,
            second_claim_id,
            now + Duration::seconds(4),
        )
        .await
        .expect("released claim should be acquirable");
    let CibaDecisionClaimOutcome::Acquired {
        claim_expires_at: second_deadline,
        ..
    } = reclaimed
    else {
        panic!("released binding must allow a new claim: {reclaimed:?}");
    };

    let revoked = connection
        .transaction::<_, anyhow::Error, _>(async |connection| {
            CibaDecisionBindingRepository::revoke_on_connection(
                connection,
                tenant_id,
                generation,
                "ciba-decision:primary",
                &resource_digest,
                second_deadline,
            )
            .await
            .map_err(anyhow::Error::from)
        })
        .await
        .expect("expired claim revoke should commit");
    assert!(matches!(revoked, CibaDecisionBindingRevoke::Revoked(_)));
    assert!(matches!(
        repository
            .claim_active(
                tenant_id,
                &token_sha256,
                &public_client_id,
                user_id,
                Uuid::now_v7(),
                second_deadline,
            )
            .await
            .expect("revoked lookup should classify"),
        CibaDecisionClaimOutcome::NotFound
    ));

    let short_generation = Uuid::now_v7();
    let short_token_sha256 = "f".repeat(64);
    let short_now = Utc::now();
    let short_expiry = short_now + Duration::seconds(5);
    let short_write = connection
        .transaction::<_, anyhow::Error, _>(async |connection| {
            CibaDecisionBindingRepository::apply_on_connection(
                connection,
                NewCibaDecisionBinding {
                    generation: short_generation,
                    tenant_id,
                    resource_id: "ciba-decision:short",
                    resource_digest: &"1".repeat(64),
                    oauth_client_id,
                    user_id,
                    token_sha256: &short_token_sha256,
                    expires_at: short_expiry,
                },
            )
            .await
            .map_err(anyhow::Error::from)
        })
        .await
        .expect("short binding should apply");
    let CibaDecisionBindingWrite::Applied(short_binding) = short_write else {
        panic!("short binding must create a generation: {short_write:?}");
    };
    assert!(matches!(
        repository
            .claim_active(
                tenant_id,
                &short_token_sha256,
                &public_client_id,
                user_id,
                Uuid::now_v7(),
                short_now,
            )
            .await
            .expect("short binding claim should execute"),
        CibaDecisionClaimOutcome::Acquired {
            claim_expires_at,
            ..
        } if claim_expires_at == short_binding.expires_at
    ));

    sql_query("DELETE FROM ciba_decision_bindings WHERE tenant_id = $1")
        .bind::<sql_types::Uuid, _>(tenant_id)
        .execute(&mut connection)
        .await
        .expect("test binding should clean up");
    sql_query("DELETE FROM oauth_clients WHERE tenant_id = $1 AND id = $2")
        .bind::<sql_types::Uuid, _>(tenant_id)
        .bind::<sql_types::Uuid, _>(oauth_client_id)
        .execute(&mut connection)
        .await
        .expect("test client should clean up");
    sql_query("DELETE FROM users WHERE tenant_id = $1 AND id = $2")
        .bind::<sql_types::Uuid, _>(tenant_id)
        .bind::<sql_types::Uuid, _>(user_id)
        .execute(&mut connection)
        .await
        .expect("test subject should clean up");
}

#[tokio::test]
async fn ciba_binding_down_refuses_persisted_resource_state() {
    let database_url = database_url();
    let schema = format!("ciba_binding_down_{}", Uuid::now_v7().simple());
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
                id UUID PRIMARY KEY,
                tenant_id UUID NOT NULL,
                CONSTRAINT uq_users_id_tenant UNIQUE (id, tenant_id)
            );
            CREATE TABLE oauth_clients (
                id UUID PRIMARY KEY,
                tenant_id UUID NOT NULL,
                CONSTRAINT uq_oauth_clients_id_tenant UNIQUE (id, tenant_id)
            );
            CREATE TABLE tenant_resource_bindings (
                resource_kind VARCHAR(64) NOT NULL,
                CONSTRAINT ck_tenant_resource_binding_kind CHECK (
                    resource_kind IN (
                        'oauth-client', 'mtls-trust-anchor', 'openid4vc-dataset',
                        'openid4vc-trust-policy', 'user'
                    )
                )
            );
            "#,
        ))
        .await
        .expect("isolated migration fixture should create");
    connection
        .batch_execute(MIGRATION_UP)
        .await
        .expect("CIBA binding up migration should apply");
    let tenant_id = Uuid::now_v7();
    let user_id = Uuid::now_v7();
    let client_id = Uuid::now_v7();
    sql_query("INSERT INTO tenants (id) VALUES ($1)")
        .bind::<sql_types::Uuid, _>(tenant_id)
        .execute(&mut connection)
        .await
        .expect("fixture tenant should insert");
    sql_query("INSERT INTO users (id, tenant_id) VALUES ($1, $2)")
        .bind::<sql_types::Uuid, _>(user_id)
        .bind::<sql_types::Uuid, _>(tenant_id)
        .execute(&mut connection)
        .await
        .expect("fixture user should insert");
    sql_query("INSERT INTO oauth_clients (id, tenant_id) VALUES ($1, $2)")
        .bind::<sql_types::Uuid, _>(client_id)
        .bind::<sql_types::Uuid, _>(tenant_id)
        .execute(&mut connection)
        .await
        .expect("fixture client should insert");
    sql_query(
        "INSERT INTO ciba_decision_bindings
            (generation, tenant_id, resource_id, resource_digest,
             oauth_client_id, user_id, token_sha256, expires_at)
         VALUES ($1, $2, 'down-evidence', $3, $4, $5, $6,
                 CURRENT_TIMESTAMP + INTERVAL '1 hour')",
    )
    .bind::<sql_types::Uuid, _>(Uuid::now_v7())
    .bind::<sql_types::Uuid, _>(tenant_id)
    .bind::<sql_types::Varchar, _>("d".repeat(64))
    .bind::<sql_types::Uuid, _>(client_id)
    .bind::<sql_types::Uuid, _>(user_id)
    .bind::<sql_types::Varchar, _>("e".repeat(64))
    .execute(&mut connection)
    .await
    .expect("fixture binding should insert");
    assert!(
        connection.batch_execute(MIGRATION_DOWN).await.is_err(),
        "down must not discard persisted ordinary resource state"
    );
    connection
        .batch_execute(
            "DELETE FROM ciba_decision_bindings;
             DELETE FROM oauth_clients;
             DELETE FROM users;
             DELETE FROM tenants;",
        )
        .await
        .expect("explicit fixture cleanup should succeed");
    connection
        .batch_execute(MIGRATION_DOWN)
        .await
        .expect("down should succeed after explicit state cleanup");
    connection
        .batch_execute(&format!(
            "SET search_path TO public; DROP SCHEMA \"{schema}\" CASCADE;"
        ))
        .await
        .expect("isolated schema should clean up");
}
