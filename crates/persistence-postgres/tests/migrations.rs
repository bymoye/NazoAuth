use diesel::{QueryableByName, sql_query, sql_types::Text};
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl, SimpleAsyncConnection};
use uuid::Uuid;

const SOCIAL_UP: &str =
    include_str!("../../../migrations/20260712000050_social_federation_provider_type/up.sql");
const SOCIAL_DOWN: &str =
    include_str!("../../../migrations/20260712000050_social_federation_provider_type/down.sql");
const RUNTIME_UP: &str =
    include_str!("../../../migrations/20260712000100_runtime_module_state/up.sql");
const RUNTIME_DOWN: &str =
    include_str!("../../../migrations/20260712000100_runtime_module_state/down.sql");
const IDENTITY_SECURITY_UP: &str =
    include_str!("../../../migrations/20260713000100_identity_security_events/up.sql");
const IDENTITY_SECURITY_DOWN: &str =
    include_str!("../../../migrations/20260713000100_identity_security_events/down.sql");
const IDENTITY_SECURITY_TOTP_INVALID_UP: &str =
    include_str!("../../../migrations/20260713000200_identity_security_totp_invalid/up.sql");
const IDENTITY_SECURITY_TOTP_INVALID_DOWN: &str =
    include_str!("../../../migrations/20260713000200_identity_security_totp_invalid/down.sql");
const OIDC_LOGOUT_IDEMPOTENCY_UP: &str =
    include_str!("../../../migrations/20260714000100_oidc_logout_idempotency/up.sql");
const OIDC_LOGOUT_IDEMPOTENCY_DOWN: &str =
    include_str!("../../../migrations/20260714000100_oidc_logout_idempotency/down.sql");

#[derive(QueryableByName)]
struct ProviderType {
    #[diesel(sql_type = Text)]
    provider_type: String,
}

#[derive(QueryableByName)]
struct RuntimeTable {
    #[diesel(sql_type = Text)]
    table_name: String,
}

fn database_url() -> Option<String> {
    let url = std::env::var("NAZO_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .ok();
    if url.is_none() && std::env::var_os("CI").is_some() {
        panic!("CI migration tests require NAZO_TEST_DATABASE_URL or DATABASE_URL");
    }
    url
}

#[tokio::test]
async fn social_provider_type_migration_preserves_existing_rows_and_has_safe_down_policy() {
    let Some(database_url) = database_url() else {
        return;
    };
    let schema = format!("social_provider_type_{}", Uuid::now_v7().simple());
    let mut connection = AsyncPgConnection::establish(&database_url)
        .await
        .expect("test database should connect");
    connection
        .batch_execute(&format!(
            r#"
            CREATE SCHEMA "{schema}";
            SET search_path TO "{schema}";
            CREATE TABLE external_identity_links (
                provider_type TEXT NOT NULL,
                CONSTRAINT ck_external_identity_links_provider_type
                    CHECK (provider_type IN ('oidc', 'saml'))
            );
            INSERT INTO external_identity_links (provider_type) VALUES ('oidc'), ('saml');
            "#
        ))
        .await
        .expect("baseline schema should create");

    connection
        .transaction::<(), diesel::result::Error, _>(async |connection| {
            connection.batch_execute(SOCIAL_UP).await
        })
        .await
        .expect("up migration should succeed");
    sql_query("INSERT INTO external_identity_links (provider_type) VALUES ('oauth2_social')")
        .execute(&mut connection)
        .await
        .expect("up migration should allow social links");
    let provider_types =
        sql_query("SELECT provider_type FROM external_identity_links ORDER BY provider_type")
            .load::<ProviderType>(&mut connection)
            .await
            .expect("provider rows should remain readable")
            .into_iter()
            .map(|row| row.provider_type)
            .collect::<Vec<_>>();
    assert_eq!(provider_types, ["oauth2_social", "oidc", "saml"]);

    let down_with_social = connection
        .transaction::<(), diesel::result::Error, _>(async |connection| {
            connection.batch_execute(SOCIAL_DOWN).await
        })
        .await;
    assert!(
        down_with_social.is_err(),
        "down migration must fail rather than discard existing social links"
    );
    sql_query("DELETE FROM external_identity_links WHERE provider_type = 'oauth2_social'")
        .execute(&mut connection)
        .await
        .expect("operator cleanup policy should be representable");
    connection
        .transaction::<(), diesel::result::Error, _>(async |connection| {
            connection.batch_execute(SOCIAL_DOWN).await
        })
        .await
        .expect("down migration should succeed after social links are handled");
    assert!(
        sql_query("INSERT INTO external_identity_links (provider_type) VALUES ('oauth2_social')")
            .execute(&mut connection)
            .await
            .is_err(),
        "down migration must restore the baseline provider constraint"
    );
    let baseline =
        sql_query("SELECT provider_type FROM external_identity_links ORDER BY provider_type")
            .load::<ProviderType>(&mut connection)
            .await
            .expect("baseline provider rows should survive down migration")
            .into_iter()
            .map(|row| row.provider_type)
            .collect::<Vec<_>>();
    assert_eq!(baseline, ["oidc", "saml"]);

    connection
        .batch_execute(&format!(
            "SET search_path TO public; DROP SCHEMA \"{schema}\" CASCADE;"
        ))
        .await
        .expect("test schema should drop");
}

#[tokio::test]
async fn pending_migrations_create_all_runtime_module_state_tables() {
    let Some(database_url) = database_url() else {
        return;
    };
    nazo_postgres::run_pending_migrations(&database_url)
        .await
        .expect("pending migrations should apply");
    let mut connection = AsyncPgConnection::establish(&database_url)
        .await
        .expect("test database should connect");
    let tables = sql_query(
        r#"
        SELECT table_name
        FROM information_schema.tables
        WHERE table_schema = current_schema()
          AND table_name IN (
            'runtime_module_desired_states',
            'runtime_module_instance_states',
            'runtime_module_state_events'
          )
        ORDER BY table_name
        "#,
    )
    .load::<RuntimeTable>(&mut connection)
    .await
    .expect("runtime table catalog should be readable")
    .into_iter()
    .map(|row| row.table_name)
    .collect::<Vec<_>>();
    assert_eq!(
        tables,
        [
            "runtime_module_desired_states",
            "runtime_module_instance_states",
            "runtime_module_state_events",
        ]
    );
}

#[tokio::test]
async fn runtime_module_state_migration_enforces_catalogs_and_round_trips() {
    let Some(database_url) = database_url() else {
        return;
    };
    let schema = format!("runtime_module_state_{}", Uuid::now_v7().simple());
    let mut connection = AsyncPgConnection::establish(&database_url)
        .await
        .expect("test database should connect");
    connection
        .batch_execute(&format!(
            r#"
            CREATE SCHEMA "{schema}";
            SET search_path TO "{schema}";
            CREATE TABLE users (id UUID PRIMARY KEY);
            "#
        ))
        .await
        .expect("runtime migration baseline should create");
    connection
        .batch_execute(RUNTIME_UP)
        .await
        .expect("runtime up migration should succeed");

    for invalid in [
        "INSERT INTO runtime_module_desired_states (module_id, desired_mode, revision) VALUES ('ciba', 'automatic', 1)",
        "INSERT INTO runtime_module_instance_states (instance_id, module_id, actual_state, transition_revision) VALUES ('instance-1', 'ciba', 'running', 1)",
        "INSERT INTO runtime_module_state_events (event_id, module_id, event_type, revision) VALUES (gen_random_uuid(), 'ciba', 'unknown', 1)",
    ] {
        assert!(
            sql_query(invalid).execute(&mut connection).await.is_err(),
            "closed runtime state catalog should reject {invalid}"
        );
    }
    for event_type in [
        "desired_state_changed",
        "transition_started",
        "transition_completed",
        "transition_failed",
        "drain_started",
        "drain_completed",
        "stale_transition_discarded",
    ] {
        sql_query(format!(
            "INSERT INTO runtime_module_state_events (event_id, module_id, event_type, revision) VALUES (gen_random_uuid(), 'ciba', '{event_type}', 1)"
        ))
        .execute(&mut connection)
        .await
        .expect("closed runtime event kind should persist");
    }

    connection
        .batch_execute(RUNTIME_DOWN)
        .await
        .expect("runtime down migration should drop only runtime state");
    let users = sql_query(
        "SELECT table_name FROM information_schema.tables WHERE table_schema = current_schema() AND table_name = 'users'",
    )
    .load::<RuntimeTable>(&mut connection)
    .await
    .expect("baseline table catalog should remain readable");
    assert_eq!(
        users.len(),
        1,
        "down migration must preserve baseline tables"
    );
    connection
        .batch_execute(RUNTIME_UP)
        .await
        .expect("runtime up migration should reapply after down");
    connection
        .batch_execute(&format!(
            "SET search_path TO public; DROP SCHEMA \"{schema}\" CASCADE;"
        ))
        .await
        .expect("test schema should drop");
}

#[tokio::test]
async fn identity_security_event_migration_is_additive_redacted_and_round_trips() {
    let Some(database_url) = database_url() else {
        return;
    };
    let schema = format!("identity_security_events_{}", Uuid::now_v7().simple());
    let mut connection = AsyncPgConnection::establish(&database_url)
        .await
        .expect("test database should connect");
    connection
        .batch_execute(&format!(
            r#"
            CREATE SCHEMA "{schema}";
            SET search_path TO "{schema}";
            CREATE TABLE tenants (id UUID PRIMARY KEY);
            CREATE TABLE users (id UUID PRIMARY KEY);
            INSERT INTO tenants (id) VALUES ('00000000-0000-0000-0000-000000000001');
            "#
        ))
        .await
        .expect("identity audit migration baseline should create");
    connection
        .batch_execute(IDENTITY_SECURITY_UP)
        .await
        .expect("identity audit up migration should succeed");

    for invalid in [
        "INSERT INTO identity_security_events (tenant_id, category, event_type, outcome, reason_code) VALUES ('00000000-0000-0000-0000-000000000001', 'secret', 'admin_user_update', 'success', 'admin_updated')",
        "INSERT INTO identity_security_events (tenant_id, category, event_type, outcome, reason_code) VALUES ('00000000-0000-0000-0000-000000000001', 'admin', 'mfa_totp_attempt', 'success', 'totp_accepted')",
        "INSERT INTO identity_security_events (tenant_id, category, event_type, outcome, reason_code) VALUES ('00000000-0000-0000-0000-000000000001', 'admin', 'admin_user_update', 'plaintext_secret', 'admin_updated')",
        "INSERT INTO identity_security_events (tenant_id, category, event_type, outcome, reason_code) VALUES ('00000000-0000-0000-0000-000000000001', 'admin', 'admin_user_update', 'denied', 'contains sensitive text')",
        "INSERT INTO identity_security_events (tenant_id, category, event_type, outcome, reason_code) VALUES ('00000000-0000-0000-0000-000000000001', 'admin', 'admin_user_update', 'success', 'totp_accepted')",
    ] {
        assert!(
            sql_query(invalid).execute(&mut connection).await.is_err(),
            "closed and redacted audit catalog should reject {invalid}"
        );
    }
    for valid in [
        "INSERT INTO identity_security_events (tenant_id, category, event_type, outcome, reason_code) VALUES ('00000000-0000-0000-0000-000000000001', 'mfa', 'mfa_totp_attempt', 'success', 'totp_accepted')",
        "INSERT INTO identity_security_events (tenant_id, category, event_type, outcome, reason_code) VALUES ('00000000-0000-0000-0000-000000000001', 'mfa', 'mfa_backup_code_attempt', 'replay', 'backup_code_replay')",
        "INSERT INTO identity_security_events (tenant_id, category, event_type, outcome, reason_code) VALUES ('00000000-0000-0000-0000-000000000001', 'admin', 'admin_user_update', 'denied', 'cross_tenant')",
    ] {
        sql_query(valid)
            .execute(&mut connection)
            .await
            .expect("typed audit event semantics should persist");
    }

    let columns = sql_query(
        "SELECT column_name AS table_name FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'identity_security_events' ORDER BY ordinal_position",
    )
    .load::<RuntimeTable>(&mut connection)
    .await
    .expect("identity event columns should be readable")
    .into_iter()
    .map(|row| row.table_name)
    .collect::<Vec<_>>();
    assert_eq!(
        columns,
        [
            "id",
            "tenant_id",
            "category",
            "event_type",
            "outcome",
            "actor_id",
            "target_user_id",
            "reason_code",
            "occurred_at",
        ],
        "the audit schema must have no free-form payload capable of storing credentials, sessions, CSRF tokens, or IP addresses"
    );

    connection
        .batch_execute(IDENTITY_SECURITY_DOWN)
        .await
        .expect("identity audit down migration should drop only the additive table");
    let baseline = sql_query(
        "SELECT table_name FROM information_schema.tables WHERE table_schema = current_schema() AND table_name IN ('tenants', 'users') ORDER BY table_name",
    )
    .load::<RuntimeTable>(&mut connection)
    .await
    .expect("baseline table catalog should remain readable")
    .into_iter()
    .map(|row| row.table_name)
    .collect::<Vec<_>>();
    assert_eq!(baseline, ["tenants", "users"]);
    connection
        .batch_execute(IDENTITY_SECURITY_UP)
        .await
        .expect("identity audit up migration should reapply after down");
    connection
        .batch_execute(&format!(
            "SET search_path TO public; DROP SCHEMA \"{schema}\" CASCADE;"
        ))
        .await
        .expect("test schema should drop");
}

#[tokio::test]
async fn totp_invalid_audit_migration_extends_and_restores_the_closed_catalog() {
    let Some(database_url) = database_url() else {
        return;
    };
    let schema = format!("identity_totp_invalid_{}", Uuid::now_v7().simple());
    let mut connection = AsyncPgConnection::establish(&database_url)
        .await
        .expect("test database should connect");
    connection
        .batch_execute(&format!(
            r#"
            CREATE SCHEMA "{schema}";
            SET search_path TO "{schema}";
            CREATE TABLE tenants (id UUID PRIMARY KEY);
            CREATE TABLE users (id UUID PRIMARY KEY);
            INSERT INTO tenants (id) VALUES ('00000000-0000-0000-0000-000000000001');
            "#
        ))
        .await
        .expect("identity audit baseline should create");
    connection
        .batch_execute(IDENTITY_SECURITY_UP)
        .await
        .expect("identity audit table should create");
    connection
        .batch_execute(IDENTITY_SECURITY_TOTP_INVALID_UP)
        .await
        .expect("TOTP invalid catalog extension should apply");

    let invalid_attempt = "INSERT INTO identity_security_events (tenant_id, category, event_type, outcome, reason_code) VALUES ('00000000-0000-0000-0000-000000000001', 'mfa', 'mfa_totp_attempt', 'invalid_credential', 'totp_invalid')";
    sql_query(invalid_attempt)
        .execute(&mut connection)
        .await
        .expect("redacted invalid TOTP audit outcome should persist");
    assert!(
        sql_query("INSERT INTO identity_security_events (tenant_id, category, event_type, outcome, reason_code) VALUES ('00000000-0000-0000-0000-000000000001', 'mfa', 'mfa_totp_attempt', 'invalid_credential', 'contains-code-123456')")
            .execute(&mut connection)
            .await
            .is_err(),
        "the extended catalog must still reject free-form reason text"
    );

    sql_query("DELETE FROM identity_security_events")
        .execute(&mut connection)
        .await
        .expect("extension-only rows can be removed before downgrade");
    connection
        .batch_execute(IDENTITY_SECURITY_TOTP_INVALID_DOWN)
        .await
        .expect("down migration should restore the prior closed catalog");
    assert!(
        sql_query(invalid_attempt)
            .execute(&mut connection)
            .await
            .is_err(),
        "the prior catalog must not silently retain the new reason"
    );
    connection
        .batch_execute(IDENTITY_SECURITY_TOTP_INVALID_UP)
        .await
        .expect("extension should reapply after down");
    sql_query(invalid_attempt)
        .execute(&mut connection)
        .await
        .expect("reapplied extension should accept the typed outcome");

    connection
        .batch_execute(&format!(
            "SET search_path TO public; DROP SCHEMA \"{schema}\" CASCADE;"
        ))
        .await
        .expect("test schema should drop");
}

#[tokio::test]
async fn oidc_logout_idempotency_migration_is_additive_partial_and_reversible() {
    let Some(database_url) = database_url() else {
        return;
    };
    let schema = format!("oidc_logout_idempotency_{}", Uuid::now_v7().simple());
    let mut connection = AsyncPgConnection::establish(&database_url)
        .await
        .expect("test database should connect");
    connection
        .batch_execute(&format!(
            r#"
            CREATE SCHEMA "{schema}";
            SET search_path TO "{schema}";
            CREATE TABLE backchannel_logout_deliveries (
                tenant_id UUID NOT NULL,
                client_id UUID NOT NULL
            );
            "#
        ))
        .await
        .expect("logout outbox baseline should create");
    connection
        .batch_execute(OIDC_LOGOUT_IDEMPOTENCY_UP)
        .await
        .expect("logout idempotency migration should apply");

    let tenant_id = Uuid::now_v7();
    let client_id = Uuid::now_v7();
    sql_query(
        "INSERT INTO backchannel_logout_deliveries (tenant_id, client_id, operation_key) \
         VALUES ($1, $2, 'operation-a')",
    )
    .bind::<diesel::sql_types::Uuid, _>(tenant_id)
    .bind::<diesel::sql_types::Uuid, _>(client_id)
    .execute(&mut connection)
    .await
    .expect("first operation/client pair should insert");
    assert!(
        sql_query(
            "INSERT INTO backchannel_logout_deliveries (tenant_id, client_id, operation_key) \
             VALUES ($1, $2, 'operation-a')",
        )
        .bind::<diesel::sql_types::Uuid, _>(tenant_id)
        .bind::<diesel::sql_types::Uuid, _>(client_id)
        .execute(&mut connection)
        .await
        .is_err(),
        "the same operation/client pair must be unique"
    );
    sql_query(
        "INSERT INTO backchannel_logout_deliveries (tenant_id, client_id, operation_key) \
         VALUES ($1, $2, NULL), ($1, $2, NULL)",
    )
    .bind::<diesel::sql_types::Uuid, _>(tenant_id)
    .bind::<diesel::sql_types::Uuid, _>(client_id)
    .execute(&mut connection)
    .await
    .expect("legacy NULL operation rows must remain compatible");

    connection
        .batch_execute(OIDC_LOGOUT_IDEMPOTENCY_DOWN)
        .await
        .expect("logout idempotency migration should roll back");
    assert!(
        sql_query("SELECT operation_key FROM backchannel_logout_deliveries")
            .execute(&mut connection)
            .await
            .is_err(),
        "down migration must remove only the additive operation key"
    );
    connection
        .batch_execute(OIDC_LOGOUT_IDEMPOTENCY_UP)
        .await
        .expect("logout idempotency migration should reapply");
    connection
        .batch_execute(&format!(
            "SET search_path TO public; DROP SCHEMA \"{schema}\" CASCADE;"
        ))
        .await
        .expect("test schema should drop");
}
