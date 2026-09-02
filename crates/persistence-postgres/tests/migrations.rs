use diesel::{
    QueryableByName, sql_query,
    sql_types::{BigInt, Text},
};
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl, SimpleAsyncConnection};
use uuid::Uuid;

#[test]
fn embedded_migration_head_tracks_latest_directory() {
    let migrations = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../migrations");
    let latest = std::fs::read_dir(&migrations)
        .expect("migration directory should be readable")
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_dir()))
        .map(|entry| entry.file_name())
        .max()
        .expect("at least one migration directory should exist");
    assert_eq!(
        include_str!("../migration-head.txt").trim(),
        latest.to_string_lossy(),
        "append-only migrations must advance migration-head.txt so cached builds re-embed them"
    );
}

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
const RECOVERY_ROOT_UP: &str =
    include_str!("../../../migrations/20260825000100_controller_recovery_root/up.sql");
const RECOVERY_ROOT_DOWN: &str =
    include_str!("../../../migrations/20260825000100_controller_recovery_root/down.sql");
const RECOVERY_RECEIPT_UP: &str =
    include_str!("../../../migrations/20260827000100_controller_recovery_receipt/up.sql");
const RECOVERY_ALLOCATION_PROOF_UP: &str =
    include_str!("../../../migrations/20260828000400_recovery_challenge_allocation_proof/up.sql");
const RECOVERY_ALLOCATION_PROOF_DOWN: &str =
    include_str!("../../../migrations/20260828000400_recovery_challenge_allocation_proof/down.sql");
const RECOVERY_ROOT_KEY_HISTORY_UP: &str =
    include_str!("../../../migrations/20260828000500_recovery_root_key_history/up.sql");
const RECOVERY_ROOT_KEY_HISTORY_DOWN: &str =
    include_str!("../../../migrations/20260828000500_recovery_root_key_history/down.sql");
const LEGACY_PERSISTED_SECURITY_STATE_CUT_UP: &str = include_str!(
    "../../../migrations/20260828000600_remove_legacy_persisted_security_state/up.sql"
);
const LEGACY_PERSISTED_SECURITY_STATE_CUT_DOWN: &str = include_str!(
    "../../../migrations/20260828000600_remove_legacy_persisted_security_state/down.sql"
);
const TENANT_RESOURCE_PROVENANCE_CUT_UP: &str = include_str!(
    "../../../migrations/20260828000300_remove_tenant_resource_change_set_provenance/up.sql"
);

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

#[derive(QueryableByName)]
struct BindingIdentity {
    #[diesel(sql_type = Text)]
    resource_id: String,
    #[diesel(sql_type = diesel::sql_types::Bool)]
    active: bool,
}

#[derive(QueryableByName)]
struct BooleanRow {
    #[diesel(sql_type = diesel::sql_types::Bool)]
    value: bool,
}

#[derive(QueryableByName)]
struct CountRow {
    #[diesel(sql_type = BigInt)]
    count: i64,
}

#[derive(QueryableByName)]
struct ExplainRow {
    #[diesel(sql_type = Text, column_name = "QUERY PLAN")]
    query_plan: String,
}

#[test]
fn recovery_root_migration_pins_kdf_ttl_uniqueness_and_fail_closed_downgrade() {
    for required in [
        // Only public material is representable; the derivation parameter set
        // is pinned per row (04A D10).
        "octet_length(recovery_public_key) = 32",
        "kdf = 'hkdf-sha256-v1'",
        "generation >= 1",
        "PRIMARY KEY (deployment_id)",
        // Challenges: fixed short window, single-use, bounded attempts,
        // exactly one pending per deployment, and no root means no challenge.
        "expires_at = created_at + INTERVAL '600 seconds'",
        "consumed_at IS NULL OR consumed_at >= created_at",
        "attempts >= 0 AND attempts <= 64",
        "UNIQUE INDEX ux_controller_recovery_challenges_pending_per_deployment",
        "REFERENCES controller_recovery_roots (deployment_id)",
        "octet_length(nonce) = 32",
    ] {
        assert!(
            RECOVERY_ROOT_UP.contains(required),
            "recovery root migration is missing {required}"
        );
    }
    assert!(
        RECOVERY_ROOT_UP
            .contains("action IN ('bind', 'add', 'rotate', 'revoke', 'recovery-root-rotate')"),
        "the approval catalog must gain the recovery-root-rotate action for D12"
    );
    assert!(
        RECOVERY_ROOT_DOWN.contains("downgrade refused: unconsumed recovery challenges remain"),
        "rollback must fail closed while a recovery is mid-flight"
    );
}

#[test]
fn recovery_root_key_history_backfills_current_keys_and_refuses_downgrade() {
    for required in [
        "PRIMARY KEY (deployment_id, recovery_public_key)",
        "REFERENCES controller_recovery_roots (deployment_id)",
        "octet_length(recovery_public_key) = 32",
        "INSERT INTO controller_recovery_root_key_history",
        "SELECT deployment_id, recovery_public_key, created_at",
    ] {
        assert!(
            RECOVERY_ROOT_KEY_HISTORY_UP.contains(required),
            "Recovery Root key-history migration is missing {required}"
        );
    }
    assert!(
        RECOVERY_ROOT_KEY_HISTORY_DOWN
            .contains("downgrade refused: Recovery Root key history is mandatory")
    );
}

#[test]
fn persisted_security_state_cut_removes_every_legacy_authority() {
    for required in [
        "WITH compromised_families AS",
        "token_family_id IS NOT DISTINCT FROM",
        "ALTER COLUMN token_family_id SET NOT NULL",
        "ALTER COLUMN oidc_auth_context SET NOT NULL",
        "ALTER COLUMN audience DROP DEFAULT",
        "every OAuth client requires an explicit v1 security_policy",
        "ALTER COLUMN security_policy SET NOT NULL",
        "every TOTP credential must already use a complete encrypted envelope",
        "DROP COLUMN secret_base32",
        "desired_mode IN ('enabled', 'disabled')",
        "DROP TABLE runtime_module_default_policy",
    ] {
        assert!(
            LEGACY_PERSISTED_SECURITY_STATE_CUT_UP.contains(required),
            "persisted security-state cut is missing {required}"
        );
    }
    assert!(
        LEGACY_PERSISTED_SECURITY_STATE_CUT_DOWN
            .contains("downgrade refused: legacy persisted security state was permanently removed")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn persisted_security_state_cut_executes_fail_closed_and_establishes_current_invariants() {
    let Some(database_url) = database_url() else {
        return;
    };
    let schema = format!("persisted_security_cut_{}", Uuid::now_v7().simple());
    let mut connection = AsyncPgConnection::establish(&database_url)
        .await
        .expect("test database should connect");
    connection
        .batch_execute(&format!(
            r#"
            CREATE SCHEMA "{schema}";
            SET search_path TO "{schema}", public;

            CREATE TABLE users (id UUID PRIMARY KEY);
            CREATE TABLE oauth_clients (
                id UUID PRIMARY KEY,
                client_id TEXT NOT NULL,
                security_policy JSONB,
                CONSTRAINT ck_oauth_clients_security_policy_object CHECK (
                    security_policy IS NULL OR jsonb_typeof(security_policy) = 'object'
                )
            );
            INSERT INTO oauth_clients VALUES
                ('00000000-0000-0000-0000-000000000021', 'client-a', NULL);

            CREATE TABLE oauth_tokens (
                id UUID PRIMARY KEY,
                tenant_id UUID NOT NULL,
                token_family_id UUID,
                client_id UUID NOT NULL,
                audience JSONB NOT NULL DEFAULT '["resource://default"]'::jsonb,
                oidc_auth_context JSONB,
                issued_at TIMESTAMPTZ NOT NULL
            );
            INSERT INTO oauth_tokens VALUES
                ('00000000-0000-0000-0000-000000000031',
                 '00000000-0000-0000-0000-000000000001',
                 '00000000-0000-7000-8000-000000000031',
                 '00000000-0000-0000-0000-000000000021', '["resource://a"]',
                 '{{"version":1,"issuer":"https://issuer.example","audience":"client-a","auth_time":1577836800,"amr":["pwd"],"oidc_sid":null,"id_token_sid":null,"acr":null,"nonce":null,"userinfo_claims":[],"userinfo_claim_requests":[],"id_token_claims":[],"id_token_claim_requests":[]}}',
                 '2020-01-01T00:00:01Z'),
                ('00000000-0000-0000-0000-000000000032',
                 '00000000-0000-0000-0000-000000000001',
                 '00000000-0000-7000-8000-000000000032',
                 '00000000-0000-0000-0000-000000000021', '["resource://a"]', NULL,
                 '2020-01-01T00:00:01Z'),
                ('00000000-0000-0000-0000-000000000033',
                 '00000000-0000-0000-0000-000000000001',
                 '00000000-0000-7000-8000-000000000032',
                 '00000000-0000-0000-0000-000000000021', '["resource://a"]',
                 '{{"version":1,"issuer":"https://issuer.example","audience":"client-a","auth_time":1577836800,"amr":["pwd"],"oidc_sid":null,"id_token_sid":null,"acr":null,"nonce":null,"userinfo_claims":[],"userinfo_claim_requests":[],"id_token_claims":[],"id_token_claim_requests":[]}}',
                 '2020-01-01T00:00:01Z'),
                ('00000000-0000-0000-0000-000000000034',
                 '00000000-0000-0000-0000-000000000001', NULL,
                 '00000000-0000-0000-0000-000000000021', '["resource://a"]',
                 '{{"version":1,"issuer":"https://issuer.example","audience":"client-a","auth_time":1577836800,"amr":["pwd"],"oidc_sid":null,"id_token_sid":null,"acr":null,"nonce":null,"userinfo_claims":[],"userinfo_claim_requests":[],"id_token_claims":[],"id_token_claim_requests":[]}}',
                 '2020-01-01T00:00:01Z');

            CREATE TABLE user_totp_credentials (
                id UUID PRIMARY KEY,
                secret_base32 TEXT,
                secret_ciphertext BYTEA,
                secret_key_id TEXT,
                CONSTRAINT ck_user_totp_credentials_secret_envelope CHECK (
                    secret_base32 IS NOT NULL
                    OR (secret_ciphertext IS NOT NULL AND secret_key_id IS NOT NULL)
                )
            );
            INSERT INTO user_totp_credentials VALUES
                ('00000000-0000-0000-0000-000000000041', 'JBSWY3DPEHPK3PXP', NULL, NULL);

            CREATE TABLE runtime_module_desired_states (
                module_id VARCHAR(64) PRIMARY KEY,
                desired_mode VARCHAR(16) NOT NULL,
                revision BIGINT NOT NULL,
                actor_id UUID,
                reason VARCHAR(500),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
                CONSTRAINT ck_runtime_module_desired_mode CHECK (
                    desired_mode IN ('inherit', 'enabled', 'disabled')
                )
            );
            CREATE TABLE runtime_module_instance_states (
                instance_id TEXT NOT NULL,
                module_id TEXT NOT NULL
            );
            CREATE TABLE runtime_module_state_events (
                event_id UUID PRIMARY KEY,
                module_id VARCHAR(64) NOT NULL,
                event_type VARCHAR(32) NOT NULL,
                revision BIGINT NOT NULL,
                instance_id VARCHAR(255),
                actor_id UUID,
                reason VARCHAR(500),
                before_state VARCHAR(16),
                after_state VARCHAR(16),
                outcome_code VARCHAR(128),
                occurred_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE runtime_module_default_policy (
                singleton BOOLEAN PRIMARY KEY,
                policy_version BIGINT NOT NULL
            );
            INSERT INTO runtime_module_desired_states (module_id, desired_mode, revision) VALUES
                ('device_authorization', 'enabled', 1),
                ('token_exchange', 'enabled', 1),
                ('jwt_bearer_grant', 'enabled', 1),
                ('ciba', 'enabled', 1),
                ('request_objects', 'enabled', 1),
                ('jarm', 'enabled', 1),
                ('scim', 'enabled', 1),
                ('frontchannel_logout', 'enabled', 1),
                ('session_management', 'enabled', 1),
                ('dynamic_client_registration', 'disabled', 1),
                ('authorization_details', 'disabled', 1),
                ('http_message_signatures', 'disabled', 1),
                ('scim_security_events', 'disabled', 1),
                ('openid4vci_issuer', 'disabled', 1),
                ('openid4vp_verifier', 'disabled', 1),
                ('native_sso', 'disabled', 1);
            "#
        ))
        .await
        .expect("security-state cut fixture should initialize");

    let missing_policy = connection
        .transaction::<(), diesel::result::Error, _>(async |connection| {
            connection
                .batch_execute(LEGACY_PERSISTED_SECURITY_STATE_CUT_UP)
                .await
        })
        .await;
    assert!(
        missing_policy.is_err(),
        "NULL client policy must fail closed"
    );

    connection
        .batch_execute(
            r#"
            UPDATE oauth_clients SET security_policy = '{
              "version":1,"assurance":"baseline",
              "require_signed_authorization_request":false,
              "require_signed_authorization_response":false,
              "require_signed_introspection_response":false,
              "session_management":true,"allow_cross_device_flows":true,
              "allow_confidential_oidc_without_pkce":false
            }';
            "#,
        )
        .await
        .expect("explicit client policy should materialize");
    let plaintext_totp = connection
        .transaction::<(), diesel::result::Error, _>(async |connection| {
            connection
                .batch_execute(LEGACY_PERSISTED_SECURITY_STATE_CUT_UP)
                .await
        })
        .await;
    assert!(plaintext_totp.is_err(), "plaintext TOTP must fail closed");

    connection
        .batch_execute(
            "UPDATE user_totp_credentials SET secret_base32 = NULL, \
             secret_ciphertext = decode('01' || repeat('00', 44), 'hex'), \
             secret_key_id = 'current-key'",
        )
        .await
        .expect("encrypted TOTP pre-cut state should materialize");
    connection
        .batch_execute(LEGACY_PERSISTED_SECURITY_STATE_CUT_UP)
        .await
        .expect("fully materialized current state should cross the hard cut");

    let surviving_tokens = sql_query("SELECT count(*) AS count FROM oauth_tokens")
        .get_result::<CountRow>(&mut connection)
        .await
        .expect("refresh token count should be readable");
    assert_eq!(
        surviving_tokens.count, 1,
        "only the current family may survive"
    );
    let runtime_rows = sql_query(
        "SELECT count(*) AS count FROM runtime_module_desired_states \
         WHERE desired_mode IN ('enabled', 'disabled')",
    )
    .get_result::<CountRow>(&mut connection)
    .await
    .expect("runtime desired-state count should be readable");
    assert_eq!(runtime_rows.count, 16);
    let invented_events = sql_query("SELECT count(*) AS count FROM runtime_module_state_events")
        .get_result::<CountRow>(&mut connection)
        .await
        .expect("runtime audit count should be readable");
    assert_eq!(
        invented_events.count, 0,
        "an existing deployment must retain its audit history without fabricated events"
    );
    let old_runtime_policy =
        sql_query("SELECT to_regclass('runtime_module_default_policy') IS NULL AS value")
            .get_result::<BooleanRow>(&mut connection)
            .await
            .expect("runtime policy catalog should be readable");
    assert!(old_runtime_policy.value);
    let legacy_openid = sql_query(
        "SELECT count(*) AS count FROM openid4vp_transactions \
         WHERE id = '00000000-0000-0000-0000-000000000011'",
    )
    .get_result::<CountRow>(&mut connection)
    .await
    .expect("OpenID4VP lineage should be readable");
    assert_eq!(legacy_openid.count, 0);

    assert!(
        sql_query(
            "INSERT INTO oauth_tokens \
             (id, tenant_id, token_family_id, client_id, audience, oidc_auth_context, issued_at) \
             VALUES (gen_random_uuid(), '00000000-0000-0000-0000-000000000001', \
             gen_random_uuid(), '00000000-0000-0000-0000-000000000021', '[]', NULL, CURRENT_TIMESTAMP)",
        )
        .execute(&mut connection)
        .await
        .is_err(),
        "post-cut schema must reject incomplete refresh contracts"
    );

    connection
        .batch_execute(&format!(
            "SET search_path TO public; DROP SCHEMA \"{schema}\" CASCADE;"
        ))
        .await
        .expect("security-state cut fixture should clean up");
}

#[test]
fn recovery_receipt_migration_binds_exact_retry_to_immutable_result() {
    for required in [
        "accepted_signature_sha256",
        "octet_length(accepted_signature_sha256) = 32",
        "recovered_controller_id",
        "recovered_slot_index BETWEEN 0 AND 2",
        "recovered_slot_issued_at",
        "recovered_slot_expires_at > recovered_slot_issued_at",
        "recovery_generation",
        "REFERENCES controller_registry_slots (deployment_id, controller_id)",
    ] {
        assert!(
            RECOVERY_RECEIPT_UP.contains(required),
            "recovery receipt migration is missing {required}"
        );
    }
}

#[test]
fn recovery_allocation_proof_migration_hard_cuts_unsigned_pending_state() {
    for required in [
        "SET consumed_at = GREATEST(created_at, CURRENT_TIMESTAMP)",
        "WHERE consumed_at IS NULL",
        "ADD COLUMN allocation_nonce BYTEA",
        "uuid_send(challenge_id) || uuid_send(challenge_id)",
        "octet_length(allocation_nonce) = 32",
        "UNIQUE (deployment_id, allocation_nonce)",
    ] {
        assert!(
            RECOVERY_ALLOCATION_PROOF_UP.contains(required),
            "allocation-proof migration is missing {required}"
        );
    }
    assert!(
        RECOVERY_ALLOCATION_PROOF_DOWN
            .contains("downgrade refused: Recovery Root allocation proof is mandatory"),
        "downgrade must not restore the unauthenticated allocation shape"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tenant_resource_provenance_cut_keeps_one_deterministic_binding_and_rejects_ambiguity() {
    let Some(database_url) = database_url() else {
        return;
    };
    let schema = format!("tenant_resource_cut_{}", Uuid::now_v7().simple());
    let mut connection = AsyncPgConnection::establish(&database_url)
        .await
        .expect("test database should connect");
    connection
        .batch_execute(&format!(
            r#"
            CREATE SCHEMA "{schema}";
            SET search_path TO "{schema}";
            CREATE TABLE tenant_resource_bindings (
              id UUID PRIMARY KEY, tenant_id UUID NOT NULL, resource_kind VARCHAR(64) NOT NULL,
              resource_id VARCHAR(255) NOT NULL, resource_digest VARCHAR(64) NOT NULL,
              change_set_id VARCHAR(255) NOT NULL, change_set_sha256 VARCHAR(64) NOT NULL,
              active BOOLEAN NOT NULL, locator TEXT NOT NULL,
              created_at TIMESTAMPTZ NOT NULL, updated_at TIMESTAMPTZ NOT NULL,
              CONSTRAINT uq_tenant_resource_binding_version UNIQUE (tenant_id, resource_kind, resource_id, change_set_id),
              CONSTRAINT ck_tenant_resource_binding_change_set CHECK (change_set_id <> '')
            );
            CREATE UNIQUE INDEX uq_tenant_resource_binding_active
              ON tenant_resource_bindings (tenant_id, resource_kind, resource_id)
              WHERE active;
            INSERT INTO tenant_resource_bindings VALUES
              ('00000000-0000-0000-0000-000000000011','00000000-0000-0000-0000-000000000001','oauth-client','inactive-only','a','old',repeat('0',64),FALSE,'x','2020-01-01','2020-01-01'),
              ('00000000-0000-0000-0000-000000000012','00000000-0000-0000-0000-000000000001','oauth-client','inactive-only','b','new',repeat('1',64),FALSE,'x','2020-01-02','2020-01-02'),
              ('00000000-0000-0000-0000-000000000021','00000000-0000-0000-0000-000000000001','oauth-client','one-active','a','old',repeat('0',64),FALSE,'x','2020-01-01','2020-01-01'),
              ('00000000-0000-0000-0000-000000000022','00000000-0000-0000-0000-000000000001','oauth-client','one-active','b','new',repeat('1',64),TRUE,'x','2020-01-02','2020-01-02');
            "#
        ))
        .await
        .expect("cut fixture should initialize");
    connection
        .batch_execute(TENANT_RESOURCE_PROVENANCE_CUT_UP)
        .await
        .expect("0/1 active rows must migrate");
    let rows =
        sql_query("SELECT resource_id, active FROM tenant_resource_bindings ORDER BY resource_id")
            .load::<BindingIdentity>(&mut connection)
            .await
            .expect("cut rows readable");
    assert_eq!(
        rows.iter()
            .map(|row| (row.resource_id.as_str(), row.active))
            .collect::<Vec<_>>(),
        vec![("inactive-only", false), ("one-active", true)]
    );
    let index_missing =
        sql_query("SELECT to_regclass('uq_tenant_resource_binding_active') IS NULL AS value")
            .get_result::<BooleanRow>(&mut connection)
            .await
            .expect("index catalog should be readable");
    assert!(
        index_missing.value,
        "obsolete active-only index must be removed"
    );
    connection
        .batch_execute(&format!(
            "SET search_path TO public; DROP SCHEMA \"{schema}\" CASCADE;"
        ))
        .await
        .expect("fixture cleanup");

    let schema = format!("tenant_resource_cut_conflict_{}", Uuid::now_v7().simple());
    connection.batch_execute(&format!(r#"
        CREATE SCHEMA "{schema}"; SET search_path TO "{schema}";
        CREATE TABLE tenant_resource_bindings (
          id UUID PRIMARY KEY, tenant_id UUID NOT NULL, resource_kind VARCHAR(64) NOT NULL, resource_id VARCHAR(255) NOT NULL,
          resource_digest VARCHAR(64) NOT NULL, change_set_id VARCHAR(255) NOT NULL, change_set_sha256 VARCHAR(64) NOT NULL,
          active BOOLEAN NOT NULL, locator TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL, updated_at TIMESTAMPTZ NOT NULL,
          CONSTRAINT uq_tenant_resource_binding_version UNIQUE (tenant_id, resource_kind, resource_id, change_set_id),
          CONSTRAINT ck_tenant_resource_binding_change_set CHECK (change_set_id <> '')
        );
        INSERT INTO tenant_resource_bindings VALUES
          ('00000000-0000-0000-0000-000000000031','00000000-0000-0000-0000-000000000001','oauth-client','ambiguous','a',repeat('0',64),repeat('0',64),TRUE,'x',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP),
          ('00000000-0000-0000-0000-000000000032','00000000-0000-0000-0000-000000000001','oauth-client','ambiguous','b',repeat('1',64),repeat('1',64),TRUE,'x',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP);
        "#)).await.expect("ambiguous fixture should initialize");
    assert!(
        connection
            .batch_execute(TENANT_RESOURCE_PROVENANCE_CUT_UP)
            .await
            .is_err(),
        "multiple active historical bindings must fail closed"
    );
    connection
        .batch_execute(&format!(
            "SET search_path TO public; DROP SCHEMA \"{schema}\" CASCADE;"
        ))
        .await
        .expect("conflict fixture cleanup");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn openid4vp_expiry_cleanup_query_is_indexable() {
    let Some(database_url) = database_url() else {
        return;
    };
    nazo_postgres::run_pending_migrations(&database_url)
        .await
        .expect("pending migrations should apply");
    let mut connection = AsyncPgConnection::establish(&database_url)
        .await
        .expect("test database should connect");
    connection
        .batch_execute("SET enable_seqscan = off")
        .await
        .expect("planner test should disable sequential scans");
    let plan = sql_query(
        "EXPLAIN (COSTS OFF) \
         SELECT id FROM openid4vp_transactions \
         WHERE expires_at <= CURRENT_TIMESTAMP \
         ORDER BY expires_at, id LIMIT 256",
    )
    .load::<ExplainRow>(&mut connection)
    .await
    .expect("cleanup EXPLAIN should succeed")
    .into_iter()
    .map(|row| row.query_plan)
    .collect::<Vec<_>>()
    .join("\n");
    assert!(
        plan.contains("ix_openid4vp_transaction_expiry"),
        "cleanup query must use the transaction expiry index:\n{plan}"
    );
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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

    let explicit_desired = sql_query(
        "SELECT count(*) AS count FROM runtime_module_desired_states \
         WHERE desired_mode IN ('enabled', 'disabled')",
    )
    .get_result::<CountRow>(&mut connection)
    .await
    .expect("explicit runtime baseline should be readable");
    assert_eq!(explicit_desired.count, 16);
    let genesis_audit = sql_query(
        "SELECT count(*) AS count FROM runtime_module_state_events \
         WHERE event_type = 'desired_state_changed' \
           AND revision = 1 AND reason = 'clean install baseline'",
    )
    .get_result::<CountRow>(&mut connection)
    .await
    .expect("runtime genesis audit should be readable");
    assert_eq!(genesis_audit.count, 16);

    let catalog_probe = connection
        .transaction::<(), diesel::result::Error, _>(async |connection| {
            connection
                .batch_execute(
                    r#"
                    INSERT INTO runtime_module_desired_states
                        (tenant_id, module_id, desired_mode, revision)
                    VALUES ('00000000-0000-0000-0000-000000000001', 'scim_security_events', 'disabled', 1)
                    ON CONFLICT (tenant_id, module_id) DO NOTHING;
                    INSERT INTO runtime_module_instance_states
                        (tenant_id, instance_id, module_id, actual_state, transition_revision)
                    VALUES (
                        '00000000-0000-0000-0000-000000000001',
                        'migration-catalog-test-' || gen_random_uuid()::text,
                        'scim_security_events', 'disabled', 1
                    );
                    INSERT INTO runtime_module_state_events
                        (event_id, tenant_id, module_id, event_type, revision)
                    VALUES (
                        gen_random_uuid(), '00000000-0000-0000-0000-000000000001', 'scim_security_events',
                        'transition_completed', 1
                    );
                    "#,
                )
                .await?;
            Err(diesel::result::Error::RollbackTransaction)
        })
        .await;
    assert!(
        matches!(
            catalog_probe,
            Err(diesel::result::Error::RollbackTransaction)
        ),
        "SCIM security-events runtime module should be in every closed catalog: {catalog_probe:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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
