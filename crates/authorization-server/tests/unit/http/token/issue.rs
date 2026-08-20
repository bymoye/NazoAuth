use crate::test_support::TestInfrastructure;

use crate::domain::tenancy::DEFAULT_ORGANIZATION_ID;

use crate::domain::tenancy::DEFAULT_REALM_ID;

use crate::domain::NativeSsoTokenBinding;
use crate::domain::tenancy::DEFAULT_TENANT_ID;

use nazo_auth::OidcClaimRequest;

use nazo_http_actix::OAuthJsonErrorFields;

pub(crate) async fn issue_token_response(
    state: &TestInfrastructure,
    client: &ClientRow,
    issue: TokenIssue,
) -> HttpResponse {
    let service = ServerTokenService::new(
        crate::test_support::token_issuance_repository(state.diesel_db.clone()),
        nazo_valkey::TokenIssuanceStateAdapter::new(&state.valkey_connection()),
        state.keyset.clone(),
    );
    let config = TokenIssuanceConfig::from(state.settings.as_ref());
    let modules = state.active_module_snapshot();
    let authorization = test_support::test_authorization_service(state);
    issue_token_response_with_service(
        &TokenIssuanceContext {
            config: &config,
            modules: &modules,
            authorization: &authorization,
        },
        &service,
        client,
        issue,
    )
    .await
}

async fn issue_token_response_with_grant_for_test(
    state: &TestInfrastructure,
    client: &ClientRow,
    grant_key: &str,
    issue: TokenIssue,
) -> HttpResponse {
    let service = ServerTokenService::new(
        crate::test_support::token_issuance_repository(state.diesel_db.clone()),
        nazo_valkey::TokenIssuanceStateAdapter::new(&state.valkey_connection()),
        state.keyset.clone(),
    );
    let config = TokenIssuanceConfig::from(state.settings.as_ref());
    let modules = state.active_module_snapshot();
    let authorization = test_support::test_authorization_service(state);
    issue_token_response_with_service_and_grant(
        &TokenIssuanceContext {
            config: &config,
            modules: &modules,
            authorization: &authorization,
        },
        &service,
        client,
        Some(grant_key),
        issue,
    )
    .await
}

async fn response_body(response: HttpResponse) -> Vec<u8> {
    actix_web::body::to_bytes(response.into_body())
        .await
        .expect("token response body should collect")
        .to_vec()
}

#[derive(diesel::QueryableByName)]
struct TokenRowCount {
    #[diesel(sql_type = BigInt)]
    count: i64,
}

async fn refresh_token_row_count(state: &TestInfrastructure, client: &ClientRow) -> i64 {
    let mut connection = get_conn(&state.diesel_db)
        .await
        .expect("issue test database connection should be available");
    sql_query(
        "SELECT COUNT(*)::BIGINT AS count FROM oauth_tokens WHERE tenant_id = $1 AND client_id = $2",
    )
    .bind::<SqlUuid, _>(client.tenant_id)
    .bind::<SqlUuid, _>(client.id)
    .get_result::<TokenRowCount>(&mut connection)
    .await
    .expect("refresh token row count should load")
    .count
}

async fn delete_token_issuance(state: &TestInfrastructure, issuance_id: Uuid) {
    let mut connection = get_conn(&state.diesel_db)
        .await
        .expect("issue test database connection should be available for cleanup");
    sql_query("DELETE FROM oauth_token_issuances WHERE issuance_id = $1")
        .bind::<SqlUuid, _>(issuance_id)
        .execute(&mut connection)
        .await
        .expect("issue test token issuance cleanup should succeed");
}

use super::*;
use std::sync::Arc;
use std::time::Duration as StdDuration;

use crate::config::ConfigSource;
use diesel::sql_query;
use diesel::sql_types::{BigInt, Jsonb, Text, Uuid as SqlUuid};
use diesel_async::RunQueryDsl;
use fred::interfaces::ClientLike;
use nazo_postgres::{create_pool, get_conn};

use crate::test_support::client_signing_fixture;
use fred::prelude::{
    Builder as ValkeyBuilder, Config as ValkeyConfig, ConnectionConfig, PerformanceConfig,
};
use nazo_auth::{
    PrepareTokenIssuance, PrepareTokenIssuanceResult, TokenIssuanceClaimResult,
    TokenIssuanceTransitionResult,
};

const LIVE_VALKEY_TIMEOUT: StdDuration = StdDuration::from_secs(5);

/// Seed a durable response for endpoint replay tests.  The HTTP handlers under
/// test must reject a consumed one-time grant even when an old issuance row is
/// present; this helper represents the response that would have been returned
/// by the original successful redemption.
pub(crate) async fn persist_token_issuance_response_for_test(
    state: &TestInfrastructure,
    client: &ClientRow,
    grant_key: &str,
) {
    let service = ServerTokenService::new(
        crate::test_support::token_issuance_repository(state.diesel_db.clone()),
        nazo_valkey::TokenIssuanceStateAdapter::new(&state.valkey_connection()),
        state.keyset.clone(),
    );
    let issuance_id = Uuid::now_v7();
    let request_digest = blake3::hash(format!("test-request-{issuance_id}").as_bytes())
        .to_hex()
        .to_string();
    let expires_at = Utc::now() + chrono::Duration::minutes(5);
    let prepared = service
        .prepare_token_issuance(PrepareTokenIssuance {
            issuance_id,
            tenant_id: client.tenant_id,
            client_id: client.id,
            user_id: None,
            grant_key: grant_key.to_owned(),
            request_digest: request_digest.clone(),
            expires_at,
        })
        .await
        .expect("test token issuance should prepare");
    assert!(matches!(prepared, PrepareTokenIssuanceResult::Created(_)));

    let response_body =
        br#"{"access_token":"replay-fixture","token_type":"Bearer","expires_in":300}"#;
    let response_digest = blake3::hash(response_body).to_hex().to_string();
    let access_token_jti = format!("replay-fixture-{issuance_id}");
    assert_eq!(
        service
            .claim_token_issuance(issuance_id, &request_digest, issuance_id)
            .await
            .expect("test token issuance should claim owner"),
        TokenIssuanceClaimResult::Applied
    );
    assert_eq!(
        service
            .record_token_issuance_signed(nazo_auth::RecordTokenIssuanceSigned {
                issuance_id,
                request_digest: &request_digest,
                claim_owner_id: issuance_id,
                access_token_jti: &access_token_jti,
                access_token_expires_at: expires_at.timestamp(),
                response_body,
                response_digest: &response_digest,
            },)
            .await
            .expect("test token issuance should record signed response"),
        TokenIssuanceTransitionResult::Applied
    );
    assert_eq!(
        service
            .mark_token_issuance_persisted(issuance_id, &request_digest)
            .await
            .expect("test token issuance should mark persisted"),
        TokenIssuanceTransitionResult::Applied
    );
    assert_eq!(
        service
            .mark_token_issuance_delivered(issuance_id, &request_digest)
            .await
            .expect("test token issuance should mark delivered"),
        TokenIssuanceTransitionResult::Applied
    );
}

fn disconnected_valkey_client() -> fred::prelude::Client {
    let mut builder = ValkeyBuilder::default_centralized();
    builder.with_performance_config(|performance: &mut PerformanceConfig| {
        performance.default_command_timeout = StdDuration::from_millis(50);
    });
    builder.with_connection_config(|connection: &mut ConnectionConfig| {
        connection.connection_timeout = StdDuration::from_millis(50);
        connection.internal_command_timeout = StdDuration::from_millis(50);
        connection.max_command_attempts = 1;
    });
    builder
        .build()
        .expect("valkey client construction should not connect")
}

fn live_valkey_client() -> Option<fred::prelude::Client> {
    let valkey_url = std::env::var("VALKEY_URL").ok()?;
    let mut builder =
        ValkeyBuilder::from_config(ValkeyConfig::from_url(&valkey_url).expect("VALKEY_URL"));
    builder.with_performance_config(|performance: &mut PerformanceConfig| {
        performance.default_command_timeout = LIVE_VALKEY_TIMEOUT;
    });
    builder.with_connection_config(|connection: &mut ConnectionConfig| {
        connection.connection_timeout = LIVE_VALKEY_TIMEOUT;
        connection.internal_command_timeout = LIVE_VALKEY_TIMEOUT;
        connection.max_command_attempts = 1;
    });
    Some(builder.build().expect("Valkey client should build"))
}

fn client_with_grants(grant_types: &[&str]) -> ClientRow {
    client_row! {
        id: Uuid::now_v7(),
        tenant_id: DEFAULT_TENANT_ID,
        realm_id: DEFAULT_REALM_ID,
        organization_id: DEFAULT_ORGANIZATION_ID,
        client_id: "client-1".to_owned(),
        client_name: "Client".to_owned(),
        client_type: "public".to_owned(),
        client_secret_hash: None,
        redirect_uris: json!(["https://client.example/callback"]),
        scopes: json!(["openid", "offline_access"]),
        allowed_audiences: json!(["resource://default"]),
        grant_types: json!(grant_types),
        token_endpoint_auth_method: "none".to_owned(),
        require_dpop_bound_tokens: false,
        require_mtls_bound_tokens: false,
        tls_client_auth_subject_dn: None,
        tls_client_auth_cert_sha256: None,
        tls_client_auth_san_dns: json!([]),
        tls_client_auth_san_uri: json!([]),
        tls_client_auth_san_ip: json!([]),
        tls_client_auth_san_email: json!([]),
        allow_client_assertion_audience_array: false,
        allow_client_assertion_endpoint_audience: false,
        require_par_request_object: false,
        is_active: true,
        jwks: None,
        introspection_encrypted_response_alg: None,
        introspection_encrypted_response_enc: None,
        userinfo_signed_response_alg: None,
        userinfo_encrypted_response_alg: None,
        userinfo_encrypted_response_enc: None,
        authorization_signed_response_alg: None,
        authorization_encrypted_response_alg: None,
        authorization_encrypted_response_enc: None,
        post_logout_redirect_uris: json!([]),
        backchannel_logout_uri: None,
        backchannel_logout_session_required: true,
        frontchannel_logout_uri: None,
        frontchannel_logout_session_required: true,
        subject_type: "public".to_owned(),
        sector_identifier_uri: None,
        sector_identifier_host: None,
    }
}

#[test]
fn id_token_signing_alg_uses_rs256_default_and_ps256_for_fapi_clients() {
    let baseline = client_with_grants(&["authorization_code"]);
    assert_eq!(
        id_token_signing_alg_for_client(&baseline),
        jsonwebtoken::Algorithm::RS256
    );

    let mut private_key_jwt = baseline.clone();
    private_key_jwt.token_endpoint_auth_method = "private_key_jwt".to_owned();
    assert_eq!(
        id_token_signing_alg_for_client(&private_key_jwt),
        jsonwebtoken::Algorithm::RS256
    );

    let mut holder_bound = baseline.clone();
    holder_bound.require_dpop_bound_tokens = true;
    assert_eq!(
        id_token_signing_alg_for_client(&holder_bound),
        jsonwebtoken::Algorithm::PS256
    );

    let mut par_request_object = baseline;
    par_request_object.require_par_request_object = true;
    assert_eq!(
        id_token_signing_alg_for_client(&par_request_object),
        jsonwebtoken::Algorithm::PS256
    );

    let mut negotiated = par_request_object;
    negotiated.id_token_signed_response_alg = Some("ES256".to_owned());
    assert_eq!(
        id_token_signing_alg_for_client(&negotiated),
        jsonwebtoken::Algorithm::ES256
    );
}

fn issue_state_with_invalid_signing_key() -> TestInfrastructure {
    TestInfrastructure {
        diesel_db: create_pool(
            "postgres://nazo_issue_test_invalid:nazo_issue_test_invalid@127.0.0.1:1/nazo"
                .to_owned(),
            1,
        )
        .expect("pool construction should not connect"),
        valkey: disconnected_valkey_client(),
        settings: Arc::new(
            Settings::from_config(&ConfigSource::default()).expect("default settings should load"),
        ),
        keyset: crate::test_support::failing_key_manager(),
    }
}

fn issue_state_with_valid_signing_key() -> TestInfrastructure {
    let _key_material = client_signing_fixture(jsonwebtoken::Algorithm::EdDSA);
    TestInfrastructure {
        diesel_db: create_pool(
            "postgres://nazo_issue_test_invalid:nazo_issue_test_invalid@127.0.0.1:1/nazo"
                .to_owned(),
            1,
        )
        .expect("pool construction should not connect"),
        valkey: disconnected_valkey_client(),
        settings: Arc::new(
            Settings::from_config(&ConfigSource::default()).expect("default settings should load"),
        ),
        keyset: crate::test_support::test_key_manager(),
    }
}

async fn insert_issue_user(state: &TestInfrastructure, user_id: Uuid) {
    let mut connection = get_conn(&state.diesel_db)
        .await
        .expect("issue test database connection should be available");
    sql_query("DELETE FROM users WHERE tenant_id = $1 AND id = $2")
        .bind::<SqlUuid, _>(DEFAULT_TENANT_ID)
        .bind::<SqlUuid, _>(user_id)
        .execute(&mut connection)
        .await
        .expect("issue test user cleanup should succeed");
    sql_query(
        "INSERT INTO users (\
            id, tenant_id, realm_id, organization_id, username, email, password_hash,\
            is_active, mfa_enabled, email_verified, role, admin_level\
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, TRUE, FALSE, TRUE, 'user', 0)",
    )
    .bind::<SqlUuid, _>(user_id)
    .bind::<SqlUuid, _>(DEFAULT_TENANT_ID)
    .bind::<SqlUuid, _>(DEFAULT_REALM_ID)
    .bind::<SqlUuid, _>(DEFAULT_ORGANIZATION_ID)
    .bind::<Text, _>(format!("issue-user-{user_id}"))
    .bind::<Text, _>(format!("issue-user-{user_id}@example.test"))
    .bind::<Text, _>("issue-test-password-hash")
    .execute(&mut connection)
    .await
    .expect("issue test user should insert");
}

async fn insert_issue_user_with_invalid_principal_metadata(
    state: &TestInfrastructure,
    user_id: Uuid,
) {
    insert_issue_user(state, user_id).await;
    let mut connection = get_conn(&state.diesel_db)
        .await
        .expect("issue test database connection should be available");
    sql_query("UPDATE users SET role = 'user', admin_level = 1 WHERE tenant_id = $1 AND id = $2")
        .bind::<SqlUuid, _>(DEFAULT_TENANT_ID)
        .bind::<SqlUuid, _>(user_id)
        .execute(&mut connection)
        .await
        .expect("issue test user metadata corruption should succeed");
}

async fn insert_issue_client(state: &TestInfrastructure, client: &ClientRow) {
    let mut connection = get_conn(&state.diesel_db)
        .await
        .expect("issue test database connection should be available");
    sql_query("DELETE FROM oauth_clients WHERE id = $1")
        .bind::<SqlUuid, _>(client.id)
        .execute(&mut connection)
        .await
        .expect("issue test client cleanup should succeed");
    sql_query(
        "INSERT INTO oauth_clients (\
            id, tenant_id, realm_id, organization_id, client_id, client_name, client_type,\
            redirect_uris, scopes, grant_types, token_endpoint_auth_method, is_active\
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, TRUE)",
    )
    .bind::<SqlUuid, _>(client.id)
    .bind::<SqlUuid, _>(client.tenant_id)
    .bind::<SqlUuid, _>(client.realm_id)
    .bind::<SqlUuid, _>(client.organization_id)
    .bind::<Text, _>(&client.client_id)
    .bind::<Text, _>(&client.client_name)
    .bind::<Text, _>(&client.client_type)
    .bind::<Jsonb, _>(serde_json::to_value(&client.redirect_uris).expect("redirect URIs JSON"))
    .bind::<Jsonb, _>(serde_json::to_value(&client.scopes).expect("scopes JSON"))
    .bind::<Jsonb, _>(serde_json::to_value(&client.grant_types).expect("grant types JSON"))
    .bind::<Text, _>(&client.token_endpoint_auth_method)
    .execute(&mut connection)
    .await
    .expect("issue test client should insert");
}

fn issue_state_with_live_database() -> Option<TestInfrastructure> {
    issue_state_with_live_database_pool_size(1)
}

fn issue_state_with_live_database_pool_size(max_size: usize) -> Option<TestInfrastructure> {
    let database_url = std::env::var("DATABASE_URL").ok()?;
    let valkey = live_valkey_client()?;
    let _key_material = client_signing_fixture(jsonwebtoken::Algorithm::EdDSA);
    let diesel_db = create_pool(database_url, max_size).expect("database pool should build");
    crate::test_support::initialize_audit_dependencies(&diesel_db);
    Some(TestInfrastructure {
        diesel_db,
        valkey,
        settings: Arc::new(
            Settings::from_config(&ConfigSource::default()).expect("default settings should load"),
        ),
        // The default OIDC ID-token algorithm is RS256. Keep the live
        // issuance fixture aligned with that protocol default so this test
        // exercises successful signing instead of manufacturing an
        // algorithm/key mismatch (the generic unit fixture intentionally
        // uses EdDSA for failure-path tests).
        keyset: crate::test_support::test_key_manager_with_algorithm(
            jsonwebtoken::Algorithm::RS256,
        ),
    })
}

fn issue_state_with_live_database_and_disconnected_valkey() -> Option<TestInfrastructure> {
    let database_url = std::env::var("DATABASE_URL").ok()?;
    let _key_material = client_signing_fixture(jsonwebtoken::Algorithm::EdDSA);
    let diesel_db = create_pool(database_url, 1).expect("database pool should build");
    crate::test_support::initialize_audit_dependencies(&diesel_db);
    Some(TestInfrastructure {
        diesel_db,
        valkey: disconnected_valkey_client(),
        settings: Arc::new(
            Settings::from_config(&ConfigSource::default()).expect("default settings should load"),
        ),
        keyset: crate::test_support::test_key_manager_with_algorithm(
            jsonwebtoken::Algorithm::RS256,
        ),
    })
}

async fn delete_token_issuance_for_grant(
    state: &TestInfrastructure,
    client: &ClientRow,
    grant_key: &str,
) {
    let service = ServerTokenService::new(
        crate::test_support::token_issuance_repository(state.diesel_db.clone()),
        nazo_valkey::TokenIssuanceStateAdapter::new(&state.valkey_connection()),
        state.keyset.clone(),
    );
    if let Ok(Some(record)) = service
        .token_issuance_by_grant(client.tenant_id, client.id, grant_key)
        .await
    {
        delete_token_issuance(state, record.issuance_id).await;
    }
}

#[test]
fn refresh_token_requires_authorized_use_case_and_client_grant() {
    let client = client_with_grants(&["authorization_code", "refresh_token"]);
    let scopes = vec!["openid".to_owned(), "profile".to_owned()];
    assert!(!should_issue_refresh_token(&client, &scopes, false));

    let scopes = vec!["openid".to_owned(), "offline_access".to_owned()];
    assert!(should_issue_refresh_token(&client, &scopes, false));

    let scopes = vec!["org.iso.18013.5.1.mDL".to_owned()];
    assert!(should_issue_refresh_token(&client, &scopes, true));

    let client = client_with_grants(&["authorization_code"]);
    assert!(!should_issue_refresh_token(&client, &scopes, true));
}

#[test]
fn refresh_token_grant_matching_is_exact_and_scope_case_sensitive() {
    let client = client_with_grants(&["authorization_code", "refresh_token:legacy"]);
    let scopes = vec!["openid".to_owned(), "offline_access".to_owned()];
    assert!(
        !should_issue_refresh_token(&client, &scopes, false),
        "refresh issuance must require the exact refresh_token grant"
    );

    let client = client_with_grants(&["authorization_code", "refresh_token"]);
    for scopes in [
        vec!["openid".to_owned(), "OFFLINE_ACCESS".to_owned()],
        vec!["openid".to_owned(), "offline_access ".to_owned()],
        vec!["openid".to_owned(), "offline".to_owned()],
    ] {
        assert!(
            !should_issue_refresh_token(&client, &scopes, false),
            "refresh issuance must require exact offline_access authorization scope: {scopes:?}"
        );
    }
}

#[test]
fn failed_authorization_code_transition_is_idempotent_only_for_terminal_or_missing_states() {
    for state in ["ok", "missing", "failed", "consumed"] {
        assert!(
            authorization_code_state::failed_authorization_code_transition_result(state).is_ok(),
            "failed marker cleanup should tolerate {state}"
        );
    }

    for state in ["pending", "busy", "malformed"] {
        let error = authorization_code_state::failed_authorization_code_transition_result(state)
            .expect_err("failed marker must not hide an unexpected active state");
        assert!(
            error.to_string().contains(state),
            "error should preserve the unexpected state for diagnostics"
        );
    }
}

#[test]
fn consumed_authorization_code_marker_lives_as_long_as_issued_credentials() {
    let refresh_family_id = Uuid::now_v7();

    assert_eq!(
        authorization_code_state::consumed_authorization_code_ttl_seconds(
            300,
            2_592_000,
            Some(refresh_family_id),
        ),
        2_592_000,
        "authorization code replay marker must not expire before the refresh token family"
    );

    assert_eq!(
        authorization_code_state::consumed_authorization_code_ttl_seconds(300, 2_592_000, None),
        300,
        "without a refresh token family the marker only needs to cover the access token lifetime"
    );
}

#[test]
fn consumed_authorization_code_marker_ttl_fails_closed_for_non_positive_settings() {
    assert_eq!(
        authorization_code_state::consumed_authorization_code_ttl_seconds(0, 2_592_000, None),
        1,
        "zero access-token TTL settings must still leave a replay marker"
    );

    assert_eq!(
        authorization_code_state::consumed_authorization_code_ttl_seconds(
            300,
            -10,
            Some(Uuid::now_v7())
        ),
        1,
        "invalid refresh-token TTL settings must not produce an absent or already-expired marker"
    );
}

fn token_issue_with_sid(id_token_claims: Vec<String>) -> TokenIssue {
    TokenIssue {
        user_id: None,
        subject: "subject-1".to_owned(),
        scopes: vec!["openid".to_owned()],
        authorization_details: json!([]),
        audiences: vec!["resource://default".to_owned()],
        nonce: None,
        auth_time: Some(1_000),
        amr: vec!["password".to_owned()],
        oidc_sid: Some("op-session-sid".to_owned()),
        acr: None,
        userinfo_claims: Vec::new(),
        userinfo_claim_requests: Vec::new(),
        id_token_claims,
        id_token_claim_requests: Vec::new(),
        refresh_id_token_sid: None,
        include_refresh: false,
        refresh_token_policy: RefreshTokenPolicy::IssueNew,
        dpop_jkt: None,
        refresh_token_dpop_jkt: None,
        mtls_x5t_s256: None,
        refresh_token_mtls_x5t_s256: None,
        refresh_token_client_attestation_jkt: None,
        refresh_token_scopes: None,
        authorization_code_hash: None,
        actor: None,
        issued_token_type: None,
        native_sso: None,
    }
}

fn token_issue_without_openid() -> TokenIssue {
    TokenIssue {
        user_id: None,
        subject: "subject-1".to_owned(),
        scopes: vec!["accounts".to_owned()],
        authorization_details: json!([]),
        audiences: vec!["resource://default".to_owned()],
        nonce: None,
        auth_time: Some(1_000),
        amr: vec!["password".to_owned()],
        oidc_sid: None,
        acr: None,
        userinfo_claims: Vec::new(),
        userinfo_claim_requests: Vec::new(),
        id_token_claims: Vec::new(),
        id_token_claim_requests: Vec::new(),
        refresh_id_token_sid: None,
        include_refresh: true,
        refresh_token_policy: RefreshTokenPolicy::IssueNew,
        dpop_jkt: None,
        refresh_token_dpop_jkt: None,
        mtls_x5t_s256: None,
        refresh_token_mtls_x5t_s256: None,
        refresh_token_client_attestation_jkt: None,
        refresh_token_scopes: None,
        authorization_code_hash: None,
        actor: None,
        issued_token_type: None,
        native_sso: None,
    }
}

#[test]
fn issuance_digest_binds_every_result_affecting_grant_identity() {
    let client = client_with_grants(&["urn:ietf:params:oauth:grant-type:token-exchange"]);
    let grant_key = "idempotency:stable-grant";
    let baseline = issuance_request_digest(&client, &token_issue_without_openid(), grant_key);

    let mut actor_changed = token_issue_without_openid();
    actor_changed.actor = Some(json!({
        "sub": "delegating-actor",
        "client_id": "actor-client",
    }));
    assert_ne!(
        issuance_request_digest(&client, &actor_changed, grant_key),
        baseline,
        "RFC 8693 actor identity must not reuse another actor's issued response",
    );

    let mut authorization_code_changed = token_issue_without_openid();
    authorization_code_changed.authorization_code_hash = Some("code-hash".to_owned());
    assert_ne!(
        issuance_request_digest(&client, &authorization_code_changed, grant_key),
        baseline,
        "authorization-code consumption identity must be bound to the issuance",
    );

    let mut refresh_policy_changed = token_issue_without_openid();
    refresh_policy_changed.refresh_token_policy = RefreshTokenPolicy::Rotate {
        family_id: Uuid::now_v7(),
        rotated_from_id: Uuid::now_v7(),
    };
    assert_ne!(
        issuance_request_digest(&client, &refresh_policy_changed, grant_key),
        baseline,
        "refresh rotation identity must not reuse a non-rotation response",
    );

    let mut native_sso_changed = token_issue_without_openid();
    native_sso_changed.native_sso = Some(NativeSsoTokenBinding {
        device_secret: "device-secret".to_owned(),
        ds_hash: "device-secret-hash".to_owned(),
        sid: "native-sso-session".to_owned(),
    });
    assert_ne!(
        issuance_request_digest(&client, &native_sso_changed, grant_key),
        baseline,
        "Native SSO device binding must not reuse an ordinary token response",
    );

    let native_sso_digest = issuance_request_digest(&client, &native_sso_changed, grant_key);
    native_sso_changed.native_sso = Some(NativeSsoTokenBinding {
        device_secret: "fresh-device-secret-from-retry".to_owned(),
        ds_hash: "fresh-device-secret-hash-from-retry".to_owned(),
        sid: "native-sso-session".to_owned(),
    });
    assert_eq!(
        issuance_request_digest(&client, &native_sso_changed, grant_key),
        native_sso_digest,
        "server-generated Native SSO secret material must not break idempotent retries",
    );

    native_sso_changed
        .native_sso
        .as_mut()
        .expect("Native SSO binding should remain present")
        .sid = "different-native-sso-session".to_owned();
    assert_ne!(
        issuance_request_digest(&client, &native_sso_changed, grant_key),
        native_sso_digest,
        "a different Native SSO session must not reuse another session's response",
    );
}

fn oauth_error_code(response: &HttpResponse) -> String {
    response
        .extensions()
        .get::<OAuthJsonErrorFields>()
        .map(|fields| fields.error.clone())
        .expect("OAuth error response should record its error code")
}

#[test]
fn id_token_sid_is_omitted_unless_explicitly_requested() {
    let client = client_with_grants(&["authorization_code"]);
    let issue = token_issue_with_sid(Vec::new());
    assert_eq!(id_token_session_sid(&client, &issue, false), None);

    let issue = token_issue_with_sid(vec!["sid".to_owned()]);
    assert_eq!(
        id_token_session_sid(&client, &issue, false),
        Some("op-session-sid")
    );
}

#[test]
fn id_token_sid_is_included_for_session_bound_logout_clients() {
    let issue = token_issue_with_sid(Vec::new());

    let mut frontchannel_client = client_with_grants(&["authorization_code"]);
    frontchannel_client.frontchannel_logout_uri = Some("https://client.example/logout".to_owned());
    assert_eq!(
        id_token_session_sid(&frontchannel_client, &issue, true),
        Some("op-session-sid")
    );

    let mut backchannel_client = client_with_grants(&["authorization_code"]);
    backchannel_client.backchannel_logout_uri =
        Some("https://client.example/backchannel".to_owned());
    assert_eq!(
        id_token_session_sid(&backchannel_client, &issue, false),
        Some("op-session-sid")
    );
}

#[test]
fn id_token_sid_is_not_enabled_for_all_clients_by_logout_feature_flags() {
    let client = client_with_grants(&["authorization_code"]);
    let issue = token_issue_with_sid(Vec::new());

    assert_eq!(id_token_session_sid(&client, &issue, true), None);
}

#[test]
fn id_token_sid_request_object_also_allows_session_sid() {
    let client = client_with_grants(&["authorization_code"]);
    let mut issue = token_issue_with_sid(Vec::new());
    issue.id_token_claim_requests.push(OidcClaimRequest {
        name: "sid".to_owned(),
        essential: true,
        value: None,
        values: Vec::new(),
    });

    assert_eq!(
        id_token_session_sid(&client, &issue, false),
        Some("op-session-sid")
    );
}

#[test]
fn refresh_id_token_sid_contract_distinguishes_presence_and_original_omission() {
    let client = client_with_grants(&["authorization_code"]);
    let mut issue = token_issue_with_sid(Vec::new());
    issue.refresh_id_token_sid = Some(Some("native-sso-sid".to_owned()));
    assert_eq!(
        id_token_session_sid(&client, &issue, false),
        Some("native-sso-sid")
    );

    issue.refresh_id_token_sid = Some(None);
    assert_eq!(id_token_session_sid(&client, &issue, false), None);
}

#[test]
fn refresh_without_id_token_preserves_the_original_sid_contract() {
    let mut issue = token_issue_with_sid(Vec::new());
    issue.refresh_id_token_sid = Some(Some("original-sid".to_owned()));

    assert_eq!(persisted_id_token_sid(&issue, None), Some("original-sid"));
    assert_eq!(
        persisted_id_token_sid(&issue, Some("new-sid")),
        Some("new-sid")
    );
}

#[test]
fn essential_id_token_claim_requests_match_protocol_claim_values() {
    let client = client_with_grants(&["authorization_code"]);
    let mut issue = token_issue_with_sid(Vec::new());
    issue.acr = Some("urn:example:loa:2".to_owned());
    issue.id_token_claim_requests = vec![
        OidcClaimRequest {
            name: "auth_time".to_owned(),
            essential: true,
            value: Some(json!(1_000)),
            values: Vec::new(),
        },
        OidcClaimRequest {
            name: "amr".to_owned(),
            essential: true,
            value: None,
            values: vec![json!(["password"]), json!(["password", "otp"])],
        },
        OidcClaimRequest {
            name: "acr".to_owned(),
            essential: true,
            value: Some(json!("urn:example:loa:2")),
            values: Vec::new(),
        },
        OidcClaimRequest {
            name: "sid".to_owned(),
            essential: true,
            value: None,
            values: Vec::new(),
        },
        OidcClaimRequest {
            name: "department".to_owned(),
            essential: true,
            value: None,
            values: vec![json!("engineering"), json!("security")],
        },
    ];
    let extra_claims = json!({"department": "engineering"});

    assert!(refreshed_id_token_essential_claims_satisfied(
        &issue,
        &client,
        false,
        Some(&extra_claims),
    ));

    assert!(claim_request_value_matches(
        &OidcClaimRequest {
            name: "department".to_owned(),
            essential: true,
            value: None,
            values: Vec::new(),
        },
        &json!("anything"),
    ));
    assert!(!claim_request_value_matches(
        &OidcClaimRequest {
            name: "department".to_owned(),
            essential: true,
            value: Some(json!("finance")),
            values: Vec::new(),
        },
        &json!("engineering"),
    ));
    assert!(!claim_request_value_matches(
        &OidcClaimRequest {
            name: "department".to_owned(),
            essential: true,
            value: None,
            values: vec![json!("finance")],
        },
        &json!("engineering"),
    ));

    issue.acr = Some("urn:example:loa:1".to_owned());
    assert!(!refreshed_id_token_essential_claims_satisfied(
        &issue,
        &client,
        false,
        Some(&extra_claims),
    ));
}

#[test]
fn request_idempotency_key_trims_and_rejects_invalid_values() {
    let missing = actix_web::test::TestRequest::get().to_http_request();
    assert_eq!(request_idempotency_key(&missing), None);

    let blank = actix_web::test::TestRequest::get()
        .insert_header(("idempotency-key", "   "))
        .to_http_request();
    assert_eq!(request_idempotency_key(&blank), None);

    let valid = actix_web::test::TestRequest::get()
        .insert_header(("idempotency-key", "  stable-grant  "))
        .to_http_request();
    let key = request_idempotency_key(&valid).expect("trimmed idempotency key should be accepted");
    assert!(key.starts_with("idempotency:"));
    assert_ne!(key, "idempotency:stable-grant");

    let too_long = "x".repeat(257);
    let too_long_request = actix_web::test::TestRequest::get()
        .insert_header(("idempotency-key", too_long))
        .to_http_request();
    assert_eq!(request_idempotency_key(&too_long_request), None);
}

#[test]
fn response_from_token_issuance_requires_a_signed_terminal_phase_and_matching_digest() {
    let mut record = TokenIssuanceRecord {
        issuance_id: Uuid::now_v7(),
        tenant_id: DEFAULT_TENANT_ID,
        client_id: Uuid::now_v7(),
        user_id: None,
        grant_key: "grant".to_owned(),
        request_digest: "digest".to_owned(),
        phase: TokenIssuancePhase::Prepared,
        claim_owner_id: None,
        access_token_jti: None,
        access_token_expires_at: None,
        response_body: Some(br#"{}"#.to_vec()),
        response_digest: None,
        response_key_version: None,
    };
    assert!(response_from_token_issuance(&record).is_none());

    record.phase = TokenIssuancePhase::Signed;
    let response = response_from_token_issuance(&record)
        .expect("signed issuance with a response body should be recoverable");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    assert!(matching_response_from_token_issuance(&record, "different-digest").is_none());
    assert!(matching_response_from_token_issuance(&record, "digest").is_some());

    record.response_body = None;
    assert!(response_from_token_issuance(&record).is_none());
}

#[actix_web::test]
async fn signing_failure_does_not_issue_any_tokens() {
    let Some(mut state) = issue_state_with_live_database() else {
        return;
    };
    state.keyset = crate::test_support::failing_key_manager();
    let mut client = client_with_grants(&["authorization_code", "refresh_token"]);
    client.client_type = "confidential".to_owned();
    client.token_endpoint_auth_method = "client_secret_basic".to_owned();
    let issue = token_issue_without_openid();

    let response = issue_token_response(&state, &client, issue).await;

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(oauth_error_code(&response), "server_error");
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        HeaderValue::from_static("no-store")
    );
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("response body should collect");
    let value: Value = serde_json::from_slice(&body).expect("OAuth error body should be JSON");
    assert_eq!(value.get("error"), Some(&json!("server_error")));
    assert!(value.get("access_token").is_none());
    assert!(value.get("refresh_token").is_none());
    assert!(value.get("id_token").is_none());
}

#[actix_web::test]
async fn invalid_authorization_details_state_fails_before_token_signing() {
    let state = issue_state_with_invalid_signing_key();
    let client = client_with_grants(&["authorization_code", "refresh_token"]);
    let mut issue = token_issue_without_openid();
    issue.authorization_details = json!({"type": "account_information"});

    let response = issue_token_response(&state, &client, issue).await;

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(oauth_error_code(&response), "server_error");
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("response body should collect");
    let value: Value = serde_json::from_slice(&body).expect("OAuth error body should be JSON");
    assert_eq!(value.get("error"), Some(&json!("server_error")));
    assert!(value.get("access_token").is_none());
    assert!(value.get("refresh_token").is_none());
    assert!(value.get("id_token").is_none());
}

#[actix_web::test]
async fn openid_issue_without_user_subject_fails_before_token_signing() {
    let state = issue_state_with_invalid_signing_key();
    let client = client_with_grants(&["authorization_code"]);
    let mut issue = token_issue_with_sid(Vec::new());
    issue.user_id = None;
    issue.authorization_code_hash = Some("code-hash".to_owned());

    let response = issue_token_response(&state, &client, issue).await;

    let status = response.status();
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("response body should collect");
    let value: Value = serde_json::from_slice(&body).expect("OAuth error body should be JSON");
    assert_eq!(status, StatusCode::BAD_REQUEST, "{value}");
    assert_eq!(value.get("error"), Some(&json!("invalid_grant")));
    assert!(value.get("access_token").is_none());
    assert!(value.get("refresh_token").is_none());
    assert!(value.get("id_token").is_none());
}

#[actix_web::test]
async fn native_sso_issue_fails_closed_when_the_runtime_module_is_disabled() {
    let state = issue_state_with_valid_signing_key();
    let client = client_with_grants(&["authorization_code", "refresh_token"]);
    let mut issue = token_issue_without_openid();
    issue.user_id = Some(Uuid::now_v7());
    issue.scopes = vec!["openid".to_owned(), "offline_access".to_owned()];
    issue.native_sso = Some(NativeSsoTokenBinding {
        device_secret: "device-secret".to_owned(),
        ds_hash: "device-hash".to_owned(),
        sid: "sid-1".to_owned(),
    });

    let response = issue_token_response(&state, &client, issue).await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(oauth_error_code(&response), "invalid_scope");
}

#[actix_web::test]
async fn native_sso_issue_requires_openid_before_token_signing() {
    let mut state = issue_state_with_valid_signing_key();
    Arc::get_mut(&mut state.settings)
        .expect("test state owns its settings")
        .modules
        .enable_native_sso = true;
    let client = client_with_grants(&["authorization_code", "refresh_token"]);
    let mut issue = token_issue_without_openid();
    issue.native_sso = Some(NativeSsoTokenBinding {
        device_secret: "device-secret".to_owned(),
        ds_hash: "device-hash".to_owned(),
        sid: "sid-1".to_owned(),
    });

    let response = issue_token_response(&state, &client, issue).await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(oauth_error_code(&response), "invalid_scope");
}

#[actix_web::test]
async fn client_credentials_issue_returns_minimal_bearer_token_response_without_oidc_artifacts() {
    let Some(state) = issue_state_with_live_database() else {
        return;
    };
    let client = client_with_grants(&["client_credentials"]);
    let mut issue = token_issue_without_openid();
    issue.user_id = None;
    issue.subject = client.client_id.clone();
    issue.scopes = vec!["accounts".to_owned(), "read".to_owned()];
    issue.include_refresh = false;
    issue.auth_time = None;
    issue.amr = Vec::new();

    let response = issue_token_response(&state, &client, issue).await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        HeaderValue::from_static("no-store")
    );
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("response body should collect");
    let value: Value = serde_json::from_slice(&body).expect("token response should be JSON");
    assert_eq!(value["token_type"], "Bearer");
    assert_eq!(
        value["expires_in"],
        state.settings.protocol.access_token_ttl_seconds
    );
    assert_eq!(value["scope"], "accounts read");
    assert!(
        value["access_token"]
            .as_str()
            .is_some_and(|token| !token.is_empty())
    );
    assert!(value.get("id_token").is_none());
    assert!(value.get("refresh_token").is_none());
}

#[actix_web::test]
async fn client_credentials_issue_returns_dpop_and_authorization_details_metadata() {
    let Some(state) = issue_state_with_live_database() else {
        return;
    };
    state
        .valkey
        .init()
        .await
        .expect("live token issuance fixture should connect to Valkey");
    let mut client = client_with_grants(&["client_credentials"]);
    client.client_id = format!("issue-dpop-client-{}", Uuid::now_v7());
    insert_issue_client(&state, &client).await;

    let mut issue = token_issue_without_openid();
    issue.user_id = None;
    issue.subject = client.client_id.clone();
    issue.scopes = vec!["accounts".to_owned()];
    issue.include_refresh = false;
    issue.auth_time = None;
    issue.amr = Vec::new();
    issue.dpop_jkt = Some("dpop-thumbprint".to_owned());
    issue.authorization_details = json!([{"type": "account_information"}]);
    issue.issued_token_type = Some("urn:example:access-token".to_owned());

    let response = issue_token_response(&state, &client, issue).await;
    let has_dpop_nonce = response.headers().get("dpop-nonce").is_some();
    let status = response.status();
    let body = response_body(response).await;

    assert_eq!(
        status,
        StatusCode::OK,
        "live DPoP issuance failed: {}",
        String::from_utf8_lossy(&body)
    );
    assert!(has_dpop_nonce);
    let value: Value = serde_json::from_slice(&body).expect("token response should be JSON");
    assert_eq!(value["token_type"], "DPoP");
    assert_eq!(
        value["authorization_details"],
        json!([{"type": "account_information"}])
    );
    assert_eq!(value["issued_token_type"], "urn:example:access-token");
    assert!(
        value["access_token"]
            .as_str()
            .is_some_and(|token| !token.is_empty())
    );
}

#[actix_web::test]
async fn openid_issue_with_active_user_emits_id_and_refresh_tokens() {
    let Some(state) = issue_state_with_live_database() else {
        return;
    };
    let mut client = client_with_grants(&["authorization_code", "refresh_token"]);
    client.client_id = format!("issue-client-{}", Uuid::now_v7());
    let user_id = Uuid::now_v7();
    insert_issue_client(&state, &client).await;
    insert_issue_user(&state, user_id).await;
    let mut issue = token_issue_with_sid(vec!["sid".to_owned()]);
    issue.user_id = Some(user_id);
    issue.subject = user_id.to_string();
    issue.scopes = vec!["openid".to_owned(), "offline_access".to_owned()];
    issue.include_refresh = true;
    issue.oidc_sid = Some("issue-session-sid".to_owned());

    let response = issue_token_response(&state, &client, issue).await;

    assert_eq!(response.status(), StatusCode::OK);
    let body = response_body(response).await;
    let value: Value = serde_json::from_slice(&body).expect("token response should be JSON");
    assert!(
        value["access_token"]
            .as_str()
            .is_some_and(|token| !token.is_empty())
    );
    assert!(
        value["id_token"]
            .as_str()
            .is_some_and(|token| !token.is_empty())
    );
    assert!(
        value["refresh_token"]
            .as_str()
            .is_some_and(|token| !token.is_empty())
    );
    assert_eq!(value["token_type"], "Bearer");
}

#[actix_web::test]
async fn dpop_nonce_store_failure_stops_token_issue_before_access_token_signing() {
    let state = issue_state_with_valid_signing_key();
    let client = client_with_grants(&["client_credentials"]);
    let mut issue = token_issue_without_openid();
    issue.user_id = None;
    issue.subject = client.client_id.clone();
    issue.scopes = vec!["accounts".to_owned()];
    issue.include_refresh = false;
    issue.dpop_jkt = Some("dpop-thumbprint".to_owned());

    let response = issue_token_response(&state, &client, issue).await;

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(oauth_error_code(&response), "server_error");
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("response body should collect");
    let value: Value = serde_json::from_slice(&body).expect("OAuth error body should be JSON");
    assert!(value.get("access_token").is_none());
    assert!(value.get("refresh_token").is_none());
    assert!(value.get("id_token").is_none());
}

#[actix_web::test]
async fn id_token_subject_load_failure_does_not_issue_oidc_response() {
    let state = issue_state_with_valid_signing_key();
    let client = client_with_grants(&["authorization_code"]);
    let mut issue = token_issue_with_sid(Vec::new());
    issue.user_id = Some(Uuid::now_v7());
    issue.subject = "subject-1".to_owned();
    issue.include_refresh = false;

    let response = issue_token_response(&state, &client, issue).await;

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(oauth_error_code(&response), "server_error");
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("response body should collect");
    let value: Value = serde_json::from_slice(&body).expect("OAuth error body should be JSON");
    assert!(value.get("id_token").is_none());
    assert!(value.get("refresh_token").is_none());
}

#[actix_web::test]
async fn missing_id_token_subject_fails_closed_without_returning_credentials() {
    let Some(state) = issue_state_with_live_database() else {
        return;
    };
    let mut client = client_with_grants(&["authorization_code"]);
    client.client_id = format!("missing-subject-client-{}", Uuid::now_v7());
    insert_issue_client(&state, &client).await;
    let mut issue = token_issue_with_sid(vec!["sid".to_owned()]);
    let missing_user_id = Uuid::now_v7();
    issue.user_id = Some(missing_user_id);
    issue.subject = missing_user_id.to_string();
    issue.include_refresh = false;

    let response = issue_token_response(&state, &client, issue).await;

    let status = response.status();
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("response body should collect");
    let value: Value = serde_json::from_slice(&body).expect("OAuth error body should be JSON");
    assert_eq!(status, StatusCode::BAD_REQUEST, "{value}");
    assert_eq!(value.get("error"), Some(&json!("invalid_grant")));
    assert!(value.get("access_token").is_none());
    assert!(value.get("refresh_token").is_none());
    assert!(value.get("id_token").is_none());
}

#[actix_web::test]
async fn attested_client_refresh_token_requires_client_instance_binding() {
    let mut state = issue_state_with_valid_signing_key();
    Arc::get_mut(&mut state.settings)
        .expect("test state owns its settings")
        .modules
        .enable_openid4vci_issuer = true;
    let mut client = client_with_grants(&["authorization_code", "refresh_token"]);
    client.token_endpoint_auth_method = "attest_jwt_client_auth".to_owned();
    let mut issue = token_issue_without_openid();
    issue.authorization_details = json!([{
        "type": "openid_credential",
        "credential_configuration_id": "org.iso.18013.5.1.mDL"
    }]);
    issue.include_refresh = true;
    issue.refresh_token_client_attestation_jkt = None;

    let response = issue_token_response(&state, &client, issue).await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(oauth_error_code(&response), "invalid_client_attestation");
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("response body should collect");
    let value: Value = serde_json::from_slice(&body).expect("OAuth error body should be JSON");
    assert_eq!(
        value.get("error"),
        Some(&json!("invalid_client_attestation"))
    );
    assert!(value.get("access_token").is_none());
    assert!(value.get("refresh_token").is_none());
    assert!(value.get("id_token").is_none());
}

#[actix_web::test]
async fn refresh_token_persistence_failure_does_not_return_partial_refresh_token() {
    let state = issue_state_with_valid_signing_key();
    let client = client_with_grants(&["client_credentials", "refresh_token"]);
    let mut issue = token_issue_without_openid();
    issue.user_id = None;
    issue.subject = client.client_id.clone();
    issue.scopes = vec!["accounts".to_owned(), "offline_access".to_owned()];
    issue.include_refresh = true;

    let response = issue_token_response(&state, &client, issue).await;

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(oauth_error_code(&response), "server_error");
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("response body should collect");
    let value: Value = serde_json::from_slice(&body).expect("OAuth error body should be JSON");
    assert!(value.get("refresh_token").is_none());
}

#[actix_web::test]
async fn refresh_token_rotation_failure_does_not_return_partial_credentials() {
    let state = issue_state_with_valid_signing_key();
    let client = client_with_grants(&["authorization_code", "refresh_token"]);
    let mut issue = token_issue_without_openid();
    issue.user_id = None;
    issue.subject = client.client_id.clone();
    issue.scopes = vec!["accounts".to_owned(), "offline_access".to_owned()];
    issue.include_refresh = true;
    issue.refresh_token_policy = RefreshTokenPolicy::Rotate {
        family_id: Uuid::now_v7(),
        rotated_from_id: Uuid::now_v7(),
    };

    let response = issue_token_response(&state, &client, issue).await;

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(oauth_error_code(&response), "server_error");
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("response body should collect");
    let value: Value = serde_json::from_slice(&body).expect("OAuth error body should be JSON");
    assert!(value.get("access_token").is_none());
    assert!(value.get("refresh_token").is_none());
    assert!(value.get("id_token").is_none());
}

#[actix_web::test]
async fn consumed_authorization_code_marker_failure_returns_error_after_revocation_attempt() {
    let state = issue_state_with_valid_signing_key();
    let client = client_with_grants(&["authorization_code"]);
    let mut issue = token_issue_without_openid();
    issue.user_id = None;
    issue.subject = "subject-1".to_owned();
    issue.scopes = vec!["accounts".to_owned()];
    issue.include_refresh = false;
    issue.authorization_code_hash = Some("code-hash".to_owned());

    let response = issue_token_response(&state, &client, issue).await;

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(oauth_error_code(&response), "server_error");
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("response body should collect");
    let value: Value = serde_json::from_slice(&body).expect("OAuth error body should be JSON");
    assert!(value.get("access_token").is_none());
    assert!(value.get("refresh_token").is_none());
}

#[actix_web::test]
async fn same_idempotent_grant_retry_reuses_the_persisted_response() {
    let Some(state) = issue_state_with_live_database() else {
        return;
    };
    let client = client_with_grants(&["client_credentials"]);
    let grant_key = format!("idempotent-test-{}", Uuid::now_v7());
    let mut first_issue = token_issue_without_openid();
    first_issue.include_refresh = false;
    let first =
        issue_token_response_with_grant_for_test(&state, &client, &grant_key, first_issue).await;
    assert_eq!(first.status(), StatusCode::OK);
    let first_body = response_body(first).await;

    let mut retry_issue = token_issue_without_openid();
    retry_issue.include_refresh = false;
    let retry =
        issue_token_response_with_grant_for_test(&state, &client, &grant_key, retry_issue).await;
    assert_eq!(retry.status(), StatusCode::OK);
    assert_eq!(response_body(retry).await, first_body);
}

#[actix_web::test]
async fn terminal_issuance_owned_by_another_claim_is_busy() {
    let Some(state) = issue_state_with_live_database() else {
        return;
    };
    let client = client_with_grants(&["client_credentials"]);
    let service = ServerTokenService::new(
        crate::test_support::token_issuance_repository(state.diesel_db.clone()),
        nazo_valkey::TokenIssuanceStateAdapter::new(&state.valkey_connection()),
        state.keyset.clone(),
    );
    let issuance_id = Uuid::now_v7();
    let first_owner_id = Uuid::now_v7();
    let grant_key = format!("terminal-claim-{issuance_id}");
    let request_digest = blake3::hash(issuance_id.as_bytes()).to_hex().to_string();
    let expires_at = Utc::now() + chrono::Duration::minutes(5);
    let response_body = br#"{"access_token":"stable","token_type":"Bearer"}"#;
    let response_digest = blake3::hash(response_body).to_hex().to_string();
    let exercise = async {
        let prepared = service
            .prepare_token_issuance(PrepareTokenIssuance {
                issuance_id,
                tenant_id: client.tenant_id,
                client_id: client.id,
                user_id: None,
                grant_key: grant_key.clone(),
                request_digest: request_digest.clone(),
                expires_at,
            })
            .await
            .map_err(|error| format!("terminal claim fixture should prepare: {error}"))?;
        let first_claim = service
            .claim_token_issuance(issuance_id, &request_digest, first_owner_id)
            .await
            .map_err(|error| format!("first owner should claim issuance: {error}"))?;
        let signed = service
            .record_token_issuance_signed(nazo_auth::RecordTokenIssuanceSigned {
                issuance_id,
                request_digest: &request_digest,
                claim_owner_id: first_owner_id,
                access_token_jti: "terminal-claim-jti",
                access_token_expires_at: expires_at.timestamp(),
                response_body,
                response_digest: &response_digest,
            })
            .await
            .map_err(|error| format!("first owner should persist signed response: {error}"))?;
        let stored = service
            .token_issuance_by_grant(client.tenant_id, client.id, &grant_key)
            .await
            .map_err(|error| format!("signed issuance lookup should succeed: {error}"))?;
        let missing = service
            .token_issuance_by_grant(client.tenant_id, client.id, "missing-grant")
            .await
            .map_err(|error| format!("missing issuance lookup should succeed: {error}"))?;
        let second_claim = service
            .claim_token_issuance(issuance_id, &request_digest, Uuid::now_v7())
            .await
            .map_err(|error| format!("second owner claim should be classified: {error}"))?;
        Ok::<_, String>((prepared, first_claim, signed, stored, missing, second_claim))
    }
    .await;

    delete_token_issuance(&state, issuance_id).await;

    let (prepared, first_claim, signed, stored, missing, second_claim) =
        exercise.unwrap_or_else(|message| panic!("{message}"));
    assert!(matches!(prepared, PrepareTokenIssuanceResult::Created(_)));
    assert_eq!(first_claim, TokenIssuanceClaimResult::Applied);
    assert_eq!(signed, TokenIssuanceTransitionResult::Applied);
    let stored = stored.expect("signed issuance should remain recoverable by grant");
    assert_eq!(stored.issuance_id, issuance_id);
    assert_eq!(stored.request_digest, request_digest);
    assert_eq!(stored.phase, TokenIssuancePhase::Signed);
    assert_eq!(stored.claim_owner_id, Some(first_owner_id));
    assert_eq!(
        stored.response_body.as_deref(),
        Some(response_body.as_slice())
    );
    assert!(missing.is_none());
    assert_eq!(second_claim, TokenIssuanceClaimResult::Busy);
}

#[actix_web::test]
async fn concurrent_prepared_issuance_recovers_the_winning_response() {
    let Some(state) = issue_state_with_live_database_pool_size(4) else {
        return;
    };
    let mut client = client_with_grants(&["client_credentials", "refresh_token"]);
    client.client_id = format!("concurrent-issue-client-{}", Uuid::now_v7());
    insert_issue_client(&state, &client).await;
    let grant_key = format!("conflict-test-{}", Uuid::now_v7());
    let initial_refresh_token_rows = refresh_token_row_count(&state, &client).await;
    let mut first_issue = token_issue_without_openid();
    first_issue.scopes.push("offline_access".to_owned());
    first_issue.include_refresh = true;
    let mut second_issue = token_issue_without_openid();
    second_issue.scopes.push("offline_access".to_owned());
    second_issue.include_refresh = true;
    let request_digest = issuance_request_digest(&client, &first_issue, &grant_key);

    let service = ServerTokenService::new(
        crate::test_support::token_issuance_repository(state.diesel_db.clone()),
        nazo_valkey::TokenIssuanceStateAdapter::new(&state.valkey_connection()),
        state.keyset.clone(),
    );
    let prepared = service
        .prepare_token_issuance(PrepareTokenIssuance {
            issuance_id: Uuid::now_v7(),
            tenant_id: client.tenant_id,
            client_id: client.id,
            user_id: None,
            grant_key: grant_key.clone(),
            request_digest,
            expires_at: Utc::now() + chrono::Duration::minutes(5),
        })
        .await
        .expect("prepared issuance should be stored");
    assert!(matches!(prepared, PrepareTokenIssuanceResult::Created(_)));

    let config = TokenIssuanceConfig::from(state.settings.as_ref());
    let modules = state.active_module_snapshot();
    let authorization = test_support::test_authorization_service(&state);
    let context = TokenIssuanceContext {
        config: &config,
        modules: &modules,
        authorization: &authorization,
    };
    let first_future = issue_token_response_with_service_and_grant(
        &context,
        &service,
        &client,
        Some(&grant_key),
        first_issue,
    );
    let second_future = issue_token_response_with_service_and_grant(
        &context,
        &service,
        &client,
        Some(&grant_key),
        second_issue,
    );
    let (first, second) = tokio::join!(first_future, second_future);

    assert_eq!(first.status(), StatusCode::OK);
    assert_eq!(second.status(), StatusCode::OK);
    assert_eq!(response_body(first).await, response_body(second).await);
    assert_eq!(
        refresh_token_row_count(&state, &client).await,
        initial_refresh_token_rows + 1,
        "one stable grant must persist only one refresh-token row",
    );
}

#[actix_web::test]
async fn prepared_issuance_rejects_a_different_request_digest_for_the_same_grant() {
    let Some(state) = issue_state_with_live_database() else {
        return;
    };
    let client = client_with_grants(&["client_credentials"]);
    let grant_key = format!("digest-conflict-{}", Uuid::now_v7());
    let first_issue = token_issue_without_openid();
    let request_digest = issuance_request_digest(&client, &first_issue, &grant_key);
    let service = ServerTokenService::new(
        crate::test_support::token_issuance_repository(state.diesel_db.clone()),
        nazo_valkey::TokenIssuanceStateAdapter::new(&state.valkey_connection()),
        state.keyset.clone(),
    );
    let prepared = service
        .prepare_token_issuance(PrepareTokenIssuance {
            issuance_id: Uuid::now_v7(),
            tenant_id: client.tenant_id,
            client_id: client.id,
            user_id: None,
            grant_key: grant_key.clone(),
            request_digest,
            expires_at: Utc::now() + chrono::Duration::minutes(5),
        })
        .await
        .expect("initial issuance should prepare");
    assert!(matches!(prepared, PrepareTokenIssuanceResult::Created(_)));

    let mut conflicting_issue = first_issue;
    conflicting_issue.subject = "different-subject".to_owned();
    let response =
        issue_token_response_with_grant_for_test(&state, &client, &grant_key, conflicting_issue)
            .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(oauth_error_code(&response), "invalid_grant");
    assert!(!response_body(response).await.is_empty());
}

#[actix_web::test]
async fn refresh_issue_rejects_missing_essential_id_token_claims() {
    let Some(state) = issue_state_with_live_database() else {
        return;
    };
    let mut client = client_with_grants(&["authorization_code"]);
    client.client_id = format!("issue-essential-{}", Uuid::now_v7());
    let user_id = Uuid::now_v7();
    insert_issue_client(&state, &client).await;
    insert_issue_user(&state, user_id).await;

    let mut issue = token_issue_with_sid(Vec::new());
    issue.user_id = Some(user_id);
    issue.subject = user_id.to_string();
    issue.refresh_token_scopes = Some(vec!["openid".to_owned()]);
    issue.id_token_claim_requests = vec![OidcClaimRequest {
        name: "department".to_owned(),
        essential: true,
        value: None,
        values: Vec::new(),
    }];

    let response = issue_token_response(&state, &client, issue).await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(oauth_error_code(&response), "invalid_grant");
    let value: Value = serde_json::from_slice(&response_body(response).await)
        .expect("OAuth error body should be JSON");
    assert_eq!(value["error"], "invalid_grant");
    assert!(value.get("id_token").is_none());
}

#[actix_web::test]
async fn id_token_signing_failure_does_not_issue_oidc_credentials() {
    let Some(mut state) = issue_state_with_live_database() else {
        return;
    };
    let _key_material = client_signing_fixture(jsonwebtoken::Algorithm::EdDSA);
    state.keyset = crate::test_support::test_key_manager();
    let mut client = client_with_grants(&["authorization_code"]);
    client.client_id = format!("issue-id-sign-{}", Uuid::now_v7());
    let user_id = Uuid::now_v7();
    insert_issue_client(&state, &client).await;
    insert_issue_user(&state, user_id).await;

    let mut issue = token_issue_with_sid(Vec::new());
    issue.user_id = Some(user_id);
    issue.subject = user_id.to_string();

    let response = issue_token_response(&state, &client, issue).await;

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(oauth_error_code(&response), "server_error");
    let value: Value = serde_json::from_slice(&response_body(response).await)
        .expect("OAuth error body should be JSON");
    assert_eq!(value["error"], "server_error");
    assert!(value.get("id_token").is_none());
}

#[actix_web::test]
async fn id_token_encryption_failure_does_not_issue_an_unencrypted_token() {
    let Some(state) = issue_state_with_live_database() else {
        return;
    };
    let mut client = client_with_grants(&["authorization_code"]);
    client.client_id = format!("issue-id-encrypt-{}", Uuid::now_v7());
    client.id_token_encrypted_response_alg = Some("RSA-OAEP-256".to_owned());
    client.id_token_encrypted_response_enc = Some("A256GCM".to_owned());
    client.jwks = Some(json!({
        "keys": [{"kty": "RSA", "use": "enc", "alg": "RSA-OAEP-256"}]
    }));
    let user_id = Uuid::now_v7();
    insert_issue_client(&state, &client).await;
    insert_issue_user(&state, user_id).await;

    let mut issue = token_issue_with_sid(Vec::new());
    issue.user_id = Some(user_id);
    issue.subject = user_id.to_string();

    let response = issue_token_response(&state, &client, issue).await;

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(oauth_error_code(&response), "server_error");
    let value: Value = serde_json::from_slice(&response_body(response).await)
        .expect("OAuth error body should be JSON");
    assert_eq!(value["error"], "server_error");
    assert!(value.get("id_token").is_none());
}

#[actix_web::test]
async fn native_sso_issue_requires_a_refresh_session_before_persisting_device_state() {
    let Some(mut state) = issue_state_with_live_database() else {
        return;
    };
    Arc::get_mut(&mut state.settings)
        .expect("test state owns its settings")
        .modules
        .enable_native_sso = true;
    let mut client = client_with_grants(&["authorization_code"]);
    client.client_id = format!("issue-native-missing-refresh-{}", Uuid::now_v7());
    let user_id = Uuid::now_v7();
    insert_issue_client(&state, &client).await;
    insert_issue_user(&state, user_id).await;

    let mut issue = token_issue_with_sid(vec!["sid".to_owned()]);
    issue.user_id = Some(user_id);
    issue.subject = user_id.to_string();
    issue.native_sso = Some(NativeSsoTokenBinding {
        device_secret: format!("device-secret-{}", Uuid::now_v7()),
        ds_hash: "device-hash".to_owned(),
        sid: "native-sso-sid".to_owned(),
    });

    let response = issue_token_response(&state, &client, issue).await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(oauth_error_code(&response), "invalid_grant");
    let value: Value = serde_json::from_slice(&response_body(response).await)
        .expect("OAuth error body should be JSON");
    assert_eq!(value["error"], "invalid_grant");
    assert!(value.get("device_secret").is_none());
}

#[actix_web::test]
async fn native_sso_issue_persists_device_state_with_the_refresh_family() {
    let Some(mut state) = issue_state_with_live_database() else {
        return;
    };
    state
        .valkey
        .init()
        .await
        .expect("live Native SSO fixture should connect to Valkey");
    Arc::get_mut(&mut state.settings)
        .expect("test state owns its settings")
        .modules
        .enable_native_sso = true;
    let mut client = client_with_grants(&["authorization_code", "refresh_token"]);
    client.client_id = format!("issue-native-success-{}", Uuid::now_v7());
    let user_id = Uuid::now_v7();
    insert_issue_client(&state, &client).await;
    insert_issue_user(&state, user_id).await;

    let device_secret = format!("device-secret-{}", Uuid::now_v7());
    let mut issue = token_issue_with_sid(vec!["sid".to_owned()]);
    issue.user_id = Some(user_id);
    issue.subject = user_id.to_string();
    issue.scopes = vec!["openid".to_owned(), "offline_access".to_owned()];
    issue.include_refresh = true;
    issue.native_sso = Some(NativeSsoTokenBinding {
        device_secret: device_secret.clone(),
        ds_hash: "device-hash".to_owned(),
        sid: "native-sso-sid".to_owned(),
    });

    let response = issue_token_response(&state, &client, issue).await;

    assert_eq!(response.status(), StatusCode::OK);
    let value: Value = serde_json::from_slice(&response_body(response).await)
        .expect("token response should be JSON");
    assert_eq!(value["device_secret"], device_secret);
    assert!(
        value["access_token"]
            .as_str()
            .is_some_and(|token| !token.is_empty())
    );
    assert!(
        value["id_token"]
            .as_str()
            .is_some_and(|token| !token.is_empty())
    );
    assert!(
        value["refresh_token"]
            .as_str()
            .is_some_and(|token| !token.is_empty())
    );
}

#[actix_web::test]
async fn authorization_code_marker_failure_revokes_the_issued_access_token() {
    let Some(state) = issue_state_with_live_database() else {
        return;
    };
    state
        .valkey
        .init()
        .await
        .expect("live authorization-code fixture should connect to Valkey");
    let client = client_with_grants(&["client_credentials"]);
    let mut issue = token_issue_without_openid();
    issue.user_id = None;
    issue.subject = client.client_id.clone();
    issue.scopes = vec!["accounts".to_owned()];
    issue.include_refresh = false;
    issue.authorization_code_hash = Some(format!("missing-code-{}", Uuid::now_v7()));

    let response = issue_token_response(&state, &client, issue).await;

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(oauth_error_code(&response), "server_error");
    let value: Value = serde_json::from_slice(&response_body(response).await)
        .expect("OAuth error body should be JSON");
    assert_eq!(value["error"], "server_error");
    assert!(value.get("access_token").is_none());
}

#[actix_web::test]
async fn refresh_rotation_conflict_fails_closed_without_returning_credentials() {
    let Some(state) = issue_state_with_live_database() else {
        return;
    };
    let mut client = client_with_grants(&["authorization_code", "refresh_token"]);
    client.client_id = format!("issue-rotation-conflict-{}", Uuid::now_v7());
    insert_issue_client(&state, &client).await;

    let mut issue = token_issue_without_openid();
    issue.user_id = None;
    issue.subject = client.client_id.clone();
    issue.scopes = vec!["accounts".to_owned(), "offline_access".to_owned()];
    issue.include_refresh = true;
    issue.refresh_token_policy = RefreshTokenPolicy::Rotate {
        family_id: Uuid::now_v7(),
        rotated_from_id: Uuid::now_v7(),
    };

    let response = issue_token_response(&state, &client, issue).await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(oauth_error_code(&response), "invalid_grant");
    let value: Value = serde_json::from_slice(&response_body(response).await)
        .expect("OAuth error body should be JSON");
    assert_eq!(value["error"], "invalid_grant");
    assert!(value.get("access_token").is_none());
    assert!(value.get("refresh_token").is_none());
}

#[actix_web::test]
async fn busy_prepared_issuance_fails_closed_after_bounded_wait() {
    let Some(state) = issue_state_with_live_database() else {
        return;
    };
    let client = client_with_grants(&["client_credentials"]);
    let grant_key = format!("busy-prepared-{}", Uuid::now_v7());
    let issue = token_issue_without_openid();
    let request_digest = issuance_request_digest(&client, &issue, &grant_key);
    let issuance_id = Uuid::now_v7();
    let service = ServerTokenService::new(
        crate::test_support::token_issuance_repository(state.diesel_db.clone()),
        nazo_valkey::TokenIssuanceStateAdapter::new(&state.valkey_connection()),
        state.keyset.clone(),
    );
    let prepared = service
        .prepare_token_issuance(PrepareTokenIssuance {
            issuance_id,
            tenant_id: client.tenant_id,
            client_id: client.id,
            user_id: None,
            grant_key: grant_key.clone(),
            request_digest,
            expires_at: Utc::now() + chrono::Duration::minutes(5),
        })
        .await
        .expect("busy issuance fixture should prepare");
    assert!(matches!(prepared, PrepareTokenIssuanceResult::Created(_)));
    assert_eq!(
        service
            .claim_token_issuance(
                issuance_id,
                &issuance_request_digest(&client, &issue, &grant_key),
                Uuid::now_v7()
            )
            .await
            .expect("busy issuance fixture should claim"),
        TokenIssuanceClaimResult::Applied
    );

    let response =
        issue_token_response_with_grant_for_test(&state, &client, &grant_key, issue).await;
    delete_token_issuance(&state, issuance_id).await;

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(oauth_error_code(&response), "server_error");
    let value: Value = serde_json::from_slice(&response_body(response).await)
        .expect("OAuth error body should be JSON");
    assert_eq!(value["error"], "server_error");
}

#[actix_web::test]
async fn busy_prepared_issuance_recovers_a_response_persisted_by_the_owner() {
    let Some(state) = issue_state_with_live_database_pool_size(2) else {
        return;
    };
    let client = client_with_grants(&["client_credentials"]);
    let grant_key = format!("busy-recovery-{}", Uuid::now_v7());
    let issue = token_issue_without_openid();
    let request_digest = issuance_request_digest(&client, &issue, &grant_key);
    let issuance_id = Uuid::now_v7();
    let owner_id = Uuid::now_v7();
    let expires_at = Utc::now() + chrono::Duration::minutes(5);
    let owner_response_body = br#"{"access_token":"owner-response","token_type":"Bearer"}"#;
    let response_digest = blake3::hash(owner_response_body).to_hex().to_string();
    let service = ServerTokenService::new(
        crate::test_support::token_issuance_repository(state.diesel_db.clone()),
        nazo_valkey::TokenIssuanceStateAdapter::new(&state.valkey_connection()),
        state.keyset.clone(),
    );
    let prepared = service
        .prepare_token_issuance(PrepareTokenIssuance {
            issuance_id,
            tenant_id: client.tenant_id,
            client_id: client.id,
            user_id: None,
            grant_key: grant_key.clone(),
            request_digest: request_digest.clone(),
            expires_at,
        })
        .await
        .expect("busy recovery fixture should prepare");
    assert!(matches!(prepared, PrepareTokenIssuanceResult::Created(_)));
    assert_eq!(
        service
            .claim_token_issuance(issuance_id, &request_digest, owner_id)
            .await
            .expect("busy recovery fixture should claim"),
        TokenIssuanceClaimResult::Applied
    );

    let writer_service = ServerTokenService::new(
        crate::test_support::token_issuance_repository(state.diesel_db.clone()),
        nazo_valkey::TokenIssuanceStateAdapter::new(&state.valkey_connection()),
        state.keyset.clone(),
    );
    let writer = async {
        tokio::task::yield_now().await;
        writer_service
            .record_token_issuance_signed(nazo_auth::RecordTokenIssuanceSigned {
                issuance_id,
                request_digest: &request_digest,
                claim_owner_id: owner_id,
                access_token_jti: "owner-jti",
                access_token_expires_at: expires_at.timestamp(),
                response_body: owner_response_body,
                response_digest: &response_digest,
            })
            .await
    };
    let issuer = issue_token_response_with_grant_for_test(&state, &client, &grant_key, issue);
    let (response, signed) = tokio::join!(issuer, writer);
    delete_token_issuance(&state, issuance_id).await;

    assert_eq!(
        signed.expect("owner should persist the response"),
        TokenIssuanceTransitionResult::Applied
    );
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response_body(response).await, owner_response_body.to_vec());
}

#[actix_web::test]
async fn dpop_nonce_failure_is_reported_after_the_issuance_claim() {
    let Some(state) = issue_state_with_live_database_and_disconnected_valkey() else {
        return;
    };
    let client = client_with_grants(&["client_credentials"]);
    let grant_key = format!("dpop-error-{}", Uuid::now_v7());
    let mut issue = token_issue_without_openid();
    issue.user_id = None;
    issue.subject = client.client_id.clone();
    issue.scopes = vec!["accounts".to_owned()];
    issue.include_refresh = false;
    issue.dpop_jkt = Some("dpop-thumbprint".to_owned());

    let response =
        issue_token_response_with_grant_for_test(&state, &client, &grant_key, issue).await;
    delete_token_issuance_for_grant(&state, &client, &grant_key).await;

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(oauth_error_code(&response), "server_error");
    let value: Value = serde_json::from_slice(&response_body(response).await)
        .expect("OAuth error body should be JSON");
    assert_eq!(value["error"], "server_error");
    assert!(value.get("access_token").is_none());
}

#[actix_web::test]
async fn access_token_subject_mapping_failure_fails_closed_before_response_assembly() {
    let Some(state) = issue_state_with_live_database_and_disconnected_valkey() else {
        return;
    };
    let mut client = client_with_grants(&["client_credentials"]);
    client.client_id = format!("subject-map-client-{}", Uuid::now_v7());
    insert_issue_client(&state, &client).await;
    let user_id = Uuid::now_v7();
    insert_issue_user(&state, user_id).await;
    let grant_key = format!("subject-map-error-{}", Uuid::now_v7());
    let mut issue = token_issue_without_openid();
    issue.user_id = Some(user_id);
    issue.subject = "pairwise-subject".to_owned();
    issue.scopes = vec!["accounts".to_owned()];
    issue.include_refresh = false;

    let response =
        issue_token_response_with_grant_for_test(&state, &client, &grant_key, issue).await;
    delete_token_issuance_for_grant(&state, &client, &grant_key).await;

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(oauth_error_code(&response), "server_error");
    let value: Value = serde_json::from_slice(&response_body(response).await)
        .expect("OAuth error body should be JSON");
    assert_eq!(value["error"], "server_error");
    assert!(value.get("access_token").is_none());
}

#[actix_web::test]
async fn malformed_active_subject_claims_fail_closed_before_id_token_signing() {
    let Some(state) = issue_state_with_live_database() else {
        return;
    };
    let mut client = client_with_grants(&["authorization_code"]);
    client.client_id = format!("invalid-subject-claims-{}", Uuid::now_v7());
    let user_id = Uuid::now_v7();
    insert_issue_client(&state, &client).await;
    insert_issue_user_with_invalid_principal_metadata(&state, user_id).await;
    let mut issue = token_issue_with_sid(Vec::new());
    issue.user_id = Some(user_id);
    issue.subject = user_id.to_string();
    issue.include_refresh = false;

    let response = issue_token_response(&state, &client, issue).await;

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(oauth_error_code(&response), "server_error");
    let value: Value = serde_json::from_slice(&response_body(response).await)
        .expect("OAuth error body should be JSON");
    assert_eq!(value["error"], "server_error");
    assert!(value.get("id_token").is_none());
}

#[actix_web::test]
async fn native_sso_device_secret_failure_does_not_return_partial_credentials() {
    let Some(mut state) = issue_state_with_live_database_and_disconnected_valkey() else {
        return;
    };
    Arc::get_mut(&mut state.settings)
        .expect("test state owns its settings")
        .modules
        .enable_native_sso = true;
    let mut client = client_with_grants(&["authorization_code", "refresh_token"]);
    client.client_id = format!("native-sso-store-error-{}", Uuid::now_v7());
    let user_id = Uuid::now_v7();
    insert_issue_client(&state, &client).await;
    insert_issue_user(&state, user_id).await;

    let mut issue = token_issue_with_sid(vec!["sid".to_owned()]);
    issue.user_id = Some(user_id);
    issue.subject = user_id.to_string();
    issue.scopes = vec!["openid".to_owned(), "offline_access".to_owned()];
    issue.include_refresh = true;
    issue.native_sso = Some(NativeSsoTokenBinding {
        device_secret: format!("device-secret-{}", Uuid::now_v7()),
        ds_hash: "device-hash".to_owned(),
        sid: "native-sso-sid".to_owned(),
    });

    let response = issue_token_response(&state, &client, issue).await;

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(oauth_error_code(&response), "server_error");
    let value: Value = serde_json::from_slice(&response_body(response).await)
        .expect("OAuth error body should be JSON");
    assert_eq!(value["error"], "server_error");
    assert!(value.get("device_secret").is_none());
}

#[actix_web::test]
async fn refresh_issue_new_persistence_failure_uses_non_rotation_error_mapping() {
    let Some(state) = issue_state_with_live_database() else {
        return;
    };
    let mut client = client_with_grants(&["authorization_code", "refresh_token"]);
    client.client_id = format!("refresh-persist-error-{}", Uuid::now_v7());
    insert_issue_client(&state, &client).await;

    let grant_key = format!("refresh-persist-error-{}", Uuid::now_v7());
    let mut issue = token_issue_without_openid();
    issue.user_id = None;
    issue.subject = "s".repeat(129);
    issue.scopes = vec!["accounts".to_owned(), "offline_access".to_owned()];
    issue.include_refresh = true;

    let response =
        issue_token_response_with_grant_for_test(&state, &client, &grant_key, issue).await;
    delete_token_issuance_for_grant(&state, &client, &grant_key).await;

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(oauth_error_code(&response), "server_error");
    let value: Value = serde_json::from_slice(&response_body(response).await)
        .expect("OAuth error body should be JSON");
    assert_eq!(value["error"], "server_error");
    assert!(value.get("refresh_token").is_none());
}
