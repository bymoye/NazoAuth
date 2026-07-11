use super::*;
use std::sync::Arc;
use std::time::Duration as StdDuration;

use crate::config::ConfigSource;
use crate::db::create_pool;
use crate::domain::{ActiveSigningKey, Keyset, KeysetStore};
use crate::support::generate_key_material;
use fred::prelude::{Builder as ValkeyBuilder, ConnectionConfig, PerformanceConfig};

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

fn client_with_grants(grant_types: &[&str]) -> ClientRow {
    ClientRow {
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
        allow_authorization_code_without_pkce: false,
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
        jsonwebtoken::Algorithm::PS256
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
}

fn issue_state_with_invalid_signing_key() -> AppState {
    AppState {
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
        keyset: KeysetStore::new(Keyset {
            active_kid: "test-kid".to_owned(),
            active_alg: jsonwebtoken::Algorithm::EdDSA,
            active_signing_key: ActiveSigningKey::LocalPkcs8Der(Vec::new()),
            verification_keys: Vec::new(),
        }),
    }
}

fn issue_state_with_valid_signing_key() -> AppState {
    let key_material =
        generate_key_material(jsonwebtoken::Algorithm::EdDSA).expect("test key should generate");
    AppState {
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
        keyset: KeysetStore::new(Keyset {
            active_kid: "test-kid".to_owned(),
            active_alg: jsonwebtoken::Algorithm::EdDSA,
            active_signing_key: ActiveSigningKey::LocalPkcs8Der(key_material.private_pkcs8_der),
            verification_keys: Vec::new(),
        }),
    }
}

fn issue_state_with_live_database() -> Option<AppState> {
    let database_url = std::env::var("DATABASE_URL").ok()?;
    let key_material =
        generate_key_material(jsonwebtoken::Algorithm::EdDSA).expect("test key should generate");
    Some(AppState {
        diesel_db: create_pool(database_url, 1).expect("database pool should build"),
        valkey: disconnected_valkey_client(),
        settings: Arc::new(
            Settings::from_config(&ConfigSource::default()).expect("default settings should load"),
        ),
        keyset: KeysetStore::new(Keyset {
            active_kid: "test-kid".to_owned(),
            active_alg: jsonwebtoken::Algorithm::EdDSA,
            active_signing_key: ActiveSigningKey::LocalPkcs8Der(key_material.private_pkcs8_der),
            verification_keys: Vec::new(),
        }),
    })
}

#[test]
fn refresh_token_requires_offline_access_scope_and_client_grant() {
    let client = client_with_grants(&["authorization_code", "refresh_token"]);
    let scopes = vec!["openid".to_owned(), "profile".to_owned()];
    assert!(!should_issue_refresh_token(&client, &scopes));

    let scopes = vec!["openid".to_owned(), "offline_access".to_owned()];
    assert!(should_issue_refresh_token(&client, &scopes));

    let client = client_with_grants(&["authorization_code"]);
    assert!(!should_issue_refresh_token(&client, &scopes));
}

#[test]
fn refresh_token_grant_matching_is_exact_and_scope_case_sensitive() {
    let client = client_with_grants(&["authorization_code", "refresh_token:legacy"]);
    let scopes = vec!["openid".to_owned(), "offline_access".to_owned()];
    assert!(
        !should_issue_refresh_token(&client, &scopes),
        "refresh issuance must require the exact refresh_token grant"
    );

    let client = client_with_grants(&["authorization_code", "refresh_token"]);
    for scopes in [
        vec!["openid".to_owned(), "OFFLINE_ACCESS".to_owned()],
        vec!["openid".to_owned(), "offline_access ".to_owned()],
        vec!["openid".to_owned(), "offline".to_owned()],
    ] {
        assert!(
            !should_issue_refresh_token(&client, &scopes),
            "refresh issuance must require exact offline_access authorization scope: {scopes:?}"
        );
    }
}

#[test]
fn consumed_authorization_code_transition_requires_active_consuming_state() {
    assert!(authorization_code_state::consumed_authorization_code_transition_result("ok").is_ok());

    for state in [
        "missing",
        "pending",
        "consumed",
        "failed",
        "busy",
        "malformed",
    ] {
        let error = authorization_code_state::consumed_authorization_code_transition_result(state)
            .expect_err("non-consuming authorization code state must fail consumed marker write");
        assert!(
            error.to_string().contains(state),
            "error should preserve the unexpected state for diagnostics"
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
        id_token_user: None,
        include_refresh: false,
        refresh_token_policy: RefreshTokenPolicy::IssueNew,
        dpop_jkt: None,
        refresh_token_dpop_jkt: None,
        mtls_x5t_s256: None,
        refresh_token_mtls_x5t_s256: None,
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
        id_token_user: None,
        include_refresh: true,
        refresh_token_policy: RefreshTokenPolicy::IssueNew,
        dpop_jkt: None,
        refresh_token_dpop_jkt: None,
        mtls_x5t_s256: None,
        refresh_token_mtls_x5t_s256: None,
        authorization_code_hash: None,
        actor: None,
        issued_token_type: None,
        native_sso: None,
    }
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
    let settings =
        Settings::from_config(&ConfigSource::default()).expect("default settings should load");
    let client = client_with_grants(&["authorization_code"]);
    let issue = token_issue_with_sid(Vec::new());
    assert_eq!(id_token_session_sid(&settings, &client, &issue), None);

    let issue = token_issue_with_sid(vec!["sid".to_owned()]);
    assert_eq!(
        id_token_session_sid(&settings, &client, &issue),
        Some("op-session-sid")
    );
}

#[test]
fn id_token_sid_is_included_for_session_bound_logout_clients() {
    let issue = token_issue_with_sid(Vec::new());

    let mut frontchannel_settings =
        Settings::from_config(&ConfigSource::default()).expect("default settings should load");
    frontchannel_settings.enable_frontchannel_logout = true;
    let mut frontchannel_client = client_with_grants(&["authorization_code"]);
    frontchannel_client.frontchannel_logout_uri = Some("https://client.example/logout".to_owned());
    assert_eq!(
        id_token_session_sid(&frontchannel_settings, &frontchannel_client, &issue),
        Some("op-session-sid")
    );

    let backchannel_settings =
        Settings::from_config(&ConfigSource::default()).expect("default settings should load");
    let mut backchannel_client = client_with_grants(&["authorization_code"]);
    backchannel_client.backchannel_logout_uri =
        Some("https://client.example/backchannel".to_owned());
    assert_eq!(
        id_token_session_sid(&backchannel_settings, &backchannel_client, &issue),
        Some("op-session-sid")
    );
}

#[test]
fn id_token_sid_is_not_enabled_for_all_clients_by_logout_feature_flags() {
    let mut settings =
        Settings::from_config(&ConfigSource::default()).expect("default settings should load");
    settings.enable_frontchannel_logout = true;
    settings.enable_session_management = true;
    let client = client_with_grants(&["authorization_code"]);
    let issue = token_issue_with_sid(Vec::new());

    assert_eq!(id_token_session_sid(&settings, &client, &issue), None);
}

#[test]
fn id_token_sid_request_object_also_allows_session_sid() {
    let settings =
        Settings::from_config(&ConfigSource::default()).expect("default settings should load");
    let client = client_with_grants(&["authorization_code"]);
    let mut issue = token_issue_with_sid(Vec::new());
    issue.id_token_claim_requests.push(OidcClaimRequest {
        name: "sid".to_owned(),
        essential: true,
        value: None,
        values: Vec::new(),
    });

    assert_eq!(
        id_token_session_sid(&settings, &client, &issue),
        Some("op-session-sid")
    );
}

#[actix_web::test]
async fn signing_failure_does_not_issue_any_tokens() {
    let state = issue_state_with_invalid_signing_key();
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

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(oauth_error_code(&response), "invalid_grant");
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("response body should collect");
    let value: Value = serde_json::from_slice(&body).expect("OAuth error body should be JSON");
    assert_eq!(value.get("error"), Some(&json!("invalid_grant")));
    assert!(value.get("access_token").is_none());
    assert!(value.get("refresh_token").is_none());
    assert!(value.get("id_token").is_none());
}

#[actix_web::test]
async fn client_credentials_issue_returns_minimal_bearer_token_response_without_oidc_artifacts() {
    let state = issue_state_with_valid_signing_key();
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
    assert_eq!(value["expires_in"], state.settings.access_token_ttl_seconds);
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
    let client = client_with_grants(&["authorization_code"]);
    let mut issue = token_issue_with_sid(vec!["sid".to_owned()]);
    let missing_user_id = Uuid::now_v7();
    issue.user_id = Some(missing_user_id);
    issue.subject = missing_user_id.to_string();
    issue.include_refresh = false;

    let response = issue_token_response(&state, &client, issue).await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(oauth_error_code(&response), "invalid_grant");
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("response body should collect");
    let value: Value = serde_json::from_slice(&body).expect("OAuth error body should be JSON");
    assert_eq!(value.get("error"), Some(&json!("invalid_grant")));
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
