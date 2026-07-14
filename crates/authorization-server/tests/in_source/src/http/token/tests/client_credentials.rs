use super::*;
use std::sync::Arc;

use nazo_postgres::create_pool;

use crate::http::client_ip::IpCidr;
use crate::settings::AuthorizationServerProfile;
use actix_web::test::TestRequest;

fn settings(profile: AuthorizationServerProfile) -> Settings {
    let mut settings =
        Settings::from_config(&crate::config::ConfigSource::default()).expect("settings");
    settings.protocol.authorization_server_profile = profile;
    settings
}

fn client() -> ClientRow {
    crate::client_row! {
        id: Uuid::now_v7(),
        tenant_id: DEFAULT_TENANT_ID,
        realm_id: DEFAULT_REALM_ID,
        organization_id: DEFAULT_ORGANIZATION_ID,
        client_id: "client-1".to_owned(),
        client_name: "Client".to_owned(),
        client_type: "confidential".to_owned(),
        client_secret_hash: None,
        redirect_uris: json!(["https://client.example/callback"]),
        scopes: json!(["accounts", "payments"]),
        allowed_audiences: json!(["resource://default", "https://api.example.com"]),
        grant_types: json!(["client_credentials"]),
        token_endpoint_auth_method: "private_key_jwt".to_owned(),
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

fn form(scope: Option<&str>, audiences: &[&str]) -> TokenForm {
    TokenForm {
        grant_type: "client_credentials".to_owned(),
        code: None,
        device_code: None,
        auth_req_id: None,
        redirect_uri: None,
        code_verifier: None,
        refresh_token: None,
        device_secret: None,
        scope: scope.map(ToOwned::to_owned),
        client_id: Some("client-1".to_owned()),
        client_secret: None,
        client_assertion_type: None,
        client_assertion: None,
        assertion: None,
        requested_token_type: None,
        subject_token: None,
        subject_token_type: None,
        actor_token: None,
        actor_token_type: None,
        audiences: audiences.iter().map(|value| (*value).to_owned()).collect(),
        has_audience_param: false,
    }
}

fn oauth_error_code(response: &HttpResponse) -> String {
    response
        .extensions()
        .get::<OAuthJsonErrorFields>()
        .map(|fields| fields.error.clone())
        .expect("OAuth error response should record its error code")
}

fn client_credentials_state() -> TestAppState {
    TestAppState {
        diesel_db: create_pool(
            "postgres://nazo_client_credentials_test_invalid:nazo_client_credentials_test_invalid@127.0.0.1:1/nazo"
                .to_owned(),
            1,
        )
        .expect("pool construction should not connect"),
        valkey: fred::prelude::Builder::default_centralized()
            .build()
            .expect("valkey client construction should not connect"),
        settings: Arc::new(settings(AuthorizationServerProfile::Oauth2Baseline)),
        keyset: crate::test_support::test_key_manager(),
    }
}

fn token_request() -> HttpRequest {
    TestRequest::post().uri("/token").to_http_request()
}

#[test]
fn client_credentials_defaults_to_allowed_scopes_and_default_audience() {
    let settings = settings(AuthorizationServerProfile::Oauth2Baseline);
    let client = client();

    let issue = client_credentials_issue_request(&settings, &client, &form(None, &[]))
        .expect("confidential client may use client_credentials");

    assert_eq!(
        issue.scopes,
        vec!["accounts".to_owned(), "payments".to_owned()]
    );
    assert_eq!(issue.audiences, vec!["resource://default".to_owned()]);
}

#[test]
fn client_credentials_scope_request_may_only_narrow_registered_scopes() {
    let settings = settings(AuthorizationServerProfile::Oauth2Baseline);
    let client = client();

    let issue = client_credentials_issue_request(
        &settings,
        &client,
        &form(Some("payments accounts"), &["https://api.example.com"]),
    )
    .expect("subset scopes and registered audience should be accepted");

    assert_eq!(
        issue.scopes,
        vec!["payments".to_owned(), "accounts".to_owned()]
    );
    assert_eq!(issue.audiences, vec!["https://api.example.com".to_owned()]);

    let response = client_credentials_issue_request(&settings, &client, &form(Some("admin"), &[]))
        .expect_err("client_credentials must reject scope privilege expansion");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(oauth_error_code(&response), "invalid_scope");
}

#[test]
fn client_credentials_rejects_openid_scope_even_if_registered() {
    let settings = settings(AuthorizationServerProfile::Oauth2Baseline);
    let mut client = client();
    client.scopes = vec!["accounts".to_owned(), "openid".to_owned()];

    let default_response = client_credentials_issue_request(&settings, &client, &form(None, &[]))
        .expect_err("client_credentials must not inherit openid from legacy client metadata");
    assert_eq!(default_response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(oauth_error_code(&default_response), "invalid_scope");

    let explicit_response =
        client_credentials_issue_request(&settings, &client, &form(Some("openid"), &[]))
            .expect_err("client_credentials must not accept explicit openid scope");
    assert_eq!(explicit_response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(oauth_error_code(&explicit_response), "invalid_scope");
}

#[test]
fn client_credentials_rejects_public_clients_before_issue_construction() {
    let mut client = client();
    client.client_type = "public".to_owned();
    client.token_endpoint_auth_method = "none".to_owned();

    let response = reject_non_confidential_client_credentials_client(&client)
        .expect("public clients must not receive client_credentials tokens");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(oauth_error_code(&response), "unauthorized_client");

    let mut confidential = client;
    confidential.client_type = "confidential".to_owned();
    assert!(
        reject_non_confidential_client_credentials_client(&confidential).is_none(),
        "confidential client must proceed to sender-constraint and grant validation"
    );
}

#[test]
fn client_credentials_rejects_unregistered_audience() {
    let settings = settings(AuthorizationServerProfile::Oauth2Baseline);
    let client = client();

    let response = client_credentials_issue_request(
        &settings,
        &client,
        &form(Some("accounts"), &["https://evil.example.com"]),
    )
    .expect_err("client_credentials access token audience must be client-registered");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(oauth_error_code(&response), "invalid_target");
}

#[actix_web::test]
async fn token_client_credentials_rejects_public_clients_at_endpoint_boundary() {
    let state = client_credentials_state();
    let mut client = client();
    client.client_type = "public".to_owned();
    client.token_endpoint_auth_method = "none".to_owned();

    let response =
        token_client_credentials(&state, &token_request(), &client, &form(None, &[]), None).await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(oauth_error_code(&response), "unauthorized_client");
}

#[actix_web::test]
async fn token_client_credentials_requires_configured_sender_constraints() {
    let state = client_credentials_state();
    let mut dpop_client = client();
    dpop_client.require_dpop_bound_tokens = true;

    let response = token_client_credentials(
        &state,
        &token_request(),
        &dpop_client,
        &form(None, &[]),
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(oauth_error_code(&response), "invalid_dpop_proof");

    let mut mtls_client = client();
    mtls_client.require_mtls_bound_tokens = true;
    let response = token_client_credentials(
        &state,
        &token_request(),
        &mtls_client,
        &form(None, &[]),
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(oauth_error_code(&response), "invalid_grant");
}

#[actix_web::test]
async fn token_client_credentials_binds_mtls_thumbprint_from_verified_certificate() {
    let mut state = client_credentials_state();
    let mut settings = (*state.settings).clone();
    settings.endpoint.trusted_proxy_cidrs =
        vec![IpCidr::parse("127.0.0.1/32").expect("trusted proxy CIDR should parse")];
    state.settings = Arc::new(settings);
    state.keyset = crate::test_support::failing_key_manager();
    let state = Data::new(state);
    let mut client = client();
    client.require_mtls_bound_tokens = true;
    let thumbprint = "ABEiM0RVZneImaq7zN3u_wARIjNEVWZ3iJmqu8zd7v8";
    let req = TestRequest::post()
        .uri("/token")
        .peer_addr("127.0.0.1:12345".parse().expect("peer addr should parse"))
        .insert_header(("x-ssl-client-verify", "SUCCESS"))
        .insert_header(("x-ssl-client-cert-sha256", thumbprint))
        .to_http_request();

    let response = token_client_credentials(&state, &req, &client, &form(None, &[]), None).await;

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(oauth_error_code(&response), "server_error");
}

#[actix_web::test]
async fn token_client_credentials_rejects_invalid_scope_before_issuing_token() {
    let state = client_credentials_state();
    let client = client();

    let response = token_client_credentials(
        &state,
        &token_request(),
        &client,
        &form(Some("admin"), &[]),
        None,
    )
    .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(oauth_error_code(&response), "invalid_scope");
}
