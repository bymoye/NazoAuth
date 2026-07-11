use super::*;
use crate::http::TokenForm;
use crate::{
    config::ConfigSource,
    db::create_pool,
    domain::{ActiveSigningKey, Keyset, KeysetStore},
};
use actix_web::test::TestRequest;
use std::collections::HashMap;
use std::sync::Arc;

fn form_request() -> HttpRequest {
    TestRequest::default()
        .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
        .to_http_request()
}

fn device_client() -> ClientRow {
    ClientRow {
        id: Uuid::now_v7(),
        tenant_id: DEFAULT_TENANT_ID,
        realm_id: DEFAULT_REALM_ID,
        organization_id: DEFAULT_ORGANIZATION_ID,
        client_id: "device-client".to_owned(),
        client_name: "Device Client".to_owned(),
        client_type: "public".to_owned(),
        client_secret_hash: None,
        redirect_uris: json!(["https://client.example/callback"]),
        scopes: json!(["openid", "profile", "offline_access"]),
        allowed_audiences: json!(["resource://default", "https://api.example.com"]),
        grant_types: json!([DEVICE_CODE_GRANT_TYPE]),
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

fn enabled_settings() -> Settings {
    let mut settings =
        Settings::from_config(&crate::config::ConfigSource::default()).expect("settings");
    settings.enable_device_authorization_grant = true;
    settings.device_authorization_ttl_seconds = 600;
    settings.device_authorization_poll_interval_seconds = 5;
    settings
}

fn disabled_state() -> AppState {
    state_with_settings(Settings::from_config(&ConfigSource::default()).expect("settings"))
}

fn enabled_state() -> AppState {
    state_with_settings(enabled_settings())
}

fn state_with_settings(settings: Settings) -> AppState {
    AppState {
        diesel_db: create_pool(
            "postgres://nazo_device_test_invalid:nazo_device_test_invalid@127.0.0.1:1/nazo"
                .to_owned(),
            1,
        )
        .expect("pool construction should not connect"),
        valkey: fred::prelude::Builder::default_centralized()
            .build()
            .expect("valkey client construction should not connect"),
        settings: Arc::new(settings),
        keyset: KeysetStore::new(Keyset {
            active_kid: "test-kid".to_owned(),
            active_alg: jsonwebtoken::Algorithm::EdDSA,
            active_signing_key: ActiveSigningKey::LocalPkcs8Der(Vec::new()),
            verification_keys: Vec::new(),
        }),
    }
}

fn device_token_form(device_code: Option<&str>) -> TokenForm {
    TokenForm {
        grant_type: DEVICE_CODE_GRANT_TYPE.to_owned(),
        code: None,
        device_code: device_code.map(ToOwned::to_owned),
        auth_req_id: None,
        redirect_uri: None,
        code_verifier: None,
        refresh_token: None,
        device_secret: None,
        scope: None,
        client_id: Some("device-client".to_owned()),
        client_secret: None,
        client_assertion_type: None,
        client_assertion: None,
        assertion: None,
        requested_token_type: None,
        subject_token: None,
        subject_token_type: None,
        actor_token: None,
        actor_token_type: None,
        audiences: Vec::new(),
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

#[test]
fn device_authorization_form_parses_scope_resource_and_auth_fields() {
    let req = form_request();

    let form = parse_device_authorization_form(
        &req,
        &Bytes::from_static(
            b"client_id=device-client&scope=openid%20profile&resource=https%3A%2F%2Fapi.example.com&client_secret=secret",
        ),
    )
    .expect("device authorization request should parse");

    assert_eq!(form.client_id.as_deref(), Some("device-client"));
    assert_eq!(form.scope.as_deref(), Some("openid profile"));
    assert_eq!(form.resources, vec!["https://api.example.com"]);
    assert_eq!(form.client_secret.as_deref(), Some("secret"));
}

#[test]
fn device_authorization_request_rejects_disabled_or_unregistered_client_grant() {
    let form = DeviceAuthorizationForm {
        client_id: Some("device-client".to_owned()),
        scope: Some("openid".to_owned()),
        resources: Vec::new(),
        client_secret: None,
        client_assertion_type: None,
        client_assertion: None,
    };
    let mut settings = enabled_settings();
    let client = device_client();

    settings.enable_device_authorization_grant = false;
    assert!(matches!(
        device_authorization_request_payload(&settings, &client, &form),
        Err(DeviceAuthorizationRequestError::Disabled)
    ));

    settings.enable_device_authorization_grant = true;
    let mut client = client;
    client.grant_types = json!(["authorization_code"]);
    assert!(matches!(
        device_authorization_request_payload(&settings, &client, &form),
        Err(DeviceAuthorizationRequestError::UnauthorizedClient)
    ));
}

#[test]
fn device_authorization_request_binds_scope_audience_ttl_and_poll_interval() {
    let settings = enabled_settings();
    let client = device_client();
    let form = DeviceAuthorizationForm {
        client_id: Some("device-client".to_owned()),
        scope: Some("openid profile".to_owned()),
        resources: vec!["https://api.example.com".to_owned()],
        client_secret: None,
        client_assertion_type: None,
        client_assertion: None,
    };

    let payload = device_authorization_request_payload(&settings, &client, &form)
        .expect("device authorization request should be accepted");

    assert_eq!(payload.client_id, "device-client");
    assert_eq!(payload.scopes, vec!["openid", "profile"]);
    assert_eq!(payload.resource_indicators, vec!["https://api.example.com"]);
    assert_eq!(payload.interval_seconds, 5);
    assert_eq!(
        payload.expires_at,
        payload.issued_at + Duration::seconds(600)
    );
}

#[test]
fn device_code_polling_enforces_pending_slow_down_denied_and_expired_results() {
    let now = Utc::now();
    let payload = DeviceAuthorizationPayload {
        client_id: "device-client".to_owned(),
        client_name: "Device Client".to_owned(),
        scopes: vec!["openid".to_owned()],
        resource_indicators: vec!["resource://default".to_owned()],
        authorization_details: json!([]),
        interval_seconds: 5,
        issued_at: now,
        expires_at: now + Duration::seconds(600),
    };

    let pending = DeviceAuthorizationState::Pending {
        payload: payload.clone(),
        last_poll_at: None,
        slow_down_count: 0,
    };
    assert!(matches!(
        evaluate_device_code_poll(&pending, now),
        DeviceCodePollResult::AuthorizationPending { .. }
    ));

    let too_soon = DeviceAuthorizationState::Pending {
        payload: payload.clone(),
        last_poll_at: Some(now - Duration::seconds(1)),
        slow_down_count: 0,
    };
    assert!(matches!(
        evaluate_device_code_poll(&too_soon, now),
        DeviceCodePollResult::SlowDown { .. }
    ));

    let denied = DeviceAuthorizationState::Denied {
        payload: payload.clone(),
        denied_at: now,
    };
    assert!(matches!(
        evaluate_device_code_poll(&denied, now),
        DeviceCodePollResult::AccessDenied
    ));

    let expired = DeviceAuthorizationState::Pending {
        payload: DeviceAuthorizationPayload {
            expires_at: now - Duration::seconds(1),
            ..payload
        },
        last_poll_at: None,
        slow_down_count: 0,
    };
    assert!(matches!(
        evaluate_device_code_poll(&expired, now),
        DeviceCodePollResult::Expired
    ));
}

#[test]
fn device_authorization_verification_uri_targets_frontend_device_page() {
    let mut settings = enabled_settings();
    settings.frontend_base_url = "https://auth.example.test/ui/".to_owned();

    assert_eq!(
        device_verification_uri(&settings),
        "https://auth.example.test/ui/device"
    );
}

#[actix_web::test]
async fn legacy_device_verification_path_redirects_to_frontend_without_html() {
    let state = Data::new(enabled_state());

    let response = device_verification_page(
        state,
        Query(HashMap::from([(
            "user_code".to_owned(),
            "ABCD 1234".to_owned(),
        )])),
    )
    .await;

    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(
        response.headers().get(header::LOCATION).unwrap(),
        "http://127.0.0.1:8000/ui/device?user_code=ABCD%201234"
    );
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
}

#[actix_web::test]
async fn device_authorization_endpoint_disabled_fails_before_client_lookup() {
    let state = Data::new(disabled_state());
    let req = form_request();

    let response = device_authorization(
        state,
        req,
        Bytes::from_static(b"client_id=device-client&scope=openid"),
    )
    .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(oauth_error_code(&response), "invalid_request");
}

#[actix_web::test]
async fn device_code_grant_requires_device_code_before_state_lookup() {
    let state = enabled_state();
    let req = TestRequest::post().uri("/token").to_http_request();
    let client = device_client();
    let form = device_token_form(None);

    let response = token_device_code(&state, &req, &client, &form, None).await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(oauth_error_code(&response), "invalid_request");
}
