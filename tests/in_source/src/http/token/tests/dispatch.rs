use super::*;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration as StdDuration;

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD},
};
use diesel::sql_query;
use diesel::sql_types::{Bool, Jsonb, Nullable, Text};
use diesel_async::RunQueryDsl;
use fred::interfaces::ClientLike;
use fred::prelude::{
    Builder as ValkeyBuilder, Config as ValkeyConfig, ConnectionConfig, PerformanceConfig,
};

use crate::config::ConfigSource;
use crate::db::{create_pool, get_conn};
use crate::domain::{ActiveSigningKey, Keyset, KeysetStore};
use crate::settings::{
    AuthorizationServerProfile, DpopNoncePolicy, EmailDelivery, EmailSettings, RateLimitSettings,
    RequestObjectJtiPolicy, SubjectType,
};
use crate::support::{ClientIpHeaderMode, IpCidr, hash_client_secret};

fn code_payload(dpop_jkt: Option<&str>) -> CodePayload {
    CodePayload {
        code_id: "code-id".to_owned(),
        user_id: Uuid::nil(),
        client_id: "client-1".to_owned(),
        redirect_uri: "https://client.example/callback".to_owned(),
        redirect_uri_was_supplied: true,
        scopes: vec!["openid".to_owned()],
        resource_indicators: Vec::new(),
        authorization_details: json!([]),
        nonce: None,
        auth_time: 1,
        amr: vec!["pwd".to_owned()],
        oidc_sid: Some("sid-1".to_owned()),
        acr: None,
        userinfo_claims: Vec::new(),
        userinfo_claim_requests: Vec::new(),
        id_token_claims: Vec::new(),
        id_token_claim_requests: Vec::new(),
        code_challenge: Some("challenge".to_owned()),
        code_challenge_method: Some("S256".to_owned()),
        dpop_jkt: dpop_jkt.map(ToOwned::to_owned),
        mtls_x5t_s256: None,
        issued_at: Utc::now(),
        expires_at: Utc::now() + Duration::minutes(5),
    }
}

fn mtls_code_payload() -> CodePayload {
    CodePayload {
        mtls_x5t_s256: Some("mtls-thumbprint".to_owned()),
        ..code_payload(None)
    }
}

fn settings(profile: AuthorizationServerProfile) -> Settings {
    Settings {
        issuer: "https://issuer.example".to_owned(),
        mtls_endpoint_base_url: "https://issuer.example".to_owned(),
        frontend_base_url: "https://app.example".to_owned(),
        cors_allowed_origins: vec!["https://app.example".to_owned()],
        default_audience: "resource://default".to_owned(),
        protected_resource_identifier: "https://issuer.example/fapi/resource".to_owned(),
        authorization_server_profile: profile,
        ciba_security_profile:
            crate::settings::CibaSecurityProfile::FapiCibaId1PlainPrivateKeyJwtPoll,
        dpop_nonce_policy: DpopNoncePolicy::Required,
        request_object_jti_policy: RequestObjectJtiPolicy::Optional,
        session_cookie_name: "sid".to_owned(),
        csrf_cookie_name: "csrf".to_owned(),
        cookie_secure: true,
        session_ttl_seconds: 3600,
        auth_code_ttl_seconds: 60,
        access_token_ttl_seconds: 300,
        id_token_ttl_seconds: 600,
        refresh_token_ttl_seconds: 2_592_000,
        avatar_max_bytes: 2_097_152,
        client_delivery_ttl_seconds: 86_400,
        client_secret_pepper: "client-secret-pepper-for-tests-000000000001".to_owned(),
        rate_limit: RateLimitSettings {
            window_seconds: 60,
            auth_max_requests: 30,
            token_max_requests: 60,
            token_management_max_requests: 120,
            login_failure_window_seconds: 900,
            login_failure_email_max_attempts: 50,
            login_failure_ip_email_max_attempts: 5,
        },
        email: EmailSettings {
            delivery: EmailDelivery::Disabled,
            code_ttl_seconds: 900,
            send_cooldown_seconds: 60,
            send_peer_cooldown_seconds: 5,
        },
        email_code_dev_response_enabled: false,
        avatar_storage_dir: PathBuf::from("runtime/avatars"),
        jwk_keys_dir: PathBuf::from("runtime/keys"),
        signing_external_command: Vec::new(),
        signing_external_timeout_ms: 2_000,
        signing_key_rotation_interval_seconds: 7_776_000,
        signing_key_prepublish_seconds: 86_400,
        trusted_proxy_cidrs: Vec::<IpCidr>::new(),
        client_ip_header_mode: ClientIpHeaderMode::None,
        subject_type: SubjectType::Public,
        pairwise_subject_secret: None,
        par_ttl_seconds: 90,
        require_pushed_authorization_requests: profile.requires_fapi2_security(),
        scim_bearer_token: None,
        passkey: crate::settings::PasskeySettings {
            rp_id: "issuer.example".to_owned(),
            rp_name: "Nazo OAuth".to_owned(),
            origin: "https://issuer.example".to_owned(),
            require_user_verification: true,
            require_user_handle: true,
            strict_base64: true,
        },
        federation: crate::settings::FederationSettings {
            providers: crate::settings::FederationProviderRegistry::default(),
            saml_gateway: None,
        },
        enable_request_object: false,
        enable_request_uri_parameter: false,
        enable_par_request_object: false,
        enable_authorization_details: false,
        enable_legacy_audience_param: false,
        enable_device_authorization_grant: false,
        enable_dynamic_client_registration: false,
        enable_frontchannel_logout: false,
        enable_session_management: false,
        enable_ciba: false,
        enable_native_sso: false,
        dynamic_client_registration_initial_access_token: None,
        device_authorization_ttl_seconds: 600,
        device_authorization_poll_interval_seconds: 5,
        ciba_auth_req_id_ttl_seconds: 600,
        ciba_poll_interval_seconds: 5,
        ciba_automated_decision_token: None,
    }
}

fn unavailable_token_valkey() -> fred::prelude::Client {
    let mut builder = ValkeyBuilder::from_config(
        ValkeyConfig::from_url("redis://127.0.0.1:1").expect("unavailable Valkey URL should parse"),
    );
    builder.with_performance_config(|performance: &mut PerformanceConfig| {
        performance.default_command_timeout = StdDuration::from_millis(200);
    });
    builder.with_connection_config(|connection: &mut ConnectionConfig| {
        connection.connection_timeout = StdDuration::from_millis(200);
        connection.internal_command_timeout = StdDuration::from_millis(200);
        connection.max_command_attempts = 1;
    });
    builder
        .build()
        .expect("unavailable valkey client construction should not connect")
}

fn fixture_secret(label: &str) -> String {
    format!("token-dispatch-fixture-secret-{label}")
}

fn fixture_secret_hash(state: &Data<AppState>, secret: &str) -> String {
    hash_client_secret(secret, &state.settings.client_secret_pepper)
}

fn fixture_mtls_thumbprint(label: &str) -> String {
    blake3_hex(&format!("token-dispatch-fixture-thumbprint-{label}"))
}

fn parseable_invalid_client_assertion(client_id: &str) -> String {
    let now = Utc::now().timestamp();
    let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"HS256","typ":"JWT"}"#);
    let payload = URL_SAFE_NO_PAD.encode(
        json!({
            "iss": client_id,
            "sub": client_id,
            "aud": "https://issuer.example/token",
            "exp": now + 60,
            "nbf": now - 1,
            "iat": now,
            "jti": format!("invalid-assertion-{}", Uuid::now_v7())
        })
        .to_string(),
    );
    format!("{header}.{payload}.signature")
}

fn unavailable_valkey_token_state(profile: AuthorizationServerProfile) -> AppState {
    AppState {
        diesel_db: create_pool(
            "postgres://nazo_token_dispatch_invalid:nazo_token_dispatch_invalid@127.0.0.1:1/nazo"
                .to_owned(),
            1,
        )
        .expect("pool construction should not connect"),
        valkey: unavailable_token_valkey(),
        settings: Arc::new(settings(profile)),
        keyset: KeysetStore::new(Keyset {
            active_kid: "test-kid".to_owned(),
            active_alg: jsonwebtoken::Algorithm::EdDSA,
            active_signing_key: ActiveSigningKey::LocalPkcs8Der(Vec::new()),
            verification_keys: Vec::new(),
        }),
    }
}

async fn live_token_state(profile: AuthorizationServerProfile) -> Option<Data<AppState>> {
    let valkey_url = std::env::var("VALKEY_URL").ok()?;
    let database_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| {
        "postgres://nazo_token_dispatch_invalid:nazo_token_dispatch_invalid@127.0.0.1:1/nazo"
            .to_owned()
    });
    let config = ConfigSource::from_pairs_for_test([
        ("ISSUER", "https://issuer.example"),
        (
            "CLIENT_SECRET_PEPPER",
            "client-secret-pepper-for-tests-000000000001",
        ),
        ("MTLS_ENDPOINT_BASE_URL", "https://issuer.example"),
        ("FRONTEND_BASE_URL", "https://app.example"),
        ("COOKIE_SECURE", "true"),
        ("TOKEN_RATE_LIMIT_MAX_REQUESTS", "100000"),
    ]);
    let mut settings = Settings::from_config(&config).expect("test settings should load");
    settings.authorization_server_profile = profile;
    let mut valkey_builder = ValkeyBuilder::from_config(
        ValkeyConfig::from_url(&valkey_url).expect("VALKEY_URL should parse"),
    );
    valkey_builder.with_performance_config(|performance: &mut PerformanceConfig| {
        performance.default_command_timeout = StdDuration::from_millis(1000);
    });
    valkey_builder.with_connection_config(|connection: &mut ConnectionConfig| {
        connection.connection_timeout = StdDuration::from_millis(1000);
        connection.internal_command_timeout = StdDuration::from_millis(1000);
        connection.max_command_attempts = 1;
    });
    let valkey = valkey_builder.build().expect("valkey client should build");
    valkey.init().await.expect("valkey should connect");

    Some(Data::new(AppState {
        diesel_db: create_pool(database_url, 1).expect("database pool should build"),
        valkey,
        settings: Arc::new(settings),
        keyset: KeysetStore::new(Keyset {
            active_kid: "test-kid".to_owned(),
            active_alg: jsonwebtoken::Algorithm::EdDSA,
            active_signing_key: ActiveSigningKey::LocalPkcs8Der(Vec::new()),
            verification_keys: Vec::new(),
        }),
    }))
}

async fn live_valkey_invalid_db_token_state(
    profile: AuthorizationServerProfile,
) -> Option<Data<AppState>> {
    let valkey_url = std::env::var("VALKEY_URL").ok()?;
    let config = ConfigSource::from_pairs_for_test([
        ("ISSUER", "https://issuer.example"),
        (
            "CLIENT_SECRET_PEPPER",
            "client-secret-pepper-for-tests-000000000001",
        ),
        ("MTLS_ENDPOINT_BASE_URL", "https://issuer.example"),
        ("FRONTEND_BASE_URL", "https://app.example"),
        ("COOKIE_SECURE", "true"),
        ("TOKEN_RATE_LIMIT_MAX_REQUESTS", "100000"),
    ]);
    let mut settings = Settings::from_config(&config).expect("test settings should load");
    settings.authorization_server_profile = profile;
    let mut valkey_builder = ValkeyBuilder::from_config(
        ValkeyConfig::from_url(&valkey_url).expect("VALKEY_URL should parse"),
    );
    valkey_builder.with_performance_config(|performance: &mut PerformanceConfig| {
        performance.default_command_timeout = StdDuration::from_millis(1000);
    });
    valkey_builder.with_connection_config(|connection: &mut ConnectionConfig| {
        connection.connection_timeout = StdDuration::from_millis(1000);
        connection.internal_command_timeout = StdDuration::from_millis(1000);
        connection.max_command_attempts = 1;
    });
    let valkey = valkey_builder.build().expect("valkey client should build");
    valkey.init().await.expect("valkey should connect");

    Some(Data::new(AppState {
        diesel_db: create_pool(
            "postgres://nazo_token_dispatch_invalid:nazo_token_dispatch_invalid@127.0.0.1:1/nazo"
                .to_owned(),
            1,
        )
        .expect("pool construction should not connect"),
        valkey,
        settings: Arc::new(settings),
        keyset: KeysetStore::new(Keyset {
            active_kid: "test-kid".to_owned(),
            active_alg: jsonwebtoken::Algorithm::EdDSA,
            active_signing_key: ActiveSigningKey::LocalPkcs8Der(Vec::new()),
            verification_keys: Vec::new(),
        }),
    }))
}

async fn live_trusted_proxy_invalid_db_token_state(
    profile: AuthorizationServerProfile,
) -> Option<Data<AppState>> {
    let state = live_valkey_invalid_db_token_state(profile).await?;
    let mut updated = (*state.settings).clone();
    updated.trusted_proxy_cidrs =
        vec![IpCidr::parse("127.0.0.1/32").expect("trusted proxy CIDR should parse")];
    Some(Data::new(AppState {
        diesel_db: state.diesel_db.clone(),
        valkey: state.valkey.clone(),
        settings: Arc::new(updated),
        keyset: state.keyset.clone(),
    }))
}

async fn live_trusted_proxy_token_state(
    profile: AuthorizationServerProfile,
) -> Option<Data<AppState>> {
    let state = live_token_state(profile).await?;
    let mut updated = (*state.settings).clone();
    updated.trusted_proxy_cidrs =
        vec![IpCidr::parse("127.0.0.1/32").expect("trusted proxy CIDR should parse")];
    Some(Data::new(AppState {
        diesel_db: state.diesel_db.clone(),
        valkey: state.valkey.clone(),
        settings: Arc::new(updated),
        keyset: state.keyset.clone(),
    }))
}

async fn token_json_body(response: HttpResponse) -> (StatusCode, Value) {
    let status = response.status();
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("response body should be readable");
    let value = serde_json::from_slice(&body).expect("response should be JSON");
    (status, value)
}

#[allow(clippy::too_many_arguments)]
async fn insert_token_client(
    state: &Data<AppState>,
    client_id: &str,
    client_type: &str,
    token_endpoint_auth_method: &str,
    client_secret_hash: Option<String>,
    grant_types: Vec<&str>,
    require_dpop_bound_tokens: bool,
    require_mtls_bound_tokens: bool,
    is_active: bool,
) {
    let mut conn = get_conn(&state.diesel_db)
        .await
        .expect("database connection should be available");
    sql_query(
        r#"
        DELETE FROM access_token_revocations
        USING oauth_clients
        WHERE access_token_revocations.client_id = oauth_clients.id
          AND oauth_clients.tenant_id = $1
          AND oauth_clients.client_id = $2
        "#,
    )
    .bind::<diesel::sql_types::Uuid, _>(DEFAULT_TENANT_ID)
    .bind::<Text, _>(client_id)
    .execute(&mut conn)
    .await
    .expect("test access token revocation cleanup should succeed");
    sql_query(
        r#"
        DELETE FROM oauth_tokens
        USING oauth_clients
        WHERE oauth_tokens.client_id = oauth_clients.id
          AND oauth_clients.tenant_id = $1
          AND oauth_clients.client_id = $2
        "#,
    )
    .bind::<diesel::sql_types::Uuid, _>(DEFAULT_TENANT_ID)
    .bind::<Text, _>(client_id)
    .execute(&mut conn)
    .await
    .expect("test refresh token cleanup should succeed");
    sql_query("DELETE FROM oauth_clients WHERE tenant_id = $1 AND client_id = $2")
        .bind::<diesel::sql_types::Uuid, _>(DEFAULT_TENANT_ID)
        .bind::<Text, _>(client_id)
        .execute(&mut conn)
        .await
        .expect("test client cleanup should succeed");

    sql_query(
        r#"
        INSERT INTO oauth_clients (
            tenant_id, realm_id, organization_id, client_id, client_name, client_type,
            client_secret_hash, redirect_uris, scopes, allowed_audiences,
            grant_types, token_endpoint_auth_method, require_dpop_bound_tokens,
            require_mtls_bound_tokens, tls_client_auth_san_dns, tls_client_auth_san_uri,
            tls_client_auth_san_ip, tls_client_auth_san_email,
            allow_client_assertion_audience_array,
            allow_client_assertion_endpoint_audience, require_par_request_object,
            allow_authorization_code_without_pkce, is_active,
            post_logout_redirect_uris, backchannel_logout_session_required
        )
        VALUES (
            $1, $2, $3, $4, 'Token Dispatch Test Client', $5,
            $6, '["https://client.example/callback"]'::jsonb, '["openid","accounts"]'::jsonb,
            '["resource://default"]'::jsonb, $7, $8, $9,
            $10, '[]'::jsonb, '[]'::jsonb,
            '[]'::jsonb, '[]'::jsonb,
            false,
            false, false,
            false, $11,
            '[]'::jsonb, true
        )
        "#,
    )
    .bind::<diesel::sql_types::Uuid, _>(DEFAULT_TENANT_ID)
    .bind::<diesel::sql_types::Uuid, _>(DEFAULT_REALM_ID)
    .bind::<diesel::sql_types::Uuid, _>(DEFAULT_ORGANIZATION_ID)
    .bind::<Text, _>(client_id)
    .bind::<Text, _>(client_type)
    .bind::<Nullable<Text>, _>(client_secret_hash)
    .bind::<Jsonb, _>(json!(grant_types))
    .bind::<Text, _>(token_endpoint_auth_method)
    .bind::<Bool, _>(require_dpop_bound_tokens)
    .bind::<Bool, _>(require_mtls_bound_tokens)
    .bind::<Bool, _>(is_active)
    .execute(&mut conn)
    .await
    .expect("test client insert should succeed");
}

async fn set_client_mtls_thumbprint(state: &Data<AppState>, client_id: &str, thumbprint: &str) {
    let mut conn = get_conn(&state.diesel_db)
        .await
        .expect("database connection should be available");
    sql_query(
        "UPDATE oauth_clients SET tls_client_auth_cert_sha256 = $1, tls_client_auth_subject_dn = $2 WHERE tenant_id = $3 AND client_id = $4",
    )
    .bind::<Text, _>(thumbprint)
    .bind::<Text, _>("CN=dispatch-mtls")
    .bind::<diesel::sql_types::Uuid, _>(DEFAULT_TENANT_ID)
    .bind::<Text, _>(client_id)
    .execute(&mut conn)
    .await
    .expect("mTLS thumbprint update should succeed");
}

async fn store_authorization_code_state(
    state: &Data<AppState>,
    code: &str,
    code_state: &AuthorizationCodeState,
) {
    valkey_set_ex(
        &state.valkey,
        authorization_code_key(code),
        serde_json::to_string(code_state).expect("authorization code state should serialize"),
        state.settings.auth_code_ttl_seconds,
    )
    .await
    .expect("authorization code state should store");
}

async fn store_raw_authorization_code_state(state: &Data<AppState>, code: &str, raw: &str) {
    valkey_set_ex(
        &state.valkey,
        authorization_code_key(code),
        raw.to_owned(),
        state.settings.auth_code_ttl_seconds,
    )
    .await
    .expect("raw authorization code state should store");
}

async fn assert_token_error(
    response: HttpResponse,
    status: StatusCode,
    error: &str,
    www_authenticate: bool,
) {
    assert_eq!(response.status(), status);
    assert_eq!(oauth_error_code(&response), error);
    assert_eq!(
        response.headers().contains_key(header::WWW_AUTHENTICATE),
        www_authenticate
    );
    let (actual_status, body) = token_json_body(response).await;
    assert_eq!(actual_status, status);
    assert_eq!(body["error"], error);
    assert!(body.get("access_token").is_none());
    assert!(body.get("refresh_token").is_none());
}

fn token_request(content_type: &str) -> HttpRequest {
    actix_web::test::TestRequest::post()
        .uri("/token")
        .insert_header((header::CONTENT_TYPE, content_type))
        .to_http_request()
}

fn client() -> ClientRow {
    ClientRow {
        id: Uuid::now_v7(),
        tenant_id: DEFAULT_TENANT_ID,
        realm_id: DEFAULT_REALM_ID,
        organization_id: DEFAULT_ORGANIZATION_ID,
        client_id: "client-a".to_owned(),
        client_name: "Client A".to_owned(),
        client_type: "confidential".to_owned(),
        client_secret_hash: None,
        redirect_uris: json!(["https://client.example/callback"]),
        scopes: json!(["openid"]),
        allowed_audiences: json!(["resource://default"]),
        grant_types: json!(["authorization_code"]),
        token_endpoint_auth_method: "private_key_jwt".to_owned(),
        require_dpop_bound_tokens: true,
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

#[actix_web::test]
async fn token_endpoint_rejects_malformed_form_requests_before_client_lookup() {
    let Some(state) = live_token_state(AuthorizationServerProfile::Oauth2Baseline).await else {
        return;
    };
    let cases = [
        (
            token_request("application/json"),
            Bytes::from_static(b"{\"grant_type\":\"client_credentials\"}"),
            "invalid_request",
        ),
        (
            token_request("application/x-www-form-urlencoded"),
            Bytes::from_static(b"grant_type=\xff"),
            "invalid_request",
        ),
        (
            token_request("application/x-www-form-urlencoded"),
            Bytes::from_static(b"grant_type=client_credentials&grant_type=refresh_token"),
            "invalid_request",
        ),
        (
            token_request("application/x-www-form-urlencoded"),
            Bytes::from_static(
                b"grant_type=client_credentials&resource=https%3A%2F%2Fapi.example%2F%23fragment",
            ),
            "invalid_target",
        ),
        (
            token_request("application/x-www-form-urlencoded"),
            Bytes::from_static(b"client_id=client-1"),
            "invalid_request",
        ),
    ];

    for (req, body, expected_error) in cases {
        assert_token_error(
            token(state.clone(), req, body).await,
            StatusCode::BAD_REQUEST,
            expected_error,
            false,
        )
        .await;
    }
}

#[actix_web::test]
async fn token_endpoint_rejects_legacy_audience_parameter_when_disabled() {
    let Some(state) = live_token_state(AuthorizationServerProfile::Oauth2Baseline).await else {
        return;
    };
    let req = token_request("application/x-www-form-urlencoded");
    let body = Bytes::from_static(
        b"grant_type=client_credentials&client_id=client-1&audience=https%3A%2F%2Fapi.example",
    );

    assert_token_error(
        token(state, req, body).await,
        StatusCode::BAD_REQUEST,
        "invalid_request",
        false,
    )
    .await;
}

#[actix_web::test]
async fn token_endpoint_rejects_disallowed_fapi_password_grant_before_client_auth() {
    let Some(state) = live_token_state(AuthorizationServerProfile::Fapi2Security).await else {
        return;
    };
    let req = token_request("application/x-www-form-urlencoded");
    let body = Bytes::from_static(b"grant_type=password&username=alice&password=secret");

    assert_token_error(
        token(state, req, body).await,
        StatusCode::BAD_REQUEST,
        "unsupported_grant_type",
        false,
    )
    .await;
}

#[actix_web::test]
async fn token_endpoint_rejects_multiple_client_auth_methods_before_secret_verification() {
    let Some(state) = live_token_state(AuthorizationServerProfile::Oauth2Baseline).await else {
        return;
    };
    let basic = format!("Basic {}", B64.encode("client-1:secret"));
    let req = actix_web::test::TestRequest::post()
        .uri("/token")
        .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
        .insert_header((header::AUTHORIZATION, basic))
        .to_http_request();
    let body = Bytes::from_static(b"grant_type=client_credentials&client_id=client-1");

    assert_token_error(
        token(state.clone(), req, body).await,
        StatusCode::BAD_REQUEST,
        "invalid_request",
        false,
    )
    .await;

    let req = token_request("application/x-www-form-urlencoded");
    let body = Bytes::from_static(
        b"grant_type=client_credentials&client_id=client-1&client_secret=secret&client_assertion=jwt",
    );

    assert_token_error(
        token(state, req, body).await,
        StatusCode::BAD_REQUEST,
        "invalid_request",
        false,
    )
    .await;
}

#[actix_web::test]
async fn token_endpoint_reports_holder_key_requirement_before_generic_client_auth_failure() {
    let Some(state) = live_token_state(AuthorizationServerProfile::Oauth2Baseline).await else {
        return;
    };
    let req = token_request("application/x-www-form-urlencoded");
    let body = Bytes::from_static(b"grant_type=client_credentials&scope=accounts");

    assert_token_error(
        token(state, req, body).await,
        StatusCode::BAD_REQUEST,
        "invalid_request",
        false,
    )
    .await;
}

#[actix_web::test]
async fn token_endpoint_without_client_auth_material_uses_invalid_client_challenge() {
    let Some(state) = live_token_state(AuthorizationServerProfile::Oauth2Baseline).await else {
        return;
    };
    let req = token_request("application/x-www-form-urlencoded");
    let body = Bytes::from_static(b"grant_type=refresh_token&refresh_token=refresh-1");

    assert_token_error(
        token(state, req, body).await,
        StatusCode::UNAUTHORIZED,
        "invalid_client",
        false,
    )
    .await;
}

#[actix_web::test]
async fn token_endpoint_reports_dpop_bound_code_before_generic_client_auth_failure() {
    let Some(state) = live_token_state(AuthorizationServerProfile::Oauth2Baseline).await else {
        return;
    };
    let code = format!("code-{}", Uuid::now_v7());
    store_authorization_code_state(
        &state,
        &code,
        &AuthorizationCodeState::Pending {
            payload: code_payload(Some("dpop-thumbprint")),
        },
    )
    .await;
    let req = token_request("application/x-www-form-urlencoded");
    let body = Bytes::from(format!(
        "grant_type=authorization_code&code={}&code_verifier=verifier",
        urlencoding::encode(&code)
    ));

    assert_token_error(
        token(state, req, body).await,
        StatusCode::BAD_REQUEST,
        "invalid_grant",
        false,
    )
    .await;
}

#[actix_web::test]
async fn token_endpoint_reports_mtls_bound_code_before_generic_client_auth_failure() {
    let Some(state) = live_token_state(AuthorizationServerProfile::Oauth2Baseline).await else {
        return;
    };
    let code = format!("code-{}", Uuid::now_v7());
    store_authorization_code_state(
        &state,
        &code,
        &AuthorizationCodeState::Pending {
            payload: mtls_code_payload(),
        },
    )
    .await;
    let req = token_request("application/x-www-form-urlencoded");
    let body = Bytes::from(format!(
        "grant_type=authorization_code&code={}&code_verifier=verifier",
        urlencoding::encode(&code)
    ));

    assert_token_error(
        token(state, req, body).await,
        StatusCode::BAD_REQUEST,
        "invalid_request",
        false,
    )
    .await;
}

#[actix_web::test]
async fn missing_client_authorization_code_holder_check_fails_closed_when_valkey_is_unavailable() {
    let state = unavailable_valkey_token_state(AuthorizationServerProfile::Oauth2Baseline);
    let form = TokenForm {
        grant_type: "authorization_code".to_owned(),
        code: Some("code-unavailable".to_owned()),
        device_code: None,
        auth_req_id: None,
        redirect_uri: None,
        code_verifier: Some("verifier".to_owned()),
        refresh_token: None,
        device_secret: None,
        scope: None,
        client_id: None,
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
    };

    let response = missing_client_authorization_code_holder_error(&state, &form)
        .await
        .expect("authorization code state lookup failures must not be ignored");

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(oauth_error_code(&response), "server_error");
}

#[actix_web::test]
async fn missing_client_authorization_code_holder_check_fails_closed_when_client_lookup_errors() {
    let Some(state) =
        live_valkey_invalid_db_token_state(AuthorizationServerProfile::Oauth2Baseline).await
    else {
        return;
    };
    let code = format!("code-{}", Uuid::now_v7());
    store_authorization_code_state(
        &state,
        &code,
        &AuthorizationCodeState::Pending {
            payload: code_payload(None),
        },
    )
    .await;
    let form = TokenForm {
        grant_type: "authorization_code".to_owned(),
        code: Some(code),
        device_code: None,
        auth_req_id: None,
        redirect_uri: None,
        code_verifier: Some("verifier".to_owned()),
        refresh_token: None,
        device_secret: None,
        scope: None,
        client_id: None,
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
    };

    let response = missing_client_authorization_code_holder_error(&state, &form)
        .await
        .expect("client lookup failures must not degrade to invalid_client");

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(oauth_error_code(&response), "server_error");
}

#[actix_web::test]
async fn token_endpoint_reports_client_holder_policy_for_unbound_code_without_client_auth() {
    let Some(state) = live_token_state(AuthorizationServerProfile::Oauth2Baseline).await else {
        return;
    };
    insert_token_client(
        &state,
        "client-1",
        "confidential",
        "client_secret_post",
        Some(fixture_secret_hash(
            &state,
            &fixture_secret("holder-client"),
        )),
        vec!["authorization_code"],
        true,
        false,
        true,
    )
    .await;
    let code = format!("code-{}", Uuid::now_v7());
    store_authorization_code_state(
        &state,
        &code,
        &AuthorizationCodeState::Pending {
            payload: code_payload(None),
        },
    )
    .await;
    let req = token_request("application/x-www-form-urlencoded");
    let body = Bytes::from(format!(
        "grant_type=authorization_code&code={}&code_verifier=verifier",
        urlencoding::encode(&code)
    ));

    assert_token_error(
        token(state, req, body).await,
        StatusCode::BAD_REQUEST,
        "invalid_grant",
        false,
    )
    .await;
}

#[actix_web::test]
async fn token_endpoint_ignores_non_pending_code_state_during_missing_client_holder_check() {
    let Some(state) = live_token_state(AuthorizationServerProfile::Oauth2Baseline).await else {
        return;
    };
    let code = format!("code-{}", Uuid::now_v7());
    store_authorization_code_state(
        &state,
        &code,
        &AuthorizationCodeState::Failed {
            failed_at: Utc::now(),
            error: "invalid_grant".to_owned(),
        },
    )
    .await;
    let req = token_request("application/x-www-form-urlencoded");
    let body = Bytes::from(format!(
        "grant_type=authorization_code&code={}&code_verifier=verifier",
        urlencoding::encode(&code)
    ));

    assert_token_error(
        token(state, req, body).await,
        StatusCode::UNAUTHORIZED,
        "invalid_client",
        false,
    )
    .await;
}

#[actix_web::test]
async fn token_endpoint_rejects_malformed_code_state_during_missing_client_holder_check() {
    let Some(state) = live_token_state(AuthorizationServerProfile::Oauth2Baseline).await else {
        return;
    };
    let code = format!("code-{}", Uuid::now_v7());
    store_raw_authorization_code_state(&state, &code, "{not-json").await;
    let req = token_request("application/x-www-form-urlencoded");
    let body = Bytes::from(format!(
        "grant_type=authorization_code&code={}&code_verifier=verifier",
        urlencoding::encode(&code)
    ));

    assert_token_error(
        token(state, req, body).await,
        StatusCode::SERVICE_UNAVAILABLE,
        "server_error",
        false,
    )
    .await;
}

#[actix_web::test]
async fn token_endpoint_reports_unknown_client_after_extracting_client_secret_post_credentials() {
    let Some(state) = live_token_state(AuthorizationServerProfile::Oauth2Baseline).await else {
        return;
    };
    let req = token_request("application/x-www-form-urlencoded");
    let body = Bytes::from_static(
        b"grant_type=client_credentials&client_id=missing-token-client&client_secret=secret",
    );

    assert_token_error(
        token(state, req, body).await,
        StatusCode::UNAUTHORIZED,
        "invalid_client",
        false,
    )
    .await;
}

#[actix_web::test]
async fn token_endpoint_rejects_mtls_client_without_verified_certificate() {
    let Some(state) = live_token_state(AuthorizationServerProfile::Oauth2Baseline).await else {
        return;
    };
    insert_token_client(
        &state,
        "mtls-token-client",
        "confidential",
        "tls_client_auth",
        None,
        vec!["client_credentials"],
        false,
        true,
        true,
    )
    .await;
    let req = token_request("application/x-www-form-urlencoded");
    let body = Bytes::from_static(b"grant_type=client_credentials&client_id=mtls-token-client");

    assert_token_error(
        token(state, req, body).await,
        StatusCode::UNAUTHORIZED,
        "invalid_client",
        false,
    )
    .await;
}

#[actix_web::test]
async fn token_endpoint_rejects_mtls_client_with_mismatched_verified_certificate() {
    let Some(state) =
        live_trusted_proxy_token_state(AuthorizationServerProfile::Oauth2Baseline).await
    else {
        return;
    };
    let registered_thumbprint = fixture_mtls_thumbprint("registered-mismatch");
    let presented_thumbprint = fixture_mtls_thumbprint("presented-mismatch");
    insert_token_client(
        &state,
        "mtls-token-client-mismatch",
        "confidential",
        "tls_client_auth",
        None,
        vec!["client_credentials"],
        false,
        true,
        true,
    )
    .await;
    set_client_mtls_thumbprint(&state, "mtls-token-client-mismatch", &registered_thumbprint).await;
    let req = actix_web::test::TestRequest::post()
        .uri("/token")
        .peer_addr("127.0.0.1:12345".parse().expect("peer addr should parse"))
        .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
        .insert_header((
            header::HeaderName::from_static("x-ssl-client-verify"),
            "SUCCESS",
        ))
        .insert_header((
            header::HeaderName::from_static("x-ssl-client-cert-sha256"),
            presented_thumbprint.as_str(),
        ))
        .insert_header((
            header::HeaderName::from_static("x-ssl-client-subject-dn"),
            "CN=dispatch-actual",
        ))
        .to_http_request();
    let body =
        Bytes::from_static(b"grant_type=client_credentials&client_id=mtls-token-client-mismatch");

    assert_token_error(
        token(state, req, body).await,
        StatusCode::UNAUTHORIZED,
        "invalid_client",
        false,
    )
    .await;
}

#[actix_web::test]
async fn token_endpoint_rejects_inactive_client_before_secret_verification() {
    let Some(state) = live_token_state(AuthorizationServerProfile::Oauth2Baseline).await else {
        return;
    };
    let correct_secret = fixture_secret("inactive-correct");
    let wrong_secret = fixture_secret("inactive-wrong");
    insert_token_client(
        &state,
        "inactive-token-client",
        "confidential",
        "client_secret_post",
        Some(fixture_secret_hash(&state, &correct_secret)),
        vec!["client_credentials"],
        false,
        false,
        false,
    )
    .await;

    let req = token_request("application/x-www-form-urlencoded");
    let body = Bytes::from(format!(
        "grant_type=client_credentials&client_id=inactive-token-client&client_secret={}",
        urlencoding::encode(&wrong_secret)
    ));

    assert_token_error(
        token(state, req, body).await,
        StatusCode::BAD_REQUEST,
        "unauthorized_client",
        false,
    )
    .await;
}

#[actix_web::test]
async fn token_endpoint_applies_fapi_profile_checks_after_successful_client_secret_authentication()
{
    let Some(state) = live_token_state(AuthorizationServerProfile::Fapi2Security).await else {
        return;
    };
    let correct_secret = fixture_secret("fapi-secret");
    insert_token_client(
        &state,
        "fapi-secret-client",
        "confidential",
        "client_secret_post",
        Some(fixture_secret_hash(&state, &correct_secret)),
        vec!["client_credentials"],
        false,
        false,
        true,
    )
    .await;
    let req = token_request("application/x-www-form-urlencoded");
    let body = Bytes::from(format!(
        "grant_type=client_credentials&client_id=fapi-secret-client&client_secret={}",
        urlencoding::encode(&correct_secret)
    ));

    assert_token_error(
        token(state, req, body).await,
        StatusCode::UNAUTHORIZED,
        "invalid_client",
        false,
    )
    .await;
}

#[actix_web::test]
async fn token_endpoint_rejects_confidential_client_auth_method_mismatch() {
    let Some(state) = live_token_state(AuthorizationServerProfile::Oauth2Baseline).await else {
        return;
    };
    insert_token_client(
        &state,
        "private-key-jwt-client",
        "confidential",
        "private_key_jwt",
        None,
        vec!["client_credentials"],
        true,
        false,
        true,
    )
    .await;

    let req = token_request("application/x-www-form-urlencoded");
    let body =
        Bytes::from_static(b"grant_type=client_credentials&client_id=private-key-jwt-client");

    assert_token_error(
        token(state, req, body).await,
        StatusCode::UNAUTHORIZED,
        "invalid_client",
        false,
    )
    .await;
}

#[actix_web::test]
async fn token_endpoint_rejects_wrong_client_secret_before_grant_dispatch() {
    let Some(state) = live_token_state(AuthorizationServerProfile::Oauth2Baseline).await else {
        return;
    };
    let correct_secret = fixture_secret("mismatch-registered");
    let wrong_secret = fixture_secret("mismatch-presented");
    insert_token_client(
        &state,
        "secret-post-client",
        "confidential",
        "client_secret_post",
        Some(fixture_secret_hash(&state, &correct_secret)),
        vec!["client_credentials"],
        false,
        false,
        true,
    )
    .await;

    let req = token_request("application/x-www-form-urlencoded");
    let body = Bytes::from(format!(
        "grant_type=client_credentials&client_id=secret-post-client&client_secret={}",
        urlencoding::encode(&wrong_secret)
    ));

    assert_token_error(
        token(state, req, body).await,
        StatusCode::UNAUTHORIZED,
        "invalid_client",
        false,
    )
    .await;
}

#[actix_web::test]
async fn token_endpoint_rejects_public_client_credentials_material() {
    let Some(state) = live_token_state(AuthorizationServerProfile::Oauth2Baseline).await else {
        return;
    };
    insert_token_client(
        &state,
        "public-token-client",
        "public",
        "none",
        None,
        vec!["client_credentials"],
        false,
        false,
        true,
    )
    .await;

    let req = token_request("application/x-www-form-urlencoded");
    let body = Bytes::from_static(
        b"grant_type=client_credentials&client_id=public-token-client&client_secret=not-allowed",
    );

    assert_token_error(
        token(state, req, body).await,
        StatusCode::UNAUTHORIZED,
        "invalid_client",
        false,
    )
    .await;
}

#[actix_web::test]
async fn token_endpoint_returns_unsupported_grant_only_after_client_authentication() {
    let Some(state) = live_token_state(AuthorizationServerProfile::Oauth2Baseline).await else {
        return;
    };
    let correct_secret = fixture_secret("unsupported-grant");
    insert_token_client(
        &state,
        "unsupported-grant-client",
        "confidential",
        "client_secret_post",
        Some(fixture_secret_hash(&state, &correct_secret)),
        vec!["urn:example:unsupported"],
        false,
        false,
        true,
    )
    .await;

    let req = token_request("application/x-www-form-urlencoded");
    let body = Bytes::from(format!(
        "grant_type=urn%3Aexample%3Aunsupported&client_id=unsupported-grant-client&client_secret={}",
        urlencoding::encode(&correct_secret)
    ));

    assert_token_error(
        token(state, req, body).await,
        StatusCode::BAD_REQUEST,
        "unsupported_grant_type",
        false,
    )
    .await;
}

#[actix_web::test]
async fn token_endpoint_identifies_mtls_client_from_verified_certificate_without_client_id() {
    let Some(state) =
        live_trusted_proxy_token_state(AuthorizationServerProfile::Oauth2Baseline).await
    else {
        return;
    };
    let client_id = format!("mtls-cert-only-{}", Uuid::now_v7());
    let thumbprint = format!(
        "{:032x}{:032x}",
        Uuid::now_v7().as_u128(),
        Uuid::now_v7().as_u128()
    );
    insert_token_client(
        &state,
        &client_id,
        "confidential",
        "tls_client_auth",
        None,
        vec!["urn:example:unsupported"],
        false,
        false,
        true,
    )
    .await;
    set_client_mtls_thumbprint(&state, &client_id, &thumbprint).await;

    let req = actix_web::test::TestRequest::post()
        .uri("/token")
        .peer_addr("127.0.0.1:12345".parse().expect("peer addr should parse"))
        .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
        .insert_header((
            header::HeaderName::from_static("x-ssl-client-verify"),
            "SUCCESS",
        ))
        .insert_header((
            header::HeaderName::from_static("x-ssl-client-cert-sha256"),
            thumbprint.as_str(),
        ))
        .insert_header((
            header::HeaderName::from_static("x-ssl-client-subject-dn"),
            "CN=dispatch-mtls",
        ))
        .to_http_request();
    let body = Bytes::from_static(b"grant_type=urn%3Aexample%3Aunsupported");

    assert_token_error(
        token(state, req, body).await,
        StatusCode::BAD_REQUEST,
        "unsupported_grant_type",
        false,
    )
    .await;
}

#[actix_web::test]
async fn mtls_client_credentials_without_client_id_returns_none_when_client_not_active() {
    let Some(state) =
        live_trusted_proxy_token_state(AuthorizationServerProfile::Oauth2Baseline).await
    else {
        return;
    };
    let presented_thumbprint = fixture_mtls_thumbprint("unknown-client");
    let req = actix_web::test::TestRequest::post()
        .uri("/token")
        .peer_addr("127.0.0.1:12345".parse().expect("peer addr should parse"))
        .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
        .insert_header((
            header::HeaderName::from_static("x-ssl-client-verify"),
            "SUCCESS",
        ))
        .insert_header((
            header::HeaderName::from_static("x-ssl-client-cert-sha256"),
            presented_thumbprint.as_str(),
        ))
        .insert_header((
            header::HeaderName::from_static("x-ssl-client-subject-dn"),
            "CN=dispatch-mtls-unknown",
        ))
        .to_http_request();

    assert!(
        mtls_client_credentials_without_client_id(&state, &req)
            .await
            .expect("query should succeed when client certificate is unknown")
            .is_none()
    );
}

#[actix_web::test]
async fn missing_client_authorization_code_holder_error_returns_none_when_code_missing() {
    let Some(state) = live_token_state(AuthorizationServerProfile::Oauth2Baseline).await else {
        return;
    };
    let form = TokenForm {
        grant_type: "authorization_code".to_owned(),
        code: Some("missing-code".to_owned()),
        device_code: None,
        auth_req_id: None,
        redirect_uri: None,
        code_verifier: Some("verifier".to_owned()),
        refresh_token: None,
        device_secret: None,
        scope: None,
        client_id: None,
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
    };

    assert!(
        missing_client_authorization_code_holder_error(&state, &form)
            .await
            .is_none()
    );
}

#[actix_web::test]
async fn missing_client_authorization_code_holder_error_returns_none_when_client_is_not_sender_bound()
 {
    let Some(state) = live_token_state(AuthorizationServerProfile::Oauth2Baseline).await else {
        return;
    };
    let client_id = format!("holder-unbound-client-{}", Uuid::now_v7());
    insert_token_client(
        &state,
        &client_id,
        "confidential",
        "client_secret_post",
        Some(fixture_secret_hash(
            &state,
            &fixture_secret("holder-unbound"),
        )),
        vec!["authorization_code"],
        false,
        false,
        true,
    )
    .await;

    let code = format!("code-{}", Uuid::now_v7());
    let mut payload = code_payload(None);
    payload.client_id = client_id;
    store_authorization_code_state(&state, &code, &AuthorizationCodeState::Pending { payload })
        .await;

    let form = TokenForm {
        grant_type: "authorization_code".to_owned(),
        code: Some(code),
        device_code: None,
        auth_req_id: None,
        redirect_uri: None,
        code_verifier: Some("verifier".to_owned()),
        refresh_token: None,
        device_secret: None,
        scope: None,
        client_id: None,
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
    };

    assert!(
        missing_client_authorization_code_holder_error(&state, &form)
            .await
            .is_none()
    );
}

#[actix_web::test]
async fn token_endpoint_rejects_private_key_jwt_without_client_assertion() {
    let Some(state) = live_token_state(AuthorizationServerProfile::Oauth2Baseline).await else {
        return;
    };
    insert_token_client(
        &state,
        "private-key-jwt-missing-assertion-client",
        "confidential",
        "private_key_jwt",
        None,
        vec!["client_credentials"],
        true,
        false,
        true,
    )
    .await;

    let req = token_request("application/x-www-form-urlencoded");
    let body = Bytes::from_static(
        b"grant_type=client_credentials&client_id=private-key-jwt-missing-assertion-client",
    );

    assert_token_error(
        token(state, req, body).await,
        StatusCode::UNAUTHORIZED,
        "invalid_client",
        false,
    )
    .await;
}

#[actix_web::test]
async fn token_endpoint_rejects_private_key_jwt_with_invalid_assertion() {
    let Some(state) = live_token_state(AuthorizationServerProfile::Oauth2Baseline).await else {
        return;
    };
    let client_id = format!(
        "private-key-jwt-invalid-assertion-client-{}",
        Uuid::now_v7()
    );
    insert_token_client(
        &state,
        &client_id,
        "confidential",
        "private_key_jwt",
        None,
        vec!["client_credentials"],
        true,
        false,
        true,
    )
    .await;

    let req = token_request("application/x-www-form-urlencoded");
    let assertion = parseable_invalid_client_assertion(&client_id);
    let body = Bytes::from(format!(
        "grant_type=client_credentials&client_assertion_type={}&client_assertion={}",
        urlencoding::encode(CLIENT_ASSERTION_TYPE_JWT_BEARER),
        urlencoding::encode(&assertion)
    ));

    assert_token_error(
        token(state, req, body).await,
        StatusCode::UNAUTHORIZED,
        "invalid_client",
        false,
    )
    .await;
}

#[actix_web::test]
async fn token_endpoint_rejects_client_auth_if_token_rate_limit_is_exceeded() {
    let Some(state) = live_token_state(AuthorizationServerProfile::Oauth2Baseline).await else {
        return;
    };
    let mut settings = (*state.settings).clone();
    settings.rate_limit.token_max_requests = 0;
    let state = Data::new(AppState {
        diesel_db: state.diesel_db.clone(),
        valkey: state.valkey.clone(),
        settings: Arc::new(settings),
        keyset: state.keyset.clone(),
    });
    let correct_secret = fixture_secret("rate-limited");
    insert_token_client(
        &state,
        "rate-limited-client",
        "confidential",
        "client_secret_post",
        Some(fixture_secret_hash(&state, &correct_secret)),
        vec!["client_credentials"],
        false,
        false,
        true,
    )
    .await;

    let req = token_request("application/x-www-form-urlencoded");
    let body = Bytes::from(format!(
        "grant_type=client_credentials&client_id=rate-limited-client&client_secret={}",
        urlencoding::encode(&correct_secret)
    ));

    let response = token(state, req, body).await;
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(oauth_error_code(&response), "temporarily_unavailable");
}

#[actix_web::test]
async fn token_endpoint_rejects_client_lookup_db_failure_with_server_error() {
    let Some(state) =
        live_valkey_invalid_db_token_state(AuthorizationServerProfile::Oauth2Baseline).await
    else {
        return;
    };
    let req = token_request("application/x-www-form-urlencoded");
    let body = Bytes::from_static(
        b"grant_type=client_credentials&client_id=db-fail-client&client_secret=secret",
    );

    assert_token_error(
        token(state, req, body).await,
        StatusCode::SERVICE_UNAVAILABLE,
        "server_error",
        false,
    )
    .await;
}

#[actix_web::test]
async fn token_endpoint_fails_closed_when_certificate_only_mtls_client_lookup_errors() {
    let Some(state) =
        live_trusted_proxy_invalid_db_token_state(AuthorizationServerProfile::Oauth2Baseline).await
    else {
        return;
    };
    let presented_thumbprint = fixture_mtls_thumbprint("lookup-error");
    let req = actix_web::test::TestRequest::post()
        .uri("/token")
        .peer_addr("127.0.0.1:12345".parse().expect("peer addr should parse"))
        .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
        .insert_header((
            header::HeaderName::from_static("x-ssl-client-verify"),
            "SUCCESS",
        ))
        .insert_header((
            header::HeaderName::from_static("x-ssl-client-cert-sha256"),
            presented_thumbprint.as_str(),
        ))
        .insert_header((
            header::HeaderName::from_static("x-ssl-client-subject-dn"),
            "CN=dispatch-mtls",
        ))
        .to_http_request();
    let body = Bytes::from_static(b"grant_type=urn%3Aexample%3Aunsupported");

    assert_token_error(
        token(state, req, body).await,
        StatusCode::SERVICE_UNAVAILABLE,
        "server_error",
        false,
    )
    .await;
}

#[actix_web::test]
async fn token_endpoint_rejects_confidential_client_without_required_client_secret() {
    let Some(state) = live_token_state(AuthorizationServerProfile::Oauth2Baseline).await else {
        return;
    };
    let client_id = format!("secret-required-{}", Uuid::now_v7());
    let correct_secret = fixture_secret("required");
    insert_token_client(
        &state,
        &client_id,
        "confidential",
        "client_secret_post",
        Some(fixture_secret_hash(&state, &correct_secret)),
        vec!["client_credentials"],
        false,
        false,
        true,
    )
    .await;

    let req = token_request("application/x-www-form-urlencoded");
    let body = Bytes::from(format!(
        "grant_type=client_credentials&client_id={}",
        urlencoding::encode(&client_id)
    ));

    assert_token_error(
        token(state, req, body).await,
        StatusCode::UNAUTHORIZED,
        "invalid_client",
        false,
    )
    .await;
}

#[actix_web::test]
async fn token_endpoint_rejects_confidential_clients_with_unsupported_auth_method() {
    let Some(state) = live_token_state(AuthorizationServerProfile::Oauth2Baseline).await else {
        return;
    };
    let client_id = format!("confidential-none-{}", Uuid::now_v7());
    insert_token_client(
        &state,
        &client_id,
        "confidential",
        "none",
        None,
        vec!["client_credentials"],
        false,
        false,
        true,
    )
    .await;

    let req = token_request("application/x-www-form-urlencoded");
    let body = Bytes::from(format!(
        "grant_type=client_credentials&client_id={}",
        urlencoding::encode(&client_id)
    ));

    assert_token_error(
        token(state, req, body).await,
        StatusCode::UNAUTHORIZED,
        "invalid_client",
        false,
    )
    .await;
}

#[test]
fn pending_authorization_code_detects_dpop_binding() {
    let raw = serde_json::to_string(&AuthorizationCodeState::Pending {
        payload: code_payload(Some("thumbprint")),
    })
    .expect("pending code should serialize");

    assert!(
        pending_authorization_code_payload(&raw)
            .expect("state should parse")
            .is_some_and(|payload| payload.dpop_jkt.is_some())
    );
}

#[test]
fn non_dpop_or_non_pending_authorization_code_is_not_holder_bound() {
    let pending = serde_json::to_string(&AuthorizationCodeState::Pending {
        payload: code_payload(None),
    })
    .expect("pending code should serialize");
    let failed = serde_json::to_string(&AuthorizationCodeState::Failed {
        failed_at: Utc::now(),
        error: "invalid_grant".to_owned(),
    })
    .expect("failed code should serialize");

    assert!(
        pending_authorization_code_payload(&pending)
            .expect("state should parse")
            .is_some_and(|payload| payload.dpop_jkt.is_none())
    );
    assert!(
        pending_authorization_code_payload(&failed)
            .expect("state should parse")
            .is_none()
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
fn missing_client_dpop_authorization_code_holder_uses_invalid_grant() {
    let response = authorization_code_holder_missing_client_error(true, false)
        .expect("dpop holder binding should return an error");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(oauth_error_code(&response), "invalid_grant");
}

#[test]
fn missing_client_mtls_authorization_code_holder_uses_invalid_request() {
    for (dpop_bound, mtls_bound) in [(false, true), (true, true)] {
        let response = authorization_code_holder_missing_client_error(dpop_bound, mtls_bound)
            .expect("mtls holder binding should return an error");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(oauth_error_code(&response), "invalid_request");
    }
}

#[test]
fn missing_client_unbound_authorization_code_does_not_mask_client_auth_failure() {
    assert!(
        authorization_code_holder_missing_client_error(false, false).is_none(),
        "authorization codes without sender binding should proceed to normal client authentication"
    );
}

#[test]
fn missing_client_client_credentials_without_dpop_uses_invalid_request() {
    let form = TokenForm {
        grant_type: "client_credentials".to_owned(),
        code: None,
        device_code: None,
        auth_req_id: None,
        redirect_uri: None,
        code_verifier: None,
        refresh_token: None,
        device_secret: None,
        scope: Some("accounts".to_owned()),
        client_id: None,
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
    };
    let response = client_credentials_holder_missing_client_error(&form, false)
        .expect("missing DPoP proof should be reported before generic client auth");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(oauth_error_code(&response), "invalid_request");
}

#[test]
fn missing_client_holder_check_ignores_non_client_credentials_grants() {
    let form = TokenForm {
        grant_type: "refresh_token".to_owned(),
        code: None,
        device_code: None,
        auth_req_id: None,
        redirect_uri: None,
        code_verifier: None,
        refresh_token: Some("refresh-token".to_owned()),
        device_secret: None,
        scope: None,
        client_id: None,
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
    };

    assert!(client_credentials_holder_missing_client_error(&form, false).is_none());
}

#[test]
fn missing_client_client_credentials_with_dpop_stays_client_auth_failure() {
    let form = TokenForm {
        grant_type: "client_credentials".to_owned(),
        code: None,
        device_code: None,
        auth_req_id: None,
        redirect_uri: None,
        code_verifier: None,
        refresh_token: None,
        device_secret: None,
        scope: Some("accounts".to_owned()),
        client_id: None,
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
    };

    assert!(client_credentials_holder_missing_client_error(&form, true).is_none());
}

#[test]
fn missing_client_mtls_client_credentials_uses_invalid_request() {
    let form = TokenForm {
        grant_type: "client_credentials".to_owned(),
        code: None,
        device_code: None,
        auth_req_id: None,
        redirect_uri: None,
        code_verifier: None,
        refresh_token: None,
        device_secret: None,
        scope: Some("accounts".to_owned()),
        client_id: None,
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
    };

    let response = client_credentials_holder_missing_client_error(&form, false)
        .expect("missing holder-of-key proof should be reported before generic client auth");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(oauth_error_code(&response), "invalid_request");
}

#[test]
fn token_request_auth_material_detects_assertion_even_without_client_id() {
    let form = TokenForm {
        grant_type: "authorization_code".to_owned(),
        code: Some("code".to_owned()),
        device_code: None,
        auth_req_id: None,
        redirect_uri: None,
        code_verifier: None,
        refresh_token: None,
        device_secret: None,
        scope: None,
        client_id: None,
        client_secret: None,
        client_assertion_type: None,
        client_assertion: Some("malformed-or-missing-sub".to_owned()),
        assertion: None,
        requested_token_type: None,
        subject_token: None,
        subject_token_type: None,
        actor_token: None,
        actor_token_type: None,
        audiences: Vec::new(),
        has_audience_param: false,
    };

    assert!(token_request_has_client_auth_material(false, &form));
}

#[test]
fn token_request_auth_material_detects_each_registered_client_auth_channel() {
    let base = TokenForm {
        grant_type: "authorization_code".to_owned(),
        code: Some("code".to_owned()),
        device_code: None,
        auth_req_id: None,
        redirect_uri: None,
        code_verifier: None,
        refresh_token: None,
        device_secret: None,
        scope: None,
        client_id: None,
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
    };

    assert!(token_request_has_client_auth_material(true, &base));

    let mut with_client_id = base;
    with_client_id.client_id = Some("client-1".to_owned());
    assert!(token_request_has_client_auth_material(
        false,
        &with_client_id
    ));

    let mut with_secret = with_client_id;
    with_secret.client_id = None;
    with_secret.client_secret = Some("secret".to_owned());
    assert!(token_request_has_client_auth_material(false, &with_secret));

    let mut with_assertion_type = with_secret;
    with_assertion_type.client_secret = None;
    with_assertion_type.client_assertion_type =
        Some("urn:ietf:params:oauth:client-assertion-type:jwt-bearer".to_owned());
    assert!(token_request_has_client_auth_material(
        false,
        &with_assertion_type
    ));
}

#[test]
fn token_request_auth_material_allows_absent_client_credentials() {
    let form = TokenForm {
        grant_type: "authorization_code".to_owned(),
        code: Some("code".to_owned()),
        device_code: None,
        auth_req_id: None,
        redirect_uri: None,
        code_verifier: None,
        refresh_token: None,
        device_secret: None,
        scope: None,
        client_id: None,
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
    };

    assert!(!token_request_has_client_auth_material(false, &form));
}

#[test]
fn mtls_client_credentials_uses_tls_auth_method() {
    let credentials = mtls_client_credentials("client-1".to_owned());

    assert_eq!(credentials.client_id.as_deref(), Some("client-1"));
    assert_eq!(credentials.method, "tls_client_auth");
    assert!(credentials.client_secret.is_none());
    assert!(credentials.client_assertion.is_none());
}

#[test]
fn baseline_profile_does_not_restrict_token_client_auth() {
    let mut client = client();
    client.token_endpoint_auth_method = "client_secret_basic".to_owned();
    client.require_dpop_bound_tokens = false;

    assert!(
        validate_token_request_profile(
            &settings(AuthorizationServerProfile::Oauth2Baseline),
            &client,
            "client_secret_basic",
        )
        .is_ok()
    );
}

#[test]
fn disabled_client_is_rejected_before_grant_dispatch() {
    let mut client = client();
    client.is_active = false;

    let response = validate_token_client_enabled(&client, "authorization_code")
        .expect_err("disabled clients must not use token grants");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(oauth_error_code(&response), "unauthorized_client");
}

#[test]
fn active_client_with_registered_grant_is_allowed_to_dispatch() {
    let client = client();

    assert!(validate_token_client_enabled(&client, "authorization_code").is_ok());
}

#[test]
fn ciba_dispatch_requires_the_client_registered_grant() {
    let client = client();

    let response = validate_token_client_enabled(&client, CIBA_GRANT_TYPE)
        .expect_err("client without the CIBA grant must fail before CIBA execution");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(oauth_error_code(&response), "unauthorized_client");
}

#[test]
fn missing_grant_registration_is_rejected_before_grant_dispatch() {
    let client = client();

    let response = validate_token_client_enabled(&client, "client_credentials")
        .expect_err("client must be registered for the requested grant");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(oauth_error_code(&response), "unauthorized_client");
}

#[test]
fn fapi2_profile_requires_confidential_client_auth_and_sender_constraint() {
    let fapi = settings(AuthorizationServerProfile::Fapi2Security);
    let valid_client = client();

    assert!(validate_token_request_profile(&fapi, &valid_client, "private_key_jwt").is_ok());

    let weak_auth = validate_token_request_profile(&fapi, &valid_client, "client_secret_basic")
        .expect_err("client_secret_basic is not a FAPI2 client auth method");
    assert_eq!(weak_auth.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(oauth_error_code(&weak_auth), "invalid_client");

    let mut bearer_client = client();
    bearer_client.require_dpop_bound_tokens = false;
    let bearer = validate_token_request_profile(&fapi, &bearer_client, "private_key_jwt")
        .expect_err("FAPI2 requires sender-constrained tokens");
    assert_eq!(bearer.status(), StatusCode::BAD_REQUEST);
    assert_eq!(oauth_error_code(&bearer), "invalid_request");

    let mut public_client = client();
    public_client.client_type = "public".to_owned();
    let public = validate_token_request_profile(&fapi, &public_client, "none")
        .expect_err("FAPI2 rejects public clients");
    assert_eq!(public.status(), StatusCode::BAD_REQUEST);
    assert_eq!(oauth_error_code(&public), "unauthorized_client");
}

#[test]
fn fapi2_profile_accepts_mtls_confidential_sender_constrained_clients() {
    let fapi = settings(AuthorizationServerProfile::Fapi2Security);
    let mut client = client();
    client.token_endpoint_auth_method = "tls_client_auth".to_owned();
    client.require_dpop_bound_tokens = false;
    client.require_mtls_bound_tokens = true;

    assert!(
        validate_token_request_profile(&fapi, &client, "tls_client_auth").is_ok(),
        "FAPI2 allows confidential mTLS clients when tokens are sender constrained"
    );
}

#[test]
fn fapi2_profile_accepts_self_signed_mtls_confidential_sender_constrained_clients() {
    let fapi = settings(AuthorizationServerProfile::Fapi2Security);
    let mut client = client();
    client.token_endpoint_auth_method = "self_signed_tls_client_auth".to_owned();
    client.require_dpop_bound_tokens = false;
    client.require_mtls_bound_tokens = true;

    assert!(
        validate_token_request_profile(&fapi, &client, "self_signed_tls_client_auth").is_ok(),
        "FAPI2 allows self-signed mTLS when the client is confidential and sender constrained"
    );
}

#[test]
fn grant_dispatch_rejects_malformed_grant_registration_without_panicking() {
    let mut client = client();
    client.grant_types = json!("authorization_code");

    let response = validate_token_client_enabled(&client, "authorization_code")
        .expect_err("non-array grant_types must fail closed");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(oauth_error_code(&response), "unauthorized_client");
}
