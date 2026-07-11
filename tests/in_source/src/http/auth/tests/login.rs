use super::*;
use crate::config::ConfigSource;
use crate::db::create_pool;
use crate::domain::{ActiveSigningKey, Keyset, KeysetStore};
use std::sync::Arc;
use std::time::Duration as StdDuration;

use actix_web::cookie::Cookie;
use actix_web::http::header;
use diesel::sql_query;
use diesel::sql_types::{Bool, Text, Uuid as SqlUuid};
use fred::{
    interfaces::ClientLike,
    prelude::{
        Builder as ValkeyBuilder, Config as ValkeyConfig, ConnectionConfig, PerformanceConfig,
    },
};

fn login_request(content_type: &'static str) -> HttpRequest {
    actix_web::test::TestRequest::default()
        .insert_header((header::CONTENT_TYPE, content_type))
        .to_http_request()
}

fn form_origin_settings() -> Settings {
    let mut settings =
        Settings::from_config(&ConfigSource::default()).expect("default settings should load");
    settings.issuer = "https://issuer.example".to_owned();
    settings.frontend_base_url = "https://app.example/base/".to_owned();
    settings
}

#[test]
fn form_login_requires_exact_issuer_or_frontend_origin() {
    let settings = form_origin_settings();
    let request_without_origin = actix_web::test::TestRequest::default().to_http_request();
    let request_with_attacker_origin = actix_web::test::TestRequest::default()
        .insert_header((header::ORIGIN, "https://attacker.example"))
        .to_http_request();
    let request_with_issuer_origin = actix_web::test::TestRequest::default()
        .insert_header((header::ORIGIN, "https://issuer.example:443"))
        .to_http_request();
    let request_with_frontend_origin = actix_web::test::TestRequest::default()
        .insert_header((header::ORIGIN, "https://app.example"))
        .to_http_request();

    assert!(!form_login_origin_is_allowed(
        &settings,
        &request_without_origin
    ));
    assert!(!form_login_origin_is_allowed(
        &settings,
        &request_with_attacker_origin
    ));
    assert!(form_login_origin_is_allowed(
        &settings,
        &request_with_issuer_origin
    ));
    assert!(form_login_origin_is_allowed(
        &settings,
        &request_with_frontend_origin
    ));
}

#[test]
fn form_login_rejects_null_and_ambiguous_origins() {
    let settings = form_origin_settings();
    let null_origin = actix_web::test::TestRequest::default()
        .insert_header((header::ORIGIN, "null"))
        .to_http_request();
    let duplicate_origins = actix_web::test::TestRequest::default()
        .append_header((header::ORIGIN, "https://issuer.example"))
        .append_header((header::ORIGIN, "https://app.example"))
        .to_http_request();

    assert!(!form_login_origin_is_allowed(&settings, &null_origin));
    assert!(!form_login_origin_is_allowed(&settings, &duplicate_origins));
}

#[actix_web::test]
async fn form_login_without_trusted_origin_is_rejected_before_backend_access() {
    let state = AppState {
        diesel_db: create_pool(
            "postgres://nazo_login_test_invalid:nazo_login_test_invalid@127.0.0.1:1/nazo"
                .to_owned(),
            1,
        )
        .expect("pool construction should not connect"),
        valkey: fred::prelude::Builder::default_centralized()
            .build()
            .expect("valkey client construction should not connect"),
        settings: Arc::new(form_origin_settings()),
        keyset: KeysetStore::new(Keyset {
            active_kid: "test-kid".to_owned(),
            active_alg: jsonwebtoken::Algorithm::EdDSA,
            active_signing_key: ActiveSigningKey::LocalPkcs8Der(Vec::new()),
            verification_keys: Vec::new(),
        }),
    };
    let req = login_request("application/x-www-form-urlencoded");
    let response = login(
        Data::new(state),
        req,
        Bytes::from_static(b"email=user%40example.test&password=s3cret"),
    )
    .await;

    let (status, body) = error_json(response).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"], "access_denied");
}

fn test_login_password() -> String {
    ["correct", "horse", "battery", "staple"].join(" ")
}

fn form_encoded_test_login_password() -> String {
    test_login_password().replace(' ', "+")
}

async fn error_json(response: HttpResponse) -> (StatusCode, Value) {
    let status = response.status();
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("response body should collect");
    let body: Value = serde_json::from_slice(&body).expect("response should be json");
    (status, body)
}

#[test]
fn form_parser_accepts_login_fields_and_next() {
    let parsed = parse_login_form(
        "email=user%40example.test&password=s3cret&next=%2Fauthorize%3Fclient_id%3Dabc",
    )
    .expect("form should parse");
    assert_eq!(parsed.email, "user@example.test");
    assert_eq!(parsed.password, "s3cret");
    assert_eq!(parsed.next.as_deref(), Some("/authorize?client_id=abc"));
}

#[actix_web::test]
async fn form_parser_rejects_duplicate_login_fields() {
    let err =
        match parse_login_form("email=a%40example.test&email=b%40example.test&password=s3cret") {
            Ok(_) => panic!("duplicate login form field must be rejected"),
            Err(response) => response,
        };

    let (status, body) = error_json(err).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");
    assert!(body.get("access_token").is_none());
}

#[actix_web::test]
async fn login_request_parser_accepts_json_content_type_parameters() {
    let req = login_request("Application/JSON; charset=utf-8");
    let body = Bytes::from_static(
        br#"{"email":"User@Example.Test","password":"s3cret","next":"/authorize?client_id=abc"}"#,
    );

    let (payload, mode) =
        parse_login_request(&req, &body).expect("JSON login request should parse");

    assert!(matches!(mode, LoginResponseMode::Json));
    assert_eq!(payload.email, "User@Example.Test");
    assert_eq!(payload.password, "s3cret");
    assert_eq!(payload.next.as_deref(), Some("/authorize?client_id=abc"));
}

#[actix_web::test]
async fn login_request_parser_rejects_invalid_json_without_authentication_side_effects() {
    let req = login_request("application/json");
    let response =
        match parse_login_request(&req, &Bytes::from_static(br#"{"email":"a@example.test""#)) {
            Ok(_) => panic!("malformed JSON must not continue to rate limits or credential lookup"),
            Err(response) => response,
        };

    let (status, body) = error_json(response).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");
    assert!(body.get("csrf_token").is_none());
    assert!(body.get("expires_in").is_none());
}

#[actix_web::test]
async fn login_request_parser_rejects_form_bodies_that_are_not_utf8() {
    let req = login_request("application/x-www-form-urlencoded; charset=utf-8");
    let response = match parse_login_request(&req, &Bytes::from_static(&[0xff, 0xfe])) {
        Ok(_) => panic!("non-UTF-8 form input must fail before parsing credentials"),
        Err(response) => response,
    };

    let (status, body) = error_json(response).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");
    assert!(body.get("csrf_token").is_none());
}

#[actix_web::test]
async fn login_request_parser_rejects_missing_required_form_fields() {
    let req = login_request("application/x-www-form-urlencoded");
    let missing_email = match parse_login_request(&req, &Bytes::from_static(b"password=s3cret")) {
        Ok(_) => panic!("email is required"),
        Err(response) => response,
    };
    let missing_password =
        match parse_login_request(&req, &Bytes::from_static(b"email=a@example.test")) {
            Ok(_) => panic!("password is required"),
            Err(response) => response,
        };

    let (email_status, email_body) = error_json(missing_email).await;
    assert_eq!(email_status, StatusCode::BAD_REQUEST);
    assert_eq!(email_body["error"], "invalid_request");
    assert_eq!(email_body["error_description"], "email is required.");

    let (password_status, password_body) = error_json(missing_password).await;
    assert_eq!(password_status, StatusCode::BAD_REQUEST);
    assert_eq!(password_body["error"], "invalid_request");
    assert_eq!(password_body["error_description"], "password is required.");
}

#[actix_web::test]
async fn login_request_parser_rejects_unsupported_content_type() {
    let req = login_request("text/plain");
    let response = match parse_login_request(
        &req,
        &Bytes::from_static(b"email=a@example.test&password=s3cret"),
    ) {
        Ok(_) => panic!("login endpoint must reject ambiguous body encodings"),
        Err(response) => response,
    };

    let (status, body) = error_json(response).await;
    assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
    assert_eq!(body["error"], "invalid_request");
}

#[test]
fn safe_relative_next_allows_authorization_path_only_when_relative() {
    assert_eq!(
        safe_relative_next("/authorize?client_id=abc").as_deref(),
        Some("/authorize?client_id=abc")
    );
    assert!(safe_relative_next("https://evil.example/authorize").is_none());
    assert!(safe_relative_next("//evil.example/authorize").is_none());
    assert!(safe_relative_next("/ui/auth?next=%2Fauthorize").is_none());
    assert!(safe_relative_next("/authorize.evil/path").is_none());
}

#[test]
fn form_login_next_uses_safe_referer_next_or_profile_fallback() {
    let mut settings =
        Settings::from_config(&ConfigSource::default()).expect("default settings should load");
    settings.frontend_base_url = "https://app.example/base/".to_owned();
    let state = AppState {
        diesel_db: create_pool(
            "postgres://nazo_login_test_invalid:nazo_login_test_invalid@127.0.0.1:1/nazo"
                .to_owned(),
            1,
        )
        .expect("pool construction should not connect"),
        valkey: fred::prelude::Builder::default_centralized()
            .build()
            .expect("valkey client construction should not connect"),
        settings: std::sync::Arc::new(settings),
        keyset: KeysetStore::new(Keyset {
            active_kid: "test-kid".to_owned(),
            active_alg: jsonwebtoken::Algorithm::EdDSA,
            active_signing_key: ActiveSigningKey::LocalPkcs8Der(Vec::new()),
            verification_keys: Vec::new(),
        }),
    };
    let safe_referer = actix_web::test::TestRequest::default()
        .insert_header((
            header::REFERER,
            "https://app.example/login?next=%2Fauthorize%3Fclient_id%3Dabc",
        ))
        .to_http_request();
    let unsafe_referer = actix_web::test::TestRequest::default()
        .insert_header((header::REFERER, "https://app.example/login?next=%2Fprofile"))
        .to_http_request();

    assert_eq!(
        safe_form_login_next(&state, &safe_referer, None),
        "/authorize?client_id=abc"
    );
    assert_eq!(
        safe_form_login_next(&state, &unsafe_referer, Some("//evil.example/authorize")),
        "https://app.example/base/profile"
    );
}

#[actix_web::test]
async fn login_form_request_creates_session_and_redirects_to_safe_next() {
    let Some(fixture) = LiveLoginFixture::new().await else {
        return;
    };

    let password = test_login_password();
    let user = fixture
        .create_user(
            "form-success",
            "form-success@example.com",
            &password,
            true,
            false,
        )
        .await;
    let req = actix_web::test::TestRequest::default()
        .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
        .insert_header((header::ORIGIN, "https://app.example"))
        .insert_header((
            header::REFERER,
            "https://app.example/login?next=%2Fauthorize%3Fclient_id%3Dabc",
        ))
        .to_http_request();
    let body = Bytes::from(format!(
        "email={}&password={}&next=%2Fauthorize%3Fclient_id%3Dabc",
        urlencoding::encode(&user.email),
        form_encoded_test_login_password()
    ));

    let response = login(fixture.state.clone(), req, body.clone()).await;

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        response
            .headers()
            .get(header::LOCATION)
            .and_then(|value| value.to_str().ok()),
        Some("/authorize?client_id=abc")
    );

    let set_cookies = response
        .headers()
        .get_all(header::SET_COOKIE)
        .filter_map(|value| value.to_str().ok())
        .collect::<Vec<_>>();
    assert_eq!(set_cookies.len(), 2);
    assert!(
        set_cookies
            .iter()
            .any(|value| value.starts_with("nazo_session_test="))
    );
    assert!(
        set_cookies
            .iter()
            .any(|value| value.starts_with("nazo_csrf_test="))
    );
}

#[actix_web::test]
async fn login_json_request_returns_session_payload_for_mfa_enabled_user_when_not_remembered() {
    let Some(fixture) = LiveLoginFixture::new().await else {
        return;
    };

    let password = test_login_password();
    let user = fixture
        .create_user(
            "json-required-mfa",
            "required-mfa@example.com",
            &password,
            true,
            true,
        )
        .await;
    let req = actix_web::test::TestRequest::default()
        .insert_header((header::CONTENT_TYPE, "application/json"))
        .to_http_request();
    let body = Bytes::from(format!(
        r#"{{"email":"{}","password":"{}"}}"#,
        user.email, password
    ));

    let response = login(fixture.state.clone(), req, body.clone()).await;
    let response_body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("JSON login body should be readable");
    let response_body =
        serde_json::from_slice::<Value>(&response_body).expect("JSON login response should parse");

    assert_eq!(response_body["mfa_required"], json!(true));
}

#[actix_web::test]
async fn login_json_request_returns_session_payload_for_remembered_mfa_device() {
    let Some(fixture) = LiveLoginFixture::new().await else {
        return;
    };

    let password = test_login_password();
    let user = fixture
        .create_user(
            "json-remembered-mfa",
            "remembered-mfa@example.com",
            &password,
            true,
            true,
        )
        .await;
    let remember_request = actix_web::test::TestRequest::default()
        .insert_header((header::USER_AGENT, "unit-test-agent"))
        .to_http_request();
    let remember_token = remember_mfa_device(&fixture.state, &remember_request, &user)
        .await
        .expect("remembered device token should be generated");
    let req = actix_web::test::TestRequest::default()
        .insert_header((header::CONTENT_TYPE, "application/json"))
        .insert_header((header::USER_AGENT, "unit-test-agent"))
        .cookie(Cookie::new(
            crate::support::MFA_REMEMBERED_COOKIE_NAME,
            remember_token,
        ))
        .to_http_request();
    let body = Bytes::from(format!(
        r#"{{"email":"{}","password":"{}"}}"#,
        user.email, password
    ));

    let response = login(fixture.state.clone(), req, body.clone()).await;
    let response_body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("JSON login body should be readable");
    let response_body =
        serde_json::from_slice::<Value>(&response_body).expect("JSON login response should parse");

    assert_eq!(response_body["mfa_required"], json!(false));
    assert!(response_body["csrf_token"].is_string());
    assert_eq!(
        response_body["expires_in"],
        json!(fixture.state.settings.session_ttl_seconds)
    );
}

#[actix_web::test]
async fn login_rejects_missing_user_as_access_denied() {
    let Some(fixture) = LiveLoginFixture::new().await else {
        return;
    };
    let req = actix_web::test::TestRequest::default()
        .insert_header((header::CONTENT_TYPE, "application/json"))
        .to_http_request();
    let body = Bytes::from_static(br#"{"email":"missing@example.com","password":"pass"}"#);

    let response = login(fixture.state.clone(), req, body).await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("login failure body should be readable");
    let body: Value = serde_json::from_slice(&body).expect("login failure body should parse");
    assert_eq!(body["error"], "access_denied");
}

#[actix_web::test]
async fn login_rejects_wrong_password_as_access_denied() {
    let Some(fixture) = LiveLoginFixture::new().await else {
        return;
    };
    let password = test_login_password();
    let user = fixture
        .create_user(
            "wrong-password",
            "wrong-password@example.com",
            &password,
            true,
            false,
        )
        .await;
    let req = actix_web::test::TestRequest::default()
        .insert_header((header::CONTENT_TYPE, "application/json"))
        .to_http_request();
    let body = Bytes::from(format!(
        r#"{{"email":"{}","password":"{}"}}"#,
        user.email, "wrong"
    ));

    let response = login(fixture.state.clone(), req, body).await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("login failure body should be readable");
    let body: Value = serde_json::from_slice(&body).expect("login failure body should parse");
    assert_eq!(body["error"], "access_denied");
}

#[actix_web::test]
async fn login_throttles_repeated_failures_for_same_email_and_source() {
    let Some(fixture) = LiveLoginFixture::new_with_login_failure_limits(10, 2).await else {
        return;
    };
    let password = test_login_password();
    let user = fixture
        .create_user(
            "failure-throttle",
            "failure-throttle@example.com",
            &password,
            true,
            false,
        )
        .await;

    for _ in 0..2 {
        let response = fixture.login_json(&user.email, "wrong").await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    let response = fixture.login_json(&user.email, "wrong").await;
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        response
            .headers()
            .get(header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok()),
        Some("60")
    );
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("throttled login body should be readable");
    let body: Value = serde_json::from_slice(&body).expect("throttled body should parse");
    assert_eq!(body["error"], "temporarily_unavailable");
}

#[actix_web::test]
async fn successful_login_clears_previous_failure_throttle_state() {
    let Some(fixture) = LiveLoginFixture::new_with_login_failure_limits(10, 2).await else {
        return;
    };
    let password = test_login_password();
    let user = fixture
        .create_user(
            "failure-clear",
            "failure-clear@example.com",
            &password,
            true,
            false,
        )
        .await;

    let response = fixture.login_json(&user.email, "wrong").await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let response = fixture.login_json(&user.email, &password).await;
    assert_eq!(response.status(), StatusCode::OK);

    for _ in 0..2 {
        let response = fixture.login_json(&user.email, "wrong").await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
    let response = fixture.login_json(&user.email, "wrong").await;
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[actix_web::test]
async fn login_rejects_inactive_user_as_access_denied() {
    let Some(fixture) = LiveLoginFixture::new().await else {
        return;
    };
    let password = test_login_password();
    let user = fixture
        .create_user(
            "inactive-user",
            "inactive-user@example.com",
            &password,
            false,
            false,
        )
        .await;
    let req = actix_web::test::TestRequest::default()
        .insert_header((header::CONTENT_TYPE, "application/json"))
        .to_http_request();
    let body = Bytes::from(format!(
        r#"{{"email":"{}","password":"{}"}}"#,
        user.email, password
    ));

    let response = login(fixture.state.clone(), req, body).await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("login failure body should be readable");
    let body: Value = serde_json::from_slice(&body).expect("login failure body should parse");
    assert_eq!(body["error"], "access_denied");
}

#[actix_web::test]
async fn login_reports_rate_limit_infrastructure_failure_as_service_unavailable() {
    let Some(state) = LoginBadValkeyState::new().await else {
        return;
    };

    let req = actix_web::test::TestRequest::default()
        .insert_header((header::CONTENT_TYPE, "application/json"))
        .to_http_request();
    let body = Bytes::from_static(br#"{"email":"a@example.com","password":"wrong"}"#);

    let response = login(Data::new(state.state), req, body).await;

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("login failure body should be readable");
    let body: Value = serde_json::from_slice(&body).expect("login failure body should parse");
    assert_eq!(body["error"], "server_error");
}

#[actix_web::test]
async fn login_reports_user_lookup_failure_as_service_unavailable() {
    let Some(state) = LoginBadDatabaseState::new().await else {
        return;
    };

    let req = actix_web::test::TestRequest::default()
        .insert_header((header::CONTENT_TYPE, "application/json"))
        .to_http_request();
    let body = Bytes::from_static(br#"{"email":"missing@example.com","password":"wrong"}"#);

    let response = login(Data::new(state.state), req, body).await;

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("login failure body should be readable");
    let body: Value = serde_json::from_slice(&body).expect("login failure body should parse");
    assert_eq!(body["error"], "server_error");
}

struct LiveLoginFixture {
    state: Data<AppState>,
}

impl LiveLoginFixture {
    async fn new() -> Option<Self> {
        Self::new_with_login_failure_limits(50, 5).await
    }

    async fn new_with_login_failure_limits(
        email_max_attempts: u64,
        ip_email_max_attempts: u64,
    ) -> Option<Self> {
        let database_url = std::env::var("DATABASE_URL").ok()?;
        let valkey_url = std::env::var("VALKEY_URL").ok()?;
        let config = ConfigSource::from_pairs_for_test([
            ("ISSUER", "https://example.com"),
            ("FRONTEND_BASE_URL", "https://app.example"),
            (
                "CLIENT_SECRET_PEPPER",
                "client-secret-pepper-for-tests-000000000001",
            ),
            ("COOKIE_SECURE", "true"),
            ("SESSION_COOKIE_NAME", "nazo_session_test"),
            ("CSRF_COOKIE_NAME", "nazo_csrf_test"),
        ]);
        let mut settings = Settings::from_config(&config).expect("test settings should load");
        settings.rate_limit.auth_max_requests = 100_000;
        settings.rate_limit.login_failure_window_seconds = 60;
        settings.rate_limit.login_failure_email_max_attempts = email_max_attempts;
        settings.rate_limit.login_failure_ip_email_max_attempts = ip_email_max_attempts;

        let valkey_config = ValkeyConfig::from_url(&valkey_url).ok()?;
        let mut valkey_builder = ValkeyBuilder::from_config(valkey_config);
        valkey_builder.with_performance_config(|performance: &mut PerformanceConfig| {
            performance.default_command_timeout = StdDuration::from_secs(2);
        });
        valkey_builder.with_connection_config(|connection: &mut ConnectionConfig| {
            connection.connection_timeout = StdDuration::from_secs(2);
            connection.internal_command_timeout = StdDuration::from_secs(2);
            connection.max_command_attempts = 1;
        });
        let valkey = valkey_builder.build().expect("valkey client should build");
        valkey.init().await.expect("valkey client should connect");

        Some(Self {
            state: Data::new(AppState {
                diesel_db: create_pool(database_url, 4).expect("database pool should build"),
                valkey,
                settings: Arc::new(settings),
                keyset: KeysetStore::new(Keyset {
                    active_kid: "test-kid".to_owned(),
                    active_alg: jsonwebtoken::Algorithm::EdDSA,
                    active_signing_key: ActiveSigningKey::LocalPkcs8Der(Vec::new()),
                    verification_keys: Vec::new(),
                }),
            }),
        })
    }

    async fn login_json(&self, email: &str, password: &str) -> HttpResponse {
        let req = actix_web::test::TestRequest::default()
            .insert_header((header::CONTENT_TYPE, "application/json"))
            .to_http_request();
        let body = Bytes::from(format!(
            r#"{{"email":"{}","password":"{}"}}"#,
            email, password
        ));
        login(self.state.clone(), req, body).await
    }

    async fn create_user(
        &self,
        suffix: &str,
        email: &str,
        password: &str,
        is_active: bool,
        mfa_enabled: bool,
    ) -> UserRow {
        let unique = Uuid::now_v7().simple().to_string();
        let username = format!("login-{suffix}-{unique}");
        let email = unique_test_email(email, &unique);
        let password_hash =
            hash_password(password).expect("password hash should be generated for test user");
        let mut conn = get_conn(&self.state.diesel_db)
            .await
            .expect("database connection");
        sql_query(
            r#"
            INSERT INTO users (
                tenant_id, realm_id, organization_id, username, email,
                password_hash, is_active, mfa_enabled, email_verified, role, admin_level
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, true, 'user', 0)
            RETURNING *
            "#,
        )
        .bind::<SqlUuid, _>(DEFAULT_TENANT_ID)
        .bind::<SqlUuid, _>(DEFAULT_REALM_ID)
        .bind::<SqlUuid, _>(DEFAULT_ORGANIZATION_ID)
        .bind::<Text, _>(username)
        .bind::<Text, _>(email)
        .bind::<Text, _>(password_hash)
        .bind::<Bool, _>(is_active)
        .bind::<Bool, _>(mfa_enabled)
        .get_result::<UserRow>(&mut conn)
        .await
        .expect("test user should insert")
    }
}

fn unique_test_email(email: &str, unique: &str) -> String {
    let Some((local, domain)) = email.split_once('@') else {
        return format!("{email}-{unique}");
    };
    format!("{local}+{unique}@{domain}")
}

struct LoginBadValkeyState {
    state: AppState,
}

impl LoginBadValkeyState {
    async fn new() -> Option<Self> {
        let database_url =
            "postgres://nazo_login_valkey_invalid:nazo_login_valkey_invalid@127.0.0.1:1/nazo"
                .to_owned();
        let config = ConfigSource::from_pairs_for_test([
            ("ISSUER", "https://example.com"),
            (
                "CLIENT_SECRET_PEPPER",
                "client-secret-pepper-for-tests-000000000001",
            ),
            ("COOKIE_SECURE", "true"),
            ("SESSION_COOKIE_NAME", "nazo_session_test"),
            ("CSRF_COOKIE_NAME", "nazo_csrf_test"),
        ]);
        let settings = Settings::from_config(&config).expect("test settings should load");

        let valkey_url = "redis://127.0.0.1:1/0";
        let mut valkey_builder =
            ValkeyBuilder::from_config(ValkeyConfig::from_url(valkey_url).ok()?);
        valkey_builder.with_performance_config(|performance: &mut PerformanceConfig| {
            performance.default_command_timeout = StdDuration::from_millis(50);
        });
        valkey_builder.with_connection_config(|connection: &mut ConnectionConfig| {
            connection.connection_timeout = StdDuration::from_millis(100);
            connection.internal_command_timeout = StdDuration::from_millis(100);
            connection.max_command_attempts = 1;
        });
        let valkey = valkey_builder.build().expect("valkey client should build");

        Some(Self {
            state: AppState {
                diesel_db: create_pool(database_url, 1).expect("database pool should build"),
                valkey,
                settings: Arc::new(settings),
                keyset: KeysetStore::new(Keyset {
                    active_kid: "test-kid".to_owned(),
                    active_alg: jsonwebtoken::Algorithm::EdDSA,
                    active_signing_key: ActiveSigningKey::LocalPkcs8Der(Vec::new()),
                    verification_keys: Vec::new(),
                }),
            },
        })
    }
}

struct LoginBadDatabaseState {
    state: AppState,
}

impl LoginBadDatabaseState {
    async fn new() -> Option<Self> {
        let valkey_url = std::env::var("VALKEY_URL").ok()?;
        let config = ConfigSource::from_pairs_for_test([
            ("ISSUER", "https://example.com"),
            (
                "CLIENT_SECRET_PEPPER",
                "client-secret-pepper-for-tests-000000000001",
            ),
            ("COOKIE_SECURE", "true"),
            ("SESSION_COOKIE_NAME", "nazo_session_test"),
            ("CSRF_COOKIE_NAME", "nazo_csrf_test"),
        ]);
        let mut settings = Settings::from_config(&config).expect("test settings should load");
        settings.rate_limit.auth_max_requests = 100_000;

        let valkey_config = ValkeyConfig::from_url(&valkey_url).ok()?;
        let mut valkey_builder = ValkeyBuilder::from_config(valkey_config);
        valkey_builder.with_performance_config(|performance: &mut PerformanceConfig| {
            performance.default_command_timeout = StdDuration::from_secs(2);
        });
        valkey_builder.with_connection_config(|connection: &mut ConnectionConfig| {
            connection.connection_timeout = StdDuration::from_secs(2);
            connection.internal_command_timeout = StdDuration::from_secs(2);
            connection.max_command_attempts = 1;
        });
        let valkey = valkey_builder.build().expect("valkey client should build");
        valkey.init().await.expect("valkey client should connect");

        Some(Self {
            state: AppState {
                diesel_db: create_pool(
                    "postgres://nazo_login_db_invalid:nazo_login_db_invalid@127.0.0.1:1/nazo"
                        .to_owned(),
                    1,
                )
                .expect("database pool should build"),
                valkey,
                settings: Arc::new(settings),
                keyset: KeysetStore::new(Keyset {
                    active_kid: "test-kid".to_owned(),
                    active_alg: jsonwebtoken::Algorithm::EdDSA,
                    active_signing_key: ActiveSigningKey::LocalPkcs8Der(Vec::new()),
                    verification_keys: Vec::new(),
                }),
            },
        })
    }
}
