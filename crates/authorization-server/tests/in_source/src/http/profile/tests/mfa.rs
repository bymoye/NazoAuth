use super::*;
use nazo_identity::{TenantId, UserId, ports::TotpEnrollment};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration as StdDuration;

use crate::schema::{user_totp_credentials, users};

use actix_web::{cookie::Cookie, http::header};
use chrono::Duration;
use diesel::prelude::*;
use diesel::sql_query;
use diesel::sql_types::{Bool, Text, Uuid as SqlUuid};
use diesel_async::RunQueryDsl;
use fred::interfaces::ClientLike;
use fred::prelude::{
    Builder as ValkeyBuilder, Config as ValkeyConfig, ConnectionConfig, PerformanceConfig,
};

use crate::config::ConfigSource;
use crate::domain::TestAppState;
use crate::test_support::remember_mfa_device;
use crate::test_support::replace_backup_codes;
use crate::test_support::verify_user_mfa_code;
use nazo_postgres::create_pool;
use nazo_postgres::get_conn;

use crate::schema::{user_mfa_backup_codes, user_mfa_remembered_devices};

fn test_state() -> TestAppState {
    TestAppState {
        diesel_db: create_pool(
            "postgres://nazo_mfa_test_invalid:nazo_mfa_test_invalid@127.0.0.1:1/nazo".to_owned(),
            1,
        )
        .expect("pool construction should not connect"),
        valkey: fred::prelude::Builder::default_centralized()
            .build()
            .expect("valkey client construction should not connect"),
        settings: Arc::new(
            Settings::from_config(&ConfigSource::default()).expect("default settings should load"),
        ),
        keyset: crate::test_support::test_key_manager(),
    }
}

fn request_with_session_but_no_csrf(state: &TestAppState) -> HttpRequest {
    actix_web::test::TestRequest::default()
        .cookie(Cookie::new(
            state.settings.session.session_cookie_name.clone(),
            "active-session",
        ))
        .to_http_request()
}

fn mfa_handles(state: &Data<TestAppState>) -> Data<MfaProfileHandles> {
    Data::new(MfaProfileHandles::from_app_state(state))
}

struct LiveMfaFixture {
    state: Data<TestAppState>,
}

#[derive(QueryableByName)]
struct AuditOutcomeRow {
    #[diesel(sql_type = Text)]
    outcome: String,
}

impl LiveMfaFixture {
    async fn new() -> Option<Self> {
        Self::new_with_rate_limit(100_000).await
    }

    async fn new_with_rate_limit(max_requests: u64) -> Option<Self> {
        let database_url = std::env::var("DATABASE_URL").ok()?;
        let valkey_url = std::env::var("VALKEY_URL").ok()?;
        let config = ConfigSource::from_pairs_for_test([
            ("ISSUER", "https://example.com"),
            (
                "CLIENT_SECRET_PEPPER",
                "client-secret-pepper-for-tests-000000000001",
            ),
            ("COOKIE_SECURE", "true"),
            ("SESSION_COOKIE_NAME", "nazo_session_mfa_test"),
            ("CSRF_COOKIE_NAME", "nazo_csrf_mfa_test"),
        ]);
        let mut settings = Settings::from_config(&config).expect("test settings should load");
        settings.identity.rate_limit.auth_max_requests = max_requests;
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

        Some(Self {
            state: Data::new(TestAppState {
                diesel_db: create_pool(database_url, 4).expect("database pool should build"),
                valkey,
                settings: Arc::new(settings),
                keyset: crate::test_support::test_key_manager(),
            }),
        })
    }

    async fn create_user(&self, suffix: &str, mfa_enabled: bool) -> DatabaseUserFixture {
        let email = format!("mfa-{suffix}@example.com");
        let username = format!("mfa-{suffix}");
        let mut conn = get_conn(&self.state.diesel_db)
            .await
            .expect("database connection");
        sql_query(
            r#"
            INSERT INTO users (
                tenant_id, realm_id, organization_id, username, email,
                password_hash, is_active, mfa_enabled, email_verified, role, admin_level
            )
            VALUES ($1, $2, $3, $4, $5, 'unused-mfa-test-hash', $6, $7, true, 'user', 0)
            RETURNING *
            "#,
        )
        .bind::<SqlUuid, _>(DEFAULT_TENANT_ID)
        .bind::<SqlUuid, _>(DEFAULT_REALM_ID)
        .bind::<SqlUuid, _>(DEFAULT_ORGANIZATION_ID)
        .bind::<Text, _>(username)
        .bind::<Text, _>(email)
        .bind::<Bool, _>(true)
        .bind::<Bool, _>(mfa_enabled)
        .get_result::<DatabaseUserFixture>(&mut conn)
        .await
        .expect("test user should insert")
    }

    async fn insert_confirmed_totp(&self, user: &DatabaseUserFixture, secret_base32: &str) {
        let mut conn = get_conn(&self.state.diesel_db)
            .await
            .expect("database connection");
        sql_query(
            r#"
            INSERT INTO user_totp_credentials (
                tenant_id, user_id, secret_base32, label, confirmed_at, last_used_step
            )
            VALUES ($1, $2, $3, 'Test TOTP', now(), NULL)
            "#,
        )
        .bind::<SqlUuid, _>(user.tenant_id)
        .bind::<SqlUuid, _>(user.id)
        .bind::<Text, _>(secret_base32.to_owned())
        .execute(&mut conn)
        .await
        .expect("confirmed TOTP credential should insert");
    }

    async fn store_session(&self, user: &DatabaseUserFixture, sid: &str, pending_mfa: bool) {
        let payload = SessionPayload {
            user_id: user.id,
            auth_time: Utc::now().timestamp(),
            amr: vec!["pwd".to_owned()],
            pending_mfa,
            oidc_sid: Some(format!("oidc-{sid}")),
        };
        valkey_set_ex(
            &self.state.valkey,
            format!("oauth:session:{sid}"),
            serde_json::to_string(&payload).expect("session should serialize"),
            self.state.settings.session.session_ttl_seconds,
        )
        .await
        .expect("session should store");
    }

    fn request(&self, sid: &str, csrf: &str) -> HttpRequest {
        self.request_from(sid, csrf, None)
    }

    fn request_from(&self, sid: &str, csrf: &str, peer_addr: Option<SocketAddr>) -> HttpRequest {
        let mut request = actix_web::test::TestRequest::default();
        if let Some(peer_addr) = peer_addr {
            request = request.peer_addr(peer_addr);
        }
        request
            .cookie(Cookie::new(
                self.state.settings.session.session_cookie_name.clone(),
                sid.to_owned(),
            ))
            .cookie(Cookie::new(
                self.state.settings.session.csrf_cookie_name.clone(),
                csrf.to_owned(),
            ))
            .insert_header(("x-csrf-token", csrf))
            .to_http_request()
    }

    async fn session_payload(&self, sid: &str) -> SessionPayload {
        self.optional_session_payload(sid)
            .await
            .expect("session should remain present")
    }

    async fn optional_session_payload(&self, sid: &str) -> Option<SessionPayload> {
        valkey_get(&self.state.valkey, &format!("oauth:session:{sid}"))
            .await
            .expect("session lookup should succeed")
            .map(|raw| serde_json::from_str(&raw).expect("session payload should deserialize"))
    }
}

async fn response_json(response: HttpResponse) -> (StatusCode, Value, bool) {
    let status = response.status();
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL),
        Some(&header::HeaderValue::from_static("no-store")),
        "every MFA response must prevent persistent caching"
    );
    assert_eq!(
        response.headers().get(header::PRAGMA),
        Some(&header::HeaderValue::from_static("no-cache")),
        "legacy intermediaries must also be told not to cache MFA responses"
    );
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE),
        Some(&header::HeaderValue::from_static("application/json")),
        "MFA response media type is part of the HTTP contract"
    );
    let has_set_cookie = response.headers().contains_key(header::SET_COOKIE);
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("response body should be readable");
    let json = serde_json::from_slice(&body).expect("response should be json");
    (status, json, has_set_cookie)
}

fn set_cookie_value(response: &HttpResponse, cookie_name: &str) -> Option<String> {
    response
        .headers()
        .get_all(header::SET_COOKIE)
        .filter_map(|value| value.to_str().ok())
        .find_map(|raw| {
            let (name, value) = raw.split(';').next()?.split_once('=')?;
            (name == cookie_name).then(|| value.to_owned())
        })
}

async fn remembered_device_count(fixture: &LiveMfaFixture, user: &DatabaseUserFixture) -> i64 {
    let mut conn = get_conn(&fixture.state.diesel_db)
        .await
        .expect("database connection");
    user_mfa_remembered_devices::table
        .filter(user_mfa_remembered_devices::tenant_id.eq(user.tenant_id))
        .filter(user_mfa_remembered_devices::user_id.eq(user.id))
        .count()
        .get_result::<i64>(&mut conn)
        .await
        .expect("remembered device count should load")
}

async fn backup_code_count(fixture: &LiveMfaFixture, user: &DatabaseUserFixture) -> i64 {
    let mut conn = get_conn(&fixture.state.diesel_db)
        .await
        .expect("database connection");
    user_mfa_backup_codes::table
        .filter(user_mfa_backup_codes::tenant_id.eq(user.tenant_id))
        .filter(user_mfa_backup_codes::user_id.eq(user.id))
        .count()
        .get_result::<i64>(&mut conn)
        .await
        .expect("backup code count should load")
}

async fn totp_credential_count(fixture: &LiveMfaFixture, user: &DatabaseUserFixture) -> i64 {
    let mut conn = get_conn(&fixture.state.diesel_db)
        .await
        .expect("database connection");
    user_totp_credentials::table
        .filter(user_totp_credentials::tenant_id.eq(user.tenant_id))
        .filter(user_totp_credentials::user_id.eq(user.id))
        .count()
        .get_result::<i64>(&mut conn)
        .await
        .expect("totp credential count should load")
}

async fn pending_totp_credential(
    fixture: &LiveMfaFixture,
    user: &DatabaseUserFixture,
) -> TotpEnrollment {
    nazo_postgres::MfaRepository::new(fixture.state.diesel_db.clone())
        .totp_enrollment(
            TenantId::new(user.tenant_id).expect("valid fixture tenant ID"),
            UserId::new(user.id).expect("valid fixture user ID"),
        )
        .await
        .expect("totp credential lookup should succeed")
        .expect("totp credential should exist")
}

async fn fresh_user(fixture: &LiveMfaFixture, user_id: Uuid) -> DatabaseUserFixture {
    let mut conn = get_conn(&fixture.state.diesel_db)
        .await
        .expect("database connection");
    users::table
        .find(user_id)
        .select(DatabaseUserFixture::as_select())
        .first::<DatabaseUserFixture>(&mut conn)
        .await
        .expect("user should reload")
}

async fn assert_mfa_endpoint_rejects_missing_csrf(response: HttpResponse) {
    let (status, body, has_set_cookie) = response_json(response).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");
    assert_eq!(body["error_description"], "Request failed.");
    assert!(body.get("secret_base32").is_none());
    assert!(body.get("otpauth_uri").is_none());
    assert!(body.get("backup_codes").is_none());
    assert!(body.get("success").is_none());
    assert!(body.get("mfa_enabled").is_none());
    assert!(
        !has_set_cookie,
        "CSRF failure must not create, replace, remember, or clear session cookies"
    );
}

async fn assert_mfa_endpoint_requires_login(response: HttpResponse) {
    let (status, body, has_set_cookie) = response_json(response).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "login_required");
    assert!(body.get("secret_base32").is_none());
    assert!(body.get("otpauth_uri").is_none());
    assert!(body.get("backup_codes").is_none());
    assert!(body.get("success").is_none());
    assert!(body.get("mfa_enabled").is_none());
    assert!(
        has_set_cookie,
        "login-required profile responses must clear stale session cookies"
    );
}

#[test]
fn protected_mfa_request_requires_code() {
    let payload = serde_json::from_value::<MfaProtectedRequest>(json!({"code": "123456"}));

    assert!(payload.is_ok());
}

#[test]
fn mfa_request_payloads_require_code_before_endpoint_logic() {
    assert!(serde_json::from_value::<ConfirmTotpRequest>(json!({})).is_err());
    assert!(serde_json::from_value::<MfaChallengeRequest>(json!({})).is_err());
    assert!(serde_json::from_value::<MfaProtectedRequest>(json!({})).is_err());
}

#[test]
fn mfa_challenge_request_preserves_optional_remember_device_choice() {
    let remembered = serde_json::from_value::<MfaChallengeRequest>(
        json!({"code": "123456", "remember_device": true}),
    )
    .expect("challenge request with remember_device should parse");
    assert_eq!(remembered.code, "123456");
    assert_eq!(remembered.remember_device, Some(true));

    let not_remembered = serde_json::from_value::<MfaChallengeRequest>(json!({"code": "123456"}))
        .expect("challenge request without remember_device should parse");
    assert_eq!(not_remembered.code, "123456");
    assert_eq!(not_remembered.remember_device, None);
}

#[test]
fn totp_confirm_and_protected_requests_preserve_submitted_code() {
    let confirm = serde_json::from_value::<ConfirmTotpRequest>(json!({"code": "654321"}))
        .expect("confirm request should parse");
    let protected = serde_json::from_value::<MfaProtectedRequest>(json!({"code": "backup-code"}))
        .expect("protected request should parse");

    assert_eq!(confirm.code, "654321");
    assert_eq!(protected.code, "backup-code");
}

#[test]
fn remembered_mfa_cookie_ttl_is_bounded_to_thirty_days() {
    assert_eq!(
        Duration::seconds(MFA_REMEMBERED_TTL_SECONDS as i64).num_days(),
        30
    );
}

#[actix_web::test]
async fn mfa_totp_begin_rejects_session_request_without_csrf_before_enrollment_secret() {
    let state = Data::new(test_state());
    let req = request_with_session_but_no_csrf(&state);

    assert_mfa_endpoint_rejects_missing_csrf(mfa_totp_begin(mfa_handles(&state), req).await).await;
}

#[actix_web::test]
async fn mfa_totp_begin_requires_login_before_enrollment_secret() {
    let state = Data::new(test_state());
    let req = actix_web::test::TestRequest::default().to_http_request();

    assert_mfa_endpoint_requires_login(mfa_totp_begin(mfa_handles(&state), req).await).await;
}

#[actix_web::test]
async fn mfa_totp_begin_replaces_unconfirmed_enrollment_and_clears_replay_state() {
    let Some(fixture) = LiveMfaFixture::new().await else {
        return;
    };
    let suffix = Uuid::now_v7().simple().to_string();
    let user = fixture.create_user(&suffix, false).await;
    let sid = format!("totp-restart-{suffix}");
    let csrf = format!("csrf-{suffix}");
    fixture.store_session(&user, &sid, false).await;
    let mut conn = get_conn(&fixture.state.diesel_db)
        .await
        .expect("database connection");
    diesel::insert_into(user_totp_credentials::table)
        .values((
            user_totp_credentials::tenant_id.eq(user.tenant_id),
            user_totp_credentials::user_id.eq(user.id),
            user_totp_credentials::secret_base32.eq("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"),
            user_totp_credentials::label.eq("stale enrollment"),
            user_totp_credentials::confirmed_at.eq::<Option<DateTime<Utc>>>(None),
            user_totp_credentials::last_used_step.eq(Some(123_i64)),
        ))
        .execute(&mut conn)
        .await
        .expect("stale unconfirmed TOTP credential should insert");

    let (status, body, has_set_cookie) = response_json(
        mfa_totp_begin(mfa_handles(&fixture.state), fixture.request(&sid, &csrf)).await,
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert!(!has_set_cookie);
    assert_eq!(totp_credential_count(&fixture, &user).await, 1);
    let credential = pending_totp_credential(&fixture, &user).await;
    let secret = body["secret_base32"]
        .as_str()
        .expect("begin response should expose the new TOTP secret");
    assert_eq!(credential.secret_base32, secret);
    assert_ne!(credential.secret_base32, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
    assert!(!credential.confirmed);
    assert!(
        credential.last_used_step.is_none(),
        "restarting enrollment must clear stale anti-replay state"
    );
    assert_eq!(body["period"], MFA_TOTP_PERIOD_SECONDS);
    assert_eq!(body["digits"], MFA_TOTP_DIGITS);
    assert!(
        body["otpauth_uri"]
            .as_str()
            .expect("otpauth URI should be returned")
            .contains(urlencoding::encode(&fixture.state.settings.endpoint.issuer).as_ref())
    );
}

#[actix_web::test]
async fn mfa_totp_confirm_rejects_session_request_without_csrf_before_backup_codes() {
    let state = Data::new(test_state());
    let req = request_with_session_but_no_csrf(&state);

    assert_mfa_endpoint_rejects_missing_csrf(
        mfa_totp_confirm(
            mfa_handles(&state),
            req,
            Json(ConfirmTotpRequest {
                code: "123456".into(),
            }),
        )
        .await,
    )
    .await;
}

#[actix_web::test]
async fn mfa_totp_confirm_requires_login_before_verifying_code() {
    let state = Data::new(test_state());
    let req = actix_web::test::TestRequest::default().to_http_request();

    assert_mfa_endpoint_requires_login(
        mfa_totp_confirm(
            mfa_handles(&state),
            req,
            Json(ConfirmTotpRequest {
                code: "123456".into(),
            }),
        )
        .await,
    )
    .await;
}

#[actix_web::test]
async fn mfa_step_up_rejects_session_request_without_csrf_before_factor_consumption() {
    let state = Data::new(test_state());
    let req = request_with_session_but_no_csrf(&state);

    assert_mfa_endpoint_rejects_missing_csrf(
        mfa_step_up(
            mfa_handles(&state),
            req,
            Json(MfaProtectedRequest {
                code: "123456".to_owned(),
            }),
        )
        .await,
    )
    .await;
}

#[actix_web::test]
async fn mfa_step_up_requires_login_before_factor_consumption() {
    let state = Data::new(test_state());
    let req = actix_web::test::TestRequest::default().to_http_request();

    assert_mfa_endpoint_requires_login(
        mfa_step_up(
            mfa_handles(&state),
            req,
            Json(MfaProtectedRequest {
                code: "123456".to_owned(),
            }),
        )
        .await,
    )
    .await;
}

#[actix_web::test]
async fn mfa_step_up_atomically_rotates_session_and_rejects_totp_replay() {
    let Some(fixture) = LiveMfaFixture::new().await else {
        return;
    };
    let suffix = Uuid::now_v7().simple().to_string();
    let user = fixture
        .create_user(&format!("step-up-{suffix}"), true)
        .await;
    let sid = format!("step-up-{suffix}");
    let csrf = format!("csrf-{suffix}");
    let secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    fixture.insert_confirmed_totp(&user, secret).await;
    fixture.store_session(&user, &sid, false).await;
    let code = nazo_identity::mfa::totp_for_step(
        b"12345678901234567890",
        Utc::now().timestamp() / MFA_TOTP_PERIOD_SECONDS,
    )
    .expect("TOTP code should generate");

    let response = mfa_step_up(
        mfa_handles(&fixture.state),
        fixture.request(&sid, &csrf),
        Json(MfaProtectedRequest { code: code.clone() }),
    )
    .await;
    let rotated_sid = set_cookie_value(
        &response,
        &fixture.state.settings.session.session_cookie_name,
    )
    .expect("successful step-up must rotate the session cookie");
    let rotated_csrf =
        set_cookie_value(&response, &fixture.state.settings.session.csrf_cookie_name)
            .expect("successful step-up must rotate the CSRF cookie");
    let (status, body, has_set_cookie) = response_json(response).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["success"], true);
    assert_eq!(body["method"], MfaVerificationMethod::Totp.amr());
    assert!(has_set_cookie);
    assert!(fixture.optional_session_payload(&sid).await.is_none());
    let session = fixture.session_payload(&rotated_sid).await;
    assert!(session.amr.iter().any(|method| method == "mfa"));
    assert!(session.amr.iter().any(|method| method == "otp"));

    let replay = mfa_step_up(
        mfa_handles(&fixture.state),
        fixture.request(&rotated_sid, &rotated_csrf),
        Json(MfaProtectedRequest { code }),
    )
    .await;
    let (status, body, has_set_cookie) = response_json(replay).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_grant");
    assert!(!has_set_cookie);
}

#[actix_web::test]
async fn mfa_step_up_rate_limit_is_fail_closed_and_preserves_session() {
    let Some(fixture) = LiveMfaFixture::new_with_rate_limit(1).await else {
        return;
    };
    let suffix = Uuid::now_v7().simple().to_string();
    let user = fixture.create_user(&suffix, true).await;
    fixture
        .insert_confirmed_totp(&user, &nazo_identity::mfa::generate_totp_secret_base32())
        .await;
    let sid = format!("step-up-rate-{suffix}");
    let csrf = format!("csrf-{suffix}");
    fixture.store_session(&user, &sid, false).await;
    let peer = SocketAddr::from(([127, 0, 0, 99], 31_337));

    let first = mfa_step_up(
        mfa_handles(&fixture.state),
        fixture.request_from(&sid, &csrf, Some(peer)),
        Json(MfaProtectedRequest {
            code: "not-a-valid-factor".to_owned(),
        }),
    )
    .await;
    let (status, body, has_set_cookie) = response_json(first).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_grant");
    assert!(!has_set_cookie);

    let second = mfa_step_up(
        mfa_handles(&fixture.state),
        fixture.request_from(&sid, &csrf, Some(peer)),
        Json(MfaProtectedRequest {
            code: "not-a-valid-factor".to_owned(),
        }),
    )
    .await;
    assert_eq!(
        second.headers().get(header::RETRY_AFTER),
        Some(&header::HeaderValue::from_static("60"))
    );
    let (status, body, has_set_cookie) = response_json(second).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(body["error"], "temporarily_unavailable");
    assert!(!has_set_cookie);

    let session = fixture.session_payload(&sid).await;
    assert!(!session.amr.iter().any(|method| method == "mfa"));
    assert!(!session.amr.iter().any(|method| method == "otp"));
}

#[actix_web::test]
async fn concurrent_totp_verification_has_exactly_one_winner() {
    let Some(fixture) = LiveMfaFixture::new().await else {
        return;
    };
    let suffix = Uuid::now_v7().simple().to_string();
    let user = fixture.create_user(&suffix, true).await;
    let secret = nazo_identity::mfa::generate_totp_secret_base32();
    fixture.insert_confirmed_totp(&user, &secret).await;
    let secret_bytes =
        nazo_identity::mfa::base32_decode(&secret).expect("generated TOTP secret should decode");
    let code = nazo_identity::mfa::totp_for_step(
        &secret_bytes,
        Utc::now().timestamp().div_euclid(MFA_TOTP_PERIOD_SECONDS),
    )
    .expect("TOTP code should generate");
    let identity = user.identity();

    let (first, second) = tokio::join!(
        verify_user_mfa_code(&fixture.state.diesel_db, &identity, &code),
        verify_user_mfa_code(&fixture.state.diesel_db, &identity, &code),
    );
    let outcomes = [
        first.expect("first verification should complete"),
        second.expect("second verification should complete"),
    ];
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| **outcome == Some(MfaVerificationMethod::Totp))
            .count(),
        1
    );
    assert_eq!(
        outcomes.iter().filter(|outcome| outcome.is_none()).count(),
        1
    );
    let mut connection = get_conn(&fixture.state.diesel_db)
        .await
        .expect("database connection");
    let audit_outcomes = sql_query(
        "SELECT outcome FROM identity_security_events \
         WHERE tenant_id = $1 AND target_user_id = $2 AND event_type = 'mfa_totp_attempt'",
    )
    .bind::<SqlUuid, _>(user.tenant_id)
    .bind::<SqlUuid, _>(user.id)
    .load::<AuditOutcomeRow>(&mut connection)
    .await
    .expect("TOTP audit events should load");
    assert_eq!(
        audit_outcomes
            .iter()
            .filter(|row| row.outcome == "success")
            .count(),
        1
    );
    assert_eq!(
        audit_outcomes
            .iter()
            .filter(|row| row.outcome == "replay")
            .count(),
        1
    );
}

#[actix_web::test]
async fn concurrent_mfa_step_up_consumes_backup_code_exactly_once() {
    let Some(fixture) = LiveMfaFixture::new().await else {
        return;
    };
    let suffix = Uuid::now_v7().simple().to_string();
    let user = fixture
        .create_user(&format!("step-up-backup-{suffix}"), true)
        .await;
    let backup_codes = replace_backup_codes(&fixture.state.diesel_db, &user.identity())
        .await
        .expect("backup codes should generate");
    let code = backup_codes
        .as_slice()
        .first()
        .expect("at least one backup code should be generated")
        .clone();
    let sid_a = format!("step-up-a-{suffix}");
    let sid_b = format!("step-up-b-{suffix}");
    let csrf_a = format!("csrf-a-{suffix}");
    let csrf_b = format!("csrf-b-{suffix}");
    fixture.store_session(&user, &sid_a, false).await;
    fixture.store_session(&user, &sid_b, false).await;

    let (response_a, response_b) = tokio::join!(
        mfa_step_up(
            mfa_handles(&fixture.state),
            fixture.request(&sid_a, &csrf_a),
            Json(MfaProtectedRequest { code: code.clone() }),
        ),
        mfa_step_up(
            mfa_handles(&fixture.state),
            fixture.request(&sid_b, &csrf_b),
            Json(MfaProtectedRequest { code: code.clone() }),
        ),
    );
    let (status_a, body_a, _) = response_json(response_a).await;
    let (status_b, body_b, _) = response_json(response_b).await;
    let mut statuses = [status_a.as_u16(), status_b.as_u16()];
    statuses.sort_unstable();
    assert_eq!(
        statuses,
        [StatusCode::OK.as_u16(), StatusCode::BAD_REQUEST.as_u16()],
        "unexpected concurrent confirmation responses: a={body_a}, b={body_b}"
    );
    let bodies = [body_a, body_b];
    assert_eq!(
        bodies.iter().filter(|body| body["success"] == true).count(),
        1
    );
    assert_eq!(
        bodies
            .iter()
            .filter(|body| body["error"] == "invalid_grant")
            .count(),
        1
    );
    assert!(
        verify_user_mfa_code(&fixture.state.diesel_db, &user.identity(), &code)
            .await
            .expect("consumed backup code lookup should succeed")
            .is_none(),
        "a backup code accepted by one concurrent step-up must be unusable afterwards"
    );
}

#[actix_web::test]
async fn mfa_totp_confirm_rejects_wrong_code_without_enabling_mfa_or_backup_codes() {
    let Some(fixture) = LiveMfaFixture::new().await else {
        return;
    };
    let suffix = Uuid::now_v7().simple().to_string();
    let user = fixture.create_user(&suffix, false).await;
    let sid = format!("totp-confirm-wrong-{suffix}");
    let csrf = format!("csrf-{suffix}");
    fixture.store_session(&user, &sid, false).await;
    let mut conn = get_conn(&fixture.state.diesel_db)
        .await
        .expect("database connection");
    diesel::insert_into(user_totp_credentials::table)
        .values((
            user_totp_credentials::tenant_id.eq(user.tenant_id),
            user_totp_credentials::user_id.eq(user.id),
            user_totp_credentials::secret_base32.eq("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"),
            user_totp_credentials::label.eq("pending enrollment"),
            user_totp_credentials::confirmed_at.eq::<Option<DateTime<Utc>>>(None),
            user_totp_credentials::last_used_step.eq::<Option<i64>>(None),
        ))
        .execute(&mut conn)
        .await
        .expect("pending TOTP credential should insert");

    let (status, body, has_set_cookie) = response_json(
        mfa_totp_confirm(
            mfa_handles(&fixture.state),
            fixture.request(&sid, &csrf),
            Json(ConfirmTotpRequest {
                code: "000000".to_owned(),
            }),
        )
        .await,
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_grant");
    assert!(body.get("backup_codes").is_none());
    assert!(!has_set_cookie);
    let credential = pending_totp_credential(&fixture, &user).await;
    assert!(!credential.confirmed);
    assert!(credential.last_used_step.is_none());
    assert!(!fresh_user(&fixture, user.id).await.mfa_enabled);
    assert_eq!(backup_code_count(&fixture, &user).await, 0);
}

#[actix_web::test]
async fn mfa_totp_confirm_rotates_session_and_csrf_after_valid_code() {
    let Some(fixture) = LiveMfaFixture::new().await else {
        return;
    };
    let suffix = Uuid::now_v7().simple().to_string();
    let user = fixture.create_user(&suffix, false).await;
    let sid = format!("totp-confirm-{suffix}");
    let csrf = format!("csrf-{suffix}");
    let secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    fixture.store_session(&user, &sid, false).await;
    let mut conn = get_conn(&fixture.state.diesel_db)
        .await
        .expect("database connection");
    diesel::insert_into(user_totp_credentials::table)
        .values((
            user_totp_credentials::tenant_id.eq(user.tenant_id),
            user_totp_credentials::user_id.eq(user.id),
            user_totp_credentials::secret_base32.eq(secret),
            user_totp_credentials::label.eq("pending enrollment"),
            user_totp_credentials::confirmed_at.eq::<Option<DateTime<Utc>>>(None),
            user_totp_credentials::last_used_step.eq::<Option<i64>>(None),
        ))
        .execute(&mut conn)
        .await
        .expect("pending TOTP credential should insert");
    let code = nazo_identity::mfa::totp_for_step(
        b"12345678901234567890",
        Utc::now().timestamp() / MFA_TOTP_PERIOD_SECONDS,
    )
    .expect("TOTP code should generate");

    let response = mfa_totp_confirm(
        mfa_handles(&fixture.state),
        fixture.request(&sid, &csrf),
        Json(ConfirmTotpRequest { code }),
    )
    .await;
    let rotated_sid = set_cookie_value(
        &response,
        &fixture.state.settings.session.session_cookie_name,
    )
    .expect("TOTP confirmation must rotate the session cookie");
    let rotated_csrf =
        set_cookie_value(&response, &fixture.state.settings.session.csrf_cookie_name)
            .expect("TOTP confirmation must rotate the CSRF cookie");
    let (status, body, has_set_cookie) = response_json(response).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["mfa_enabled"], true);
    assert!(has_set_cookie);
    assert_ne!(rotated_sid, sid);
    assert_ne!(rotated_csrf, csrf);
    assert!(fixture.optional_session_payload(&sid).await.is_none());
    let session = fixture.session_payload(&rotated_sid).await;
    assert!(session.amr.iter().any(|method| method == "otp"));
    assert!(session.amr.iter().any(|method| method == "mfa"));
    assert!(fresh_user(&fixture, user.id).await.mfa_enabled);
    assert_eq!(
        backup_code_count(&fixture, &user).await,
        MFA_BACKUP_CODE_COUNT as i64
    );
}

#[actix_web::test]
async fn rejected_enrollment_discards_unpublished_rotation_and_clears_cookies() {
    let Some(fixture) = LiveMfaFixture::new().await else {
        return;
    };
    let suffix = Uuid::now_v7().simple().to_string();
    let user = fixture.create_user(&suffix, false).await;
    let session_id = format!("unpublished-mfa-rotation-{suffix}");
    fixture.store_session(&user, &session_id, false).await;
    let handles = mfa_handles(&fixture.state);

    let rotation = SessionRotation {
        session_id: session_id.clone(),
        csrf_token: "never-published".to_owned(),
    };
    let response = no_store(
        discard_failed_enrollment_rotation(
            &handles,
            &rotation,
            oauth_error(StatusCode::BAD_REQUEST, "invalid_grant", "MFA 验证码无效."),
        )
        .await,
    );

    assert_eq!(
        set_cookie_value(
            &response,
            &fixture.state.settings.session.session_cookie_name
        )
        .as_deref(),
        Some("")
    );
    assert_eq!(
        set_cookie_value(&response, &fixture.state.settings.session.csrf_cookie_name).as_deref(),
        Some("")
    );
    let (status, body, _) = response_json(response).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_grant");

    assert!(
        fixture
            .optional_session_payload(&session_id)
            .await
            .is_none()
    );
}

#[actix_web::test]
async fn mfa_verify_rejects_session_request_without_csrf_before_completing_challenge() {
    let state = Data::new(test_state());
    let req = request_with_session_but_no_csrf(&state);

    assert_mfa_endpoint_rejects_missing_csrf(
        mfa_verify(
            mfa_handles(&state),
            req,
            Json(MfaChallengeRequest {
                code: "123456".into(),
                remember_device: Some(true),
            }),
        )
        .await,
    )
    .await;
}

#[actix_web::test]
async fn mfa_backup_codes_regenerate_rejects_session_request_without_csrf_before_rotation() {
    let state = Data::new(test_state());
    let req = request_with_session_but_no_csrf(&state);

    assert_mfa_endpoint_rejects_missing_csrf(
        mfa_backup_codes_regenerate(
            mfa_handles(&state),
            req,
            Json(MfaProtectedRequest {
                code: "123456".into(),
            }),
        )
        .await,
    )
    .await;
}

#[actix_web::test]
async fn mfa_backup_codes_regenerate_requires_login_before_code_rotation() {
    let state = Data::new(test_state());
    let req = actix_web::test::TestRequest::default().to_http_request();

    assert_mfa_endpoint_requires_login(
        mfa_backup_codes_regenerate(
            mfa_handles(&state),
            req,
            Json(MfaProtectedRequest {
                code: "123456".into(),
            }),
        )
        .await,
    )
    .await;
}

#[actix_web::test]
async fn mfa_disable_rejects_session_request_without_csrf_before_clearing_mfa_state() {
    let state = Data::new(test_state());
    let req = request_with_session_but_no_csrf(&state);

    assert_mfa_endpoint_rejects_missing_csrf(
        mfa_disable(
            mfa_handles(&state),
            req,
            Json(MfaProtectedRequest {
                code: "123456".into(),
            }),
        )
        .await,
    )
    .await;
}

#[actix_web::test]
async fn mfa_disable_requires_login_before_clearing_mfa_state() {
    let state = Data::new(test_state());
    let req = actix_web::test::TestRequest::default().to_http_request();

    assert_mfa_endpoint_requires_login(
        mfa_disable(
            mfa_handles(&state),
            req,
            Json(MfaProtectedRequest {
                code: "123456".into(),
            }),
        )
        .await,
    )
    .await;
}

#[actix_web::test]
async fn mfa_verify_rejects_non_pending_session_without_consuming_mfa_code() {
    let Some(fixture) = LiveMfaFixture::new().await else {
        return;
    };
    let suffix = Uuid::now_v7().simple().to_string();
    let user = fixture.create_user(&suffix, true).await;
    let sid = format!("active-{suffix}");
    let csrf = format!("csrf-{suffix}");
    fixture.store_session(&user, &sid, false).await;

    let response = mfa_verify(
        mfa_handles(&fixture.state),
        fixture.request(&sid, &csrf),
        Json(MfaChallengeRequest {
            code: "123456".into(),
            remember_device: Some(false),
        }),
    )
    .await;
    let (status, body, has_set_cookie) = response_json(response).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "login_required");
    assert_eq!(body["error_description"], "Request failed.");
    assert!(!has_set_cookie);
    let session = fixture.session_payload(&sid).await;
    assert!(!session.pending_mfa);
    assert_eq!(session.amr, vec!["pwd"]);
}

#[actix_web::test]
async fn mfa_verify_completes_pending_totp_challenge_and_updates_session_amr() {
    let Some(fixture) = LiveMfaFixture::new().await else {
        return;
    };
    let suffix = Uuid::now_v7().simple().to_string();
    let user = fixture.create_user(&suffix, true).await;
    let sid = format!("pending-{suffix}");
    let csrf = format!("csrf-{suffix}");
    let secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".to_owned();
    fixture.insert_confirmed_totp(&user, &secret).await;
    fixture.store_session(&user, &sid, true).await;
    let code = nazo_identity::mfa::totp_for_step(
        b"12345678901234567890",
        Utc::now().timestamp() / MFA_TOTP_PERIOD_SECONDS,
    )
    .expect("TOTP code should generate");

    let response = mfa_verify(
        mfa_handles(&fixture.state),
        fixture.request(&sid, &csrf),
        Json(MfaChallengeRequest {
            code,
            remember_device: Some(false),
        }),
    )
    .await;
    let rotated_sid = set_cookie_value(
        &response,
        &fixture.state.settings.session.session_cookie_name,
    )
    .expect("MFA completion must rotate the session cookie");
    let rotated_csrf =
        set_cookie_value(&response, &fixture.state.settings.session.csrf_cookie_name)
            .expect("MFA completion must rotate the CSRF cookie");
    let (status, body, has_set_cookie) = response_json(response).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["success"], true);
    assert_eq!(body["method"], MfaVerificationMethod::Totp.amr());
    assert!(has_set_cookie);
    assert_ne!(rotated_sid, sid);
    assert_ne!(rotated_csrf, csrf);
    assert!(fixture.optional_session_payload(&sid).await.is_none());
    let session = fixture.session_payload(&rotated_sid).await;
    assert!(!session.pending_mfa);
    assert!(session.amr.iter().any(|method| method == "pwd"));
    assert!(session.amr.iter().any(|method| method == "otp"));
    assert!(session.amr.iter().any(|method| method == "mfa"));
}

#[actix_web::test]
async fn mfa_verify_reports_session_lookup_failure_after_rate_limit_for_pending_session_cookie() {
    let Some(fixture) = LiveMfaFixture::new().await else {
        return;
    };
    let sid = format!("broken-{}", Uuid::now_v7().simple());
    let csrf = format!("csrf-{}", Uuid::now_v7().simple());
    let state = Data::new(TestAppState {
        diesel_db: create_pool(
            "postgres://nazo_mfa_session_lookup_invalid:nazo_mfa_session_lookup_invalid@127.0.0.1:1/nazo"
                .to_owned(),
            1,
        )
        .expect("pool construction should not connect"),
        valkey: fixture.state.valkey.clone(),
        settings: fixture.state.settings.clone(),
        keyset: fixture.state.keyset.clone(),
    });
    let payload = SessionPayload {
        user_id: Uuid::now_v7(),
        auth_time: Utc::now().timestamp(),
        amr: vec!["pwd".to_owned()],
        pending_mfa: true,
        oidc_sid: Some(format!("oidc-{sid}")),
    };
    valkey_set_ex(
        &state.valkey,
        format!("oauth:session:{sid}"),
        serde_json::to_string(&payload).expect("session should serialize"),
        state.settings.session.session_ttl_seconds,
    )
    .await
    .expect("session should store");
    let req = actix_web::test::TestRequest::default()
        .cookie(Cookie::new(
            state.settings.session.session_cookie_name.clone(),
            sid,
        ))
        .cookie(Cookie::new(
            state.settings.session.csrf_cookie_name.clone(),
            csrf.clone(),
        ))
        .insert_header(("x-csrf-token", csrf))
        .to_http_request();

    let (status, body, has_set_cookie) = response_json(
        mfa_verify(
            mfa_handles(&state),
            req,
            Json(MfaChallengeRequest {
                code: "123456".into(),
                remember_device: Some(false),
            }),
        )
        .await,
    )
    .await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"], "server_error");
    assert!(body["error_description"].is_string());
    assert!(!has_set_cookie);
}

#[actix_web::test]
async fn mfa_verify_remember_device_sets_cookie_and_persists_remembered_device() {
    let Some(fixture) = LiveMfaFixture::new().await else {
        return;
    };
    let suffix = Uuid::now_v7().simple().to_string();
    let user = fixture.create_user(&suffix, true).await;
    let sid = format!("remember-{suffix}");
    let csrf = format!("csrf-{suffix}");
    let user_agent = format!("nazo-mfa-remember/{suffix}");
    let secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".to_owned();
    fixture.insert_confirmed_totp(&user, &secret).await;
    fixture.store_session(&user, &sid, true).await;
    let code = nazo_identity::mfa::totp_for_step(
        b"12345678901234567890",
        Utc::now().timestamp() / MFA_TOTP_PERIOD_SECONDS,
    )
    .expect("TOTP code should generate");
    let req = actix_web::test::TestRequest::default()
        .cookie(Cookie::new(
            fixture.state.settings.session.session_cookie_name.clone(),
            sid.clone(),
        ))
        .cookie(Cookie::new(
            fixture.state.settings.session.csrf_cookie_name.clone(),
            csrf.clone(),
        ))
        .insert_header(("x-csrf-token", csrf))
        .insert_header((header::USER_AGENT, user_agent.clone()))
        .to_http_request();

    let response = mfa_verify(
        mfa_handles(&fixture.state),
        req,
        Json(MfaChallengeRequest {
            code,
            remember_device: Some(true),
        }),
    )
    .await;
    let remembered_token = set_cookie_value(&response, MFA_REMEMBERED_COOKIE_NAME)
        .expect("remember-device success must issue the remembered-device cookie");
    let rotated_sid = set_cookie_value(
        &response,
        &fixture.state.settings.session.session_cookie_name,
    )
    .expect("MFA completion must rotate the session cookie");
    let (status, body, has_set_cookie) = response_json(response).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["success"], true);
    assert_eq!(body["method"], MfaVerificationMethod::Totp.amr());
    assert!(has_set_cookie);
    assert_eq!(remembered_device_count(&fixture, &user).await, 1);
    assert_ne!(rotated_sid, sid);
    assert!(fixture.optional_session_payload(&sid).await.is_none());
    let session = fixture.session_payload(&rotated_sid).await;
    assert!(!session.pending_mfa);
    assert!(session.amr.iter().any(|method| method == "mfa"));
    assert!(session.amr.iter().any(|method| method == "otp"));

    let remembered_req = actix_web::test::TestRequest::default()
        .cookie(Cookie::new(MFA_REMEMBERED_COOKIE_NAME, remembered_token))
        .insert_header((header::USER_AGENT, user_agent))
        .to_http_request();
    assert!(
        remembered_mfa_device_valid(&fixture.state, &remembered_req, &user.identity())
            .await
            .expect("remembered device lookup should succeed"),
        "remember-device success must persist a reusable device marker"
    );
}

#[actix_web::test]
async fn mfa_backup_codes_regenerate_rejects_when_mfa_is_not_enabled() {
    let Some(fixture) = LiveMfaFixture::new().await else {
        return;
    };
    let suffix = Uuid::now_v7().simple().to_string();
    let user = fixture.create_user(&suffix, false).await;
    let sid = format!("regen-disabled-{suffix}");
    let csrf = format!("csrf-{suffix}");
    fixture.store_session(&user, &sid, false).await;

    let (status, body, has_set_cookie) = response_json(
        mfa_backup_codes_regenerate(
            mfa_handles(&fixture.state),
            fixture.request(&sid, &csrf),
            Json(MfaProtectedRequest {
                code: "123456".into(),
            }),
        )
        .await,
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");
    assert!(body["error_description"].is_string());
    assert!(!has_set_cookie);
}

#[actix_web::test]
async fn mfa_backup_codes_regenerate_rotates_codes_after_valid_totp() {
    let Some(fixture) = LiveMfaFixture::new().await else {
        return;
    };
    let suffix = Uuid::now_v7().simple().to_string();
    let user = fixture.create_user(&suffix, true).await;
    let sid = format!("regen-{suffix}");
    let csrf = format!("csrf-{suffix}");
    let secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".to_owned();
    fixture.insert_confirmed_totp(&user, &secret).await;
    fixture.store_session(&user, &sid, false).await;
    let previous_codes = replace_backup_codes(&fixture.state.diesel_db, &user.identity())
        .await
        .expect("initial backup codes should generate");
    let code = nazo_identity::mfa::totp_for_step(
        b"12345678901234567890",
        Utc::now().timestamp() / MFA_TOTP_PERIOD_SECONDS,
    )
    .expect("TOTP code should generate");

    let response = mfa_backup_codes_regenerate(
        mfa_handles(&fixture.state),
        fixture.request(&sid, &csrf),
        Json(MfaProtectedRequest { code }),
    )
    .await;
    let rotated_sid = set_cookie_value(
        &response,
        &fixture.state.settings.session.session_cookie_name,
    )
    .expect("MFA step-up must rotate the session cookie");
    let (status, body, has_set_cookie) = response_json(response).await;

    assert_eq!(status, StatusCode::OK);
    assert!(has_set_cookie);
    let rotated_codes = body["backup_codes"]
        .as_array()
        .expect("backup codes should be an array");
    assert_eq!(rotated_codes.len(), MFA_BACKUP_CODE_COUNT);
    assert_eq!(
        backup_code_count(&fixture, &user).await,
        MFA_BACKUP_CODE_COUNT as i64
    );
    assert_eq!(
        verify_user_mfa_code(
            &fixture.state.diesel_db,
            &user.identity(),
            &previous_codes[0]
        )
        .await
        .expect("old backup code verification should succeed"),
        None,
        "rotating backup codes must invalidate previously issued codes"
    );
    assert_eq!(
        verify_user_mfa_code(
            &fixture.state.diesel_db,
            &user.identity(),
            rotated_codes[0]
                .as_str()
                .expect("backup code should serialize as a string"),
        )
        .await
        .expect("new backup code verification should succeed"),
        Some(MfaVerificationMethod::BackupCode),
        "a freshly rotated backup code must immediately become the valid recovery factor"
    );
    assert_ne!(rotated_sid, sid);
    assert!(fixture.optional_session_payload(&sid).await.is_none());
    let session = fixture.session_payload(&rotated_sid).await;
    assert!(session.amr.iter().any(|method| method == "otp"));
    assert!(session.amr.iter().any(|method| method == "mfa"));
}

#[actix_web::test]
async fn mfa_backup_codes_regenerate_rejects_wrong_totp_without_rotating_codes() {
    let Some(fixture) = LiveMfaFixture::new().await else {
        return;
    };
    let suffix = Uuid::now_v7().simple().to_string();
    let user = fixture.create_user(&suffix, true).await;
    let sid = format!("regen-wrong-{suffix}");
    let csrf = format!("csrf-{suffix}");
    fixture
        .insert_confirmed_totp(&user, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
        .await;
    fixture.store_session(&user, &sid, false).await;
    let previous_codes = replace_backup_codes(&fixture.state.diesel_db, &user.identity())
        .await
        .expect("initial backup codes should generate");

    let (status, body, has_set_cookie) = response_json(
        mfa_backup_codes_regenerate(
            mfa_handles(&fixture.state),
            fixture.request(&sid, &csrf),
            Json(MfaProtectedRequest {
                code: "000000".to_owned(),
            }),
        )
        .await,
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_grant");
    assert!(body.get("backup_codes").is_none());
    assert!(!has_set_cookie);
    assert_eq!(
        backup_code_count(&fixture, &user).await,
        MFA_BACKUP_CODE_COUNT as i64
    );
    assert_eq!(
        verify_user_mfa_code(
            &fixture.state.diesel_db,
            &user.identity(),
            &previous_codes[0]
        )
        .await
        .expect("existing backup code verification should succeed"),
        Some(MfaVerificationMethod::BackupCode),
        "failed regeneration must not rotate or consume existing recovery codes"
    );
}

#[actix_web::test]
async fn mfa_disable_clears_totp_backup_codes_and_remembered_devices() {
    let Some(fixture) = LiveMfaFixture::new().await else {
        return;
    };
    let suffix = Uuid::now_v7().simple().to_string();
    let user = fixture.create_user(&suffix, true).await;
    let sid = format!("disable-{suffix}");
    let csrf = format!("csrf-{suffix}");
    let secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".to_owned();
    let user_agent = format!("nazo-mfa-disable/{suffix}");
    fixture.insert_confirmed_totp(&user, &secret).await;
    fixture.store_session(&user, &sid, false).await;
    replace_backup_codes(&fixture.state.diesel_db, &user.identity())
        .await
        .expect("backup codes should generate");
    let remembered_req = actix_web::test::TestRequest::default()
        .insert_header((header::USER_AGENT, user_agent))
        .to_http_request();
    remember_mfa_device(&fixture.state, &remembered_req, &user.identity())
        .await
        .expect("remembered device should persist");
    let code = nazo_identity::mfa::totp_for_step(
        b"12345678901234567890",
        Utc::now().timestamp() / MFA_TOTP_PERIOD_SECONDS,
    )
    .expect("TOTP code should generate");

    let response = mfa_disable(
        mfa_handles(&fixture.state),
        fixture.request(&sid, &csrf),
        Json(MfaProtectedRequest { code }),
    )
    .await;
    let cleared_cookie = set_cookie_value(&response, MFA_REMEMBERED_COOKIE_NAME)
        .expect("MFA disable must clear the remembered-device cookie");
    let (status, body, has_set_cookie) = response_json(response).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["mfa_enabled"], false);
    assert!(has_set_cookie);
    assert_eq!(cleared_cookie, "");
    assert_eq!(totp_credential_count(&fixture, &user).await, 0);
    assert_eq!(backup_code_count(&fixture, &user).await, 0);
    assert_eq!(remembered_device_count(&fixture, &user).await, 0);
    assert!(!fresh_user(&fixture, user.id).await.mfa_enabled);
}

#[actix_web::test]
async fn mfa_totp_begin_rejects_confirmed_credential_without_rotating_secret() {
    let Some(fixture) = LiveMfaFixture::new().await else {
        return;
    };
    let suffix = Uuid::now_v7().simple().to_string();
    let user = fixture.create_user(&suffix, true).await;
    let sid = format!("totp-confirmed-{suffix}");
    let csrf = format!("csrf-{suffix}");
    let secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    fixture.store_session(&user, &sid, false).await;
    fixture.insert_confirmed_totp(&user, secret).await;

    let (status, body, has_set_cookie) = response_json(
        mfa_totp_begin(mfa_handles(&fixture.state), fixture.request(&sid, &csrf)).await,
    )
    .await;

    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["error"], "invalid_request");
    assert!(body.get("secret_base32").is_none());
    assert!(!has_set_cookie);
    let credential = pending_totp_credential(&fixture, &user).await;
    assert_eq!(credential.secret_base32, secret);
    assert!(credential.confirmed);
    assert_eq!(totp_credential_count(&fixture, &user).await, 1);
    assert!(fresh_user(&fixture, user.id).await.mfa_enabled);
}

#[actix_web::test]
async fn mfa_verify_rejects_wrong_code_without_completing_session_or_remembering_device() {
    let Some(fixture) = LiveMfaFixture::new().await else {
        return;
    };
    let suffix = Uuid::now_v7().simple().to_string();
    let user = fixture.create_user(&suffix, true).await;
    let sid = format!("pending-wrong-{suffix}");
    let csrf = format!("csrf-{suffix}");
    fixture
        .insert_confirmed_totp(&user, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
        .await;
    fixture.store_session(&user, &sid, true).await;

    let (status, body, has_set_cookie) = response_json(
        mfa_verify(
            mfa_handles(&fixture.state),
            fixture.request(&sid, &csrf),
            Json(MfaChallengeRequest {
                code: "000000".to_owned(),
                remember_device: Some(true),
            }),
        )
        .await,
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_grant");
    assert!(body.get("success").is_none());
    assert!(!has_set_cookie);
    let session = fixture.session_payload(&sid).await;
    assert!(session.pending_mfa);
    assert_eq!(session.amr, vec!["pwd"]);
    assert_eq!(remembered_device_count(&fixture, &user).await, 0);
}

#[actix_web::test]
async fn mfa_disable_rejects_wrong_code_without_clearing_existing_state() {
    let Some(fixture) = LiveMfaFixture::new().await else {
        return;
    };
    let suffix = Uuid::now_v7().simple().to_string();
    let user = fixture.create_user(&suffix, true).await;
    let sid = format!("disable-wrong-{suffix}");
    let csrf = format!("csrf-{suffix}");
    let user_agent = format!("nazo-mfa-disable-wrong/{suffix}");
    fixture
        .insert_confirmed_totp(&user, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
        .await;
    fixture.store_session(&user, &sid, false).await;
    let previous_codes = replace_backup_codes(&fixture.state.diesel_db, &user.identity())
        .await
        .expect("backup codes should generate");
    let remembered_req = actix_web::test::TestRequest::default()
        .insert_header((header::USER_AGENT, user_agent))
        .to_http_request();
    remember_mfa_device(&fixture.state, &remembered_req, &user.identity())
        .await
        .expect("remembered device should persist");

    let (status, body, has_set_cookie) = response_json(
        mfa_disable(
            mfa_handles(&fixture.state),
            fixture.request(&sid, &csrf),
            Json(MfaProtectedRequest {
                code: "000000".to_owned(),
            }),
        )
        .await,
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_grant");
    assert!(body["error_description"].is_string());
    assert!(!has_set_cookie);
    assert_eq!(totp_credential_count(&fixture, &user).await, 1);
    assert_eq!(
        backup_code_count(&fixture, &user).await,
        MFA_BACKUP_CODE_COUNT as i64
    );
    assert_eq!(remembered_device_count(&fixture, &user).await, 1);
    assert!(fresh_user(&fixture, user.id).await.mfa_enabled);
    assert_eq!(
        verify_user_mfa_code(
            &fixture.state.diesel_db,
            &user.identity(),
            &previous_codes[0]
        )
        .await
        .expect("existing backup code verification should succeed"),
        Some(MfaVerificationMethod::BackupCode),
        "failed disable must not clear recovery codes"
    );
}
