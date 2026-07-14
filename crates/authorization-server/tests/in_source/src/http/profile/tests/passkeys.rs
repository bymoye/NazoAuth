use std::sync::Arc;
use std::time::Duration as StdDuration;

use crate::bootstrap::PASSKEY_CEREMONY_TTL_SECONDS;
use crate::domain::tenancy::DEFAULT_ORGANIZATION_ID;
use crate::domain::tenancy::DEFAULT_REALM_ID;
use crate::domain::tenancy::DEFAULT_TENANT_ID;
use crate::domain::{DatabasePasskeyFixture, DatabaseUserFixture, TestAppState};
use crate::http::sessions::SessionPayload;
use crate::settings::Settings;
use crate::test_support::valkey::valkey_set_ex;
use actix_web::{
    HttpRequest, HttpResponse,
    cookie::Cookie,
    http::{StatusCode, header},
    web::{Data, Json, Path},
};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use chrono::Utc;
use diesel::sql_query;
use diesel::sql_types::{Bool, Jsonb, Text, Uuid as SqlUuid};
use diesel_async::RunQueryDsl;
use ed25519_dalek::SigningKey;
use fred::interfaces::ClientLike;
use fred::prelude::{
    Builder as ValkeyBuilder, Config as ValkeyConfig, ConnectionConfig, PerformanceConfig,
};
use nazo_http_actix::{
    PasskeyRegistrationBeginRequest as PasskeyBeginRequest,
    PasskeyRegistrationFinishRequest as PasskeyFinishRequest, authorization_error_response,
};
use nazo_identity::ports::PasskeyCredential;
use passkey_auth::RegistrationResponse;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::config::ConfigSource;
use nazo_postgres::create_pool;
use nazo_postgres::get_conn;

fn normalize_passkey_label(value: Option<String>) -> Result<String, HttpResponse> {
    nazo_identity::passkey::normalize_passkey_label(value.as_deref()).map_err(|_| {
        authorization_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "passkey label is too long.",
        )
    })
}

fn normalize_ceremony_id(value: &str) -> Result<String, HttpResponse> {
    nazo_identity::passkey::normalize_ceremony_id(value).map_err(|_| {
        authorization_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "invalid ceremony id.",
        )
    })
}

fn registration_key(ceremony_id: &str) -> String {
    format!("oauth:passkey:registration:{ceremony_id}")
}

#[test]
fn passkey_profile_transport_has_no_identity_or_storage_orchestration() {
    let source = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../http-actix/src/passkey.rs"
    ));
    for forbidden in [
        "TestAppState",
        "nazo_postgres",
        "nazo_valkey",
        "PasskeyRepository",
        "AuthenticationStore",
        "passkey_webauthn",
        "store_passkey",
        "take_passkey",
    ] {
        assert!(
            !source.contains(forbidden),
            "passkey profile transport must not depend on {forbidden}"
        );
    }
}

async fn passkey_registration_begin(
    state: Data<TestAppState>,
    req: HttpRequest,
    payload: Json<PasskeyBeginRequest>,
) -> HttpResponse {
    nazo_http_actix::passkey_registration_begin(
        super::test_profile_endpoint(&state),
        req,
        Ok(payload),
    )
    .await
}

async fn passkey_registration_finish(
    state: Data<TestAppState>,
    req: HttpRequest,
    payload: Json<PasskeyFinishRequest>,
) -> HttpResponse {
    nazo_http_actix::passkey_registration_finish(
        super::test_profile_endpoint(&state),
        req,
        Ok(payload),
    )
    .await
}

async fn passkey_list(state: Data<TestAppState>, req: HttpRequest) -> HttpResponse {
    nazo_http_actix::passkey_list(super::test_profile_endpoint(&state), req).await
}

async fn passkey_delete(
    state: Data<TestAppState>,
    req: HttpRequest,
    path: Path<Uuid>,
) -> HttpResponse {
    nazo_http_actix::passkey_delete(super::test_profile_endpoint(&state), req, path).await
}

async fn load_user_passkeys(
    state: &TestAppState,
    user: &nazo_identity::PublicAccount,
) -> Result<Vec<PasskeyCredential>, HttpResponse> {
    nazo_postgres::PasskeyRepository::new(state.diesel_db.clone())
        .list(user.tenant().tenant_id, user.user_id())
        .await
        .map_err(|_| {
            authorization_error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "passkey state unavailable.",
            )
        })
}

fn test_state() -> TestAppState {
    TestAppState {
        diesel_db: create_pool(
            "postgres://nazo_profile_passkey_test_invalid:nazo_profile_passkey_test_invalid@127.0.0.1:1/nazo".to_owned(),
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

fn uuid_fixture(value: u128) -> Uuid {
    Uuid::from_u128(value)
}

struct LivePasskeyFixture {
    state: Data<TestAppState>,
}

struct FakeAuthenticator {
    sk: SigningKey,
    credential_id: Vec<u8>,
    counter: u32,
    flags: u8,
}

const FLAG_UP: u8 = 1 << 0;
const FLAG_UV: u8 = 1 << 2;
const FLAG_AT: u8 = 1 << 6;

impl FakeAuthenticator {
    fn new(label: &[u8]) -> Self {
        let digest = Sha256::digest(label);
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&digest[..32]);
        Self {
            sk: SigningKey::from_bytes(&seed),
            credential_id: label.to_vec(),
            counter: 0,
            flags: FLAG_UP | FLAG_UV,
        }
    }

    fn registration_response(&self, challenge_b64: &str, origin: &str) -> RegistrationResponse {
        let (_raw, client_data_json) = client_data("webauthn.create", challenge_b64, origin);
        RegistrationResponse {
            id: B64URL.encode(&self.credential_id),
            transports: vec!["internal".to_owned()],
            attestation_object: B64URL.encode(self.attestation_object()),
            client_data_json,
        }
    }

    fn cose_pubkey(&self) -> Vec<u8> {
        cbor_map(vec![
            (cbor_uint(1), cbor_uint(1)),
            (cbor_uint(3), cbor_nint(-8)),
            (cbor_nint(-1), cbor_uint(6)),
            (
                cbor_nint(-2),
                cbor_bytes(&self.sk.verifying_key().to_bytes()),
            ),
        ])
    }

    fn auth_data_register(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&Sha256::digest("example.com".as_bytes()));
        buf.push(self.flags | FLAG_AT);
        buf.extend_from_slice(&self.counter.to_be_bytes());
        buf.extend_from_slice(&[0u8; 16]);
        buf.extend_from_slice(&(self.credential_id.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.credential_id);
        buf.extend_from_slice(&self.cose_pubkey());
        buf
    }

    fn attestation_object(&self) -> Vec<u8> {
        cbor_map(vec![
            (cbor_text("fmt"), cbor_text("none")),
            (cbor_text("attStmt"), cbor_map(Vec::new())),
            (
                cbor_text("authData"),
                cbor_bytes(&self.auth_data_register()),
            ),
        ])
    }
}

impl LivePasskeyFixture {
    async fn new() -> Option<Self> {
        let database_url = std::env::var("DATABASE_URL").ok()?;
        let valkey_url = std::env::var("VALKEY_URL").ok()?;
        let config = ConfigSource::from_pairs_for_test([
            ("ISSUER", "https://example.com"),
            (
                "CLIENT_SECRET_PEPPER",
                "client-secret-pepper-for-tests-000000000001",
            ),
            ("PASSKEY_RP_ID", "example.com"),
            ("PASSKEY_RP_NAME", "Nazo OAuth Test"),
            ("PASSKEY_ORIGIN", "https://example.com"),
            ("PASSKEY_REQUIRE_USER_VERIFICATION", "true"),
            ("PASSKEY_REQUIRE_USER_HANDLE", "true"),
            ("PASSKEY_STRICT_BASE64", "true"),
            ("COOKIE_SECURE", "true"),
            ("SESSION_COOKIE_NAME", "nazo_session_test"),
            ("CSRF_COOKIE_NAME", "nazo_csrf_test"),
            ("AUTH_RATE_LIMIT_MAX_REQUESTS", "100000"),
        ]);
        let settings = Settings::from_config(&config).expect("test settings should load");
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

    async fn create_user(&self, suffix: &str) -> DatabaseUserFixture {
        let email = format!("passkey-{suffix}@example.com");
        let username = format!("passkey-{suffix}");
        let mut conn = get_conn(&self.state.diesel_db)
            .await
            .expect("database connection");
        sql_query(
            r#"
            INSERT INTO users (
                tenant_id, realm_id, organization_id, username, email,
                password_hash, is_active, mfa_enabled, email_verified, role, admin_level
            )
            VALUES ($1, $2, $3, $4, $5, 'unused-passkey-test-hash', $6, false, true, 'user', 0)
            RETURNING *
            "#,
        )
        .bind::<SqlUuid, _>(DEFAULT_TENANT_ID)
        .bind::<SqlUuid, _>(DEFAULT_REALM_ID)
        .bind::<SqlUuid, _>(DEFAULT_ORGANIZATION_ID)
        .bind::<Text, _>(username)
        .bind::<Text, _>(email)
        .bind::<Bool, _>(true)
        .get_result::<DatabaseUserFixture>(&mut conn)
        .await
        .expect("test user should insert")
    }

    async fn store_session(&self, user: &DatabaseUserFixture, sid: &str) {
        let payload = SessionPayload {
            user_id: user.id,
            auth_time: Utc::now().timestamp(),
            amr: vec!["pwd".to_owned()],
            pending_mfa: false,
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
        actix_web::test::TestRequest::default()
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

    async fn insert_passkey_credential(
        &self,
        user: &DatabaseUserFixture,
        credential_id: &str,
        credential: Value,
        label: &str,
    ) -> DatabasePasskeyFixture {
        let mut conn = get_conn(&self.state.diesel_db)
            .await
            .expect("database connection");
        sql_query(
            r#"
            INSERT INTO user_passkey_credentials (
                tenant_id, user_id, credential_id, credential, label, sign_count
            )
            VALUES ($1, $2, $3, $4, $5, 0)
            RETURNING *
            "#,
        )
        .bind::<SqlUuid, _>(user.tenant_id)
        .bind::<SqlUuid, _>(user.id)
        .bind::<Text, _>(format!("{credential_id}-{}", Uuid::now_v7().simple()))
        .bind::<Jsonb, _>(credential)
        .bind::<Text, _>(label.to_owned())
        .get_result::<DatabasePasskeyFixture>(&mut conn)
        .await
        .expect("passkey credential should insert")
    }
}

fn cbor_type(major: u8, len: u64) -> Vec<u8> {
    let mut out = Vec::new();
    match len {
        0..=23 => out.push((major << 5) | len as u8),
        24..=0xff => out.extend_from_slice(&[(major << 5) | 24, len as u8]),
        0x100..=0xffff => {
            out.push((major << 5) | 25);
            out.extend_from_slice(&(len as u16).to_be_bytes());
        }
        _ => {
            out.push((major << 5) | 26);
            out.extend_from_slice(&(len as u32).to_be_bytes());
        }
    }
    out
}

fn cbor_uint(value: u64) -> Vec<u8> {
    cbor_type(0, value)
}

fn cbor_nint(value: i64) -> Vec<u8> {
    assert!(value < 0);
    cbor_type(1, (-1 - value) as u64)
}

fn cbor_bytes(value: &[u8]) -> Vec<u8> {
    let mut out = cbor_type(2, value.len() as u64);
    out.extend_from_slice(value);
    out
}

fn cbor_text(value: &str) -> Vec<u8> {
    let mut out = cbor_type(3, value.len() as u64);
    out.extend_from_slice(value.as_bytes());
    out
}

fn cbor_map(entries: Vec<(Vec<u8>, Vec<u8>)>) -> Vec<u8> {
    let mut out = cbor_type(5, entries.len() as u64);
    for (key, value) in entries {
        out.extend_from_slice(&key);
        out.extend_from_slice(&value);
    }
    out
}

fn client_data(kind: &str, challenge_b64: &str, origin: &str) -> (Vec<u8>, String) {
    let raw = format!(
        r#"{{"type":"{kind}","challenge":"{challenge_b64}","origin":"{origin}","crossOrigin":false}}"#
    )
    .into_bytes();
    let encoded = B64URL.encode(&raw);
    (raw, encoded)
}

fn invalid_registration_response() -> RegistrationResponse {
    RegistrationResponse {
        id: "invalid".to_owned(),
        transports: Vec::new(),
        attestation_object: "invalid".to_owned(),
        client_data_json: "invalid".to_owned(),
    }
}

async fn response_json(response: HttpResponse) -> (StatusCode, Value) {
    assert_no_store(response.headers());
    let status = response.status();
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("response body should be readable");
    let json = serde_json::from_slice(&body).expect("response should be json");
    (status, json)
}

async fn response_json_with_cookie_state(response: HttpResponse) -> (StatusCode, Value, bool) {
    assert_no_store(response.headers());
    let status = response.status();
    let has_set_cookie = response.headers().contains_key(header::SET_COOKIE);
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("response body should be readable");
    let json = serde_json::from_slice(&body).expect("response should be json");
    (status, json, has_set_cookie)
}

fn assert_no_store(headers: &header::HeaderMap) {
    assert_eq!(headers.get(header::CACHE_CONTROL).unwrap(), "no-store");
    assert_eq!(headers.get(header::PRAGMA).unwrap(), "no-cache");
}

async fn assert_passkey_write_rejects_missing_csrf(response: HttpResponse) {
    let (status, body, has_set_cookie) = response_json_with_cookie_state(response).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");
    assert_eq!(body["error_description"], "Request failed.");
    assert!(body.get("ceremony_id").is_none());
    assert!(body.get("publicKey").is_none());
    assert!(body.get("credential_id").is_none());
    assert!(body.get("credential").is_none());
    assert!(!has_set_cookie);
}

async fn assert_passkey_endpoint_requires_login(response: HttpResponse) {
    let (status, body, has_set_cookie) = response_json_with_cookie_state(response).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "login_required");
    assert!(body.get("ceremony_id").is_none());
    assert!(body.get("publicKey").is_none());
    assert!(body.get("passkeys").is_none());
    assert!(body.get("credential_id").is_none());
    assert!(body.get("credential").is_none());
    assert!(
        has_set_cookie,
        "login-required profile responses must clear stale session cookies"
    );
}

#[test]
fn passkey_label_normalization_defaults_trims_and_rejects_oversized_labels() {
    assert_eq!(
        normalize_passkey_label(None).expect("missing label should use stable default"),
        "Passkey"
    );
    assert_eq!(
        normalize_passkey_label(Some("  Hardware key  ".to_owned()))
            .expect("label should trim transport whitespace"),
        "Hardware key"
    );
    assert_eq!(
        normalize_passkey_label(Some(" \t ".to_owned()))
            .expect("blank label should use stable default"),
        "Passkey"
    );

    let response = normalize_passkey_label(Some("x".repeat(121)))
        .expect_err("oversized passkey labels must fail before ceremony state is created");
    let (status, body) = actix_web::rt::System::new().block_on(response_json(response));
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");
    assert!(body.get("publicKey").is_none());
}

#[test]
fn passkey_ceremony_id_normalization_accepts_only_bounded_urlsafe_identifiers() {
    let valid = "A".repeat(32);
    assert_eq!(
        normalize_ceremony_id(&format!("  {valid}  ")).expect("URL-safe ceremony id should parse"),
        valid
    );

    for invalid in [
        "short",
        "contains space in identifier",
        "contains/slash/in/identifier",
        "x",
    ] {
        let response = normalize_ceremony_id(invalid)
            .expect_err("malformed ceremony ids must fail before Valkey lookup");
        let (status, body) = actix_web::rt::System::new().block_on(response_json(response));
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "invalid_request");
        assert!(body.get("credential").is_none());
    }
    let too_long = "A".repeat(257);
    assert!(normalize_ceremony_id(&too_long).is_err());
}

#[actix_web::test]
async fn passkey_list_requires_login_before_loading_credentials() {
    let state = Data::new(test_state());
    let req = actix_web::test::TestRequest::default().to_http_request();

    assert_passkey_endpoint_requires_login(passkey_list(state, req).await).await;
}

#[actix_web::test]
async fn registration_begin_rejects_session_request_without_csrf_before_ceremony_creation() {
    let state = Data::new(test_state());
    let req = request_with_session_but_no_csrf(&state);

    assert_passkey_write_rejects_missing_csrf(
        passkey_registration_begin(state, req, Json(PasskeyBeginRequest { label: None })).await,
    )
    .await;
}

#[actix_web::test]
async fn registration_begin_requires_login_before_ceremony_creation() {
    let state = Data::new(test_state());
    let req = actix_web::test::TestRequest::default().to_http_request();

    assert_passkey_endpoint_requires_login(
        passkey_registration_begin(state, req, Json(PasskeyBeginRequest { label: None })).await,
    )
    .await;
}

#[actix_web::test]
async fn registration_finish_rejects_session_request_without_csrf_before_ceremony_lookup() {
    let state = Data::new(test_state());
    let req = request_with_session_but_no_csrf(&state);

    assert_passkey_write_rejects_missing_csrf(
        passkey_registration_finish(
            state,
            req,
            Json(PasskeyFinishRequest {
                ceremony_id: "A".repeat(32),
                response: invalid_registration_response(),
            }),
        )
        .await,
    )
    .await;
}

#[actix_web::test]
async fn registration_finish_requires_login_before_ceremony_lookup() {
    let state = Data::new(test_state());
    let req = actix_web::test::TestRequest::default().to_http_request();

    assert_passkey_endpoint_requires_login(
        passkey_registration_finish(
            state,
            req,
            Json(PasskeyFinishRequest {
                ceremony_id: "A".repeat(32),
                response: invalid_registration_response(),
            }),
        )
        .await,
    )
    .await;
}

#[actix_web::test]
async fn delete_passkey_rejects_session_request_without_csrf_before_credential_delete() {
    let state = Data::new(test_state());
    let req = request_with_session_but_no_csrf(&state);
    let credential_id = uuid_fixture(0x77777777777777777777777777777777);

    assert_passkey_write_rejects_missing_csrf(
        passkey_delete(state, req, actix_web::web::Path::from(credential_id)).await,
    )
    .await;
}

#[actix_web::test]
async fn delete_passkey_requires_login_before_credential_delete() {
    let state = Data::new(test_state());
    let req = actix_web::test::TestRequest::default().to_http_request();
    let credential_id = uuid_fixture(0x88888888888888888888888888888888);

    assert_passkey_endpoint_requires_login(
        passkey_delete(state, req, actix_web::web::Path::from(credential_id)).await,
    )
    .await;
}

#[actix_web::test]
async fn registration_finish_persists_credential_and_consumes_ceremony_once() {
    let Some(fixture) = LivePasskeyFixture::new().await else {
        return;
    };
    let suffix = Uuid::now_v7().simple().to_string();
    let user = fixture.create_user(&suffix).await;
    let sid = format!("sid-{suffix}");
    let csrf = format!("csrf-{suffix}");
    fixture.store_session(&user, &sid).await;

    let begin_response = passkey_registration_begin(
        fixture.state.clone(),
        fixture.request(&sid, &csrf),
        Json(PasskeyBeginRequest {
            label: Some("Work laptop".to_owned()),
        }),
    )
    .await;
    let (begin_status, begin_body) = response_json(begin_response).await;
    assert_eq!(begin_status, StatusCode::OK);
    let ceremony_id = begin_body["ceremony_id"]
        .as_str()
        .expect("begin response should include ceremony id");
    let challenge = begin_body["publicKey"]["challenge"]
        .as_str()
        .expect("begin response should include challenge");

    let authenticator = FakeAuthenticator::new(format!("credential-{suffix}").as_bytes());
    let finish_response = passkey_registration_finish(
        fixture.state.clone(),
        fixture.request(&sid, &csrf),
        Json(PasskeyFinishRequest {
            ceremony_id: ceremony_id.to_owned(),
            response: authenticator
                .registration_response(challenge, &fixture.state.settings.identity.passkey.origin),
        }),
    )
    .await;
    let (finish_status, finish_body) = response_json(finish_response).await;
    assert_eq!(finish_status, StatusCode::CREATED);
    assert_eq!(finish_body["label"], "Work laptop");
    assert_eq!(
        finish_body["credential_id"],
        B64URL.encode(&authenticator.credential_id)
    );
    assert!(finish_body.get("credential").is_none());

    let replay_response = passkey_registration_finish(
        fixture.state.clone(),
        fixture.request(&sid, &csrf),
        Json(PasskeyFinishRequest {
            ceremony_id: ceremony_id.to_owned(),
            response: authenticator
                .registration_response(challenge, &fixture.state.settings.identity.passkey.origin),
        }),
    )
    .await;
    let (replay_status, replay_body) = response_json(replay_response).await;
    assert_eq!(replay_status, StatusCode::BAD_REQUEST);
    assert_eq!(replay_body["error"], "invalid_request");
    assert_eq!(
        replay_body["error_description"],
        "passkey ceremony expired."
    );
}

#[actix_web::test]
async fn registration_finish_rejects_ceremony_user_mismatch_without_inserting_credential() {
    let Some(fixture) = LivePasskeyFixture::new().await else {
        return;
    };
    let suffix = Uuid::now_v7().simple().to_string();
    let owner = fixture.create_user(&format!("{suffix}-owner")).await;
    let attacker = fixture.create_user(&format!("{suffix}-attacker")).await;
    let owner_sid = format!("owner-{suffix}");
    let attacker_sid = format!("attacker-{suffix}");
    let csrf = format!("csrf-{suffix}");
    fixture.store_session(&owner, &owner_sid).await;
    fixture.store_session(&attacker, &attacker_sid).await;

    let begin_response = passkey_registration_begin(
        fixture.state.clone(),
        fixture.request(&owner_sid, &csrf),
        Json(PasskeyBeginRequest { label: None }),
    )
    .await;
    let (begin_status, begin_body) = response_json(begin_response).await;
    assert_eq!(begin_status, StatusCode::OK);
    let ceremony_id = begin_body["ceremony_id"]
        .as_str()
        .expect("begin response should include ceremony id");
    let challenge = begin_body["publicKey"]["challenge"]
        .as_str()
        .expect("begin response should include challenge");
    let authenticator = FakeAuthenticator::new(format!("credential-{suffix}").as_bytes());

    let finish_response = passkey_registration_finish(
        fixture.state.clone(),
        fixture.request(&attacker_sid, &csrf),
        Json(PasskeyFinishRequest {
            ceremony_id: ceremony_id.to_owned(),
            response: authenticator
                .registration_response(challenge, &fixture.state.settings.identity.passkey.origin),
        }),
    )
    .await;
    let (status, body) = response_json(finish_response).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");
    assert_eq!(body["error_description"], "passkey ceremony mismatch.");

    let owner_rows = load_user_passkeys(&fixture.state, &owner.identity())
        .await
        .expect("owner passkeys should load");
    assert!(owner_rows.is_empty());
    let attacker_rows = load_user_passkeys(&fixture.state, &attacker.identity())
        .await
        .expect("attacker passkeys should load");
    assert!(attacker_rows.is_empty());
}

#[actix_web::test]
async fn registration_begin_rejects_malformed_stored_credential_before_new_ceremony() {
    let Some(fixture) = LivePasskeyFixture::new().await else {
        return;
    };
    let suffix = Uuid::now_v7().simple().to_string();
    let user = fixture.create_user(&suffix).await;
    let sid = format!("malformed-begin-{suffix}");
    let csrf = format!("csrf-{suffix}");
    fixture.store_session(&user, &sid).await;
    fixture
        .insert_passkey_credential(
            &user,
            "broken-credential",
            json!({"unexpected": true}),
            "Broken passkey",
        )
        .await;

    let (status, body) = response_json(
        passkey_registration_begin(
            fixture.state.clone(),
            fixture.request(&sid, &csrf),
            Json(PasskeyBeginRequest { label: None }),
        )
        .await,
    )
    .await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"], "server_error");
    assert_eq!(body["error_description"], "passkey state unavailable.");
}

#[actix_web::test]
async fn registration_finish_projects_malformed_ceremony_state_as_expired() {
    let Some(fixture) = LivePasskeyFixture::new().await else {
        return;
    };
    let suffix = Uuid::now_v7().simple().to_string();
    let user = fixture.create_user(&suffix).await;
    let sid = format!("malformed-ceremony-{suffix}");
    let csrf = format!("csrf-{suffix}");
    let ceremony_id = "A".repeat(32);
    fixture.store_session(&user, &sid).await;
    valkey_set_ex(
        &fixture.state.valkey,
        registration_key(&ceremony_id),
        "{not-json".to_owned(),
        PASSKEY_CEREMONY_TTL_SECONDS,
    )
    .await
    .expect("malformed ceremony should store");

    let (status, body) = response_json(
        passkey_registration_finish(
            fixture.state.clone(),
            fixture.request(&sid, &csrf),
            Json(PasskeyFinishRequest {
                ceremony_id,
                response: invalid_registration_response(),
            }),
        )
        .await,
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");
    assert_eq!(body["error_description"], "passkey ceremony expired.");
}

#[actix_web::test]
async fn registration_finish_rejects_invalid_authenticator_response_without_persisting_credential()
{
    let Some(fixture) = LivePasskeyFixture::new().await else {
        return;
    };
    let suffix = Uuid::now_v7().simple().to_string();
    let user = fixture.create_user(&suffix).await;
    let sid = format!("invalid-finish-{suffix}");
    let csrf = format!("csrf-{suffix}");
    fixture.store_session(&user, &sid).await;

    let begin_response = passkey_registration_begin(
        fixture.state.clone(),
        fixture.request(&sid, &csrf),
        Json(PasskeyBeginRequest {
            label: Some("Security key".to_owned()),
        }),
    )
    .await;
    let (begin_status, begin_body) = response_json(begin_response).await;
    assert_eq!(begin_status, StatusCode::OK);
    let ceremony_id = begin_body["ceremony_id"]
        .as_str()
        .expect("begin response should include ceremony id");

    let (status, body) = response_json(
        passkey_registration_finish(
            fixture.state.clone(),
            fixture.request(&sid, &csrf),
            Json(PasskeyFinishRequest {
                ceremony_id: ceremony_id.to_owned(),
                response: invalid_registration_response(),
            }),
        )
        .await,
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");
    assert_eq!(body["error_description"], "passkey registration failed.");
    assert!(
        load_user_passkeys(&fixture.state, &user.identity())
            .await
            .expect("passkeys should load")
            .is_empty(),
        "a rejected ceremony must not persist any credential material"
    );
}

#[actix_web::test]
async fn passkey_list_returns_authenticated_user_credentials_from_database() {
    let Some(fixture) = LivePasskeyFixture::new().await else {
        return;
    };
    let suffix = Uuid::now_v7().simple().to_string();
    let user = fixture.create_user(&suffix).await;
    let sid = format!("list-{suffix}");
    let csrf = format!("csrf-{suffix}");
    fixture.store_session(&user, &sid).await;
    fixture
        .insert_passkey_credential(&user, "credential-one", json!({"placeholder": 1}), "Laptop")
        .await;
    fixture
        .insert_passkey_credential(&user, "credential-two", json!({"placeholder": 2}), "Phone")
        .await;

    let (status, body) =
        response_json(passkey_list(fixture.state.clone(), fixture.request(&sid, &csrf)).await)
            .await;

    assert_eq!(status, StatusCode::OK);
    let passkeys = body["passkeys"]
        .as_array()
        .expect("passkeys must be an array");
    assert_eq!(passkeys.len(), 2);
    assert_eq!(passkeys[0]["label"], "Laptop");
    assert_eq!(passkeys[1]["label"], "Phone");
    assert!(passkeys[0].get("credential").is_none());
}

#[actix_web::test]
async fn delete_passkey_removes_authenticated_user_credential() {
    let Some(fixture) = LivePasskeyFixture::new().await else {
        return;
    };
    let suffix = Uuid::now_v7().simple().to_string();
    let user = fixture.create_user(&suffix).await;
    let sid = format!("delete-{suffix}");
    let csrf = format!("csrf-{suffix}");
    fixture.store_session(&user, &sid).await;
    let row = fixture
        .insert_passkey_credential(
            &user,
            "credential-delete",
            json!({"placeholder": true}),
            "Hardware key",
        )
        .await;

    let response = passkey_delete(
        fixture.state.clone(),
        fixture.request(&sid, &csrf),
        actix_web::web::Path::from(row.id),
    )
    .await;
    assert_no_store(response.headers());
    let status = response.status();
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("response body should be readable");

    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(body.is_empty());
    assert!(
        load_user_passkeys(&fixture.state, &user.identity())
            .await
            .expect("passkeys should load")
            .is_empty(),
        "delete must remove the current user's credential row"
    );
}

#[actix_web::test]
async fn registration_finish_returns_conflict_without_second_row_on_duplicate_credential() {
    let Some(fixture) = LivePasskeyFixture::new().await else {
        return;
    };
    let suffix = Uuid::now_v7().simple().to_string();
    let user = fixture.create_user(&suffix).await;
    let sid = format!("duplicate-{suffix}");
    let csrf = format!("csrf-{suffix}");
    fixture.store_session(&user, &sid).await;
    let authenticator = FakeAuthenticator::new(format!("credential-{suffix}").as_bytes());

    let begin_one = passkey_registration_begin(
        fixture.state.clone(),
        fixture.request(&sid, &csrf),
        Json(PasskeyBeginRequest {
            label: Some("Primary key".to_owned()),
        }),
    )
    .await;
    let (begin_one_status, begin_one_body) = response_json(begin_one).await;
    assert_eq!(begin_one_status, StatusCode::OK);
    let ceremony_one = begin_one_body["ceremony_id"]
        .as_str()
        .expect("begin response should include ceremony id");
    let challenge_one = begin_one_body["publicKey"]["challenge"]
        .as_str()
        .expect("begin response should include challenge");

    let (first_status, first_body) = response_json(
        passkey_registration_finish(
            fixture.state.clone(),
            fixture.request(&sid, &csrf),
            Json(PasskeyFinishRequest {
                ceremony_id: ceremony_one.to_owned(),
                response: authenticator.registration_response(
                    challenge_one,
                    &fixture.state.settings.identity.passkey.origin,
                ),
            }),
        )
        .await,
    )
    .await;
    assert_eq!(first_status, StatusCode::CREATED);
    assert_eq!(first_body["label"], "Primary key");

    let begin_two = passkey_registration_begin(
        fixture.state.clone(),
        fixture.request(&sid, &csrf),
        Json(PasskeyBeginRequest {
            label: Some("Duplicate attempt".to_owned()),
        }),
    )
    .await;
    let (begin_two_status, begin_two_body) = response_json(begin_two).await;
    assert_eq!(begin_two_status, StatusCode::OK);
    let ceremony_two = begin_two_body["ceremony_id"]
        .as_str()
        .expect("second begin response should include ceremony id");
    let challenge_two = begin_two_body["publicKey"]["challenge"]
        .as_str()
        .expect("second begin response should include challenge");

    let (status, body) = response_json(
        passkey_registration_finish(
            fixture.state.clone(),
            fixture.request(&sid, &csrf),
            Json(PasskeyFinishRequest {
                ceremony_id: ceremony_two.to_owned(),
                response: authenticator.registration_response(
                    challenge_two,
                    &fixture.state.settings.identity.passkey.origin,
                ),
            }),
        )
        .await,
    )
    .await;

    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["error"], "invalid_request");
    assert_eq!(body["error_description"], "passkey already registered.");
    let rows = load_user_passkeys(&fixture.state, &user.identity())
        .await
        .expect("passkeys should load");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].label, "Primary key");
}

#[actix_web::test]
async fn delete_passkey_cannot_remove_another_users_credential() {
    let Some(fixture) = LivePasskeyFixture::new().await else {
        return;
    };
    let suffix = Uuid::now_v7().simple().to_string();
    let owner = fixture.create_user(&format!("{suffix}-owner")).await;
    let attacker = fixture.create_user(&format!("{suffix}-attacker")).await;
    let owner_sid = format!("owner-delete-{suffix}");
    let attacker_sid = format!("attacker-delete-{suffix}");
    let csrf = format!("csrf-{suffix}");
    fixture.store_session(&owner, &owner_sid).await;
    fixture.store_session(&attacker, &attacker_sid).await;
    let row = fixture
        .insert_passkey_credential(
            &owner,
            "owner-credential",
            json!({"placeholder": true}),
            "Owner key",
        )
        .await;

    let (status, body) = response_json(
        passkey_delete(
            fixture.state.clone(),
            fixture.request(&attacker_sid, &csrf),
            actix_web::web::Path::from(row.id),
        )
        .await,
    )
    .await;

    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["error"], "invalid_request");
    assert_eq!(body["error_description"], "passkey not found.");
    let owner_rows = load_user_passkeys(&fixture.state, &owner.identity())
        .await
        .expect("owner passkeys should load");
    assert_eq!(owner_rows.len(), 1);
    assert_eq!(owner_rows[0].label, "Owner key");
    assert!(
        load_user_passkeys(&fixture.state, &attacker.identity())
            .await
            .expect("attacker passkeys should load")
            .is_empty()
    );
}
