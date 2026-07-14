use std::sync::Arc;
use std::time::Duration as StdDuration;

use crate::domain::tenancy::DEFAULT_ORGANIZATION_ID;
use crate::domain::tenancy::DEFAULT_REALM_ID;
use crate::domain::tenancy::DEFAULT_TENANT_ID;
use crate::domain::{
    DatabasePasskeyFixture, DatabaseUserFixture, MFA_REMEMBERED_COOKIE_NAME,
    MFA_REMEMBERED_TTL_SECONDS, ServerMfaSecretHasher, TestAppState,
};
use crate::http::sessions::SessionPayload;
use crate::schema::{user_passkey_credentials, users};
use crate::settings::Settings;
use crate::test_support::valkey::valkey_get;
use actix_web::http::{StatusCode, header};
use actix_web::web::{Data, Json};
use actix_web::{HttpRequest, HttpResponse};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use chrono::Utc;
use diesel::prelude::*;
use diesel::sql_query;
use diesel::sql_types::{Bool, Text, Uuid as SqlUuid};
use diesel_async::RunQueryDsl;
use ed25519_dalek::{Signer, SigningKey};
use fred::interfaces::ClientLike;
use fred::prelude::{
    Builder as ValkeyBuilder, Config as ValkeyConfig, ConnectionConfig, PerformanceConfig,
};
use nazo_http_actix::{PasskeyLoginBeginRequest, PasskeyLoginFinishRequest, oauth_error};
use nazo_identity::PublicAccount;
use nazo_postgres::get_conn;
use passkey_auth::{AuthenticationResponse, PasskeyCredential, RegistrationResponse, Webauthn};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::config::ConfigSource;
use nazo_postgres::create_pool;

async fn remember_mfa_device(
    state: &TestAppState,
    request: &HttpRequest,
    user: &PublicAccount,
) -> anyhow::Result<String> {
    let user_agent_hash = request
        .headers()
        .get(header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(crate::adapters::security::blake3_hex);
    nazo_identity::MfaService::new(
        Arc::new(nazo_postgres::MfaRepository::new(state.diesel_db.clone())),
        Arc::new(ServerMfaSecretHasher),
    )
    .remember_device(
        user,
        user_agent_hash,
        chrono::Utc::now()
            + chrono::Duration::seconds(
                i64::try_from(MFA_REMEMBERED_TTL_SECONDS).expect("MFA TTL fits i64"),
            ),
    )
    .await
    .map_err(|error| anyhow::anyhow!("failed to remember MFA device: {error:?}"))
}

#[test]
fn passkey_login_transport_has_no_identity_or_storage_orchestration() {
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
        "update_counter(",
    ] {
        assert!(
            !source.contains(forbidden),
            "passkey login transport must not depend on {forbidden}"
        );
    }
}

async fn passkey_login_begin(
    state: Data<TestAppState>,
    req: HttpRequest,
    payload: Json<PasskeyLoginBeginRequest>,
) -> HttpResponse {
    nazo_http_actix::passkey_login_begin(super::test_login_endpoint(&state), req, Ok(payload)).await
}

async fn passkey_login_finish(
    state: Data<TestAppState>,
    req: HttpRequest,
    payload: Json<PasskeyLoginFinishRequest>,
) -> HttpResponse {
    nazo_http_actix::passkey_login_finish(super::test_login_endpoint(&state), req, Ok(payload))
        .await
}

async fn load_user_passkeys(
    state: &TestAppState,
    user: &PublicAccount,
) -> Result<Vec<nazo_identity::ports::PasskeyCredential>, HttpResponse> {
    nazo_postgres::PasskeyRepository::new(state.diesel_db.clone())
        .list(user.tenant().tenant_id, user.user_id())
        .await
        .map_err(|_| {
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "passkey state unavailable.",
            )
        })
}

fn passkey_user_handle(user: &DatabaseUserFixture) -> Vec<u8> {
    nazo_identity::passkey::passkey_user_handle(
        nazo_identity::TenantId::new(user.tenant_id).expect("test tenant ID must be valid"),
        nazo_identity::UserId::new(user.id).expect("test user ID must be valid"),
    )
}

fn passkey_credential_id(credential: &PasskeyCredential) -> String {
    credential.id.to_b64url()
}

fn passkey_webauthn(settings: &Settings) -> Webauthn {
    let passkey = &settings.identity.passkey;
    Webauthn::new(&passkey.rp_id, &passkey.rp_name, &passkey.origin)
        .require_user_verification(passkey.require_user_verification)
        .require_user_handle(passkey.require_user_handle)
        .strict_base64(passkey.strict_base64)
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

    fn authentication_response(
        &mut self,
        challenge_b64: &str,
        origin: &str,
        user_handle: Option<&[u8]>,
    ) -> AuthenticationResponse {
        let auth_data = self.auth_data_authenticate(None);
        let (client_data_raw, client_data_json) =
            client_data("webauthn.get", challenge_b64, origin);
        let signature = self.sign_assertion(&auth_data, &client_data_raw);
        AuthenticationResponse {
            id: B64URL.encode(&self.credential_id),
            authenticator_data: B64URL.encode(&auth_data),
            signature: B64URL.encode(signature),
            client_data_json,
            user_handle: user_handle.map(|handle| B64URL.encode(handle)),
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

    fn auth_data_authenticate(&mut self, counter: Option<u32>) -> Vec<u8> {
        let count = match counter {
            Some(count) => count,
            None => {
                self.counter += 1;
                self.counter
            }
        };
        let mut buf = Vec::new();
        buf.extend_from_slice(&Sha256::digest("example.com".as_bytes()));
        buf.push(self.flags);
        buf.extend_from_slice(&count.to_be_bytes());
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

    fn sign_assertion(&self, auth_data: &[u8], client_data_json_raw: &[u8]) -> Vec<u8> {
        let client_data_hash = Sha256::digest(client_data_json_raw);
        let mut message = Vec::with_capacity(auth_data.len() + 32);
        message.extend_from_slice(auth_data);
        message.extend_from_slice(&client_data_hash);
        self.sk.sign(&message).to_bytes().to_vec()
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
        self.create_user_with_email(&format!("passkey-login-{suffix}@example.com"), true)
            .await
    }

    async fn create_user_with_email(&self, email: &str, is_active: bool) -> DatabaseUserFixture {
        let username = format!("passkey-login-{}", Uuid::now_v7().simple());
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
        .bind::<Text, _>(email.to_owned())
        .bind::<Bool, _>(is_active)
        .get_result::<DatabaseUserFixture>(&mut conn)
        .await
        .expect("test user should insert")
    }

    async fn set_user_active(&self, user_id: Uuid, is_active: bool) {
        let mut conn = get_conn(&self.state.diesel_db)
            .await
            .expect("database connection");
        diesel::update(users::table.find(user_id))
            .set(users::is_active.eq(is_active))
            .execute(&mut conn)
            .await
            .expect("user activity state should update");
    }

    async fn set_user_mfa_enabled(&self, user_id: Uuid, mfa_enabled: bool) {
        let mut conn = get_conn(&self.state.diesel_db)
            .await
            .expect("database connection");
        diesel::update(users::table.find(user_id))
            .set(users::mfa_enabled.eq(mfa_enabled))
            .execute(&mut conn)
            .await
            .expect("user MFA state should update");
    }

    async fn session_payload(&self, sid: &str) -> SessionPayload {
        let raw = valkey_get(&self.state.valkey, format!("oauth:session:{sid}"))
            .await
            .expect("session lookup should succeed")
            .expect("session should be present");
        serde_json::from_str(&raw).expect("session payload should deserialize")
    }

    fn register_credential(
        &self,
        user: &DatabaseUserFixture,
        authenticator: &FakeAuthenticator,
    ) -> PasskeyCredential {
        let webauthn = passkey_webauthn(&self.state.settings);
        let (challenge, state) = webauthn.start_registration(
            &passkey_user_handle(user),
            &user.email,
            user.display_name.as_deref().unwrap_or(&user.email),
            &[],
        );
        webauthn
            .finish_registration(
                &state,
                &authenticator.registration_response(
                    &challenge.challenge,
                    &self.state.settings.identity.passkey.origin,
                ),
            )
            .expect("synthetic registration should succeed")
    }

    async fn insert_credential(
        &self,
        user: &DatabaseUserFixture,
        credential: &PasskeyCredential,
    ) -> DatabasePasskeyFixture {
        let mut conn = get_conn(&self.state.diesel_db)
            .await
            .expect("database connection");
        diesel::insert_into(user_passkey_credentials::table)
            .values((
                user_passkey_credentials::tenant_id.eq(user.tenant_id),
                user_passkey_credentials::user_id.eq(user.id),
                user_passkey_credentials::credential_id.eq(passkey_credential_id(credential)),
                user_passkey_credentials::credential
                    .eq(serde_json::to_value(credential).expect("credential should serialize")),
                user_passkey_credentials::label.eq("Security key"),
                user_passkey_credentials::sign_count.eq(i64::from(credential.counter)),
            ))
            .returning(DatabasePasskeyFixture::as_returning())
            .get_result::<DatabasePasskeyFixture>(&mut conn)
            .await
            .expect("passkey credential should insert")
    }

    async fn insert_malformed_credential(
        &self,
        user: &DatabaseUserFixture,
        credential_id: &str,
    ) -> DatabasePasskeyFixture {
        let mut conn = get_conn(&self.state.diesel_db)
            .await
            .expect("database connection");
        diesel::insert_into(user_passkey_credentials::table)
            .values((
                user_passkey_credentials::tenant_id.eq(user.tenant_id),
                user_passkey_credentials::user_id.eq(user.id),
                user_passkey_credentials::credential_id.eq(credential_id),
                user_passkey_credentials::credential.eq(json!({"broken": true})),
                user_passkey_credentials::label.eq("Broken credential"),
                user_passkey_credentials::sign_count.eq(0_i64),
            ))
            .returning(DatabasePasskeyFixture::as_returning())
            .get_result::<DatabasePasskeyFixture>(&mut conn)
            .await
            .expect("malformed passkey credential should insert")
    }

    async fn overwrite_credential_json(&self, row_id: Uuid, credential: Value) {
        let mut conn = get_conn(&self.state.diesel_db)
            .await
            .expect("database connection");
        diesel::update(user_passkey_credentials::table.find(row_id))
            .set(user_passkey_credentials::credential.eq(credential))
            .execute(&mut conn)
            .await
            .expect("credential JSON should update");
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

async fn response_json(response: HttpResponse) -> (StatusCode, Value) {
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    assert_eq!(response.headers().get(header::PRAGMA).unwrap(), "no-cache");
    let status = response.status();
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("response body should be readable");
    let json = serde_json::from_slice(&body).expect("response should be json");
    (status, json)
}

fn session_cookie_value(response: &HttpResponse, cookie_name: &str) -> String {
    let cookie_prefix = format!("{}=", cookie_name);
    for cookie in response
        .headers()
        .get_all(header::SET_COOKIE)
        .filter_map(|value| value.to_str().ok())
    {
        if let Some(value) = cookie
            .strip_prefix(&cookie_prefix)
            .and_then(|tail| tail.split(';').next())
        {
            return value.to_owned();
        }
    }
    panic!("response should include session cookie");
}

fn dummy_authentication_response() -> AuthenticationResponse {
    AuthenticationResponse {
        id: "not-used".to_owned(),
        authenticator_data: "not-used".to_owned(),
        signature: "not-used".to_owned(),
        client_data_json: "not-used".to_owned(),
        user_handle: None,
    }
}

async fn begin_passkey_login(fixture: &LivePasskeyFixture, email: &str) -> (String, String) {
    let begin_response = passkey_login_begin(
        fixture.state.clone(),
        actix_web::test::TestRequest::default().to_http_request(),
        Json(PasskeyLoginBeginRequest {
            email: email.to_owned(),
        }),
    )
    .await;
    let (status, body) = response_json(begin_response).await;
    assert_eq!(status, StatusCode::OK);
    (
        body["ceremony_id"]
            .as_str()
            .expect("begin response should include ceremony id")
            .to_owned(),
        body["publicKey"]["challenge"]
            .as_str()
            .expect("begin response should include challenge")
            .to_owned(),
    )
}

#[actix_web::test]
async fn passkey_login_finish_creates_session_updates_counter_and_consumes_ceremony_once() {
    let Some(fixture) = LivePasskeyFixture::new().await else {
        return;
    };
    let suffix = Uuid::now_v7().simple().to_string();
    let user = fixture.create_user(&suffix).await;
    let mut authenticator = FakeAuthenticator::new(format!("login-credential-{suffix}").as_bytes());
    let credential = fixture.register_credential(&user, &authenticator);
    let row = fixture.insert_credential(&user, &credential).await;
    let previous_session_id = Uuid::now_v7().to_string();
    let previous_session = nazo_identity::session::SessionRecord::new(
        nazo_identity::UserId::new(user.id).expect("fixture user id is valid"),
        Utc::now().timestamp(),
        vec!["pwd".to_owned()],
        false,
        Some(Uuid::now_v7().to_string()),
    );
    nazo_identity::ports::LoginSessionPort::create(
        &nazo_valkey::SessionStore::new(&fixture.state.valkey_connection()),
        &previous_session_id,
        &previous_session,
        900,
    )
    .await
    .expect("previous session should be stored");

    let begin_response = passkey_login_begin(
        fixture.state.clone(),
        actix_web::test::TestRequest::default().to_http_request(),
        Json(PasskeyLoginBeginRequest {
            email: user.email.clone(),
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

    let finish_response = passkey_login_finish(
        fixture.state.clone(),
        actix_web::test::TestRequest::default()
            .cookie(actix_web::cookie::Cookie::new(
                fixture.state.settings.session.session_cookie_name.clone(),
                previous_session_id.clone(),
            ))
            .to_http_request(),
        Json(PasskeyLoginFinishRequest {
            ceremony_id: ceremony_id.to_owned(),
            response: authenticator.authentication_response(
                challenge,
                &fixture.state.settings.identity.passkey.origin,
                Some(&passkey_user_handle(&user)),
            ),
        }),
    )
    .await;
    assert_eq!(finish_response.status(), StatusCode::OK);
    assert!(
        finish_response.headers().contains_key(header::SET_COOKIE),
        "successful passkey login must establish bound cookies"
    );
    let body = actix_web::body::to_bytes(finish_response.into_body())
        .await
        .expect("response body should be readable");
    let body: Value = serde_json::from_slice(&body).expect("response should be json");
    assert_eq!(body["mfa_required"], false);
    assert!(body.get("session_id").is_none());
    assert!(
        valkey_get(
            &fixture.state.valkey,
            format!("oauth:session:{previous_session_id}")
        )
        .await
        .expect("previous session lookup should succeed")
        .is_none(),
        "successful passkey login must atomically invalidate the previous session"
    );

    let rows = load_user_passkeys(&fixture.state, &user.identity())
        .await
        .expect("passkeys should load");
    let updated = rows
        .iter()
        .find(|candidate| candidate.id == row.id)
        .expect("registered credential should remain stored");
    assert_eq!(updated.sign_count, 1);
    assert!(updated.last_used_at.is_some());

    let replay_response = passkey_login_finish(
        fixture.state.clone(),
        actix_web::test::TestRequest::default().to_http_request(),
        Json(PasskeyLoginFinishRequest {
            ceremony_id: ceremony_id.to_owned(),
            response: authenticator.authentication_response(
                challenge,
                &fixture.state.settings.identity.passkey.origin,
                Some(&passkey_user_handle(&user)),
            ),
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
async fn passkey_login_finish_requires_mfa_for_mfa_enabled_user_without_remembered_device() {
    let Some(fixture) = LivePasskeyFixture::new().await else {
        return;
    };
    let suffix = Uuid::now_v7().simple().to_string();
    let user = fixture.create_user(&format!("required-mfa-{suffix}")).await;
    fixture.set_user_mfa_enabled(user.id, true).await;
    let identity_user = nazo_postgres::UserRepository::new(fixture.state.diesel_db.clone())
        .public_account_by_id(
            nazo_identity::TenantId::new(DEFAULT_TENANT_ID).unwrap(),
            nazo_identity::UserId::new(user.id).unwrap(),
        )
        .await
        .expect("user lookup should succeed")
        .expect("user should exist");
    let mut authenticator =
        FakeAuthenticator::new(format!("mfa-login-credential-{suffix}").as_bytes());
    let credential = fixture.register_credential(&user, &authenticator);
    fixture.insert_credential(&user, &credential).await;
    let (ceremony_id, challenge) =
        begin_passkey_login(&fixture, &identity_user.account.email).await;

    let finish_response = passkey_login_finish(
        fixture.state.clone(),
        actix_web::test::TestRequest::default().to_http_request(),
        Json(PasskeyLoginFinishRequest {
            ceremony_id,
            response: authenticator.authentication_response(
                &challenge,
                &fixture.state.settings.identity.passkey.origin,
                Some(&passkey_user_handle(&user)),
            ),
        }),
    )
    .await;
    assert_eq!(finish_response.status(), StatusCode::OK);
    let session_id = session_cookie_value(
        &finish_response,
        &fixture.state.settings.session.session_cookie_name,
    );
    let body = actix_web::body::to_bytes(finish_response.into_body())
        .await
        .expect("response body should be readable");
    let body: Value = serde_json::from_slice(&body).expect("response should be json");
    assert_eq!(body["mfa_required"], true);

    let session = fixture.session_payload(&session_id).await;
    assert_eq!(session.amr, vec!["passkey".to_owned()]);
    assert!(session.pending_mfa);
}

#[actix_web::test]
async fn passkey_login_finish_skips_pending_mfa_for_remembered_device() {
    let Some(fixture) = LivePasskeyFixture::new().await else {
        return;
    };
    let suffix = Uuid::now_v7().simple().to_string();
    let user_agent = format!("passkey-remembered-mfa/{suffix}");
    let user = fixture
        .create_user(&format!("remembered-mfa-{suffix}"))
        .await;
    fixture.set_user_mfa_enabled(user.id, true).await;
    let identity_user = nazo_postgres::UserRepository::new(fixture.state.diesel_db.clone())
        .public_account_by_id(
            nazo_identity::TenantId::new(DEFAULT_TENANT_ID).unwrap(),
            nazo_identity::UserId::new(user.id).unwrap(),
        )
        .await
        .expect("user lookup should succeed")
        .expect("user should exist");
    let remember_request = actix_web::test::TestRequest::default()
        .insert_header((header::USER_AGENT, user_agent.clone()))
        .to_http_request();
    let remember_token = remember_mfa_device(&fixture.state, &remember_request, &identity_user)
        .await
        .expect("remembered device token should be generated");
    let mut authenticator =
        FakeAuthenticator::new(format!("remembered-mfa-credential-{suffix}").as_bytes());
    let credential = fixture.register_credential(&user, &authenticator);
    fixture.insert_credential(&user, &credential).await;
    let (ceremony_id, challenge) =
        begin_passkey_login(&fixture, &identity_user.account.email).await;

    let finish_response = passkey_login_finish(
        fixture.state.clone(),
        actix_web::test::TestRequest::default()
            .insert_header((header::USER_AGENT, user_agent))
            .cookie(actix_web::cookie::Cookie::new(
                MFA_REMEMBERED_COOKIE_NAME,
                remember_token,
            ))
            .to_http_request(),
        Json(PasskeyLoginFinishRequest {
            ceremony_id,
            response: authenticator.authentication_response(
                &challenge,
                &fixture.state.settings.identity.passkey.origin,
                Some(&passkey_user_handle(&user)),
            ),
        }),
    )
    .await;
    assert_eq!(finish_response.status(), StatusCode::OK);
    let session_id = session_cookie_value(
        &finish_response,
        &fixture.state.settings.session.session_cookie_name,
    );
    let body = actix_web::body::to_bytes(finish_response.into_body())
        .await
        .expect("response body should be readable");
    let body: Value = serde_json::from_slice(&body).expect("response should be json");
    assert_eq!(body["mfa_required"], false);

    let session = fixture.session_payload(&session_id).await;
    assert_eq!(
        session.amr,
        vec![
            "passkey".to_owned(),
            "remembered_mfa".to_owned(),
            "mfa".to_owned()
        ]
    );
    assert!(!session.pending_mfa);
}

#[actix_web::test]
async fn passkey_login_finish_rejects_credential_mismatch_uniformly_and_consumes_ceremony() {
    let Some(fixture) = LivePasskeyFixture::new().await else {
        return;
    };
    let suffix = Uuid::now_v7().simple().to_string();
    let user = fixture.create_user(&suffix).await;
    let authenticator = FakeAuthenticator::new(format!("login-credential-{suffix}").as_bytes());
    let credential = fixture.register_credential(&user, &authenticator);
    fixture.insert_credential(&user, &credential).await;

    let begin_response = passkey_login_begin(
        fixture.state.clone(),
        actix_web::test::TestRequest::default().to_http_request(),
        Json(PasskeyLoginBeginRequest {
            email: user.email.clone(),
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

    let mut mismatched =
        FakeAuthenticator::new(format!("different-credential-{suffix}").as_bytes());
    let mismatch_response = passkey_login_finish(
        fixture.state.clone(),
        actix_web::test::TestRequest::default().to_http_request(),
        Json(PasskeyLoginFinishRequest {
            ceremony_id: ceremony_id.to_owned(),
            response: mismatched.authentication_response(
                challenge,
                &fixture.state.settings.identity.passkey.origin,
                Some(&passkey_user_handle(&user)),
            ),
        }),
    )
    .await;
    assert!(
        !mismatch_response
            .headers()
            .contains_key(actix_web::http::header::SET_COOKIE)
    );
    let (mismatch_status, mismatch_body) = response_json(mismatch_response).await;
    assert_eq!(mismatch_status, StatusCode::UNAUTHORIZED);
    assert_eq!(mismatch_body["error"], "access_denied");
    assert_eq!(mismatch_body["error_description"], "passkey login failed.");
    assert!(mismatch_body.get("credential_id").is_none());
    assert!(mismatch_body.get("user_id").is_none());

    let mut correct = FakeAuthenticator::new(format!("login-credential-{suffix}").as_bytes());
    let replay_response = passkey_login_finish(
        fixture.state.clone(),
        actix_web::test::TestRequest::default().to_http_request(),
        Json(PasskeyLoginFinishRequest {
            ceremony_id: ceremony_id.to_owned(),
            response: correct.authentication_response(
                challenge,
                &fixture.state.settings.identity.passkey.origin,
                Some(&passkey_user_handle(&user)),
            ),
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

fn normalized_login_begin(mut body: Value) -> Value {
    body["ceremony_id"] = json!("<opaque>");
    body["publicKey"]["challenge"] = json!("<opaque>");
    for credential in body["publicKey"]["allowCredentials"]
        .as_array_mut()
        .expect("allowCredentials must be an array")
    {
        credential["id"] = json!("<opaque>");
    }
    body
}

#[actix_web::test]
async fn passkey_login_begin_does_not_enumerate_account_or_credential_state() {
    let Some(fixture) = LivePasskeyFixture::new().await else {
        return;
    };
    let suffix = Uuid::now_v7().simple().to_string();
    let registered = fixture
        .create_user_with_email(&format!("passkey-registered-{suffix}@example.com"), true)
        .await;
    let authenticator = FakeAuthenticator::new(format!("registered-{suffix}").as_bytes());
    let credential = fixture.register_credential(&registered, &authenticator);
    fixture.insert_credential(&registered, &credential).await;
    let without_credential = fixture
        .create_user_with_email(&format!("passkey-empty-{suffix}@example.com"), true)
        .await;
    let inactive_email = format!("passkey-inactive-{suffix}@example.com");
    fixture.create_user_with_email(&inactive_email, false).await;

    let cases = [
        (registered.email, false),
        (format!("missing-{suffix}@example.com"), true),
        (without_credential.email, true),
        (inactive_email.to_uppercase(), true),
    ];
    let mut expected_response = None;
    for (email, dummy) in cases {
        let response = passkey_login_begin(
            fixture.state.clone(),
            actix_web::test::TestRequest::default().to_http_request(),
            Json(PasskeyLoginBeginRequest {
                email: format!("  {email}  "),
            }),
        )
        .await;
        assert!(
            !response.headers().contains_key(header::SET_COOKIE),
            "begin responses must not mint session cookies"
        );
        let (status, body) = response_json(response).await;

        assert_eq!(status, StatusCode::OK);
        assert!(
            body["ceremony_id"]
                .as_str()
                .is_some_and(|id| id.len() >= 32)
        );
        assert_eq!(body["publicKey"]["rpId"], "example.com");
        let allowed_credentials = body["publicKey"]["allowCredentials"]
            .as_array()
            .expect("allowCredentials must be present");
        assert_eq!(allowed_credentials.len(), 1);
        for descriptor in allowed_credentials {
            assert!(
                descriptor.get("transports").is_none(),
                "unauthenticated begin responses must not expose authenticator transport hints"
            );
        }
        let normalized = normalized_login_begin(body.clone());
        match &expected_response {
            Some(expected) => assert_eq!(
                &normalized, expected,
                "account and credential state must not change the response contract"
            ),
            None => expected_response = Some(normalized),
        }

        if dummy {
            let finish = passkey_login_finish(
                fixture.state.clone(),
                actix_web::test::TestRequest::default().to_http_request(),
                Json(PasskeyLoginFinishRequest {
                    ceremony_id: body["ceremony_id"].as_str().unwrap().to_owned(),
                    response: dummy_authentication_response(),
                }),
            )
            .await;
            assert!(!finish.headers().contains_key(header::SET_COOKIE));
            let (finish_status, finish_body) = response_json(finish).await;
            assert_eq!(finish_status, StatusCode::UNAUTHORIZED);
            assert_eq!(finish_body["error"], "access_denied");
            assert_eq!(finish_body["error_description"], "passkey login failed.");
        }
    }
}

#[actix_web::test]
async fn passkey_login_begin_reports_user_lookup_failure_before_challenge_issue() {
    let Some(fixture) = LivePasskeyFixture::new().await else {
        return;
    };
    let state = Data::new(TestAppState {
        diesel_db: create_pool(
            "postgres://nazo_passkey_begin_lookup_invalid:nazo_passkey_begin_lookup_invalid@127.0.0.1:1/nazo"
                .to_owned(),
            1,
        )
        .expect("pool construction should not connect"),
        valkey: fixture.state.valkey.clone(),
        settings: fixture.state.settings.clone(),
        keyset: fixture.state.keyset.clone(),
    });

    let response = passkey_login_begin(
        state,
        actix_web::test::TestRequest::default().to_http_request(),
        Json(PasskeyLoginBeginRequest {
            email: "user@example.com".to_owned(),
        }),
    )
    .await;
    assert!(
        !response.headers().contains_key(header::SET_COOKIE),
        "database lookup failures must not advance passkey login to a ceremony or session"
    );
    let (status, body) = response_json(response).await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"], "server_error");
    assert_eq!(body["error_description"], "user lookup failed.");
    assert!(body.get("ceremony_id").is_none());
    assert!(body.get("publicKey").is_none());
}

#[actix_web::test]
async fn passkey_login_begin_rejects_malformed_stored_credentials_before_challenge_issue() {
    let Some(fixture) = LivePasskeyFixture::new().await else {
        return;
    };
    let suffix = Uuid::now_v7().simple().to_string();
    let user = fixture.create_user(&suffix).await;
    fixture
        .insert_malformed_credential(&user, &B64URL.encode(format!("broken-{suffix}").as_bytes()))
        .await;

    let response = passkey_login_begin(
        fixture.state.clone(),
        actix_web::test::TestRequest::default().to_http_request(),
        Json(PasskeyLoginBeginRequest {
            email: user.email.clone(),
        }),
    )
    .await;
    assert!(
        !response.headers().contains_key(header::SET_COOKIE),
        "credential parse failures must not progress to session creation"
    );
    let (status, body) = response_json(response).await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"], "server_error");
    assert_eq!(body["error_description"], "passkey state unavailable.");
    assert!(body.get("ceremony_id").is_none());
    assert!(body.get("publicKey").is_none());
}

#[actix_web::test]
async fn passkey_login_finish_rejects_invalid_ceremony_id_before_state_lookup() {
    let Some(fixture) = LivePasskeyFixture::new().await else {
        return;
    };
    let response = passkey_login_finish(
        fixture.state.clone(),
        actix_web::test::TestRequest::default().to_http_request(),
        Json(PasskeyLoginFinishRequest {
            ceremony_id: "not/a-valid-ceremony".to_owned(),
            response: dummy_authentication_response(),
        }),
    )
    .await;
    assert!(
        !response.headers().contains_key(header::SET_COOKIE),
        "invalid ceremony ids must fail before any session material is issued"
    );
    let (status, body) = response_json(response).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");
    assert_eq!(body["error_description"], "invalid ceremony id.");
}

#[actix_web::test]
async fn passkey_login_finish_rejects_malformed_credential_id_before_credential_lookup() {
    let Some(fixture) = LivePasskeyFixture::new().await else {
        return;
    };
    let suffix = Uuid::now_v7().simple().to_string();
    let user = fixture.create_user(&suffix).await;
    let authenticator = FakeAuthenticator::new(format!("credential-id-{suffix}").as_bytes());
    let credential = fixture.register_credential(&user, &authenticator);
    fixture.insert_credential(&user, &credential).await;
    let (ceremony_id, _) = begin_passkey_login(&fixture, &user.email).await;

    let response = passkey_login_finish(
        fixture.state.clone(),
        actix_web::test::TestRequest::default().to_http_request(),
        Json(PasskeyLoginFinishRequest {
            ceremony_id,
            response: AuthenticationResponse {
                id: "not/base64url".to_owned(),
                authenticator_data: "not-used".to_owned(),
                signature: "not-used".to_owned(),
                client_data_json: "not-used".to_owned(),
                user_handle: None,
            },
        }),
    )
    .await;
    assert!(
        !response.headers().contains_key(header::SET_COOKIE),
        "malformed credential ids must fail before session creation"
    );
    let (status, body) = response_json(response).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");
    assert_eq!(body["error_description"], "invalid passkey credential id.");
    let rows = load_user_passkeys(&fixture.state, &user.identity())
        .await
        .expect("passkeys should load after rejected login");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].sign_count, 0);
    assert!(rows[0].last_used_at.is_none());
}

#[actix_web::test]
async fn passkey_login_finish_rejects_inactive_users_and_consumes_ceremony() {
    let Some(fixture) = LivePasskeyFixture::new().await else {
        return;
    };
    let suffix = Uuid::now_v7().simple().to_string();
    let user = fixture.create_user(&suffix).await;
    let mut authenticator =
        FakeAuthenticator::new(format!("inactive-credential-{suffix}").as_bytes());
    let credential = fixture.register_credential(&user, &authenticator);
    fixture.insert_credential(&user, &credential).await;
    let (ceremony_id, challenge) = begin_passkey_login(&fixture, &user.email).await;
    fixture.set_user_active(user.id, false).await;

    let response = passkey_login_finish(
        fixture.state.clone(),
        actix_web::test::TestRequest::default().to_http_request(),
        Json(PasskeyLoginFinishRequest {
            ceremony_id: ceremony_id.clone(),
            response: authenticator.authentication_response(
                &challenge,
                &fixture.state.settings.identity.passkey.origin,
                Some(&passkey_user_handle(&user)),
            ),
        }),
    )
    .await;
    assert!(
        !response.headers().contains_key(header::SET_COOKIE),
        "inactive users must not receive a new authenticated session"
    );
    let (status, body) = response_json(response).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "access_denied");
    assert_eq!(body["error_description"], "passkey login failed.");

    let replay_response = passkey_login_finish(
        fixture.state.clone(),
        actix_web::test::TestRequest::default().to_http_request(),
        Json(PasskeyLoginFinishRequest {
            ceremony_id,
            response: authenticator.authentication_response(
                &challenge,
                &fixture.state.settings.identity.passkey.origin,
                Some(&passkey_user_handle(&user)),
            ),
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
async fn passkey_login_finish_rejects_malformed_stored_credentials_before_webauthn_verification() {
    let Some(fixture) = LivePasskeyFixture::new().await else {
        return;
    };
    let suffix = Uuid::now_v7().simple().to_string();
    let user = fixture.create_user(&suffix).await;
    let mut authenticator =
        FakeAuthenticator::new(format!("malformed-credential-{suffix}").as_bytes());
    let credential = fixture.register_credential(&user, &authenticator);
    let row = fixture.insert_credential(&user, &credential).await;
    let (ceremony_id, challenge) = begin_passkey_login(&fixture, &user.email).await;
    fixture
        .overwrite_credential_json(row.id, json!({"broken": true}))
        .await;

    let response = passkey_login_finish(
        fixture.state.clone(),
        actix_web::test::TestRequest::default().to_http_request(),
        Json(PasskeyLoginFinishRequest {
            ceremony_id: ceremony_id.clone(),
            response: authenticator.authentication_response(
                &challenge,
                &fixture.state.settings.identity.passkey.origin,
                Some(&passkey_user_handle(&user)),
            ),
        }),
    )
    .await;
    assert!(
        !response.headers().contains_key(header::SET_COOKIE),
        "credential deserialization failures must not create sessions"
    );
    let (status, body) = response_json(response).await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"], "server_error");
    assert_eq!(body["error_description"], "passkey state unavailable.");

    let replay_response = passkey_login_finish(
        fixture.state.clone(),
        actix_web::test::TestRequest::default().to_http_request(),
        Json(PasskeyLoginFinishRequest {
            ceremony_id,
            response: authenticator.authentication_response(
                &challenge,
                &fixture.state.settings.identity.passkey.origin,
                Some(&passkey_user_handle(&user)),
            ),
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
async fn passkey_login_finish_rejects_origin_mismatch_and_consumes_ceremony() {
    let Some(fixture) = LivePasskeyFixture::new().await else {
        return;
    };
    let suffix = Uuid::now_v7().simple().to_string();
    let user = fixture.create_user(&suffix).await;
    let mut authenticator =
        FakeAuthenticator::new(format!("origin-credential-{suffix}").as_bytes());
    let credential = fixture.register_credential(&user, &authenticator);
    fixture.insert_credential(&user, &credential).await;
    let (ceremony_id, challenge) = begin_passkey_login(&fixture, &user.email).await;

    let response = passkey_login_finish(
        fixture.state.clone(),
        actix_web::test::TestRequest::default().to_http_request(),
        Json(PasskeyLoginFinishRequest {
            ceremony_id: ceremony_id.clone(),
            response: authenticator.authentication_response(
                &challenge,
                "https://attacker.example",
                Some(&passkey_user_handle(&user)),
            ),
        }),
    )
    .await;
    assert!(
        !response.headers().contains_key(header::SET_COOKIE),
        "origin-binding failures must not create sessions"
    );
    let (status, body) = response_json(response).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "access_denied");
    assert_eq!(body["error_description"], "passkey login failed.");

    let replay_response = passkey_login_finish(
        fixture.state.clone(),
        actix_web::test::TestRequest::default().to_http_request(),
        Json(PasskeyLoginFinishRequest {
            ceremony_id,
            response: authenticator.authentication_response(
                &challenge,
                "https://attacker.example",
                Some(&passkey_user_handle(&user)),
            ),
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
async fn passkey_login_finish_reports_user_lookup_failure_after_consuming_ceremony() {
    let Some(fixture) = LivePasskeyFixture::new().await else {
        return;
    };
    let suffix = Uuid::now_v7().simple().to_string();
    let user = fixture.create_user(&suffix).await;
    let mut authenticator = FakeAuthenticator::new(format!("db-failure-{suffix}").as_bytes());
    let credential = fixture.register_credential(&user, &authenticator);
    fixture.insert_credential(&user, &credential).await;
    let (ceremony_id, challenge) = begin_passkey_login(&fixture, &user.email).await;
    let state = Data::new(TestAppState {
        diesel_db: create_pool(
            "postgres://nazo_passkey_finish_lookup_invalid:nazo_passkey_finish_lookup_invalid@127.0.0.1:1/nazo"
                .to_owned(),
            1,
        )
        .expect("pool construction should not connect"),
        valkey: fixture.state.valkey.clone(),
        settings: fixture.state.settings.clone(),
        keyset: fixture.state.keyset.clone(),
    });

    let response = passkey_login_finish(
        state,
        actix_web::test::TestRequest::default().to_http_request(),
        Json(PasskeyLoginFinishRequest {
            ceremony_id: ceremony_id.clone(),
            response: authenticator.authentication_response(
                &challenge,
                &fixture.state.settings.identity.passkey.origin,
                Some(&passkey_user_handle(&user)),
            ),
        }),
    )
    .await;
    assert!(
        !response.headers().contains_key(header::SET_COOKIE),
        "user lookup failures after ceremony consumption must not mint a session"
    );
    let (status, body) = response_json(response).await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"], "server_error");
    assert_eq!(body["error_description"], "user lookup failed.");

    let replay_response = passkey_login_finish(
        fixture.state.clone(),
        actix_web::test::TestRequest::default().to_http_request(),
        Json(PasskeyLoginFinishRequest {
            ceremony_id,
            response: authenticator.authentication_response(
                &challenge,
                &fixture.state.settings.identity.passkey.origin,
                Some(&passkey_user_handle(&user)),
            ),
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
