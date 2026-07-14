use super::*;
use actix_web::cookie::Cookie;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use diesel::sql_query;
use diesel::sql_types::{Bool, Int4, Jsonb, Text, Uuid as SqlUuid};
use diesel_async::RunQueryDsl;
use fred::interfaces::ClientLike;
use fred::prelude::{
    Builder as ValkeyBuilder, Config as ValkeyConfig, ConnectionConfig, PerformanceConfig,
};
use openssl::encrypt::Decrypter;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::rsa::{Padding, Rsa};
use openssl::symm::{Cipher, decrypt_aead};
use std::sync::Arc;
use std::time::Duration as StdDuration;

use crate::adapters::security::jwt_decoding_key_from_jwk;
use crate::config::ConfigSource;
use crate::domain::{ConsentPayload, PushedAuthorizationRequest};
use crate::settings::AuthorizationServerProfile;
use nazo_postgres::{create_pool, get_conn};

fn unavailable_valkey_client() -> fred::prelude::Client {
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

fn endpoint_state(require_par: bool) -> TestAppState {
    let mut settings =
        Settings::from_config(&ConfigSource::default()).expect("default settings should load");
    settings.protocol.require_pushed_authorization_requests = require_par;
    settings.modules.enable_request_uri_parameter = true;
    settings.modules.enable_request_object = true;
    settings.modules.enable_par_request_object = true;
    settings.modules.enable_authorization_details = true;
    settings.endpoint.issuer = "https://issuer.example".to_owned();
    settings.endpoint.frontend_base_url = "https://app.example".to_owned();
    settings.protocol.auth_code_ttl_seconds = 60;

    TestAppState {
        diesel_db: create_pool(
            "postgres://nazo_authorize_test_invalid:nazo_authorize_test_invalid@127.0.0.1:1/nazo"
                .to_owned(),
            1,
        )
        .expect("pool construction should not connect"),
        valkey: unavailable_valkey_client(),
        settings: Arc::new(settings),
        keyset: crate::test_support::test_key_manager(),
    }
}

fn rs256_test_key_manager() -> nazo_key_management::KeyManager {
    crate::test_support::test_key_manager_with_algorithm(jsonwebtoken::Algorithm::RS256)
}

async fn json_body(response: HttpResponse) -> (StatusCode, Value) {
    let status = response.status();
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("response body should be readable");
    let value = serde_json::from_slice(&body).expect("response should be JSON");
    (status, value)
}

fn unsigned_request_object(claims: Value) -> String {
    let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"none"}"#);
    let payload = URL_SAFE_NO_PAD.encode(claims.to_string());
    format!("{header}.{payload}.")
}

struct LiveAuthorizationFixture {
    state: Data<TestAppState>,
}

impl LiveAuthorizationFixture {
    async fn new() -> Option<Self> {
        let database_url = std::env::var("DATABASE_URL").ok()?;
        let valkey_url = std::env::var("VALKEY_URL").ok()?;
        let config = ConfigSource::from_pairs_for_test([
            ("ISSUER", "https://issuer.example"),
            (
                "CLIENT_SECRET_PEPPER",
                "client-secret-pepper-for-tests-000000000001",
            ),
            ("FRONTEND_BASE_URL", "https://app.example"),
            ("COOKIE_SECURE", "true"),
            ("AUTH_RATE_LIMIT_MAX_REQUESTS", "100000"),
        ]);
        let mut settings = Settings::from_config(&config).expect("test settings should load");
        settings.protocol.require_pushed_authorization_requests = false;
        settings.modules.enable_request_object = true;
        settings.modules.enable_request_uri_parameter = true;
        settings.modules.enable_par_request_object = true;
        settings.modules.enable_authorization_details = true;

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

    fn state_with_request_uri_parameter(&self, enabled: bool) -> Data<TestAppState> {
        let mut settings = self.state.settings.as_ref().clone();
        settings.modules.enable_request_uri_parameter = enabled;
        Data::new(TestAppState {
            diesel_db: self.state.diesel_db.clone(),
            valkey: self.state.valkey.clone(),
            settings: Arc::new(settings),
            keyset: self.state.keyset.clone(),
        })
    }

    fn state_with_authorization_server_profile(
        &self,
        profile: AuthorizationServerProfile,
    ) -> Data<TestAppState> {
        let mut settings = self.state.settings.as_ref().clone();
        settings.protocol.authorization_server_profile = profile;
        settings.protocol.require_pushed_authorization_requests = profile.requires_fapi2_security();
        Data::new(TestAppState {
            diesel_db: self.state.diesel_db.clone(),
            valkey: self.state.valkey.clone(),
            settings: Arc::new(settings),
            keyset: self.state.keyset.clone(),
        })
    }

    async fn create_user(
        &self,
        suffix: &str,
        auth_role: &str,
        admin_level: i32,
    ) -> DatabaseUserFixture {
        let email = format!("authorize-{suffix}@example.com");
        let username = format!("authorize-{suffix}");
        let mut conn = get_conn(&self.state.diesel_db)
            .await
            .expect("database connection");
        sql_query(
            r#"
            INSERT INTO users (
                tenant_id, realm_id, organization_id, username, email,
                password_hash, is_active, mfa_enabled, email_verified, role, admin_level
            )
            VALUES ($1, $2, $3, $4, $5, 'unused-authorize-test-hash', true, false, true, $6, $7)
            RETURNING *
            "#,
        )
        .bind::<SqlUuid, _>(DEFAULT_TENANT_ID)
        .bind::<SqlUuid, _>(DEFAULT_REALM_ID)
        .bind::<SqlUuid, _>(DEFAULT_ORGANIZATION_ID)
        .bind::<Text, _>(username)
        .bind::<Text, _>(email)
        .bind::<Text, _>(auth_role.to_owned())
        .bind::<Int4, _>(admin_level)
        .get_result::<DatabaseUserFixture>(&mut conn)
        .await
        .expect("test user should insert")
    }

    async fn insert_client(
        &self,
        client_id: &str,
        redirect_uris: Vec<&str>,
        grant_types: Vec<&str>,
        allow_authorization_code_without_pkce: bool,
        is_active: bool,
    ) {
        let mut conn = get_conn(&self.state.diesel_db)
            .await
            .expect("database connection");
        sql_query("DELETE FROM oauth_clients WHERE tenant_id = $1 AND client_id = $2")
            .bind::<diesel::sql_types::Uuid, _>(DEFAULT_TENANT_ID)
            .bind::<Text, _>(client_id)
            .execute(&mut conn)
            .await
            .expect("test client cleanup should succeed");

        let redirect_uris = json!(redirect_uris);
        let grant_types = json!(grant_types);
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
                $1, $2, $3, $4, 'Authorization Test Client', 'confidential',
                NULL, $5, '["openid","profile"]'::jsonb, '["resource://default"]'::jsonb,
                $6, 'client_secret_basic', false,
                false, '[]'::jsonb, '[]'::jsonb,
                '[]'::jsonb, '[]'::jsonb,
                false,
                false, false,
                $7, $8,
                '[]'::jsonb, true
            )
            "#,
        )
        .bind::<diesel::sql_types::Uuid, _>(DEFAULT_TENANT_ID)
        .bind::<diesel::sql_types::Uuid, _>(DEFAULT_REALM_ID)
        .bind::<diesel::sql_types::Uuid, _>(DEFAULT_ORGANIZATION_ID)
        .bind::<Text, _>(client_id)
        .bind::<Jsonb, _>(redirect_uris)
        .bind::<Jsonb, _>(grant_types)
        .bind::<Bool, _>(allow_authorization_code_without_pkce)
        .bind::<Bool, _>(is_active)
        .execute(&mut conn)
        .await
        .expect("test client insert should succeed");
    }

    async fn mark_client_sender_constrained(
        &self,
        client_id: &str,
        require_dpop_bound_tokens: bool,
        require_mtls_bound_tokens: bool,
    ) {
        let mut conn = get_conn(&self.state.diesel_db)
            .await
            .expect("database connection");
        sql_query(
            r#"
            UPDATE oauth_clients
            SET require_dpop_bound_tokens = $1,
                require_mtls_bound_tokens = $2
            WHERE tenant_id = $3 AND client_id = $4
            "#,
        )
        .bind::<Bool, _>(require_dpop_bound_tokens)
        .bind::<Bool, _>(require_mtls_bound_tokens)
        .bind::<diesel::sql_types::Uuid, _>(DEFAULT_TENANT_ID)
        .bind::<Text, _>(client_id)
        .execute(&mut conn)
        .await
        .expect("test client sender constraint update should succeed");
    }

    async fn store_session(&self, user: &DatabaseUserFixture, sid: &str, auth_time: i64) {
        let payload = SessionPayload {
            user_id: user.id,
            auth_time,
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

    fn session_request(&self, sid: &str, uri: &str) -> HttpRequest {
        actix_web::test::TestRequest::get()
            .uri(uri)
            .cookie(Cookie::new(
                self.state.settings.session.session_cookie_name.clone(),
                sid.to_owned(),
            ))
            .to_http_request()
    }

    async fn store_pushed_request(
        &self,
        request_uri: &str,
        client_id: &str,
        params: HashMap<String, String>,
    ) {
        let payload = PushedAuthorizationRequest {
            client_id: client_id.to_owned(),
            params,
            dpop_jkt: None,
            mtls_x5t_s256: None,
            issued_at: Utc::now(),
            expires_at: Utc::now() + Duration::seconds(60),
        };
        valkey_set_ex(
            &self.state.valkey,
            &pushed_authorization_request_key(request_uri),
            serde_json::to_string(&payload).expect("PAR payload should serialize"),
            60,
        )
        .await
        .expect("PAR payload should persist");
    }

    async fn store_pushed_request_with_bindings(
        &self,
        request_uri: &str,
        client_id: &str,
        params: HashMap<String, String>,
        dpop_jkt: Option<&str>,
        mtls_x5t_s256: Option<&str>,
    ) {
        let payload = PushedAuthorizationRequest {
            client_id: client_id.to_owned(),
            params,
            dpop_jkt: dpop_jkt.map(ToOwned::to_owned),
            mtls_x5t_s256: mtls_x5t_s256.map(ToOwned::to_owned),
            issued_at: Utc::now(),
            expires_at: Utc::now() + Duration::seconds(60),
        };
        valkey_set_ex(
            &self.state.valkey,
            &pushed_authorization_request_key(request_uri),
            serde_json::to_string(&payload).expect("PAR payload should serialize"),
            60,
        )
        .await
        .expect("PAR payload should persist");
    }

    async fn store_raw_pushed_request(&self, request_uri: &str, raw: &str) {
        valkey_set_ex(
            &self.state.valkey,
            &pushed_authorization_request_key(request_uri),
            raw.to_owned(),
            60,
        )
        .await
        .expect("raw PAR payload should persist");
    }

    async fn stored_consent_payload(&self, request_id: &str) -> ConsentPayload {
        let raw = valkey_get(&self.state.valkey, format!("oauth:consent:{request_id}"))
            .await
            .expect("consent lookup should succeed")
            .expect("consent payload should exist");
        serde_json::from_str(&raw).expect("consent payload should deserialize")
    }
}

fn authorization_location(response: &HttpResponse) -> url::Url {
    assert_eq!(response.status(), StatusCode::FOUND);
    let location = response
        .headers()
        .get(header::LOCATION)
        .expect("authorization error should redirect")
        .to_str()
        .expect("redirect location should be ASCII");
    url::Url::parse(location).expect("redirect location should be absolute")
}

fn assert_authorization_error_redirect(response: HttpResponse, error: &str, state: Option<&str>) {
    let location = authorization_location(&response);
    assert_eq!(
        location.origin().ascii_serialization(),
        "https://client.example"
    );
    assert_eq!(location.path(), "/callback");
    let pairs = location.query_pairs().collect::<HashMap<_, _>>();
    assert_eq!(pairs.get("error").map(|value| value.as_ref()), Some(error));
    assert_eq!(
        pairs.get("iss").map(|value| value.as_ref()),
        Some("https://issuer.example")
    );
    assert_eq!(pairs.get("state").map(|value| value.as_ref()), state);
    assert!(!pairs.contains_key("code"));
}

async fn assert_authorization_invalid_request(response: HttpResponse) {
    if response.headers().get(header::LOCATION).is_some() {
        assert_authorization_error_redirect(response, "invalid_request", None);
    } else {
        let (status, body) = json_body(response).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "invalid_request");
        assert!(body.get("code").is_none());
    }
}

fn decode_jarm_claims(state: &TestAppState, response_jwt: &str, audience: &str) -> Value {
    let header =
        jsonwebtoken::decode_header(response_jwt).expect("JARM response header should decode");
    let decoding_key =
        jwt_decoding_key_from_jwk(&state.keyset.snapshot().jwks()["keys"][0], header.alg)
            .expect("JARM decoding key should derive from test JWKS");
    let mut validation = jsonwebtoken::Validation::new(header.alg);
    validation.validate_exp = false;
    validation.set_audience(&[audience]);
    validation.set_issuer(&[state.settings.endpoint.issuer.as_str()]);
    jsonwebtoken::decode::<Value>(response_jwt, &decoding_key, &validation)
        .expect("JARM response should verify with the active key")
        .claims
}

fn rsa_jarm_jwe_keypair(kid: &str) -> (PKey<Private>, Value) {
    let rsa = Rsa::generate(2048).expect("test RSA key should generate");
    let jwk = json!({
        "kty": "RSA",
        "kid": kid,
        "use": "enc",
        "alg": "RSA-OAEP-256",
        "n": URL_SAFE_NO_PAD.encode(rsa.n().to_vec()),
        "e": URL_SAFE_NO_PAD.encode(rsa.e().to_vec())
    });
    (
        PKey::from_rsa(rsa).expect("test RSA key should convert to PKey"),
        jwk,
    )
}

fn decrypt_jarm_jwe(
    private_key: &PKey<Private>,
    compact_jwe: &str,
) -> anyhow::Result<(Value, String)> {
    let parts = compact_jwe.split('.').collect::<Vec<_>>();
    anyhow::ensure!(parts.len() == 5, "compact JWE must have five parts");
    let protected_header: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0])?)?;
    let encrypted_key = URL_SAFE_NO_PAD.decode(parts[1])?;
    let iv = URL_SAFE_NO_PAD.decode(parts[2])?;
    let ciphertext = URL_SAFE_NO_PAD.decode(parts[3])?;
    let tag = URL_SAFE_NO_PAD.decode(parts[4])?;
    let mut decrypter = Decrypter::new(private_key)?;
    decrypter.set_rsa_padding(Padding::PKCS1_OAEP)?;
    decrypter.set_rsa_oaep_md(MessageDigest::sha256())?;
    decrypter.set_rsa_mgf1_md(MessageDigest::sha256())?;
    let mut cek = vec![0; decrypter.decrypt_len(&encrypted_key)?];
    let len = decrypter.decrypt(&encrypted_key, &mut cek)?;
    cek.truncate(len);
    let plaintext = decrypt_aead(
        Cipher::aes_256_gcm(),
        &cek,
        Some(&iv),
        parts[0].as_bytes(),
        &ciphertext,
        &tag,
    )?;
    Ok((protected_header, String::from_utf8(plaintext)?))
}

#[actix_web::test]
async fn authorization_get_rejects_duplicate_oauth_parameters_before_client_lookup() {
    let state = Data::new(endpoint_state(false));
    let req = actix_web::test::TestRequest::get()
        .uri("/authorize?client_id=client-a&client_id=client-b&response_type=code")
        .to_http_request();

    let (status, body) = json_body(authorize_get(state, req).await).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");
    assert_eq!(body["error_description"], "Request failed.");
    assert!(body.get("code").is_none());
    assert!(body.get("access_token").is_none());
    assert!(body.get("refresh_token").is_none());
}

#[actix_web::test]
async fn authorization_get_requires_par_before_untrusted_runtime_parameters() {
    let state = Data::new(endpoint_state(true));
    let req = actix_web::test::TestRequest::get()
        .uri("/authorize?client_id=client-a&response_type=code")
        .to_http_request();
    let mut q = query(&[("client_id", "client-a"), ("response_type", "code")]);

    let (status, body) = json_body(authorize_request(state, req, &mut q).await).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");
    assert_eq!(body["error_description"], "Request failed.");
    assert!(body.get("redirect_uri").is_none());
    assert!(body.get("code").is_none());
}

#[actix_web::test]
async fn authorization_request_rejects_disabled_request_object_parameters_before_client_lookup() {
    let mut state = endpoint_state(false);
    Arc::get_mut(&mut state.settings)
        .expect("test state owns its settings")
        .modules
        .enable_request_object = false;
    let state = Data::new(state);
    let req = actix_web::test::TestRequest::get()
        .uri("/authorize?request=jwt")
        .to_http_request();
    let mut q = query(&[("request", "jwt")]);

    let (status, body) = json_body(authorize_request(state, req, &mut q).await).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");
    assert!(body.get("code").is_none());
}

#[actix_web::test]
async fn authorization_request_rejects_disabled_request_uri_parameter_before_client_lookup() {
    let mut state = endpoint_state(false);
    Arc::get_mut(&mut state.settings)
        .expect("test state owns its settings")
        .modules
        .enable_request_uri_parameter = false;
    let state = Data::new(state);
    let req = actix_web::test::TestRequest::get()
        .uri("/authorize?request_uri=https%3A%2F%2Fclient.example%2Frequest.jwt")
        .to_http_request();
    let mut q = query(&[("request_uri", "https://client.example/request.jwt")]);

    let (status, body) = json_body(authorize_request(state, req, &mut q).await).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");
    assert!(body.get("code").is_none());
}

#[actix_web::test]
async fn authorization_request_allows_par_request_uri_when_request_uri_parameter_is_disabled() {
    let Some(fixture) = LiveAuthorizationFixture::new().await else {
        return;
    };
    let client_id = format!("authorize-par-disabled-request-uri-{}", Uuid::now_v7());
    fixture
        .insert_client(
            &client_id,
            vec!["https://client.example/callback"],
            vec!["authorization_code"],
            true,
            true,
        )
        .await;
    let request_uri = format!("urn:ietf:params:oauth:request_uri:{}", Uuid::now_v7());
    fixture
        .store_pushed_request(
            &request_uri,
            &client_id,
            query(&[
                ("client_id", client_id.as_str()),
                ("redirect_uri", "https://client.example/callback"),
                ("response_type", "code"),
                ("scope", "openid"),
                ("state", "par-disabled-request-uri"),
            ]),
        )
        .await;
    let uri = format!(
        "/authorize?client_id={}&request_uri={}&redirect_uri=https%3A%2F%2Fclient.example%2Fcallback&response_type=code&scope=openid",
        urlencoding::encode(&client_id),
        urlencoding::encode(&request_uri)
    );
    let req = actix_web::test::TestRequest::get()
        .uri(&uri)
        .to_http_request();
    let mut q = query(&[
        ("client_id", client_id.as_str()),
        ("request_uri", request_uri.as_str()),
        ("redirect_uri", "https://client.example/callback"),
        ("response_type", "code"),
        ("scope", "openid"),
    ]);

    let response =
        authorize_request(fixture.state_with_request_uri_parameter(false), req, &mut q).await;
    let location = authorization_location(&response);

    assert_eq!(
        location.origin().ascii_serialization(),
        "https://app.example"
    );
    assert_eq!(location.path(), "/auth");
    let next = location
        .query_pairs()
        .find_map(|(key, value)| (key == "next").then_some(value.into_owned()))
        .expect("login redirect should include next parameter");
    let next = urlencoding::decode(&next).expect("next parameter should decode");
    assert!(next.contains("request_uri="));
    assert!(!next.contains("state=par-disabled-request-uri"));
}

#[actix_web::test]
async fn authorization_request_redirects_non_par_request_uri_as_unsupported() {
    let Some(fixture) = LiveAuthorizationFixture::new().await else {
        return;
    };
    let client_id = format!("authorize-external-request-uri-{}", Uuid::now_v7());
    fixture
        .insert_client(
            &client_id,
            vec!["https://client.example/callback"],
            vec!["authorization_code"],
            true,
            true,
        )
        .await;
    let req = actix_web::test::TestRequest::get()
        .uri(&format!(
            "/authorize?client_id={}&request_uri=https%3A%2F%2Fclient.example%2Frequest.jwt&redirect_uri=https%3A%2F%2Fclient.example%2Fcallback&response_type=code&scope=openid&state=external-request-uri",
            urlencoding::encode(&client_id)
        ))
        .to_http_request();
    let mut q = query(&[
        ("client_id", client_id.as_str()),
        ("request_uri", "https://client.example/request.jwt"),
        ("redirect_uri", "https://client.example/callback"),
        ("response_type", "code"),
        ("scope", "openid"),
        ("state", "external-request-uri"),
    ]);

    let response = authorize_request(fixture.state.clone(), req, &mut q).await;

    assert_authorization_error_redirect(
        response,
        "request_uri_not_supported",
        Some("external-request-uri"),
    );
}

#[actix_web::test]
async fn authorization_request_rejects_disabled_authorization_details_before_client_lookup() {
    let mut state = endpoint_state(false);
    Arc::get_mut(&mut state.settings)
        .expect("test state owns its settings")
        .modules
        .enable_authorization_details = false;
    let state = Data::new(state);
    let req = actix_web::test::TestRequest::get()
        .uri("/authorize?authorization_details=%5B%5D")
        .to_http_request();
    let mut q = query(&[("authorization_details", "[]")]);

    let (status, body) = json_body(authorize_request(state, req, &mut q).await).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");
    assert!(body.get("code").is_none());
}

#[actix_web::test]
async fn authorization_request_reports_request_uri_storage_failure_without_redirect() {
    let state = Data::new(endpoint_state(false));
    let request_uri = "urn:ietf:params:oauth:request_uri:broken-storage";
    let req = actix_web::test::TestRequest::get()
        .uri("/authorize?client_id=client-a&request_uri=urn%3Aietf%3Aparams%3Aoauth%3Arequest_uri%3Abroken-storage")
        .to_http_request();
    let mut q = query(&[("client_id", "client-a"), ("request_uri", request_uri)]);

    let response = authorize_request(state, req, &mut q).await;
    assert!(response.headers().get(header::LOCATION).is_none());
    let (status, body) = json_body(response).await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"], "server_error");
}

#[actix_web::test]
async fn authorization_get_requires_client_id_before_database_lookup() {
    let state = Data::new(endpoint_state(false));
    let req = actix_web::test::TestRequest::get()
        .uri("/authorize?response_type=code")
        .to_http_request();
    let mut q = query(&[("response_type", "code")]);

    let response = authorize_request(state, req, &mut q).await;
    assert!(response.headers().get(header::LOCATION).is_none());
    let (status, body) = json_body(response).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");
    assert_eq!(body["error_description"], "Request failed.");
    assert!(body.get("code").is_none());
    assert!(body.get("access_token").is_none());
}

#[actix_web::test]
async fn authorization_get_wrapper_uses_same_pre_database_validation() {
    let state = Data::new(endpoint_state(false));
    let req = actix_web::test::TestRequest::get()
        .uri("/authorize?response_type=code")
        .to_http_request();

    let response = authorize_get(state, req).await;
    assert!(response.headers().get(header::LOCATION).is_none());
    let (status, body) = json_body(response).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");
    assert_eq!(body["error_description"], "Request failed.");
    assert!(body.get("code").is_none());
}

#[actix_web::test]
async fn authorization_post_wrapper_rejects_duplicate_parameters_before_client_lookup() {
    let state = Data::new(endpoint_state(false));
    let req = actix_web::test::TestRequest::post()
        .uri("/authorize")
        .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
        .to_http_request();
    let body = Bytes::from_static(b"client_id=client-a&client_id=client-b&response_type=code");

    let (status, body) = json_body(authorize_post(state, req, body).await).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");
    assert_eq!(body["error_description"], "Request failed.");
    assert!(body.get("code").is_none());
}

#[actix_web::test]
async fn authorization_request_rejects_unsigned_request_object_without_client_id() {
    let state = Data::new(endpoint_state(false));
    let request_object = unsigned_request_object(json!({
        "client_id": "client-from-request-object",
        "iss": "client-from-request-object",
        "aud": "https://issuer.example",
        "response_type": "code",
        "redirect_uri": "https://client.example/cb"
    }));
    let uri = format!(
        "/authorize?request={}",
        urlencoding::encode(&request_object)
    );
    let req = actix_web::test::TestRequest::get()
        .uri(&uri)
        .to_http_request();
    let mut q = query(&[("request", request_object.as_str())]);

    let (status, body) = json_body(authorize_request(state, req, &mut q).await).await;

    assert!(!q.contains_key("client_id"));
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");
    assert_eq!(body["error_description"], "Request failed.");
}

#[actix_web::test]
async fn authorization_request_reports_client_lookup_failure_without_redirecting() {
    let state = Data::new(endpoint_state(false));
    let req = actix_web::test::TestRequest::get()
        .uri("/authorize?client_id=client-a&response_type=code")
        .to_http_request();
    let mut q = query(&[("client_id", "client-a"), ("response_type", "code")]);

    let response = authorize_request(state, req, &mut q).await;
    assert!(response.headers().get(header::LOCATION).is_none());
    let (status, body) = json_body(response).await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"], "server_error");
    assert_eq!(body["error_description"], "Request failed.");
    assert!(body.get("code").is_none());
}

#[actix_web::test]
async fn authorization_request_rejects_malformed_request_uri_state_without_redirecting() {
    let Some(fixture) = LiveAuthorizationFixture::new().await else {
        return;
    };
    let request_uri = format!("urn:ietf:params:oauth:request_uri:{}", Uuid::now_v7());
    fixture
        .store_raw_pushed_request(&request_uri, "{not-json")
        .await;
    let req = actix_web::test::TestRequest::get()
        .uri("/authorize?client_id=client-a&request_uri=urn%3Aietf%3Aparams%3Aoauth%3Arequest_uri%3Abad")
        .to_http_request();
    let mut q = query(&[
        ("client_id", "client-a"),
        ("request_uri", request_uri.as_str()),
    ]);

    let response = authorize_request(fixture.state.clone(), req, &mut q).await;
    assert!(response.headers().get(header::LOCATION).is_none());
    let (status, body) = json_body(response).await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"], "server_error");
}

#[actix_web::test]
async fn authorization_request_redirects_missing_par_uri_after_registered_redirect_is_known() {
    let Some(fixture) = LiveAuthorizationFixture::new().await else {
        return;
    };
    let client_id = format!("authorize-par-missing-{}", Uuid::now_v7());
    fixture
        .insert_client(
            &client_id,
            vec!["https://client.example/callback"],
            vec!["authorization_code"],
            true,
            true,
        )
        .await;
    let request_uri = format!("urn:ietf:params:oauth:request_uri:{}", Uuid::now_v7());
    let uri = format!(
        "/authorize?client_id={}&request_uri={}&redirect_uri=https%3A%2F%2Fclient.example%2Fcallback&response_type=code&state=par-state",
        urlencoding::encode(&client_id),
        urlencoding::encode(&request_uri)
    );
    let req = actix_web::test::TestRequest::get()
        .uri(&uri)
        .to_http_request();
    let mut q = query(&[
        ("client_id", client_id.as_str()),
        ("request_uri", request_uri.as_str()),
        ("redirect_uri", "https://client.example/callback"),
        ("response_type", "code"),
        ("state", "par-state"),
    ]);

    let response = authorize_request(fixture.state.clone(), req, &mut q).await;

    assert_authorization_error_redirect(response, "invalid_request_uri", Some("par-state"));
}

#[actix_web::test]
async fn authorization_request_redirects_when_outer_request_uri_parameters_do_not_match_par() {
    let Some(fixture) = LiveAuthorizationFixture::new().await else {
        return;
    };
    let client_id = format!("authorize-par-mismatch-{}", Uuid::now_v7());
    fixture
        .insert_client(
            &client_id,
            vec!["https://client.example/callback"],
            vec!["authorization_code"],
            true,
            true,
        )
        .await;
    let request_uri = format!("urn:ietf:params:oauth:request_uri:{}", Uuid::now_v7());
    fixture
        .store_pushed_request(
            &request_uri,
            &client_id,
            query(&[
                ("client_id", client_id.as_str()),
                ("redirect_uri", "https://client.example/callback"),
                ("response_type", "code"),
                ("scope", "openid"),
                ("state", "pushed-state"),
            ]),
        )
        .await;
    let uri = format!(
        "/authorize?client_id={}&request_uri={}&redirect_uri=https%3A%2F%2Fattacker.example%2Fcallback&response_type=code",
        urlencoding::encode(&client_id),
        urlencoding::encode(&request_uri)
    );
    let req = actix_web::test::TestRequest::get()
        .uri(&uri)
        .to_http_request();
    let mut q = query(&[
        ("client_id", client_id.as_str()),
        ("request_uri", request_uri.as_str()),
        ("redirect_uri", "https://attacker.example/callback"),
        ("response_type", "code"),
    ]);

    let response = authorize_request(fixture.state.clone(), req, &mut q).await;

    assert_authorization_error_redirect(response, "invalid_request", Some("pushed-state"));
}

#[actix_web::test]
async fn fapi_authorization_request_rejects_outer_parameters_beyond_client_id_and_request_uri() {
    let Some(fixture) = LiveAuthorizationFixture::new().await else {
        return;
    };
    let client_id = format!("authorize-fapi-par-outer-{}", Uuid::now_v7());
    fixture
        .insert_client(
            &client_id,
            vec!["https://client.example/callback"],
            vec!["authorization_code"],
            true,
            true,
        )
        .await;
    let request_uri = format!("urn:ietf:params:oauth:request_uri:{}", Uuid::now_v7());
    fixture
        .store_pushed_request(
            &request_uri,
            &client_id,
            query(&[
                ("client_id", client_id.as_str()),
                ("redirect_uri", "https://client.example/callback"),
                ("response_type", "code"),
                ("scope", "openid"),
                ("state", "fapi-par-state"),
            ]),
        )
        .await;
    let uri = format!(
        "/authorize?client_id={}&request_uri={}&redirect_uri=https%3A%2F%2Fclient.example%2Fcallback&response_type=code",
        urlencoding::encode(&client_id),
        urlencoding::encode(&request_uri)
    );
    let req = actix_web::test::TestRequest::get()
        .uri(&uri)
        .to_http_request();
    let mut q = query(&[
        ("client_id", client_id.as_str()),
        ("request_uri", request_uri.as_str()),
        ("redirect_uri", "https://client.example/callback"),
        ("response_type", "code"),
    ]);

    let response = authorize_request(
        fixture.state_with_authorization_server_profile(AuthorizationServerProfile::Fapi2Security),
        req,
        &mut q,
    )
    .await;

    assert_authorization_error_redirect(response, "invalid_request", Some("fapi-par-state"));
}

#[actix_web::test]
async fn authorization_request_redirects_when_par_client_id_does_not_match() {
    let Some(fixture) = LiveAuthorizationFixture::new().await else {
        return;
    };
    let client_id = format!("authorize-par-client-mismatch-{}", Uuid::now_v7());
    fixture
        .insert_client(
            &client_id,
            vec!["https://client.example/callback"],
            vec!["authorization_code"],
            true,
            true,
        )
        .await;
    let request_uri = format!("urn:ietf:params:oauth:request_uri:{}", Uuid::now_v7());
    fixture
        .store_pushed_request(
            &request_uri,
            "different-client",
            query(&[
                ("client_id", "different-client"),
                ("redirect_uri", "https://client.example/callback"),
                ("response_type", "code"),
                ("state", "state-1"),
            ]),
        )
        .await;
    let uri = format!(
        "/authorize?client_id={}&request_uri={}&redirect_uri=https%3A%2F%2Fclient.example%2Fcallback&response_type=code&state=state-1",
        urlencoding::encode(&client_id),
        urlencoding::encode(&request_uri)
    );
    let req = actix_web::test::TestRequest::get()
        .uri(&uri)
        .to_http_request();
    let mut q = query(&[
        ("client_id", client_id.as_str()),
        ("request_uri", request_uri.as_str()),
        ("redirect_uri", "https://client.example/callback"),
        ("response_type", "code"),
        ("state", "state-1"),
    ]);

    let response = authorize_request(fixture.state.clone(), req, &mut q).await;

    assert_authorization_error_redirect(response, "invalid_request_uri", Some("state-1"));
}

#[actix_web::test]
async fn authorization_request_rejects_client_without_authorization_code_grant_before_redirect() {
    let Some(fixture) = LiveAuthorizationFixture::new().await else {
        return;
    };
    let client_id = format!("authorize-no-code-grant-{}", Uuid::now_v7());
    fixture
        .insert_client(
            &client_id,
            vec!["https://client.example/callback"],
            vec!["client_credentials"],
            true,
            true,
        )
        .await;
    let uri = format!(
        "/authorize?client_id={}&redirect_uri=https%3A%2F%2Fclient.example%2Fcallback&response_type=code",
        urlencoding::encode(&client_id)
    );
    let req = actix_web::test::TestRequest::get()
        .uri(&uri)
        .to_http_request();
    let mut q = query(&[
        ("client_id", client_id.as_str()),
        ("redirect_uri", "https://client.example/callback"),
        ("response_type", "code"),
    ]);

    let response = authorize_request(fixture.state.clone(), req, &mut q).await;
    assert!(response.headers().get(header::LOCATION).is_none());
    let (status, body) = json_body(response).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "unauthorized_client");
    assert!(body.get("code").is_none());
}

#[actix_web::test]
async fn authorization_request_rejects_inactive_client_before_session_lookup() {
    let Some(fixture) = LiveAuthorizationFixture::new().await else {
        return;
    };
    let client_id = format!("authorize-inactive-{}", Uuid::now_v7());
    fixture
        .insert_client(
            &client_id,
            vec!["https://client.example/callback"],
            vec!["authorization_code"],
            true,
            false,
        )
        .await;
    let uri = format!(
        "/authorize?client_id={}&redirect_uri=https%3A%2F%2Fclient.example%2Fcallback&response_type=code",
        urlencoding::encode(&client_id)
    );
    let req = actix_web::test::TestRequest::get()
        .uri(&uri)
        .to_http_request();
    let mut q = query(&[
        ("client_id", client_id.as_str()),
        ("redirect_uri", "https://client.example/callback"),
        ("response_type", "code"),
    ]);

    let response = authorize_request(fixture.state.clone(), req, &mut q).await;
    assert!(response.headers().get(header::LOCATION).is_none());
    let (status, body) = json_body(response).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "unauthorized_client");
}

#[actix_web::test]
async fn authorization_request_rejects_unregistered_redirect_uri_before_session_lookup() {
    let Some(fixture) = LiveAuthorizationFixture::new().await else {
        return;
    };
    let client_id = format!("authorize-bad-redirect-{}", Uuid::now_v7());
    fixture
        .insert_client(
            &client_id,
            vec!["https://client.example/callback"],
            vec!["authorization_code"],
            true,
            true,
        )
        .await;
    let uri = format!(
        "/authorize?client_id={}&redirect_uri=https%3A%2F%2Fattacker.example%2Fcallback&response_type=code",
        urlencoding::encode(&client_id)
    );
    let req = actix_web::test::TestRequest::get()
        .uri(&uri)
        .to_http_request();
    let mut q = query(&[
        ("client_id", client_id.as_str()),
        ("redirect_uri", "https://attacker.example/callback"),
        ("response_type", "code"),
    ]);

    let response = authorize_request(fixture.state.clone(), req, &mut q).await;
    assert!(response.headers().get(header::LOCATION).is_none());
    let (status, body) = json_body(response).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");
    assert!(body.get("code").is_none());
}

#[actix_web::test]
async fn authorization_request_rejects_missing_redirect_uri_when_client_has_multiple_registrations()
{
    let Some(fixture) = LiveAuthorizationFixture::new().await else {
        return;
    };
    let client_id = format!("authorize-multi-redirect-{}", Uuid::now_v7());
    fixture
        .insert_client(
            &client_id,
            vec![
                "https://client.example/callback-a",
                "https://client.example/callback-b",
            ],
            vec!["authorization_code"],
            true,
            true,
        )
        .await;
    let uri = format!(
        "/authorize?client_id={}&response_type=code",
        urlencoding::encode(&client_id)
    );
    let req = actix_web::test::TestRequest::get()
        .uri(&uri)
        .to_http_request();
    let mut q = query(&[("client_id", client_id.as_str()), ("response_type", "code")]);

    let response = authorize_request(fixture.state.clone(), req, &mut q).await;
    assert_authorization_invalid_request(response).await;
}

#[actix_web::test]
async fn authorization_request_rejects_invalid_dpop_jkt_before_redirect_response() {
    let Some(fixture) = LiveAuthorizationFixture::new().await else {
        return;
    };
    let client_id = format!("authorize-dpop-invalid-{}", Uuid::now_v7());
    fixture
        .insert_client(
            &client_id,
            vec!["https://client.example/callback"],
            vec!["authorization_code"],
            true,
            true,
        )
        .await;
    let uri = format!(
        "/authorize?client_id={}&redirect_uri=https%3A%2F%2Fclient.example%2Fcallback&response_type=code&dpop_jkt=not-a-thumbprint",
        urlencoding::encode(&client_id)
    );
    let req = actix_web::test::TestRequest::get()
        .uri(&uri)
        .to_http_request();
    let mut q = query(&[
        ("client_id", client_id.as_str()),
        ("redirect_uri", "https://client.example/callback"),
        ("response_type", "code"),
        ("dpop_jkt", "not-a-thumbprint"),
    ]);

    let response = authorize_request(fixture.state.clone(), req, &mut q).await;
    assert_authorization_invalid_request(response).await;
}

#[actix_web::test]
async fn authorization_request_rejects_sender_constrained_client_without_par_or_jar() {
    let Some(fixture) = LiveAuthorizationFixture::new().await else {
        return;
    };
    let client_id = format!("authorize-holder-bound-{}", Uuid::now_v7());
    fixture
        .insert_client(
            &client_id,
            vec!["https://client.example/callback"],
            vec!["authorization_code"],
            true,
            true,
        )
        .await;
    fixture
        .mark_client_sender_constrained(&client_id, true, false)
        .await;
    let uri = format!(
        "/authorize?client_id={}&redirect_uri=https%3A%2F%2Fclient.example%2Fcallback&response_type=code&state=holder-required",
        urlencoding::encode(&client_id)
    );
    let req = actix_web::test::TestRequest::get()
        .uri(&uri)
        .to_http_request();
    let mut q = query(&[
        ("client_id", client_id.as_str()),
        ("redirect_uri", "https://client.example/callback"),
        ("response_type", "code"),
        ("state", "holder-required"),
    ]);

    let response = authorize_request(fixture.state.clone(), req, &mut q).await;

    assert_authorization_error_redirect(response, "invalid_request", Some("holder-required"));
}

#[actix_web::test]
async fn authorization_request_rejects_par_dpop_binding_mismatch_without_redirect() {
    let Some(fixture) = LiveAuthorizationFixture::new().await else {
        return;
    };
    let client_id = format!("authorize-par-dpop-{}", Uuid::now_v7());
    let pushed_jkt = "w7JAoU_gJbZJvV-zCOvU9yFJq0FNC_edCMRM78P8eQQ";
    let request_jkt = "Vx6mH6nGWV2DnuqEbuGX4Xw_Dc0p0AQxnKpEG7o5YS8";
    fixture
        .insert_client(
            &client_id,
            vec!["https://client.example/callback"],
            vec!["authorization_code"],
            true,
            true,
        )
        .await;
    let request_uri = format!("urn:ietf:params:oauth:request_uri:{}", Uuid::now_v7());
    fixture
        .store_pushed_request_with_bindings(
            &request_uri,
            &client_id,
            query(&[
                ("client_id", client_id.as_str()),
                ("redirect_uri", "https://client.example/callback"),
                ("response_type", "code"),
            ]),
            Some(pushed_jkt),
            None,
        )
        .await;
    let uri = format!(
        "/authorize?client_id={}&request_uri={}&redirect_uri=https%3A%2F%2Fclient.example%2Fcallback&response_type=code&dpop_jkt={}",
        urlencoding::encode(&client_id),
        urlencoding::encode(&request_uri),
        request_jkt
    );
    let req = actix_web::test::TestRequest::get()
        .uri(&uri)
        .to_http_request();
    let mut q = query(&[
        ("client_id", client_id.as_str()),
        ("request_uri", request_uri.as_str()),
        ("redirect_uri", "https://client.example/callback"),
        ("response_type", "code"),
        ("dpop_jkt", request_jkt),
    ]);

    let response = authorize_request(fixture.state.clone(), req, &mut q).await;
    assert_authorization_invalid_request(response).await;
}

#[actix_web::test]
async fn authorization_request_redirects_prompt_max_age_and_claims_parse_errors() {
    let Some(fixture) = LiveAuthorizationFixture::new().await else {
        return;
    };
    let client_id = format!("authorize-parse-errors-{}", Uuid::now_v7());
    fixture
        .insert_client(
            &client_id,
            vec!["https://client.example/callback"],
            vec!["authorization_code"],
            true,
            true,
        )
        .await;

    for (name, extra) in [
        ("bad-prompt", ("prompt", "none login")),
        ("bad-max-age", ("max_age", "-1")),
        ("bad-claims", ("claims", r#"{"userinfo":[]}"#)),
    ] {
        let uri = format!(
            "/authorize?client_id={}&redirect_uri=https%3A%2F%2Fclient.example%2Fcallback&response_type=code&state={}&{}={}",
            urlencoding::encode(&client_id),
            name,
            extra.0,
            urlencoding::encode(extra.1)
        );
        let req = actix_web::test::TestRequest::get()
            .uri(&uri)
            .to_http_request();
        let mut q = query(&[
            ("client_id", client_id.as_str()),
            ("redirect_uri", "https://client.example/callback"),
            ("response_type", "code"),
            ("state", name),
            extra,
        ]);

        let response = authorize_request(fixture.state.clone(), req, &mut q).await;

        assert_authorization_error_redirect(response, "invalid_request", Some(name));
    }
}

#[actix_web::test]
async fn authorization_request_redirects_core_protocol_validation_errors_after_redirect_resolution()
{
    let Some(fixture) = LiveAuthorizationFixture::new().await else {
        return;
    };
    let client_id = format!("authorize-core-validation-{}", Uuid::now_v7());
    fixture
        .insert_client(
            &client_id,
            vec!["https://client.example/callback"],
            vec!["authorization_code"],
            false,
            true,
        )
        .await;

    let long_nonce = "n".repeat(513);
    for (name, mut params) in [
        (
            "bad-nonce",
            query(&[
                ("client_id", client_id.as_str()),
                ("redirect_uri", "https://client.example/callback"),
                ("response_type", "code"),
                ("nonce", long_nonce.as_str()),
                ("state", "bad-nonce"),
            ]),
        ),
        (
            "bad-response-type",
            query(&[
                ("client_id", client_id.as_str()),
                ("redirect_uri", "https://client.example/callback"),
                ("response_type", "token"),
                ("state", "bad-response-type"),
            ]),
        ),
        (
            "bad-response-mode",
            query(&[
                ("client_id", client_id.as_str()),
                ("redirect_uri", "https://client.example/callback"),
                ("response_type", "code"),
                ("response_mode", "fragment"),
                ("state", "bad-response-mode"),
            ]),
        ),
        (
            "bad-pkce",
            query(&[
                ("client_id", client_id.as_str()),
                ("redirect_uri", "https://client.example/callback"),
                ("response_type", "code"),
                ("code_challenge", "too-short"),
                ("code_challenge_method", "plain"),
                ("state", "bad-pkce"),
            ]),
        ),
    ] {
        let uri = format!(
            "/authorize?client_id={}&redirect_uri=https%3A%2F%2Fclient.example%2Fcallback&state={}",
            urlencoding::encode(&client_id),
            name
        );
        let req = actix_web::test::TestRequest::get()
            .uri(&uri)
            .to_http_request();

        let response = authorize_request(fixture.state.clone(), req, &mut params).await;

        let expected_error = if name == "bad-response-type" {
            "unsupported_response_type"
        } else {
            "invalid_request"
        };
        assert_authorization_error_redirect(response, expected_error, Some(name));
    }
}

#[actix_web::test]
async fn authorization_request_redirects_request_object_claim_errors_after_redirect_resolution() {
    let Some(fixture) = LiveAuthorizationFixture::new().await else {
        return;
    };
    let client_id = format!("authorize-jar-redirect-{}", Uuid::now_v7());
    fixture
        .insert_client(
            &client_id,
            vec!["https://client.example/callback"],
            vec!["authorization_code"],
            true,
            true,
        )
        .await;
    let request_object = unsigned_request_object(json!({
        "client_id": client_id,
        "iss": "attacker-client",
        "aud": "https://issuer.example",
        "response_type": "code",
        "redirect_uri": "https://client.example/callback",
        "state": "jar-state"
    }));
    let uri = format!(
        "/authorize?client_id={}&redirect_uri=https%3A%2F%2Fclient.example%2Fcallback&response_type=code&state=jar-state&request={}",
        urlencoding::encode(&client_id),
        urlencoding::encode(&request_object)
    );
    let req = actix_web::test::TestRequest::get()
        .uri(&uri)
        .to_http_request();
    let mut q = query(&[
        ("client_id", client_id.as_str()),
        ("redirect_uri", "https://client.example/callback"),
        ("response_type", "code"),
        ("state", "jar-state"),
        ("request", request_object.as_str()),
    ]);

    let response = authorize_request(fixture.state.clone(), req, &mut q).await;

    assert_authorization_error_redirect(response, "invalid_request_object", Some("jar-state"));
}

#[actix_web::test]
async fn authorization_request_redirects_prompt_none_without_session() {
    let Some(fixture) = LiveAuthorizationFixture::new().await else {
        return;
    };
    let client_id = format!("authorize-prompt-none-{}", Uuid::now_v7());
    fixture
        .insert_client(
            &client_id,
            vec!["https://client.example/callback"],
            vec!["authorization_code"],
            true,
            true,
        )
        .await;
    let uri = format!(
        "/authorize?client_id={}&redirect_uri=https%3A%2F%2Fclient.example%2Fcallback&response_type=code&prompt=none&state=login-required",
        urlencoding::encode(&client_id)
    );
    let req = actix_web::test::TestRequest::get()
        .uri(&uri)
        .to_http_request();
    let mut q = query(&[
        ("client_id", client_id.as_str()),
        ("redirect_uri", "https://client.example/callback"),
        ("response_type", "code"),
        ("prompt", "none"),
        ("state", "login-required"),
    ]);

    let response = authorize_request(fixture.state.clone(), req, &mut q).await;

    assert_authorization_error_redirect(response, "login_required", Some("login-required"));
}

#[actix_web::test]
async fn authorization_request_redirects_to_login_with_original_request_uri_after_par_expansion() {
    let Some(fixture) = LiveAuthorizationFixture::new().await else {
        return;
    };
    let client_id = format!("authorize-par-login-{}", Uuid::now_v7());
    fixture
        .insert_client(
            &client_id,
            vec!["https://client.example/callback"],
            vec!["authorization_code"],
            true,
            true,
        )
        .await;
    let request_uri = format!("urn:ietf:params:oauth:request_uri:{}", Uuid::now_v7());
    fixture
        .store_pushed_request(
            &request_uri,
            &client_id,
            query(&[
                ("client_id", client_id.as_str()),
                ("redirect_uri", "https://client.example/callback"),
                ("response_type", "code"),
                ("scope", "openid"),
                ("state", "par-login"),
            ]),
        )
        .await;
    let uri = format!(
        "/authorize?client_id={}&request_uri={}",
        urlencoding::encode(&client_id),
        urlencoding::encode(&request_uri)
    );
    let req = actix_web::test::TestRequest::get()
        .uri(&uri)
        .to_http_request();
    let mut q = query(&[
        ("client_id", client_id.as_str()),
        ("request_uri", request_uri.as_str()),
    ]);

    let response = authorize_request(fixture.state.clone(), req, &mut q).await;
    let location = authorization_location(&response);

    assert_eq!(
        location.origin().ascii_serialization(),
        "https://app.example"
    );
    assert_eq!(location.path(), "/auth");
    let next = location
        .query_pairs()
        .find_map(|(key, value)| (key == "next").then_some(value.into_owned()))
        .expect("login redirect should include next parameter");
    let next = urlencoding::decode(&next).expect("next parameter should decode");
    assert!(next.contains("request_uri="));
    assert!(!next.contains("redirect_uri="));
}

#[actix_web::test]
async fn authorization_request_fails_closed_when_reauth_nonce_storage_is_unavailable() {
    let Some(fixture) = LiveAuthorizationFixture::new().await else {
        return;
    };
    let client_id = format!("authorize-reauth-nonce-fail-{}", Uuid::now_v7());
    fixture
        .insert_client(
            &client_id,
            vec!["https://client.example/callback"],
            vec!["authorization_code"],
            true,
            true,
        )
        .await;

    let mut broken_state = endpoint_state(false);
    broken_state.diesel_db = fixture.state.diesel_db.clone();
    let broken_state = Data::new(broken_state);
    let uri = format!(
        "/authorize?client_id={}&redirect_uri=https%3A%2F%2Fclient.example%2Fcallback&response_type=code&prompt=login&state=reauth-nonce-fail",
        urlencoding::encode(&client_id)
    );
    let req = actix_web::test::TestRequest::get()
        .uri(&uri)
        .to_http_request();
    let mut q = query(&[
        ("client_id", client_id.as_str()),
        ("redirect_uri", "https://client.example/callback"),
        ("response_type", "code"),
        ("prompt", "login"),
        ("state", "reauth-nonce-fail"),
    ]);

    let response = authorize_request(broken_state, req, &mut q).await;
    assert!(response.headers().get(header::LOCATION).is_none());
    let (status, body) = json_body(response).await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"], "server_error");
    assert!(body.get("code").is_none());
}

#[actix_web::test]
async fn authorization_request_reports_session_lookup_failure_after_client_validation() {
    let Some(fixture) = LiveAuthorizationFixture::new().await else {
        return;
    };
    let client_id = format!("authorize-session-fail-{}", Uuid::now_v7());
    fixture
        .insert_client(
            &client_id,
            vec!["https://client.example/callback"],
            vec!["authorization_code"],
            true,
            true,
        )
        .await;

    let mut broken_state = endpoint_state(false);
    broken_state.diesel_db = fixture.state.diesel_db.clone();
    let broken_state = Data::new(broken_state);
    let req = actix_web::test::TestRequest::get()
        .uri("/authorize")
        .cookie(Cookie::new(
            broken_state.settings.session.session_cookie_name.clone(),
            "broken-session",
        ))
        .to_http_request();
    let mut q = query(&[
        ("client_id", client_id.as_str()),
        ("redirect_uri", "https://client.example/callback"),
        ("response_type", "code"),
    ]);

    let response = authorize_request(broken_state, req, &mut q).await;
    assert!(response.headers().get(header::LOCATION).is_none());
    let (status, body) = json_body(response).await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"], "server_error");
}

#[actix_web::test]
async fn authorization_request_requires_reauthentication_for_prompt_none_sessions() {
    let Some(fixture) = LiveAuthorizationFixture::new().await else {
        return;
    };
    let suffix = Uuid::now_v7().simple().to_string();
    let client_id = format!("authorize-reauth-{suffix}");
    fixture
        .insert_client(
            &client_id,
            vec!["https://client.example/callback"],
            vec!["authorization_code"],
            true,
            true,
        )
        .await;
    let user = fixture.create_user(&suffix, "user", 0).await;
    let sid = format!("sid-{suffix}");
    fixture
        .store_session(&user, &sid, Utc::now().timestamp() - 600)
        .await;
    let uri = format!(
        "/authorize?client_id={}&redirect_uri=https%3A%2F%2Fclient.example%2Fcallback&response_type=code&prompt=none&max_age=0&state=reauth",
        urlencoding::encode(&client_id)
    );
    let req = fixture.session_request(&sid, &uri);
    let mut q = query(&[
        ("client_id", client_id.as_str()),
        ("redirect_uri", "https://client.example/callback"),
        ("response_type", "code"),
        ("prompt", "none"),
        ("max_age", "0"),
        ("state", "reauth"),
    ]);

    let response = authorize_request(fixture.state.clone(), req, &mut q).await;

    assert_authorization_error_redirect(response, "login_required", Some("reauth"));
}

#[actix_web::test]
async fn authorization_request_redirects_invalid_scope_for_authenticated_session() {
    let Some(fixture) = LiveAuthorizationFixture::new().await else {
        return;
    };
    let suffix = Uuid::now_v7().simple().to_string();
    let client_id = format!("authorize-scope-{suffix}");
    fixture
        .insert_client(
            &client_id,
            vec!["https://client.example/callback"],
            vec!["authorization_code"],
            true,
            true,
        )
        .await;
    let user = fixture.create_user(&suffix, "user", 0).await;
    let sid = format!("sid-{suffix}");
    fixture
        .store_session(&user, &sid, Utc::now().timestamp())
        .await;
    let uri = format!(
        "/authorize?client_id={}&redirect_uri=https%3A%2F%2Fclient.example%2Fcallback&response_type=code&scope=openid%20email&state=invalid-scope",
        urlencoding::encode(&client_id)
    );
    let req = fixture.session_request(&sid, &uri);
    let mut q = query(&[
        ("client_id", client_id.as_str()),
        ("redirect_uri", "https://client.example/callback"),
        ("response_type", "code"),
        ("scope", "openid email"),
        ("state", "invalid-scope"),
    ]);

    let response = authorize_request(fixture.state.clone(), req, &mut q).await;

    assert_authorization_error_redirect(response, "invalid_scope", Some("invalid-scope"));
}

#[actix_web::test]
async fn authorization_request_redirects_invalid_authorization_details_for_authenticated_session() {
    let Some(fixture) = LiveAuthorizationFixture::new().await else {
        return;
    };
    let suffix = Uuid::now_v7().simple().to_string();
    let client_id = format!("authorize-details-{suffix}");
    fixture
        .insert_client(
            &client_id,
            vec!["https://client.example/callback"],
            vec!["authorization_code"],
            true,
            true,
        )
        .await;
    let user = fixture.create_user(&suffix, "user", 0).await;
    let sid = format!("sid-{suffix}");
    fixture
        .store_session(&user, &sid, Utc::now().timestamp())
        .await;
    let uri = format!(
        "/authorize?client_id={}&redirect_uri=https%3A%2F%2Fclient.example%2Fcallback&response_type=code&authorization_details=not-json&state=bad-details",
        urlencoding::encode(&client_id)
    );
    let req = fixture.session_request(&sid, &uri);
    let mut q = query(&[
        ("client_id", client_id.as_str()),
        ("redirect_uri", "https://client.example/callback"),
        ("response_type", "code"),
        ("authorization_details", "not-json"),
        ("state", "bad-details"),
    ]);

    let response = authorize_request(fixture.state.clone(), req, &mut q).await;

    assert_authorization_error_redirect(response, "invalid_request", Some("bad-details"));
}

#[actix_web::test]
async fn authorization_request_prompt_none_without_prior_grant_returns_consent_required() {
    let Some(fixture) = LiveAuthorizationFixture::new().await else {
        return;
    };
    let suffix = Uuid::now_v7().simple().to_string();
    let client_id = format!("authorize-consent-{suffix}");
    fixture
        .insert_client(
            &client_id,
            vec!["https://client.example/callback"],
            vec!["authorization_code", "refresh_token"],
            true,
            true,
        )
        .await;
    let user = fixture.create_user(&suffix, "user", 0).await;
    let sid = format!("sid-{suffix}");
    fixture
        .store_session(&user, &sid, Utc::now().timestamp())
        .await;
    let uri = format!(
        "/authorize?client_id={}&redirect_uri=https%3A%2F%2Fclient.example%2Fcallback&response_type=code&prompt=none&scope=openid&state=consent-required",
        urlencoding::encode(&client_id)
    );
    let req = fixture.session_request(&sid, &uri);
    let mut q = query(&[
        ("client_id", client_id.as_str()),
        ("redirect_uri", "https://client.example/callback"),
        ("response_type", "code"),
        ("prompt", "none"),
        ("scope", "openid"),
        ("state", "consent-required"),
    ]);

    let response = authorize_request(fixture.state.clone(), req, &mut q).await;

    assert_authorization_error_redirect(response, "consent_required", Some("consent-required"));
}

#[actix_web::test]
async fn authorization_request_persists_consent_payload_for_authenticated_interaction() {
    let Some(fixture) = LiveAuthorizationFixture::new().await else {
        return;
    };
    let suffix = Uuid::now_v7().simple().to_string();
    let client_id = format!("authorize-interactive-{suffix}");
    fixture
        .insert_client(
            &client_id,
            vec!["https://client.example/callback"],
            vec!["authorization_code"],
            true,
            true,
        )
        .await;
    let user = fixture.create_user(&suffix, "user", 0).await;
    let sid = format!("sid-{suffix}");
    fixture
        .store_session(&user, &sid, Utc::now().timestamp())
        .await;
    let uri = format!(
        "/authorize?client_id={}&redirect_uri=https%3A%2F%2Fclient.example%2Fcallback&response_type=code&scope=openid&state=interactive",
        urlencoding::encode(&client_id)
    );
    let req = fixture.session_request(&sid, &uri);
    let mut q = query(&[
        ("client_id", client_id.as_str()),
        ("redirect_uri", "https://client.example/callback"),
        ("response_type", "code"),
        ("scope", "openid"),
        ("state", "interactive"),
    ]);

    let response = authorize_request(fixture.state.clone(), req, &mut q).await;
    let location = authorization_location(&response);

    assert_eq!(
        location.origin().ascii_serialization(),
        "https://app.example"
    );
    assert_eq!(location.path(), "/consent");
    let request_id = location
        .query_pairs()
        .find_map(|(key, value)| (key == "request_id").then_some(value.into_owned()))
        .expect("interactive authorization should persist a consent request");
    let payload = fixture.stored_consent_payload(&request_id).await;
    assert_eq!(payload.user_id, user.id);
    assert_eq!(payload.client_id, client_id);
    assert_eq!(payload.redirect_uri, "https://client.example/callback");
    assert_eq!(payload.state.as_deref(), Some("interactive"));
    assert_eq!(payload.scopes, vec!["openid"]);
}

#[actix_web::test]
async fn consume_pushed_authorization_request_enforces_single_use_and_malformed_states() {
    let Some(fixture) = LiveAuthorizationFixture::new().await else {
        return;
    };
    let request_uri = format!("urn:ietf:params:oauth:request_uri:{}", Uuid::now_v7());
    fixture
        .store_pushed_request(
            &request_uri,
            "client-a",
            query(&[
                ("client_id", "client-a"),
                ("redirect_uri", "https://client.example/callback"),
                ("response_type", "code"),
            ]),
        )
        .await;

    assert_eq!(
        consume_pushed_authorization_request(&fixture.state, &request_uri).await,
        Ok(())
    );
    assert_eq!(
        consume_pushed_authorization_request(&fixture.state, &request_uri).await,
        Err(PushedAuthorizationRequestConsumeError::Missing)
    );

    let malformed_request_uri = format!("urn:ietf:params:oauth:request_uri:{}", Uuid::now_v7());
    fixture
        .store_raw_pushed_request(&malformed_request_uri, "{not-json")
        .await;
    assert_eq!(
        consume_pushed_authorization_request(&fixture.state, &malformed_request_uri).await,
        Err(PushedAuthorizationRequestConsumeError::Malformed)
    );

    let broken_state = endpoint_state(false);
    assert_eq!(
        consume_pushed_authorization_request(
            &broken_state,
            "urn:ietf:params:oauth:request_uri:missing"
        )
        .await,
        Err(PushedAuthorizationRequestConsumeError::ReadFailed)
    );
}

#[actix_web::test]
async fn concurrent_pushed_authorization_request_consumption_allows_exactly_one_winner() {
    let Some(fixture) = LiveAuthorizationFixture::new().await else {
        return;
    };
    let request_uri = format!("urn:ietf:params:oauth:request_uri:{}", Uuid::now_v7());
    fixture
        .store_pushed_request(
            &request_uri,
            "client-a",
            query(&[
                ("client_id", "client-a"),
                ("redirect_uri", "https://client.example/callback"),
                ("response_type", "code"),
            ]),
        )
        .await;

    let (first, second) = tokio::join!(
        consume_pushed_authorization_request(&fixture.state, &request_uri),
        consume_pushed_authorization_request(&fixture.state, &request_uri)
    );
    let results = [first, second];

    assert_eq!(
        results.iter().filter(|result| **result == Ok(())).count(),
        1
    );
    assert_eq!(
        results
            .iter()
            .filter(|result| **result == Err(PushedAuthorizationRequestConsumeError::Missing))
            .count(),
        1
    );
}

#[actix_web::test]
async fn authorization_response_redirect_emits_signed_jarm_response() {
    let mut state = endpoint_state(false);
    state.keyset = rs256_test_key_manager();
    let state = Data::new(state);

    let response = authorization_response_redirect_with_protection(
        &state,
        AuthorizationResponseRedirect {
            redirect_uri: "https://client.example/callback?existing=1",
            client_id: "client-jarm",
            response_mode: Some("jwt"),
            code: Some("code-123"),
            error: None,
            state: Some("state-123"),
            oidc_sid: None,
        },
        AuthorizationResponseProtection::default(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::FOUND);
    let location = authorization_location(&response);
    let pairs = location.query_pairs().collect::<HashMap<_, _>>();
    assert_eq!(pairs.get("existing").map(|value| value.as_ref()), Some("1"));
    assert!(pairs.contains_key("response"));
    assert!(!pairs.contains_key("code"));
    assert!(!pairs.contains_key("state"));
    assert!(!pairs.contains_key("iss"));

    let claims = decode_jarm_claims(
        &state,
        pairs
            .get("response")
            .expect("JARM response parameter should be present"),
        "client-jarm",
    );
    assert_eq!(claims["iss"], "https://issuer.example");
    assert_eq!(claims["aud"], "client-jarm");
    assert_eq!(claims["code"], "code-123");
    assert_eq!(claims["state"], "state-123");
}

#[actix_web::test]
async fn authorization_response_redirect_jarm_profile_signs_without_response_mode() {
    let mut state = endpoint_state(false);
    let mut settings = state.settings.as_ref().clone();
    settings.protocol.authorization_server_profile =
        AuthorizationServerProfile::Fapi2MessageSigningJarm;
    state.settings = Arc::new(settings);
    state.keyset = rs256_test_key_manager();
    let state = Data::new(state);

    let response = authorization_response_redirect_with_protection(
        &state,
        AuthorizationResponseRedirect {
            redirect_uri: "https://client.example/callback",
            client_id: "client-jarm-profile",
            response_mode: None,
            code: Some("code-456"),
            error: None,
            state: Some("state-456"),
            oidc_sid: None,
        },
        AuthorizationResponseProtection::default(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::FOUND);
    let location = authorization_location(&response);
    let pairs = location.query_pairs().collect::<HashMap<_, _>>();
    assert!(pairs.contains_key("response"));
    assert!(!pairs.contains_key("code"));
    assert!(!pairs.contains_key("state"));
    assert!(!pairs.contains_key("iss"));

    let claims = decode_jarm_claims(
        &state,
        pairs
            .get("response")
            .expect("JARM response parameter should be present"),
        "client-jarm-profile",
    );
    assert_eq!(claims["iss"], "https://issuer.example");
    assert_eq!(claims["aud"], "client-jarm-profile");
    assert_eq!(claims["code"], "code-456");
    assert_eq!(claims["state"], "state-456");
}

#[actix_web::test]
async fn authorization_response_redirect_signs_then_encrypts_jarm_for_client_policy() {
    let mut state = endpoint_state(false);
    state.keyset = rs256_test_key_manager();
    let state = Data::new(state);
    let (private_key, public_jwk) = rsa_jarm_jwe_keypair("jarm-enc");
    let (wrong_private_key, _) = rsa_jarm_jwe_keypair("wrong-jarm-enc");
    let jwks = json!({"keys": [public_jwk]});

    let response = authorization_response_redirect_with_protection(
        &state,
        AuthorizationResponseRedirect {
            redirect_uri: "https://client.example/callback?existing=1",
            client_id: "client-encrypted-jarm",
            response_mode: Some("jwt"),
            code: Some("encrypted-code"),
            error: None,
            state: Some("encrypted-state"),
            oidc_sid: None,
        },
        AuthorizationResponseProtection {
            signing_alg: Some("RS256"),
            encryption_alg: Some("RSA-OAEP-256"),
            encryption_enc: Some("A256GCM"),
            jwks: Some(&jwks),
        },
    )
    .await;

    assert_eq!(response.status(), StatusCode::FOUND);
    let location = authorization_location(&response);
    let pairs = location.query_pairs().collect::<HashMap<_, _>>();
    assert_eq!(pairs.get("existing").map(|value| value.as_ref()), Some("1"));
    assert!(!pairs.contains_key("code"));
    assert!(!pairs.contains_key("state"));
    let encrypted = pairs
        .get("response")
        .expect("encrypted JARM response parameter should be present");
    assert!(
        decrypt_jarm_jwe(&wrong_private_key, encrypted).is_err(),
        "an unrelated private key must not decrypt JARM"
    );
    let (protected, nested_jwt) =
        decrypt_jarm_jwe(&private_key, encrypted).expect("matching key should decrypt JARM");
    assert_eq!(protected["alg"], "RSA-OAEP-256");
    assert_eq!(protected["enc"], "A256GCM");
    assert_eq!(protected["kid"], "jarm-enc");
    assert_eq!(protected["cty"], "JWT");
    let claims = decode_jarm_claims(&state, &nested_jwt, "client-encrypted-jarm");
    assert_eq!(claims["code"], "encrypted-code");
    assert_eq!(claims["state"], "encrypted-state");
}

#[actix_web::test]
async fn authorization_response_crypto_failure_never_falls_back_to_plain_query() {
    let mut state = endpoint_state(false);
    state.keyset = rs256_test_key_manager();
    let state = Data::new(state);
    for protection in [
        AuthorizationResponseProtection {
            signing_alg: Some("none"),
            ..AuthorizationResponseProtection::default()
        },
        AuthorizationResponseProtection {
            encryption_alg: Some("RSA-OAEP-256"),
            encryption_enc: Some("A256GCM"),
            jwks: None,
            ..AuthorizationResponseProtection::default()
        },
    ] {
        let response = authorization_response_redirect_with_protection(
            &state,
            AuthorizationResponseRedirect {
                redirect_uri: "https://client.example/callback",
                client_id: "client-failed-jarm",
                response_mode: Some("jwt"),
                code: Some("must-not-leak"),
                error: None,
                state: Some("must-not-leak-state"),
                oidc_sid: None,
            },
            protection,
        )
        .await;

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(
            response.headers().get(header::LOCATION).is_none(),
            "crypto failure must not emit any redirect containing code or state"
        );
    }
}
