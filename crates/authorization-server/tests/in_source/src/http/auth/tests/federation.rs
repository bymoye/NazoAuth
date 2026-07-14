use super::*;
use std::{sync::Arc, time::Duration};

use crate::adapters::security::pkce_s256;
use crate::config::ConfigSource;
use crate::domain::tenancy::DEFAULT_ORGANIZATION_ID;
use crate::domain::tenancy::DEFAULT_REALM_ID;
use crate::domain::tenancy::DEFAULT_TENANT_ID;
use crate::domain::{DatabaseExternalIdentityFixture, DatabaseUserFixture, TestAppState};
use crate::http::sessions::SessionPayload;
use crate::schema::external_identity_links;
use crate::settings::Settings;
use crate::test_support::valkey::valkey_get;
use crate::test_support::valkey::valkey_set_ex;
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use nazo_postgres::create_pool;
use nazo_postgres::get_conn;

use crate::adapters::security::random_urlsafe_token;
use crate::settings::{OidcFederationSettings, SamlGatewaySettings};
use crate::test_support::ClientSigningFixture;
use crate::test_support::client_signing_fixture;
use actix_web::http::header;
use diesel::sql_query;
use diesel::sql_types::{Bool, Text, Uuid as SqlUuid};
use fred::{
    interfaces::ClientLike,
    prelude::{
        Builder as ValkeyBuilder, Config as ValkeyConfig, ConnectionConfig, PerformanceConfig,
    },
};
use jsonwebtoken::{Algorithm, Header};
use nazo_http_actix::OAuthJsonErrorFields;
use nazo_identity::OidcFederationState;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use uuid::Uuid;

#[test]
fn federation_transport_has_no_identity_or_storage_orchestration() {
    let source = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/http/auth/federation.rs"
    ));
    for forbidden in [
        "TestAppState",
        "nazo_postgres",
        "nazo_valkey",
        "FederationRepository",
        "UserRepository",
        "AuthenticationStore",
        "store_session(",
        "hash_password(",
    ] {
        assert!(
            !source.contains(forbidden),
            "federation transport must not depend on {forbidden}"
        );
    }
    assert!(
        source.contains("redirect(reqwest::redirect::Policy::none())"),
        "federation HTTP clients must reject provider-controlled redirects"
    );
}

#[actix_web::test]
async fn federation_provider_response_limit_rejects_oversized_content_length() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("test server should bind");
    let addr = listener.local_addr().expect("test server address");
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("test request should arrive");
        let mut request = [0_u8; 1024];
        let _ = stream
            .read(&mut request)
            .await
            .expect("request should read");
        stream
            .write_all(
                format!(
                    "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                    MAX_FEDERATION_PROVIDER_RESPONSE_BYTES + 1
                )
                .as_bytes(),
            )
            .await
            .expect("response headers should write");
    });
    let response = federation_http_client()
        .expect("federation HTTP client should build")
        .get(format!("http://{addr}"))
        .send()
        .await
        .expect("response headers should be accepted");

    let error = federation_response_bytes(response)
        .await
        .expect_err("oversized provider response must be rejected before buffering");
    server.await.expect("test server should finish");
    assert!(error.to_string().contains("too large"));
}

fn normalize_federation_token(value: &str) -> Option<String> {
    nazo_identity::federation::normalize_federation_token(value)
}

async fn federation_provider_list(state: Data<TestAppState>) -> HttpResponse {
    super::federation_provider_list(crate::test_support::federation_http_config(&state)).await
}

async fn federation_provider_start(
    state: Data<TestAppState>,
    req: HttpRequest,
    path: Path<String>,
) -> HttpResponse {
    super::federation_provider_start(
        crate::test_support::auth_request_limiter(&state),
        crate::test_support::federation_service(&state),
        crate::test_support::federation_http_config(&state),
        req,
        path,
    )
    .await
}

async fn federation_provider_callback(
    state: Data<TestAppState>,
    req: HttpRequest,
    path: Path<String>,
    query: Query<OidcCallbackQuery>,
) -> HttpResponse {
    super::federation_provider_callback(
        crate::test_support::auth_request_limiter(&state),
        crate::test_support::client_ip_config(&state),
        crate::test_support::federation_service(&state),
        crate::test_support::federation_http_config(&state),
        req,
        path,
        query,
    )
    .await
}

async fn oidc_callback_after_rate_limit_for_provider(
    state: Data<TestAppState>,
    req: HttpRequest,
    query: OidcCallbackQuery,
    provider: OidcFederationSettings,
) -> HttpResponse {
    super::oidc_callback_after_rate_limit_for_provider(
        crate::test_support::federation_service(&state),
        crate::test_support::federation_http_config(&state),
        crate::test_support::client_ip_config(&state),
        req,
        query,
        provider,
    )
    .await
}

async fn federation_saml_acs(
    state: Data<TestAppState>,
    req: HttpRequest,
    payload: Json<SamlGatewayAssertion>,
) -> HttpResponse {
    super::federation_saml_acs(
        crate::test_support::auth_request_limiter(&state),
        crate::test_support::client_ip_config(&state),
        crate::test_support::federation_service(&state),
        crate::test_support::federation_http_config(&state),
        req,
        payload,
    )
    .await
}

async fn complete_social_callback(
    state: Data<TestAppState>,
    req: HttpRequest,
    provider_id: String,
    identity: SocialIdentity,
) -> HttpResponse {
    let client_ip = crate::test_support::client_ip_config(&state);
    let service = crate::test_support::federation_service(&state);
    let config = crate::test_support::federation_http_config(&state);
    super::complete_federation(
        service.get_ref(),
        config.get_ref(),
        VerifiedExternalIdentity {
            provider_type: "oauth2_social".to_owned(),
            provider_id,
            subject: identity.subject,
            email: identity.email,
            display_name: identity.display_name,
            claims: identity.claims,
        },
        "oauth2_social",
        client_ip_with_config(&req, client_ip.get_ref()),
        true,
    )
    .await
}

// 测试使用非默认 provider id，避免把动态 provider 路由误写成固定 OIDC 入口。
const TEST_OIDC_PROVIDER_ID: &str = "test-oidc";

fn oidc_provider() -> OidcFederationSettings {
    OidcFederationSettings {
        provider_id: TEST_OIDC_PROVIDER_ID.to_owned(),
        issuer: "https://issuer.example".to_owned(),
        authorization_endpoint: "https://issuer.example/authorize".to_owned(),
        token_endpoint: "https://issuer.example/token".to_owned(),
        jwks_url: "https://issuer.example/jwks".to_owned(),
        client_id: "client-1".to_owned(),
        client_secret: "secret".to_owned(),
        redirect_uri: "https://auth.example/federation/test-oidc/callback".to_owned(),
        scopes: "openid email".to_owned(),
    }
}

fn oidc_provider_registry_config(provider: &OidcFederationSettings) -> ConfigSource {
    // 测试与生产启动保持同一事实源：OIDC provider 也必须来自 provider registry。
    ConfigSource::from_owned_pairs_for_test([(
        "FEDERATION_PROVIDER_CONFIGS".to_owned(),
        json!([{
            "provider_id": provider.provider_id.as_str(),
            "enabled": true,
            "display_name": "OIDC",
            "adapter_type": "oidc",
            "issuer": provider.issuer.as_str(),
            "authorization_endpoint": provider.authorization_endpoint.as_str(),
            "token_endpoint": provider.token_endpoint.as_str(),
            "jwks_url": provider.jwks_url.as_str(),
            "client_id": provider.client_id.as_str(),
            "client_secret": provider.client_secret.as_str(),
            "redirect_uri": provider.redirect_uri.as_str(),
            "scopes": provider.scopes.as_str(),
        }])
        .to_string(),
    )])
}

fn settings_with_oidc_provider(provider: Option<&OidcFederationSettings>) -> Settings {
    // None 表示没有任何外部登录 provider；Some 表示通过 registry 注册一个 OIDC provider。
    let config = match provider {
        Some(provider) => oidc_provider_registry_config(provider),
        None => ConfigSource::default(),
    };
    Settings::from_config(&config).expect("federation settings should load")
}

fn oidc_callback_state() -> TestAppState {
    let provider = oidc_provider();
    let settings = settings_with_oidc_provider(Some(&provider));
    let mut valkey_builder = fred::prelude::Builder::default_centralized();
    valkey_builder.with_performance_config(|performance| {
        performance.default_command_timeout = Duration::from_millis(50);
    });
    valkey_builder.with_connection_config(|connection| {
        connection.connection_timeout = Duration::from_millis(50);
        connection.internal_command_timeout = Duration::from_millis(50);
    });

    TestAppState {
        diesel_db: create_pool(
            "postgres://nazo_federation_test_invalid:nazo_federation_test_invalid@127.0.0.1:1/nazo"
                .to_owned(),
            1,
        )
        .expect("pool construction should not connect"),
        valkey: valkey_builder
            .build()
            .expect("valkey client construction should not connect"),
        settings: Arc::new(settings),
        keyset: crate::test_support::test_key_manager(),
    }
}

fn provider_list_state() -> TestAppState {
    let config = ConfigSource::from_pairs_for_test([(
        "FEDERATION_PROVIDER_CONFIGS",
        r#"[
            {
                "provider_id": "google",
                "enabled": true,
                "display_name": "Google",
                "adapter_type": "oidc",
                "issuer": "https://accounts.google.com",
                "authorization_endpoint": "https://accounts.google.com/o/oauth2/v2/auth",
                "token_endpoint": "https://oauth2.googleapis.com/token",
                "jwks_url": "https://www.googleapis.com/oauth2/v3/certs",
                "client_id": "google-client",
                "client_secret": "google-secret",
                "redirect_uri": "https://auth.example.test/auth/federation/google/callback",
                "scopes": "openid email profile"
            },
            {
                "provider_id": "disabled",
                "enabled": false,
                "display_name": "Disabled",
                "adapter_type": "oauth2_social",
                "provider_kind": "qq",
                "client_id": "disabled-client",
                "client_secret": "disabled-secret",
                "redirect_uri": "https://auth.example.test/auth/federation/disabled/callback"
            }
        ]"#,
    )]);
    let settings = Settings::from_config(&config).expect("provider registry settings should load");
    let mut valkey_builder = fred::prelude::Builder::default_centralized();
    valkey_builder.with_performance_config(|performance| {
        performance.default_command_timeout = Duration::from_millis(50);
    });

    TestAppState {
        diesel_db: create_pool(
            "postgres://nazo_federation_test_invalid:nazo_federation_test_invalid@127.0.0.1:1/nazo"
                .to_owned(),
            1,
        )
        .expect("pool construction should not connect"),
        valkey: valkey_builder
            .build()
            .expect("valkey client construction should not connect"),
        settings: Arc::new(settings),
        keyset: crate::test_support::test_key_manager(),
    }
}

async fn live_federation_state(
    oidc: Option<OidcFederationSettings>,
    saml_gateway: Option<SamlGatewaySettings>,
) -> Option<TestAppState> {
    let valkey_url = std::env::var("VALKEY_URL").ok()?;
    let mut settings = settings_with_oidc_provider(oidc.as_ref());
    settings.identity.federation.saml_gateway = saml_gateway;
    settings.identity.rate_limit.auth_max_requests = 1_000;

    let valkey_config = ValkeyConfig::from_url(&valkey_url).ok()?;
    let mut valkey_builder = ValkeyBuilder::from_config(valkey_config);
    valkey_builder.with_performance_config(|performance: &mut PerformanceConfig| {
        performance.default_command_timeout = Duration::from_secs(2);
    });
    valkey_builder.with_connection_config(|connection: &mut ConnectionConfig| {
        connection.connection_timeout = Duration::from_secs(2);
        connection.internal_command_timeout = Duration::from_secs(2);
    });
    let valkey = valkey_builder.build().expect("valkey client should build");
    valkey.init().await.expect("valkey should connect");

    Some(TestAppState {
        diesel_db: create_pool(
            "postgres://nazo_federation_test_invalid:nazo_federation_test_invalid@127.0.0.1:1/nazo"
                .to_owned(),
            1,
        )
        .expect("pool construction should not connect"),
        valkey,
        settings: Arc::new(settings),
        keyset: crate::test_support::test_key_manager(),
    })
}

struct LiveFederationFixture {
    state: Data<TestAppState>,
}

impl LiveFederationFixture {
    async fn new(
        oidc: Option<OidcFederationSettings>,
        saml_gateway: Option<SamlGatewaySettings>,
    ) -> Option<Self> {
        let database_url = std::env::var("DATABASE_URL").ok()?;
        let valkey_url = std::env::var("VALKEY_URL").ok()?;
        let mut settings = settings_with_oidc_provider(oidc.as_ref());
        settings.identity.federation.saml_gateway = saml_gateway;
        settings.identity.rate_limit.auth_max_requests = 1_000;
        settings.session.session_cookie_name = "nazo_federation_session".to_owned();
        settings.session.csrf_cookie_name = "nazo_federation_csrf".to_owned();
        settings.session.cookie_secure = true;

        let mut valkey_builder = ValkeyBuilder::from_config(
            ValkeyConfig::from_url(&valkey_url).expect("VALKEY_URL should parse"),
        );
        valkey_builder.with_performance_config(|performance: &mut PerformanceConfig| {
            performance.default_command_timeout = Duration::from_secs(2);
        });
        valkey_builder.with_connection_config(|connection: &mut ConnectionConfig| {
            connection.connection_timeout = Duration::from_secs(2);
            connection.internal_command_timeout = Duration::from_secs(2);
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

    async fn create_user(&self, email: &str, is_active: bool) -> DatabaseUserFixture {
        let username = format!("federation-{}", Uuid::now_v7().simple());
        let mut conn = get_conn(&self.state.diesel_db)
            .await
            .expect("database connection");
        sql_query(
            r#"
            INSERT INTO users (
                tenant_id, realm_id, organization_id, username, email,
                password_hash, is_active, mfa_enabled, email_verified, role, admin_level
            )
            VALUES ($1, $2, $3, $4, $5, 'unused-federation-test-hash', $6, false, true, 'user', 0)
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

    async fn insert_external_identity_link(
        &self,
        user: &DatabaseUserFixture,
        provider_type: &str,
        provider_id: &str,
        subject: &str,
        email: &str,
    ) -> DatabaseExternalIdentityFixture {
        let mut conn = get_conn(&self.state.diesel_db)
            .await
            .expect("database connection");
        diesel::insert_into(external_identity_links::table)
            .values((
                external_identity_links::tenant_id.eq(user.tenant_id),
                external_identity_links::user_id.eq(user.id),
                external_identity_links::provider_type.eq(provider_type),
                external_identity_links::provider_id.eq(provider_id),
                external_identity_links::subject.eq(subject),
                external_identity_links::email.eq(email),
                external_identity_links::claims.eq(json!({"sub": subject})),
                external_identity_links::last_login_at.eq(Utc::now()),
            ))
            .returning(DatabaseExternalIdentityFixture::as_returning())
            .get_result::<DatabaseExternalIdentityFixture>(&mut conn)
            .await
            .expect("external identity link should insert")
    }

    async fn user_by_email(&self, email: &str) -> Option<PublicAccount> {
        nazo_postgres::UserRepository::new(self.state.diesel_db.clone())
            .public_account_by_email(
                nazo_identity::TenantId::new(DEFAULT_TENANT_ID).unwrap(),
                email,
            )
            .await
            .expect("user lookup should succeed")
    }

    async fn external_identity_link(
        &self,
        provider_type: &str,
        provider_id: &str,
        subject: &str,
    ) -> Option<DatabaseExternalIdentityFixture> {
        let mut conn = get_conn(&self.state.diesel_db)
            .await
            .expect("database connection");
        external_identity_links::table
            .filter(external_identity_links::tenant_id.eq(DEFAULT_TENANT_ID))
            .filter(external_identity_links::provider_type.eq(provider_type))
            .filter(external_identity_links::provider_id.eq(provider_id))
            .filter(external_identity_links::subject.eq(subject))
            .select(DatabaseExternalIdentityFixture::as_select())
            .first::<DatabaseExternalIdentityFixture>(&mut conn)
            .await
            .optional()
            .expect("external identity link lookup should succeed")
    }

    async fn session_payload(&self, sid: &str) -> SessionPayload {
        let raw = valkey_get(&self.state.valkey, format!("oauth:session:{sid}"))
            .await
            .expect("session lookup should succeed")
            .expect("session should be present");
        serde_json::from_str(&raw).expect("session payload should deserialize")
    }
}

fn oauth_error_code(response: &HttpResponse) -> Option<String> {
    response
        .extensions()
        .get::<OAuthJsonErrorFields>()
        .map(|fields| fields.error.clone())
}

fn cookie_value_from_response(response: &HttpResponse, name: &str) -> Option<String> {
    let prefix = format!("{name}=");
    response
        .headers()
        .get_all(header::SET_COOKIE)
        .filter_map(|value| value.to_str().ok())
        .find_map(|cookie| {
            cookie
                .strip_prefix(&prefix)
                .and_then(|value| value.split(';').next())
                .map(ToOwned::to_owned)
        })
}

async fn response_json(response: HttpResponse) -> (StatusCode, Value) {
    let status = response.status();
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("response body should be readable");
    let json = serde_json::from_slice(&body).expect("response should be json");
    (status, json)
}

async fn store_oidc_state(state: &TestAppState, state_token: &str, created_at: i64) {
    let nonce = random_urlsafe_token();
    store_oidc_state_with_nonce(state, state_token, &nonce, created_at).await;
}

async fn store_oidc_state_with_nonce(
    state: &TestAppState,
    state_token: &str,
    nonce: &str,
    created_at: i64,
) {
    let body = serde_json::to_string(&OidcFederationState {
        provider_id: None,
        nonce: nonce.to_owned(),
        pkce_verifier: "verifier-1".to_owned(),
        created_at,
    })
    .expect("test federation state should serialize");
    valkey_set_ex(
        &state.valkey,
        oidc_state_key(state_token),
        body,
        FEDERATION_STATE_TTL_SECONDS,
    )
    .await
    .expect("test OIDC state should be written");
}

async fn one_shot_json_server(body: Value) -> (String, tokio::task::JoinHandle<String>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("test server should bind");
    let addr = listener.local_addr().expect("test server address");
    let handle = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("test request should arrive");
        let mut buffer = vec![0_u8; 8192];
        let read = stream.read(&mut buffer).await.expect("request should read");
        let request = String::from_utf8_lossy(&buffer[..read]).to_string();
        let response_body = body.to_string();
        let response = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
            response_body.len(),
            response_body
        );
        stream
            .write_all(response.as_bytes())
            .await
            .expect("response should write");
        request
    });
    (format!("http://{addr}"), handle)
}

fn signed_oidc_token(
    provider: &OidcFederationSettings,
    kid: &str,
    fixture: &ClientSigningFixture,
    nonce: &str,
    overrides: Value,
) -> String {
    let now = Utc::now().timestamp();
    let mut claims = json!({
        "iss": provider.issuer,
        "sub": "subject-1",
        "aud": provider.client_id,
        "exp": now + 300,
        "iat": now,
        "nonce": nonce,
        "email": "user@example.com",
        "email_verified": true,
        "name": "User One"
    });
    let claims_object = claims
        .as_object_mut()
        .expect("test claims should be a JSON object");
    for (key, value) in overrides.as_object().into_iter().flatten() {
        if value.is_null() {
            claims_object.remove(key);
        } else {
            claims_object.insert(key.clone(), value.clone());
        }
    }
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(kid.to_owned());
    fixture.encode_jwt(&header, &claims)
}

async fn provider_backed_by_local_oidc(
    id_token_overrides: Value,
) -> (
    OidcFederationSettings,
    tokio::task::JoinHandle<String>,
    tokio::task::JoinHandle<String>,
    String,
) {
    let mut provider = oidc_provider();
    let nonce = random_urlsafe_token();
    let key = client_signing_fixture(Algorithm::RS256);
    let jwk = key.public_jwk("oidc-kid");
    let id_token = signed_oidc_token(&provider, "oidc-kid", &key, &nonce, id_token_overrides);
    let (token_endpoint, token_request) =
        one_shot_json_server(json!({ "id_token": id_token })).await;
    let (jwks_url, jwks_request) = one_shot_json_server(json!({ "keys": [jwk] })).await;
    provider.token_endpoint = token_endpoint;
    provider.jwks_url = jwks_url;
    (provider, token_request, jwks_request, nonce)
}

#[test]
fn federation_token_accepts_only_urlsafe_values() {
    assert!(normalize_federation_token("abcdefghijklmnopqrstuvwxyzABCDEF0123456789-_").is_some());
    assert!(normalize_federation_token("short").is_none());
    assert!(normalize_federation_token("abcdefghijklmnopqrstuvwxyzABCDEF0123456789+/").is_none());
}

#[test]
fn federation_token_trims_transport_whitespace_but_preserves_length_and_charset_limits() {
    let min = "A".repeat(32);
    let max = "b".repeat(256);

    assert_eq!(
        normalize_federation_token(&format!(" \t{min}\n")).as_deref(),
        Some(min.as_str())
    );
    assert_eq!(
        normalize_federation_token(&max).as_deref(),
        Some(max.as_str())
    );
    assert!(
        normalize_federation_token(&"c".repeat(31)).is_none(),
        "state tokens shorter than 256 bits of base64url-like entropy must fail closed"
    );
    assert!(
        normalize_federation_token(&"d".repeat(257)).is_none(),
        "oversized state tokens must not be accepted into Valkey keys"
    );
    assert!(
        normalize_federation_token(&format!("{}=", "e".repeat(32))).is_none(),
        "base64 padding is intentionally outside the accepted state-token alphabet"
    );
}

#[actix_web::test]
async fn federation_provider_list_returns_enabled_non_secret_provider_metadata() {
    let response = federation_provider_list(Data::new(provider_list_state())).await;
    let (status, body) = response_json(response).await;
    let providers = body["providers"]
        .as_array()
        .expect("providers must be an array");

    // 登录入口响应只能包含展示字段和 start URL；client_secret、token endpoint
    // 和 JWKS URL 等敏感或后端专用配置不能泄漏给前端。
    assert_eq!(status, StatusCode::OK);
    assert_eq!(providers.len(), 1);
    assert_eq!(providers[0]["provider_id"], "google");
    assert_eq!(providers[0]["display_name"], "Google");
    assert_eq!(providers[0]["adapter_type"], "oidc");
    assert_eq!(providers[0]["start_url"], "/auth/federation/google/start");
    assert!(providers[0].get("client_secret").is_none());
    assert!(providers[0].get("token_endpoint").is_none());
    assert!(providers[0].get("jwks_url").is_none());
}

#[test]
fn oidc_callback_input_rejects_provider_error_before_code_or_state_processing() {
    let query = OidcCallbackQuery {
        code: Some("authorization-code".to_owned()),
        state: Some("A".repeat(32)),
        error: Some("access_denied".to_owned()),
    };
    let response = validate_oidc_callback_input(&query)
        .expect_err("upstream OIDC error must stop callback processing");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response
            .extensions()
            .get::<OAuthJsonErrorFields>()
            .map(|fields| fields.error.as_str()),
        Some("access_denied")
    );
}

#[test]
fn oidc_callback_input_requires_urlsafe_state_and_bounded_non_empty_code() {
    let valid_state = "A".repeat(32);
    let valid = OidcCallbackQuery {
        code: Some(" code-1 ".to_owned()),
        state: Some(valid_state.clone()),
        error: None,
    };
    let input = validate_oidc_callback_input(&valid).expect("valid callback input should parse");
    assert_eq!(input.state_token, valid_state);
    assert_eq!(input.code, "code-1");

    for query in [
        OidcCallbackQuery {
            code: Some("code-1".to_owned()),
            state: None,
            error: None,
        },
        OidcCallbackQuery {
            code: Some("code-1".to_owned()),
            state: Some("not+urlsafe".to_owned()),
            error: None,
        },
    ] {
        let response = validate_oidc_callback_input(&query)
            .expect_err("missing or malformed state must fail before token exchange");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response
                .extensions()
                .get::<OAuthJsonErrorFields>()
                .map(|fields| fields.error.as_str()),
            Some("invalid_request")
        );
    }

    for code in [None, Some("   ".to_owned()), Some("x".repeat(4097))] {
        let response = validate_oidc_callback_input(&OidcCallbackQuery {
            code,
            state: Some(valid_state.clone()),
            error: None,
        })
        .expect_err("missing, blank, or oversized authorization code must fail closed");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response
                .extensions()
                .get::<OAuthJsonErrorFields>()
                .map(|fields| fields.error.as_str()),
            Some("invalid_request")
        );
    }
}

#[actix_web::test]
async fn oidc_callback_after_rate_limit_rejects_provider_error_before_state_lookup() {
    let state = Data::new(oidc_callback_state());
    let provider = oidc_provider();
    let req = actix_web::test::TestRequest::get()
        .uri("/auth/federation/test-oidc/callback?error=access_denied")
        .to_http_request();
    let query = OidcCallbackQuery {
        code: None,
        state: None,
        error: Some("access_denied".to_owned()),
    };

    let response = oidc_callback_after_rate_limit_for_provider(state, req, query, provider).await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response
            .extensions()
            .get::<OAuthJsonErrorFields>()
            .map(|fields| fields.error.as_str()),
        Some("access_denied")
    );
}

#[actix_web::test]
async fn federation_provider_callback_rejects_unknown_provider_before_input_processing() {
    let Some(state) = live_federation_state(None, None).await else {
        return;
    };
    let state = Data::new(state);
    let req = actix_web::test::TestRequest::get()
        .uri("/auth/federation/missing/callback?error=access_denied")
        .to_http_request();
    let query = OidcCallbackQuery {
        code: None,
        state: None,
        error: Some("access_denied".to_owned()),
    };

    let response =
        federation_provider_callback(state, req, Path::from("missing".to_owned()), Query(query))
            .await;

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        response
            .extensions()
            .get::<OAuthJsonErrorFields>()
            .map(|fields| fields.error.as_str()),
        Some("invalid_request")
    );
}

#[actix_web::test]
async fn oidc_callback_after_rate_limit_validates_input_before_state_storage_errors() {
    let state = Data::new(oidc_callback_state());
    let provider = oidc_provider();
    let req = actix_web::test::TestRequest::get()
        .uri("/auth/federation/test-oidc/callback?state=valid&code=code")
        .to_http_request();
    let query = OidcCallbackQuery {
        code: Some(" code-1 ".to_owned()),
        state: Some("A".repeat(32)),
        error: None,
    };

    let response = oidc_callback_after_rate_limit_for_provider(state, req, query, provider).await;

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        response
            .extensions()
            .get::<OAuthJsonErrorFields>()
            .map(|fields| fields.error.as_str()),
        Some("server_error")
    );
}

#[actix_web::test]
async fn oidc_callback_treats_missing_state_as_expired_before_token_exchange() {
    let provider = oidc_provider();
    let Some(state) = live_federation_state(Some(provider.clone()), None).await else {
        return;
    };
    let state = Data::new(state);
    let req = actix_web::test::TestRequest::get()
        .uri("/auth/federation/test-oidc/callback?state=missing&code=code")
        .to_http_request();
    let query = OidcCallbackQuery {
        code: Some("code-1".to_owned()),
        state: Some(random_urlsafe_token()),
        error: None,
    };

    let response = oidc_callback_after_rate_limit_for_provider(state, req, query, provider).await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        oauth_error_code(&response).as_deref(),
        Some("invalid_request")
    );
}

#[actix_web::test]
async fn oidc_callback_rejects_malformed_stored_state_before_token_exchange() {
    let provider = oidc_provider();
    let Some(state) = live_federation_state(Some(provider.clone()), None).await else {
        return;
    };
    let state_token = random_urlsafe_token();
    valkey_set_ex(
        &state.valkey,
        oidc_state_key(&state_token),
        "{not-json",
        FEDERATION_STATE_TTL_SECONDS,
    )
    .await
    .expect("malformed test OIDC state should be written");
    let state = Data::new(state);
    let req = actix_web::test::TestRequest::get()
        .uri("/auth/federation/test-oidc/callback?state=bad&code=code")
        .to_http_request();
    let query = OidcCallbackQuery {
        code: Some("code-1".to_owned()),
        state: Some(state_token),
        error: None,
    };

    let response = oidc_callback_after_rate_limit_for_provider(state, req, query, provider).await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        oauth_error_code(&response).as_deref(),
        Some("invalid_request")
    );
}

#[actix_web::test]
async fn oidc_callback_rejects_expired_stored_state_before_token_exchange() {
    let provider = oidc_provider();
    let Some(state) = live_federation_state(Some(provider.clone()), None).await else {
        return;
    };
    let state_token = random_urlsafe_token();
    store_oidc_state(
        &state,
        &state_token,
        Utc::now().timestamp() - FEDERATION_STATE_TTL_SECONDS as i64 - 1,
    )
    .await;
    let state = Data::new(state);
    let req = actix_web::test::TestRequest::get()
        .uri("/auth/federation/test-oidc/callback?state=expired&code=code")
        .to_http_request();
    let query = OidcCallbackQuery {
        code: Some("code-1".to_owned()),
        state: Some(state_token),
        error: None,
    };

    let response = oidc_callback_after_rate_limit_for_provider(state, req, query, provider).await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        oauth_error_code(&response).as_deref(),
        Some("invalid_request")
    );
}

#[actix_web::test]
async fn oidc_callback_rejects_state_bound_to_another_provider_before_token_exchange() {
    let provider = oidc_provider();
    let Some(state) = live_federation_state(Some(provider.clone()), None).await else {
        return;
    };
    let state_token = random_urlsafe_token();
    let stored = OidcFederationState {
        provider_id: Some("another-provider".to_owned()),
        nonce: random_urlsafe_token(),
        pkce_verifier: random_urlsafe_token(),
        created_at: Utc::now().timestamp(),
    };
    valkey_set_ex(
        &state.valkey,
        oidc_state_key(&state_token),
        serde_json::to_string(&stored).expect("bound OIDC state should serialize"),
        FEDERATION_STATE_TTL_SECONDS,
    )
    .await
    .expect("bound OIDC state should be written");

    let response = oidc_callback_after_rate_limit_for_provider(
        Data::new(state),
        actix_web::test::TestRequest::get()
            .uri("/auth/federation/test-oidc/callback?state=mixup&code=code")
            .to_http_request(),
        OidcCallbackQuery {
            code: Some("code-1".to_owned()),
            state: Some(state_token),
            error: None,
        },
        provider,
    )
    .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        oauth_error_code(&response).as_deref(),
        Some("invalid_request")
    );
}

#[actix_web::test]
async fn oidc_callback_requires_normalized_email_claim_before_identity_resolution() {
    let (provider, token_request, jwks_request, nonce) =
        provider_backed_by_local_oidc(json!({"email": null})).await;
    let Some(state) = live_federation_state(Some(provider.clone()), None).await else {
        return;
    };
    let state_token = random_urlsafe_token();
    store_oidc_state_with_nonce(&state, &state_token, &nonce, Utc::now().timestamp()).await;
    let state = Data::new(state);
    let req = actix_web::test::TestRequest::get()
        .uri("/auth/federation/test-oidc/callback?state=email&code=code")
        .to_http_request();
    let query = OidcCallbackQuery {
        code: Some("code-1".to_owned()),
        state: Some(state_token),
        error: None,
    };

    let response = oidc_callback_after_rate_limit_for_provider(state, req, query, provider).await;
    token_request
        .await
        .expect("token request should finish before email validation");
    jwks_request
        .await
        .expect("JWKS request should finish before email validation");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        oauth_error_code(&response).as_deref(),
        Some("access_denied")
    );
}

#[actix_web::test]
async fn oidc_callback_rejects_unverified_email_before_identity_resolution() {
    let (provider, token_request, jwks_request, nonce) =
        provider_backed_by_local_oidc(json!({"email_verified": false})).await;
    let Some(state) = live_federation_state(Some(provider.clone()), None).await else {
        return;
    };
    let state_token = random_urlsafe_token();
    store_oidc_state_with_nonce(&state, &state_token, &nonce, Utc::now().timestamp()).await;
    let state = Data::new(state);
    let req = actix_web::test::TestRequest::get()
        .uri("/auth/federation/test-oidc/callback?state=email&code=code")
        .to_http_request();
    let query = OidcCallbackQuery {
        code: Some("code-1".to_owned()),
        state: Some(state_token),
        error: None,
    };

    let response = oidc_callback_after_rate_limit_for_provider(state, req, query, provider).await;
    token_request
        .await
        .expect("token request should finish before email verification");
    jwks_request
        .await
        .expect("JWKS request should finish before email verification");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        oauth_error_code(&response).as_deref(),
        Some("access_denied")
    );
}

#[actix_web::test]
async fn oidc_callback_rejects_missing_email_verification_before_identity_resolution() {
    let (provider, token_request, jwks_request, nonce) =
        provider_backed_by_local_oidc(json!({"email_verified": null})).await;
    let Some(state) = live_federation_state(Some(provider.clone()), None).await else {
        return;
    };
    let state_token = random_urlsafe_token();
    store_oidc_state_with_nonce(&state, &state_token, &nonce, Utc::now().timestamp()).await;
    let state = Data::new(state);
    let req = actix_web::test::TestRequest::get()
        .uri("/auth/federation/test-oidc/callback?state=email&code=code")
        .to_http_request();
    let query = OidcCallbackQuery {
        code: Some("code-1".to_owned()),
        state: Some(state_token),
        error: None,
    };

    let response = oidc_callback_after_rate_limit_for_provider(state, req, query, provider).await;
    token_request
        .await
        .expect("token request should finish before email verification");
    jwks_request
        .await
        .expect("JWKS request should finish before email verification");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        oauth_error_code(&response).as_deref(),
        Some("access_denied")
    );
}

#[test]
fn oidc_authorization_url_binds_state_nonce_and_s256_pkce() {
    let provider = oidc_provider();
    let nonce = random_urlsafe_token();

    let location = oidc_authorization_url(&provider, "state-1", &nonce, "verifier-1");
    let url = url::Url::parse(&location).unwrap();
    let params = url
        .query_pairs()
        .collect::<std::collections::HashMap<_, _>>();

    assert_eq!(
        url.as_str().split('?').next(),
        Some("https://issuer.example/authorize")
    );
    assert_eq!(
        params.get("response_type").map(|value| value.as_ref()),
        Some("code")
    );
    assert_eq!(
        params.get("state").map(|value| value.as_ref()),
        Some("state-1")
    );
    assert_eq!(
        params.get("nonce").map(|value| value.as_ref()),
        Some(nonce.as_str())
    );
    assert_eq!(
        params
            .get("code_challenge_method")
            .map(|value| value.as_ref()),
        Some("S256")
    );
    assert_eq!(
        params.get("code_challenge").map(|value| value.as_ref()),
        Some(pkce_s256("verifier-1").as_str())
    );
}

fn saml_assertion(
    settings: &SamlGatewaySettings,
    subject: &str,
    email: &str,
    iat: i64,
    exp: i64,
) -> SamlGatewayAssertion {
    SamlGatewayAssertion {
        issuer: settings.issuer.clone(),
        audience: settings.audience.clone(),
        subject: subject.to_owned(),
        email: email.to_owned(),
        name: None,
        iat,
        exp,
        signature: saml_gateway_signature(
            &settings.secret,
            &settings.issuer,
            &settings.audience,
            subject,
            email,
            iat,
            exp,
        ),
    }
}

#[test]
fn saml_gateway_signature_is_bound_to_assertion_fields() {
    let settings = SamlGatewaySettings {
        issuer: "gateway".to_owned(),
        audience: "nazo".to_owned(),
        secret: "01234567890123456789012345678901".to_owned(),
    };
    let now = Utc::now().timestamp();
    let signature = saml_gateway_signature(
        &settings.secret,
        &settings.issuer,
        &settings.audience,
        "subject",
        "user@example.com",
        now,
        now + 60,
    );
    let assertion = SamlGatewayAssertion {
        issuer: settings.issuer.clone(),
        audience: settings.audience.clone(),
        subject: "subject".to_owned(),
        email: "user@example.com".to_owned(),
        name: None,
        iat: now,
        exp: now + 60,
        signature,
    };
    assert!(valid_saml_gateway_assertion(
        &settings,
        &assertion,
        "user@example.com"
    ));
    assert!(!valid_saml_gateway_assertion(
        &settings,
        &assertion,
        "other@example.com"
    ));
}

#[test]
fn saml_gateway_assertion_rejects_correctly_signed_overlong_ttl() {
    let settings = SamlGatewaySettings {
        issuer: "gateway".to_owned(),
        audience: "nazo".to_owned(),
        secret: "01234567890123456789012345678901".to_owned(),
    };
    let now = Utc::now().timestamp();
    let signature = saml_gateway_signature(
        &settings.secret,
        &settings.issuer,
        &settings.audience,
        "subject",
        "user@example.com",
        now,
        now + 301,
    );
    let assertion = SamlGatewayAssertion {
        issuer: settings.issuer.clone(),
        audience: settings.audience.clone(),
        subject: "subject".to_owned(),
        email: "user@example.com".to_owned(),
        name: None,
        iat: now,
        exp: now + 301,
        signature,
    };

    assert!(!valid_saml_gateway_assertion(
        &settings,
        &assertion,
        "user@example.com"
    ));
}

#[test]
fn saml_gateway_assertion_rejects_wrong_issuer_audience_and_signature() {
    let settings = SamlGatewaySettings {
        issuer: "gateway".to_owned(),
        audience: "nazo".to_owned(),
        secret: "01234567890123456789012345678901".to_owned(),
    };
    let now = Utc::now().timestamp();
    let mut wrong_issuer = saml_assertion(&settings, "subject", "user@example.com", now, now + 60);
    wrong_issuer.issuer = "other-gateway".to_owned();
    assert!(!valid_saml_gateway_assertion(
        &settings,
        &wrong_issuer,
        "user@example.com"
    ));

    let mut wrong_audience =
        saml_assertion(&settings, "subject", "user@example.com", now, now + 60);
    wrong_audience.audience = "other-audience".to_owned();
    assert!(!valid_saml_gateway_assertion(
        &settings,
        &wrong_audience,
        "user@example.com"
    ));

    let mut wrong_signature =
        saml_assertion(&settings, "subject", "user@example.com", now, now + 60);
    wrong_signature.signature = saml_gateway_signature(
        &settings.secret,
        &settings.issuer,
        &settings.audience,
        "other-subject",
        "user@example.com",
        now,
        now + 60,
    );
    assert!(!valid_saml_gateway_assertion(
        &settings,
        &wrong_signature,
        "user@example.com"
    ));
}

#[test]
fn saml_gateway_assertion_rejects_expired_or_future_assertions() {
    let settings = SamlGatewaySettings {
        issuer: "gateway".to_owned(),
        audience: "nazo".to_owned(),
        secret: "01234567890123456789012345678901".to_owned(),
    };
    let now = Utc::now().timestamp();
    for (iat, exp) in [(now - 600, now - 60), (now + 61, now + 120)] {
        let assertion = saml_assertion(&settings, "subject", "user@example.com", iat, exp);

        assert!(!valid_saml_gateway_assertion(
            &settings,
            &assertion,
            "user@example.com"
        ));
    }
}

#[actix_web::test]
async fn saml_acs_requires_gateway_configuration_before_payload_validation() {
    let Some(state) = live_federation_state(None, None).await else {
        return;
    };
    let req = actix_web::test::TestRequest::post()
        .uri("/auth/federation/saml/acs")
        .to_http_request();
    let payload = SamlGatewayAssertion {
        issuer: "gateway".to_owned(),
        audience: "nazo".to_owned(),
        subject: "subject".to_owned(),
        email: "not-an-email".to_owned(),
        name: None,
        iat: Utc::now().timestamp(),
        exp: Utc::now().timestamp() + 60,
        signature: "invalid".to_owned(),
    };

    let response = federation_saml_acs(Data::new(state), req, Json(payload)).await;

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        oauth_error_code(&response).as_deref(),
        Some("temporarily_unavailable")
    );
}

#[actix_web::test]
async fn saml_acs_rejects_invalid_email_before_signature_or_identity_resolution() {
    let settings = SamlGatewaySettings {
        issuer: "gateway".to_owned(),
        audience: "nazo".to_owned(),
        secret: "01234567890123456789012345678901".to_owned(),
    };
    let Some(state) = live_federation_state(None, Some(settings)).await else {
        return;
    };
    let req = actix_web::test::TestRequest::post()
        .uri("/auth/federation/saml/acs")
        .to_http_request();
    let payload = SamlGatewayAssertion {
        issuer: "gateway".to_owned(),
        audience: "nazo".to_owned(),
        subject: "subject".to_owned(),
        email: "not-an-email".to_owned(),
        name: None,
        iat: Utc::now().timestamp(),
        exp: Utc::now().timestamp() + 60,
        signature: "invalid".to_owned(),
    };

    let response = federation_saml_acs(Data::new(state), req, Json(payload)).await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        oauth_error_code(&response).as_deref(),
        Some("invalid_request")
    );
}

#[actix_web::test]
async fn saml_acs_rejects_signed_assertion_with_wrong_audience_before_identity_resolution() {
    let settings = SamlGatewaySettings {
        issuer: "gateway".to_owned(),
        audience: "nazo".to_owned(),
        secret: "01234567890123456789012345678901".to_owned(),
    };
    let now = Utc::now().timestamp();
    let mut payload = saml_assertion(&settings, "subject", "user@example.com", now, now + 60);
    payload.audience = "other-audience".to_owned();
    let Some(state) = live_federation_state(None, Some(settings)).await else {
        return;
    };
    let req = actix_web::test::TestRequest::post()
        .uri("/auth/federation/saml/acs")
        .to_http_request();

    let response = federation_saml_acs(Data::new(state), req, Json(payload)).await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        oauth_error_code(&response).as_deref(),
        Some("access_denied")
    );
}

#[actix_web::test]
async fn federation_provider_start_rejects_unknown_provider_after_rate_limit() {
    let Some(state) = live_federation_state(None, None).await else {
        return;
    };
    let response = federation_provider_start(
        Data::new(state),
        actix_web::test::TestRequest::get()
            .peer_addr(
                "198.51.100.10:443"
                    .parse()
                    .expect("peer address should parse"),
            )
            .to_http_request(),
        Path::from("missing".to_owned()),
    )
    .await;

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        oauth_error_code(&response).as_deref(),
        Some("invalid_request")
    );
}

#[actix_web::test]
async fn federation_provider_start_persists_oidc_state_nonce_and_pkce_binding() {
    let provider = oidc_provider();
    let Some(state) = live_federation_state(Some(provider), None).await else {
        return;
    };
    let state = Data::new(state);
    let response = federation_provider_start(
        state.clone(),
        actix_web::test::TestRequest::get()
            .peer_addr(
                "198.51.100.11:443"
                    .parse()
                    .expect("peer address should parse"),
            )
            .to_http_request(),
        Path::from(TEST_OIDC_PROVIDER_ID.to_owned()),
    )
    .await;

    assert_eq!(response.status(), StatusCode::FOUND);
    let location = response
        .headers()
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .expect("redirect should include location");
    let url = url::Url::parse(location).expect("redirect should be a valid URL");
    let params = url
        .query_pairs()
        .collect::<std::collections::HashMap<_, _>>();
    let state_token = params
        .get("state")
        .map(|value| value.to_string())
        .expect("OIDC start must bind a CSRF state token");
    let nonce = params
        .get("nonce")
        .map(|value| value.as_ref())
        .expect("OIDC start must bind a nonce");
    let raw = valkey_get(&state.valkey, oidc_state_key(&state_token))
        .await
        .expect("state lookup should succeed")
        .expect("OIDC start must persist callback state");
    let stored: OidcFederationState =
        serde_json::from_str(&raw).expect("stored state should deserialize");
    let expected_challenge = pkce_s256(&stored.pkce_verifier);

    assert_eq!(stored.provider_id.as_deref(), Some(TEST_OIDC_PROVIDER_ID));
    assert_eq!(stored.nonce, nonce);
    assert_eq!(
        params
            .get("code_challenge_method")
            .map(|value| value.as_ref()),
        Some("S256")
    );
    assert_eq!(
        params.get("code_challenge").map(|value| value.as_ref()),
        Some(expected_challenge.as_str())
    );
    assert!(stored.created_at <= Utc::now().timestamp());
}

#[actix_web::test]
async fn oidc_callback_denies_failed_token_exchange_and_consumes_state() {
    let (token_endpoint, token_request) = one_shot_json_server(json!({})).await;
    let mut provider = oidc_provider();
    provider.token_endpoint = token_endpoint;
    let Some(state) = live_federation_state(Some(provider.clone()), None).await else {
        return;
    };
    let state_token = random_urlsafe_token();
    store_oidc_state(&state, &state_token, Utc::now().timestamp()).await;
    let state = Data::new(state);

    let response = oidc_callback_after_rate_limit_for_provider(
        state.clone(),
        actix_web::test::TestRequest::get()
            .peer_addr(
                "198.51.100.12:443"
                    .parse()
                    .expect("peer address should parse"),
            )
            .to_http_request(),
        OidcCallbackQuery {
            code: Some("code-1".to_owned()),
            state: Some(state_token.clone()),
            error: None,
        },
        provider,
    )
    .await;
    token_request
        .await
        .expect("token endpoint should receive the exchange request");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        oauth_error_code(&response).as_deref(),
        Some("access_denied")
    );
    assert!(
        valkey_get(&state.valkey, oidc_state_key(&state_token))
            .await
            .expect("state lookup should succeed")
            .is_none(),
        "callback state must be single-use even when the upstream token endpoint fails"
    );
}

#[actix_web::test]
async fn oidc_callback_returns_server_error_when_jwks_response_is_invalid() {
    let mut provider = oidc_provider();
    let key = client_signing_fixture(Algorithm::RS256);
    let nonce = random_urlsafe_token();
    let id_token = signed_oidc_token(&provider, "oidc-kid", &key, &nonce, json!({}));
    let (token_endpoint, token_request) =
        one_shot_json_server(json!({ "id_token": id_token })).await;
    let (jwks_url, jwks_request) = one_shot_json_server(json!({ "not_keys": [] })).await;
    provider.token_endpoint = token_endpoint;
    provider.jwks_url = jwks_url;
    let Some(state) = live_federation_state(Some(provider.clone()), None).await else {
        return;
    };
    let state_token = random_urlsafe_token();
    store_oidc_state_with_nonce(&state, &state_token, &nonce, Utc::now().timestamp()).await;
    let state = Data::new(state);

    let response = oidc_callback_after_rate_limit_for_provider(
        state,
        actix_web::test::TestRequest::get()
            .peer_addr(
                "198.51.100.13:443"
                    .parse()
                    .expect("peer address should parse"),
            )
            .to_http_request(),
        OidcCallbackQuery {
            code: Some("code-1".to_owned()),
            state: Some(state_token),
            error: None,
        },
        provider,
    )
    .await;
    token_request
        .await
        .expect("token endpoint should receive the exchange request");
    jwks_request
        .await
        .expect("JWKS endpoint should receive the fetch request");

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(oauth_error_code(&response).as_deref(), Some("server_error"));
}

#[actix_web::test]
async fn oidc_callback_rejects_id_token_policy_failures_and_consumes_state() {
    let wrong_nonce = random_urlsafe_token();
    let (provider, token_request, jwks_request, nonce) =
        provider_backed_by_local_oidc(json!({"nonce": wrong_nonce})).await;
    let Some(state) = live_federation_state(Some(provider.clone()), None).await else {
        return;
    };
    let state_token = random_urlsafe_token();
    store_oidc_state_with_nonce(&state, &state_token, &nonce, Utc::now().timestamp()).await;
    let state = Data::new(state);

    let response = oidc_callback_after_rate_limit_for_provider(
        state.clone(),
        actix_web::test::TestRequest::get()
            .peer_addr(
                "198.51.100.14:443"
                    .parse()
                    .expect("peer address should parse"),
            )
            .to_http_request(),
        OidcCallbackQuery {
            code: Some("code-1".to_owned()),
            state: Some(state_token.clone()),
            error: None,
        },
        provider,
    )
    .await;
    token_request
        .await
        .expect("token endpoint should receive the exchange request");
    jwks_request
        .await
        .expect("JWKS endpoint should receive the fetch request");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        oauth_error_code(&response).as_deref(),
        Some("access_denied")
    );
    assert!(
        valkey_get(&state.valkey, oidc_state_key(&state_token))
            .await
            .expect("state lookup should succeed")
            .is_none(),
        "callback state must be consumed before ID token verification to prevent replay"
    );
}

#[actix_web::test]
async fn oidc_callback_reports_identity_resolution_db_failure_without_session_cookie() {
    let (provider, token_request, jwks_request, nonce) = provider_backed_by_local_oidc(json!({
        "sub": format!("oidc-db-failure-subject-{}", Uuid::now_v7().simple()),
        "email": format!("oidc-db-failure-{}@example.com", Uuid::now_v7().simple()),
        "name": "Database Failure"
    }))
    .await;
    let Some(state) = live_federation_state(Some(provider.clone()), None).await else {
        return;
    };
    let state_token = random_urlsafe_token();
    store_oidc_state_with_nonce(&state, &state_token, &nonce, Utc::now().timestamp()).await;
    let state = Data::new(state);

    let response = oidc_callback_after_rate_limit_for_provider(
        state.clone(),
        actix_web::test::TestRequest::get()
            .peer_addr(
                "198.51.100.21:443"
                    .parse()
                    .expect("peer address should parse"),
            )
            .to_http_request(),
        OidcCallbackQuery {
            code: Some("code-1".to_owned()),
            state: Some(state_token.clone()),
            error: None,
        },
        provider,
    )
    .await;
    token_request
        .await
        .expect("token endpoint should receive the exchange request");
    jwks_request
        .await
        .expect("JWKS endpoint should receive the fetch request");

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(oauth_error_code(&response).as_deref(), Some("server_error"));
    assert!(
        cookie_value_from_response(&response, &state.settings.session.session_cookie_name)
            .is_none(),
        "identity-resolution database failures must not issue a federated session"
    );
    assert!(
        valkey_get(&state.valkey, oidc_state_key(&state_token))
            .await
            .expect("state lookup should succeed")
            .is_none(),
        "callback state must remain single-use even when identity resolution fails closed"
    );
}

#[actix_web::test]
async fn oidc_callback_creates_new_federated_user_session_and_external_link() {
    let suffix = Uuid::now_v7().simple().to_string();
    let email = format!("oidc-new-{suffix}@example.com");
    let subject = format!("oidc-subject-{suffix}");
    let (provider, token_request, jwks_request, nonce) = provider_backed_by_local_oidc(json!({
        "sub": subject,
        "email": email,
        "name": "Federated User"
    }))
    .await;
    let Some(fixture) = LiveFederationFixture::new(Some(provider.clone()), None).await else {
        return;
    };
    let state_token = random_urlsafe_token();
    store_oidc_state_with_nonce(&fixture.state, &state_token, &nonce, Utc::now().timestamp()).await;

    let response = oidc_callback_after_rate_limit_for_provider(
        fixture.state.clone(),
        actix_web::test::TestRequest::get()
            .peer_addr(
                "198.51.100.15:443"
                    .parse()
                    .expect("peer address should parse"),
            )
            .to_http_request(),
        OidcCallbackQuery {
            code: Some("code-1".to_owned()),
            state: Some(state_token),
            error: None,
        },
        provider,
    )
    .await;
    token_request
        .await
        .expect("token endpoint should receive the exchange request");
    jwks_request
        .await
        .expect("JWKS endpoint should receive the fetch request");

    let session_cookie = cookie_value_from_response(
        &response,
        &fixture.state.settings.session.session_cookie_name,
    )
    .expect("federated login must set a session cookie");
    let csrf_cookie =
        cookie_value_from_response(&response, &fixture.state.settings.session.csrf_cookie_name)
            .expect("federated login must set a CSRF cookie");
    let (status, body) = response_json(response).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["mfa_required"], false);
    assert_eq!(body["csrf_token"], csrf_cookie);
    assert_eq!(
        body["expires_in"],
        fixture.state.settings.session.session_ttl_seconds
    );
    assert!(body.get("session_id").is_none());

    let user = fixture
        .user_by_email(&email)
        .await
        .expect("OIDC login should provision a user for a new verified email");
    let link = fixture
        .external_identity_link("oidc", TEST_OIDC_PROVIDER_ID, &subject)
        .await
        .expect("OIDC login should persist the external identity link");
    let session = fixture.session_payload(&session_cookie).await;

    assert_eq!(user.profile.display_name.as_deref(), Some("Federated User"));
    assert!(user.account.email_verified);
    assert_eq!(link.user_id, user.id());
    assert_eq!(link.email, email);
    assert_eq!(session.user_id, user.id());
    assert_eq!(session.amr, vec!["oidc".to_owned(), "federated".to_owned()]);
    assert!(!session.pending_mfa);
    assert!(session.oidc_sid.is_some());
}

#[actix_web::test]
async fn oidc_callback_rejects_existing_active_email_account_without_explicit_link() {
    let suffix = Uuid::now_v7().simple().to_string();
    let email = format!("oidc-existing-{suffix}@example.com");
    let subject = format!("oidc-existing-subject-{suffix}");
    let (provider, token_request, jwks_request, nonce) = provider_backed_by_local_oidc(json!({
        "sub": subject,
        "email": email,
        "name": "Existing User"
    }))
    .await;
    let Some(fixture) = LiveFederationFixture::new(Some(provider.clone()), None).await else {
        return;
    };
    let existing_user = fixture.create_user(&email, true).await;
    let state_token = random_urlsafe_token();
    store_oidc_state_with_nonce(&fixture.state, &state_token, &nonce, Utc::now().timestamp()).await;

    let response = oidc_callback_after_rate_limit_for_provider(
        fixture.state.clone(),
        actix_web::test::TestRequest::get()
            .peer_addr(
                "198.51.100.16:443"
                    .parse()
                    .expect("peer address should parse"),
            )
            .to_http_request(),
        OidcCallbackQuery {
            code: Some("code-1".to_owned()),
            state: Some(state_token),
            error: None,
        },
        provider,
    )
    .await;
    token_request
        .await
        .expect("token endpoint should receive the exchange request");
    jwks_request
        .await
        .expect("JWKS endpoint should receive the fetch request");

    // 拒绝自动绑定已有 email 账号时，响应不应创建新的登录会话。
    let session_cookie = cookie_value_from_response(
        &response,
        &fixture.state.settings.session.session_cookie_name,
    );
    let (status, body) = response_json(response).await;
    let linked_user = fixture
        .user_by_email(&email)
        .await
        .expect("existing user should still be present");

    // 已有本地账号必须走显式 linking 流程；不能只凭第三方 email claim
    // 自动把外部 subject 绑定到该账号。
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "access_denied");
    assert_eq!(linked_user.id(), existing_user.id);
    assert!(
        fixture
            .external_identity_link("oidc", TEST_OIDC_PROVIDER_ID, &subject)
            .await
            .is_none()
    );
    assert!(session_cookie.is_none());
}

#[actix_web::test]
async fn oidc_callback_rejects_existing_inactive_email_account_without_link_or_session() {
    let suffix = Uuid::now_v7().simple().to_string();
    let email = format!("oidc-existing-inactive-{suffix}@example.com");
    let subject = format!("oidc-existing-inactive-subject-{suffix}");
    let (provider, token_request, jwks_request, nonce) = provider_backed_by_local_oidc(json!({
        "sub": subject,
        "email": email,
        "name": "Inactive Existing User"
    }))
    .await;
    let Some(fixture) = LiveFederationFixture::new(Some(provider.clone()), None).await else {
        return;
    };
    let inactive_user = fixture.create_user(&email, false).await;
    let state_token = random_urlsafe_token();
    store_oidc_state_with_nonce(&fixture.state, &state_token, &nonce, Utc::now().timestamp()).await;

    let response = oidc_callback_after_rate_limit_for_provider(
        fixture.state.clone(),
        actix_web::test::TestRequest::get()
            .peer_addr(
                "198.51.100.19:443"
                    .parse()
                    .expect("peer address should parse"),
            )
            .to_http_request(),
        OidcCallbackQuery {
            code: Some("code-1".to_owned()),
            state: Some(state_token),
            error: None,
        },
        provider,
    )
    .await;
    token_request
        .await
        .expect("token endpoint should receive the exchange request");
    jwks_request
        .await
        .expect("JWKS endpoint should receive the fetch request");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        oauth_error_code(&response).as_deref(),
        Some("access_denied")
    );
    assert!(
        cookie_value_from_response(
            &response,
            &fixture.state.settings.session.session_cookie_name
        )
        .is_none(),
        "inactive existing email accounts must not receive a federated session"
    );
    assert!(
        fixture
            .external_identity_link("oidc", TEST_OIDC_PROVIDER_ID, &subject)
            .await
            .is_none(),
        "inactive local accounts must not be silently linked to a new OIDC subject"
    );
    let reloaded = fixture
        .user_by_email(&email)
        .await
        .expect("inactive user should remain present");
    assert_eq!(reloaded.id(), inactive_user.id);
    assert!(!reloaded.principal.active);
}

#[actix_web::test]
async fn oidc_callback_rejects_inactive_linked_user() {
    let suffix = Uuid::now_v7().simple().to_string();
    let email = format!("oidc-inactive-{suffix}@example.com");
    let subject = format!("oidc-inactive-subject-{suffix}");
    let (provider, token_request, jwks_request, nonce) = provider_backed_by_local_oidc(json!({
        "sub": subject,
        "email": email
    }))
    .await;
    let Some(fixture) = LiveFederationFixture::new(Some(provider.clone()), None).await else {
        return;
    };
    let inactive_user = fixture.create_user(&email, false).await;
    fixture
        .insert_external_identity_link(
            &inactive_user,
            "oidc",
            TEST_OIDC_PROVIDER_ID,
            &subject,
            &email,
        )
        .await;
    let state_token = random_urlsafe_token();
    store_oidc_state_with_nonce(&fixture.state, &state_token, &nonce, Utc::now().timestamp()).await;

    let response = oidc_callback_after_rate_limit_for_provider(
        fixture.state.clone(),
        actix_web::test::TestRequest::get()
            .peer_addr(
                "198.51.100.17:443"
                    .parse()
                    .expect("peer address should parse"),
            )
            .to_http_request(),
        OidcCallbackQuery {
            code: Some("code-1".to_owned()),
            state: Some(state_token),
            error: None,
        },
        provider,
    )
    .await;
    token_request
        .await
        .expect("token endpoint should receive the exchange request");
    jwks_request
        .await
        .expect("JWKS endpoint should receive the fetch request");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        oauth_error_code(&response).as_deref(),
        Some("access_denied")
    );
    assert!(
        cookie_value_from_response(
            &response,
            &fixture.state.settings.session.session_cookie_name
        )
        .is_none(),
        "inactive linked users must not receive a session cookie"
    );
}

#[actix_web::test]
async fn social_callback_without_email_rejects_inactive_linked_user() {
    let provider_id = "test-social";
    let suffix = Uuid::now_v7().simple().to_string();
    let subject = format!("social-inactive-subject-{suffix}");
    let email = format!("social-inactive-{suffix}@example.com");
    let Some(fixture) = LiveFederationFixture::new(None, None).await else {
        return;
    };
    let inactive_user = fixture.create_user(&email, false).await;
    fixture
        .insert_external_identity_link(
            &inactive_user,
            "oauth2_social",
            provider_id,
            &subject,
            &email,
        )
        .await;
    let response = tokio::time::timeout(
        Duration::from_secs(5),
        complete_social_callback(
            fixture.state.clone(),
            actix_web::test::TestRequest::get()
                .peer_addr(
                    "198.51.100.23:443"
                        .parse()
                        .expect("peer address should parse"),
                )
                .to_http_request(),
            provider_id.to_owned(),
            SocialIdentity {
                subject,
                email: None,
                display_name: Some("Inactive Social User".to_owned()),
                claims: json!({"adapter": "oauth2_social"}),
            },
        ),
    )
    .await
    .expect("social callback should complete within the fixture deadline");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        oauth_error_code(&response).as_deref(),
        Some("access_denied")
    );
    assert!(
        cookie_value_from_response(
            &response,
            &fixture.state.settings.session.session_cookie_name
        )
        .is_none(),
        "inactive linked social users must not receive a session"
    );
}

#[actix_web::test]
async fn saml_acs_creates_new_federated_user_session_and_external_link() {
    let settings = SamlGatewaySettings {
        issuer: "gateway".to_owned(),
        audience: "nazo".to_owned(),
        secret: "01234567890123456789012345678901".to_owned(),
    };
    let suffix = Uuid::now_v7().simple().to_string();
    let email = format!("saml-{suffix}@example.com");
    let subject = format!("saml-subject-{suffix}");
    let Some(fixture) = LiveFederationFixture::new(None, Some(settings.clone())).await else {
        return;
    };
    let now = Utc::now().timestamp();
    let mut payload = saml_assertion(&settings, &subject, &email, now, now + 60);
    payload.name = Some("SAML User".to_owned());
    let replay_payload = payload.clone();

    let response = federation_saml_acs(
        fixture.state.clone(),
        actix_web::test::TestRequest::post()
            .peer_addr(
                "198.51.100.18:443"
                    .parse()
                    .expect("peer address should parse"),
            )
            .to_http_request(),
        Json(payload),
    )
    .await;

    let session_cookie = cookie_value_from_response(
        &response,
        &fixture.state.settings.session.session_cookie_name,
    )
    .expect("successful SAML federation must set a session cookie");
    let csrf_cookie =
        cookie_value_from_response(&response, &fixture.state.settings.session.csrf_cookie_name)
            .expect("successful SAML federation must set a CSRF cookie");
    let (status, body) = response_json(response).await;
    let user = fixture
        .user_by_email(&email)
        .await
        .expect("SAML federation should provision a user for a new verified email");
    let link = fixture
        .external_identity_link("saml", &settings.issuer, &subject)
        .await
        .expect("SAML federation should persist the external identity link");
    let session = fixture.session_payload(&session_cookie).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["mfa_required"], false);
    assert_eq!(body["csrf_token"], csrf_cookie);
    assert_eq!(user.profile.display_name.as_deref(), Some("SAML User"));
    assert_eq!(link.user_id, user.id());
    assert_eq!(session.user_id, user.id());
    assert_eq!(session.amr, vec!["saml".to_owned(), "federated".to_owned()]);

    let replay = federation_saml_acs(
        fixture.state.clone(),
        actix_web::test::TestRequest::post()
            .uri("/auth/federation/saml/acs")
            .to_http_request(),
        Json(replay_payload),
    )
    .await;
    assert_eq!(replay.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        oauth_error_code(&replay).as_deref(),
        Some("access_denied"),
        "a signed SAML assertion must be accepted at most once"
    );
}
