use super::*;
use crate::config::ConfigSource;
use crate::http::authorization::{
    AuthorizationHttpConfig, AuthorizationTestFixture, ServerAuthorizationService,
};
use crate::http::sessions::AdminSessionHandles;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nazo_postgres::{DbPool, create_pool, get_conn};

use crate::adapters::security::hash_client_secret;
use crate::http::client_ip::IpCidr;
use crate::settings::{AuthorizationServerProfile, DpopNoncePolicy};
use crate::test_support::ClientSigningFixture;
use crate::test_support::client_signing_fixture;
use actix_web::test::TestRequest;
use diesel::sql_query;
use diesel::sql_types::{Bool, Nullable, Text, Uuid as SqlUuid};
use diesel_async::RunQueryDsl;
use fred::interfaces::ClientLike;
use fred::prelude::{
    Builder as ValkeyBuilder, Config as ValkeyConfig, ConnectionConfig, PerformanceConfig,
};

async fn par(fixture: &ParTestFixture, req: HttpRequest, body: Bytes) -> HttpResponse {
    let context = fixture.authorization.context();
    if let Err(response) = enforce_par_rate_limit(&context, &req).await {
        return response;
    }
    par_after_rate_limit(fixture, req, body).await
}

async fn par_after_rate_limit(
    fixture: &ParTestFixture,
    req: HttpRequest,
    body: Bytes,
) -> HttpResponse {
    par_after_rate_limit_with_context(&fixture.authorization.context(), req, body).await
}

fn client(require_dpop_bound_tokens: bool) -> ClientRow {
    crate::client_row! {
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
        allowed_audiences: json!([]),
        grant_types: json!(["authorization_code"]),
        token_endpoint_auth_method: "private_key_jwt".to_owned(),
        require_dpop_bound_tokens: require_dpop_bound_tokens,
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

fn baseline_settings() -> Settings {
    let mut settings =
        Settings::from_config(&crate::config::ConfigSource::default()).expect("settings");
    settings.endpoint.issuer = "https://issuer.example".to_owned();
    settings.endpoint.mtls_endpoint_base_url = "https://issuer.example".to_owned();
    settings.endpoint.frontend_base_url = "https://frontend.example".to_owned();
    settings.endpoint.cors_allowed_origins = vec!["https://frontend.example".to_owned()];
    settings.protocol.protected_resource_identifier =
        "https://issuer.example/fapi/resource".to_owned();
    settings.protocol.dpop_nonce_policy = DpopNoncePolicy::Required;
    settings.protocol.auth_code_ttl_seconds = 300;
    settings.session.cookie_secure = true;
    settings.storage.avatar_storage_dir = std::env::temp_dir().join("unused-avatars");
    settings.keys.jwk_keys_dir = std::env::temp_dir().join("unused-keys");
    settings
}

fn oauth_error_code(response: &HttpResponse) -> Option<String> {
    response
        .extensions()
        .get::<OAuthJsonErrorFields>()
        .map(|fields| fields.error.clone())
}

#[test]
fn par_error_log_fields_skip_success_and_include_only_safe_error_metadata() {
    let created = json_response_status(
        StatusCode::CREATED,
        json!({
            "request_uri": "urn:ietf:params:oauth:request_uri:secret",
            "expires_in": 90
        }),
    );
    assert_eq!(par_error_log_fields(&created), None);

    let rejected = oauth_error(
        StatusCode::BAD_REQUEST,
        "invalid_request_object",
        "request=secret must not be logged",
    );
    assert_eq!(
        par_error_log_fields(&rejected),
        Some((400, Some("invalid_request_object".to_owned())))
    );
}

fn par_test_secret() -> String {
    ["par", "client", "secret"].join("-")
}

#[test]
fn pushed_authorization_request_resources_allow_registered_targets() {
    let mut client = client(false);
    client.allowed_audiences = vec![
        "https://api.example/one".to_owned(),
        "https://api.example/two".to_owned(),
    ];
    let mut params = HashMap::new();
    params.insert(
        "resource".to_owned(),
        json!(["https://api.example/one", "https://api.example/two"]).to_string(),
    );

    assert!(validate_pushed_authorization_request_resources(&client, &params).is_ok());
}

#[test]
fn pushed_authorization_request_resources_reject_unregistered_target() {
    let mut client = client(false);
    client.allowed_audiences = vec!["https://api.example/one".to_owned()];
    let mut params = HashMap::new();
    params.insert("resource".to_owned(), "https://api.example/two".to_owned());

    let response = validate_pushed_authorization_request_resources(&client, &params).unwrap_err();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        oauth_error_code(&response).as_deref(),
        Some("invalid_target")
    );
}

fn signed_request_object(client_id: &str, fixture: &ClientSigningFixture, extra: Value) -> String {
    let now = Utc::now().timestamp();
    let mut claims = json!({
        "client_id": client_id,
        "iss": client_id,
        "sub": client_id,
        "aud": "https://issuer.example",
        "iat": now,
        "nbf": now,
        "exp": now + 120,
        "jti": format!("par-jar-jti-{}", Uuid::now_v7()),
        "response_type": "code",
        "redirect_uri": "https://client.example/callback",
    });
    let target = claims.as_object_mut().expect("claims should be an object");
    for (key, value) in extra.as_object().expect("extra should be an object") {
        target.insert(key.clone(), value.clone());
    }
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = Some("par-request-object-kid".to_owned());
    fixture.encode_jwt(&header, &claims)
}

fn private_key_client_assertion(
    client_id: &str,
    audience: &str,
    fixture: &ClientSigningFixture,
) -> String {
    let now = Utc::now().timestamp();
    let claims = json!({
        "iss": client_id,
        "sub": client_id,
        "aud": audience,
        "iat": now,
        "exp": now + 120,
        "jti": format!("par-client-assertion-{}", Uuid::now_v7()),
    });
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::PS256);
    header.kid = Some("par-client-assertion-kid".to_owned());
    fixture.encode_jwt(&header, &claims)
}

fn unsigned_request_object(client_id: &str) -> String {
    let now = Utc::now().timestamp();
    let header = json!({"alg": "none"});
    let claims = json!({
        "client_id": client_id,
        "iss": client_id,
        "sub": client_id,
        "aud": "https://issuer.example",
        "iat": now,
        "nbf": now,
        "exp": now + 120,
        "jti": format!("par-unsigned-jti-{}", Uuid::now_v7()),
        "response_type": "code",
        "redirect_uri": "https://client.example/callback",
    });
    format!(
        "{}.{}.",
        URL_SAFE_NO_PAD.encode(header.to_string()),
        URL_SAFE_NO_PAD.encode(claims.to_string())
    )
}

fn unavailable_valkey_client(timeout_ms: u64) -> fred::prelude::Client {
    let mut valkey_builder = fred::prelude::Builder::from_config(
        fred::prelude::Config::from_url("redis://127.0.0.1:1")
            .expect("unavailable Valkey URL should parse"),
    );
    valkey_builder.with_performance_config(|performance: &mut fred::prelude::PerformanceConfig| {
        performance.default_command_timeout = std::time::Duration::from_millis(timeout_ms);
    });
    valkey_builder.with_connection_config(|connection: &mut fred::prelude::ConnectionConfig| {
        connection.connection_timeout = std::time::Duration::from_millis(timeout_ms);
        connection.internal_command_timeout = std::time::Duration::from_millis(timeout_ms);
        connection.max_command_attempts = 1;
    });
    valkey_builder
        .build()
        .expect("unavailable valkey client construction should not connect")
}

struct ParTestFixture {
    authorization: AuthorizationTestFixture,
    database: DbPool,
    valkey: fred::prelude::Client,
    keyset: nazo_key_management::KeyManager,
}

impl ParTestFixture {
    fn new(
        settings: Settings,
        database: DbPool,
        valkey: fred::prelude::Client,
        keyset: nazo_key_management::KeyManager,
    ) -> Self {
        let connection = nazo_valkey::ValkeyConnection::from_existing_client(valkey.clone());
        let session = &settings.session;
        let authorization = AuthorizationTestFixture::new(
            ServerAuthorizationService::new(
                nazo_postgres::AuthorizationFlowRepository::new(
                    database.clone(),
                    DEFAULT_TENANT_ID,
                ),
                nazo_valkey::AuthorizationStateAdapter::new(&connection),
                keyset.clone(),
            ),
            AuthorizationHttpConfig::from(&settings),
            AdminSessionHandles::new(
                nazo_valkey::SessionStore::new(&connection),
                nazo_postgres::UserRepository::new(database.clone()),
                crate::http::sessions::SessionHttpConfig::new(
                    &session.session_cookie_name,
                    &session.csrf_cookie_name,
                    session.cookie_secure,
                ),
            ),
            crate::runtime_modules::inherited_enabled(&settings),
        );
        Self {
            authorization,
            database,
            valkey,
            keyset,
        }
    }

    fn with_valkey(&self, valkey: fred::prelude::Client) -> Self {
        let connection = nazo_valkey::ValkeyConnection::from_existing_client(valkey.clone());
        Self {
            authorization: self.authorization.rebind_storage(
                self.database.clone(),
                &connection,
                self.keyset.clone(),
            ),
            database: self.database.clone(),
            valkey,
            keyset: self.keyset.clone(),
        }
    }
}

struct LiveParFixture {
    par: ParTestFixture,
}

impl LiveParFixture {
    async fn new() -> Option<Self> {
        Self::new_with_settings(|_| {}).await
    }

    async fn new_fapi2_security() -> Option<Self> {
        Self::new_with_settings(|settings| {
            settings.protocol.authorization_server_profile =
                AuthorizationServerProfile::Fapi2Security;
        })
        .await
    }

    async fn new_with_settings(configure: impl FnOnce(&mut Settings)) -> Option<Self> {
        let database_url = std::env::var("DATABASE_URL").ok()?;
        let valkey_url = std::env::var("VALKEY_URL").ok()?;
        let mut settings =
            Settings::from_config(&ConfigSource::default()).expect("test settings should load");
        settings.endpoint.issuer = "https://issuer.example".to_owned();
        settings.protocol.par_ttl_seconds = 90;
        settings.identity.rate_limit.token_management_max_requests = 100_000;
        settings.endpoint.trusted_proxy_cidrs =
            vec![IpCidr::parse("127.0.0.1/32").expect("trusted proxy CIDR should parse")];
        configure(&mut settings);

        let mut valkey_builder = ValkeyBuilder::from_config(
            ValkeyConfig::from_url(&valkey_url).expect("VALKEY_URL should parse"),
        );
        valkey_builder.with_performance_config(|performance: &mut PerformanceConfig| {
            performance.default_command_timeout = std::time::Duration::from_millis(1000);
        });
        valkey_builder.with_connection_config(|connection: &mut ConnectionConfig| {
            connection.connection_timeout = std::time::Duration::from_millis(1000);
            connection.internal_command_timeout = std::time::Duration::from_millis(1000);
            connection.max_command_attempts = 1;
        });
        let valkey = valkey_builder.build().expect("valkey client should build");
        valkey.init().await.expect("valkey should connect");

        Some(Self {
            par: ParTestFixture::new(
                settings,
                create_pool(database_url, 4).expect("database pool should build"),
                valkey,
                crate::test_support::test_key_manager(),
            ),
        })
    }

    fn par_with_unavailable_valkey(&self) -> ParTestFixture {
        self.par.with_valkey(unavailable_valkey_client(50))
    }

    async fn insert_client_secret_post_client(&self, client_id: &str, secret: &str) {
        self.insert_client_secret_post_client_with_options(client_id, secret, false, false, true)
            .await;
    }

    async fn insert_private_key_jwt_client(
        &self,
        client_id: &str,
        jwks: Value,
        allow_endpoint_audience: bool,
    ) {
        self.insert_client_secret_post_client(client_id, &par_test_secret())
            .await;
        let mut conn = get_conn(&self.par.database)
            .await
            .expect("database connection should open");
        sql_query(
            r#"
            UPDATE oauth_clients
            SET client_secret_hash = NULL,
                token_endpoint_auth_method = 'private_key_jwt',
                require_dpop_bound_tokens = true,
                jwks = $1,
                allow_client_assertion_endpoint_audience = $2
            WHERE tenant_id = $3 AND client_id = $4
            "#,
        )
        .bind::<diesel::sql_types::Jsonb, _>(jwks)
        .bind::<Bool, _>(allow_endpoint_audience)
        .bind::<SqlUuid, _>(DEFAULT_TENANT_ID)
        .bind::<Text, _>(client_id)
        .execute(&mut conn)
        .await
        .expect("PAR private_key_jwt client update should succeed");
    }

    async fn set_client_jwks(&self, client_id: &str, jwks: Value) {
        let mut conn = get_conn(&self.par.database)
            .await
            .expect("database connection should open");
        sql_query("UPDATE oauth_clients SET jwks = $1 WHERE tenant_id = $2 AND client_id = $3")
            .bind::<diesel::sql_types::Jsonb, _>(jwks)
            .bind::<SqlUuid, _>(DEFAULT_TENANT_ID)
            .bind::<Text, _>(client_id)
            .execute(&mut conn)
            .await
            .expect("PAR test client jwks update should succeed");
    }

    async fn insert_client_secret_post_client_with_options(
        &self,
        client_id: &str,
        secret: &str,
        require_par_request_object: bool,
        require_mtls_bound_tokens: bool,
        is_active: bool,
    ) {
        let mut conn = get_conn(&self.par.database)
            .await
            .expect("database connection should open");
        sql_query("DELETE FROM oauth_clients WHERE tenant_id = $1 AND client_id = $2")
            .bind::<SqlUuid, _>(DEFAULT_TENANT_ID)
            .bind::<Text, _>(client_id)
            .execute(&mut conn)
            .await
            .expect("PAR test client cleanup should succeed");
        let secret_hash = hash_client_secret(
            secret,
            &self.par.authorization.context().config.client_secret_pepper,
        );
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
                $1, $2, $3, $4, 'PAR Test Client', 'confidential',
                $5, '["https://client.example/callback"]'::jsonb, '["openid","email"]'::jsonb,
                '["resource://default"]'::jsonb,
                '["authorization_code"]'::jsonb, 'client_secret_post', false,
                $6, '[]'::jsonb, '[]'::jsonb,
                '[]'::jsonb, '[]'::jsonb,
                false, false, $7,
                false, $8,
                '[]'::jsonb, true
            )
            "#,
        )
        .bind::<SqlUuid, _>(DEFAULT_TENANT_ID)
        .bind::<SqlUuid, _>(DEFAULT_REALM_ID)
        .bind::<SqlUuid, _>(DEFAULT_ORGANIZATION_ID)
        .bind::<Text, _>(client_id)
        .bind::<Nullable<Text>, _>(Some(secret_hash.as_str()))
        .bind::<Bool, _>(require_mtls_bound_tokens)
        .bind::<Bool, _>(require_par_request_object)
        .bind::<Bool, _>(is_active)
        .execute(&mut conn)
        .await
        .expect("PAR test client insert should succeed");
    }
}

fn par_state_without_live_services() -> ParTestFixture {
    let mut settings =
        Settings::from_config(&ConfigSource::default()).expect("default settings should load");
    settings.identity.rate_limit.token_management_max_requests = 100_000;

    ParTestFixture::new(
        settings,
        create_pool(
            "postgres://nazo_par_test_invalid:nazo_par_test_invalid@127.0.0.1:1/nazo".to_owned(),
            1,
        )
        .expect("pool construction should not connect"),
        unavailable_valkey_client(50),
        crate::test_support::test_key_manager(),
    )
}

fn par_form_request() -> HttpRequest {
    TestRequest::post()
        .uri("/oauth/par")
        .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
        .to_http_request()
}

fn par_form_request_from_trusted_proxy() -> HttpRequest {
    TestRequest::post()
        .uri("/oauth/par")
        .peer_addr("127.0.0.1:443".parse().expect("peer address should parse"))
        .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
        .insert_header(("x-ssl-client-verify", "SUCCESS"))
        .insert_header((
            "x-ssl-client-cert-sha256",
            "00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff",
        ))
        .to_http_request()
}

async fn par_json_body(response: HttpResponse) -> (StatusCode, Value) {
    let status = response.status();
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("PAR response body should collect");
    let value = serde_json::from_slice(&body).expect("PAR error response should be JSON");
    (status, value)
}

#[test]
fn par_policy_does_not_require_request_object_for_dpop_bound_clients() {
    let settings = baseline_settings();

    assert!(!pushed_authorization_request_requires_request_object(
        &settings,
        &client(true)
    ));
}

#[test]
fn par_policy_requires_request_object_when_enabled() {
    let mut policy_client = client(true);
    policy_client.require_par_request_object = true;
    let settings = baseline_settings();

    assert!(!pushed_authorization_request_requires_request_object(
        &settings,
        &client(false)
    ));
    assert!(pushed_authorization_request_requires_request_object(
        &settings,
        &policy_client
    ));
}

#[test]
fn message_signing_profile_requires_request_object_at_par() {
    let mut settings = baseline_settings();
    settings.protocol.authorization_server_profile =
        AuthorizationServerProfile::Fapi2MessageSigningAuthzRequest;
    settings.protocol.require_pushed_authorization_requests = true;

    assert!(pushed_authorization_request_requires_request_object(
        &settings,
        &client(true)
    ));
}

#[test]
fn baseline_profile_does_not_reject_legacy_par_client_auth_combinations() {
    let settings = baseline_settings();
    let mut public_client = client(false);
    public_client.client_type = "public".to_owned();
    public_client.token_endpoint_auth_method = "none".to_owned();

    assert!(
        validate_pushed_authorization_request_profile(&settings, &public_client, "none").is_ok()
    );
}

#[test]
fn fapi2_profile_requires_confidential_clients() {
    let mut settings = baseline_settings();
    settings.protocol.authorization_server_profile = AuthorizationServerProfile::Fapi2Security;
    let mut public_client = client(true);
    public_client.client_type = "public".to_owned();
    public_client.token_endpoint_auth_method = "none".to_owned();

    let response = validate_pushed_authorization_request_profile(&settings, &public_client, "none")
        .expect_err("FAPI2 PAR must reject public clients");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        oauth_error_code(&response).as_deref(),
        Some("unauthorized_client")
    );
}

#[test]
fn fapi2_profile_requires_private_key_jwt_or_mtls_client_auth() {
    let mut settings = baseline_settings();
    settings.protocol.authorization_server_profile = AuthorizationServerProfile::Fapi2Security;
    let mut confidential_client = client(true);
    confidential_client.token_endpoint_auth_method = "client_secret_basic".to_owned();

    let response = validate_pushed_authorization_request_profile(
        &settings,
        &confidential_client,
        "client_secret_basic",
    )
    .expect_err("FAPI2 PAR must reject shared-secret client authentication");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        oauth_error_code(&response).as_deref(),
        Some("invalid_client")
    );

    assert!(
        validate_pushed_authorization_request_profile(
            &settings,
            &confidential_client,
            "private_key_jwt",
        )
        .is_ok()
    );
    assert!(
        validate_pushed_authorization_request_profile(
            &settings,
            &confidential_client,
            "tls_client_auth",
        )
        .is_ok()
    );
}

#[test]
fn fapi2_profile_requires_sender_constrained_tokens() {
    let mut settings = baseline_settings();
    settings.protocol.authorization_server_profile = AuthorizationServerProfile::Fapi2Security;
    let bearer_client = client(false);

    let response =
        validate_pushed_authorization_request_profile(&settings, &bearer_client, "private_key_jwt")
            .expect_err("FAPI2 PAR must reject bearer-only access token clients");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        oauth_error_code(&response).as_deref(),
        Some("invalid_request")
    );
}

#[test]
fn fapi2_profile_requires_explicit_par_redirect_uri_even_when_unambiguous() {
    let mut settings = baseline_settings();
    settings.protocol.authorization_server_profile = AuthorizationServerProfile::Fapi2Security;
    let params = HashMap::from([("response_type".to_owned(), "code".to_owned())]);

    let response = validate_pushed_authorization_request_profile_parameters(&settings, &params)
        .expect_err("FAPI2 PAR must carry redirect_uri explicitly");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        oauth_error_code(&response).as_deref(),
        Some("invalid_request")
    );

    let baseline = baseline_settings();
    assert!(validate_pushed_authorization_request_profile_parameters(&baseline, &params).is_ok());

    let with_redirect = HashMap::from([
        ("response_type".to_owned(), "code".to_owned()),
        (
            "redirect_uri".to_owned(),
            "https://client.example/callback".to_owned(),
        ),
    ]);
    assert!(
        validate_pushed_authorization_request_profile_parameters(&settings, &with_redirect).is_ok()
    );
}

#[test]
fn par_rejects_request_uri_after_request_object_expansion() {
    assert!(!pushed_authorization_request_contains_request_uri(
        &HashMap::new()
    ));

    let mut params = HashMap::new();
    params.insert(
        "request_uri".to_owned(),
        "urn:example:bwc4JK-ESC0w8acc191e-Y1LTC2".to_owned(),
    );
    assert!(pushed_authorization_request_contains_request_uri(&params));
}

#[test]
fn par_rejects_explicit_unsupported_response_type() {
    assert!(!pushed_authorization_request_has_unsupported_response_type(
        &HashMap::new()
    ));

    let mut params = HashMap::new();
    params.insert("response_type".to_owned(), "code".to_owned());
    assert!(!pushed_authorization_request_has_unsupported_response_type(
        &params
    ));

    params.insert("response_type".to_owned(), "code id_token".to_owned());
    assert!(pushed_authorization_request_has_unsupported_response_type(
        &params
    ));
}

#[test]
fn par_validation_binds_request_uri_to_registered_redirect_uri() {
    let mut params = HashMap::from([("response_type".to_owned(), "code".to_owned())]);

    assert!(
        validate_pushed_authorization_request(&client(false), &params).is_ok(),
        "single registered redirect_uri remains unambiguous when omitted"
    );

    let mut multi_redirect_client = client(false);
    multi_redirect_client.redirect_uris = vec![
        "https://client.example/callback".to_owned(),
        "https://client.example/secondary-callback".to_owned(),
    ];
    let missing = validate_pushed_authorization_request(&multi_redirect_client, &params)
        .expect_err("PAR must not mint a request_uri when redirect_uri is ambiguous");
    assert_eq!(missing.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        oauth_error_code(&missing).as_deref(),
        Some("invalid_request")
    );

    params.insert(
        "redirect_uri".to_owned(),
        "https://attacker.example/callback".to_owned(),
    );
    let invalid = validate_pushed_authorization_request(&client(false), &params)
        .expect_err("PAR must bind only pre-registered redirect_uri values");
    assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        oauth_error_code(&invalid).as_deref(),
        Some("invalid_request")
    );

    params.insert(
        "redirect_uri".to_owned(),
        "https://client.example/callback".to_owned(),
    );
    assert!(validate_pushed_authorization_request(&client(false), &params).is_ok());
}

#[actix_web::test]
async fn par_rejects_non_form_content_type_before_client_lookup() {
    let response = par_after_rate_limit(
        &par_state_without_live_services(),
        TestRequest::post()
            .uri("/oauth/par")
            .insert_header((header::CONTENT_TYPE, "application/json"))
            .to_http_request(),
        Bytes::from_static(br#"{"client_id":"client-a"}"#),
    )
    .await;

    let (status, body) = par_json_body(response).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body.get("error"), Some(&json!("invalid_request")));
}

#[actix_web::test]
async fn par_rejects_malformed_or_ambiguous_authorization_parameters_before_client_lookup() {
    let cases: &[&[u8]] = &[
        b"client_id=\xff",
        b"client_id=client-a&request_uri=urn%3Aietf%3Aparams%3Aoauth%3Arequest_uri%3Ax",
        b"client_id=client-a&unsupported=value",
        b"client_id=client-a&client_id=client-b",
        b"response_type=code&redirect_uri=https%3A%2F%2Fclient.example%2Fcallback",
    ];

    for body in cases {
        let response = par_after_rate_limit(
            &par_state_without_live_services(),
            par_form_request(),
            Bytes::copy_from_slice(body),
        )
        .await;
        let (status, value) = par_json_body(response).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(value.get("error"), Some(&json!("invalid_request")));
    }
}

#[actix_web::test]
async fn par_rejects_disabled_request_object_before_client_lookup() {
    let response = par_after_rate_limit(
        &par_state_without_live_services(),
        par_form_request(),
        Bytes::from_static(b"client_id=client-a&response_type=code&request=jwt"),
    )
    .await;

    let (status, value) = par_json_body(response).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(value.get("error"), Some(&json!("invalid_request")));
}

#[actix_web::test]
async fn par_rejects_disabled_authorization_details_before_client_lookup() {
    let response = par_after_rate_limit(
        &par_state_without_live_services(),
        par_form_request(),
        Bytes::from_static(b"client_id=client-a&response_type=code&authorization_details=%5B%5D"),
    )
    .await;

    let (status, value) = par_json_body(response).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(value.get("error"), Some(&json!("invalid_request")));
}

#[actix_web::test]
async fn par_rate_limit_failure_short_circuits_before_client_lookup() {
    let response = par(
        &par_state_without_live_services(),
        par_form_request(),
        Bytes::from_static(b"client_id=client-a&client_secret=secret&response_type=code"),
    )
    .await;

    let (status, value) = par_json_body(response).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(value.get("error"), Some(&json!("server_error")));
}

#[actix_web::test]
async fn par_returns_invalid_client_for_unknown_or_inactive_client() {
    let Some(fixture) = LiveParFixture::new().await else {
        return;
    };
    let unknown_client_id = format!("par-missing-{}", Uuid::now_v7().simple());
    let unknown = Bytes::from(format!(
        "client_id={}&client_secret=secret&response_type=code&redirect_uri=https%3A%2F%2Fclient.example%2Fcallback",
        urlencoding::encode(&unknown_client_id)
    ));

    let response = par_after_rate_limit(&fixture.par, par_form_request(), unknown).await;
    let (status, value) = par_json_body(response).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(value.get("error"), Some(&json!("invalid_client")));
    assert!(value.get("request_uri").is_none());

    let inactive_client_id = format!("par-inactive-{}", Uuid::now_v7().simple());
    let secret = par_test_secret();
    fixture
        .insert_client_secret_post_client_with_options(
            &inactive_client_id,
            &secret,
            false,
            false,
            false,
        )
        .await;
    let inactive = Bytes::from(format!(
        "client_id={}&client_secret={}&response_type=code&redirect_uri=https%3A%2F%2Fclient.example%2Fcallback",
        urlencoding::encode(&inactive_client_id),
        urlencoding::encode(&secret)
    ));

    let response = par_after_rate_limit(&fixture.par, par_form_request(), inactive).await;
    let (status, value) = par_json_body(response).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(value.get("error"), Some(&json!("invalid_client")));
    assert!(value.get("request_uri").is_none());
}

#[actix_web::test]
async fn par_client_lookup_failure_is_server_error_not_invalid_client() {
    let response = par_after_rate_limit(
        &par_state_without_live_services(),
        par_form_request(),
        Bytes::from_static(
            b"client_id=client-a&client_secret=secret&response_type=code&redirect_uri=https%3A%2F%2Fclient.example%2Fcallback",
        ),
    )
    .await;

    let (status, value) = par_json_body(response).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(value.get("error"), Some(&json!("server_error")));
    assert!(value.get("request_uri").is_none());
}

#[actix_web::test]
async fn par_enforces_client_request_object_policy_after_authentication() {
    let Some(fixture) = LiveParFixture::new().await else {
        return;
    };
    let client_id = format!("par-require-jar-{}", Uuid::now_v7().simple());
    let secret = par_test_secret();
    fixture
        .insert_client_secret_post_client_with_options(&client_id, &secret, true, false, true)
        .await;
    let body = Bytes::from(format!(
        "client_id={}&client_secret={}&response_type=code&redirect_uri=https%3A%2F%2Fclient.example%2Fcallback",
        urlencoding::encode(&client_id),
        urlencoding::encode(&secret)
    ));

    let response = par_after_rate_limit(&fixture.par, par_form_request(), body).await;
    let (status, value) = par_json_body(response).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(value.get("error"), Some(&json!("invalid_request")));
    assert!(value.get("request_uri").is_none());
}

#[actix_web::test]
async fn par_fapi2_rejects_shared_secret_client_auth_after_authentication() {
    let Some(fixture) = LiveParFixture::new_fapi2_security().await else {
        return;
    };
    let client_id = format!("par-fapi-secret-{}", Uuid::now_v7().simple());
    let secret = par_test_secret();
    fixture
        .insert_client_secret_post_client_with_options(&client_id, &secret, false, true, true)
        .await;
    let body = Bytes::from(format!(
        "client_id={}&client_secret={}&response_type=code&redirect_uri=https%3A%2F%2Fclient.example%2Fcallback",
        urlencoding::encode(&client_id),
        urlencoding::encode(&secret)
    ));

    let response = par_after_rate_limit(&fixture.par, par_form_request(), body).await;
    let (status, value) = par_json_body(response).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(value.get("error"), Some(&json!("invalid_client")));
    assert!(value.get("request_uri").is_none());
}

#[actix_web::test]
async fn par_rejects_endpoint_url_client_assertion_audiences_as_oauth_errors() {
    let Some(fixture) = LiveParFixture::new_with_settings(|settings| {
        settings.protocol.authorization_server_profile =
            AuthorizationServerProfile::Fapi2MessageSigningAuthzRequest;
    })
    .await
    else {
        return;
    };
    let client_id = format!("par-private-key-audience-{}", Uuid::now_v7().simple());
    let key = client_signing_fixture(jsonwebtoken::Algorithm::PS256);
    fixture
        .insert_private_key_jwt_client(
            &client_id,
            json!({"keys": [key.public_jwk("par-client-assertion-kid")]}),
            false,
        )
        .await;

    for audience in ["https://issuer.example/par", "https://issuer.example/token"] {
        let assertion = private_key_client_assertion(&client_id, audience, &key);
        let body = Bytes::from(format!(
            "client_id={}&client_assertion_type={}&client_assertion={}&response_type=code&redirect_uri=https%3A%2F%2Fclient.example%2Fcallback",
            urlencoding::encode(&client_id),
            urlencoding::encode(nazo_auth::CLIENT_ASSERTION_TYPE_JWT_BEARER),
            urlencoding::encode(&assertion),
        ));
        let response = par_after_rate_limit(
            &fixture.par,
            TestRequest::post()
                .uri("/par")
                .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
                .to_http_request(),
            body,
        )
        .await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("application/json")
        );
        assert!(response.headers().get(header::WWW_AUTHENTICATE).is_none());
        let (_, value) = par_json_body(response).await;
        assert_eq!(value.get("error"), Some(&json!("invalid_client")));
        assert!(value.get("error_description").is_some_and(Value::is_string));
        assert!(value.get("request_uri").is_none());
    }
}

#[actix_web::test]
async fn par_rejects_invalid_dpop_jkt_after_client_authentication() {
    let Some(fixture) = LiveParFixture::new().await else {
        return;
    };
    let client_id = format!("par-invalid-dpop-jkt-{}", Uuid::now_v7().simple());
    let secret = par_test_secret();
    fixture
        .insert_client_secret_post_client(&client_id, &secret)
        .await;
    let body = Bytes::from(format!(
        "client_id={}&client_secret={}&response_type=code&redirect_uri=https%3A%2F%2Fclient.example%2Fcallback&dpop_jkt=not-a-jwk-thumbprint",
        urlencoding::encode(&client_id),
        urlencoding::encode(&secret)
    ));

    let response = par_after_rate_limit(&fixture.par, par_form_request(), body).await;
    let (status, value) = par_json_body(response).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(value.get("error"), Some(&json!("invalid_request")));
    assert!(value.get("request_uri").is_none());
}

#[actix_web::test]
async fn par_rejects_request_uri_from_request_object_after_client_authentication() {
    let Some(fixture) = LiveParFixture::new_with_settings(|s| {
        s.modules.enable_par_request_object = true;
    })
    .await
    else {
        return;
    };
    let client_id = format!("par-request-object-uri-{}", Uuid::now_v7().simple());
    let secret = par_test_secret();
    fixture
        .insert_client_secret_post_client(&client_id, &secret)
        .await;
    let key = client_signing_fixture(jsonwebtoken::Algorithm::RS256);
    let public_jwk = key.public_jwk("par-request-object-kid");
    fixture
        .set_client_jwks(&client_id, json!({"keys": [public_jwk]}))
        .await;
    let request_object = signed_request_object(
        &client_id,
        &key,
        json!({
            "request_uri": "urn:ietf:params:oauth:request_uri:attacker"
        }),
    );
    let body = Bytes::from(format!(
        "client_id={}&client_secret={}&request={}",
        urlencoding::encode(&client_id),
        urlencoding::encode(&secret),
        urlencoding::encode(&request_object)
    ));

    let response = par_after_rate_limit(&fixture.par, par_form_request(), body).await;
    let (status, value) = par_json_body(response).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(value.get("error"), Some(&json!("invalid_request_object")));
    assert!(value.get("request_uri").is_none());
}

#[actix_web::test]
async fn par_rejects_unsigned_request_object_without_outer_client_id_as_request_object_error() {
    let Some(fixture) = LiveParFixture::new_with_settings(|s| {
        s.modules.enable_par_request_object = true;
    })
    .await
    else {
        return;
    };
    let client_id = format!("par-unsigned-request-object-{}", Uuid::now_v7().simple());
    let secret = par_test_secret();
    fixture
        .insert_client_secret_post_client(&client_id, &secret)
        .await;
    let request_object = unsigned_request_object(&client_id);
    let body = Bytes::from(format!(
        "client_secret={}&request={}",
        urlencoding::encode(&secret),
        urlencoding::encode(&request_object)
    ));

    let response = par_after_rate_limit(&fixture.par, par_form_request(), body).await;
    let (status, value) = par_json_body(response).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(value.get("error"), Some(&json!("invalid_request_object")));
    assert!(value.get("request_uri").is_none());
}

#[actix_web::test]
async fn par_rejects_authorization_details_from_request_object_when_disabled() {
    let Some(fixture) = LiveParFixture::new_with_settings(|settings| {
        settings.modules.enable_par_request_object = true;
        settings.modules.enable_authorization_details = false;
    })
    .await
    else {
        return;
    };
    let client_id = format!(
        "par-request-object-rar-disabled-{}",
        Uuid::now_v7().simple()
    );
    let secret = par_test_secret();
    fixture
        .insert_client_secret_post_client(&client_id, &secret)
        .await;
    let key = client_signing_fixture(jsonwebtoken::Algorithm::RS256);
    let public_jwk = key.public_jwk("par-request-object-kid");
    fixture
        .set_client_jwks(&client_id, json!({"keys": [public_jwk]}))
        .await;
    let request_object = signed_request_object(
        &client_id,
        &key,
        json!({
            "authorization_details": [{"type": "account_information", "actions": ["read"]}]
        }),
    );
    let body = Bytes::from(format!(
        "client_id={}&client_secret={}&request={}",
        urlencoding::encode(&client_id),
        urlencoding::encode(&secret),
        urlencoding::encode(&request_object)
    ));

    let response = par_after_rate_limit(&fixture.par, par_form_request(), body).await;
    let (status, value) = par_json_body(response).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(value.get("error"), Some(&json!("invalid_request")));
    assert!(value.get("request_uri").is_none());
}

#[actix_web::test]
async fn par_rejects_unsupported_response_type_after_client_authentication() {
    let Some(fixture) = LiveParFixture::new().await else {
        return;
    };
    let client_id = format!("par-unsupported-response-{}", Uuid::now_v7().simple());
    let secret = par_test_secret();
    fixture
        .insert_client_secret_post_client(&client_id, &secret)
        .await;
    let body = Bytes::from(format!(
        "client_id={}&client_secret={}&response_type=token&redirect_uri=https%3A%2F%2Fclient.example%2Fcallback",
        urlencoding::encode(&client_id),
        urlencoding::encode(&secret)
    ));

    let response = par_after_rate_limit(&fixture.par, par_form_request(), body).await;
    let (status, value) = par_json_body(response).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        value.get("error"),
        Some(&json!("unsupported_response_type"))
    );
    assert!(value.get("request_uri").is_none());
}

#[actix_web::test]
async fn par_persists_mtls_thumbprint_for_sender_constrained_request_uri() {
    let Some(fixture) = LiveParFixture::new().await else {
        return;
    };
    let client_id = format!("par-mtls-success-{}", Uuid::now_v7().simple());
    let secret = par_test_secret();
    fixture
        .insert_client_secret_post_client_with_options(&client_id, &secret, false, true, true)
        .await;
    let body = Bytes::from(format!(
        "client_id={}&client_secret={}&response_type=code&redirect_uri=https%3A%2F%2Fclient.example%2Fcallback&scope=openid",
        urlencoding::encode(&client_id),
        urlencoding::encode(&secret)
    ));

    let response =
        par_after_rate_limit(&fixture.par, par_form_request_from_trusted_proxy(), body).await;
    let (status, value) = par_json_body(response).await;

    assert_eq!(status, StatusCode::CREATED);
    let request_uri = value["request_uri"]
        .as_str()
        .expect("PAR success should return request_uri");
    let raw = valkey_get(
        &fixture.par.valkey,
        pushed_authorization_request_key(request_uri),
    )
    .await
    .expect("PAR payload should be readable")
    .expect("PAR payload should be persisted");
    let stored =
        serde_json::from_str::<PushedAuthorizationRequest>(&raw).expect("PAR payload should parse");
    assert_eq!(
        stored.mtls_x5t_s256.as_deref(),
        Some("ABEiM0RVZneImaq7zN3u_wARIjNEVWZ3iJmqu8zd7v8"),
        "mTLS-bound PAR state should persist the normalized certificate thumbprint"
    );
}

#[actix_web::test]
async fn par_fails_closed_when_request_uri_persistence_fails() {
    let Some(fixture) = LiveParFixture::new().await else {
        return;
    };
    let client_id = format!("par-valkey-failure-{}", Uuid::now_v7().simple());
    let secret = par_test_secret();
    fixture
        .insert_client_secret_post_client(&client_id, &secret)
        .await;
    let body = Bytes::from(format!(
        "client_id={}&client_secret={}&response_type=code&redirect_uri=https%3A%2F%2Fclient.example%2Fcallback",
        urlencoding::encode(&client_id),
        urlencoding::encode(&secret)
    ));

    let response = par_after_rate_limit(
        &fixture.par_with_unavailable_valkey(),
        par_form_request(),
        body,
    )
    .await;
    let (status, value) = par_json_body(response).await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(value.get("error"), Some(&json!("server_error")));
    assert!(value.get("request_uri").is_none());
}

#[actix_web::test]
async fn par_success_persists_request_uri_without_client_secret_material() {
    let Some(fixture) = LiveParFixture::new().await else {
        return;
    };
    let client_id = format!("par-success-{}", Uuid::now_v7().simple());
    let secret = par_test_secret();
    fixture
        .insert_client_secret_post_client(&client_id, &secret)
        .await;
    let body = Bytes::from(format!(
        "client_id={}&client_secret={}&response_type=code&redirect_uri=https%3A%2F%2Fclient.example%2Fcallback&scope=openid+email&state=par-state&dpop_jkt=w7JAoU_gJbZJvV-zCOvU9yFJq0FNC_edCMRM78P8eQQ",
        urlencoding::encode(&client_id),
        urlencoding::encode(&secret)
    ));

    let response = par_after_rate_limit(&fixture.par, par_form_request(), body).await;
    let (status, value) = par_json_body(response).await;

    assert_eq!(status, StatusCode::CREATED);
    let request_uri = value["request_uri"]
        .as_str()
        .expect("PAR success should return request_uri");
    assert!(request_uri.starts_with("urn:ietf:params:oauth:request_uri:"));
    assert_eq!(
        value["expires_in"],
        json!(fixture.par.authorization.context().config.par_ttl_seconds)
    );

    let raw = valkey_get(
        &fixture.par.valkey,
        pushed_authorization_request_key(request_uri),
    )
    .await
    .expect("PAR payload should be readable")
    .expect("PAR payload should be persisted");
    assert!(
        !raw.contains("client_secret"),
        "PAR storage must not retain client authentication secret material"
    );
    let stored =
        serde_json::from_str::<PushedAuthorizationRequest>(&raw).expect("PAR payload should parse");
    assert_eq!(stored.client_id, client_id);
    assert_eq!(
        stored.params.get("redirect_uri").map(String::as_str),
        Some("https://client.example/callback")
    );
    assert_eq!(
        stored.dpop_jkt.as_deref(),
        Some("w7JAoU_gJbZJvV-zCOvU9yFJq0FNC_edCMRM78P8eQQ")
    );
}
