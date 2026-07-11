use super::*;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use diesel::sql_query;
use diesel::sql_types::{Bool, Jsonb, Nullable, Text, Uuid as SqlUuid};
use diesel_async::RunQueryDsl;
use fred::interfaces::ClientLike;
use fred::prelude::{
    Builder as ValkeyBuilder, Config as ValkeyConfig, ConnectionConfig, PerformanceConfig,
};
use std::sync::Arc;
use std::time::Duration as StdDuration;

use crate::config::ConfigSource;
use crate::db::{create_pool, get_conn};
use crate::domain::{ActiveSigningKey, Keyset, KeysetStore, UserRow, VerificationKey};
use crate::support::{generate_key_material, oidc_subject, public_jwk_from_private_der};

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

fn test_state() -> AppState {
    AppState {
        diesel_db: create_pool(
            "postgres://nazo_auth_code_test_invalid:nazo_auth_code_test_invalid@127.0.0.1:1/nazo"
                .to_owned(),
            1,
        )
        .expect("pool construction should not connect"),
        valkey: unavailable_valkey_client(),
        settings: Arc::new(
            Settings::from_config(&ConfigSource::default()).expect("default settings should load"),
        ),
        keyset: KeysetStore::new(Keyset {
            active_kid: "test-kid".to_owned(),
            active_alg: jsonwebtoken::Algorithm::EdDSA,
            active_signing_key: ActiveSigningKey::LocalPkcs8Der(Vec::new()),
            verification_keys: Vec::new(),
        }),
    }
}

fn pkce_policy_client() -> ClientRow {
    ClientRow {
        id: Uuid::now_v7(),
        tenant_id: DEFAULT_TENANT_ID,
        realm_id: DEFAULT_REALM_ID,
        organization_id: DEFAULT_ORGANIZATION_ID,
        client_id: "client-1".to_owned(),
        client_name: "Client".to_owned(),
        client_type: "confidential".to_owned(),
        client_secret_hash: None,
        redirect_uris: json!(["https://client.example/callback"]),
        scopes: json!(["openid"]),
        allowed_audiences: json!(["resource://default"]),
        grant_types: json!(["authorization_code"]),
        token_endpoint_auth_method: "client_secret_basic".to_owned(),
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

const VALID_CODE_VERIFIER: &str =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~";

fn code_payload(redirect_uri_was_supplied: bool) -> CodePayload {
    let now = Utc::now();
    CodePayload {
        code_id: "code-1".to_owned(),
        user_id: Uuid::now_v7(),
        client_id: "client-1".to_owned(),
        redirect_uri: "https://client.example/callback".to_owned(),
        redirect_uri_was_supplied,
        scopes: vec!["openid".to_owned()],
        resource_indicators: Vec::new(),
        authorization_details: json!([]),
        nonce: None,
        auth_time: now.timestamp(),
        amr: vec!["password".to_owned()],
        oidc_sid: Some("sid-1".to_owned()),
        acr: None,
        userinfo_claims: Vec::new(),
        userinfo_claim_requests: Vec::new(),
        id_token_claims: Vec::new(),
        id_token_claim_requests: Vec::new(),
        code_challenge: Some("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ".to_owned()),
        code_challenge_method: Some("S256".to_owned()),
        dpop_jkt: None,
        mtls_x5t_s256: None,
        issued_at: now,
        expires_at: now + Duration::seconds(300),
    }
}

struct LiveAuthorizationCodeFixture {
    state: Data<AppState>,
}

impl LiveAuthorizationCodeFixture {
    async fn new() -> Option<Self> {
        let settings = Self::settings();
        Self::new_with_settings_and_keyset(
            settings,
            Keyset {
                active_kid: "test-kid".to_owned(),
                active_alg: jsonwebtoken::Algorithm::EdDSA,
                active_signing_key: ActiveSigningKey::LocalPkcs8Der(Vec::new()),
                verification_keys: Vec::new(),
            },
        )
        .await
    }

    fn settings() -> Settings {
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
        settings.trusted_proxy_cidrs = vec![
            crate::support::IpCidr::parse("127.0.0.1/32").expect("trusted proxy CIDR should parse"),
        ];
        settings
    }

    async fn new_with_settings_and_keyset(settings: Settings, keyset: Keyset) -> Option<Self> {
        let database_url = std::env::var("DATABASE_URL").ok()?;
        let valkey_url = std::env::var("VALKEY_URL").ok()?;
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
            state: Data::new(AppState {
                diesel_db: create_pool(database_url, 4).expect("database pool should build"),
                valkey,
                settings: Arc::new(settings),
                keyset: KeysetStore::new(keyset),
            }),
        })
    }

    async fn insert_client(&self, client: &ClientRow) {
        let mut conn = get_conn(&self.state.diesel_db)
            .await
            .expect("database connection");
        sql_query("DELETE FROM oauth_clients WHERE tenant_id = $1 AND client_id = $2")
            .bind::<SqlUuid, _>(DEFAULT_TENANT_ID)
            .bind::<Text, _>(client.client_id.as_str())
            .execute(&mut conn)
            .await
            .expect("test client cleanup should succeed");

        sql_query(
            r#"
            INSERT INTO oauth_clients (
                id, tenant_id, realm_id, organization_id, client_id, client_name, client_type,
                client_secret_hash, redirect_uris, scopes, allowed_audiences,
                grant_types, token_endpoint_auth_method, require_dpop_bound_tokens,
                require_mtls_bound_tokens, tls_client_auth_subject_dn, tls_client_auth_cert_sha256,
                tls_client_auth_san_dns, tls_client_auth_san_uri, tls_client_auth_san_ip,
                tls_client_auth_san_email, allow_client_assertion_audience_array,
                allow_client_assertion_endpoint_audience, require_par_request_object,
                allow_authorization_code_without_pkce, is_active, jwks,
                post_logout_redirect_uris, backchannel_logout_uri,
                backchannel_logout_session_required, subject_type, sector_identifier_uri,
                sector_identifier_host
            )
            VALUES (
                $1, $2, $3, $4, $5, $6, $7,
                $8, $9, $10, $11,
                $12, $13, $14,
                $15, NULL, NULL,
                '[]'::jsonb, '[]'::jsonb, '[]'::jsonb,
                '[]'::jsonb, false,
                false, false,
                $16, $17, NULL,
                '[]'::jsonb, NULL,
                true, $18, $19, $20
            )
            "#,
        )
        .bind::<SqlUuid, _>(client.id)
        .bind::<SqlUuid, _>(client.tenant_id)
        .bind::<SqlUuid, _>(client.realm_id)
        .bind::<SqlUuid, _>(client.organization_id)
        .bind::<Text, _>(client.client_id.as_str())
        .bind::<Text, _>(client.client_name.as_str())
        .bind::<Text, _>(client.client_type.as_str())
        .bind::<Nullable<Text>, _>(client.client_secret_hash.as_deref())
        .bind::<Jsonb, _>(client.redirect_uris.clone())
        .bind::<Jsonb, _>(client.scopes.clone())
        .bind::<Jsonb, _>(client.allowed_audiences.clone())
        .bind::<Jsonb, _>(client.grant_types.clone())
        .bind::<Text, _>(client.token_endpoint_auth_method.as_str())
        .bind::<Bool, _>(client.require_dpop_bound_tokens)
        .bind::<Bool, _>(client.require_mtls_bound_tokens)
        .bind::<Bool, _>(client.allow_authorization_code_without_pkce)
        .bind::<Bool, _>(client.is_active)
        .bind::<Text, _>(client.subject_type.as_str())
        .bind::<Nullable<Text>, _>(client.sector_identifier_uri.as_deref())
        .bind::<Nullable<Text>, _>(client.sector_identifier_host.as_deref())
        .execute(&mut conn)
        .await
        .expect("test client insert should succeed");
    }

    async fn insert_user(&self) -> UserRow {
        let suffix = Uuid::now_v7();
        let mut conn = get_conn(&self.state.diesel_db)
            .await
            .expect("database connection");
        sql_query(
            r#"
            INSERT INTO users (
                id, tenant_id, realm_id, organization_id, username, email,
                password_hash, is_active, mfa_enabled, email_verified, role, admin_level
            )
            VALUES (
                $1, $2, $3, $4, $5, $6,
                'unused-auth-code-test-hash', true, false, true, 'user', 0
            )
            RETURNING *
            "#,
        )
        .bind::<SqlUuid, _>(suffix)
        .bind::<SqlUuid, _>(DEFAULT_TENANT_ID)
        .bind::<SqlUuid, _>(DEFAULT_REALM_ID)
        .bind::<SqlUuid, _>(DEFAULT_ORGANIZATION_ID)
        .bind::<Text, _>(format!("auth-code-{suffix}"))
        .bind::<Text, _>(format!("auth-code-{suffix}@example.com"))
        .get_result::<UserRow>(&mut conn)
        .await
        .expect("test user should insert")
    }

    async fn store_code_state(&self, code: &str, state: &AuthorizationCodeState) {
        valkey_set_ex(
            &self.state.valkey,
            authorization_code_key(code),
            serde_json::to_string(state).expect("authorization code state should serialize"),
            self.state.settings.auth_code_ttl_seconds,
        )
        .await
        .expect("authorization code state should store");
    }

    async fn store_raw_code_state(&self, code: &str, raw: &str) {
        valkey_set_ex(
            &self.state.valkey,
            authorization_code_key(code),
            raw.to_owned(),
            self.state.settings.auth_code_ttl_seconds,
        )
        .await
        .expect("raw authorization code state should store");
    }

    async fn code_state(&self, code: &str) -> AuthorizationCodeState {
        let raw = valkey_get(&self.state.valkey, authorization_code_key(code))
            .await
            .expect("authorization code lookup should succeed")
            .expect("authorization code state should exist");
        serde_json::from_str(&raw).expect("authorization code state should deserialize")
    }

    async fn insert_refresh_token(&self, client: &ClientRow, family_id: Uuid) {
        let mut conn = get_conn(&self.state.diesel_db)
            .await
            .expect("database connection");
        sql_query(
            r#"
            INSERT INTO oauth_tokens (
                id, tenant_id, refresh_token_blake3, token_family_id, rotated_from_id,
                client_id, user_id, scopes, authorization_details, issued_at, expires_at,
                revoked_at, reuse_detected_at, subject, dpop_jkt, mtls_x5t_s256
            )
            VALUES (
                $1, $2, $3, $4, NULL,
                $5, $6, '["openid","offline_access"]'::jsonb, '[]'::jsonb, now(),
                now() + interval '1 day', NULL, NULL, 'subject-1', NULL, NULL
            )
            "#,
        )
        .bind::<SqlUuid, _>(Uuid::now_v7())
        .bind::<SqlUuid, _>(client.tenant_id)
        .bind::<Text, _>(blake3_hex("refresh-token-1"))
        .bind::<SqlUuid, _>(family_id)
        .bind::<SqlUuid, _>(client.id)
        .bind::<Nullable<SqlUuid>, _>(None::<Uuid>)
        .execute(&mut conn)
        .await
        .expect("refresh token row should insert");
    }

    async fn access_token_revocation_count(
        &self,
        client: &ClientRow,
        access_token_jti: &str,
    ) -> i64 {
        let mut conn = get_conn(&self.state.diesel_db)
            .await
            .expect("database connection");
        access_token_revocations::table
            .filter(access_token_revocations::tenant_id.eq(client.tenant_id))
            .filter(access_token_revocations::client_id.eq(client.id))
            .filter(
                access_token_revocations::access_token_jti_blake3.eq(blake3_hex(access_token_jti)),
            )
            .count()
            .get_result::<i64>(&mut conn)
            .await
            .expect("access token revocation count should load")
    }

    async fn refresh_token_revoked_at(
        &self,
        client: &ClientRow,
        family_id: Uuid,
    ) -> Option<DateTime<Utc>> {
        let mut conn = get_conn(&self.state.diesel_db)
            .await
            .expect("database connection");
        oauth_tokens::table
            .filter(oauth_tokens::tenant_id.eq(client.tenant_id))
            .filter(oauth_tokens::client_id.eq(client.id))
            .filter(oauth_tokens::token_family_id.eq(family_id))
            .select(oauth_tokens::revoked_at)
            .first::<Option<DateTime<Utc>>>(&mut conn)
            .await
            .expect("refresh token row should load")
    }
}

fn valid_keyset(kid: &str) -> Keyset {
    let key_material =
        generate_key_material(jsonwebtoken::Algorithm::RS256).expect("test key should generate");
    let public_jwk = public_jwk_from_private_der(
        kid,
        jsonwebtoken::Algorithm::RS256,
        &key_material.private_pkcs8_der,
    )
    .expect("test public JWK should derive");
    Keyset {
        active_kid: kid.to_owned(),
        active_alg: jsonwebtoken::Algorithm::RS256,
        active_signing_key: ActiveSigningKey::LocalPkcs8Der(key_material.private_pkcs8_der),
        verification_keys: vec![VerificationKey {
            kid: kid.to_owned(),
            public_jwk,
            local_signing_key: None,
        }],
    }
}

fn live_client(client_id: &str) -> ClientRow {
    let mut client = pkce_policy_client();
    client.id = Uuid::now_v7();
    client.client_id = client_id.to_owned();
    client.client_name = "Live Token Client".to_owned();
    client.grant_types = json!(["authorization_code", "refresh_token"]);
    client.allowed_audiences = json!(["resource://default"]);
    client.redirect_uris = json!(["https://client.example/callback"]);
    client.allow_authorization_code_without_pkce = true;
    client
}

fn payload_for_client(client: &ClientRow) -> CodePayload {
    let mut payload = code_payload(true);
    payload.client_id = client.client_id.clone();
    payload.code_challenge = Some(pkce_s256(VALID_CODE_VERIFIER));
    payload.code_challenge_method = Some("S256".to_owned());
    payload.redirect_uri = "https://client.example/callback".to_owned();
    payload.redirect_uri_was_supplied = true;
    payload.scopes = vec!["openid".to_owned()];
    payload
}

fn form_for_code(code: &str) -> TokenForm {
    TokenForm {
        grant_type: "authorization_code".to_owned(),
        code: Some(code.to_owned()),
        device_code: None,
        auth_req_id: None,
        redirect_uri: Some("https://client.example/callback".to_owned()),
        code_verifier: Some(VALID_CODE_VERIFIER.to_owned()),
        refresh_token: None,
        device_secret: None,
        scope: None,
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
        audiences: Vec::new(),
        has_audience_param: false,
    }
}

#[test]
fn authorization_code_audiences_inherit_authorized_resources_when_token_request_omits_resource() {
    let settings = Settings::from_config(&ConfigSource::default()).unwrap();
    let mut payload = code_payload(true);
    payload.resource_indicators = vec![
        "https://api.example/one".to_owned(),
        "https://api.example/two".to_owned(),
    ];
    let form = form_for_code("code-1");

    assert_eq!(
        authorization_code_audiences(&settings, &payload, &form).unwrap(),
        payload.resource_indicators
    );
}

#[test]
fn authorization_code_audiences_allow_token_request_to_narrow_authorized_resources() {
    let settings = Settings::from_config(&ConfigSource::default()).unwrap();
    let mut payload = code_payload(true);
    payload.resource_indicators = vec![
        "https://api.example/one".to_owned(),
        "https://api.example/two".to_owned(),
    ];
    let mut form = form_for_code("code-1");
    form.audiences = vec!["https://api.example/two".to_owned()];

    assert_eq!(
        authorization_code_audiences(&settings, &payload, &form).unwrap(),
        vec!["https://api.example/two".to_owned()]
    );
}

#[test]
fn authorization_code_audiences_reject_token_request_resource_outside_authorization() {
    let settings = Settings::from_config(&ConfigSource::default()).unwrap();
    let mut payload = code_payload(true);
    payload.resource_indicators = vec!["https://api.example/one".to_owned()];
    let mut form = form_for_code("code-1");
    form.audiences = vec!["https://api.example/two".to_owned()];

    assert!(authorization_code_audiences(&settings, &payload, &form).is_err());
}

async fn token_json_body(response: HttpResponse) -> (StatusCode, Value) {
    let status = response.status();
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("response body should be readable");
    let value = serde_json::from_slice(&body).expect("response should be JSON");
    (status, value)
}

fn jwt_payload(token: &str) -> Value {
    let payload = token
        .split('.')
        .nth(1)
        .expect("JWT should contain a payload segment");
    let decoded = URL_SAFE_NO_PAD
        .decode(payload)
        .expect("JWT payload should be base64url");
    serde_json::from_slice(&decoded).expect("JWT payload should be JSON")
}

#[actix_web::test]
async fn token_authorization_code_uses_client_pairwise_subject_sector() {
    let mut settings = LiveAuthorizationCodeFixture::settings();
    settings.pairwise_subject_secret = Some("0123456789012345678901234567890123456789".to_owned());
    let Some(fixture) = LiveAuthorizationCodeFixture::new_with_settings_and_keyset(
        settings,
        valid_keyset("auth-code-pairwise-test-kid"),
    )
    .await
    else {
        return;
    };

    let user = fixture.insert_user().await;
    let mut client = live_client(&format!("client-pairwise-{}", Uuid::now_v7()));
    client.subject_type = "pairwise".to_owned();
    client.sector_identifier_host = Some("registered-sector.example".to_owned());
    fixture.insert_client(&client).await;

    let mut payload = payload_for_client(&client);
    payload.user_id = user.id;
    payload.scopes = vec!["openid".to_owned()];
    let code = format!("code-{}", Uuid::now_v7());
    fixture
        .store_code_state(&code, &AuthorizationCodeState::Pending { payload })
        .await;

    let req = actix_web::test::TestRequest::post()
        .uri("/token")
        .to_http_request();
    let mut form = form_for_code(&code);
    form.client_id = Some(client.client_id.clone());
    let response = token_authorization_code(&fixture.state, &req, &client, &form, None).await;
    let (status, body) = token_json_body(response).await;

    assert_eq!(status, StatusCode::OK, "unexpected token response: {body}");
    let expected_subject = oidc_subject(
        fixture
            .state
            .settings
            .pairwise_subject_secret
            .as_ref()
            .expect("pairwise secret should be configured")
            .as_bytes(),
        &fixture.state.settings.issuer,
        "registered-sector.example",
        user.id,
    );
    assert_ne!(expected_subject, user.id.to_string());
    assert_eq!(
        jwt_payload(
            body["access_token"]
                .as_str()
                .expect("access token should be returned")
        )["sub"],
        json!(expected_subject)
    );
    assert_eq!(
        jwt_payload(
            body["id_token"]
                .as_str()
                .expect("id token should be returned")
        )["sub"],
        json!(expected_subject)
    );
}

#[actix_web::test]
async fn token_authorization_code_fails_closed_when_pairwise_secret_is_missing() {
    let Some(fixture) = LiveAuthorizationCodeFixture::new_with_settings_and_keyset(
        LiveAuthorizationCodeFixture::settings(),
        valid_keyset("auth-code-subject-policy-test-kid"),
    )
    .await
    else {
        return;
    };

    let user = fixture.insert_user().await;
    let mut client = live_client(&format!("client-subject-policy-{}", Uuid::now_v7()));
    client.subject_type = "pairwise".to_owned();
    client.sector_identifier_host = Some("registered-sector.example".to_owned());
    fixture.insert_client(&client).await;

    let mut payload = payload_for_client(&client);
    payload.user_id = user.id;
    payload.scopes = vec!["openid".to_owned()];
    let code = format!("code-{}", Uuid::now_v7());
    fixture
        .store_code_state(&code, &AuthorizationCodeState::Pending { payload })
        .await;

    let req = actix_web::test::TestRequest::post()
        .uri("/token")
        .to_http_request();
    let mut form = form_for_code(&code);
    form.client_id = Some(client.client_id.clone());
    let response = token_authorization_code(&fixture.state, &req, &client, &form, None).await;

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(oauth_error_code(&response), "server_error");
    match fixture.code_state(&code).await {
        AuthorizationCodeState::Failed { error, .. } => {
            assert_eq!(error, "subject_policy_invalid");
        }
        _ => panic!("invalid subject policy should mark the authorization code as failed"),
    }
}

#[test]
fn authorization_code_token_issue_preserves_independent_oidc_sid() {
    let payload = code_payload(true);
    let auth_time = payload.auth_time;

    let issue = token_issue_from_authorization_code(AuthorizationCodeIssueInput {
        payload,
        subject: "subject-1".to_owned(),
        audiences: vec!["resource://default".to_owned()],
        dpop_jkt: Some("dpop-jkt".to_owned()),
        mtls_x5t_s256: Some("mtls-thumbprint".to_owned()),
        code_hash: "code-hash".to_owned(),
        refresh_token_dpop_jkt: Some("refresh-dpop-jkt".to_owned()),
        refresh_token_mtls_x5t_s256: Some("refresh-mtls-thumbprint".to_owned()),
    });

    assert_eq!(issue.subject, "subject-1");
    assert_eq!(issue.oidc_sid.as_deref(), Some("sid-1"));
    assert_eq!(issue.authorization_code_hash.as_deref(), Some("code-hash"));
    assert!(issue.include_refresh);
    assert_eq!(issue.refresh_token_policy, RefreshTokenPolicy::IssueNew);
    assert_eq!(issue.scopes, vec!["openid".to_owned()]);
    assert_eq!(issue.audiences, vec!["resource://default".to_owned()]);
    assert_eq!(issue.nonce, None);
    assert_eq!(issue.auth_time, Some(auth_time));
    assert_eq!(issue.dpop_jkt.as_deref(), Some("dpop-jkt"));
    assert_eq!(
        issue.refresh_token_mtls_x5t_s256.as_deref(),
        Some("refresh-mtls-thumbprint")
    );
}

#[test]
fn authorization_code_token_issue_creates_native_sso_binding_for_device_sso_scope() {
    let mut payload = code_payload(true);
    payload.scopes = vec![
        "openid".to_owned(),
        "offline_access".to_owned(),
        "device_sso".to_owned(),
    ];

    let issue = token_issue_from_authorization_code(AuthorizationCodeIssueInput {
        payload,
        subject: "subject-1".to_owned(),
        audiences: vec!["resource://default".to_owned()],
        dpop_jkt: None,
        mtls_x5t_s256: None,
        code_hash: "code-hash".to_owned(),
        refresh_token_dpop_jkt: None,
        refresh_token_mtls_x5t_s256: None,
    });

    let binding = issue
        .native_sso
        .as_ref()
        .expect("device_sso scope should create a Native SSO binding");
    assert_eq!(binding.sid, "sid-1");
    assert_eq!(
        binding.ds_hash,
        crate::http::token::native_sso_device_secret_hash(&binding.device_secret)
    );
}

#[test]
fn authorization_code_token_issue_preserves_requested_oidc_claims_and_acr() {
    let mut payload = code_payload(true);
    payload.acr = Some("urn:example:acr:phishing-resistant".to_owned());
    payload.userinfo_claims = vec!["name".to_owned(), "email".to_owned()];
    payload.userinfo_claim_requests = vec![OidcClaimRequest {
        name: "email".to_owned(),
        essential: true,
        value: Some(json!("alice@example.com")),
        values: Vec::new(),
    }];
    payload.id_token_claims = vec!["auth_time".to_owned(), "sid".to_owned()];
    payload.id_token_claim_requests = vec![OidcClaimRequest {
        name: "acr".to_owned(),
        essential: true,
        value: Some(json!("urn:example:acr:phishing-resistant")),
        values: Vec::new(),
    }];

    let issue = token_issue_from_authorization_code(AuthorizationCodeIssueInput {
        payload,
        subject: "subject-1".to_owned(),
        audiences: vec!["resource://default".to_owned()],
        dpop_jkt: None,
        mtls_x5t_s256: None,
        code_hash: "code-hash".to_owned(),
        refresh_token_dpop_jkt: None,
        refresh_token_mtls_x5t_s256: None,
    });

    assert_eq!(
        issue.acr.as_deref(),
        Some("urn:example:acr:phishing-resistant")
    );
    assert_eq!(issue.userinfo_claims, vec!["name", "email"]);
    assert_eq!(issue.userinfo_claim_requests.len(), 1);
    assert_eq!(issue.userinfo_claim_requests[0].name, "email");
    assert!(issue.userinfo_claim_requests[0].essential);
    assert_eq!(issue.id_token_claims, vec!["auth_time", "sid"]);
    assert_eq!(issue.id_token_claim_requests.len(), 1);
    assert_eq!(issue.id_token_claim_requests[0].name, "acr");
    assert!(issue.id_token_claim_requests[0].essential);
}

#[test]
fn authorization_code_consumption_parser_maps_redis_states_without_guessing() {
    assert!(matches!(
        parse_authorization_code_consumption_response("busy"),
        AuthorizationCodeConsumption::Busy
    ));
    assert!(matches!(
        parse_authorization_code_consumption_response("failed"),
        AuthorizationCodeConsumption::Failed
    ));
    assert!(matches!(
        parse_authorization_code_consumption_response("missing"),
        AuthorizationCodeConsumption::Missing
    ));
    assert!(matches!(
        parse_authorization_code_consumption_response("unknown"),
        AuthorizationCodeConsumption::Malformed
    ));
    assert!(matches!(
        parse_authorization_code_consumption_response("consuming|{not-json"),
        AuthorizationCodeConsumption::Malformed
    ));
    assert!(matches!(
        parse_authorization_code_consumption_response("consumed|{\"status\":\"pending\"}"),
        AuthorizationCodeConsumption::Malformed
    ));
}

#[test]
fn authorization_code_consumption_parser_extracts_pending_payload_and_consumed_marker() {
    let payload = code_payload(true);
    let consuming = format!("consuming|{}", serde_json::to_string(&payload).unwrap());
    match parse_authorization_code_consumption_response(&consuming) {
        AuthorizationCodeConsumption::Consuming(parsed) => {
            assert_eq!(parsed.client_id, "client-1");
            assert_eq!(
                parsed.redirect_uri.as_str(),
                "https://client.example/callback"
            );
        }
        _ => panic!("pending authorization code payload should be parsed"),
    }

    let marker = ConsumedAuthorizationCode {
        client_id: Uuid::now_v7(),
        access_token_jti: "access-jti".to_owned(),
        access_token_expires_at: Utc::now().timestamp() + 300,
        refresh_token_family_id: Some(Uuid::now_v7()),
        consumed_at: Utc::now(),
    };
    let consumed = format!(
        "consumed|{}",
        serde_json::to_string(&AuthorizationCodeState::Consumed {
            marker: marker.clone()
        })
        .unwrap()
    );
    match parse_authorization_code_consumption_response(&consumed) {
        AuthorizationCodeConsumption::Consumed(parsed) => {
            assert_eq!(parsed.client_id, marker.client_id);
            assert_eq!(parsed.access_token_jti, marker.access_token_jti);
            assert_eq!(
                parsed.refresh_token_family_id,
                marker.refresh_token_family_id
            );
        }
        _ => panic!("consumed authorization code marker should be parsed"),
    }
}

#[test]
fn authorization_code_redirect_uri_matching_preserves_oauth_binding_rules() {
    let mut supplied = code_payload(true);
    assert!(redirect_uri_matches_authorization_request(
        &supplied,
        Some("https://client.example/callback")
    ));
    assert!(!redirect_uri_matches_authorization_request(&supplied, None));
    assert!(!redirect_uri_matches_authorization_request(
        &supplied,
        Some("https://client.example/other")
    ));

    supplied.redirect_uri_was_supplied = false;
    assert!(redirect_uri_matches_authorization_request(&supplied, None));
    assert!(redirect_uri_matches_authorization_request(
        &supplied,
        Some("https://client.example/callback")
    ));
    assert!(!redirect_uri_matches_authorization_request(
        &supplied,
        Some("https://client.example/other")
    ));
}

#[test]
fn authorization_code_pkce_policy_requires_pkce_for_public_or_sender_constrained_codes() {
    let mut client = pkce_policy_client();
    let mut payload = code_payload(true);

    assert!(authorization_code_requires_pkce(&client, &payload));

    client.allow_authorization_code_without_pkce = true;
    assert!(!authorization_code_requires_pkce(&client, &payload));

    client.client_type = "public".to_owned();
    assert!(authorization_code_requires_pkce(&client, &payload));

    client.client_type = "confidential".to_owned();
    client.require_dpop_bound_tokens = true;
    assert!(authorization_code_requires_pkce(&client, &payload));

    client.require_dpop_bound_tokens = false;
    client.require_mtls_bound_tokens = true;
    assert!(authorization_code_requires_pkce(&client, &payload));

    client.require_mtls_bound_tokens = false;
    payload.dpop_jkt = Some("request-dpop-jkt".to_owned());
    assert!(authorization_code_requires_pkce(&client, &payload));

    payload.dpop_jkt = None;
    payload.mtls_x5t_s256 = Some("request-mtls-thumbprint".to_owned());
    assert!(authorization_code_requires_pkce(&client, &payload));
}

#[test]
fn authorization_code_holder_error_responses_preserve_oauth_error_classes() {
    let mtls = authorization_code_mtls_holder_error_response();
    assert_eq!(mtls.status(), StatusCode::BAD_REQUEST);
    assert_eq!(oauth_error_code(&mtls), "invalid_request");

    let mismatch = authorization_code_client_mismatch_response();
    assert_eq!(mismatch.status(), StatusCode::BAD_REQUEST);
    assert_eq!(oauth_error_code(&mismatch), "invalid_grant");

    let dpop = authorization_code_dpop_error_response(DpopError::MissingProof);
    assert_eq!(dpop.status(), StatusCode::BAD_REQUEST);
    assert_eq!(oauth_error_code(&dpop), "invalid_grant");
}

#[test]
fn confidential_required_dpop_client_does_not_pin_refresh_token_to_access_token_dpop_key() {
    let mut client = pkce_policy_client();
    client.client_type = "confidential".to_owned();
    client.require_dpop_bound_tokens = true;
    let mut payload = code_payload(true);
    payload.dpop_jkt = None;

    assert!(
        refresh_token_dpop_binding(&client, &payload, Some("verified-dpop-jkt".to_owned()))
            .is_none()
    );
}

#[test]
fn public_dpop_client_binds_refresh_token_to_dpop_key() {
    let mut client = pkce_policy_client();
    client.client_type = "public".to_owned();
    client.require_dpop_bound_tokens = false;
    let mut payload = code_payload(true);
    payload.dpop_jkt = None;

    assert_eq!(
        refresh_token_dpop_binding(&client, &payload, Some("verified-dpop-jkt".to_owned()))
            .as_deref(),
        Some("verified-dpop-jkt")
    );
}

#[test]
fn confidential_optional_dpop_code_pins_refresh_token_to_verified_dpop_key() {
    let mut client = pkce_policy_client();
    client.client_type = "confidential".to_owned();
    client.require_dpop_bound_tokens = false;
    let mut payload = code_payload(true);
    payload.dpop_jkt = Some("request-dpop-jkt".to_owned());

    assert_eq!(
        refresh_token_dpop_binding(&client, &payload, Some("verified-dpop-jkt".to_owned()))
            .as_deref(),
        Some("verified-dpop-jkt")
    );
}

#[test]
fn bearer_confidential_client_does_not_bind_refresh_token_to_access_token_dpop() {
    let mut client = pkce_policy_client();
    client.client_type = "confidential".to_owned();
    client.require_dpop_bound_tokens = false;
    let mut payload = code_payload(true);
    payload.dpop_jkt = None;

    assert!(
        refresh_token_dpop_binding(&client, &payload, Some("verified-dpop-jkt".to_owned()))
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

#[actix_web::test]
async fn authorization_code_grant_requires_code_before_state_lookup() {
    let state = test_state();
    let client = pkce_policy_client();
    let req = actix_web::test::TestRequest::post()
        .uri("/token")
        .to_http_request();
    let form = TokenForm {
        grant_type: "authorization_code".to_owned(),
        code: None,
        device_code: None,
        auth_req_id: None,
        redirect_uri: Some("https://client.example/callback".to_owned()),
        code_verifier: Some("verifier".to_owned()),
        refresh_token: None,
        device_secret: None,
        scope: None,
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
        audiences: Vec::new(),
        has_audience_param: false,
    };

    let response = token_authorization_code(&state, &req, &client, &form, None).await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(oauth_error_code(&response), "invalid_request");
}

#[actix_web::test]
async fn authorization_code_helpers_fail_closed_when_valkey_is_unavailable() {
    let state = test_state();
    let code_hash = blake3_hex("code-unavailable");
    let client = pkce_policy_client();
    let req = actix_web::test::TestRequest::post()
        .uri("/token")
        .to_http_request();

    let pending = load_pending_authorization_code_payload(&state, &code_hash)
        .await
        .expect_err("unavailable Valkey must not be treated as an absent authorization code");
    assert_eq!(pending.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(oauth_error_code(&pending), "server_error");

    let consuming = match begin_authorization_code_consumption(&state, &code_hash).await {
        Ok(_) => panic!("unavailable Valkey must not start authorization code consumption"),
        Err(response) => response,
    };
    assert_eq!(consuming.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(oauth_error_code(&consuming), "server_error");

    let endpoint = token_authorization_code(
        &state,
        &req,
        &client,
        &form_for_code("code-unavailable"),
        None,
    )
    .await;
    assert_eq!(endpoint.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(oauth_error_code(&endpoint), "server_error");
}

#[actix_web::test]
async fn load_pending_authorization_code_payload_reads_pending_missing_and_malformed_states() {
    let Some(fixture) = LiveAuthorizationCodeFixture::new().await else {
        return;
    };
    let client = live_client("live-load-client");
    let pending_code = format!("code-{}", Uuid::now_v7());
    fixture
        .store_code_state(
            &pending_code,
            &AuthorizationCodeState::Pending {
                payload: payload_for_client(&client),
            },
        )
        .await;

    let pending =
        load_pending_authorization_code_payload(&fixture.state, &blake3_hex(&pending_code))
            .await
            .expect("pending state should load");
    assert_eq!(
        pending.expect("pending payload should exist").client_id,
        client.client_id
    );

    let missing =
        load_pending_authorization_code_payload(&fixture.state, &blake3_hex("missing-code"))
            .await
            .expect("missing state should not error");
    assert!(missing.is_none());

    let malformed_code = format!("code-{}", Uuid::now_v7());
    fixture
        .store_raw_code_state(&malformed_code, "{not-json")
        .await;
    let malformed =
        load_pending_authorization_code_payload(&fixture.state, &blake3_hex(&malformed_code))
            .await
            .expect_err("malformed authorization code state must fail closed");
    assert_eq!(malformed.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(oauth_error_code(&malformed), "server_error");
}

#[actix_web::test]
async fn begin_authorization_code_consumption_tracks_single_consumer_and_terminal_states() {
    let Some(fixture) = LiveAuthorizationCodeFixture::new().await else {
        return;
    };
    let client = live_client("live-consume-client");
    let code = format!("code-{}", Uuid::now_v7());
    fixture
        .store_code_state(
            &code,
            &AuthorizationCodeState::Pending {
                payload: payload_for_client(&client),
            },
        )
        .await;

    match begin_authorization_code_consumption(&fixture.state, &blake3_hex(&code))
        .await
        .expect("pending authorization code should start consuming")
    {
        AuthorizationCodeConsumption::Consuming(payload) => {
            assert_eq!(payload.client_id, client.client_id);
        }
        _ => panic!("pending authorization code must move into consuming state"),
    }

    assert!(matches!(
        begin_authorization_code_consumption(&fixture.state, &blake3_hex(&code))
            .await
            .expect("second consumer should observe busy state"),
        AuthorizationCodeConsumption::Busy
    ));

    let failed_code = format!("code-{}", Uuid::now_v7());
    fixture
        .store_code_state(
            &failed_code,
            &AuthorizationCodeState::Failed {
                failed_at: Utc::now(),
                error: "pkce_failed".to_owned(),
            },
        )
        .await;
    assert!(matches!(
        begin_authorization_code_consumption(&fixture.state, &blake3_hex(&failed_code))
            .await
            .expect("failed code should remain terminal"),
        AuthorizationCodeConsumption::Failed
    ));

    let malformed_code = format!("code-{}", Uuid::now_v7());
    fixture.store_raw_code_state(&malformed_code, "{").await;
    assert!(matches!(
        begin_authorization_code_consumption(&fixture.state, &blake3_hex(&malformed_code))
            .await
            .expect("malformed stored state should map to malformed consumption"),
        AuthorizationCodeConsumption::Malformed
    ));
}

#[actix_web::test]
async fn token_authorization_code_rejects_client_binding_mismatch_without_consuming_code() {
    let Some(fixture) = LiveAuthorizationCodeFixture::new().await else {
        return;
    };
    let client = live_client("client-bound");
    let mut payload = payload_for_client(&client);
    payload.client_id = "different-client".to_owned();
    let code = format!("code-{}", Uuid::now_v7());
    fixture
        .store_code_state(&code, &AuthorizationCodeState::Pending { payload })
        .await;
    let req = actix_web::test::TestRequest::post()
        .uri("/token")
        .to_http_request();
    let form = form_for_code(&code);

    let response = token_authorization_code(&fixture.state, &req, &client, &form, None).await;
    let (status, body) = token_json_body(response).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_grant");
    assert!(matches!(
        fixture.code_state(&code).await,
        AuthorizationCodeState::Pending { .. }
    ));
}

#[actix_web::test]
async fn token_authorization_code_requires_sender_constrained_proof_before_consumption() {
    let Some(fixture) = LiveAuthorizationCodeFixture::new().await else {
        return;
    };
    let req = actix_web::test::TestRequest::post()
        .uri("/token")
        .to_http_request();

    let mut dpop_client = live_client("client-dpop");
    dpop_client.require_dpop_bound_tokens = true;
    let dpop_code = format!("code-{}", Uuid::now_v7());
    fixture
        .store_code_state(
            &dpop_code,
            &AuthorizationCodeState::Pending {
                payload: payload_for_client(&dpop_client),
            },
        )
        .await;
    let dpop_response = token_authorization_code(
        &fixture.state,
        &req,
        &dpop_client,
        &form_for_code(&dpop_code),
        None,
    )
    .await;
    let (status, body) = token_json_body(dpop_response).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_grant");
    assert!(matches!(
        fixture.code_state(&dpop_code).await,
        AuthorizationCodeState::Pending { .. }
    ));

    let mtls_client = live_client("client-mtls");
    let mut mtls_payload = payload_for_client(&mtls_client);
    mtls_payload.mtls_x5t_s256 = Some("w7JAoU_gJbZJvV-zCOvU9yFJq0FNC_edCMRM78P8eQQ".to_owned());
    let mtls_code = format!("code-{}", Uuid::now_v7());
    fixture
        .store_code_state(
            &mtls_code,
            &AuthorizationCodeState::Pending {
                payload: mtls_payload,
            },
        )
        .await;
    let mtls_response = token_authorization_code(
        &fixture.state,
        &req,
        &mtls_client,
        &form_for_code(&mtls_code),
        None,
    )
    .await;
    let (status, body) = token_json_body(mtls_response).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");
    assert!(matches!(
        fixture.code_state(&mtls_code).await,
        AuthorizationCodeState::Pending { .. }
    ));
}

#[actix_web::test]
async fn token_authorization_code_enforces_client_mtls_policy_before_consumption() {
    let Some(fixture) = LiveAuthorizationCodeFixture::new().await else {
        return;
    };
    let req = actix_web::test::TestRequest::post()
        .uri("/token")
        .to_http_request();
    let mut client = live_client(&format!("client-mtls-policy-{}", Uuid::now_v7()));
    client.require_mtls_bound_tokens = true;
    fixture.insert_client(&client).await;
    let code = format!("code-{}", Uuid::now_v7());
    fixture
        .store_code_state(
            &code,
            &AuthorizationCodeState::Pending {
                payload: payload_for_client(&client),
            },
        )
        .await;

    let response =
        token_authorization_code(&fixture.state, &req, &client, &form_for_code(&code), None).await;
    let (status, body) = token_json_body(response).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");
    assert!(matches!(
        fixture.code_state(&code).await,
        AuthorizationCodeState::Pending { .. }
    ));

    let bound_code = format!("code-{}", Uuid::now_v7());
    fixture
        .store_code_state(
            &bound_code,
            &AuthorizationCodeState::Pending {
                payload: payload_for_client(&client),
            },
        )
        .await;
    let thumbprint = "REREREREREREREREREREREREREREREREREREREREREQ";
    let verified_req = actix_web::test::TestRequest::post()
        .uri("/token")
        .peer_addr("127.0.0.1:12345".parse().expect("peer addr should parse"))
        .insert_header((
            header::HeaderName::from_static("x-ssl-client-verify"),
            "SUCCESS",
        ))
        .insert_header((
            header::HeaderName::from_static("x-ssl-client-cert-sha256"),
            thumbprint,
        ))
        .insert_header((
            header::HeaderName::from_static("x-ssl-client-subject-dn"),
            "CN=authorization-code-mtls-policy",
        ))
        .to_http_request();

    let bound_response = token_authorization_code(
        &fixture.state,
        &verified_req,
        &client,
        &form_for_code(&bound_code),
        None,
    )
    .await;
    let (bound_status, bound_body) = token_json_body(bound_response).await;

    assert_eq!(
        bound_status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "holder binding should succeed before the fixture reaches its intentionally invalid signing key: {bound_body}"
    );
    assert_eq!(bound_body["error"], "server_error");
}

#[actix_web::test]
async fn token_authorization_code_accepts_matching_mtls_bound_code_before_issuing_response() {
    let Some(fixture) = LiveAuthorizationCodeFixture::new().await else {
        return;
    };
    let client = live_client(&format!("client-mtls-bound-{}", Uuid::now_v7()));
    fixture.insert_client(&client).await;
    let thumbprint = "REREREREREREREREREREREREREREREREREREREREREQ";
    let mut payload = payload_for_client(&client);
    payload.mtls_x5t_s256 = Some(thumbprint.to_owned());
    payload.scopes = vec!["accounts".to_owned()];
    let code = format!("code-{}", Uuid::now_v7());
    fixture
        .store_code_state(&code, &AuthorizationCodeState::Pending { payload })
        .await;
    let req = actix_web::test::TestRequest::post()
        .uri("/token")
        .peer_addr("127.0.0.1:12345".parse().expect("peer addr should parse"))
        .insert_header((
            header::HeaderName::from_static("x-ssl-client-verify"),
            "SUCCESS",
        ))
        .insert_header((
            header::HeaderName::from_static("x-ssl-client-cert-sha256"),
            thumbprint,
        ))
        .insert_header((
            header::HeaderName::from_static("x-ssl-client-subject-dn"),
            "CN=authorization-code-actual",
        ))
        .to_http_request();

    let response =
        token_authorization_code(&fixture.state, &req, &client, &form_for_code(&code), None).await;
    let (status, body) = token_json_body(response).await;

    assert_eq!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "the fixture uses an intentionally invalid signing key after holder binding succeeds: {body}"
    );
    assert_eq!(body["error"], "server_error");
}

#[actix_web::test]
async fn token_authorization_code_marks_failed_states_for_redirect_pkce_and_audience_errors() {
    let Some(fixture) = LiveAuthorizationCodeFixture::new().await else {
        return;
    };
    let req = actix_web::test::TestRequest::post()
        .uri("/token")
        .to_http_request();
    let client = live_client("client-failure-cases");

    let redirect_code = format!("code-{}", Uuid::now_v7());
    fixture
        .store_code_state(
            &redirect_code,
            &AuthorizationCodeState::Pending {
                payload: payload_for_client(&client),
            },
        )
        .await;
    let mut redirect_form = form_for_code(&redirect_code);
    redirect_form.redirect_uri = Some("https://attacker.example/callback".to_owned());
    let redirect_response =
        token_authorization_code(&fixture.state, &req, &client, &redirect_form, None).await;
    assert_eq!(oauth_error_code(&redirect_response), "invalid_grant");
    match fixture.code_state(&redirect_code).await {
        AuthorizationCodeState::Failed { error, .. } => {
            assert_eq!(error, "client_or_redirect_uri_mismatch");
        }
        _ => panic!("redirect mismatch should mark the authorization code as failed"),
    }

    let missing_verifier_code = format!("code-{}", Uuid::now_v7());
    fixture
        .store_code_state(
            &missing_verifier_code,
            &AuthorizationCodeState::Pending {
                payload: payload_for_client(&client),
            },
        )
        .await;
    let mut missing_verifier_form = form_for_code(&missing_verifier_code);
    missing_verifier_form.code_verifier = None;
    let missing_verifier_response =
        token_authorization_code(&fixture.state, &req, &client, &missing_verifier_form, None).await;
    assert_eq!(
        oauth_error_code(&missing_verifier_response),
        "invalid_grant"
    );
    match fixture.code_state(&missing_verifier_code).await {
        AuthorizationCodeState::Failed { error, .. } => {
            assert_eq!(error, "missing_code_verifier");
        }
        _ => panic!("missing code_verifier should mark the authorization code as failed"),
    }

    let pkce_failed_code = format!("code-{}", Uuid::now_v7());
    fixture
        .store_code_state(
            &pkce_failed_code,
            &AuthorizationCodeState::Pending {
                payload: payload_for_client(&client),
            },
        )
        .await;
    let mut pkce_failed_form = form_for_code(&pkce_failed_code);
    pkce_failed_form.code_verifier = Some("wrong-verifier".to_owned());
    let pkce_failed_response =
        token_authorization_code(&fixture.state, &req, &client, &pkce_failed_form, None).await;
    assert_eq!(oauth_error_code(&pkce_failed_response), "invalid_grant");
    match fixture.code_state(&pkce_failed_code).await {
        AuthorizationCodeState::Failed { error, .. } => {
            assert_eq!(error, "pkce_failed");
        }
        _ => panic!("PKCE mismatch should mark the authorization code as failed"),
    }

    let pkce_state_code = format!("code-{}", Uuid::now_v7());
    let mut pkce_state_payload = payload_for_client(&client);
    pkce_state_payload.code_challenge_method = None;
    fixture
        .store_code_state(
            &pkce_state_code,
            &AuthorizationCodeState::Pending {
                payload: pkce_state_payload,
            },
        )
        .await;
    let pkce_state_response = token_authorization_code(
        &fixture.state,
        &req,
        &client,
        &form_for_code(&pkce_state_code),
        None,
    )
    .await;
    assert_eq!(
        pkce_state_response.status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(oauth_error_code(&pkce_state_response), "server_error");
    match fixture.code_state(&pkce_state_code).await {
        AuthorizationCodeState::Failed { error, .. } => {
            assert_eq!(error, "pkce_state_invalid");
        }
        _ => panic!("invalid PKCE state should mark the authorization code as failed"),
    }

    let audience_code = format!("code-{}", Uuid::now_v7());
    fixture
        .store_code_state(
            &audience_code,
            &AuthorizationCodeState::Pending {
                payload: payload_for_client(&client),
            },
        )
        .await;
    let mut audience_form = form_for_code(&audience_code);
    audience_form.audiences = vec!["resource://other".to_owned()];
    let audience_response =
        token_authorization_code(&fixture.state, &req, &client, &audience_form, None).await;
    assert_eq!(audience_response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(oauth_error_code(&audience_response), "invalid_target");
    match fixture.code_state(&audience_code).await {
        AuthorizationCodeState::Failed { error, .. } => {
            assert_eq!(error, "audience_not_allowed");
        }
        _ => panic!("invalid audience should mark the authorization code as failed"),
    }
}

#[actix_web::test]
async fn token_authorization_code_replay_revokes_previous_tokens_and_rejects_reuse() {
    let Some(fixture) = LiveAuthorizationCodeFixture::new().await else {
        return;
    };
    let client = live_client(&format!("client-replay-{}", Uuid::now_v7()));
    fixture.insert_client(&client).await;
    let family_id = Uuid::now_v7();
    fixture.insert_refresh_token(&client, family_id).await;

    let code = format!("code-{}", Uuid::now_v7());
    let marker = ConsumedAuthorizationCode {
        client_id: client.id,
        access_token_jti: "access-jti-1".to_owned(),
        access_token_expires_at: Utc::now().timestamp() + 300,
        refresh_token_family_id: Some(family_id),
        consumed_at: Utc::now(),
    };
    fixture
        .store_code_state(
            &code,
            &AuthorizationCodeState::Consumed {
                marker: marker.clone(),
            },
        )
        .await;
    let req = actix_web::test::TestRequest::post()
        .uri("/token")
        .to_http_request();
    let response =
        token_authorization_code(&fixture.state, &req, &client, &form_for_code(&code), None).await;
    let (status, body) = token_json_body(response).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_grant");
    assert_eq!(
        fixture
            .access_token_revocation_count(&client, &marker.access_token_jti)
            .await,
        1
    );
    assert!(
        fixture
            .refresh_token_revoked_at(&client, family_id)
            .await
            .is_some(),
        "authorization code replay must revoke the refresh token family"
    );

    let missing_client_code = format!("code-{}", Uuid::now_v7());
    fixture
        .store_code_state(
            &missing_client_code,
            &AuthorizationCodeState::Consumed {
                marker: ConsumedAuthorizationCode {
                    client_id: Uuid::now_v7(),
                    access_token_jti: "access-jti-2".to_owned(),
                    access_token_expires_at: Utc::now().timestamp() + 300,
                    refresh_token_family_id: None,
                    consumed_at: Utc::now(),
                },
            },
        )
        .await;
    let missing_client_response = token_authorization_code(
        &fixture.state,
        &req,
        &client,
        &form_for_code(&missing_client_code),
        None,
    )
    .await;
    assert_eq!(missing_client_response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(oauth_error_code(&missing_client_response), "invalid_grant");
}

#[actix_web::test]
async fn token_authorization_code_replay_fails_closed_when_replayed_client_lookup_errors() {
    let Some(fixture) = LiveAuthorizationCodeFixture::new().await else {
        return;
    };
    let client = live_client(&format!("client-replay-db-error-{}", Uuid::now_v7()));
    let state = Data::new(AppState {
        diesel_db: create_pool(
            "postgres://nazo_auth_code_test_invalid:nazo_auth_code_test_invalid@127.0.0.1:1/nazo"
                .to_owned(),
            1,
        )
        .expect("pool construction should not connect"),
        valkey: fixture.state.valkey.clone(),
        settings: fixture.state.settings.clone(),
        keyset: fixture.state.keyset.clone(),
    });
    let code = format!("code-{}", Uuid::now_v7());
    fixture
        .store_code_state(
            &code,
            &AuthorizationCodeState::Consumed {
                marker: ConsumedAuthorizationCode {
                    client_id: Uuid::now_v7(),
                    access_token_jti: format!("access-jti-{}", Uuid::now_v7()),
                    access_token_expires_at: Utc::now().timestamp() + 300,
                    refresh_token_family_id: Some(Uuid::now_v7()),
                    consumed_at: Utc::now(),
                },
            },
        )
        .await;
    let req = actix_web::test::TestRequest::post()
        .uri("/token")
        .to_http_request();

    let response =
        token_authorization_code(&state, &req, &client, &form_for_code(&code), None).await;

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(oauth_error_code(&response), "server_error");
}

#[actix_web::test]
async fn token_authorization_code_reports_busy_failed_and_missing_states() {
    let Some(fixture) = LiveAuthorizationCodeFixture::new().await else {
        return;
    };
    let client = live_client("client-terminal");
    let req = actix_web::test::TestRequest::post()
        .uri("/token")
        .to_http_request();

    let consuming_code = format!("code-{}", Uuid::now_v7());
    fixture
        .store_code_state(
            &consuming_code,
            &AuthorizationCodeState::Consuming {
                payload: payload_for_client(&client),
                consuming_at: Utc::now(),
            },
        )
        .await;
    let consuming_response = token_authorization_code(
        &fixture.state,
        &req,
        &client,
        &form_for_code(&consuming_code),
        None,
    )
    .await;
    assert_eq!(consuming_response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(oauth_error_code(&consuming_response), "invalid_grant");

    let failed_code = format!("code-{}", Uuid::now_v7());
    fixture
        .store_code_state(
            &failed_code,
            &AuthorizationCodeState::Failed {
                failed_at: Utc::now(),
                error: "pkce_failed".to_owned(),
            },
        )
        .await;
    let failed_response = token_authorization_code(
        &fixture.state,
        &req,
        &client,
        &form_for_code(&failed_code),
        None,
    )
    .await;
    assert_eq!(failed_response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(oauth_error_code(&failed_response), "invalid_grant");

    let missing_response = token_authorization_code(
        &fixture.state,
        &req,
        &client,
        &form_for_code("missing-code"),
        None,
    )
    .await;
    assert_eq!(missing_response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(oauth_error_code(&missing_response), "invalid_grant");

    let malformed_code = format!("code-{}", Uuid::now_v7());
    fixture
        .store_raw_code_state(&malformed_code, r#"{"status":"unknown"}"#)
        .await;
    let malformed_response = token_authorization_code(
        &fixture.state,
        &req,
        &client,
        &form_for_code(&malformed_code),
        None,
    )
    .await;
    assert_eq!(malformed_response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(oauth_error_code(&malformed_response), "server_error");
}

#[path = "authorization_code/consumption.rs"]
mod consumption;
#[path = "authorization_code/error_mapping.rs"]
mod error_mapping;
#[path = "authorization_code/pkce.rs"]
mod pkce;
#[path = "authorization_code/redirect_uri.rs"]
mod redirect_uri;
