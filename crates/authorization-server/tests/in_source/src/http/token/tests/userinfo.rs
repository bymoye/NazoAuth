use super::*;
use std::sync::Arc;
use std::time::Duration as StdDuration;

use crate::config::ConfigSource;
use crate::domain::{TestAppState, UserinfoConfig};
use crate::settings::Settings;
use nazo_postgres::{create_pool, get_conn};

use crate::http::client_ip::IpCidr;
use crate::schema::oauth_clients;
use crate::test_support::client_signing_fixture;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use diesel::prelude::*;
use diesel::sql_query;
use diesel::sql_types::{Bool, Text, Timestamptz, Uuid as SqlUuid};
use diesel_async::RunQueryDsl;
use fred::interfaces::{ClientLike, KeysInterface};
use fred::prelude::{
    Builder as ValkeyBuilder, Config as ValkeyConfig, ConnectionConfig, PerformanceConfig,
};
use nazo_auth::Claims;
use openssl::encrypt::Decrypter;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::rsa::{Padding, Rsa};
use openssl::symm::{Cipher, decrypt_aead};

fn disconnected_valkey_client() -> fred::prelude::Client {
    let mut builder = ValkeyBuilder::default_centralized();
    builder.with_performance_config(|performance: &mut PerformanceConfig| {
        performance.default_command_timeout = StdDuration::from_millis(50);
    });
    builder.with_connection_config(|connection: &mut ConnectionConfig| {
        connection.connection_timeout = StdDuration::from_millis(50);
        connection.internal_command_timeout = StdDuration::from_millis(50);
        connection.max_command_attempts = 1;
    });
    builder
        .build()
        .expect("valkey client construction should not connect")
}

fn userinfo_test_state() -> TestAppState {
    let mut settings =
        Settings::from_config(&ConfigSource::default()).expect("default settings should load");
    settings.endpoint.issuer = "https://issuer.example".to_owned();
    settings.protocol.default_audience = "resource://default".to_owned();

    TestAppState {
        diesel_db: create_pool(
            "postgres://nazo_userinfo_test_invalid:nazo_userinfo_test_invalid@127.0.0.1:1/nazo"
                .to_owned(),
            1,
        )
        .expect("pool construction should not connect"),
        valkey: disconnected_valkey_client(),
        settings: Arc::new(settings),
        keyset: crate::test_support::test_key_manager(),
    }
}

fn userinfo_token_service(state: &TestAppState) -> ServerTokenService {
    let connection = state.valkey_connection();
    ServerTokenService::new(
        nazo_postgres::TokenIssuanceRepository::new(state.diesel_db.clone()),
        nazo_valkey::TokenIssuanceStateAdapter::new(&connection),
        state.keyset.clone(),
    )
}

async fn call_userinfo(state: Data<TestAppState>, req: HttpRequest, body: Bytes) -> HttpResponse {
    let token_service = Data::new(userinfo_token_service(&state));
    super::userinfo(
        Data::new(UserinfoHandles::from_test_state(state.get_ref())),
        token_service,
        req,
        body,
    )
    .await
}

fn userinfo_audience_allowed(settings: &Settings, audience: &Value) -> bool {
    UserinfoConfig::from(settings).audience_allowed(audience)
}

async fn live_userinfo_state() -> Option<Data<TestAppState>> {
    let database_url = std::env::var("DATABASE_URL").ok()?;
    live_userinfo_state_from_database_url(database_url).await
}

async fn live_userinfo_state_from_database_url(database_url: String) -> Option<Data<TestAppState>> {
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
    let key_material = client_signing_fixture(jsonwebtoken::Algorithm::EdDSA);
    let _public_jwk = key_material.public_jwk("userinfo-test-kid");
    let mut settings =
        Settings::from_config(&ConfigSource::default()).expect("default settings should load");
    settings.endpoint.issuer = "https://issuer.example".to_owned();
    settings.protocol.default_audience = "resource://default".to_owned();

    Some(Data::new(TestAppState {
        diesel_db: create_pool(database_url, 1).expect("database pool should build"),
        valkey,
        settings: Arc::new(settings),
        keyset: crate::test_support::test_key_manager(),
    }))
}

fn database_url_with_search_path(schema: &str) -> Option<String> {
    let base = std::env::var("DATABASE_URL").ok()?;
    let separator = if base.contains('?') { "&" } else { "?" };
    Some(format!(
        "{base}{separator}options=-csearch_path%3D{schema}%2Cpublic"
    ))
}

async fn create_isolated_schema(state: &Data<TestAppState>, schema: &str, tables: &[&str]) {
    exec_sql(
        state,
        &format!(r#"CREATE SCHEMA IF NOT EXISTS "{}""#, schema),
    )
    .await;
    for table in tables {
        exec_sql(
            state,
            &format!(
                r#"CREATE TABLE "{}"."{}" (LIKE public."{}" INCLUDING ALL)"#,
                schema, table, table
            ),
        )
        .await;
    }
}

async fn exec_sql(state: &Data<TestAppState>, sql: &str) {
    let mut conn = get_conn(&state.diesel_db)
        .await
        .expect("database connection should be available");
    sql_query(sql)
        .execute(&mut conn)
        .await
        .expect("schema mutation should succeed");
}

async fn rename_column(
    state: &Data<TestAppState>,
    schema: &str,
    table: &str,
    from: &str,
    to: &str,
) {
    exec_sql(
        state,
        &format!(
            r#"ALTER TABLE "{}"."{}" RENAME COLUMN "{}" TO "{}""#,
            schema, table, from, to
        ),
    )
    .await;
}

async fn drop_schema(state: &Data<TestAppState>, schema: &str) {
    exec_sql(
        state,
        &format!(r#"DROP SCHEMA IF EXISTS "{}" CASCADE"#, schema),
    )
    .await;
}

fn userinfo_state_with_valid_signing_key_invalid_db() -> Data<TestAppState> {
    let key_material = client_signing_fixture(jsonwebtoken::Algorithm::EdDSA);
    let _public_jwk = key_material.public_jwk("userinfo-test-kid");
    let mut settings =
        Settings::from_config(&ConfigSource::default()).expect("default settings should load");
    settings.endpoint.issuer = "https://issuer.example".to_owned();
    settings.protocol.default_audience = "resource://default".to_owned();

    Data::new(TestAppState {
        diesel_db: create_pool(
            "postgres://nazo_userinfo_test_invalid:nazo_userinfo_test_invalid@127.0.0.1:1/nazo"
                .to_owned(),
            1,
        )
        .expect("pool construction should not connect"),
        valkey: disconnected_valkey_client(),
        settings: Arc::new(settings),
        keyset: crate::test_support::test_key_manager(),
    })
}

fn userinfo_access_claims(user_id: Option<String>) -> Claims {
    let now = Utc::now().timestamp();
    Claims {
        iss: "https://issuer.example".to_owned(),
        sub: Uuid::now_v7().to_string(),
        tenant_id: DEFAULT_TENANT_ID.to_string(),
        user_id,
        subject_type: "user".to_owned(),
        aud: json!("resource://default"),
        client_id: "userinfo-client".to_owned(),
        scope: "openid".to_owned(),
        authorization_details: json!([]),
        token_use: "access".to_owned(),
        jti: Uuid::now_v7().to_string(),
        iat: now,
        nbf: now,
        exp: now + 300,
        cnf: None,
        act: None,
        userinfo_claims: Vec::new(),
        userinfo_claim_requests: Vec::new(),
    }
}

async fn live_userinfo_state_with_trusted_proxy() -> Option<Data<TestAppState>> {
    let state = live_userinfo_state().await?;
    let mut settings = (*state.settings).clone();
    settings.endpoint.trusted_proxy_cidrs =
        vec![IpCidr::parse("127.0.0.1/32").expect("trusted proxy CIDR should parse")];

    Some(Data::new(TestAppState {
        diesel_db: state.diesel_db.clone(),
        valkey: state.valkey.clone(),
        settings: Arc::new(settings),
        keyset: state.keyset.clone(),
    }))
}

#[actix_web::test]
async fn access_token_user_id_prefers_valid_user_id_claim_without_valkey_lookup() {
    let state = userinfo_test_state();
    let expected_user_id = Uuid::now_v7();
    let claims = userinfo_access_claims(Some(expected_user_id.to_string()));
    let token_service = userinfo_token_service(&state);

    let actual = access_token_user_id(&token_service, DEFAULT_TENANT_ID, &claims)
        .await
        .expect("valid user_id claim should not require valkey");

    assert_eq!(actual, Some(expected_user_id));
}

#[actix_web::test]
async fn access_token_user_id_uses_valkey_when_user_id_claim_is_absent() {
    let Some(state) = live_userinfo_state().await else {
        return;
    };
    let claims = userinfo_access_claims(None);
    let expected_user_id = Uuid::now_v7();
    state
        .valkey
        .set::<(), _, _>(
            access_token_subject_key(DEFAULT_TENANT_ID, &claims.jti),
            expected_user_id.to_string(),
            None,
            None,
            false,
        )
        .await
        .expect("subject mapping should be stored");
    let token_service = userinfo_token_service(&state);

    let actual = access_token_user_id(&token_service, DEFAULT_TENANT_ID, &claims)
        .await
        .expect("stored subject mapping should load");

    assert_eq!(actual, Some(expected_user_id));
}

#[actix_web::test]
async fn access_token_user_id_rejects_unavailable_subject_mapping_store() {
    let state = userinfo_test_state();
    let claims = userinfo_access_claims(None);
    let token_service = userinfo_token_service(&state);

    assert!(
        access_token_user_id(&token_service, DEFAULT_TENANT_ID, &claims)
            .await
            .is_err()
    );
}

async fn insert_userinfo_client(state: &Data<TestAppState>, client_id: &str) -> Uuid {
    #[derive(diesel::QueryableByName)]
    struct IdRow {
        #[diesel(sql_type = SqlUuid)]
        id: Uuid,
    }

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
    .bind::<SqlUuid, _>(DEFAULT_TENANT_ID)
    .bind::<Text, _>(client_id)
    .execute(&mut conn)
    .await
    .expect("test access token revocation cleanup should succeed");
    sql_query("DELETE FROM oauth_clients WHERE tenant_id = $1 AND client_id = $2")
        .bind::<SqlUuid, _>(DEFAULT_TENANT_ID)
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
            $1, $2, $3, $4, 'UserInfo Test Client', 'confidential',
            NULL, '["https://client.example/callback"]'::jsonb, '["openid","profile"]'::jsonb,
            '["resource://default"]'::jsonb, '["authorization_code"]'::jsonb,
            'client_secret_post', false, false, '[]'::jsonb, '[]'::jsonb,
            '[]'::jsonb, '[]'::jsonb, false, false, false, false, true,
            '[]'::jsonb, true
        )
        RETURNING id
        "#,
    )
    .bind::<SqlUuid, _>(DEFAULT_TENANT_ID)
    .bind::<SqlUuid, _>(DEFAULT_REALM_ID)
    .bind::<SqlUuid, _>(DEFAULT_ORGANIZATION_ID)
    .bind::<Text, _>(client_id)
    .get_result::<IdRow>(&mut conn)
    .await
    .expect("test client insert should succeed")
    .id
}

async fn update_userinfo_crypto_policy(
    state: &Data<TestAppState>,
    client_id: &str,
    signing_alg: Option<&str>,
    encryption_alg: Option<&str>,
    encryption_enc: Option<&str>,
    jwks: Option<Value>,
) {
    let mut conn = get_conn(&state.diesel_db)
        .await
        .expect("database connection should be available");
    diesel::update(
        oauth_clients::table
            .filter(oauth_clients::tenant_id.eq(DEFAULT_TENANT_ID))
            .filter(oauth_clients::client_id.eq(client_id)),
    )
    .set((
        oauth_clients::userinfo_signed_response_alg.eq(signing_alg),
        oauth_clients::userinfo_encrypted_response_alg.eq(encryption_alg),
        oauth_clients::userinfo_encrypted_response_enc.eq(encryption_enc),
        oauth_clients::jwks.eq(jwks),
    ))
    .execute(&mut conn)
    .await
    .expect("UserInfo response crypto policy should update");
}

fn rsa_userinfo_jwe_keypair(kid: &str) -> (PKey<Private>, Value) {
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

fn decrypt_userinfo_jwe(private_key: &PKey<Private>, compact_jwe: &str) -> (Value, String) {
    let parts = compact_jwe.split('.').collect::<Vec<_>>();
    assert_eq!(parts.len(), 5, "compact JWE must have five parts");
    let protected_header: Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(parts[0])
            .expect("protected header should be base64url"),
    )
    .expect("protected header should be JSON");
    let encrypted_key = URL_SAFE_NO_PAD
        .decode(parts[1])
        .expect("encrypted key should be base64url");
    let iv = URL_SAFE_NO_PAD
        .decode(parts[2])
        .expect("iv should be base64url");
    let ciphertext = URL_SAFE_NO_PAD
        .decode(parts[3])
        .expect("ciphertext should be base64url");
    let tag = URL_SAFE_NO_PAD
        .decode(parts[4])
        .expect("tag should be base64url");
    let mut decrypter = Decrypter::new(private_key).expect("RSA decrypter should initialize");
    decrypter
        .set_rsa_padding(Padding::PKCS1_OAEP)
        .expect("RSA-OAEP padding should configure");
    decrypter
        .set_rsa_oaep_md(MessageDigest::sha256())
        .expect("RSA-OAEP SHA-256 should configure");
    decrypter
        .set_rsa_mgf1_md(MessageDigest::sha256())
        .expect("RSA-OAEP MGF1 SHA-256 should configure");
    let mut cek = vec![
        0;
        decrypter
            .decrypt_len(&encrypted_key)
            .expect("encrypted key length should be known")
    ];
    let len = decrypter
        .decrypt(&encrypted_key, &mut cek)
        .expect("content-encryption key should decrypt");
    cek.truncate(len);
    let plaintext = decrypt_aead(
        Cipher::aes_256_gcm(),
        &cek,
        Some(&iv),
        parts[0].as_bytes(),
        &ciphertext,
        &tag,
    )
    .expect("A256GCM ciphertext should decrypt");
    (
        protected_header,
        String::from_utf8(plaintext).expect("JWE plaintext should be UTF-8"),
    )
}

fn decode_signed_userinfo(state: &TestAppState, client_id: &str, token: &str) -> Value {
    let header = jsonwebtoken::decode_header(token).expect("UserInfo JWS header should decode");
    let decoding_key =
        jwt_decoding_key_from_jwk(&state.keyset.snapshot().jwks()["keys"][0], header.alg)
            .expect("UserInfo JWS decoding key should derive");
    let mut validation = jsonwebtoken::Validation::new(header.alg);
    validation.validate_exp = false;
    validation.required_spec_claims.clear();
    validation.set_audience(&[client_id]);
    validation.set_issuer(&[state.settings.endpoint.issuer.as_str()]);
    jsonwebtoken::decode::<Value>(token, &decoding_key, &validation)
        .expect("UserInfo JWS should verify")
        .claims
}

async fn insert_userinfo_user(state: &Data<TestAppState>, active: bool) -> DatabaseUserFixture {
    let suffix = Uuid::now_v7();
    let mut conn = get_conn(&state.diesel_db)
        .await
        .expect("database connection should be available");
    sql_query(
        r#"
        INSERT INTO users (
            tenant_id, realm_id, organization_id, username, email,
            password_hash, is_active, mfa_enabled, email_verified, role, admin_level
        )
        VALUES ($1, $2, $3, $4, $5, 'unused-userinfo-test-hash', $6, false, true, 'user', 0)
        RETURNING *
        "#,
    )
    .bind::<SqlUuid, _>(DEFAULT_TENANT_ID)
    .bind::<SqlUuid, _>(DEFAULT_REALM_ID)
    .bind::<SqlUuid, _>(DEFAULT_ORGANIZATION_ID)
    .bind::<Text, _>(format!("userinfo-{suffix}"))
    .bind::<Text, _>(format!("userinfo-{suffix}@example.com"))
    .bind::<Bool, _>(active)
    .get_result::<DatabaseUserFixture>(&mut conn)
    .await
    .expect("test user insert should succeed")
}

async fn revoke_access_token(
    state: &Data<TestAppState>,
    client_row_id: Uuid,
    access_token_jti: &str,
) {
    let mut conn = get_conn(&state.diesel_db)
        .await
        .expect("database connection should be available");
    sql_query(
        r#"
        INSERT INTO access_token_revocations (
            tenant_id, client_id, access_token_jti_blake3, expires_at
        )
        VALUES ($1, $2, $3, $4)
        "#,
    )
    .bind::<SqlUuid, _>(DEFAULT_TENANT_ID)
    .bind::<SqlUuid, _>(client_row_id)
    .bind::<Text, _>(blake3_hex(access_token_jti))
    .bind::<Timestamptz, _>(Utc::now() + Duration::minutes(5))
    .execute(&mut conn)
    .await
    .expect("access token revocation insert should succeed");
}

#[allow(clippy::too_many_arguments)]
async fn signed_userinfo_access_token(
    state: &Data<TestAppState>,
    tenant_id: Uuid,
    subject: &str,
    user_id: Option<Uuid>,
    subject_type: &str,
    audiences: &[String],
    scopes: &[String],
    dpop_jkt: Option<&str>,
    mtls_x5t_s256: Option<&str>,
) -> IssuedAccessToken {
    make_jwt(
        &state.keyset,
        &state.settings.endpoint.issuer,
        AccessTokenJwtInput {
            tenant_id,
            subject,
            user_id,
            subject_type,
            client_id: "userinfo-client",
            audiences,
            scopes,
            authorization_details: &json!([]),
            userinfo_claims: &[],
            userinfo_claim_requests: &[],
            ttl: 300,
            dpop_jkt,
            mtls_x5t_s256,
            actor: None,
        },
    )
    .await
    .expect("access token should sign")
}

async fn userinfo_error_for_token(
    state: Data<TestAppState>,
    scheme: &str,
    token: &str,
) -> HttpResponse {
    let req = actix_web::test::TestRequest::get()
        .uri("/userinfo")
        .insert_header((header::AUTHORIZATION, format!("{scheme} {token}")))
        .to_http_request();
    call_userinfo(state, req, Bytes::new()).await
}

async fn userinfo_response_for_active_user(
    state: Data<TestAppState>,
    user: &DatabaseUserFixture,
    client_id: &str,
) -> HttpResponse {
    let token = make_jwt(
        &state.keyset,
        &state.settings.endpoint.issuer,
        AccessTokenJwtInput {
            tenant_id: DEFAULT_TENANT_ID,
            subject: &user.id.to_string(),
            user_id: Some(user.id),
            subject_type: "user",
            client_id,
            audiences: &["resource://default".to_owned()],
            scopes: &["openid".to_owned(), "email".to_owned()],
            authorization_details: &json!([]),
            userinfo_claims: &[],
            userinfo_claim_requests: &[],
            ttl: 300,
            dpop_jkt: None,
            mtls_x5t_s256: None,
            actor: None,
        },
    )
    .await
    .expect("access token should sign");
    let req = actix_web::test::TestRequest::get()
        .uri("/userinfo")
        .insert_header((header::AUTHORIZATION, format!("Bearer {}", token.token)))
        .to_http_request();
    call_userinfo(state, req, Bytes::new()).await
}

fn oauth_error_code(response: &HttpResponse) -> Option<String> {
    response
        .extensions()
        .get::<OAuthJsonErrorFields>()
        .map(|fields| fields.error.clone())
}

#[actix_web::test]
async fn userinfo_rejects_signed_access_token_with_wrong_audience() {
    let Some(state) = live_userinfo_state().await else {
        return;
    };
    let token = signed_userinfo_access_token(
        &state,
        DEFAULT_TENANT_ID,
        &Uuid::now_v7().to_string(),
        None,
        "user",
        &["https://issuer.example/fapi/resource".to_owned()],
        &["openid".to_owned()],
        None,
        None,
    )
    .await;

    let response = userinfo_error_for_token(state, "Bearer", &token.token).await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        oauth_error_code(&response).as_deref(),
        Some("invalid_token")
    );
}

#[actix_web::test]
async fn userinfo_rejects_signed_access_token_without_valid_tenant_boundary() {
    let Some(state) = live_userinfo_state().await else {
        return;
    };
    let claims = Claims {
        iss: state.settings.endpoint.issuer.clone(),
        sub: Uuid::now_v7().to_string(),
        tenant_id: "not-a-uuid".to_owned(),
        user_id: None,
        subject_type: "user".to_owned(),
        aud: json!("resource://default"),
        client_id: "userinfo-client".to_owned(),
        scope: "openid".to_owned(),
        authorization_details: json!([]),
        token_use: "access".to_owned(),
        jti: Uuid::now_v7().to_string(),
        iat: Utc::now().timestamp(),
        nbf: Utc::now().timestamp(),
        exp: Utc::now().timestamp() + 300,
        cnf: None,
        act: None,
        userinfo_claims: Vec::new(),
        userinfo_claim_requests: Vec::new(),
    };
    let keyset = state.keyset.snapshot();
    let mut header = jsonwebtoken::Header::new(keyset.active_alg);
    header.typ = Some("at+jwt".to_owned());
    header.kid = Some(keyset.active_kid.clone());
    let token = state
        .keyset
        .encode_jwt(nazo_auth::SigningPurpose::AccessToken, &header, &claims)
        .await
        .expect("access token should sign");

    let response = userinfo_error_for_token(state, "Bearer", &token).await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        oauth_error_code(&response).as_deref(),
        Some("invalid_token")
    );
}

#[actix_web::test]
async fn userinfo_rejects_revoked_access_token_before_subject_lookup() {
    let Some(state) = live_userinfo_state().await else {
        return;
    };
    let client_row_id = insert_userinfo_client(&state, "userinfo-client").await;
    let token = signed_userinfo_access_token(
        &state,
        DEFAULT_TENANT_ID,
        &Uuid::now_v7().to_string(),
        None,
        "user",
        &["resource://default".to_owned()],
        &["openid".to_owned()],
        None,
        None,
    )
    .await;
    revoke_access_token(&state, client_row_id, &token.jti).await;

    let response = userinfo_error_for_token(state, "Bearer", &token.token).await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        oauth_error_code(&response).as_deref(),
        Some("invalid_token")
    );
}

#[actix_web::test]
async fn userinfo_returns_server_error_when_subject_mapping_store_is_unavailable() {
    let Some(state) = live_userinfo_state().await else {
        return;
    };
    let token = signed_userinfo_access_token(
        &state,
        DEFAULT_TENANT_ID,
        &Uuid::now_v7().to_string(),
        None,
        "user",
        &["resource://default".to_owned()],
        &["openid".to_owned()],
        None,
        None,
    )
    .await;
    let state = Data::new(TestAppState {
        diesel_db: state.diesel_db.clone(),
        valkey: disconnected_valkey_client(),
        settings: state.settings.clone(),
        keyset: state.keyset.clone(),
    });

    let response = userinfo_error_for_token(state, "Bearer", &token.token).await;

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(oauth_error_code(&response).as_deref(), Some("server_error"));
}

#[actix_web::test]
async fn userinfo_rejects_sender_constrained_tokens_on_wrong_transport() {
    let Some(state) = live_userinfo_state().await else {
        return;
    };
    let bearer_with_dpop_cnf = signed_userinfo_access_token(
        &state,
        DEFAULT_TENANT_ID,
        &Uuid::now_v7().to_string(),
        None,
        "user",
        &["resource://default".to_owned()],
        &["openid".to_owned()],
        Some("dpop-thumbprint"),
        None,
    )
    .await;
    let response =
        userinfo_error_for_token(state.clone(), "Bearer", &bearer_with_dpop_cnf.token).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        oauth_error_code(&response).as_deref(),
        Some("invalid_dpop_proof")
    );

    let dpop_without_cnf = signed_userinfo_access_token(
        &state,
        DEFAULT_TENANT_ID,
        &Uuid::now_v7().to_string(),
        None,
        "user",
        &["resource://default".to_owned()],
        &["openid".to_owned()],
        None,
        None,
    )
    .await;
    let response = userinfo_error_for_token(state, "DPoP", &dpop_without_cnf.token).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        oauth_error_code(&response).as_deref(),
        Some("invalid_dpop_proof")
    );
}

#[actix_web::test]
async fn userinfo_rejects_mtls_bound_token_without_verified_certificate() {
    let Some(state) = live_userinfo_state().await else {
        return;
    };
    let token = signed_userinfo_access_token(
        &state,
        DEFAULT_TENANT_ID,
        &Uuid::now_v7().to_string(),
        None,
        "user",
        &["resource://default".to_owned()],
        &["openid".to_owned()],
        None,
        Some("ABEiM0RVZneImaq7zN3u_wARIjNEVWZ3iJmqu8zd7v8"),
    )
    .await;

    let response = userinfo_error_for_token(state, "Bearer", &token.token).await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        oauth_error_code(&response).as_deref(),
        Some("invalid_token")
    );
}

#[actix_web::test]
async fn userinfo_requires_openid_scope_and_user_subject_type() {
    let Some(state) = live_userinfo_state().await else {
        return;
    };
    for (subject_type, scopes) in [
        ("user", vec!["profile".to_owned()]),
        ("client", vec!["openid".to_owned()]),
    ] {
        let token = signed_userinfo_access_token(
            &state,
            DEFAULT_TENANT_ID,
            &Uuid::now_v7().to_string(),
            None,
            subject_type,
            &["resource://default".to_owned()],
            &scopes,
            None,
            None,
        )
        .await;

        let response = userinfo_error_for_token(state.clone(), "Bearer", &token.token).await;

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            oauth_error_code(&response).as_deref(),
            Some("insufficient_scope")
        );
    }
}

#[actix_web::test]
async fn userinfo_rejects_invalid_or_inactive_token_subject() {
    let Some(state) = live_userinfo_state().await else {
        return;
    };
    let invalid_subject = signed_userinfo_access_token(
        &state,
        DEFAULT_TENANT_ID,
        "not-a-uuid",
        None,
        "user",
        &["resource://default".to_owned()],
        &["openid".to_owned()],
        None,
        None,
    )
    .await;
    let response = userinfo_error_for_token(state.clone(), "Bearer", &invalid_subject.token).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        oauth_error_code(&response).as_deref(),
        Some("invalid_token")
    );

    let inactive = insert_userinfo_user(&state, false).await;
    let inactive_token = signed_userinfo_access_token(
        &state,
        DEFAULT_TENANT_ID,
        &inactive.id.to_string(),
        Some(inactive.id),
        "user",
        &["resource://default".to_owned()],
        &["openid".to_owned()],
        None,
        None,
    )
    .await;
    let response = userinfo_error_for_token(state, "Bearer", &inactive_token.token).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        oauth_error_code(&response).as_deref(),
        Some("invalid_token")
    );
}

#[actix_web::test]
async fn userinfo_returns_claims_for_active_user_access_token() {
    let Some(state) = live_userinfo_state().await else {
        return;
    };
    let client_id = format!("userinfo-json-{}", Uuid::now_v7());
    insert_userinfo_client(&state, &client_id).await;
    let user = insert_userinfo_user(&state, true).await;
    let response = userinfo_response_for_active_user(state, &user, &client_id).await;

    assert_eq!(response.status(), StatusCode::OK);
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("userinfo response body should collect");
    let value: Value = serde_json::from_slice(&body).expect("userinfo body should be JSON");
    assert_eq!(value["sub"], user.id.to_string());
    assert_eq!(value["email"], user.email);
}

#[actix_web::test]
async fn userinfo_returns_signed_jwt_for_registered_client_policy() {
    let Some(state) = live_userinfo_state().await else {
        return;
    };
    let client_id = format!("userinfo-signed-{}", Uuid::now_v7());
    insert_userinfo_client(&state, &client_id).await;
    update_userinfo_crypto_policy(&state, &client_id, Some("EdDSA"), None, None, None).await;
    let user = insert_userinfo_user(&state, true).await;

    let response = userinfo_response_for_active_user(state.clone(), &user, &client_id).await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("application/jwt")
    );
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("signed UserInfo body should collect");
    let claims = decode_signed_userinfo(
        &state,
        &client_id,
        std::str::from_utf8(&body).expect("signed UserInfo body should be UTF-8"),
    );
    assert_eq!(claims["iss"], state.settings.endpoint.issuer);
    assert_eq!(claims["aud"], client_id);
    assert_eq!(claims["sub"], user.id.to_string());
    assert_eq!(claims["email"], user.email);
    assert!(claims.get("scope").is_none());
    assert!(claims.get("client_id").is_none());
}

#[actix_web::test]
async fn userinfo_returns_encrypted_claims_for_registered_client_policy() {
    let Some(state) = live_userinfo_state().await else {
        return;
    };
    let client_id = format!("userinfo-encrypted-{}", Uuid::now_v7());
    insert_userinfo_client(&state, &client_id).await;
    let (private_key, public_jwk) = rsa_userinfo_jwe_keypair("userinfo-enc");
    update_userinfo_crypto_policy(
        &state,
        &client_id,
        None,
        Some("RSA-OAEP-256"),
        Some("A256GCM"),
        Some(json!({"keys": [public_jwk]})),
    )
    .await;
    let user = insert_userinfo_user(&state, true).await;

    let response = userinfo_response_for_active_user(state, &user, &client_id).await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("application/jwt")
    );
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("encrypted UserInfo body should collect");
    let (protected, plaintext) = decrypt_userinfo_jwe(
        &private_key,
        std::str::from_utf8(&body).expect("encrypted UserInfo body should be UTF-8"),
    );
    assert_eq!(protected["alg"], "RSA-OAEP-256");
    assert_eq!(protected["enc"], "A256GCM");
    assert_eq!(protected["kid"], "userinfo-enc");
    assert_eq!(protected["typ"], "JWT");
    assert!(protected.get("cty").is_none());
    let claims: Value = serde_json::from_str(&plaintext).expect("JWE claims should be JSON");
    assert_eq!(claims["sub"], user.id.to_string());
    assert_eq!(claims["email"], user.email);
    assert!(claims.get("scope").is_none());
}

#[actix_web::test]
async fn userinfo_signs_then_encrypts_when_both_policies_are_registered() {
    let Some(state) = live_userinfo_state().await else {
        return;
    };
    let client_id = format!("userinfo-nested-{}", Uuid::now_v7());
    insert_userinfo_client(&state, &client_id).await;
    let (private_key, public_jwk) = rsa_userinfo_jwe_keypair("userinfo-nested");
    update_userinfo_crypto_policy(
        &state,
        &client_id,
        Some("EdDSA"),
        Some("RSA-OAEP-256"),
        Some("A256GCM"),
        Some(json!({"keys": [public_jwk]})),
    )
    .await;
    let user = insert_userinfo_user(&state, true).await;

    let response = userinfo_response_for_active_user(state.clone(), &user, &client_id).await;

    assert_eq!(response.status(), StatusCode::OK);
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("nested UserInfo body should collect");
    let (protected, nested_jwt) = decrypt_userinfo_jwe(
        &private_key,
        std::str::from_utf8(&body).expect("nested UserInfo body should be UTF-8"),
    );
    assert_eq!(protected["cty"], "JWT");
    assert!(protected.get("typ").is_none());
    let claims = decode_signed_userinfo(&state, &client_id, &nested_jwt);
    assert_eq!(claims["iss"], state.settings.endpoint.issuer);
    assert_eq!(claims["aud"], client_id);
    assert_eq!(claims["sub"], user.id.to_string());
    assert_eq!(claims["email"], user.email);
}

#[actix_web::test]
async fn userinfo_crypto_failure_never_falls_back_to_json() {
    let Some(state) = live_userinfo_state().await else {
        return;
    };
    let client_id = format!("userinfo-failure-{}", Uuid::now_v7());
    insert_userinfo_client(&state, &client_id).await;
    update_userinfo_crypto_policy(
        &state,
        &client_id,
        None,
        Some("RSA-OAEP-256"),
        Some("A256GCM"),
        None,
    )
    .await;
    let user = insert_userinfo_user(&state, true).await;

    let response = userinfo_response_for_active_user(state, &user, &client_id).await;

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(oauth_error_code(&response).as_deref(), Some("server_error"));
}

#[actix_web::test]
async fn userinfo_rejects_missing_or_conflicting_access_token_transport_before_decode() {
    let state = Data::new(userinfo_test_state());

    let missing_req = actix_web::test::TestRequest::get()
        .uri("/userinfo")
        .to_http_request();
    let missing = call_userinfo(state.clone(), missing_req, Bytes::new()).await;
    assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(oauth_error_code(&missing).as_deref(), Some("invalid_token"));
    assert_eq!(
        missing
            .headers()
            .get(header::WWW_AUTHENTICATE)
            .and_then(|value| value.to_str().ok()),
        Some(r#"Bearer error="invalid_token", error_description="Request failed.""#)
    );
    assert_eq!(
        missing
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("application/json")
    );

    let duplicate_req = actix_web::test::TestRequest::post()
        .uri("/userinfo")
        .insert_header((header::AUTHORIZATION, "Bearer header-token"))
        .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
        .to_http_request();
    let duplicate = call_userinfo(
        state,
        duplicate_req,
        Bytes::from_static(b"access_token=body-token"),
    )
    .await;
    assert_eq!(duplicate.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        oauth_error_code(&duplicate).as_deref(),
        Some("invalid_request")
    );
    assert_eq!(
        duplicate
            .headers()
            .get(header::WWW_AUTHENTICATE)
            .and_then(|value| value.to_str().ok()),
        Some(
            r#"Bearer error="invalid_request", error_description="Only one access token transport method may be used.""#
        )
    );
    assert_eq!(
        duplicate
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("application/json")
    );
}

#[actix_web::test]
async fn userinfo_rejects_unverifiable_access_token_before_revocation_lookup() {
    let state = Data::new(userinfo_test_state());
    let req = actix_web::test::TestRequest::get()
        .uri("/userinfo")
        .insert_header((header::AUTHORIZATION, "Bearer not-a-jwt"))
        .to_http_request();

    let response = call_userinfo(state, req, Bytes::new()).await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        oauth_error_code(&response).as_deref(),
        Some("invalid_token")
    );
}

#[actix_web::test]
async fn userinfo_returns_server_error_when_revocation_lookup_fails_after_decode() {
    let state = userinfo_state_with_valid_signing_key_invalid_db();
    let token = signed_userinfo_access_token(
        &state,
        DEFAULT_TENANT_ID,
        &Uuid::now_v7().to_string(),
        None,
        "user",
        &["resource://default".to_owned()],
        &["openid".to_owned()],
        None,
        None,
    )
    .await;

    let response = userinfo_error_for_token(state, "Bearer", &token.token).await;

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(oauth_error_code(&response).as_deref(), Some("server_error"));
}

#[actix_web::test]
async fn userinfo_returns_server_error_when_revocation_query_fails_after_decode() {
    let schema = format!(
        "userinfo_revocation_query_failure_{}",
        Uuid::now_v7().simple()
    );
    let Some(database_url) = database_url_with_search_path(&schema) else {
        return;
    };
    let Some(state) = live_userinfo_state_from_database_url(database_url).await else {
        return;
    };
    create_isolated_schema(
        &state,
        &schema,
        &["users", "oauth_clients", "access_token_revocations"],
    )
    .await;
    let token = signed_userinfo_access_token(
        &state,
        DEFAULT_TENANT_ID,
        &Uuid::now_v7().to_string(),
        None,
        "user",
        &["resource://default".to_owned()],
        &["openid".to_owned()],
        None,
        None,
    )
    .await;
    rename_column(
        &state,
        &schema,
        "access_token_revocations",
        "access_token_jti_blake3",
        "access_token_jti_blake3_broken",
    )
    .await;

    let response = userinfo_error_for_token(state.clone(), "Bearer", &token.token).await;

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(oauth_error_code(&response).as_deref(), Some("server_error"));
    drop_schema(&state, &schema).await;
}

#[actix_web::test]
async fn userinfo_returns_server_error_when_subject_lookup_fails_after_token_validation() {
    let schema = format!("userinfo_subject_query_failure_{}", Uuid::now_v7().simple());
    let Some(database_url) = database_url_with_search_path(&schema) else {
        return;
    };
    let Some(state) = live_userinfo_state_from_database_url(database_url).await else {
        return;
    };
    create_isolated_schema(
        &state,
        &schema,
        &["users", "oauth_clients", "access_token_revocations"],
    )
    .await;
    let user = insert_userinfo_user(&state, true).await;
    let token = signed_userinfo_access_token(
        &state,
        DEFAULT_TENANT_ID,
        &user.id.to_string(),
        Some(user.id),
        "user",
        &["resource://default".to_owned()],
        &["openid".to_owned()],
        None,
        None,
    )
    .await;
    rename_column(&state, &schema, "users", "id", "id_broken").await;

    let response = userinfo_error_for_token(state.clone(), "Bearer", &token.token).await;

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(oauth_error_code(&response).as_deref(), Some("server_error"));
    drop_schema(&state, &schema).await;
}

#[actix_web::test]
async fn userinfo_rejects_mtls_bound_token_with_mismatched_verified_certificate() {
    let Some(state) = live_userinfo_state_with_trusted_proxy().await else {
        return;
    };
    let token = signed_userinfo_access_token(
        &state,
        DEFAULT_TENANT_ID,
        &Uuid::now_v7().to_string(),
        None,
        "user",
        &["resource://default".to_owned()],
        &["openid".to_owned()],
        None,
        Some("ABEiM0RVZneImaq7zN3u_wARIjNEVWZ3iJmqu8zd7v8"),
    )
    .await;
    let req = actix_web::test::TestRequest::get()
        .uri("/userinfo")
        .peer_addr("127.0.0.1:12345".parse().expect("peer addr should parse"))
        .insert_header((header::AUTHORIZATION, format!("Bearer {}", token.token)))
        .insert_header((
            header::HeaderName::from_static("x-ssl-client-verify"),
            "SUCCESS",
        ))
        .insert_header((
            header::HeaderName::from_static("x-ssl-client-cert-sha256"),
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ))
        .insert_header((
            header::HeaderName::from_static("x-ssl-client-subject-dn"),
            "CN=userinfo-mismatch",
        ))
        .to_http_request();

    let response = call_userinfo(state, req, Bytes::new()).await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        oauth_error_code(&response).as_deref(),
        Some("invalid_token")
    );
}

#[test]
fn userinfo_accepts_only_userinfo_or_default_audience() {
    let mut settings = Settings::from_config(&crate::config::ConfigSource::default())
        .expect("default settings should load");
    settings.endpoint.issuer = "https://issuer.example".to_owned();
    settings.protocol.default_audience = "resource://default".to_owned();

    assert!(userinfo_audience_allowed(
        &settings,
        &json!("resource://default")
    ));
    assert!(userinfo_audience_allowed(
        &settings,
        &json!("https://issuer.example/userinfo")
    ));
    assert!(userinfo_audience_allowed(
        &settings,
        &json!(["resource://other", "https://issuer.example/userinfo"])
    ));
    assert!(!userinfo_audience_allowed(
        &settings,
        &json!("https://issuer.example/fapi/resource")
    ));
    assert!(!userinfo_audience_allowed(
        &settings,
        &json!(["resource://other", "https://issuer.example/fapi/resource"])
    ));
}
