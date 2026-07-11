use super::*;
use std::sync::Arc;

use crate::config::ConfigSource;
use crate::db::{create_pool, get_conn};
use crate::domain::ConfirmationClaims;
use crate::domain::{ActiveSigningKey, Claims, Keyset, KeysetStore, VerificationKey};
use crate::support::{generate_key_material, hash_client_secret, public_jwk_from_private_der};
use actix_web::test::TestRequest;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use diesel::sql_query;
use diesel::sql_types::{Bool, Jsonb, Nullable, Text, Timestamptz, Uuid as SqlUuid};
use diesel_async::RunQueryDsl;
use fred::interfaces::ClientLike;
use fred::prelude::{Builder as ValkeyBuilder, Config as ValkeyConfig};
use openssl::encrypt::Decrypter;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::rsa::{Padding, Rsa};
use openssl::symm::{Cipher, decrypt_aead};

fn introspection_state() -> Data<AppState> {
    Data::new(AppState {
        diesel_db: create_pool(
            "postgres://nazo_introspect_test_invalid:nazo_introspect_test_invalid@127.0.0.1:1/nazo"
                .to_owned(),
            1,
        )
        .expect("pool construction should not connect"),
        valkey: fred::prelude::Builder::default_centralized()
            .build()
            .expect("valkey client construction should not connect"),
        settings: Arc::new(
            Settings::from_config(&ConfigSource::default()).expect("default settings should load"),
        ),
        keyset: KeysetStore::new(Keyset {
            active_kid: "test-kid".to_owned(),
            active_alg: jsonwebtoken::Algorithm::EdDSA,
            active_signing_key: ActiveSigningKey::LocalPkcs8Der(Vec::new()),
            verification_keys: Vec::new(),
        }),
    })
}

fn signed_introspection_offline_state() -> Data<AppState> {
    let key_material =
        generate_key_material(jsonwebtoken::Algorithm::EdDSA).expect("test key should generate");
    let public_jwk = public_jwk_from_private_der(
        "introspect-offline-kid",
        jsonwebtoken::Algorithm::EdDSA,
        &key_material.private_pkcs8_der,
    )
    .expect("test public JWK should derive");
    let mut settings =
        Settings::from_config(&ConfigSource::default()).expect("default settings should load");
    settings.issuer = "https://issuer.example".to_owned();
    settings.authorization_server_profile =
        crate::settings::AuthorizationServerProfile::Fapi2MessageSigningIntrospection;
    Data::new(AppState {
        diesel_db: create_pool(
            "postgres://nazo_introspect_test_invalid:nazo_introspect_test_invalid@127.0.0.1:1/nazo"
                .to_owned(),
            1,
        )
        .expect("pool construction should not connect"),
        valkey: fred::prelude::Builder::default_centralized()
            .build()
            .expect("valkey client construction should not connect"),
        settings: Arc::new(settings),
        keyset: KeysetStore::new(Keyset {
            active_kid: "introspect-offline-kid".to_owned(),
            active_alg: jsonwebtoken::Algorithm::EdDSA,
            active_signing_key: ActiveSigningKey::LocalPkcs8Der(key_material.private_pkcs8_der),
            verification_keys: vec![VerificationKey {
                kid: "introspect-offline-kid".to_owned(),
                public_jwk,
                local_signing_key: None,
            }],
        }),
    })
}

fn live_introspection_state() -> Option<Data<AppState>> {
    let database_url = std::env::var("DATABASE_URL").ok()?;
    live_introspection_state_from_database_url(database_url)
}

fn fixture_secret(label: &str) -> String {
    format!("introspection-fixture-secret-{label}")
}

fn fixture_token(label: &str) -> String {
    format!("introspection-fixture-token-{label}")
}

fn live_introspection_state_from_database_url(database_url: String) -> Option<Data<AppState>> {
    let key_material =
        generate_key_material(jsonwebtoken::Algorithm::EdDSA).expect("test key should generate");
    let public_jwk = public_jwk_from_private_der(
        "introspect-test-kid",
        jsonwebtoken::Algorithm::EdDSA,
        &key_material.private_pkcs8_der,
    )
    .expect("test public JWK should derive");
    let mut settings =
        Settings::from_config(&ConfigSource::default()).expect("default settings should load");
    settings.issuer = "https://issuer.example".to_owned();
    settings.default_audience = "resource://default".to_owned();

    Some(Data::new(AppState {
        diesel_db: create_pool(database_url, 1).expect("database pool should build"),
        valkey: fred::prelude::Builder::default_centralized()
            .build()
            .expect("valkey client construction should not connect"),
        settings: Arc::new(settings),
        keyset: KeysetStore::new(Keyset {
            active_kid: "introspect-test-kid".to_owned(),
            active_alg: jsonwebtoken::Algorithm::EdDSA,
            active_signing_key: ActiveSigningKey::LocalPkcs8Der(key_material.private_pkcs8_der),
            verification_keys: vec![VerificationKey {
                kid: "introspect-test-kid".to_owned(),
                public_jwk,
                local_signing_key: None,
            }],
        }),
    }))
}

fn with_signed_introspection_profile(state: &Data<AppState>) -> Data<AppState> {
    let mut settings = (*state.settings).clone();
    settings.authorization_server_profile =
        crate::settings::AuthorizationServerProfile::Fapi2MessageSigningIntrospection;
    Data::new(AppState {
        diesel_db: state.diesel_db.clone(),
        valkey: state.valkey.clone(),
        settings: Arc::new(settings),
        keyset: state.keyset.clone(),
    })
}

fn introspection_response_client(
    client_id: &str,
    jwks: Option<Value>,
    encrypted_response_alg: Option<&str>,
    encrypted_response_enc: Option<&str>,
) -> ClientRow {
    ClientRow {
        id: Uuid::now_v7(),
        tenant_id: DEFAULT_TENANT_ID,
        realm_id: DEFAULT_REALM_ID,
        organization_id: DEFAULT_ORGANIZATION_ID,
        client_id: client_id.to_owned(),
        client_name: "Introspection Response Client".to_owned(),
        client_type: "confidential".to_owned(),
        client_secret_hash: None,
        redirect_uris: json!(["https://client.example/callback"]),
        scopes: json!(["openid"]),
        allowed_audiences: json!(["resource://default"]),
        grant_types: json!(["authorization_code"]),
        token_endpoint_auth_method: "client_secret_post".to_owned(),
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
        jwks,
        introspection_encrypted_response_alg: encrypted_response_alg.map(ToOwned::to_owned),
        introspection_encrypted_response_enc: encrypted_response_enc.map(ToOwned::to_owned),
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

fn rsa_jwe_keypair(kid: &str) -> (PKey<Private>, Value) {
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

fn decrypt_compact_jwe(private_key: &PKey<Private>, compact_jwe: &str) -> (Value, String) {
    let parts = compact_jwe.split('.').collect::<Vec<_>>();
    assert_eq!(
        parts.len(),
        5,
        "JWE compact serialization must have 5 parts"
    );
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

    let mut decrypter = Decrypter::new(private_key).expect("RSA-OAEP decrypter should initialize");
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
        .expect("encrypted content-encryption key should decrypt");
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
        String::from_utf8(plaintext).expect("nested JWT should be UTF-8"),
    )
}

fn database_url_with_search_path(schema: &str) -> Option<String> {
    let base = std::env::var("DATABASE_URL").ok()?;
    let separator = if base.contains('?') { "&" } else { "?" };
    Some(format!(
        "{base}{separator}options=-csearch_path%3D{schema}%2Cpublic"
    ))
}

async fn create_isolated_schema(state: &Data<AppState>, schema: &str, tables: &[&str]) {
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

async fn exec_sql(state: &Data<AppState>, sql: &str) {
    let mut conn = get_conn(&state.diesel_db)
        .await
        .expect("database connection should be available");
    sql_query(sql)
        .execute(&mut conn)
        .await
        .expect("schema mutation should succeed");
}

async fn rename_column(state: &Data<AppState>, schema: &str, table: &str, from: &str, to: &str) {
    exec_sql(
        state,
        &format!(
            r#"ALTER TABLE "{}"."{}" RENAME COLUMN "{}" TO "{}""#,
            schema, table, from, to
        ),
    )
    .await;
}

async fn drop_schema(state: &Data<AppState>, schema: &str) {
    exec_sql(
        state,
        &format!(r#"DROP SCHEMA IF EXISTS "{}" CASCADE"#, schema),
    )
    .await;
}

async fn live_rate_limited_introspection_state() -> Option<Data<AppState>> {
    let state = live_introspection_state()?;
    let valkey_url = std::env::var("VALKEY_URL").ok()?;
    let valkey = ValkeyBuilder::from_config(
        ValkeyConfig::from_url(&valkey_url).expect("VALKEY_URL should parse"),
    )
    .build()
    .expect("valkey client should build");
    valkey.init().await.expect("valkey should connect");
    let mut settings = (*state.settings).clone();
    settings.rate_limit.token_management_max_requests = 0;

    Some(Data::new(AppState {
        diesel_db: state.diesel_db.clone(),
        valkey,
        settings: Arc::new(settings),
        keyset: state.keyset.clone(),
    }))
}

async fn insert_introspection_client(
    state: &Data<AppState>,
    client_id: &str,
    secret: &str,
) -> ClientRow {
    let row = ClientRow {
        id: Uuid::now_v7(),
        tenant_id: DEFAULT_TENANT_ID,
        realm_id: DEFAULT_REALM_ID,
        organization_id: DEFAULT_ORGANIZATION_ID,
        client_id: client_id.to_owned(),
        client_name: "Introspection Test Client".to_owned(),
        client_type: "confidential".to_owned(),
        client_secret_hash: Some(hash_client_secret(
            secret,
            &state.settings.client_secret_pepper,
        )),
        redirect_uris: json!(["https://client.example/callback"]),
        scopes: json!(["openid", "offline_access"]),
        allowed_audiences: json!(["resource://default"]),
        grant_types: json!(["authorization_code", "refresh_token"]),
        token_endpoint_auth_method: "client_secret_post".to_owned(),
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
    };
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
    .bind::<SqlUuid, _>(row.tenant_id)
    .bind::<Text, _>(row.client_id.as_str())
    .execute(&mut conn)
    .await
    .expect("introspection access token revocation cleanup should succeed");
    sql_query(
        r#"
        DELETE FROM oauth_tokens
        USING oauth_clients
        WHERE oauth_tokens.client_id = oauth_clients.id
          AND oauth_clients.tenant_id = $1
          AND oauth_clients.client_id = $2
        "#,
    )
    .bind::<SqlUuid, _>(row.tenant_id)
    .bind::<Text, _>(row.client_id.as_str())
    .execute(&mut conn)
    .await
    .expect("introspection refresh token cleanup should succeed");
    sql_query("DELETE FROM oauth_clients WHERE tenant_id = $1 AND client_id = $2")
        .bind::<SqlUuid, _>(row.tenant_id)
        .bind::<Text, _>(row.client_id.as_str())
        .execute(&mut conn)
        .await
        .expect("introspection test client cleanup should succeed");
    sql_query(
        r#"
        INSERT INTO oauth_clients (
            id, tenant_id, realm_id, organization_id, client_id, client_name, client_type,
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
            $1, $2, $3, $4, $5, $6, $7,
            $8, $9, $10, $11,
            $12, $13, $14,
            $15, '[]'::jsonb, '[]'::jsonb,
            '[]'::jsonb, '[]'::jsonb,
            false, false, false,
            false, true,
            '[]'::jsonb, true
        )
        "#,
    )
    .bind::<SqlUuid, _>(row.id)
    .bind::<SqlUuid, _>(row.tenant_id)
    .bind::<SqlUuid, _>(row.realm_id)
    .bind::<SqlUuid, _>(row.organization_id)
    .bind::<Text, _>(row.client_id.as_str())
    .bind::<Text, _>(row.client_name.as_str())
    .bind::<Text, _>(row.client_type.as_str())
    .bind::<Nullable<Text>, _>(row.client_secret_hash.as_deref())
    .bind::<Jsonb, _>(row.redirect_uris.clone())
    .bind::<Jsonb, _>(row.scopes.clone())
    .bind::<Jsonb, _>(row.allowed_audiences.clone())
    .bind::<Jsonb, _>(row.grant_types.clone())
    .bind::<Text, _>(row.token_endpoint_auth_method.as_str())
    .bind::<Bool, _>(row.require_dpop_bound_tokens)
    .bind::<Bool, _>(row.require_mtls_bound_tokens)
    .execute(&mut conn)
    .await
    .expect("introspection test client insert should succeed");
    row
}

async fn sign_access_token(
    state: &Data<AppState>,
    tenant_id: Uuid,
    client_id: &str,
    audience: Value,
) -> IssuedAccessToken {
    make_jwt(
        state,
        AccessTokenJwtInput {
            tenant_id,
            subject: client_id,
            user_id: None,
            subject_type: "client",
            client_id,
            audiences: &json_array_to_strings(&audience),
            scopes: &["openid".to_owned()],
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
    .expect("access token should sign")
}

async fn insert_access_token_revocation(
    state: &Data<AppState>,
    client: &ClientRow,
    access_token_jti: &str,
) {
    let mut conn = get_conn(&state.diesel_db)
        .await
        .expect("database connection should be available");
    sql_query(
        r#"
        INSERT INTO access_token_revocations (
            tenant_id, client_id, access_token_jti_blake3, revoked_at, expires_at
        )
        VALUES ($1, $2, $3, now(), $4)
        "#,
    )
    .bind::<SqlUuid, _>(client.tenant_id)
    .bind::<SqlUuid, _>(client.id)
    .bind::<Text, _>(blake3_hex(access_token_jti))
    .bind::<Timestamptz, _>(Utc::now() + Duration::minutes(5))
    .execute(&mut conn)
    .await
    .expect("introspection test access token revocation insert should succeed");
}

async fn insert_refresh_token_for_client(
    state: &Data<AppState>,
    client_id: Uuid,
    raw_refresh_token: &str,
    revoked_at: Option<DateTime<Utc>>,
    expires_at: DateTime<Utc>,
) {
    let mut conn = get_conn(&state.diesel_db)
        .await
        .expect("database connection should be available");
    sql_query("DELETE FROM oauth_tokens WHERE tenant_id = $1 AND refresh_token_blake3 = $2")
        .bind::<SqlUuid, _>(DEFAULT_TENANT_ID)
        .bind::<Text, _>(blake3_hex(raw_refresh_token))
        .execute(&mut conn)
        .await
        .expect("refresh token cleanup should succeed");
    sql_query(
        r#"
        INSERT INTO oauth_tokens (
            id, tenant_id, refresh_token_blake3, token_family_id, rotated_from_id,
            client_id, user_id, scopes, authorization_details, issued_at, expires_at,
            revoked_at, reuse_detected_at, subject, dpop_jkt, mtls_x5t_s256
        )
        VALUES (
            $1, $2, $3, $4, NULL,
            $5, NULL, '["openid","offline_access"]'::jsonb, '[]'::jsonb, now(), $6,
            $7, NULL, 'subject-1', NULL, NULL
        )
        "#,
    )
    .bind::<SqlUuid, _>(Uuid::now_v7())
    .bind::<SqlUuid, _>(DEFAULT_TENANT_ID)
    .bind::<Text, _>(blake3_hex(raw_refresh_token))
    .bind::<SqlUuid, _>(Uuid::now_v7())
    .bind::<SqlUuid, _>(client_id)
    .bind::<Timestamptz, _>(expires_at)
    .bind::<Nullable<Timestamptz>, _>(revoked_at)
    .execute(&mut conn)
    .await
    .expect("refresh token insert should succeed");
}

async fn introspect_with_client(
    state: Data<AppState>,
    client_id: &str,
    client_secret: &str,
    token: &str,
) -> (StatusCode, Value) {
    let body = Bytes::from(format!(
        "token={}&client_id={}&client_secret={}",
        urlencoding::encode(token),
        urlencoding::encode(client_id),
        urlencoding::encode(client_secret)
    ));
    json_body(introspect_after_rate_limit(state, form_request(), body).await).await
}

fn form_request() -> HttpRequest {
    TestRequest::default()
        .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
        .to_http_request()
}

fn signed_introspection_form_request() -> HttpRequest {
    TestRequest::default()
        .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
        .insert_header((
            header::ACCEPT,
            HeaderValue::from_static("application/token-introspection+jwt"),
        ))
        .to_http_request()
}

async fn introspect_form(body: &'static [u8]) -> HttpResponse {
    introspect_after_rate_limit(
        introspection_state(),
        form_request(),
        Bytes::from_static(body),
    )
    .await
}

async fn json_body(response: HttpResponse) -> (StatusCode, Value) {
    let status = response.status();
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        HeaderValue::from_static("no-store")
    );
    assert_eq!(
        response.headers().get(header::PRAGMA).unwrap(),
        HeaderValue::from_static("no-cache")
    );
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("response body should collect");
    let value = serde_json::from_slice(&body).expect("response body should be JSON");
    (status, value)
}

async fn signed_introspection_jwt_body(state: &Data<AppState>, response: HttpResponse) -> Value {
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        HeaderValue::from_static("application/token-introspection+jwt")
    );
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        HeaderValue::from_static("no-store")
    );
    assert_eq!(
        response.headers().get(header::PRAGMA).unwrap(),
        HeaderValue::from_static("no-cache")
    );
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("JWT introspection response body should collect");
    let token = std::str::from_utf8(&body).expect("JWT response body should be UTF-8");
    let header = jsonwebtoken::decode_header(token).expect("JWT header should decode");
    assert_eq!(header.typ.as_deref(), Some("token-introspection+jwt"));
    let keyset = state.keyset.snapshot();
    let verification_key = keyset
        .verification_key(
            header
                .kid
                .as_deref()
                .expect("signed response should include kid"),
        )
        .expect("signed response key should be published");
    let decoding_key = jwt_decoding_key_from_jwk(&verification_key.public_jwk, header.alg)
        .expect("signed response key should decode");
    let mut validation = jsonwebtoken::Validation::new(header.alg);
    validation.validate_aud = false;
    validation.validate_exp = false;
    validation.required_spec_claims.clear();
    validation.set_issuer(&[state.settings.issuer.as_str()]);
    jsonwebtoken::decode::<Value>(token, &decoding_key, &validation)
        .expect("JWT introspection response should verify")
        .claims
}

fn access_claims(cnf: Option<ConfirmationClaims>) -> Claims {
    Claims {
        iss: "https://as.example".to_owned(),
        sub: "subject".to_owned(),
        tenant_id: DEFAULT_TENANT_ID.to_string(),
        user_id: None,
        subject_type: "client".to_owned(),
        aud: json!("resource://default"),
        client_id: "client-1".to_owned(),
        scope: "openid".to_owned(),
        authorization_details: json!([]),
        token_use: "access".to_owned(),
        jti: "jti-1".to_owned(),
        iat: 1,
        nbf: 1,
        exp: 2,
        cnf,
        act: None,
        userinfo_claims: Vec::new(),
        userinfo_claim_requests: Vec::new(),
    }
}

#[test]
fn access_token_introspection_type_matches_issued_bearer_token_type() {
    assert_eq!(
        introspection_access_token_type(&access_claims(None)),
        "Bearer"
    );
}

#[test]
fn access_token_introspection_type_matches_issued_dpop_token_type() {
    let claims = access_claims(Some(ConfirmationClaims {
        jkt: Some("thumbprint".to_owned()),
        x5t_s256: None,
    }));

    assert_eq!(introspection_access_token_type(&claims), "DPoP");
}

#[test]
fn mtls_bound_access_token_introspection_type_remains_bearer() {
    let claims = access_claims(Some(ConfirmationClaims {
        jkt: None,
        x5t_s256: Some("certificate-thumbprint".to_owned()),
    }));

    assert_eq!(introspection_access_token_type(&claims), "Bearer");
}

#[test]
fn refresh_token_introspection_metadata_omits_access_token_type() {
    let issued_at = DateTime::<Utc>::from_timestamp(1_700_000_000, 0).unwrap();
    let token = TokenRow {
        id: Uuid::now_v7(),
        tenant_id: DEFAULT_TENANT_ID,
        token_family_id: Uuid::now_v7(),
        client_id: Uuid::now_v7(),
        user_id: None,
        scopes: json!(["openid", "offline_access"]),
        audience: json!(["resource://default"]),
        authorization_details: json!([]),
        issued_at,
        expires_at: issued_at + Duration::days(30),
        revoked_at: None,
        subject: "subject".to_owned(),
        dpop_jkt: None,
        mtls_x5t_s256: None,
    };

    let body = active_refresh_token_introspection_body(&token, "client-1");

    assert_eq!(body.get("active"), Some(&json!(true)));
    assert_eq!(body.get("client_id"), Some(&json!("client-1")));
    assert_eq!(body.get("scope"), Some(&json!("openid offline_access")));
    assert_eq!(
        body.get("exp"),
        Some(&json!(issued_at.timestamp() + 30 * 24 * 60 * 60))
    );
    assert_eq!(body.get("iat"), Some(&json!(issued_at.timestamp())));
    assert_eq!(body.get("sub"), Some(&json!("subject")));
    assert!(!body.as_object().unwrap().contains_key("token_type"));
    assert!(!body.as_object().unwrap().contains_key("jti"));
}

#[actix_web::test]
async fn inactive_introspection_response_is_minimal_and_not_cacheable() {
    let response = json_response_no_store(json!({"active": false}));

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        HeaderValue::from_static("no-store")
    );
    assert_eq!(
        response.headers().get(header::PRAGMA).unwrap(),
        HeaderValue::from_static("no-cache")
    );
    assert!(response.headers().get(header::WWW_AUTHENTICATE).is_none());

    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("response body should collect");
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value, json!({"active": false}));
    assert!(
        value.get("client_id").is_none() && value.get("sub").is_none(),
        "inactive introspection must not leak token metadata"
    );
}

#[actix_web::test]
async fn signed_introspection_response_wraps_body_without_top_level_token_claims() {
    let state = signed_introspection_offline_state();
    let client = introspection_response_client("resource-server-client", None, None, None);
    let response = signed_introspection_response(
        &state,
        &client,
        json!({
            "active": true,
            "sub": "subject-1",
            "exp": 1_900_000_000,
            "client_id": "client-1"
        }),
    )
    .await
    .expect("signed introspection response should be signable");

    let claims = signed_introspection_jwt_body(&state, response).await;

    assert_eq!(claims.get("aud"), Some(&json!("resource-server-client")));
    assert!(claims.get("sub").is_none());
    assert!(claims.get("exp").is_none());
    assert_eq!(
        claims.pointer("/token_introspection/sub"),
        Some(&json!("subject-1"))
    );
    assert_eq!(
        claims.pointer("/token_introspection/exp"),
        Some(&json!(1_900_000_000))
    );
}

#[actix_web::test]
async fn encrypted_introspection_response_is_nested_jwt_for_configured_resource_server() {
    let state = signed_introspection_offline_state();
    let (private_key, encryption_jwk) = rsa_jwe_keypair("introspection-enc-key");
    let client = introspection_response_client(
        "encrypted-resource-server",
        Some(json!({ "keys": [encryption_jwk] })),
        Some("RSA-OAEP-256"),
        Some("A256GCM"),
    );

    let response = signed_introspection_response(
        &state,
        &client,
        json!({
            "active": true,
            "sub": "subject-1",
            "exp": 1_900_000_000,
            "client_id": "client-1"
        }),
    )
    .await
    .expect("encrypted introspection response should be buildable");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        HeaderValue::from_static("application/token-introspection+jwt")
    );
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("JWE introspection response body should collect");
    let compact_jwe = std::str::from_utf8(&body).expect("JWE response body should be UTF-8");
    let (jwe_header, nested_jwt) = decrypt_compact_jwe(&private_key, compact_jwe);
    assert_eq!(jwe_header.get("alg"), Some(&json!("RSA-OAEP-256")));
    assert_eq!(jwe_header.get("enc"), Some(&json!("A256GCM")));
    assert_eq!(jwe_header.get("cty"), Some(&json!("JWT")));
    assert_eq!(jwe_header.get("kid"), Some(&json!("introspection-enc-key")));

    let jwt_header = jsonwebtoken::decode_header(&nested_jwt).expect("nested JWT should decode");
    assert_eq!(jwt_header.typ.as_deref(), Some("token-introspection+jwt"));
    let keyset = state.keyset.snapshot();
    let verification_key = keyset
        .verification_key(
            jwt_header
                .kid
                .as_deref()
                .expect("nested signed response should include kid"),
        )
        .expect("nested signed response key should be published");
    let decoding_key = jwt_decoding_key_from_jwk(&verification_key.public_jwk, jwt_header.alg)
        .expect("nested signed response key should decode");
    let mut validation = jsonwebtoken::Validation::new(jwt_header.alg);
    validation.validate_aud = false;
    validation.validate_exp = false;
    validation.required_spec_claims.clear();
    validation.set_issuer(&[state.settings.issuer.as_str()]);
    let claims = jsonwebtoken::decode::<Value>(&nested_jwt, &decoding_key, &validation)
        .expect("nested JWT introspection response should verify")
        .claims;

    assert_eq!(claims.get("aud"), Some(&json!("encrypted-resource-server")));
    assert!(claims.get("sub").is_none());
    assert_eq!(
        claims.pointer("/token_introspection/sub"),
        Some(&json!("subject-1"))
    );
}

#[test]
fn introspection_encryption_key_rejects_incomplete_metadata_and_unusable_keys() {
    let (_, encryption_jwk) = rsa_jwe_keypair("introspection-enc-key");

    let signed_only = introspection_response_client("signed-only", None, None, None);
    assert!(matches!(
        introspection_encryption_key(&signed_only),
        Ok(None)
    ));

    let missing_alg = introspection_response_client(
        "missing-alg",
        Some(json!({ "keys": [encryption_jwk.clone()] })),
        None,
        Some("A256GCM"),
    );
    assert!(introspection_encryption_key(&missing_alg).is_err());

    let missing_enc = introspection_response_client(
        "missing-enc",
        Some(json!({ "keys": [encryption_jwk.clone()] })),
        Some("RSA-OAEP-256"),
        None,
    );
    assert!(introspection_encryption_key(&missing_enc).is_err());

    let mut signing_use_key = encryption_jwk.clone();
    signing_use_key
        .as_object_mut()
        .expect("test jwk should be an object")
        .insert("use".to_owned(), json!("sig"));
    let wrong_use = introspection_response_client(
        "wrong-use",
        Some(json!({ "keys": [signing_use_key] })),
        Some("RSA-OAEP-256"),
        Some("A256GCM"),
    );
    assert!(introspection_encryption_key(&wrong_use).is_err());

    let mut wrong_alg_key = encryption_jwk.clone();
    wrong_alg_key
        .as_object_mut()
        .expect("test jwk should be an object")
        .insert("alg".to_owned(), json!("RSA-OAEP"));
    let wrong_alg = introspection_response_client(
        "wrong-alg",
        Some(json!({ "keys": [wrong_alg_key] })),
        Some("RSA-OAEP-256"),
        Some("A256GCM"),
    );
    assert!(introspection_encryption_key(&wrong_alg).is_err());

    let mut missing_kid_key = encryption_jwk;
    missing_kid_key
        .as_object_mut()
        .expect("test jwk should be an object")
        .remove("kid");
    let missing_kid = introspection_response_client(
        "missing-kid",
        Some(json!({ "keys": [missing_kid_key] })),
        Some("RSA-OAEP-256"),
        Some("A256GCM"),
    );
    assert!(introspection_encryption_key(&missing_kid).is_err());
}

#[test]
fn token_management_server_errors_are_oauth_json_without_auth_challenge() {
    let response = token_management_oauth_error(
        StatusCode::SERVICE_UNAVAILABLE,
        "server_error",
        "token 状态查询失败.",
    );

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        response
            .extensions()
            .get::<OAuthJsonErrorFields>()
            .map(|fields| fields.error.as_str()),
        Some("server_error")
    );
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        HeaderValue::from_static("no-store")
    );
    assert_eq!(
        response.headers().get(header::PRAGMA).unwrap(),
        HeaderValue::from_static("no-cache")
    );
    assert!(
        response.headers().get(header::WWW_AUTHENTICATE).is_none(),
        "backend failures must not be exposed as client-auth challenges"
    );
}

#[actix_web::test]
async fn introspection_rejects_malformed_form_before_token_lookup() {
    let cases = [
        introspect_after_rate_limit(
            introspection_state(),
            TestRequest::default()
                .insert_header((header::CONTENT_TYPE, "application/json"))
                .to_http_request(),
            Bytes::from_static(br#"{"token":"secret"}"#),
        )
        .await,
        introspect_form(b"token=\xff").await,
        introspect_form(b"token=token-1&token=token-2").await,
        introspect_form(b"token=%20%20").await,
    ];

    for response in cases {
        assert!(
            response.headers().get(header::WWW_AUTHENTICATE).is_none(),
            "malformed introspection input is invalid_request, not a client-auth challenge"
        );
        let (status, body) = json_body(response).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body.get("error"), Some(&json!("invalid_request")));
        assert_eq!(
            body.get("error_description"),
            Some(&json!("Request failed."))
        );
        assert!(body.get("active").is_none());
        assert!(body.get("client_id").is_none());
        assert!(body.get("sub").is_none());
    }
}

#[actix_web::test]
async fn introspection_rate_limit_short_circuits_before_client_or_token_lookup() {
    let Some(state) = live_rate_limited_introspection_state().await else {
        return;
    };
    let response = introspect(
        state,
        form_request(),
        Bytes::from_static(
            b"token=refresh-token&client_id=rate-limited-client&client_secret=secret",
        ),
    )
    .await;

    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        response
            .extensions()
            .get::<OAuthJsonErrorFields>()
            .map(|fields| fields.error.as_str()),
        Some("temporarily_unavailable")
    );
}

#[actix_web::test]
async fn introspection_rejects_conflicting_client_auth_without_token_lookup() {
    let response = introspect_after_rate_limit(
        introspection_state(),
        TestRequest::default()
            .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
            .insert_header((header::AUTHORIZATION, "Basic Y2xpZW50LTE6c2VjcmV0"))
            .to_http_request(),
        Bytes::from_static(b"token=token-1&client_assertion=jwt"),
    )
    .await;

    let (status, body) = json_body(response).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body.get("error"), Some(&json!("invalid_request")));
    assert_eq!(
        body.get("error_description"),
        Some(&json!("Request failed."))
    );
    assert!(body.get("active").is_none());
    assert!(body.get("client_id").is_none());
    assert!(body.get("sub").is_none());
}

#[actix_web::test]
async fn introspection_requires_client_authentication_before_token_lookup() {
    let response = introspect_after_rate_limit(
        introspection_state(),
        form_request(),
        Bytes::from_static(b"token=token-1"),
    )
    .await;

    assert!(
        response.headers().get(header::WWW_AUTHENTICATE).is_none(),
        "introspection must not invent a Basic challenge unless the client attempted Basic auth"
    );
    let (status, body) = json_body(response).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body.get("error"), Some(&json!("invalid_client")));
    assert_eq!(
        body.get("error_description"),
        Some(&json!("Request failed."))
    );
    assert!(body.get("active").is_none());
    assert!(body.get("client_id").is_none());
    assert!(body.get("sub").is_none());
}

#[actix_web::test]
async fn introspection_client_lookup_failures_return_server_error() {
    let response = introspect_after_rate_limit(
        introspection_state(),
        form_request(),
        Bytes::from_static(b"token=token-1&client_id=introspect-lookup-error&client_secret=secret"),
    )
    .await;

    let (status, body) = json_body(response).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body.get("error"), Some(&json!("server_error")));
    assert!(body.get("active").is_none());
    assert!(body.get("client_id").is_none());
    assert!(body.get("sub").is_none());
}

#[actix_web::test]
async fn introspection_rejects_unknown_client_before_token_state_lookup() {
    let Some(state) = live_introspection_state() else {
        return;
    };
    let missing_client = format!("missing-introspect-client-{}", Uuid::now_v7());
    let body = Bytes::from(format!(
        "token={}&client_id={missing_client}&client_secret=secret",
        urlencoding::encode("token-1")
    ));

    let response = introspect_after_rate_limit(state, form_request(), body).await;

    let (status, body) = json_body(response).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body.get("error"), Some(&json!("invalid_client")));
    assert_eq!(
        body.get("error_description"),
        Some(&json!("Request failed."))
    );
    assert!(body.get("active").is_none());
    assert!(body.get("client_id").is_none());
    assert!(body.get("sub").is_none());
}

#[actix_web::test]
async fn introspection_rejects_wrong_client_secret_before_token_state_lookup() {
    let Some(state) = live_introspection_state() else {
        return;
    };
    let correct_secret = fixture_secret("registered");
    let wrong_secret = fixture_secret("presented");
    let token = fixture_token("wrong-client-secret");
    let client = insert_introspection_client(
        &state,
        &format!("introspect-auth-mismatch-{}", Uuid::now_v7()),
        &correct_secret,
    )
    .await;

    let (status, body) =
        introspect_with_client(state, &client.client_id, &wrong_secret, &token).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body.get("error"), Some(&json!("invalid_client")));
    assert_eq!(
        body.get("error_description"),
        Some(&json!("Request failed."))
    );
    assert!(body.get("active").is_none());
    assert!(body.get("client_id").is_none());
    assert!(body.get("sub").is_none());
}

#[actix_web::test]
async fn introspection_fails_closed_when_client_lookup_query_fails() {
    let schema = format!(
        "introspect_client_lookup_failure_{}",
        Uuid::now_v7().simple()
    );
    let Some(database_url) = database_url_with_search_path(&schema) else {
        return;
    };
    let Some(state) = live_introspection_state_from_database_url(database_url) else {
        return;
    };
    create_isolated_schema(
        &state,
        &schema,
        &["oauth_clients", "oauth_tokens", "access_token_revocations"],
    )
    .await;
    let client = insert_introspection_client(
        &state,
        &format!("introspect-client-query-failure-{}", Uuid::now_v7()),
        &fixture_secret("client-query-failure"),
    )
    .await;
    rename_column(
        &state,
        &schema,
        "oauth_clients",
        "client_id",
        "client_id_broken",
    )
    .await;

    let (status, body) = introspect_with_client(
        state.clone(),
        &client.client_id,
        &fixture_secret("client-query-failure"),
        &fixture_token("client-query-failure"),
    )
    .await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body.get("error"), Some(&json!("server_error")));
    assert!(body.get("active").is_none());
    assert!(body.get("client_id").is_none());
    assert!(body.get("sub").is_none());
    drop_schema(&state, &schema).await;
}

#[actix_web::test]
async fn introspection_fails_closed_when_access_token_revocation_query_fails() {
    let schema = format!(
        "introspect_access_revocation_failure_{}",
        Uuid::now_v7().simple()
    );
    let Some(database_url) = database_url_with_search_path(&schema) else {
        return;
    };
    let Some(state) = live_introspection_state_from_database_url(database_url) else {
        return;
    };
    create_isolated_schema(
        &state,
        &schema,
        &["oauth_clients", "oauth_tokens", "access_token_revocations"],
    )
    .await;
    let client = insert_introspection_client(
        &state,
        &format!("introspect-access-query-failure-{}", Uuid::now_v7()),
        &fixture_secret("access-query-failure"),
    )
    .await;
    let access_token = sign_access_token(
        &state,
        client.tenant_id,
        &client.client_id,
        json!("resource://default"),
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

    let (status, body) = introspect_with_client(
        state.clone(),
        &client.client_id,
        &fixture_secret("access-query-failure"),
        &access_token.token,
    )
    .await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body.get("error"), Some(&json!("server_error")));
    assert!(body.get("active").is_none());
    assert!(body.get("client_id").is_none());
    assert!(body.get("sub").is_none());
    drop_schema(&state, &schema).await;
}

#[actix_web::test]
async fn introspection_fails_closed_when_refresh_token_query_fails() {
    let schema = format!(
        "introspect_refresh_query_failure_{}",
        Uuid::now_v7().simple()
    );
    let Some(database_url) = database_url_with_search_path(&schema) else {
        return;
    };
    let Some(state) = live_introspection_state_from_database_url(database_url) else {
        return;
    };
    create_isolated_schema(
        &state,
        &schema,
        &["oauth_clients", "oauth_tokens", "access_token_revocations"],
    )
    .await;
    let client = insert_introspection_client(
        &state,
        &format!("introspect-refresh-query-failure-{}", Uuid::now_v7()),
        &fixture_secret("refresh-query-failure"),
    )
    .await;
    rename_column(
        &state,
        &schema,
        "oauth_tokens",
        "refresh_token_blake3",
        "refresh_token_blake3_broken",
    )
    .await;

    let (status, body) = introspect_with_client(
        state.clone(),
        &client.client_id,
        &fixture_secret("refresh-query-failure"),
        &fixture_token("refresh-query-failure"),
    )
    .await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body.get("error"), Some(&json!("server_error")));
    assert!(body.get("active").is_none());
    assert!(body.get("client_id").is_none());
    assert!(body.get("sub").is_none());
    drop_schema(&state, &schema).await;
}

#[actix_web::test]
async fn introspection_returns_inactive_for_access_tokens_outside_client_or_tenant_binding() {
    let Some(state) = live_introspection_state() else {
        return;
    };
    let client = insert_introspection_client(
        &state,
        "introspect-client",
        &fixture_secret("inactive-binding"),
    )
    .await;

    let foreign_audience_token = sign_access_token(
        &state,
        DEFAULT_TENANT_ID,
        "other-client",
        json!("resource://other"),
    )
    .await;
    let (status, body) = introspect_with_client(
        state.clone(),
        &client.client_id,
        &fixture_secret("inactive-binding"),
        &foreign_audience_token.token,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, json!({"active": false}));

    let foreign_tenant_token = sign_access_token(
        &state,
        Uuid::now_v7(),
        &client.client_id,
        json!("resource://default"),
    )
    .await;
    let (status, body) = introspect_with_client(
        state,
        &client.client_id,
        &fixture_secret("inactive-binding"),
        &foreign_tenant_token.token,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, json!({"active": false}));
}

#[actix_web::test]
async fn introspection_respects_access_token_revocation_state() {
    let Some(state) = live_introspection_state() else {
        return;
    };
    let client = insert_introspection_client(
        &state,
        "introspect-client-access",
        &fixture_secret("access-revocation"),
    )
    .await;
    let access_token = sign_access_token(
        &state,
        client.tenant_id,
        &client.client_id,
        json!("resource://default"),
    )
    .await;
    insert_access_token_revocation(&state, &client, &access_token.jti).await;

    let (status, body) = introspect_with_client(
        state,
        &client.client_id,
        &fixture_secret("access-revocation"),
        &access_token.token,
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, json!({"active": false}));
}

#[actix_web::test]
async fn signed_introspection_returns_rfc9701_jwt_for_active_access_token() {
    let Some(state) = live_introspection_state() else {
        return;
    };
    let state = with_signed_introspection_profile(&state);
    let client = insert_introspection_client(
        &state,
        &format!("introspect-signed-{}", Uuid::now_v7()),
        &fixture_secret("signed-active"),
    )
    .await;
    let access_token = sign_access_token(
        &state,
        client.tenant_id,
        &client.client_id,
        json!("resource://default"),
    )
    .await;
    let body = Bytes::from(format!(
        "token={}&client_id={}&client_secret={}",
        urlencoding::encode(&access_token.token),
        urlencoding::encode(&client.client_id),
        urlencoding::encode(&fixture_secret("signed-active"))
    ));

    let response =
        introspect_after_rate_limit(state.clone(), signed_introspection_form_request(), body).await;
    let claims = signed_introspection_jwt_body(&state, response).await;

    assert_eq!(claims.get("iss"), Some(&json!("https://issuer.example")));
    assert_eq!(claims.get("aud"), Some(&json!(client.client_id)));
    assert!(claims.get("iat").and_then(Value::as_i64).is_some());
    assert!(
        claims.get("sub").is_none() && claims.get("exp").is_none(),
        "RFC 9701 response JWT must not look like an access token"
    );
    let introspection = claims
        .get("token_introspection")
        .and_then(Value::as_object)
        .expect("introspection response must be nested");
    assert_eq!(introspection.get("active"), Some(&json!(true)));
    assert_eq!(
        introspection.get("client_id"),
        Some(&json!(client.client_id.clone()))
    );
    assert_eq!(introspection.get("jti"), Some(&json!(access_token.jti)));
}

#[actix_web::test]
async fn introspection_reports_refresh_token_activity_and_client_binding() {
    let Some(state) = live_introspection_state() else {
        return;
    };
    let client = insert_introspection_client(
        &state,
        "introspect-client-refresh",
        &fixture_secret("refresh-active"),
    )
    .await;

    let active_refresh = fixture_token("active-refresh");
    insert_refresh_token_for_client(
        &state,
        client.id,
        &active_refresh,
        None,
        Utc::now() + Duration::minutes(30),
    )
    .await;
    let (status, body) = introspect_with_client(
        state.clone(),
        &client.client_id,
        &fixture_secret("refresh-active"),
        &active_refresh,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.get("active"), Some(&json!(true)));
    assert_eq!(
        body.get("client_id"),
        Some(&json!(client.client_id.clone()))
    );
    assert_eq!(body.get("scope"), Some(&json!("openid offline_access")));
    assert!(body.get("token_type").is_none());

    let revoked_refresh = fixture_token("revoked-refresh");
    insert_refresh_token_for_client(
        &state,
        client.id,
        &revoked_refresh,
        Some(Utc::now()),
        Utc::now() + Duration::minutes(30),
    )
    .await;
    let (status, body) = introspect_with_client(
        state.clone(),
        &client.client_id,
        &fixture_secret("refresh-active"),
        &revoked_refresh,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, json!({"active": false}));

    let other_client = insert_introspection_client(
        &state,
        "introspect-client-refresh-other",
        &fixture_secret("refresh-other"),
    )
    .await;
    let mismatched_refresh = fixture_token("mismatched-refresh");
    insert_refresh_token_for_client(
        &state,
        other_client.id,
        &mismatched_refresh,
        None,
        Utc::now() + Duration::minutes(30),
    )
    .await;
    let (status, body) = introspect_with_client(
        state,
        &client.client_id,
        &fixture_secret("refresh-active"),
        &mismatched_refresh,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, json!({"active": false}));
}

#[actix_web::test]
async fn introspection_returns_minimal_inactive_for_unknown_tokens() {
    let Some(state) = live_introspection_state() else {
        return;
    };
    let client = insert_introspection_client(
        &state,
        &format!("introspect-client-missing-{}", Uuid::now_v7()),
        &fixture_secret("missing-token"),
    )
    .await;

    let (status, body) = introspect_with_client(
        state,
        &client.client_id,
        &fixture_secret("missing-token"),
        &format!("missing-refresh-{}", Uuid::now_v7()),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, json!({"active": false}));
}
