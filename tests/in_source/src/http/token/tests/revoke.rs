use super::*;
use std::sync::Arc;

use crate::config::ConfigSource;
use crate::db::{create_pool, get_conn};
use crate::domain::{ActiveSigningKey, Keyset, KeysetStore, VerificationKey};
use crate::support::{generate_key_material, hash_client_secret, public_jwk_from_private_der};
use actix_web::test::TestRequest;
use diesel::sql_query;
use diesel::sql_types::{Bool, Jsonb, Nullable, Text, Uuid as SqlUuid};
use diesel_async::RunQueryDsl;
use fred::interfaces::ClientLike;
use fred::prelude::{Builder as ValkeyBuilder, Config as ValkeyConfig};

fn revocation_state() -> Data<AppState> {
    Data::new(AppState {
        diesel_db: create_pool(
            "postgres://nazo_revoke_test_invalid:nazo_revoke_test_invalid@127.0.0.1:1/nazo"
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

fn live_revocation_state() -> Option<Data<AppState>> {
    let database_url = std::env::var("DATABASE_URL").ok()?;
    live_revocation_state_from_database_url(database_url)
}

fn fixture_secret(label: &str) -> String {
    format!("revocation-fixture-secret-{label}")
}

fn fixture_token(label: &str) -> String {
    format!("revocation-fixture-token-{label}")
}

fn live_revocation_state_from_database_url(database_url: String) -> Option<Data<AppState>> {
    let key_material =
        generate_key_material(jsonwebtoken::Algorithm::EdDSA).expect("test key should generate");
    let public_jwk = public_jwk_from_private_der(
        "revoke-test-kid",
        jsonwebtoken::Algorithm::EdDSA,
        &key_material.private_pkcs8_der,
    )
    .expect("test public JWK should derive");
    Some(Data::new(AppState {
        diesel_db: create_pool(database_url, 1).expect("database pool should build"),
        valkey: fred::prelude::Builder::default_centralized()
            .build()
            .expect("valkey client construction should not connect"),
        settings: Arc::new(
            Settings::from_config(&ConfigSource::default()).expect("default settings should load"),
        ),
        keyset: KeysetStore::new(Keyset {
            active_kid: "revoke-test-kid".to_owned(),
            active_alg: jsonwebtoken::Algorithm::EdDSA,
            active_signing_key: ActiveSigningKey::LocalPkcs8Der(key_material.private_pkcs8_der),
            verification_keys: vec![VerificationKey {
                kid: "revoke-test-kid".to_owned(),
                public_jwk,
                local_signing_key: None,
            }],
        }),
    }))
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

async fn live_rate_limited_revocation_state() -> Option<Data<AppState>> {
    let state = live_revocation_state()?;
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

async fn insert_revocation_client(
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
        client_name: "Revocation Test Client".to_owned(),
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
    .expect("revocation access token revocation cleanup should succeed");
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
    .expect("revocation refresh token cleanup should succeed");
    sql_query("DELETE FROM oauth_clients WHERE tenant_id = $1 AND client_id = $2")
        .bind::<SqlUuid, _>(row.tenant_id)
        .bind::<Text, _>(row.client_id.as_str())
        .execute(&mut conn)
        .await
        .expect("revocation test client cleanup should succeed");
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
    .expect("revocation test client insert should succeed");
    row
}

async fn insert_refresh_token_for_client(
    state: &Data<AppState>,
    client: &ClientRow,
    raw_refresh_token: &str,
) {
    let mut conn = get_conn(&state.diesel_db)
        .await
        .expect("database connection should be available");
    sql_query("DELETE FROM oauth_tokens WHERE tenant_id = $1 AND refresh_token_blake3 = $2")
        .bind::<SqlUuid, _>(client.tenant_id)
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
            $5, NULL, '["openid","offline_access"]'::jsonb, '[]'::jsonb, now(),
            now() + interval '1 day', NULL, NULL, 'subject-1', NULL, NULL
        )
        "#,
    )
    .bind::<SqlUuid, _>(Uuid::now_v7())
    .bind::<SqlUuid, _>(client.tenant_id)
    .bind::<Text, _>(blake3_hex(raw_refresh_token))
    .bind::<SqlUuid, _>(Uuid::now_v7())
    .bind::<SqlUuid, _>(client.id)
    .execute(&mut conn)
    .await
    .expect("refresh token insert should succeed");
}

async fn refresh_token_revoked_at(
    state: &Data<AppState>,
    raw_refresh_token: &str,
) -> Option<DateTime<Utc>> {
    let mut conn = get_conn(&state.diesel_db)
        .await
        .expect("database connection should be available");
    oauth_tokens::table
        .filter(oauth_tokens::tenant_id.eq(DEFAULT_TENANT_ID))
        .filter(oauth_tokens::refresh_token_blake3.eq(blake3_hex(raw_refresh_token)))
        .select(oauth_tokens::revoked_at)
        .first::<Option<DateTime<Utc>>>(&mut conn)
        .await
        .expect("refresh token row should load")
}

async fn sign_access_token(state: &Data<AppState>, client: &ClientRow) -> IssuedAccessToken {
    make_jwt(
        state,
        AccessTokenJwtInput {
            tenant_id: client.tenant_id,
            subject: client.client_id.as_str(),
            user_id: None,
            subject_type: "client",
            client_id: client.client_id.as_str(),
            audiences: std::slice::from_ref(&state.settings.default_audience),
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

async fn revoke_with_client(
    state: Data<AppState>,
    client: &ClientRow,
    client_secret: &str,
    token: &str,
) -> HttpResponse {
    let body = Bytes::from(format!(
        "token={}&client_id={}&client_secret={}",
        urlencoding::encode(token),
        urlencoding::encode(&client.client_id),
        urlencoding::encode(client_secret)
    ));
    revoke_after_rate_limit(state, form_request(), body).await
}

async fn access_token_revocation_count(
    state: &Data<AppState>,
    client: &ClientRow,
    access_token_jti: &str,
) -> i64 {
    let mut conn = get_conn(&state.diesel_db)
        .await
        .expect("database connection should be available");
    access_token_revocations::table
        .filter(access_token_revocations::tenant_id.eq(client.tenant_id))
        .filter(access_token_revocations::client_id.eq(client.id))
        .filter(access_token_revocations::access_token_jti_blake3.eq(blake3_hex(access_token_jti)))
        .count()
        .get_result::<i64>(&mut conn)
        .await
        .expect("access token revocation count should load")
}

fn oauth_error_code(response: &HttpResponse) -> String {
    response
        .extensions()
        .get::<OAuthJsonErrorFields>()
        .map(|fields| fields.error.clone())
        .expect("OAuth error response should record its error code")
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
    let value = serde_json::from_slice(&body).expect("OAuth error body should be JSON");
    (status, value)
}

fn form_request() -> HttpRequest {
    TestRequest::default()
        .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
        .to_http_request()
}

async fn revoke_form(body: &'static [u8]) -> HttpResponse {
    revoke_after_rate_limit(revocation_state(), form_request(), Bytes::from_static(body)).await
}

#[actix_web::test]
async fn revocation_success_response_is_empty_and_not_cacheable() {
    let response = empty_response_no_store(StatusCode::OK);

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        HeaderValue::from_static("no-store")
    );
    assert_eq!(
        response.headers().get(header::PRAGMA).unwrap(),
        HeaderValue::from_static("no-cache")
    );
    assert!(response.headers().get(header::CONTENT_TYPE).is_none());
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("response body should collect");
    assert!(body.is_empty());
}

#[test]
fn revocation_conflicting_client_auth_error_is_exact_oauth_invalid_request() {
    let response = token_management_oauth_error(
        StatusCode::BAD_REQUEST,
        "invalid_request",
        "同一请求不能同时使用多种客户端认证方式.",
    );

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(oauth_error_code(&response), "invalid_request");
    assert!(response.headers().get(header::WWW_AUTHENTICATE).is_none());
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        HeaderValue::from_static("no-store")
    );
}

#[actix_web::test]
async fn revocation_rejects_malformed_form_before_client_or_token_lookup() {
    let cases = [
        (
            revoke_after_rate_limit(
                revocation_state(),
                TestRequest::default()
                    .insert_header((header::CONTENT_TYPE, "application/json"))
                    .to_http_request(),
                Bytes::from_static(br#"{"token":"secret"}"#),
            )
            .await,
            "token management 请求必须使用 application/x-www-form-urlencoded.",
        ),
        (
            revoke_form(b"token=\xff").await,
            "token management 请求体必须使用 UTF-8 编码.",
        ),
        (
            revoke_form(b"token=token-1&token=token-2").await,
            "OAuth 参数不能重复.",
        ),
        (revoke_form(b"token=%20%20").await, "缺少 token."),
    ];

    for (response, expected_description) in cases {
        assert_eq!(oauth_error_code(&response), "invalid_request");
        assert!(
            response.headers().get(header::WWW_AUTHENTICATE).is_none(),
            "malformed revocation input is an invalid request, not a client-auth challenge"
        );
        let (status, body) = json_body(response).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body.get("error"), Some(&json!("invalid_request")));
        assert_eq!(
            body.get("error_description"),
            Some(&json!("Request failed."))
        );
        assert_ne!(
            body.get("error_description"),
            Some(&json!(expected_description)),
            "non-ASCII internal validation reasons must not be reflected to token clients"
        );
        assert!(body.get("access_token").is_none());
        assert!(body.get("refresh_token").is_none());
    }
}

#[actix_web::test]
async fn revocation_rate_limit_short_circuits_before_client_or_token_lookup() {
    let Some(state) = live_rate_limited_revocation_state().await else {
        return;
    };
    let response = revoke(
        state,
        form_request(),
        Bytes::from_static(
            b"token=refresh-token&client_id=rate-limited-client&client_secret=secret",
        ),
    )
    .await;

    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(oauth_error_code(&response), "temporarily_unavailable");
}

#[actix_web::test]
async fn revocation_rejects_conflicting_client_auth_without_token_state_lookup() {
    let response = revoke_after_rate_limit(
        revocation_state(),
        TestRequest::default()
            .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
            .insert_header((header::AUTHORIZATION, "Basic Y2xpZW50LTE6c2VjcmV0"))
            .to_http_request(),
        Bytes::from_static(b"token=token-1&client_id=client-1"),
    )
    .await;

    assert_eq!(oauth_error_code(&response), "invalid_request");
    let (status, body) = json_body(response).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body.get("error"), Some(&json!("invalid_request")));
    assert_eq!(
        body.get("error_description"),
        Some(&json!("Request failed."))
    );
    assert!(body.get("access_token").is_none());
    assert!(body.get("refresh_token").is_none());
}

#[actix_web::test]
async fn revocation_requires_client_authentication_before_token_state_lookup() {
    let response = revoke_after_rate_limit(
        revocation_state(),
        form_request(),
        Bytes::from_static(b"token=token-1"),
    )
    .await;

    assert_eq!(oauth_error_code(&response), "invalid_client");
    assert!(
        response.headers().get(header::WWW_AUTHENTICATE).is_none(),
        "revocation must not invent a Basic challenge unless the client attempted Basic auth"
    );
    let (status, body) = json_body(response).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body.get("error"), Some(&json!("invalid_client")));
    assert_eq!(
        body.get("error_description"),
        Some(&json!("Request failed."))
    );
    assert!(body.get("access_token").is_none());
    assert!(body.get("refresh_token").is_none());
}

#[actix_web::test]
async fn revocation_client_lookup_failures_return_server_error() {
    let response = revoke_after_rate_limit(
        revocation_state(),
        form_request(),
        Bytes::from_static(b"token=token-1&client_id=revoke-lookup-error&client_secret=secret"),
    )
    .await;

    let (status, body) = json_body(response).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body.get("error"), Some(&json!("server_error")));
    assert!(body.get("access_token").is_none());
    assert!(body.get("refresh_token").is_none());
}

#[actix_web::test]
async fn revocation_rejects_unknown_client_before_token_state_lookup() {
    let Some(state) = live_revocation_state() else {
        return;
    };
    let body = Bytes::from(format!(
        "token={}&client_id={}&client_secret=secret",
        urlencoding::encode("token-1"),
        urlencoding::encode(&format!("missing-revoke-client-{}", Uuid::now_v7()))
    ));

    let response = revoke_after_rate_limit(state, form_request(), body).await;

    assert_eq!(oauth_error_code(&response), "invalid_client");
    let (status, body) = json_body(response).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body.get("error"), Some(&json!("invalid_client")));
    assert_eq!(
        body.get("error_description"),
        Some(&json!("Request failed."))
    );
    assert!(body.get("access_token").is_none());
    assert!(body.get("refresh_token").is_none());
}

#[actix_web::test]
async fn revocation_rejects_wrong_client_secret_before_token_state_lookup() {
    let Some(state) = live_revocation_state() else {
        return;
    };
    let correct_secret = fixture_secret("registered");
    let wrong_secret = fixture_secret("presented");
    let token = fixture_token("wrong-client-secret");
    let client = insert_revocation_client(
        &state,
        &format!("revoke-auth-mismatch-{}", Uuid::now_v7()),
        &correct_secret,
    )
    .await;

    let response = revoke_with_client(state, &client, &wrong_secret, &token).await;

    assert_eq!(oauth_error_code(&response), "invalid_client");
    let (status, body) = json_body(response).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body.get("error"), Some(&json!("invalid_client")));
    assert_eq!(
        body.get("error_description"),
        Some(&json!("Request failed."))
    );
    assert!(body.get("access_token").is_none());
    assert!(body.get("refresh_token").is_none());
}

#[actix_web::test]
async fn revocation_fails_closed_when_client_lookup_query_fails() {
    let schema = format!("revoke_client_lookup_failure_{}", Uuid::now_v7().simple());
    let Some(database_url) = database_url_with_search_path(&schema) else {
        return;
    };
    let Some(state) = live_revocation_state_from_database_url(database_url) else {
        return;
    };
    create_isolated_schema(
        &state,
        &schema,
        &["oauth_clients", "oauth_tokens", "access_token_revocations"],
    )
    .await;
    let client = insert_revocation_client(
        &state,
        &format!("revoke-client-query-failure-{}", Uuid::now_v7()),
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

    let response = revoke_with_client(
        state.clone(),
        &client,
        &fixture_secret("client-query-failure"),
        &fixture_token("client-query-failure"),
    )
    .await;
    let (status, body) = json_body(response).await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body.get("error"), Some(&json!("server_error")));
    assert!(body.get("access_token").is_none());
    assert!(body.get("refresh_token").is_none());
    drop_schema(&state, &schema).await;
}

#[actix_web::test]
async fn revocation_fails_closed_when_refresh_token_update_query_fails() {
    let schema = format!("revoke_refresh_update_failure_{}", Uuid::now_v7().simple());
    let Some(database_url) = database_url_with_search_path(&schema) else {
        return;
    };
    let Some(state) = live_revocation_state_from_database_url(database_url) else {
        return;
    };
    create_isolated_schema(
        &state,
        &schema,
        &["oauth_clients", "oauth_tokens", "access_token_revocations"],
    )
    .await;
    let client = insert_revocation_client(
        &state,
        &format!("revoke-refresh-query-failure-{}", Uuid::now_v7()),
        &fixture_secret("refresh-update-failure"),
    )
    .await;
    rename_column(
        &state,
        &schema,
        "oauth_tokens",
        "revoked_at",
        "revoked_at_broken",
    )
    .await;

    let response = revoke_with_client(
        state.clone(),
        &client,
        &fixture_secret("refresh-update-failure"),
        &fixture_token("refresh-update-failure"),
    )
    .await;
    let (status, body) = json_body(response).await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body.get("error"), Some(&json!("server_error")));
    assert!(body.get("access_token").is_none());
    assert!(body.get("refresh_token").is_none());
    drop_schema(&state, &schema).await;
}

#[actix_web::test]
async fn revocation_fails_closed_when_access_token_blacklist_insert_fails() {
    let schema = format!(
        "revoke_access_blacklist_failure_{}",
        Uuid::now_v7().simple()
    );
    let Some(database_url) = database_url_with_search_path(&schema) else {
        return;
    };
    let Some(state) = live_revocation_state_from_database_url(database_url) else {
        return;
    };
    create_isolated_schema(
        &state,
        &schema,
        &["oauth_clients", "oauth_tokens", "access_token_revocations"],
    )
    .await;
    let client = insert_revocation_client(
        &state,
        &format!("revoke-access-insert-failure-{}", Uuid::now_v7()),
        &fixture_secret("access-insert-failure"),
    )
    .await;
    let access = sign_access_token(&state, &client).await;
    rename_column(
        &state,
        &schema,
        "access_token_revocations",
        "access_token_jti_blake3",
        "access_token_jti_blake3_broken",
    )
    .await;

    let response = revoke_with_client(
        state.clone(),
        &client,
        &fixture_secret("access-insert-failure"),
        &access.token,
    )
    .await;
    let (status, body) = json_body(response).await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body.get("error"), Some(&json!("server_error")));
    assert!(body.get("access_token").is_none());
    assert!(body.get("refresh_token").is_none());
    drop_schema(&state, &schema).await;
}

#[actix_web::test]
async fn revocation_updates_refresh_token_state_for_authenticated_client() {
    let Some(state) = live_revocation_state() else {
        return;
    };
    let client = insert_revocation_client(
        &state,
        "revoke-refresh-client",
        &fixture_secret("refresh-revoke"),
    )
    .await;
    let refresh_token = fixture_token("refresh-revoke");
    insert_refresh_token_for_client(&state, &client, &refresh_token).await;

    let response = revoke_with_client(
        state.clone(),
        &client,
        &fixture_secret("refresh-revoke"),
        &refresh_token,
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("response body should collect");
    assert!(body.is_empty());
    assert!(
        refresh_token_revoked_at(&state, &refresh_token)
            .await
            .is_some(),
        "refresh token revocation must persist revoked_at"
    );
}

#[actix_web::test]
async fn revocation_does_not_revoke_foreign_refresh_tokens_or_leak_ownership() {
    let Some(state) = live_revocation_state() else {
        return;
    };
    let owner_client = insert_revocation_client(
        &state,
        &format!("revoke-owner-{}", Uuid::now_v7()),
        &fixture_secret("foreign-owner"),
    )
    .await;
    let caller_client = insert_revocation_client(
        &state,
        &format!("revoke-caller-{}", Uuid::now_v7()),
        &fixture_secret("foreign-caller"),
    )
    .await;
    let refresh_token = format!("foreign-refresh-{}", Uuid::now_v7());
    insert_refresh_token_for_client(&state, &owner_client, &refresh_token).await;

    let response = revoke_with_client(
        state.clone(),
        &caller_client,
        &fixture_secret("foreign-caller"),
        &refresh_token,
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("response body should collect");
    assert!(body.is_empty());
    assert!(
        refresh_token_revoked_at(&state, &refresh_token)
            .await
            .is_none(),
        "revocation must not disclose or mutate refresh tokens issued to another client"
    );
}

#[actix_web::test]
async fn revocation_blacklists_access_token_jti_idempotently() {
    let Some(state) = live_revocation_state() else {
        return;
    };
    let client = insert_revocation_client(
        &state,
        "revoke-access-client",
        &fixture_secret("access-idempotent"),
    )
    .await;
    let access = sign_access_token(&state, &client).await;

    for _ in 0..2 {
        let response = revoke_with_client(
            state.clone(),
            &client,
            &fixture_secret("access-idempotent"),
            &access.token,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = actix_web::body::to_bytes(response.into_body())
            .await
            .expect("response body should collect");
        assert!(body.is_empty());
    }

    assert_eq!(
        access_token_revocation_count(&state, &client, &access.jti).await,
        1,
        "access token revocation should be idempotent on repeated requests"
    );
}
