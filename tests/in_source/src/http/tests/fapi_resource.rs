use super::*;
use std::sync::Arc;

use crate::config::ConfigSource;
use crate::db::{create_pool, get_conn};
use crate::domain::{ActiveSigningKey, ConfirmationClaims, Keyset, KeysetStore, VerificationKey};
use crate::support::{generate_key_material, public_jwk_from_private_der};
use diesel::sql_query;
use diesel::sql_types::{Text, Timestamptz, Uuid as SqlUuid};
use diesel_async::RunQueryDsl;

fn fapi_test_state() -> AppState {
    fapi_test_state_with_settings(
        Settings::from_config(&ConfigSource::default()).expect("default settings should load"),
    )
}

fn fapi_test_state_with_settings(settings: Settings) -> AppState {
    AppState {
        diesel_db: create_pool(
            "postgres://nazo_fapi_test_invalid:nazo_fapi_test_invalid@127.0.0.1:1/nazo".to_owned(),
            1,
        )
        .expect("pool construction should not connect"),
        valkey: fred::prelude::Builder::default_centralized()
            .build()
            .expect("valkey client construction should not connect"),
        settings: Arc::new(settings),
        keyset: KeysetStore::new(Keyset {
            active_kid: "test-kid".to_owned(),
            active_alg: jsonwebtoken::Algorithm::EdDSA,
            active_signing_key: ActiveSigningKey::LocalPkcs8Der(Vec::new()),
            verification_keys: Vec::new(),
        }),
    }
}

fn fapi_signing_state_with_invalid_db() -> Data<AppState> {
    let key_material =
        generate_key_material(jsonwebtoken::Algorithm::EdDSA).expect("test key should generate");
    let public_jwk = public_jwk_from_private_der(
        "fapi-resource-test-kid",
        jsonwebtoken::Algorithm::EdDSA,
        &key_material.private_pkcs8_der,
    )
    .expect("test public JWK should derive");
    let mut settings =
        Settings::from_config(&ConfigSource::default()).expect("default settings should load");
    settings.issuer = "https://issuer.example".to_owned();
    settings.default_audience = "resource://default".to_owned();
    settings.protected_resource_identifier = "https://issuer.example/fapi/resource".to_owned();

    Data::new(AppState {
        diesel_db: create_pool(
            "postgres://nazo_fapi_test_invalid:nazo_fapi_test_invalid@127.0.0.1:1/nazo".to_owned(),
            1,
        )
        .expect("pool construction should not connect"),
        valkey: fred::prelude::Builder::default_centralized()
            .build()
            .expect("valkey client construction should not connect"),
        settings: Arc::new(settings),
        keyset: KeysetStore::new(Keyset {
            active_kid: "fapi-resource-test-kid".to_owned(),
            active_alg: jsonwebtoken::Algorithm::EdDSA,
            active_signing_key: ActiveSigningKey::LocalPkcs8Der(key_material.private_pkcs8_der),
            verification_keys: vec![VerificationKey {
                kid: "fapi-resource-test-kid".to_owned(),
                public_jwk,
                local_signing_key: None,
            }],
        }),
    })
}

fn live_fapi_signing_state() -> Option<Data<AppState>> {
    live_fapi_signing_state_from_database_url(std::env::var("DATABASE_URL").ok()?)
}

fn live_fapi_signing_state_from_database_url(database_url: String) -> Option<Data<AppState>> {
    let key_material =
        generate_key_material(jsonwebtoken::Algorithm::EdDSA).expect("test key should generate");
    let public_jwk = public_jwk_from_private_der(
        "fapi-resource-test-kid",
        jsonwebtoken::Algorithm::EdDSA,
        &key_material.private_pkcs8_der,
    )
    .expect("test public JWK should derive");
    let mut settings =
        Settings::from_config(&ConfigSource::default()).expect("default settings should load");
    settings.issuer = "https://issuer.example".to_owned();
    settings.default_audience = "resource://default".to_owned();
    settings.protected_resource_identifier = "https://issuer.example/fapi/resource".to_owned();

    Some(Data::new(AppState {
        diesel_db: create_pool(database_url, 1).expect("database pool should build"),
        valkey: fred::prelude::Builder::default_centralized()
            .build()
            .expect("valkey client construction should not connect"),
        settings: Arc::new(settings),
        keyset: KeysetStore::new(Keyset {
            active_kid: "fapi-resource-test-kid".to_owned(),
            active_alg: jsonwebtoken::Algorithm::EdDSA,
            active_signing_key: ActiveSigningKey::LocalPkcs8Der(key_material.private_pkcs8_der),
            verification_keys: vec![VerificationKey {
                kid: "fapi-resource-test-kid".to_owned(),
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

async fn exec_sql(state: &Data<AppState>, sql: &str) {
    let mut conn = get_conn(&state.diesel_db)
        .await
        .expect("database connection should be available");
    sql_query(sql)
        .execute(&mut conn)
        .await
        .expect("schema mutation should succeed");
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

fn fapi_trusted_proxy_state() -> AppState {
    let mut settings =
        Settings::from_config(&ConfigSource::default()).expect("default settings should load");
    settings.client_ip_header_mode = ClientIpHeaderMode::None;
    settings.trusted_proxy_cidrs =
        parse_trusted_proxy_cidrs(Some("192.0.2.0/24".to_owned())).unwrap();
    fapi_test_state_with_settings(settings)
}

async fn signed_fapi_access_token(
    state: &Data<AppState>,
    tenant_id: Uuid,
    audiences: &[String],
    ttl: i64,
) -> IssuedAccessToken {
    make_jwt(
        state,
        AccessTokenJwtInput {
            tenant_id,
            subject: "fapi-subject",
            user_id: None,
            subject_type: "client",
            client_id: "fapi-client",
            audiences,
            scopes: &["openid".to_owned()],
            authorization_details: &json!([]),
            userinfo_claims: &[],
            userinfo_claim_requests: &[],
            ttl,
            dpop_jkt: None,
            mtls_x5t_s256: None,
            actor: None,
        },
    )
    .await
    .expect("FAPI resource access token should sign")
}

async fn signed_fapi_claims(state: &Data<AppState>, claims: Claims) -> String {
    let keyset = state.keyset.snapshot();
    let mut header = jsonwebtoken::Header::new(keyset.active_alg);
    header.typ = Some("at+jwt".to_owned());
    header.kid = Some(keyset.active_kid.clone());
    keyset
        .sign_jwt(&header, &claims)
        .await
        .expect("FAPI resource claims should sign")
}

async fn insert_fapi_client_and_revocation(
    state: &Data<AppState>,
    client_id: &str,
    access_token_jti: &str,
) {
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
    .expect("FAPI resource revocation cleanup should succeed");
    sql_query("DELETE FROM oauth_clients WHERE tenant_id = $1 AND client_id = $2")
        .bind::<SqlUuid, _>(DEFAULT_TENANT_ID)
        .bind::<Text, _>(client_id)
        .execute(&mut conn)
        .await
        .expect("FAPI resource client cleanup should succeed");
    let row = sql_query(
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
            $1, $2, $3, $4, 'FAPI Resource Test Client', 'confidential',
            NULL, '["https://client.example/callback"]'::jsonb, '["openid"]'::jsonb,
            '["resource://default"]'::jsonb, '["client_credentials"]'::jsonb,
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
    .expect("FAPI resource client insert should succeed");
    sql_query(
        r#"
        INSERT INTO access_token_revocations (
            tenant_id, client_id, access_token_jti_blake3, revoked_at, expires_at
        )
        VALUES ($1, $2, $3, now(), $4)
        "#,
    )
    .bind::<SqlUuid, _>(DEFAULT_TENANT_ID)
    .bind::<SqlUuid, _>(row.id)
    .bind::<Text, _>(blake3_hex(access_token_jti))
    .bind::<Timestamptz, _>(Utc::now() + Duration::minutes(5))
    .execute(&mut conn)
    .await
    .expect("FAPI resource revocation insert should succeed");
}

fn access_claims(cnf: Option<ConfirmationClaims>) -> Claims {
    Claims {
        iss: "https://issuer.example".to_owned(),
        sub: "subject-1".to_owned(),
        tenant_id: DEFAULT_TENANT_ID.to_string(),
        user_id: None,
        subject_type: "public".to_owned(),
        aud: json!("resource://default"),
        client_id: "client-1".to_owned(),
        scope: "openid".to_owned(),
        authorization_details: json!([]),
        token_use: "access".to_owned(),
        jti: "jti-1".to_owned(),
        iat: Utc::now().timestamp(),
        nbf: Utc::now().timestamp(),
        exp: Utc::now().timestamp() + 300,
        cnf,
        act: None,
        userinfo_claims: Vec::new(),
        userinfo_claim_requests: Vec::new(),
    }
}

fn oauth_error_code(response: &HttpResponse) -> Option<String> {
    response
        .extensions()
        .get::<OAuthJsonErrorFields>()
        .map(|fields| fields.error.clone())
}

#[actix_web::test]
async fn fapi_resource_rejects_missing_or_conflicting_access_token_transport() {
    let state = Data::new(fapi_test_state());
    let missing_req = actix_web::test::TestRequest::get()
        .uri("/fapi/resource")
        .to_http_request();

    let missing = fapi_resource(state.clone(), missing_req, Bytes::new()).await;
    assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(oauth_error_code(&missing).as_deref(), Some("invalid_token"));

    let duplicate_req = actix_web::test::TestRequest::post()
        .uri("/fapi/resource")
        .insert_header((header::AUTHORIZATION, "Bearer header-token"))
        .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
        .to_http_request();
    let duplicate = fapi_resource(
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
}

#[actix_web::test]
async fn fapi_resource_rejects_unverifiable_access_token_before_revocation_lookup() {
    let state = Data::new(fapi_test_state());
    let req = actix_web::test::TestRequest::get()
        .uri("/fapi/resource")
        .insert_header((header::AUTHORIZATION, "Bearer not-a-jwt"))
        .to_http_request();

    let response = fapi_resource(state, req, Bytes::new()).await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        oauth_error_code(&response).as_deref(),
        Some("invalid_token")
    );
}

#[actix_web::test]
async fn fapi_resource_rejects_signed_token_with_wrong_resource_audience_before_db_lookup() {
    let state = fapi_signing_state_with_invalid_db();
    let token = signed_fapi_access_token(
        &state,
        DEFAULT_TENANT_ID,
        &["https://issuer.example/userinfo".to_owned()],
        300,
    )
    .await;
    let req = actix_web::test::TestRequest::get()
        .uri("/fapi/resource")
        .insert_header((header::AUTHORIZATION, format!("Bearer {}", token.token)))
        .to_http_request();

    let response = fapi_resource(state, req, Bytes::new()).await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        oauth_error_code(&response).as_deref(),
        Some("invalid_token")
    );
}

#[actix_web::test]
async fn fapi_resource_rejects_signed_token_with_invalid_tenant_boundary_before_db_lookup() {
    let state = fapi_signing_state_with_invalid_db();
    let mut claims = access_claims(None);
    claims.iss = state.settings.issuer.clone();
    claims.tenant_id = "not-a-uuid".to_owned();
    claims.aud = json!("resource://default");
    let token = signed_fapi_claims(&state, claims).await;
    let req = actix_web::test::TestRequest::get()
        .uri("/fapi/resource")
        .insert_header((header::AUTHORIZATION, format!("Bearer {token}")))
        .to_http_request();

    let response = fapi_resource(state, req, Bytes::new()).await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        oauth_error_code(&response).as_deref(),
        Some("invalid_token")
    );
}

#[actix_web::test]
async fn fapi_resource_rejects_revoked_access_token() {
    let Some(state) = live_fapi_signing_state() else {
        return;
    };
    let token = signed_fapi_access_token(
        &state,
        DEFAULT_TENANT_ID,
        &["resource://default".to_owned()],
        300,
    )
    .await;
    insert_fapi_client_and_revocation(&state, "fapi-client", &token.jti).await;
    let req = actix_web::test::TestRequest::get()
        .uri("/fapi/resource")
        .insert_header((header::AUTHORIZATION, format!("Bearer {}", token.token)))
        .to_http_request();

    let response = fapi_resource(state, req, Bytes::new()).await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        oauth_error_code(&response).as_deref(),
        Some("invalid_token")
    );
}

#[actix_web::test]
async fn fapi_resource_rejects_expired_access_token_after_revocation_lookup() {
    let Some(state) = live_fapi_signing_state() else {
        return;
    };
    let token = signed_fapi_access_token(
        &state,
        DEFAULT_TENANT_ID,
        &["resource://default".to_owned()],
        -1,
    )
    .await;
    let req = actix_web::test::TestRequest::get()
        .uri("/fapi/resource")
        .insert_header((header::AUTHORIZATION, format!("Bearer {}", token.token)))
        .to_http_request();

    let response = fapi_resource(state, req, Bytes::new()).await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        oauth_error_code(&response).as_deref(),
        Some("invalid_token")
    );
}

#[actix_web::test]
async fn fapi_resource_returns_server_error_when_revocation_lookup_cannot_connect() {
    let state = fapi_signing_state_with_invalid_db();
    let token = signed_fapi_access_token(
        &state,
        DEFAULT_TENANT_ID,
        &["resource://default".to_owned()],
        300,
    )
    .await;
    let req = actix_web::test::TestRequest::get()
        .uri("/fapi/resource")
        .insert_header((header::AUTHORIZATION, format!("Bearer {}", token.token)))
        .to_http_request();

    let response = fapi_resource(state, req, Bytes::new()).await;

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(oauth_error_code(&response).as_deref(), Some("server_error"));
}

#[actix_web::test]
async fn fapi_resource_returns_server_error_when_revocation_query_fails_after_token_validation() {
    let schema = format!("fapi_revocation_failure_{}", Uuid::now_v7().simple());
    let Some(database_url) = database_url_with_search_path(&schema) else {
        return;
    };
    let Some(state) = live_fapi_signing_state_from_database_url(database_url) else {
        return;
    };
    create_isolated_schema(&state, &schema, &["access_token_revocations"]).await;
    rename_column(
        &state,
        &schema,
        "access_token_revocations",
        "access_token_jti_blake3",
        "access_token_jti_blake3_broken",
    )
    .await;
    let token = signed_fapi_access_token(
        &state,
        DEFAULT_TENANT_ID,
        &["resource://default".to_owned()],
        300,
    )
    .await;
    let req = actix_web::test::TestRequest::get()
        .uri("/fapi/resource")
        .insert_header((header::AUTHORIZATION, format!("Bearer {}", token.token)))
        .to_http_request();

    let response = fapi_resource(state.clone(), req, Bytes::new()).await;

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(oauth_error_code(&response).as_deref(), Some("server_error"));
    drop_schema(&state, &schema).await;
}

#[test]
fn post_body_access_token_accepts_single_form_value() {
    let req = actix_web::test::TestRequest::post()
        .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
        .to_http_request();
    let token = resource_access_token(&req, &Bytes::from_static(b"access_token=token-1"));

    let ResourceAccessToken::Present(AccessTokenAuthScheme::Bearer, token) = token else {
        panic!("expected bearer token from form body");
    };
    assert_eq!(token, "token-1");
}

#[test]
fn post_body_access_token_rejects_missing_content_type() {
    let req = actix_web::test::TestRequest::post().to_http_request();
    let token = resource_access_token(&req, &Bytes::from_static(b"access_token=token-1"));

    assert!(matches!(token, ResourceAccessToken::Missing));
}

#[test]
fn post_body_access_token_rejects_duplicate_value() {
    let req = actix_web::test::TestRequest::post()
        .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
        .to_http_request();
    let token = resource_access_token(
        &req,
        &Bytes::from_static(b"access_token=token-1&access_token=token-2"),
    );

    assert!(matches!(token, ResourceAccessToken::InvalidRequest));
}

#[test]
fn post_body_access_token_treats_blank_or_absent_value_as_missing() {
    let req = actix_web::test::TestRequest::post()
        .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
        .to_http_request();

    let blank = resource_access_token(&req, &Bytes::from_static(b"access_token=%20%09"));
    assert!(matches!(blank, ResourceAccessToken::Missing));

    let absent = resource_access_token(&req, &Bytes::from_static(b"scope=openid"));
    assert!(matches!(absent, ResourceAccessToken::Missing));
}

#[test]
fn query_access_token_is_not_accepted() {
    let req = actix_web::test::TestRequest::get()
        .uri("/fapi/resource?access_token=query-token")
        .to_http_request();
    let token = resource_access_token(&req, &Bytes::new());

    assert!(matches!(token, ResourceAccessToken::Missing));
}

#[test]
fn authorization_header_access_token_accepts_single_value() {
    let req = actix_web::test::TestRequest::get()
        .insert_header((header::AUTHORIZATION, "DPoP header-token"))
        .to_http_request();
    let token = resource_access_token(&req, &Bytes::new());

    let ResourceAccessToken::Present(AccessTokenAuthScheme::DPoP, token) = token else {
        panic!("expected dpop token from authorization header");
    };
    assert_eq!(token, "header-token");
}

#[test]
fn access_token_rejects_multiple_transport_methods() {
    let req = actix_web::test::TestRequest::post()
        .insert_header((header::AUTHORIZATION, "Bearer header-token"))
        .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
        .to_http_request();
    let token = resource_access_token(&req, &Bytes::from_static(b"access_token=body-token"));

    assert!(matches!(token, ResourceAccessToken::InvalidRequest));
}

#[test]
fn fapi_resource_accepts_only_bound_resource_audiences() {
    let mut settings = Settings::from_config(&crate::config::ConfigSource::default())
        .expect("default settings should load");
    settings.issuer = "https://issuer.example".to_owned();
    settings.default_audience = "resource://default".to_owned();
    settings.protected_resource_identifier = "https://issuer.example/fapi/resource".to_owned();

    assert!(fapi_resource_audience_allowed(
        &settings,
        &json!("resource://default")
    ));
    assert!(fapi_resource_audience_allowed(
        &settings,
        &json!("https://issuer.example/fapi/resource")
    ));
    assert!(fapi_resource_audience_allowed(
        &settings,
        &json!(["resource://other", "https://issuer.example/fapi/resource"])
    ));
    settings.protected_resource_identifier = "https://api.example/fapi/resource".to_owned();
    assert!(fapi_resource_audience_allowed(
        &settings,
        &json!("https://api.example/fapi/resource")
    ));
    assert!(!fapi_resource_audience_allowed(
        &settings,
        &json!("https://issuer.example/fapi/resource")
    ));
    assert!(!fapi_resource_audience_allowed(
        &settings,
        &json!("https://issuer.example/userinfo")
    ));
    assert!(!fapi_resource_audience_allowed(
        &settings,
        &json!(["resource://other", "https://issuer.example/userinfo"])
    ));
}

#[test]
fn fapi_interaction_id_echoes_request_or_generates_response_value() {
    let echoed = actix_web::test::TestRequest::get()
        .insert_header((
            "x-fapi-interaction-id",
            "fAf943Fd-23A7-441b-B8cE-d012413FcA0c",
        ))
        .to_http_request();
    assert_eq!(
        fapi_interaction_id(&echoed).to_str().ok(),
        Some("fAf943Fd-23A7-441b-B8cE-d012413FcA0c")
    );

    let generated = actix_web::test::TestRequest::get().to_http_request();
    assert!(
        fapi_interaction_id(&generated)
            .to_str()
            .is_ok_and(|value| { Uuid::parse_str(value).is_ok() })
    );
}

#[actix_web::test]
async fn sender_constrained_resource_rejects_wrong_transport_without_backend_lookup() {
    let state = fapi_test_state();
    let req = actix_web::test::TestRequest::get().to_http_request();

    let bearer_with_dpop_cnf = validate_access_token_binding(
        &state,
        &req,
        "access-token",
        AccessTokenAuthScheme::Bearer,
        &access_claims(Some(ConfirmationClaims {
            jkt: Some("dpop-jkt".to_owned()),
            x5t_s256: None,
        })),
    )
    .await
    .expect_err("Bearer transport must not accept a DPoP-bound access token");
    assert_eq!(bearer_with_dpop_cnf.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        oauth_error_code(&bearer_with_dpop_cnf).as_deref(),
        Some("invalid_dpop_proof")
    );

    let dpop_without_cnf = validate_access_token_binding(
        &state,
        &req,
        "access-token",
        AccessTokenAuthScheme::DPoP,
        &access_claims(None),
    )
    .await
    .expect_err("DPoP transport must require a DPoP-bound access token");
    assert_eq!(dpop_without_cnf.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        oauth_error_code(&dpop_without_cnf).as_deref(),
        Some("invalid_dpop_proof")
    );
}

#[actix_web::test]
async fn mtls_bound_resource_token_requires_verified_certificate() {
    let state = fapi_test_state();
    let req = actix_web::test::TestRequest::get().to_http_request();

    let response = validate_access_token_binding(
        &state,
        &req,
        "access-token",
        AccessTokenAuthScheme::Bearer,
        &access_claims(Some(ConfirmationClaims {
            jkt: None,
            x5t_s256: Some("thumbprint".to_owned()),
        })),
    )
    .await
    .expect_err("mTLS-bound access token must require a verified certificate");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        oauth_error_code(&response).as_deref(),
        Some("invalid_token")
    );
}

#[actix_web::test]
async fn mtls_bound_resource_token_rejects_certificate_thumbprint_mismatch() {
    let state = fapi_trusted_proxy_state();
    let req = actix_web::test::TestRequest::get()
        .peer_addr("192.0.2.10:443".parse().unwrap())
        .insert_header(("x-ssl-client-verify", "SUCCESS"))
        .insert_header((
            "x-forwarded-tls-client-cert-sha256",
            "ABEiM0RVZneImaq7zN3u_wARIjNEVWZ3iJmqu8zd7v8",
        ))
        .to_http_request();

    let response = validate_access_token_binding(
        &state,
        &req,
        "access-token",
        AccessTokenAuthScheme::Bearer,
        &access_claims(Some(ConfirmationClaims {
            jkt: None,
            x5t_s256: Some("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned()),
        })),
    )
    .await
    .expect_err("mTLS-bound access token must reject the wrong client certificate");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        oauth_error_code(&response).as_deref(),
        Some("invalid_token")
    );
}

#[actix_web::test]
async fn mtls_bound_resource_token_accepts_matching_verified_certificate() {
    let state = fapi_trusted_proxy_state();
    let thumbprint = "ABEiM0RVZneImaq7zN3u_wARIjNEVWZ3iJmqu8zd7v8";
    let req = actix_web::test::TestRequest::get()
        .peer_addr("192.0.2.10:443".parse().unwrap())
        .insert_header(("x-ssl-client-verify", "SUCCESS"))
        .insert_header(("x-forwarded-tls-client-cert-sha256", thumbprint))
        .to_http_request();

    validate_access_token_binding(
        &state,
        &req,
        "access-token",
        AccessTokenAuthScheme::Bearer,
        &access_claims(Some(ConfirmationClaims {
            jkt: None,
            x5t_s256: Some(thumbprint.to_owned()),
        })),
    )
    .await
    .expect("matching verified mTLS certificate should satisfy token binding");
}
