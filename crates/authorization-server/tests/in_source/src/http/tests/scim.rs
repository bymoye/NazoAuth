use super::*;
use std::sync::Arc;

use crate::config::ConfigSource;
use crate::http::client_ip::ClientIpConfig;
use crate::settings::Settings;
use diesel::sql_query;
use diesel::sql_types::{BigInt, Jsonb, Nullable, Text, Timestamptz, Uuid as SqlUuid};
use diesel_async::RunQueryDsl;
use nazo_postgres::{create_pool, get_conn};

type ScimHandles = ScimEndpoint;

struct ScimTestFixture {
    state: Data<ScimHandles>,
    pool: nazo_postgres::DbPool,
}

fn uuid_fixture(value: u128) -> Uuid {
    Uuid::from_u128(value)
}

fn test_scim_config(settings: &Settings) -> ScimConfig {
    let endpoint = &settings.endpoint;
    ScimConfig::new(
        settings.storage.scim_bearer_token.as_deref(),
        &settings.protocol.client_secret_pepper,
        ClientIpConfig::new(
            &endpoint.trusted_proxy_cidrs,
            endpoint.client_ip_header_mode,
        ),
    )
    .expect("test SCIM settings should be valid")
}

fn test_scim_service(pool: &nazo_postgres::DbPool) -> nazo_identity::scim::ScimService {
    nazo_identity::scim::ScimService::new(
        Arc::new(nazo_postgres::ScimRepository::new(pool.clone())),
        Arc::new(nazo_postgres::AuditRepository::new(pool.clone())),
    )
}

fn test_state_with_scim_bearer_token(scim_bearer_token: Option<&str>) -> ScimHandles {
    let mut settings =
        Settings::from_config(&ConfigSource::default()).expect("default settings should load");
    settings.storage.scim_bearer_token = scim_bearer_token.map(ToOwned::to_owned);
    let pool = create_pool(
        "postgres://nazo_scim_test_invalid:nazo_scim_test_invalid@127.0.0.1:1/nazo".to_owned(),
        1,
    )
    .expect("pool construction should not connect");
    ScimHandles::for_test(test_scim_service(&pool), test_scim_config(&settings))
}

fn test_state() -> ScimHandles {
    test_state_with_scim_bearer_token(None)
}

#[derive(diesel::QueryableByName)]
struct CountRow {
    #[diesel(sql_type = BigInt)]
    count: i64,
}

fn database_url_with_search_path(schema: &str) -> Option<String> {
    let base = std::env::var("DATABASE_URL").ok()?;
    let separator = if base.contains('?') { "&" } else { "?" };
    Some(format!(
        "{base}{separator}options=-csearch_path%3D{schema}%2Cpublic"
    ))
}

async fn live_state_with_scim_bearer_token(scim_bearer_token: &str) -> Option<ScimTestFixture> {
    let database_url = std::env::var("DATABASE_URL").ok()?;
    live_state_for_database_url(scim_bearer_token, database_url).await
}

async fn live_state_with_isolated_scim_bearer_token(
    scim_bearer_token: &str,
    schema: &str,
    tables: &[&str],
) -> Option<ScimTestFixture> {
    let database_url = database_url_with_search_path(schema)?;
    let fixture = live_state_for_database_url(scim_bearer_token, database_url).await?;
    create_isolated_scim_schema(&fixture.pool, schema, tables).await;
    Some(fixture)
}

async fn live_state_for_database_url(
    scim_bearer_token: &str,
    database_url: String,
) -> Option<ScimTestFixture> {
    let mut settings =
        Settings::from_config(&ConfigSource::default()).expect("default settings should load");
    settings.storage.scim_bearer_token = Some(scim_bearer_token.to_owned());
    let pool = create_pool(database_url, 4).expect("database pool should build");
    let state = Data::new(ScimHandles::for_test(
        test_scim_service(&pool),
        test_scim_config(&settings),
    ));
    Some(ScimTestFixture { state, pool })
}

async fn exec_scim_schema_sql(pool: &nazo_postgres::DbPool, sql: &str) {
    let mut conn = get_conn(pool)
        .await
        .expect("database connection should be available");
    sql_query(sql)
        .execute(&mut conn)
        .await
        .expect("schema mutation should succeed");
}

async fn create_isolated_scim_schema(pool: &nazo_postgres::DbPool, schema: &str, tables: &[&str]) {
    exec_scim_schema_sql(
        pool,
        &format!(r#"CREATE SCHEMA IF NOT EXISTS "{}""#, schema),
    )
    .await;
    for table in tables {
        exec_scim_schema_sql(
            pool,
            &format!(
                r#"CREATE TABLE "{}"."{}" (LIKE public."{}" INCLUDING ALL)"#,
                schema, table, table
            ),
        )
        .await;
    }
}

async fn rename_scim_column(
    pool: &nazo_postgres::DbPool,
    schema: &str,
    table: &str,
    from: &str,
    to: &str,
) {
    exec_scim_schema_sql(
        pool,
        &format!(
            r#"ALTER TABLE "{}"."{}" RENAME COLUMN "{}" TO "{}""#,
            schema, table, from, to
        ),
    )
    .await;
}

async fn cleanup_scim_schema(pool: &nazo_postgres::DbPool, schema: &str) {
    exec_scim_schema_sql(
        pool,
        &format!(r#"DROP SCHEMA IF EXISTS "{}" CASCADE"#, schema),
    )
    .await;
}

async fn cleanup_scim_user_by_email(pool: &nazo_postgres::DbPool, email: &str) {
    let mut conn = get_conn(pool)
        .await
        .expect("database connection should be available");
    sql_query("DELETE FROM users WHERE email = $1")
        .bind::<Text, _>(email.to_owned())
        .execute(&mut conn)
        .await
        .expect("SCIM test user cleanup should succeed");
}

fn user_row(id: Uuid, email: &str) -> PublicAccount {
    let now = Utc::now();
    DatabaseUserFixture {
        id,
        tenant_id: uuid_fixture(0x11111111111111111111111111111111),
        realm_id: uuid_fixture(0x22222222222222222222222222222222),
        organization_id: uuid_fixture(0x33333333333333333333333333333333),
        username: email.to_owned(),
        email: email.to_owned(),
        display_name: Some("Alice Example".to_owned()),
        avatar_url: Some("https://cdn.example/avatar.png".to_owned()),
        given_name: Some("Alice".to_owned()),
        family_name: Some("Example".to_owned()),
        middle_name: Some("Q".to_owned()),
        nickname: Some("alice".to_owned()),
        profile_url: Some("https://example.test/alice".to_owned()),
        website_url: Some("https://alice.example".to_owned()),
        gender: Some("unspecified".to_owned()),
        birthdate: Some("1970-01-01".to_owned()),
        zoneinfo: Some("UTC".to_owned()),
        locale: Some("en-US".to_owned()),
        role: "admin".to_owned(),
        admin_level: 99,
        address_formatted: Some("Internal address".to_owned()),
        address_street_address: Some("Secret street".to_owned()),
        address_locality: Some("Secret city".to_owned()),
        address_region: Some("Secret region".to_owned()),
        address_postal_code: Some("Secret postal".to_owned()),
        address_country: Some("Secret country".to_owned()),
        phone_number: Some("+15555555555".to_owned()),
        phone_number_verified: true,
        email_verified: true,
        mfa_enabled: true,
        password_hash: "argon2-secret-hash".to_owned(),
        is_active: true,
        created_at: now,
        updated_at: now,
    }
    .identity()
}

fn scim_user_request_fixture() -> ScimUserRequest {
    ScimUserRequest {
        user_name: Some("user@example.test".to_owned()),
        active: Some(true),
        name: None,
        emails: Some(vec![ScimEmail {
            value: Some("user@example.test".to_owned()),
            primary: Some(true),
        }]),
    }
}

fn scim_user_request_mismatched_identity_fixture() -> ScimUserRequest {
    ScimUserRequest {
        user_name: Some("user@example.test".to_owned()),
        active: Some(true),
        name: None,
        emails: Some(vec![ScimEmail {
            value: Some("other@example.test".to_owned()),
            primary: Some(true),
        }]),
    }
}

fn scim_user_request_for_email(email: &str) -> ScimUserRequest {
    ScimUserRequest {
        user_name: Some(email.to_owned()),
        active: Some(true),
        name: Some(ScimName {
            given_name: Some("Lifecycle".to_owned()),
            family_name: Some("User".to_owned()),
            formatted: Some("Lifecycle User".to_owned()),
        }),
        emails: Some(vec![ScimEmail {
            value: Some(email.to_owned()),
            primary: Some(true),
        }]),
    }
}

fn bearer_request(token: &str) -> HttpRequest {
    actix_web::test::TestRequest::default()
        .insert_header((header::AUTHORIZATION, format!("Bearer {token}")))
        .to_http_request()
}

fn bearer_request_uri(token: &str, uri: &str) -> HttpRequest {
    actix_web::test::TestRequest::get()
        .uri(uri)
        .insert_header((header::AUTHORIZATION, format!("Bearer {token}")))
        .to_http_request()
}

async fn response_json(response: HttpResponse) -> (StatusCode, Value) {
    let status = response.status();
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("response body should be readable");
    let json = serde_json::from_slice(&body).expect("response should be json");
    (status, json)
}

async fn assert_scim_disabled(response: HttpResponse) {
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/json"
    );
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("disabled SCIM response body should be readable");
    let body: Value = serde_json::from_slice(&body).expect("disabled SCIM response should be JSON");
    assert_eq!(body["schemas"], json!([SCIM_ERROR_SCHEMA]));
    assert_eq!(body["status"], "404");
    assert_eq!(body["scimType"], "not_found");
    assert_eq!(body["detail"], "SCIM is disabled");
}

#[test]
fn scim_routes_are_static_and_handlers_do_not_depend_on_app_state() {
    let routes = include_str!("../../../../../src/bootstrap/routes.rs");
    for contract in [
        "web::get().to(scim_service_provider_config)",
        "web::get().to(scim_schemas)",
        "web::get().to(scim_resource_types)",
        "web::get().to(scim_list_users)",
        "web::post().to(scim_create_user)",
        "web::get().to(scim_get_user)",
        "web::put().to(scim_replace_user)",
        "web::patch().to(scim_patch_user)",
        "web::delete().to(scim_delete_user)",
    ] {
        assert!(
            routes.contains(contract),
            "missing static SCIM route: {contract}"
        );
    }
    let handlers = include_str!("../../../../../src/http/scim.rs");
    let auth = include_str!("../../../../../src/http/scim/auth.rs");
    assert!(!handlers.contains("Data<TestAppState>"));
    assert!(!handlers.contains("ScimRepository"));
    assert!(!handlers.contains("AuditRepository"));
    assert!(!handlers.contains("ScimHandles"));
    assert!(!auth.contains("TestAppState"));
    assert!(!auth.contains("nazo_postgres"));
}

#[actix_web::test]
async fn disabled_scim_contract_is_consistent_across_registered_methods() {
    let mut handles = test_state_with_scim_bearer_token(Some("legacy-scim-secret"));
    handles.admission.enabled = false;
    let handles = Data::new(handles);
    let request = bearer_request("legacy-scim-secret");
    let user_id = Uuid::now_v7();

    assert_scim_disabled(scim_service_provider_config(handles.clone(), request.clone()).await)
        .await;
    assert_scim_disabled(scim_schemas(handles.clone(), request.clone()).await).await;
    assert_scim_disabled(scim_resource_types(handles.clone(), request.clone()).await).await;
    assert_scim_disabled(scim_list_users(handles.clone(), request.clone()).await).await;
    assert_scim_disabled(
        scim_create_user(
            handles.clone(),
            request.clone(),
            Json(scim_user_request_fixture()),
        )
        .await,
    )
    .await;
    assert_scim_disabled(
        scim_get_user(
            handles.clone(),
            request.clone(),
            actix_web::web::Path::from(user_id),
        )
        .await,
    )
    .await;
    assert_scim_disabled(
        scim_replace_user(
            handles.clone(),
            request.clone(),
            actix_web::web::Path::from(user_id),
            Json(scim_user_request_fixture()),
        )
        .await,
    )
    .await;
    assert_scim_disabled(
        scim_patch_user(
            handles.clone(),
            request.clone(),
            actix_web::web::Path::from(user_id),
            Json(ScimPatchRequest {
                schemas: vec![SCIM_PATCH_SCHEMA.to_owned()],
                operations: Vec::new(),
            }),
        )
        .await,
    )
    .await;
    assert_scim_disabled(
        scim_delete_user(handles, request, actix_web::web::Path::from(user_id)).await,
    )
    .await;
}

async fn create_scim_user_id(state: Data<ScimHandles>, req: &HttpRequest, email: &str) -> Uuid {
    let (status, body) = response_json(
        scim_create_user(state, req.clone(), Json(scim_user_request_for_email(email))).await,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    serde_json::from_value::<Uuid>(body["id"].clone())
        .expect("SCIM create response should include a UUID id")
}

async fn insert_scim_user_oauth_credentials(
    pool: &nazo_postgres::DbPool,
    user_id: Uuid,
    suffix: &str,
) -> Uuid {
    let mut conn = get_conn(pool)
        .await
        .expect("database connection should be available");
    let tenant = default_tenant_context();
    let client_id = Uuid::now_v7();
    let client_identifier = format!("scim-deprovision-client-{suffix}");

    sql_query("DELETE FROM oauth_clients WHERE tenant_id = $1 AND client_id = $2")
        .bind::<SqlUuid, _>(tenant.tenant_id)
        .bind::<Text, _>(&client_identifier)
        .execute(&mut conn)
        .await
        .expect("SCIM credential test client cleanup should succeed");

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
            $1, $2, $3, $4, $5, $6, 'public',
            NULL, '["https://client.example/callback"]'::jsonb, '["openid","offline_access"]'::jsonb,
            '["https://api.example"]'::jsonb, '["authorization_code","refresh_token"]'::jsonb,
            'none', false, false, '[]'::jsonb, '[]'::jsonb, '[]'::jsonb, '[]'::jsonb,
            false, false, false, false, true, '[]'::jsonb, false
        )
        "#,
    )
    .bind::<SqlUuid, _>(client_id)
    .bind::<SqlUuid, _>(tenant.tenant_id)
    .bind::<SqlUuid, _>(tenant.realm_id)
    .bind::<SqlUuid, _>(tenant.organization_id)
    .bind::<Text, _>(&client_identifier)
    .bind::<Text, _>("SCIM Deprovision Test Client")
    .execute(&mut conn)
    .await
    .expect("SCIM credential test client should insert");

    sql_query(
        r#"
        INSERT INTO user_client_grants (
            tenant_id, user_id, client_id, first_authorized_at, last_authorized_at,
            last_scopes, last_authorization_details, authorization_count
        )
        VALUES ($1, $2, $3, now(), now(), '["openid","offline_access"]'::jsonb, '[]'::jsonb, 1)
        "#,
    )
    .bind::<SqlUuid, _>(tenant.tenant_id)
    .bind::<SqlUuid, _>(user_id)
    .bind::<SqlUuid, _>(client_id)
    .execute(&mut conn)
    .await
    .expect("SCIM credential test grant should insert");

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
            now() + interval '1 day', NULL, NULL, $7, NULL, NULL
        )
        "#,
    )
    .bind::<SqlUuid, _>(Uuid::now_v7())
    .bind::<SqlUuid, _>(tenant.tenant_id)
    .bind::<Text, _>(format!("scim-deprovision-refresh-{suffix}"))
    .bind::<SqlUuid, _>(Uuid::now_v7())
    .bind::<SqlUuid, _>(client_id)
    .bind::<Nullable<SqlUuid>, _>(Some(user_id))
    .bind::<Text, _>(user_id.to_string())
    .execute(&mut conn)
    .await
    .expect("SCIM credential test token should insert");

    client_id
}

async fn grant_count_for_user_client(
    pool: &nazo_postgres::DbPool,
    user_id: Uuid,
    client_id: Uuid,
) -> i64 {
    let mut conn = get_conn(pool)
        .await
        .expect("database connection should be available");
    sql_query(
        "SELECT COUNT(*) AS count FROM user_client_grants WHERE user_id = $1 AND client_id = $2",
    )
    .bind::<SqlUuid, _>(user_id)
    .bind::<SqlUuid, _>(client_id)
    .get_result::<CountRow>(&mut conn)
    .await
    .expect("SCIM credential test grant count should load")
    .count
}

async fn active_refresh_token_count_for_user_client(
    pool: &nazo_postgres::DbPool,
    user_id: Uuid,
    client_id: Uuid,
) -> i64 {
    let mut conn = get_conn(pool)
        .await
        .expect("database connection should be available");
    sql_query("SELECT COUNT(*) AS count FROM oauth_tokens WHERE user_id = $1 AND client_id = $2 AND revoked_at IS NULL")
        .bind::<SqlUuid, _>(user_id)
        .bind::<SqlUuid, _>(client_id)
        .get_result::<CountRow>(&mut conn)
        .await
        .expect("SCIM credential test token count should load")
        .count
}

async fn assert_missing_bearer_is_scim_unauthorized(response: HttpResponse) {
    let (status, body) = response_json(response).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["schemas"], json!([SCIM_ERROR_SCHEMA]));
    assert_eq!(body["status"], "401");
    assert_eq!(body["scimType"], "unauthorized");
    assert_eq!(body["detail"], "missing bearer token");
    assert!(body.get("Resources").is_none());
    assert!(body.get("password_hash").is_none());
}

async fn assert_scim_error_response(
    response: HttpResponse,
    expected_status: StatusCode,
    expected_scim_type: &str,
    expected_detail: &str,
) {
    let (status, body) = response_json(response).await;
    assert_eq!(status, expected_status);
    assert_eq!(body["schemas"], json!([SCIM_ERROR_SCHEMA]));
    assert_eq!(body["status"], expected_status.as_u16().to_string());
    assert_eq!(body["scimType"], expected_scim_type);
    assert_eq!(body["detail"], expected_detail);
}

#[test]
fn scim_user_filter_accepts_user_name_eq_quoted_email() {
    assert_eq!(
        normalize_scim_user_filter(Some(r#"userName eq "USER@example.com""#))
            .unwrap()
            .as_deref(),
        Some("user@example.com")
    );
}

#[test]
fn scim_user_filter_rejects_other_fields() {
    assert!(normalize_scim_user_filter(Some(r#"email eq "user@example.com""#)).is_err());
}

#[test]
fn patch_requires_replace_operations() {
    let operation = ScimPatchOperation {
        op: "add".to_owned(),
        path: Some("active".to_owned()),
        value: json!(true),
    };

    assert!(normalize_patch(vec![operation]).is_err());
}

#[test]
fn bearer_token_accepts_only_non_empty_bearer_scheme() {
    let req = actix_web::test::TestRequest::default()
        .insert_header((header::AUTHORIZATION, "Bearer scim-secret"))
        .to_http_request();
    assert_eq!(bearer_token(&req), Some("scim-secret"));

    let req = actix_web::test::TestRequest::default()
        .insert_header((header::AUTHORIZATION, "Basic scim-secret"))
        .to_http_request();
    assert_eq!(bearer_token(&req), None);

    let req = actix_web::test::TestRequest::default()
        .insert_header((header::AUTHORIZATION, "Bearer   "))
        .to_http_request();
    assert_eq!(bearer_token(&req), None);

    let req = actix_web::test::TestRequest::default()
        .insert_header((header::AUTHORIZATION, "Bearer token extra"))
        .to_http_request();
    assert_eq!(bearer_token(&req), None);
}

#[test]
fn scim_scope_values_accepts_only_non_empty_strings() {
    assert_eq!(
        scim_scope_values(&json!([SCIM_SCOPE_READ, "", 7, SCIM_SCOPE_WRITE])),
        vec![SCIM_SCOPE_READ, SCIM_SCOPE_WRITE]
    );
}

#[test]
fn scim_credentials_enforce_read_write_and_wildcard_scopes() {
    let tenant = default_tenant_context();
    let read_only = ScimCredential {
        token_id: None,
        tenant_id: tenant.tenant_id,
        scopes: vec![SCIM_SCOPE_READ.to_owned()],
        source: "test",
    };
    let wildcard = ScimCredential {
        scopes: vec![SCIM_SCOPE_ALL.to_owned()],
        ..read_only.clone()
    };

    assert!(scim_credential_allows(&read_only, ScimRequiredScope::Read));
    assert!(!scim_credential_allows(
        &read_only,
        ScimRequiredScope::Write
    ));
    assert!(scim_credential_allows(&wildcard, ScimRequiredScope::Read));
    assert!(scim_credential_allows(&wildcard, ScimRequiredScope::Write));
}

#[test]
fn scim_payload_requires_user_name_and_primary_email_to_match() {
    let payload = ScimUserRequest {
        user_name: Some("user@example.com".to_owned()),
        active: Some(true),
        name: None,
        emails: Some(vec![ScimEmail {
            value: Some("other@example.com".to_owned()),
            primary: Some(true),
        }]),
    };

    assert!(normalize_scim_user_payload(payload, true).is_err());
}

#[test]
fn scim_payload_normalizes_primary_email_identity() {
    let payload = ScimUserRequest {
        user_name: Some("USER@example.com".to_owned()),
        active: None,
        name: Some(ScimName {
            given_name: Some(" Alice ".to_owned()),
            family_name: Some(" Example ".to_owned()),
            formatted: Some(" Alice Example ".to_owned()),
        }),
        emails: Some(vec![ScimEmail {
            value: Some("user@example.com".to_owned()),
            primary: Some(true),
        }]),
    };

    let normalized = normalize_scim_user_payload(payload, true).unwrap();
    assert_eq!(normalized.user_name, "user@example.com");
    assert_eq!(normalized.email, "user@example.com");
    assert_eq!(normalized.display_name.as_deref(), Some("Alice Example"));
    assert!(normalized.active);
}

#[test]
fn patch_syncs_user_name_and_email_identity() {
    let patch = normalize_patch(vec![ScimPatchOperation {
        op: "replace".to_owned(),
        path: Some("userName".to_owned()),
        value: json!("USER@example.com"),
    }])
    .unwrap();

    assert_eq!(patch.user_name.as_deref(), Some("user@example.com"));
    assert_eq!(patch.email.as_deref(), Some("user@example.com"));
}

#[test]
fn patch_rejects_conflicting_user_name_and_email_identity() {
    let patch = normalize_patch(vec![ScimPatchOperation {
        op: "replace".to_owned(),
        path: None,
        value: json!({
            "userName": "user@example.com",
            "emails": [{"value": "other@example.com", "primary": true}]
        }),
    }]);

    assert!(patch.is_err());
}

#[actix_web::test]
async fn scim_error_response_uses_scim_error_schema_and_exact_status() {
    let response = scim_error(StatusCode::FORBIDDEN, "forbidden", "SCIM token lacks scope");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["schemas"], json!([SCIM_ERROR_SCHEMA]));
    assert_eq!(value["status"], "403");
    assert_eq!(value["scimType"], "forbidden");
    assert_eq!(value["detail"], "SCIM token lacks scope");
}

#[test]
fn scim_user_schema_declares_core_identity_fields() {
    let schema = scim_user_schema();
    assert_eq!(schema["schemas"], json!([SCIM_SCHEMA_SCHEMA]));
    assert_eq!(schema["id"], SCIM_USER_SCHEMA);

    let names = schema["attributes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|attribute| attribute["name"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert!(names.contains(&"userName"));
    assert!(names.contains(&"emails"));
    assert!(names.contains(&"active"));
    assert!(names.contains(&"name"));
}

#[actix_web::test]
async fn scim_service_provider_config_advertises_only_supported_capabilities() {
    let (status, body) = response_json(scim_service_provider_config_response()).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["schemas"],
        json!([SCIM_SERVICE_PROVIDER_CONFIG_SCHEMA])
    );
    assert_eq!(body["patch"]["supported"], true);
    assert_eq!(body["bulk"]["supported"], false);
    assert_eq!(body["filter"]["supported"], true);
    assert_eq!(body["filter"]["maxResults"], 200);
    assert_eq!(body["pagination"]["cursor"], true);
    assert_eq!(body["pagination"]["index"], true);
    assert_eq!(body["pagination"]["defaultPaginationMethod"], "index");
    assert_eq!(body["pagination"]["defaultPageSize"], 100);
    assert_eq!(body["pagination"]["maxPageSize"], 200);
    assert_eq!(body["pagination"]["cursorTimeout"], 600);
    assert_eq!(body["securityEvents"]["asyncRequest"], "none");
    assert_eq!(body["securityEvents"]["eventUris"], json!([]));
    assert_eq!(body["authenticationSchemes"][0]["type"], "oauthbearertoken");
    assert!(body.get("scim_bearer_token").is_none());
}

#[actix_web::test]
async fn scim_schemas_and_resource_types_use_list_response_shape() {
    let (schemas_status, schemas) = response_json(scim_schemas_response()).await;
    let (types_status, resource_types) = response_json(scim_resource_types_response()).await;

    assert_eq!(schemas_status, StatusCode::OK);
    assert_eq!(schemas["schemas"], json!([SCIM_LIST_SCHEMA]));
    assert_eq!(schemas["totalResults"], 1);
    assert_eq!(schemas["itemsPerPage"], 1);
    assert_eq!(schemas["Resources"][0]["id"], SCIM_USER_SCHEMA);

    assert_eq!(types_status, StatusCode::OK);
    assert_eq!(resource_types["schemas"], json!([SCIM_LIST_SCHEMA]));
    assert_eq!(resource_types["Resources"][0]["id"], "User");
    assert_eq!(resource_types["Resources"][0]["endpoint"], "/Users");
    assert_eq!(resource_types["Resources"][0]["schema"], SCIM_USER_SCHEMA);
}

#[actix_web::test]
async fn scim_list_users_response_preserves_pagination_and_hides_internal_user_fields() {
    let user = user_row(
        uuid_fixture(0x44444444444444444444444444444444),
        "alice@example.test",
    );

    let (status, body) = response_json(scim_list_users_response(10, 3, vec![user.clone()])).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["schemas"], json!([SCIM_LIST_SCHEMA]));
    assert_eq!(body["totalResults"], 10);
    assert_eq!(body["startIndex"], 3);
    assert_eq!(body["itemsPerPage"], 1);
    let resource = body["Resources"][0]
        .as_object()
        .expect("SCIM resource should be an object");
    assert_eq!(resource["schemas"], json!([SCIM_USER_SCHEMA]));
    assert_eq!(resource["id"], json!(user.id()));
    assert_eq!(resource["userName"], "alice@example.test");
    assert_eq!(resource["emails"][0]["value"], "alice@example.test");
    assert_eq!(
        resource["meta"]["location"],
        format!("/scim/v2/Users/{}", user.id())
    );
    for forbidden in [
        "tenant_id",
        "realm_id",
        "organization_id",
        "password_hash",
        "role",
        "admin_level",
        "mfa_enabled",
        "phone_number",
    ] {
        assert!(
            resource.get(forbidden).is_none(),
            "{forbidden} must not be exposed through SCIM user projection"
        );
    }
}

#[actix_web::test]
async fn scim_pagination_selects_index_and_cursor_methods_without_changing_default() {
    assert_eq!(
        select_scim_pagination(&ScimListQuery {
            start_index: None,
            count: None,
            filter: None,
            cursor: None,
        })
        .expect("default pagination should select index"),
        ScimPagination::Index {
            start_index: 1,
            count: SCIM_DEFAULT_PAGE_SIZE,
        }
    );
    assert_eq!(
        select_scim_pagination(&ScimListQuery {
            start_index: Some(7),
            count: Some(10),
            filter: None,
            cursor: None,
        })
        .expect("startIndex should select index"),
        ScimPagination::Index {
            start_index: 7,
            count: 10,
        }
    );
    assert_eq!(
        select_scim_pagination(&ScimListQuery {
            start_index: None,
            count: Some(-1),
            filter: None,
            cursor: Some(String::new()),
        })
        .expect("empty cursor should select the first cursor page"),
        ScimPagination::Cursor {
            encoded: None,
            count: 0,
        }
    );
    assert_eq!(
        select_scim_pagination(&ScimListQuery {
            start_index: None,
            count: Some(25),
            filter: None,
            cursor: Some("opaque".to_owned()),
        })
        .expect("non-empty cursor should select a later cursor page"),
        ScimPagination::Cursor {
            encoded: Some("opaque".to_owned()),
            count: 25,
        }
    );
}

#[actix_web::test]
async fn scim_pagination_rejects_mixed_methods_and_cursor_count_above_maximum() {
    for (query, expected_type) in [
        (
            ScimListQuery {
                start_index: Some(1),
                count: Some(10),
                filter: None,
                cursor: Some(String::new()),
            },
            "invalidValue",
        ),
        (
            ScimListQuery {
                start_index: None,
                count: Some(SCIM_MAX_PAGE_SIZE + 1),
                filter: None,
                cursor: Some(String::new()),
            },
            "invalidCount",
        ),
    ] {
        let response = select_scim_pagination(&query).expect_err("query should be rejected");
        let (status, body) = response_json(response).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["scimType"], expected_type);
    }
}

#[actix_web::test]
async fn scim_cursor_list_response_uses_cursor_attributes_only() {
    let user = user_row(
        uuid_fixture(0x66666666666666666666666666666666),
        "cursor@example.test",
    );
    let (status, body) = response_json(scim_cursor_list_users_response(
        10,
        vec![user],
        Some("opaque-next".to_owned()),
    ))
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["totalResults"], 10);
    assert_eq!(body["itemsPerPage"], 1);
    assert_eq!(body["nextCursor"], "opaque-next");
    assert!(body.get("startIndex").is_none());
    assert!(body.get("previousCursor").is_none());

    let (_, final_body) = response_json(scim_cursor_list_users_response(0, Vec::new(), None)).await;
    assert!(final_body.get("nextCursor").is_none());
}

#[actix_web::test]
async fn scim_create_user_response_returns_created_public_projection() {
    let user = user_row(
        uuid_fixture(0x55555555555555555555555555555555),
        "created@example.test",
    );

    let (status, body) = response_json(scim_create_user_response(user)).await;

    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["schemas"], json!([SCIM_USER_SCHEMA]));
    assert_eq!(body["userName"], "created@example.test");
    assert!(body.get("password_hash").is_none());
    assert!(body.get("tenant_id").is_none());
}

#[actix_web::test]
async fn scim_conflict_and_not_found_errors_use_exact_scim_error_shape() {
    let (conflict_status, conflict) = response_json(scim_uniqueness_conflict_response()).await;
    assert_eq!(conflict_status, StatusCode::CONFLICT);
    assert_eq!(conflict["schemas"], json!([SCIM_ERROR_SCHEMA]));
    assert_eq!(conflict["status"], "409");
    assert_eq!(conflict["scimType"], "uniqueness");
    assert_eq!(conflict["detail"], "userName or email already exists");

    let (missing_status, missing) = response_json(scim_user_not_found_response()).await;
    assert_eq!(missing_status, StatusCode::NOT_FOUND);
    assert_eq!(missing["schemas"], json!([SCIM_ERROR_SCHEMA]));
    assert_eq!(missing["status"], "404");
    assert_eq!(missing["scimType"], "notFound");
    assert_eq!(missing["detail"], "user not found");
}

#[actix_web::test]
async fn scim_delete_response_is_not_found_or_empty_no_content() {
    let (missing_status, missing) = response_json(scim_delete_user_response(0)).await;
    assert_eq!(missing_status, StatusCode::NOT_FOUND);
    assert_eq!(missing["scimType"], "notFound");

    let response = scim_delete_user_response(1);
    let status = response.status();
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("response body should be readable");
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(body.is_empty());
}

#[actix_web::test]
async fn scim_metadata_endpoints_require_bearer_before_disclosing_capabilities() {
    let state = Data::new(test_state());
    let req = actix_web::test::TestRequest::default().to_http_request();

    assert_missing_bearer_is_scim_unauthorized(
        scim_service_provider_config(state.clone(), req.clone()).await,
    )
    .await;
    assert_missing_bearer_is_scim_unauthorized(scim_schemas(state.clone(), req.clone()).await)
        .await;
    assert_missing_bearer_is_scim_unauthorized(scim_resource_types(state, req).await).await;
}

#[actix_web::test]
async fn scim_metadata_endpoints_accept_configured_legacy_bearer_token() {
    let state = Data::new(test_state_with_scim_bearer_token(Some(
        "legacy-scim-secret",
    )));
    let req = bearer_request("legacy-scim-secret");

    let (config_status, config) =
        response_json(scim_service_provider_config(state.clone(), req.clone()).await).await;
    assert_eq!(config_status, StatusCode::OK);
    assert_eq!(
        config["schemas"],
        json!([SCIM_SERVICE_PROVIDER_CONFIG_SCHEMA])
    );

    let (schemas_status, schemas) =
        response_json(scim_schemas(state.clone(), req.clone()).await).await;
    assert_eq!(schemas_status, StatusCode::OK);
    assert_eq!(schemas["schemas"], json!([SCIM_LIST_SCHEMA]));
    assert_eq!(schemas["Resources"][0]["id"], SCIM_USER_SCHEMA);

    let (types_status, resource_types) = response_json(scim_resource_types(state, req).await).await;
    assert_eq!(types_status, StatusCode::OK);
    assert_eq!(resource_types["schemas"], json!([SCIM_LIST_SCHEMA]));
    assert_eq!(resource_types["Resources"][0]["schema"], SCIM_USER_SCHEMA);
}

#[actix_web::test]
async fn scim_list_users_authenticates_before_parsing_malformed_query() {
    let app = actix_web::test::init_service(
        actix_web::App::new()
            .app_data(Data::new(test_state_with_scim_bearer_token(Some(
                "legacy-scim-secret",
            ))))
            .route("/Users", actix_web::web::get().to(scim_list_users)),
    )
    .await;
    let request = actix_web::test::TestRequest::get()
        .uri("/Users?cursor&count=not-a-number")
        .to_request();

    let response = actix_web::test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body: Value = actix_web::test::read_body_json(response).await;
    assert_eq!(body["schemas"], json!([SCIM_ERROR_SCHEMA]));
    assert_eq!(body["status"], "401");
}

#[actix_web::test]
async fn scim_list_users_maps_malformed_and_duplicate_query_to_scim_errors() {
    let app = actix_web::test::init_service(
        actix_web::App::new()
            .app_data(Data::new(test_state_with_scim_bearer_token(Some(
                "legacy-scim-secret",
            ))))
            .route("/Users", actix_web::web::get().to(scim_list_users)),
    )
    .await;

    for (query, expected_type) in [
        ("cursor&count=not-a-number", "invalidCount"),
        ("cursor&count=10&count=11", "invalidCount"),
        ("cursor&cursor=again&count=10", "invalidCursor"),
        ("cursor&startIndex=1&startIndex=2", "invalidValue"),
        ("cursor&filter=a&filter=b", "invalidValue"),
    ] {
        let request = actix_web::test::TestRequest::get()
            .uri(&format!("/Users?{query}"))
            .insert_header((header::AUTHORIZATION, "Bearer legacy-scim-secret"))
            .to_request();
        let response = actix_web::test::call_service(&app, request).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{query}");
        let body: Value = actix_web::test::read_body_json(response).await;
        assert_eq!(body["schemas"], json!([SCIM_ERROR_SCHEMA]), "{query}");
        assert_eq!(body["scimType"], expected_type, "{query}");
    }
}

#[actix_web::test]
async fn scim_list_users_rejects_invalid_filter_before_database_access() {
    let state = Data::new(test_state_with_scim_bearer_token(Some(
        "legacy-scim-secret",
    )));
    let req = bearer_request("legacy-scim-secret");

    assert_scim_error_response(
        scim_list_users_with_query(
            state,
            req,
            Query(ScimListQuery {
                start_index: Some(1),
                count: Some(10),
                filter: Some(r#"email eq "user@example.test""#.to_owned()),
                cursor: None,
            }),
        )
        .await,
        StatusCode::BAD_REQUEST,
        "invalidFilter",
        "only userName filters are supported",
    )
    .await;
}

#[actix_web::test]
async fn scim_cursor_validation_runs_after_auth_and_before_database_access() {
    let state = Data::new(test_state_with_scim_bearer_token(Some(
        "legacy-scim-secret",
    )));
    let req = bearer_request("legacy-scim-secret");

    assert_scim_error_response(
        scim_list_users_with_query(
            state,
            req,
            Query(ScimListQuery {
                start_index: None,
                count: Some(10),
                filter: None,
                cursor: Some("not-a-valid-cursor".to_owned()),
            }),
        )
        .await,
        StatusCode::BAD_REQUEST,
        "invalidCursor",
        "invalid cursor",
    )
    .await;
}

#[actix_web::test]
async fn scim_cursor_database_traverses_equal_timestamps_exactly_once() {
    let schema = format!("scim_cursor_{}", Uuid::now_v7().simple());
    let token = format!("legacy-scim-cursor-{}", Uuid::now_v7().simple());
    let Some(ScimTestFixture { state, pool }) =
        live_state_with_isolated_scim_bearer_token(&token, &schema, &["users"]).await
    else {
        return;
    };
    let req = bearer_request(&token);
    let mut expected = Vec::new();
    for index in 0..3 {
        let email = format!("cursor-{index}-{}@example.test", Uuid::now_v7().simple());
        expected.push(create_scim_user_id(state.clone(), &req, &email).await);
    }
    expected.sort();
    let fixed_created_at = Utc::now() - Duration::minutes(5);
    let mut conn = get_conn(&pool)
        .await
        .expect("database connection should be available");
    for user_id in &expected {
        sql_query("UPDATE users SET created_at = $1 WHERE id = $2")
            .bind::<Timestamptz, _>(fixed_created_at)
            .bind::<SqlUuid, _>(*user_id)
            .execute(&mut conn)
            .await
            .expect("cursor fixture timestamp should update");
    }
    drop(conn);

    let (zero_status, zero_body) = response_json(
        scim_list_users(
            state.clone(),
            bearer_request_uri(&token, "/scim/v2/Users?cursor&count=0"),
        )
        .await,
    )
    .await;
    assert_eq!(zero_status, StatusCode::OK);
    assert_eq!(zero_body["totalResults"], 3);
    assert_eq!(zero_body["itemsPerPage"], 0);
    assert!(zero_body["Resources"].as_array().unwrap().is_empty());
    assert!(zero_body.get("nextCursor").is_none());

    let (boundary_status, boundary_body) = response_json(
        scim_list_users(
            state.clone(),
            bearer_request_uri(&token, "/scim/v2/Users?cursor&count=3"),
        )
        .await,
    )
    .await;
    assert_eq!(boundary_status, StatusCode::OK);
    assert_eq!(boundary_body["itemsPerPage"], 3);
    assert!(boundary_body.get("nextCursor").is_none());

    let mut cursor = String::new();
    let mut collected = Vec::new();
    loop {
        let uri = if cursor.is_empty() {
            "/scim/v2/Users?cursor&count=1".to_owned()
        } else {
            format!("/scim/v2/Users?cursor={cursor}&count=1")
        };
        let (status, body) =
            response_json(scim_list_users(state.clone(), bearer_request_uri(&token, &uri)).await)
                .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["totalResults"], 3);
        assert_eq!(body["itemsPerPage"], 1);
        assert!(body.get("startIndex").is_none());
        assert!(body.get("previousCursor").is_none());
        collected.push(
            serde_json::from_value::<Uuid>(body["Resources"][0]["id"].clone())
                .expect("cursor resource should include an id"),
        );
        let Some(next) = body.get("nextCursor").and_then(Value::as_str) else {
            break;
        };
        if collected.len() == 1 {
            assert_scim_error_response(
                scim_list_users(
                    state.clone(),
                    bearer_request_uri(&token, &format!("/scim/v2/Users?cursor={next}&count=2")),
                )
                .await,
                StatusCode::BAD_REQUEST,
                "invalidCount",
                "count does not match cursor",
            )
            .await;
            assert_scim_error_response(
                scim_list_users(
                    state.clone(),
                    bearer_request_uri(
                        &token,
                        &format!(
                            "/scim/v2/Users?cursor={next}&count=1&filter=userName%20eq%20%22other%40example.test%22"
                        ),
                    ),
                )
                .await,
                StatusCode::BAD_REQUEST,
                "invalidCursor",
                "invalid cursor",
            )
            .await;

            let database_token = format!("cursor-database-{}", Uuid::now_v7().simple());
            let database_token_id = Uuid::now_v7();
            let mut conn = get_conn(&pool)
                .await
                .expect("database connection should be available");
            sql_query(
                "INSERT INTO public.scim_tokens \
                 (id, tenant_id, token_hash, label, scopes) \
                 VALUES ($1, $2, $3, $4, $5)",
            )
            .bind::<SqlUuid, _>(database_token_id)
            .bind::<SqlUuid, _>(default_tenant_context().tenant_id)
            .bind::<Text, _>(blake3_hex(&database_token))
            .bind::<Text, _>(format!("cursor-database-{database_token_id}"))
            .bind::<Jsonb, _>(json!([SCIM_SCOPE_READ]))
            .execute(&mut conn)
            .await
            .expect("database cursor credential should insert");
            drop(conn);
            assert_scim_error_response(
                scim_list_users(
                    state.clone(),
                    bearer_request_uri(
                        &database_token,
                        &format!("/scim/v2/Users?cursor={next}&count=1"),
                    ),
                )
                .await,
                StatusCode::BAD_REQUEST,
                "invalidCursor",
                "invalid cursor",
            )
            .await;
            let mut conn = get_conn(&pool)
                .await
                .expect("database connection should be available");
            sql_query("DELETE FROM public.scim_audit_events WHERE scim_token_id = $1")
                .bind::<SqlUuid, _>(database_token_id)
                .execute(&mut conn)
                .await
                .expect("database cursor audit fixture should clean up");
            sql_query("DELETE FROM public.scim_tokens WHERE id = $1")
                .bind::<SqlUuid, _>(database_token_id)
                .execute(&mut conn)
                .await
                .expect("database cursor credential should clean up");
            drop(conn);

            let deleted_id = expected.remove(1);
            let inserted_email =
                format!("cursor-inserted-{}@example.test", Uuid::now_v7().simple());
            let inserted_id = create_scim_user_id(state.clone(), &req, &inserted_email).await;
            let mut conn = get_conn(&pool)
                .await
                .expect("database connection should be available");
            sql_query("DELETE FROM users WHERE id = $1")
                .bind::<SqlUuid, _>(deleted_id)
                .execute(&mut conn)
                .await
                .expect("concurrent cursor fixture deletion should succeed");
            sql_query("UPDATE users SET created_at = $1 WHERE id = $2")
                .bind::<Timestamptz, _>(fixed_created_at)
                .bind::<SqlUuid, _>(inserted_id)
                .execute(&mut conn)
                .await
                .expect("concurrent cursor fixture insertion should update");
            drop(conn);
            expected.push(inserted_id);
            expected.sort();
        }
        cursor = next.to_owned();
    }

    cleanup_scim_schema(&pool, &schema).await;
    assert_eq!(collected, expected);
}

#[actix_web::test]
async fn scim_create_and_replace_user_reject_identity_mismatch_before_database_access() {
    let state = Data::new(test_state_with_scim_bearer_token(Some(
        "legacy-scim-secret",
    )));
    let req = bearer_request("legacy-scim-secret");
    let user_id = uuid_fixture(0x77777777777777777777777777777777);

    assert_scim_error_response(
        scim_create_user(
            state.clone(),
            req.clone(),
            Json(scim_user_request_mismatched_identity_fixture()),
        )
        .await,
        StatusCode::BAD_REQUEST,
        "invalidValue",
        "primary email must match userName",
    )
    .await;
    assert_scim_error_response(
        scim_replace_user(
            state,
            req,
            actix_web::web::Path::from(user_id),
            Json(scim_user_request_mismatched_identity_fixture()),
        )
        .await,
        StatusCode::BAD_REQUEST,
        "invalidValue",
        "primary email must match userName",
    )
    .await;
}

#[actix_web::test]
async fn scim_patch_user_rejects_invalid_schema_and_invalid_path_before_database_access() {
    let state = Data::new(test_state_with_scim_bearer_token(Some(
        "legacy-scim-secret",
    )));
    let req = bearer_request("legacy-scim-secret");
    let user_id = uuid_fixture(0x88888888888888888888888888888888);

    assert_scim_error_response(
        scim_patch_user(
            state.clone(),
            req.clone(),
            actix_web::web::Path::from(user_id),
            Json(ScimPatchRequest {
                schemas: vec!["urn:example:unsupported:PatchOp".to_owned()],
                operations: vec![ScimPatchOperation {
                    op: "replace".to_owned(),
                    path: Some("active".to_owned()),
                    value: json!(false),
                }],
            }),
        )
        .await,
        StatusCode::BAD_REQUEST,
        "invalidSyntax",
        "unsupported PATCH schema",
    )
    .await;
    assert_scim_error_response(
        scim_patch_user(
            state,
            req,
            actix_web::web::Path::from(user_id),
            Json(ScimPatchRequest {
                schemas: vec![SCIM_PATCH_SCHEMA.to_owned()],
                operations: vec![ScimPatchOperation {
                    op: "replace".to_owned(),
                    path: Some("password".to_owned()),
                    value: json!("secret"),
                }],
            }),
        )
        .await,
        StatusCode::BAD_REQUEST,
        "invalidPath",
        "unsupported path",
    )
    .await;
}

#[actix_web::test]
async fn scim_read_endpoints_surface_backend_unavailable_after_legacy_auth() {
    let state = Data::new(test_state_with_scim_bearer_token(Some(
        "legacy-scim-secret",
    )));
    let req = bearer_request("legacy-scim-secret");
    let user_id = uuid_fixture(0x99999999999999999999999999999999);

    assert_scim_error_response(
        scim_list_users_with_query(
            state.clone(),
            req.clone(),
            Query(ScimListQuery {
                start_index: Some(1),
                count: Some(10),
                filter: Some(r#"userName eq "user@example.test""#.to_owned()),
                cursor: None,
            }),
        )
        .await,
        StatusCode::SERVICE_UNAVAILABLE,
        "server_error",
        "backend unavailable",
    )
    .await;
    assert_scim_error_response(
        scim_get_user(state, req, actix_web::web::Path::from(user_id)).await,
        StatusCode::SERVICE_UNAVAILABLE,
        "server_error",
        "backend unavailable",
    )
    .await;
}

#[actix_web::test]
async fn scim_mutating_endpoints_surface_backend_unavailable_after_legacy_auth() {
    let state = Data::new(test_state_with_scim_bearer_token(Some(
        "legacy-scim-secret",
    )));
    let req = bearer_request("legacy-scim-secret");
    let user_id = uuid_fixture(0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa);
    let patch_payload = ScimPatchRequest {
        schemas: vec![SCIM_PATCH_SCHEMA.to_owned()],
        operations: vec![ScimPatchOperation {
            op: "replace".to_owned(),
            path: Some("active".to_owned()),
            value: json!(false),
        }],
    };

    assert_scim_error_response(
        scim_create_user(
            state.clone(),
            req.clone(),
            Json(scim_user_request_fixture()),
        )
        .await,
        StatusCode::SERVICE_UNAVAILABLE,
        "server_error",
        "backend unavailable",
    )
    .await;
    assert_scim_error_response(
        scim_replace_user(
            state.clone(),
            req.clone(),
            actix_web::web::Path::from(user_id),
            Json(scim_user_request_fixture()),
        )
        .await,
        StatusCode::SERVICE_UNAVAILABLE,
        "server_error",
        "backend unavailable",
    )
    .await;
    assert_scim_error_response(
        scim_patch_user(
            state.clone(),
            req.clone(),
            actix_web::web::Path::from(user_id),
            Json(patch_payload),
        )
        .await,
        StatusCode::SERVICE_UNAVAILABLE,
        "server_error",
        "backend unavailable",
    )
    .await;
    assert_scim_error_response(
        scim_delete_user(state, req, actix_web::web::Path::from(user_id)).await,
        StatusCode::SERVICE_UNAVAILABLE,
        "server_error",
        "backend unavailable",
    )
    .await;
}

#[actix_web::test]
async fn scim_user_lifecycle_enforces_bearer_scope_identity_uniqueness_and_soft_delete() {
    let suffix = Uuid::now_v7().simple().to_string();
    let token = format!("legacy-scim-{suffix}");
    let Some(ScimTestFixture { state, pool }) = live_state_with_scim_bearer_token(&token).await
    else {
        return;
    };
    let email = format!("scim-lifecycle-{suffix}@example.test");
    cleanup_scim_user_by_email(&pool, &email).await;
    let req = bearer_request(&token);

    let (create_status, created) = response_json(
        scim_create_user(
            state.clone(),
            req.clone(),
            Json(scim_user_request_for_email(&email)),
        )
        .await,
    )
    .await;
    assert_eq!(create_status, StatusCode::CREATED);
    assert_eq!(created["schemas"], json!([SCIM_USER_SCHEMA]));
    assert_eq!(created["userName"], email);
    assert!(created.get("password_hash").is_none());
    let user_id = serde_json::from_value::<Uuid>(created["id"].clone())
        .expect("SCIM create response should include id");

    assert_scim_error_response(
        scim_create_user(
            state.clone(),
            req.clone(),
            Json(scim_user_request_for_email(&email)),
        )
        .await,
        StatusCode::CONFLICT,
        "uniqueness",
        "userName or email already exists",
    )
    .await;

    let (list_status, list) = response_json(
        scim_list_users_with_query(
            state.clone(),
            req.clone(),
            Query(ScimListQuery {
                start_index: Some(1),
                count: Some(10),
                filter: Some(format!(r#"userName eq "{email}""#)),
                cursor: None,
            }),
        )
        .await,
    )
    .await;
    assert_eq!(list_status, StatusCode::OK);
    assert_eq!(list["totalResults"], 1);
    assert_eq!(list["Resources"][0]["id"], json!(user_id));

    let (empty_list_status, empty_list) = response_json(
        scim_list_users_with_query(
            state.clone(),
            req.clone(),
            Query(ScimListQuery {
                start_index: Some(1),
                count: Some(0),
                filter: Some(format!(r#"userName eq "{email}""#)),
                cursor: None,
            }),
        )
        .await,
    )
    .await;
    assert_eq!(empty_list_status, StatusCode::OK);
    assert_eq!(empty_list["totalResults"], 1);
    assert_eq!(empty_list["itemsPerPage"], 0);
    assert!(empty_list["Resources"].as_array().unwrap().is_empty());

    let (get_status, got) = response_json(
        scim_get_user(
            state.clone(),
            req.clone(),
            actix_web::web::Path::from(user_id),
        )
        .await,
    )
    .await;
    assert_eq!(get_status, StatusCode::OK);
    assert_eq!(got["userName"], email);

    let replace_payload = ScimUserRequest {
        user_name: Some(email.clone()),
        active: Some(true),
        name: Some(ScimName {
            given_name: Some("Updated".to_owned()),
            family_name: Some("User".to_owned()),
            formatted: Some("Updated User".to_owned()),
        }),
        emails: Some(vec![ScimEmail {
            value: Some(email.clone()),
            primary: Some(true),
        }]),
    };
    let (replace_status, replaced) = response_json(
        scim_replace_user(
            state.clone(),
            req.clone(),
            actix_web::web::Path::from(user_id),
            Json(replace_payload),
        )
        .await,
    )
    .await;
    assert_eq!(replace_status, StatusCode::OK);
    assert_eq!(replaced["name"]["givenName"], "Updated");

    let (patch_status, patched) = response_json(
        scim_patch_user(
            state.clone(),
            req.clone(),
            actix_web::web::Path::from(user_id),
            Json(ScimPatchRequest {
                schemas: vec![SCIM_PATCH_SCHEMA.to_owned()],
                operations: vec![ScimPatchOperation {
                    op: "replace".to_owned(),
                    path: Some("active".to_owned()),
                    value: json!(false),
                }],
            }),
        )
        .await,
    )
    .await;
    assert_eq!(patch_status, StatusCode::OK);
    assert_eq!(patched["active"], false);

    let delete_response = scim_delete_user(
        state.clone(),
        req.clone(),
        actix_web::web::Path::from(user_id),
    )
    .await;
    assert_eq!(delete_response.status(), StatusCode::NO_CONTENT);

    assert_scim_error_response(
        scim_replace_user(
            state.clone(),
            req.clone(),
            actix_web::web::Path::from(Uuid::now_v7()),
            Json(scim_user_request_fixture()),
        )
        .await,
        StatusCode::NOT_FOUND,
        "notFound",
        "user not found",
    )
    .await;
    assert_scim_error_response(
        scim_get_user(state, req, actix_web::web::Path::from(Uuid::now_v7())).await,
        StatusCode::NOT_FOUND,
        "notFound",
        "user not found",
    )
    .await;
}

#[actix_web::test]
async fn scim_delete_is_a_soft_delete_and_keeps_resource_visible_as_inactive() {
    let suffix = Uuid::now_v7().simple().to_string();
    let token = format!("legacy-scim-soft-delete-{suffix}");
    let Some(ScimTestFixture { state, pool }) = live_state_with_scim_bearer_token(&token).await
    else {
        return;
    };
    let email = format!("scim-soft-delete-{suffix}@example.test");
    cleanup_scim_user_by_email(&pool, &email).await;
    let req = bearer_request(&token);
    let user_id = create_scim_user_id(state.clone(), &req, &email).await;

    let delete_response = scim_delete_user(
        state.clone(),
        req.clone(),
        actix_web::web::Path::from(user_id),
    )
    .await;
    assert_eq!(delete_response.status(), StatusCode::NO_CONTENT);

    let (get_status, got) = response_json(
        scim_get_user(
            state.clone(),
            req.clone(),
            actix_web::web::Path::from(user_id),
        )
        .await,
    )
    .await;
    assert_eq!(get_status, StatusCode::OK);
    assert_eq!(got["userName"], email);
    assert_eq!(got["active"], false);
    assert!(got.get("password_hash").is_none());
    assert!(got.get("tenant_id").is_none());

    let (list_status, list) = response_json(
        scim_list_users_with_query(
            state,
            req,
            Query(ScimListQuery {
                start_index: Some(1),
                count: Some(10),
                filter: Some(format!(r#"userName eq "{email}""#)),
                cursor: None,
            }),
        )
        .await,
    )
    .await;
    assert_eq!(list_status, StatusCode::OK);
    assert_eq!(list["totalResults"], 1);
    assert_eq!(list["Resources"][0]["id"], json!(user_id));
    assert_eq!(list["Resources"][0]["active"], false);
}

#[actix_web::test]
async fn scim_delete_revokes_refresh_tokens_and_removes_client_grants() {
    let suffix = Uuid::now_v7().simple().to_string();
    let token = format!("legacy-scim-credential-revoke-{suffix}");
    let Some(ScimTestFixture { state, pool }) = live_state_with_scim_bearer_token(&token).await
    else {
        return;
    };
    let email = format!("scim-credential-revoke-{suffix}@example.test");
    cleanup_scim_user_by_email(&pool, &email).await;
    let req = bearer_request(&token);
    let user_id = create_scim_user_id(state.clone(), &req, &email).await;
    let client_id = insert_scim_user_oauth_credentials(&pool, user_id, &suffix).await;

    assert_eq!(
        grant_count_for_user_client(&pool, user_id, client_id).await,
        1
    );
    assert_eq!(
        active_refresh_token_count_for_user_client(&pool, user_id, client_id).await,
        1
    );

    let delete_response = scim_delete_user(
        state.clone(),
        req.clone(),
        actix_web::web::Path::from(user_id),
    )
    .await;
    assert_eq!(delete_response.status(), StatusCode::NO_CONTENT);

    assert_eq!(
        grant_count_for_user_client(&pool, user_id, client_id).await,
        0
    );
    assert_eq!(
        active_refresh_token_count_for_user_client(&pool, user_id, client_id).await,
        0
    );
}

#[actix_web::test]
async fn scim_replace_deprovision_revokes_refresh_tokens_and_removes_client_grants() {
    let suffix = Uuid::now_v7().simple().to_string();
    let token = format!("legacy-scim-replace-revoke-{suffix}");
    let Some(ScimTestFixture { state, pool }) = live_state_with_scim_bearer_token(&token).await
    else {
        return;
    };
    let email = format!("scim-replace-revoke-{suffix}@example.test");
    cleanup_scim_user_by_email(&pool, &email).await;
    let req = bearer_request(&token);
    let user_id = create_scim_user_id(state.clone(), &req, &email).await;
    let client_id = insert_scim_user_oauth_credentials(&pool, user_id, &suffix).await;

    let replace_response = scim_replace_user(
        state.clone(),
        req.clone(),
        actix_web::web::Path::from(user_id),
        Json(ScimUserRequest {
            user_name: Some(email.clone()),
            active: Some(false),
            name: Some(ScimName {
                given_name: Some("Inactive".to_owned()),
                family_name: Some("User".to_owned()),
                formatted: Some("Inactive User".to_owned()),
            }),
            emails: Some(vec![ScimEmail {
                value: Some(email),
                primary: Some(true),
            }]),
        }),
    )
    .await;
    assert_eq!(replace_response.status(), StatusCode::OK);
    assert_eq!(
        grant_count_for_user_client(&pool, user_id, client_id).await,
        0
    );
    assert_eq!(
        active_refresh_token_count_for_user_client(&pool, user_id, client_id).await,
        0
    );
}

#[actix_web::test]
async fn scim_patch_deprovision_revokes_refresh_tokens_and_removes_client_grants() {
    let suffix = Uuid::now_v7().simple().to_string();
    let token = format!("legacy-scim-patch-revoke-{suffix}");
    let Some(ScimTestFixture { state, pool }) = live_state_with_scim_bearer_token(&token).await
    else {
        return;
    };
    let email = format!("scim-patch-revoke-{suffix}@example.test");
    cleanup_scim_user_by_email(&pool, &email).await;
    let req = bearer_request(&token);
    let user_id = create_scim_user_id(state.clone(), &req, &email).await;
    let client_id = insert_scim_user_oauth_credentials(&pool, user_id, &suffix).await;

    let patch_response = scim_patch_user(
        state.clone(),
        req.clone(),
        actix_web::web::Path::from(user_id),
        Json(ScimPatchRequest {
            schemas: vec![SCIM_PATCH_SCHEMA.to_owned()],
            operations: vec![ScimPatchOperation {
                op: "replace".to_owned(),
                path: Some("active".to_owned()),
                value: json!(false),
            }],
        }),
    )
    .await;
    assert_eq!(patch_response.status(), StatusCode::OK);
    assert_eq!(
        grant_count_for_user_client(&pool, user_id, client_id).await,
        0
    );
    assert_eq!(
        active_refresh_token_count_for_user_client(&pool, user_id, client_id).await,
        0
    );
}

#[actix_web::test]
async fn scim_replace_and_patch_return_uniqueness_conflicts_without_internal_fields() {
    let suffix = Uuid::now_v7().simple().to_string();
    let token = format!("legacy-scim-uniqueness-{suffix}");
    let Some(ScimTestFixture { state, pool }) = live_state_with_scim_bearer_token(&token).await
    else {
        return;
    };
    let first_email = format!("scim-uniqueness-a-{suffix}@example.test");
    let second_email = format!("scim-uniqueness-b-{suffix}@example.test");
    cleanup_scim_user_by_email(&pool, &first_email).await;
    cleanup_scim_user_by_email(&pool, &second_email).await;
    let req = bearer_request(&token);
    let first_id = create_scim_user_id(state.clone(), &req, &first_email).await;
    let _second_id = create_scim_user_id(state.clone(), &req, &second_email).await;

    let (replace_status, replace_body) = response_json(
        scim_replace_user(
            state.clone(),
            req.clone(),
            actix_web::web::Path::from(first_id),
            Json(scim_user_request_for_email(&second_email)),
        )
        .await,
    )
    .await;
    assert_eq!(replace_status, StatusCode::CONFLICT);
    assert_eq!(replace_body["schemas"], json!([SCIM_ERROR_SCHEMA]));
    assert_eq!(replace_body["scimType"], "uniqueness");
    assert_eq!(replace_body["detail"], "userName or email already exists");
    assert!(replace_body.get("password_hash").is_none());
    assert!(replace_body.get("tenant_id").is_none());

    let (patch_status, patch_body) = response_json(
        scim_patch_user(
            state,
            req,
            actix_web::web::Path::from(first_id),
            Json(ScimPatchRequest {
                schemas: vec![SCIM_PATCH_SCHEMA.to_owned()],
                operations: vec![ScimPatchOperation {
                    op: "replace".to_owned(),
                    path: None,
                    value: json!({
                        "userName": second_email,
                        "emails": [{"value": second_email, "primary": true}]
                    }),
                }],
            }),
        )
        .await,
    )
    .await;
    assert_eq!(patch_status, StatusCode::CONFLICT);
    assert_eq!(patch_body["schemas"], json!([SCIM_ERROR_SCHEMA]));
    assert_eq!(patch_body["scimType"], "uniqueness");
    assert_eq!(patch_body["detail"], "userName or email already exists");
    assert!(patch_body.get("password_hash").is_none());
    assert!(patch_body.get("tenant_id").is_none());
}

#[actix_web::test]
async fn scim_patch_bulk_replace_updates_identity_profile_and_filter_projection() {
    let suffix = Uuid::now_v7().simple().to_string();
    let token = format!("legacy-scim-patch-{suffix}");
    let Some(ScimTestFixture { state, pool }) = live_state_with_scim_bearer_token(&token).await
    else {
        return;
    };
    let original_email = format!("scim-patch-a-{suffix}@example.test");
    let updated_email = format!("scim-patch-b-{suffix}@example.test");
    cleanup_scim_user_by_email(&pool, &original_email).await;
    cleanup_scim_user_by_email(&pool, &updated_email).await;
    let req = bearer_request(&token);
    let user_id = create_scim_user_id(state.clone(), &req, &original_email).await;

    let (patch_status, patched) = response_json(
        scim_patch_user(
            state.clone(),
            req.clone(),
            actix_web::web::Path::from(user_id),
            Json(ScimPatchRequest {
                schemas: vec![SCIM_PATCH_SCHEMA.to_owned()],
                operations: vec![ScimPatchOperation {
                    op: "replace".to_owned(),
                    path: None,
                    value: json!({
                        "userName": updated_email,
                        "emails": [{"value": updated_email, "primary": true}],
                        "active": false,
                        "name": {
                            "formatted": "Patched User",
                            "givenName": "Patched",
                            "familyName": "User"
                        }
                    }),
                }],
            }),
        )
        .await,
    )
    .await;
    assert_eq!(patch_status, StatusCode::OK);
    assert_eq!(patched["schemas"], json!([SCIM_USER_SCHEMA]));
    assert_eq!(patched["userName"], updated_email);
    assert_eq!(patched["emails"][0]["value"], updated_email);
    assert_eq!(patched["active"], false);
    assert_eq!(patched["name"]["formatted"], "Patched User");
    assert_eq!(patched["name"]["givenName"], "Patched");
    assert_eq!(patched["name"]["familyName"], "User");
    assert!(patched.get("password_hash").is_none());
    assert!(patched.get("tenant_id").is_none());

    let (list_status, list) = response_json(
        scim_list_users_with_query(
            state,
            req,
            Query(ScimListQuery {
                start_index: Some(1),
                count: Some(10),
                filter: Some(format!(r#"userName eq "{updated_email}""#)),
                cursor: None,
            }),
        )
        .await,
    )
    .await;
    assert_eq!(list_status, StatusCode::OK);
    assert_eq!(list["totalResults"], 1);
    assert_eq!(list["Resources"][0]["id"], json!(user_id));
    assert_eq!(list["Resources"][0]["userName"], updated_email);
    assert_eq!(list["Resources"][0]["active"], false);
}

#[actix_web::test]
async fn scim_patch_reports_not_found_for_missing_user_after_successful_authentication() {
    let suffix = Uuid::now_v7().simple().to_string();
    let token = format!("legacy-scim-missing-patch-{suffix}");
    let Some(ScimTestFixture { state, pool: _ }) = live_state_with_scim_bearer_token(&token).await
    else {
        return;
    };
    let req = bearer_request(&token);

    assert_scim_error_response(
        scim_patch_user(
            state,
            req,
            actix_web::web::Path::from(Uuid::now_v7()),
            Json(ScimPatchRequest {
                schemas: vec![SCIM_PATCH_SCHEMA.to_owned()],
                operations: vec![ScimPatchOperation {
                    op: "replace".to_owned(),
                    path: Some("active".to_owned()),
                    value: json!(false),
                }],
            }),
        )
        .await,
        StatusCode::NOT_FOUND,
        "notFound",
        "user not found",
    )
    .await;
}

#[actix_web::test]
async fn scim_user_endpoints_require_bearer_before_user_state_access() {
    let state = Data::new(test_state());
    let req = actix_web::test::TestRequest::default().to_http_request();
    let user_id = uuid_fixture(0x66666666666666666666666666666666);
    let patch_payload = ScimPatchRequest {
        schemas: vec![SCIM_PATCH_SCHEMA.to_owned()],
        operations: vec![ScimPatchOperation {
            op: "replace".to_owned(),
            path: Some("active".to_owned()),
            value: json!(false),
        }],
    };

    assert_missing_bearer_is_scim_unauthorized(
        scim_list_users_with_query(
            state.clone(),
            req.clone(),
            Query(ScimListQuery {
                start_index: Some(1),
                count: Some(10),
                filter: None,
                cursor: None,
            }),
        )
        .await,
    )
    .await;
    assert_missing_bearer_is_scim_unauthorized(
        scim_create_user(
            state.clone(),
            req.clone(),
            Json(scim_user_request_fixture()),
        )
        .await,
    )
    .await;
    assert_missing_bearer_is_scim_unauthorized(
        scim_get_user(
            state.clone(),
            req.clone(),
            actix_web::web::Path::from(user_id),
        )
        .await,
    )
    .await;
    assert_missing_bearer_is_scim_unauthorized(
        scim_replace_user(
            state.clone(),
            req.clone(),
            actix_web::web::Path::from(user_id),
            Json(scim_user_request_fixture()),
        )
        .await,
    )
    .await;
    assert_missing_bearer_is_scim_unauthorized(
        scim_patch_user(
            state.clone(),
            req.clone(),
            actix_web::web::Path::from(user_id),
            Json(patch_payload),
        )
        .await,
    )
    .await;
    assert_missing_bearer_is_scim_unauthorized(
        scim_delete_user(state, req, actix_web::web::Path::from(user_id)).await,
    )
    .await;
}

#[actix_web::test]
async fn scim_list_users_surfaces_backend_unavailable_when_projection_query_breaks() {
    let schema = format!("scim_projection_{}", Uuid::now_v7().simple());
    let token = "legacy-scim-projection-token";
    let Some(ScimTestFixture { state, pool }) =
        live_state_with_isolated_scim_bearer_token(token, &schema, &["users"]).await
    else {
        return;
    };
    let req = bearer_request(token);
    let email = format!("projection-{}@example.test", Uuid::now_v7().simple());
    let _ = create_scim_user_id(state.clone(), &req, &email).await;
    rename_scim_column(
        &pool,
        &schema,
        "users",
        "display_name",
        "display_name_unavailable",
    )
    .await;

    let response = scim_list_users_with_query(
        state.clone(),
        req,
        Query(ScimListQuery {
            start_index: Some(1),
            count: Some(10),
            filter: Some(format!(r#"userName eq "{email}""#)),
            cursor: None,
        }),
    )
    .await;
    cleanup_scim_schema(&pool, &schema).await;

    assert_scim_error_response(
        response,
        StatusCode::SERVICE_UNAVAILABLE,
        "server_error",
        "backend unavailable",
    )
    .await;
}

#[actix_web::test]
async fn scim_create_user_surfaces_backend_unavailable_when_insert_query_breaks() {
    let schema = format!("scim_create_write_{}", Uuid::now_v7().simple());
    let token = "legacy-scim-create-write-token";
    let Some(ScimTestFixture { state, pool }) =
        live_state_with_isolated_scim_bearer_token(token, &schema, &["users"]).await
    else {
        return;
    };
    rename_scim_column(
        &pool,
        &schema,
        "users",
        "display_name",
        "display_name_unavailable",
    )
    .await;

    let response = scim_create_user(
        state.clone(),
        bearer_request(token),
        Json(scim_user_request_for_email(&format!(
            "create-write-{}@example.test",
            Uuid::now_v7().simple()
        ))),
    )
    .await;
    cleanup_scim_schema(&pool, &schema).await;

    assert_scim_error_response(
        response,
        StatusCode::SERVICE_UNAVAILABLE,
        "server_error",
        "backend unavailable",
    )
    .await;
}

#[actix_web::test]
async fn scim_get_user_surfaces_backend_unavailable_when_projection_query_breaks() {
    let schema = format!("scim_get_projection_{}", Uuid::now_v7().simple());
    let token = "legacy-scim-get-projection-token";
    let Some(ScimTestFixture { state, pool }) =
        live_state_with_isolated_scim_bearer_token(token, &schema, &["users"]).await
    else {
        return;
    };
    let req = bearer_request(token);
    let email = format!("get-projection-{}@example.test", Uuid::now_v7().simple());
    let user_id = create_scim_user_id(state.clone(), &req, &email).await;
    rename_scim_column(
        &pool,
        &schema,
        "users",
        "display_name",
        "display_name_unavailable",
    )
    .await;

    let response = scim_get_user(state.clone(), req, actix_web::web::Path::from(user_id)).await;
    cleanup_scim_schema(&pool, &schema).await;

    assert_scim_error_response(
        response,
        StatusCode::SERVICE_UNAVAILABLE,
        "server_error",
        "backend unavailable",
    )
    .await;
}

#[actix_web::test]
async fn scim_replace_user_surfaces_backend_unavailable_when_update_query_breaks() {
    let schema = format!("scim_replace_write_{}", Uuid::now_v7().simple());
    let token = "legacy-scim-replace-write-token";
    let Some(ScimTestFixture { state, pool }) =
        live_state_with_isolated_scim_bearer_token(token, &schema, &["users"]).await
    else {
        return;
    };
    let req = bearer_request(token);
    let email = format!("replace-write-{}@example.test", Uuid::now_v7().simple());
    let user_id = create_scim_user_id(state.clone(), &req, &email).await;
    rename_scim_column(
        &pool,
        &schema,
        "users",
        "updated_at",
        "updated_at_unavailable",
    )
    .await;

    let response = scim_replace_user(
        state.clone(),
        req,
        actix_web::web::Path::from(user_id),
        Json(scim_user_request_for_email(&format!(
            "replace-after-failure-{}@example.test",
            Uuid::now_v7().simple()
        ))),
    )
    .await;
    cleanup_scim_schema(&pool, &schema).await;

    assert_scim_error_response(
        response,
        StatusCode::SERVICE_UNAVAILABLE,
        "server_error",
        "backend unavailable",
    )
    .await;
}

#[actix_web::test]
async fn scim_delete_user_surfaces_backend_unavailable_when_soft_delete_query_breaks() {
    let schema = format!("scim_delete_write_{}", Uuid::now_v7().simple());
    let token = "legacy-scim-delete-write-token";
    let Some(ScimTestFixture { state, pool }) =
        live_state_with_isolated_scim_bearer_token(token, &schema, &["users"]).await
    else {
        return;
    };
    let req = bearer_request(token);
    let email = format!("delete-write-{}@example.test", Uuid::now_v7().simple());
    let user_id = create_scim_user_id(state.clone(), &req, &email).await;
    rename_scim_column(
        &pool,
        &schema,
        "users",
        "updated_at",
        "updated_at_unavailable",
    )
    .await;

    let response = scim_delete_user(state.clone(), req, actix_web::web::Path::from(user_id)).await;
    cleanup_scim_schema(&pool, &schema).await;

    assert_scim_error_response(
        response,
        StatusCode::SERVICE_UNAVAILABLE,
        "server_error",
        "backend unavailable",
    )
    .await;
}
