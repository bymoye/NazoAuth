use super::*;
use actix_web::cookie::Cookie;
use diesel::QueryableByName;
use diesel::sql_query;
use diesel::sql_types::{BigInt, Int4, Nullable, Text, Uuid as SqlUuid};
use diesel_async::RunQueryDsl;
use fred::interfaces::ClientLike;
use fred::prelude::{
    Builder as ValkeyBuilder, Config as ValkeyConfig, ConnectionConfig, PerformanceConfig,
};
use std::sync::Arc;
use std::time::Duration as StdDuration;

use crate::config::ConfigSource;
use crate::db::{create_pool, get_conn};
use crate::domain::{ActiveSigningKey, Keyset, KeysetStore};
use crate::http::admin::{
    CreateClientRequest, InsertClientError, PreparedClientInsert, insert_prepared_client,
    prepare_client_insert_with_secret_pepper,
};

async fn prepare_client_insert_for_test(
    payload: CreateClientRequest,
    pairwise_subject_secret: Option<&str>,
    issuer: &str,
) -> Result<PreparedClientInsert, InsertClientError> {
    prepare_client_insert_with_secret_pepper(
        payload,
        pairwise_subject_secret,
        crate::support::LOCAL_DEVELOPMENT_CLIENT_SECRET_PEPPER,
        issuer,
        crate::support::SUPPORTED_CLIENT_JWT_SIGNING_ALGS,
    )
    .await
}

fn grant_row() -> GrantRow {
    GrantRow {
        user_id: Uuid::now_v7(),
        email: "user@example.com".to_owned(),
        client_id: "client-1".to_owned(),
        client_name: "Client One".to_owned(),
        last_authorized_at: Utc::now(),
        authorization_count: 3,
        last_scopes: json!(["openid", "payments", 42, null]),
        last_authorization_details: json!([{"type": "payment_initiation"}]),
    }
}

#[derive(QueryableByName)]
struct CountRow {
    #[diesel(sql_type = BigInt)]
    count: i64,
}

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
            "postgres://nazo_admin_grants_test_invalid:nazo_admin_grants_test_invalid@127.0.0.1:1/nazo"
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

fn create_client_request(client_name: &str) -> CreateClientRequest {
    CreateClientRequest {
        client_name: client_name.to_owned(),
        client_type: "confidential".to_owned(),
        redirect_uris: vec!["https://client.example/callback".to_owned()],
        post_logout_redirect_uris: Vec::new(),
        scopes: vec!["openid".to_owned(), "payments".to_owned()],
        allowed_audiences: vec!["https://api.example".to_owned()],
        grant_types: vec!["authorization_code".to_owned(), "refresh_token".to_owned()],
        token_endpoint_auth_method: "client_secret_post".to_owned(),
        require_dpop_bound_tokens: false,
        allow_client_assertion_audience_array: false,
        allow_client_assertion_endpoint_audience: false,
        require_par_request_object: false,
        allow_authorization_code_without_pkce: false,
        backchannel_logout_uri: None,
        backchannel_logout_session_required: true,
        frontchannel_logout_uri: None,
        frontchannel_logout_session_required: true,
        tls_client_auth_subject_dn: None,
        tls_client_auth_cert_sha256: None,
        tls_client_auth_san_dns: Vec::new(),
        tls_client_auth_san_uri: Vec::new(),
        tls_client_auth_san_ip: Vec::new(),
        tls_client_auth_san_email: Vec::new(),
        jwks: None,
        introspection_encrypted_response_alg: None,
        introspection_encrypted_response_enc: None,
        userinfo_signed_response_alg: None,
        userinfo_encrypted_response_alg: None,
        userinfo_encrypted_response_enc: None,
        authorization_signed_response_alg: None,
        authorization_encrypted_response_alg: None,
        authorization_encrypted_response_enc: None,
        allow_jwks_without_kid: false,
        subject_type: None,
        sector_identifier_uri: None,
    }
}

fn oauth_error_name(response: &HttpResponse) -> Option<String> {
    response
        .extensions()
        .get::<OAuthJsonErrorFields>()
        .map(|fields| fields.error.clone())
}

fn database_url_with_search_path(schema: &str) -> Option<String> {
    let base = std::env::var("DATABASE_URL").ok()?;
    let separator = if base.contains('?') { "&" } else { "?" };
    Some(format!(
        "{base}{separator}options=-csearch_path%3D{schema}%2Cpublic"
    ))
}

struct LiveAdminGrantFixture {
    state: Data<AppState>,
    schema: Option<String>,
}

impl LiveAdminGrantFixture {
    async fn new() -> Option<Self> {
        let database_url = std::env::var("DATABASE_URL").ok()?;
        Self::from_database_url(database_url, None).await
    }

    async fn new_isolated(schema: &str) -> Option<Self> {
        let database_url = database_url_with_search_path(schema)?;
        let fixture = Self::from_database_url(database_url, Some(schema.to_owned())).await?;
        fixture
            .create_isolated_schema(&[
                "users",
                "oauth_clients",
                "user_client_grants",
                "oauth_tokens",
            ])
            .await;
        Some(fixture)
    }

    async fn from_database_url(database_url: String, schema: Option<String>) -> Option<Self> {
        let valkey_url = std::env::var("VALKEY_URL").ok()?;
        let config = ConfigSource::from_pairs_for_test([
            ("ISSUER", "https://issuer.example"),
            (
                "CLIENT_SECRET_PEPPER",
                "client-secret-pepper-for-tests-000000000001",
            ),
            ("COOKIE_SECURE", "true"),
            ("SESSION_COOKIE_NAME", "nazo_admin_grants_session"),
            ("CSRF_COOKIE_NAME", "nazo_admin_grants_csrf"),
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
            state: Data::new(AppState {
                diesel_db: create_pool(database_url, 4).expect("database pool should build"),
                valkey,
                settings: Arc::new(settings),
                keyset: KeysetStore::new(Keyset {
                    active_kid: "test-kid".to_owned(),
                    active_alg: jsonwebtoken::Algorithm::EdDSA,
                    active_signing_key: ActiveSigningKey::LocalPkcs8Der(Vec::new()),
                    verification_keys: Vec::new(),
                }),
            }),
            schema,
        })
    }

    async fn create_isolated_schema(&self, tables: &[&str]) {
        let Some(schema) = self.schema.as_deref() else {
            return;
        };
        self.exec_sql(&format!(r#"CREATE SCHEMA IF NOT EXISTS "{}""#, schema))
            .await;
        for table in tables {
            self.exec_sql(&format!(
                r#"CREATE TABLE "{}"."{}" (LIKE public."{}" INCLUDING ALL)"#,
                schema, table, table
            ))
            .await;
        }
    }

    async fn exec_sql(&self, sql: &str) {
        let mut conn = get_conn(&self.state.diesel_db)
            .await
            .expect("database connection");
        sql_query(sql)
            .execute(&mut conn)
            .await
            .expect("schema mutation should succeed");
    }

    async fn rename_column(&self, table: &str, from: &str, to: &str) {
        let schema = self
            .schema
            .as_deref()
            .expect("isolated fixture should provide schema");
        self.exec_sql(&format!(
            r#"ALTER TABLE "{}"."{}" RENAME COLUMN "{}" TO "{}""#,
            schema, table, from, to
        ))
        .await;
    }

    async fn cleanup(&self) {
        let Some(schema) = self.schema.as_deref() else {
            return;
        };
        self.exec_sql(&format!(r#"DROP SCHEMA IF EXISTS "{}" CASCADE"#, schema))
            .await;
    }

    async fn create_user(&self, suffix: &str, role: &str, admin_level: i32) -> UserRow {
        let email = format!("admin-grants-{suffix}@example.com");
        let username = format!("admin-grants-{suffix}");
        let mut conn = get_conn(&self.state.diesel_db)
            .await
            .expect("database connection");
        sql_query(
            r#"
            INSERT INTO users (
                tenant_id, realm_id, organization_id, username, email,
                password_hash, is_active, mfa_enabled, email_verified, role, admin_level
            )
            VALUES ($1, $2, $3, $4, $5, 'unused-admin-grants-hash', true, false, true, $6, $7)
            RETURNING *
            "#,
        )
        .bind::<SqlUuid, _>(DEFAULT_TENANT_ID)
        .bind::<SqlUuid, _>(DEFAULT_REALM_ID)
        .bind::<SqlUuid, _>(DEFAULT_ORGANIZATION_ID)
        .bind::<Text, _>(username)
        .bind::<Text, _>(email)
        .bind::<Text, _>(role.to_owned())
        .bind::<Int4, _>(admin_level)
        .get_result::<UserRow>(&mut conn)
        .await
        .expect("test user should insert")
    }

    async fn store_session(&self, user: &UserRow, sid: &str) {
        let payload = SessionPayload {
            user_id: user.id,
            auth_time: Utc::now().timestamp(),
            amr: vec!["pwd".to_owned()],
            pending_mfa: false,
            oidc_sid: Some(format!("oidc-{sid}")),
        };
        valkey_set_ex(
            &self.state.valkey,
            format!("oauth:session:{sid}"),
            serde_json::to_string(&payload).expect("session should serialize"),
            self.state.settings.session_ttl_seconds,
        )
        .await
        .expect("session should store");
    }

    fn admin_get_request(&self, sid: &str, uri: &str) -> HttpRequest {
        actix_web::test::TestRequest::get()
            .uri(uri)
            .cookie(Cookie::new(
                self.state.settings.session_cookie_name.clone(),
                sid.to_owned(),
            ))
            .to_http_request()
    }

    fn admin_post_request(&self, sid: &str, csrf: &str, uri: &str) -> HttpRequest {
        actix_web::test::TestRequest::post()
            .uri(uri)
            .cookie(Cookie::new(
                self.state.settings.session_cookie_name.clone(),
                sid.to_owned(),
            ))
            .cookie(Cookie::new(
                self.state.settings.csrf_cookie_name.clone(),
                csrf.to_owned(),
            ))
            .insert_header(("x-csrf-token", csrf))
            .to_http_request()
    }

    async fn insert_client(&self, client_name: &str) -> ClientRow {
        let mut conn = get_conn(&self.state.diesel_db)
            .await
            .expect("database connection");
        let prepared = match prepare_client_insert_for_test(
            create_client_request(client_name),
            None,
            "http://localhost:8000",
        )
        .await
        {
            Ok(prepared) => prepared,
            Err(_) => panic!("client creation payload should be valid"),
        };
        insert_prepared_client(&mut conn, &prepared)
            .await
            .expect("client should insert")
    }

    async fn insert_grant(&self, user: &UserRow, client: &ClientRow) {
        let mut conn = get_conn(&self.state.diesel_db)
            .await
            .expect("database connection");
        sql_query(
            r#"
            INSERT INTO user_client_grants (
                tenant_id, user_id, client_id, first_authorized_at, last_authorized_at,
                last_scopes, last_authorization_details, authorization_count
            )
            VALUES ($1, $2, $3, now(), now(), '["openid","payments"]'::jsonb, '[]'::jsonb, 2)
            "#,
        )
        .bind::<SqlUuid, _>(user.tenant_id)
        .bind::<SqlUuid, _>(user.id)
        .bind::<SqlUuid, _>(client.id)
        .execute(&mut conn)
        .await
        .expect("user grant should insert");
    }

    async fn insert_refresh_token(&self, user: &UserRow, client: &ClientRow) {
        let family_id = Uuid::now_v7();
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
        .bind::<Text, _>(format!("refresh-{}", Uuid::now_v7()))
        .bind::<SqlUuid, _>(family_id)
        .bind::<SqlUuid, _>(client.id)
        .bind::<Nullable<SqlUuid>, _>(Some(user.id))
        .execute(&mut conn)
        .await
        .expect("refresh token row should insert");
    }

    async fn grant_count(&self, user: &UserRow, client: &ClientRow) -> i64 {
        let mut conn = get_conn(&self.state.diesel_db)
            .await
            .expect("database connection");
        sql_query(
            "SELECT COUNT(*) AS count FROM user_client_grants WHERE user_id = $1 AND client_id = $2",
        )
        .bind::<SqlUuid, _>(user.id)
        .bind::<SqlUuid, _>(client.id)
        .get_result::<CountRow>(&mut conn)
        .await
        .expect("grant count should load")
        .count
    }

    async fn revoked_refresh_token_count(&self, user: &UserRow, client: &ClientRow) -> i64 {
        let mut conn = get_conn(&self.state.diesel_db)
            .await
            .expect("database connection");
        sql_query(
            "SELECT COUNT(*) AS count FROM oauth_tokens WHERE user_id = $1 AND client_id = $2 AND revoked_at IS NOT NULL",
        )
        .bind::<SqlUuid, _>(user.id)
        .bind::<SqlUuid, _>(client.id)
        .get_result::<CountRow>(&mut conn)
        .await
        .expect("revoked token count should load")
        .count
    }
}

#[test]
fn grant_json_projects_authorization_record_without_internal_ids() {
    let row = grant_row();
    let value = grant_json(row);

    assert_eq!(value["email"], "user@example.com");
    assert_eq!(value["client_id"], "client-1");
    assert_eq!(value["client_name"], "Client One");
    assert_eq!(value["authorization_count"], 3);
    assert_eq!(value["last_scopes"], json!(["openid", "payments"]));
    assert_eq!(
        value["last_authorization_details"],
        json!([{"type": "payment_initiation"}])
    );
    assert!(value.get("client_pk").is_none());
    assert!(value.get("tenant_id").is_none());
    assert!(value.get("refresh_token").is_none());
}

#[actix_web::test]
async fn grants_list_response_preserves_pagination_and_scope_projection() {
    let response = grants_list_response(2, 50, 101, vec![grant_row()]);

    assert_eq!(response.status(), StatusCode::OK);
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("grant list body should collect");
    let body: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(body["total"], json!(101));
    assert_eq!(body["page"], json!(2));
    assert_eq!(body["page_size"], json!(50));
    let items = body["items"].as_array().expect("items should be an array");
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["last_scopes"], json!(["openid", "payments"]));
    assert!(items[0].get("oauth_token_id").is_none());
}

#[actix_web::test]
async fn grant_revocation_response_reports_only_aggregate_state_change() {
    let response = grant_revocation_response(2, 1);

    assert_eq!(response.status(), StatusCode::OK);
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("grant revocation body should collect");
    let body: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(body["revoked_refresh_tokens"], json!(2));
    assert_eq!(body["removed_grants"], json!(1));
    assert!(body.get("refresh_token").is_none());
    assert!(body.get("access_token").is_none());
}

#[actix_web::test]
async fn admin_grants_requires_admin_before_database_lookup() {
    let state = Data::new(test_state());
    let req = actix_web::test::TestRequest::get()
        .uri("/admin/grants")
        .to_http_request();

    let response = admin_grants(state, req, Query(HashMap::new())).await;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        oauth_error_name(&response).as_deref(),
        Some("access_denied")
    );
}

#[actix_web::test]
async fn admin_revoke_grant_rejects_missing_csrf_before_auth_or_lookup() {
    let state = Data::new(test_state());
    let req = actix_web::test::TestRequest::post()
        .uri("/admin/grants/revoke")
        .cookie(Cookie::new(
            state.settings.session_cookie_name.clone(),
            "session-id",
        ))
        .to_http_request();

    let response = admin_revoke_grant(
        state,
        req,
        Json(GrantRevokeRequest {
            user_id: Uuid::now_v7().to_string(),
            client_id: "client-1".to_owned(),
        }),
    )
    .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        oauth_error_name(&response).as_deref(),
        Some("invalid_request")
    );
}

#[actix_web::test]
async fn admin_revoke_grant_requires_admin_even_with_valid_csrf() {
    let Some(fixture) = LiveAdminGrantFixture::new().await else {
        return;
    };
    let suffix = Uuid::now_v7().simple().to_string();
    let non_admin = fixture
        .create_user(&format!("{suffix}-user"), "user", 0)
        .await;
    let target = fixture
        .create_user(&format!("{suffix}-target"), "user", 0)
        .await;
    let client = fixture
        .insert_client(&format!("Grant Non Admin {suffix}"))
        .await;
    let sid = format!("sid-{suffix}");
    let csrf = format!("csrf-{suffix}");
    fixture.store_session(&non_admin, &sid).await;

    let response = admin_revoke_grant(
        fixture.state.clone(),
        fixture.admin_post_request(&sid, &csrf, "/admin/grants/revoke"),
        Json(GrantRevokeRequest {
            user_id: target.id.to_string(),
            client_id: client.client_id,
        }),
    )
    .await;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        oauth_error_name(&response).as_deref(),
        Some("access_denied")
    );
}

#[actix_web::test]
async fn admin_grants_list_returns_admin_view_without_token_material() {
    let Some(fixture) = LiveAdminGrantFixture::new().await else {
        return;
    };
    let suffix = Uuid::now_v7().simple().to_string();
    let admin = fixture
        .create_user(&format!("{suffix}-admin"), "admin", 10)
        .await;
    let user = fixture
        .create_user(&format!("{suffix}-user"), "user", 0)
        .await;
    let client = fixture
        .insert_client(&format!("Grant Client {suffix}"))
        .await;
    fixture.insert_grant(&user, &client).await;
    let sid = format!("sid-{suffix}");
    fixture.store_session(&admin, &sid).await;

    let response = admin_grants(
        fixture.state.clone(),
        fixture.admin_get_request(&sid, "/admin/grants?page=1&page_size=20"),
        Query(HashMap::from([
            ("page".to_owned(), "1".to_owned()),
            ("page_size".to_owned(), "20".to_owned()),
        ])),
    )
    .await;

    let status = response.status();
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("response body should be readable");
    let body: Value = serde_json::from_slice(&body).expect("response should be JSON");

    assert_eq!(status, StatusCode::OK);
    assert!(body["total"].as_i64().is_some_and(|total| total >= 1));
    let items = body["items"].as_array().expect("items should be an array");
    let item = items
        .iter()
        .find(|item| {
            item["user_id"] == json!(user.id) && item["client_id"] == json!(client.client_id)
        })
        .expect("admin grants response should include the grant inserted by this test");
    assert_eq!(item["authorization_count"], 2);
    assert!(item.get("refresh_token").is_none());
    assert!(item.get("access_token").is_none());
}

#[actix_web::test]
async fn admin_revoke_grant_validates_input_and_removes_live_grants() {
    let Some(fixture) = LiveAdminGrantFixture::new().await else {
        return;
    };
    let suffix = Uuid::now_v7().simple().to_string();
    let admin = fixture
        .create_user(&format!("{suffix}-admin"), "admin", 10)
        .await;
    let user = fixture
        .create_user(&format!("{suffix}-user"), "user", 0)
        .await;
    let client = fixture
        .insert_client(&format!("Grant Revoke {suffix}"))
        .await;
    fixture.insert_grant(&user, &client).await;
    fixture.insert_refresh_token(&user, &client).await;
    let sid = format!("sid-{suffix}");
    let csrf = format!("csrf-{suffix}");
    fixture.store_session(&admin, &sid).await;

    let invalid_user_response = admin_revoke_grant(
        fixture.state.clone(),
        fixture.admin_post_request(&sid, &csrf, "/admin/grants/revoke"),
        Json(GrantRevokeRequest {
            user_id: "not-a-uuid".to_owned(),
            client_id: client.client_id.clone(),
        }),
    )
    .await;
    assert_eq!(invalid_user_response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        oauth_error_name(&invalid_user_response).as_deref(),
        Some("invalid_request")
    );

    let missing_client_response = admin_revoke_grant(
        fixture.state.clone(),
        fixture.admin_post_request(&sid, &csrf, "/admin/grants/revoke"),
        Json(GrantRevokeRequest {
            user_id: user.id.to_string(),
            client_id: "missing-client".to_owned(),
        }),
    )
    .await;
    assert_eq!(missing_client_response.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        oauth_error_name(&missing_client_response).as_deref(),
        Some("invalid_request")
    );

    let response = admin_revoke_grant(
        fixture.state.clone(),
        fixture.admin_post_request(&sid, &csrf, "/admin/grants/revoke"),
        Json(GrantRevokeRequest {
            user_id: user.id.to_string(),
            client_id: client.client_id.clone(),
        }),
    )
    .await;

    let status = response.status();
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("response body should be readable");
    let body: Value = serde_json::from_slice(&body).expect("response should be JSON");

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["revoked_refresh_tokens"], 1);
    assert_eq!(body["removed_grants"], 1);
    assert_eq!(fixture.grant_count(&user, &client).await, 0);
    assert_eq!(fixture.revoked_refresh_token_count(&user, &client).await, 1);
}

#[actix_web::test]
async fn admin_grants_list_surfaces_backend_failure_when_projection_breaks() {
    let schema = format!("admin_grants_projection_{}", Uuid::now_v7().simple());
    let Some(fixture) = LiveAdminGrantFixture::new_isolated(&schema).await else {
        return;
    };
    let admin = fixture.create_user("projection-admin", "admin", 10).await;
    let end_user = fixture.create_user("projection-user", "user", 0).await;
    let sid = "sid-grants-projection";
    fixture.store_session(&admin, sid).await;
    let client = fixture.insert_client("Projection Client").await;
    fixture.insert_grant(&end_user, &client).await;
    fixture
        .rename_column(
            "user_client_grants",
            "last_authorization_details",
            "last_authorization_details_unavailable",
        )
        .await;

    let response = admin_grants(
        fixture.state.clone(),
        fixture.admin_get_request(sid, "/admin/grants"),
        Query(HashMap::new()),
    )
    .await;
    fixture.cleanup().await;
    let status = response.status();
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("response body should be readable");
    let body: Value = serde_json::from_slice(&body).expect("response should be JSON");

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"], "server_error");
}

#[actix_web::test]
async fn admin_revoke_grant_surfaces_client_lookup_failure_after_admin_authentication() {
    let schema = format!("admin_grants_lookup_{}", Uuid::now_v7().simple());
    let Some(fixture) = LiveAdminGrantFixture::new_isolated(&schema).await else {
        return;
    };
    let admin = fixture.create_user("lookup-admin", "admin", 10).await;
    let end_user = fixture.create_user("lookup-user", "user", 0).await;
    let sid = format!("sid-grants-lookup-{}", Uuid::now_v7().simple());
    let csrf = format!("csrf-grants-lookup-{}", Uuid::now_v7().simple());
    fixture.store_session(&admin, &sid).await;
    let client = fixture.insert_client("Lookup Client").await;
    fixture
        .rename_column("oauth_clients", "client_id", "client_id_unavailable")
        .await;

    let response = admin_revoke_grant(
        fixture.state.clone(),
        fixture.admin_post_request(&sid, &csrf, "/admin/grants/revoke"),
        Json(GrantRevokeRequest {
            user_id: end_user.id.to_string(),
            client_id: client.client_id,
        }),
    )
    .await;
    fixture.cleanup().await;
    let status = response.status();
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("response body should be readable");
    let body: Value = serde_json::from_slice(&body).expect("response should be JSON");

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"], "server_error");
}

#[actix_web::test]
async fn admin_revoke_grant_surfaces_transaction_failure_without_partial_revocation() {
    let schema = format!("admin_grants_write_{}", Uuid::now_v7().simple());
    let Some(fixture) = LiveAdminGrantFixture::new_isolated(&schema).await else {
        return;
    };
    let admin = fixture.create_user("write-admin", "admin", 10).await;
    let end_user = fixture.create_user("write-user", "user", 0).await;
    let sid = format!("sid-grants-write-{}", Uuid::now_v7().simple());
    let csrf = format!("csrf-grants-write-{}", Uuid::now_v7().simple());
    fixture.store_session(&admin, &sid).await;
    let client = fixture.insert_client("Write Client").await;
    fixture.insert_grant(&end_user, &client).await;
    fixture.insert_refresh_token(&end_user, &client).await;
    fixture
        .rename_column("oauth_tokens", "revoked_at", "revoked_at_unavailable")
        .await;

    let response = admin_revoke_grant(
        fixture.state.clone(),
        fixture.admin_post_request(&sid, &csrf, "/admin/grants/revoke"),
        Json(GrantRevokeRequest {
            user_id: end_user.id.to_string(),
            client_id: client.client_id.clone(),
        }),
    )
    .await;
    fixture
        .rename_column("oauth_tokens", "revoked_at_unavailable", "revoked_at")
        .await;
    let grant_count = fixture.grant_count(&end_user, &client).await;
    let token_count = fixture
        .revoked_refresh_token_count(&end_user, &client)
        .await;
    fixture.cleanup().await;
    let status = response.status();
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("response body should be readable");
    let body: Value = serde_json::from_slice(&body).expect("response should be JSON");

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"], "server_error");
    assert_eq!(
        grant_count, 1,
        "grant row should remain when transaction fails"
    );
    assert_eq!(
        token_count, 0,
        "refresh token should remain unrecalled on failure"
    );
}
