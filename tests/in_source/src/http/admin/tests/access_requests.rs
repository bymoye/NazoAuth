use super::*;
use actix_web::cookie::Cookie;
use diesel::QueryableByName;
use diesel::prelude::SelectableHelper;
use diesel::sql_query;
use diesel::sql_types::{Int2, Int4, Text, Uuid as SqlUuid};
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

#[derive(QueryableByName)]
struct IdRow {
    #[diesel(sql_type = SqlUuid)]
    id: Uuid,
}

#[derive(QueryableByName)]
struct AccessRequestStateRow {
    #[diesel(sql_type = Int2)]
    status: i16,
    #[diesel(sql_type = diesel::sql_types::Nullable<SqlUuid>)]
    approved_client_id: Option<Uuid>,
    #[diesel(sql_type = diesel::sql_types::Nullable<Text>)]
    admin_note: Option<String>,
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
            "postgres://nazo_access_request_test_invalid:nazo_access_request_test_invalid@127.0.0.1:1/nazo"
                .to_owned(),
            1,
        )
        .expect("pool construction should not connect"),
        valkey: unavailable_valkey_client(),
        settings: Arc::new(
            Settings::from_config(&ConfigSource::default())
                .expect("default settings should load"),
        ),
        keyset: KeysetStore::new(Keyset {
            active_kid: "test-kid".to_owned(),
            active_alg: jsonwebtoken::Algorithm::EdDSA,
            active_signing_key: ActiveSigningKey::LocalPkcs8Der(Vec::new()),
            verification_keys: Vec::new(),
        }),
    }
}

fn create_client_request() -> CreateClientRequest {
    CreateClientRequest {
        client_name: "Access Request Client".to_owned(),
        client_type: "confidential".to_owned(),
        redirect_uris: vec!["https://client.example/callback".to_owned()],
        post_logout_redirect_uris: Vec::new(),
        scopes: vec!["openid".to_owned()],
        allowed_audiences: vec!["resource://default".to_owned()],
        grant_types: vec!["authorization_code".to_owned()],
        token_endpoint_auth_method: "client_secret_basic".to_owned(),
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

fn query_with_status(value: &str) -> HashMap<String, String> {
    HashMap::from([("status".to_owned(), value.to_owned())])
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

struct LiveAdminAccessRequestFixture {
    state: Data<AppState>,
    schema: Option<String>,
}

impl LiveAdminAccessRequestFixture {
    async fn new() -> Option<Self> {
        let database_url = std::env::var("DATABASE_URL").ok()?;
        Self::from_database_url(database_url, None).await
    }

    async fn new_isolated(schema: &str) -> Option<Self> {
        let database_url = database_url_with_search_path(schema)?;
        let fixture = Self::from_database_url(database_url, Some(schema.to_owned())).await?;
        fixture
            .create_isolated_schema(&["users", "client_access_requests", "oauth_clients"])
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
            ("SESSION_COOKIE_NAME", "nazo_admin_session_test"),
            ("CSRF_COOKIE_NAME", "nazo_admin_csrf_test"),
            ("AUTH_RATE_LIMIT_MAX_REQUESTS", "100000"),
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
        let email = format!("admin-access-{suffix}@example.com");
        let username = format!("admin-access-{suffix}");
        let mut conn = get_conn(&self.state.diesel_db)
            .await
            .expect("database connection");
        sql_query(
            r#"
            INSERT INTO users (
                tenant_id, realm_id, organization_id, username, email,
                password_hash, is_active, mfa_enabled, email_verified, role, admin_level
            )
            VALUES ($1, $2, $3, $4, $5, 'unused-admin-access-test-hash', true, false, true, $6, $7)
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

    async fn insert_access_request(
        &self,
        user: &UserRow,
        site_name: &str,
        status: AccessRequestStatus,
    ) -> Uuid {
        let mut conn = get_conn(&self.state.diesel_db)
            .await
            .expect("database connection");
        sql_query(
            r#"
            INSERT INTO client_access_requests (
                tenant_id, user_id, site_name, site_url, request_description, status,
                admin_note, resolved_by_user_id, approved_client_id, resolved_at, updated_at
            )
            VALUES (
                $1, $2, $3, $4, $5, $6,
                NULL, NULL, NULL, NULL, now()
            )
            RETURNING id
            "#,
        )
        .bind::<SqlUuid, _>(user.tenant_id)
        .bind::<SqlUuid, _>(user.id)
        .bind::<Text, _>(site_name.to_owned())
        .bind::<Text, _>(format!("https://{}.example.com", site_name.to_lowercase()))
        .bind::<Text, _>(format!("Need {site_name} access"))
        .bind::<Int2, _>(status.code())
        .get_result::<IdRow>(&mut conn)
        .await
        .expect("access request should insert")
        .id
    }

    async fn client_row(&self, approved_client_id: Uuid) -> ClientRow {
        let mut conn = get_conn(&self.state.diesel_db)
            .await
            .expect("database connection");
        oauth_clients::table
            .find(approved_client_id)
            .select(ClientRow::as_select())
            .first::<ClientRow>(&mut conn)
            .await
            .expect("approved client should exist")
    }

    async fn access_request_state(&self, request_id: Uuid) -> AccessRequestStateRow {
        let mut conn = get_conn(&self.state.diesel_db)
            .await
            .expect("database connection");
        sql_query(
            r#"
            SELECT status, approved_client_id, admin_note
            FROM client_access_requests
            WHERE id = $1
            "#,
        )
        .bind::<SqlUuid, _>(request_id)
        .get_result::<AccessRequestStateRow>(&mut conn)
        .await
        .expect("access request state should load")
    }
}

async fn json_body(response: HttpResponse) -> (StatusCode, Value) {
    let status = response.status();
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("response body should be readable");
    let value = serde_json::from_slice(&body).expect("response should be JSON");
    (status, value)
}

#[test]
fn parse_access_request_status_accepts_only_protocol_state_codes() {
    assert!(
        parse_access_request_status(&HashMap::new())
            .expect("missing status should list all states")
            .is_none()
    );
    assert!(
        parse_access_request_status(&query_with_status("   "))
            .expect("blank status should list all states")
            .is_none()
    );

    for (raw, expected) in [
        ("0", AccessRequestStatus::Pending.code()),
        (" 1 ", AccessRequestStatus::Approved.code()),
        ("2", AccessRequestStatus::Rejected.code()),
    ] {
        let parsed = parse_access_request_status(&query_with_status(raw))
            .expect("valid status should parse")
            .expect("status should be present");
        assert_eq!(parsed.code(), expected);
    }
}

#[test]
fn parse_access_request_status_rejects_malformed_and_unknown_states_fail_closed() {
    for raw in ["-1", "3", "approved", "1.0"] {
        let response = parse_access_request_status(&query_with_status(raw))
            .err()
            .expect("invalid status must not reach database filtering");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            oauth_error_name(&response).as_deref(),
            Some("invalid_request")
        );
    }
}

#[actix_web::test]
async fn access_requests_response_preserves_pagination_and_rows() {
    let request_id = Uuid::now_v7();
    let response = access_requests_response(
        4,
        25,
        77,
        vec![json!({
            "id": request_id,
            "site_name": "Client App",
            "status": AccessRequestStatus::Pending.code()
        })],
    );

    assert_eq!(response.status(), StatusCode::OK);
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("access request list body should collect");
    let body: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(body["total"], json!(77));
    assert_eq!(body["page"], json!(4));
    assert_eq!(body["page_size"], json!(25));
    assert_eq!(body["items"][0]["id"], json!(request_id));
    assert!(body.get("client_secret").is_none());
}

#[actix_web::test]
async fn access_request_list_requires_admin_before_query_validation_or_database_lookup() {
    let state = Data::new(test_state());
    let req = actix_web::test::TestRequest::get()
        .uri("/admin/access-requests?status=not-a-status")
        .to_http_request();

    let response = admin_access_requests(
        state,
        req,
        Query(HashMap::from([(
            "status".to_owned(),
            "not-a-status".to_owned(),
        )])),
    )
    .await;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        oauth_error_name(&response).as_deref(),
        Some("access_denied")
    );
}

#[actix_web::test]
async fn access_request_list_without_status_requires_admin_before_database_lookup() {
    let state = Data::new(test_state());
    let req = actix_web::test::TestRequest::get()
        .uri("/admin/access-requests")
        .to_http_request();

    let response = admin_access_requests(state, req, Query(HashMap::new())).await;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        oauth_error_name(&response).as_deref(),
        Some("access_denied")
    );
}

#[actix_web::test]
async fn admin_access_request_list_validates_status_after_admin_auth_and_returns_filtered_rows() {
    let Some(fixture) = LiveAdminAccessRequestFixture::new().await else {
        return;
    };
    let suffix = Uuid::now_v7().simple().to_string();
    let admin = fixture
        .create_user(&format!("{suffix}-admin"), "admin", 10)
        .await;
    let applicant = fixture
        .create_user(&format!("{suffix}-user"), "user", 0)
        .await;
    let sid = format!("sid-{suffix}");
    fixture.store_session(&admin, &sid).await;
    let pending_site = format!("Payments-{suffix}");
    fixture
        .insert_access_request(&applicant, &pending_site, AccessRequestStatus::Pending)
        .await;
    fixture
        .insert_access_request(&applicant, "Reports", AccessRequestStatus::Approved)
        .await;

    let list_uri = format!("/admin/access-requests?status=0&q={pending_site}");
    let list_req = fixture.admin_get_request(&sid, &list_uri);
    let list_response = admin_access_requests(
        fixture.state.clone(),
        list_req,
        Query(HashMap::from([
            ("status".to_owned(), "0".to_owned()),
            ("q".to_owned(), pending_site.clone()),
        ])),
    )
    .await;
    let (status, body) = json_body(list_response).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["total"], 1);
    assert_eq!(body["items"][0]["site_name"], pending_site);
    assert_eq!(body["items"][0]["user_email"], applicant.email);
    assert!(body["items"][0].get("client_secret").is_none());

    let invalid_req = fixture.admin_get_request(&sid, "/admin/access-requests?status=9");
    let invalid_response = admin_access_requests(
        fixture.state.clone(),
        invalid_req,
        Query(HashMap::from([("status".to_owned(), "9".to_owned())])),
    )
    .await;
    let (status, body) = json_body(invalid_response).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");
}

#[test]
fn duplicate_access_request_approval_uses_conflict_without_secret_material() {
    let response = access_request_already_approved_response();

    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(
        oauth_error_name(&response).as_deref(),
        Some("invalid_request")
    );
}

#[test]
fn duplicate_access_request_rejection_uses_conflict_without_secret_material() {
    let response = access_request_already_rejected_response();

    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(
        oauth_error_name(&response).as_deref(),
        Some("invalid_request")
    );
}

#[actix_web::test]
async fn approve_access_request_rejects_missing_csrf_before_admin_or_database_lookup() {
    let state = Data::new(test_state());
    let req = actix_web::test::TestRequest::post()
        .uri("/admin/access-requests/request-id/approve")
        .cookie(actix_web::cookie::Cookie::new(
            state.settings.session_cookie_name.clone(),
            "session-id",
        ))
        .to_http_request();

    let response = admin_approve_access_request(
        state,
        req,
        actix_web::web::Path::from(Uuid::now_v7()),
        Json(create_client_request()),
    )
    .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        oauth_error_name(&response).as_deref(),
        Some("invalid_request")
    );
}

#[actix_web::test]
async fn approve_access_request_requires_admin_before_access_request_lookup() {
    let state = Data::new(test_state());
    let req = actix_web::test::TestRequest::post()
        .uri("/admin/access-requests/request-id/approve")
        .to_http_request();

    let response = admin_approve_access_request(
        state,
        req,
        actix_web::web::Path::from(Uuid::now_v7()),
        Json(create_client_request()),
    )
    .await;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        oauth_error_name(&response).as_deref(),
        Some("access_denied")
    );
}

#[actix_web::test]
async fn approve_access_request_validates_client_request_before_mutation() {
    let Some(fixture) = LiveAdminAccessRequestFixture::new().await else {
        return;
    };
    let suffix = Uuid::now_v7().simple().to_string();
    let admin = fixture
        .create_user(&format!("{suffix}-admin"), "admin", 10)
        .await;
    let applicant = fixture
        .create_user(&format!("{suffix}-user"), "user", 0)
        .await;
    let sid = format!("sid-{suffix}");
    let csrf = format!("csrf-{suffix}");
    fixture.store_session(&admin, &sid).await;
    let request_id = fixture
        .insert_access_request(&applicant, "InvalidClient", AccessRequestStatus::Pending)
        .await;
    let mut payload = create_client_request();
    payload.client_type = "public".to_owned();
    payload.token_endpoint_auth_method = "client_secret_post".to_owned();
    payload.jwks = None;
    let req = fixture.admin_post_request(&sid, &csrf, "/admin/access-requests/request/approve");

    let response = admin_approve_access_request(
        fixture.state.clone(),
        req,
        actix_web::web::Path::from(request_id),
        Json(payload),
    )
    .await;
    let (status, body) = json_body(response).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");
    let row = access_request_by_id(&fixture.state.diesel_db, request_id)
        .await
        .expect("access request should load")
        .expect("access request should remain present");
    assert_eq!(row["status"], AccessRequestStatus::Pending.code());
    assert!(row["approved_client_id"].is_null());
}

#[actix_web::test]
async fn approve_access_request_creates_client_and_marks_request_approved_once() {
    let Some(fixture) = LiveAdminAccessRequestFixture::new().await else {
        return;
    };
    let suffix = Uuid::now_v7().simple().to_string();
    let admin = fixture
        .create_user(&format!("{suffix}-admin"), "admin", 10)
        .await;
    let applicant = fixture
        .create_user(&format!("{suffix}-user"), "user", 0)
        .await;
    let sid = format!("sid-{suffix}");
    let csrf = format!("csrf-{suffix}");
    fixture.store_session(&admin, &sid).await;
    let request_id = fixture
        .insert_access_request(&applicant, "Payments", AccessRequestStatus::Pending)
        .await;
    let mut payload = create_client_request();
    payload.token_endpoint_auth_method = "client_secret_post".to_owned();
    payload.jwks = None;
    let req = fixture.admin_post_request(&sid, &csrf, "/admin/access-requests/request/approve");

    let response = admin_approve_access_request(
        fixture.state.clone(),
        req,
        actix_web::web::Path::from(request_id),
        Json(payload),
    )
    .await;
    let (status, body) = json_body(response).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], AccessRequestStatus::Approved.code());
    assert_eq!(
        body["user_id"].as_str(),
        Some(applicant.id.to_string().as_str())
    );
    let approved_client_id = serde_json::from_value::<Uuid>(body["approved_client_id"].clone())
        .expect("approval response should include approved client id");
    let client = fixture.client_row(approved_client_id).await;
    assert_eq!(client.token_endpoint_auth_method, "client_secret_post");
    assert_eq!(client.client_type, "confidential");
    assert!(client.client_secret_hash.is_some());

    let duplicate_req =
        fixture.admin_post_request(&sid, &csrf, "/admin/access-requests/request/approve");
    let duplicate = admin_approve_access_request(
        fixture.state.clone(),
        duplicate_req,
        actix_web::web::Path::from(request_id),
        Json(create_client_request()),
    )
    .await;
    let (status, body) = json_body(duplicate).await;

    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["error"], "invalid_request");
}

#[actix_web::test]
async fn approve_access_request_rejects_previously_rejected_request_without_creating_client() {
    let Some(fixture) = LiveAdminAccessRequestFixture::new().await else {
        return;
    };
    let suffix = Uuid::now_v7().simple().to_string();
    let admin = fixture
        .create_user(&format!("{suffix}-admin"), "admin", 10)
        .await;
    let applicant = fixture
        .create_user(&format!("{suffix}-user"), "user", 0)
        .await;
    let sid = format!("sid-{suffix}");
    let csrf = format!("csrf-{suffix}");
    fixture.store_session(&admin, &sid).await;
    let request_id = fixture
        .insert_access_request(
            &applicant,
            "RejectedBeforeApproval",
            AccessRequestStatus::Rejected,
        )
        .await;
    let req = fixture.admin_post_request(&sid, &csrf, "/admin/access-requests/request/approve");

    let response = admin_approve_access_request(
        fixture.state.clone(),
        req,
        actix_web::web::Path::from(request_id),
        Json(create_client_request()),
    )
    .await;
    let (status, body) = json_body(response).await;

    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["error"], "invalid_request");
    let row = access_request_by_id(&fixture.state.diesel_db, request_id)
        .await
        .expect("access request should load")
        .expect("access request should remain present");
    assert_eq!(row["status"], AccessRequestStatus::Rejected.code());
    assert!(row["approved_client_id"].is_null());
}

#[actix_web::test]
async fn reject_access_request_rejects_missing_csrf_before_admin_or_database_lookup() {
    let state = Data::new(test_state());
    let req = actix_web::test::TestRequest::post()
        .uri("/admin/access-requests/request-id/reject")
        .cookie(actix_web::cookie::Cookie::new(
            state.settings.session_cookie_name.clone(),
            "session-id",
        ))
        .to_http_request();

    let response = admin_reject_access_request(
        state,
        req,
        actix_web::web::Path::from(Uuid::now_v7()),
        Json(RejectAccessRequest {
            admin_note: "not enough details".to_owned(),
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
async fn reject_access_request_requires_admin_before_access_request_update() {
    let state = Data::new(test_state());
    let req = actix_web::test::TestRequest::post()
        .uri("/admin/access-requests/request-id/reject")
        .to_http_request();

    let response = admin_reject_access_request(
        state,
        req,
        actix_web::web::Path::from(Uuid::now_v7()),
        Json(RejectAccessRequest {
            admin_note: "not enough details".to_owned(),
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
async fn reject_access_request_marks_request_rejected_once() {
    let Some(fixture) = LiveAdminAccessRequestFixture::new().await else {
        return;
    };
    let suffix = Uuid::now_v7().simple().to_string();
    let admin = fixture
        .create_user(&format!("{suffix}-admin"), "admin", 10)
        .await;
    let applicant = fixture
        .create_user(&format!("{suffix}-user"), "user", 0)
        .await;
    let sid = format!("sid-{suffix}");
    let csrf = format!("csrf-{suffix}");
    fixture.store_session(&admin, &sid).await;
    let request_id = fixture
        .insert_access_request(&applicant, "Analytics", AccessRequestStatus::Pending)
        .await;
    let req = fixture.admin_post_request(&sid, &csrf, "/admin/access-requests/request/reject");

    let response = admin_reject_access_request(
        fixture.state.clone(),
        req,
        actix_web::web::Path::from(request_id),
        Json(RejectAccessRequest {
            admin_note: "insufficient justification".to_owned(),
        }),
    )
    .await;
    let (status, body) = json_body(response).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], AccessRequestStatus::Rejected.code());
    assert_eq!(body["admin_note"], "insufficient justification");

    let duplicate_req =
        fixture.admin_post_request(&sid, &csrf, "/admin/access-requests/request/reject");
    let duplicate = admin_reject_access_request(
        fixture.state.clone(),
        duplicate_req,
        actix_web::web::Path::from(request_id),
        Json(RejectAccessRequest {
            admin_note: "second attempt".to_owned(),
        }),
    )
    .await;
    let (status, body) = json_body(duplicate).await;

    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["error"], "invalid_request");
}

#[actix_web::test]
async fn reject_access_request_rejects_previously_approved_request_without_losing_client_link() {
    let Some(fixture) = LiveAdminAccessRequestFixture::new().await else {
        return;
    };
    let suffix = Uuid::now_v7().simple().to_string();
    let admin = fixture
        .create_user(&format!("{suffix}-admin"), "admin", 10)
        .await;
    let applicant = fixture
        .create_user(&format!("{suffix}-user"), "user", 0)
        .await;
    let sid = format!("sid-{suffix}");
    let csrf = format!("csrf-{suffix}");
    fixture.store_session(&admin, &sid).await;
    let request_id = fixture
        .insert_access_request(
            &applicant,
            "ApproveThenReject",
            AccessRequestStatus::Pending,
        )
        .await;
    let mut payload = create_client_request();
    payload.client_name = format!("Approved Client {suffix}");
    payload.token_endpoint_auth_method = "client_secret_post".to_owned();
    payload.jwks = None;
    let approve_req =
        fixture.admin_post_request(&sid, &csrf, "/admin/access-requests/request/approve");
    let approved = admin_approve_access_request(
        fixture.state.clone(),
        approve_req,
        actix_web::web::Path::from(request_id),
        Json(payload),
    )
    .await;
    let (status, approved_body) = json_body(approved).await;
    assert_eq!(status, StatusCode::OK);
    let approved_client_id =
        serde_json::from_value::<Uuid>(approved_body["approved_client_id"].clone())
            .expect("approval response should include client id");

    let reject_req =
        fixture.admin_post_request(&sid, &csrf, "/admin/access-requests/request/reject");
    let rejected = admin_reject_access_request(
        fixture.state.clone(),
        reject_req,
        actix_web::web::Path::from(request_id),
        Json(RejectAccessRequest {
            admin_note: "attempt after approval".to_owned(),
        }),
    )
    .await;
    let (status, body) = json_body(rejected).await;

    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["error"], "invalid_request");
    let row = access_request_by_id(&fixture.state.diesel_db, request_id)
        .await
        .expect("access request should load")
        .expect("access request should remain present");
    assert_eq!(row["status"], AccessRequestStatus::Approved.code());
    assert_eq!(row["approved_client_id"], json!(approved_client_id));
}

#[actix_web::test]
async fn approve_access_request_surfaces_pending_request_lookup_failure_after_admin_authentication()
{
    let schema = format!("admin_access_lookup_{}", Uuid::now_v7().simple());
    let Some(fixture) = LiveAdminAccessRequestFixture::new_isolated(&schema).await else {
        return;
    };
    let admin = fixture.create_user("lookup-admin", "admin", 10).await;
    let applicant = fixture.create_user("lookup-user", "user", 0).await;
    let sid = "sid-lookup";
    let csrf = "csrf-lookup";
    fixture.store_session(&admin, sid).await;
    let request_id = fixture
        .insert_access_request(&applicant, "LookupFailure", AccessRequestStatus::Pending)
        .await;
    fixture
        .rename_column(
            "client_access_requests",
            "site_name",
            "site_name_unavailable",
        )
        .await;
    let req = fixture.admin_post_request(sid, csrf, "/admin/access-requests/request/approve");

    let response = admin_approve_access_request(
        fixture.state.clone(),
        req,
        actix_web::web::Path::from(request_id),
        Json(create_client_request()),
    )
    .await;
    fixture.cleanup().await;
    let (status, body) = json_body(response).await;

    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "approve_access_request unexpected response body: {body}"
    );
    assert_eq!(body["error"], "server_error");
}

#[actix_web::test]
async fn approve_access_request_rolls_back_when_status_write_fails_after_client_prepare() {
    let schema = format!("admin_access_write_{}", Uuid::now_v7().simple());
    let Some(fixture) = LiveAdminAccessRequestFixture::new_isolated(&schema).await else {
        return;
    };
    let admin = fixture.create_user("write-admin", "admin", 10).await;
    let applicant = fixture.create_user("write-user", "user", 0).await;
    let sid = format!("sid-write-{}", Uuid::now_v7().simple());
    let csrf = format!("csrf-write-{}", Uuid::now_v7().simple());
    fixture.store_session(&admin, &sid).await;
    let request_id = fixture
        .insert_access_request(&applicant, "WriteFailure", AccessRequestStatus::Pending)
        .await;
    fixture
        .rename_column(
            "client_access_requests",
            "updated_at",
            "updated_at_unavailable",
        )
        .await;
    let req = fixture.admin_post_request(&sid, &csrf, "/admin/access-requests/request/approve");
    let mut payload = create_client_request();
    payload.token_endpoint_auth_method = "client_secret_post".to_owned();
    payload.jwks = None;

    let response = admin_approve_access_request(
        fixture.state.clone(),
        req,
        actix_web::web::Path::from(request_id),
        Json(payload),
    )
    .await;
    let state = fixture.access_request_state(request_id).await;
    fixture.cleanup().await;
    let (status, body) = json_body(response).await;

    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "approve_access_request unexpected response body: {body}"
    );
    assert_eq!(body["error"], "server_error");
    assert_eq!(state.status, AccessRequestStatus::Pending.code());
    assert!(state.approved_client_id.is_none());
}

#[actix_web::test]
async fn reject_access_request_surfaces_update_failure_without_changing_status() {
    let schema = format!("admin_access_reject_write_{}", Uuid::now_v7().simple());
    let Some(fixture) = LiveAdminAccessRequestFixture::new_isolated(&schema).await else {
        return;
    };
    let admin = fixture.create_user("reject-write-admin", "admin", 10).await;
    let applicant = fixture.create_user("reject-write-user", "user", 0).await;
    let sid = "sid-reject-write";
    let csrf = "csrf-reject-write";
    fixture.store_session(&admin, sid).await;
    let request_id = fixture
        .insert_access_request(
            &applicant,
            "RejectWriteFailure",
            AccessRequestStatus::Pending,
        )
        .await;
    fixture
        .rename_column(
            "client_access_requests",
            "updated_at",
            "updated_at_unavailable",
        )
        .await;
    let req = fixture.admin_post_request(sid, csrf, "/admin/access-requests/request/reject");

    let response = admin_reject_access_request(
        fixture.state.clone(),
        req,
        actix_web::web::Path::from(request_id),
        Json(RejectAccessRequest {
            admin_note: "write should fail".to_owned(),
        }),
    )
    .await;
    let state = fixture.access_request_state(request_id).await;
    fixture.cleanup().await;
    let (status, body) = json_body(response).await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"], "server_error");
    assert_eq!(state.status, AccessRequestStatus::Pending.code());
    assert!(state.admin_note.is_none());
}

#[actix_web::test]
async fn reject_access_request_surfaces_projection_failure_after_state_transition() {
    let schema = format!("admin_access_projection_{}", Uuid::now_v7().simple());
    let Some(fixture) = LiveAdminAccessRequestFixture::new_isolated(&schema).await else {
        return;
    };
    let admin = fixture.create_user("projection-admin", "admin", 10).await;
    let applicant = fixture.create_user("projection-user", "user", 0).await;
    let sid = "sid-projection";
    let csrf = "csrf-projection";
    fixture.store_session(&admin, sid).await;
    let request_id = fixture
        .insert_access_request(
            &applicant,
            "ProjectionFailure",
            AccessRequestStatus::Pending,
        )
        .await;
    fixture
        .rename_column(
            "client_access_requests",
            "request_description",
            "request_description_unavailable",
        )
        .await;
    let req = fixture.admin_post_request(sid, csrf, "/admin/access-requests/request/reject");

    let response = admin_reject_access_request(
        fixture.state.clone(),
        req,
        actix_web::web::Path::from(request_id),
        Json(RejectAccessRequest {
            admin_note: "projection should fail".to_owned(),
        }),
    )
    .await;
    let state = fixture.access_request_state(request_id).await;
    fixture.cleanup().await;
    let (status, body) = json_body(response).await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"], "server_error");
    assert_eq!(state.status, AccessRequestStatus::Rejected.code());
    assert_eq!(state.admin_note.as_deref(), Some("projection should fail"));
}
