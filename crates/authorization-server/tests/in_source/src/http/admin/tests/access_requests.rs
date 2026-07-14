use super::*;
use crate::test_support::{access_request_profiles, delivery_profiles, profile_sessions};
use actix_web::cookie::Cookie;
use diesel::QueryableByName;
use diesel::sql_query;
use diesel::sql_types::{BigInt, Int2, Int4, Text, Uuid as SqlUuid};
use diesel_async::RunQueryDsl;
use fred::interfaces::{ClientLike, KeysInterface};
use fred::prelude::{
    Builder as ValkeyBuilder, Config as ValkeyConfig, ConnectionConfig, PerformanceConfig,
};
use nazo_http_actix::OAuthJsonErrorFields;
use std::sync::Arc;
use std::time::Duration as StdDuration;

use crate::config::ConfigSource;
use crate::domain::tenancy::DEFAULT_ORGANIZATION_ID;
use crate::domain::tenancy::DEFAULT_REALM_ID;
use crate::domain::tenancy::DEFAULT_TENANT_ID;
use crate::domain::{ClientRow, DatabaseUserFixture, TestAppState};
use crate::http::admin::clients::{
    ServerAdminClientCrypto, ServerSectorIdentifierResolver, admin_client_policy,
};
use crate::http::sessions::SessionHttpConfig;
use crate::http::sessions::SessionPayload;
use crate::schema::oauth_clients;
use crate::settings::Settings;
use crate::test_support::valkey::valkey_set_ex;
use chrono::Utc;
use diesel::prelude::*;
use nazo_identity::AccessRequestStatus;
use nazo_postgres::{create_pool, get_conn};

async fn profile_access_requests_from_state(
    state: Data<TestAppState>,
    req: HttpRequest,
) -> HttpResponse {
    crate::http::profile::access_requests::my_access_requests(
        profile_sessions(&state),
        access_request_profiles(&state),
        req,
    )
    .await
}

async fn profile_delivery_from_state(
    state: Data<TestAppState>,
    req: HttpRequest,
    query: Query<HashMap<String, String>>,
) -> HttpResponse {
    crate::http::profile::delivery::access_delivery(
        profile_sessions(&state),
        delivery_profiles(&state),
        req,
        query,
    )
    .await
}

#[derive(QueryableByName)]
struct IdRow {
    #[diesel(sql_type = SqlUuid)]
    id: Uuid,
}

#[derive(QueryableByName)]
struct CountRow {
    #[diesel(sql_type = BigInt)]
    count: i64,
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

fn test_state() -> TestAppState {
    TestAppState {
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
        keyset: crate::test_support::test_key_manager(),
    }
}

struct TestAdminAccessRequestDependencies {
    admin_sessions: Data<AdminSessionHandles>,
    repository: Data<AccessRequestRepository>,
    delivery_store: Data<DeliveryStore>,
    client_service: Data<ServerAdminClientService>,
    config: Data<AdminAccessRequestConfig>,
    client_ip_config: Data<ClientIpConfig>,
}

fn admin_access_request_dependencies(
    state: &Data<TestAppState>,
) -> TestAdminAccessRequestDependencies {
    let session = &state.settings.session;
    let protocol = &state.settings.protocol;
    let storage = &state.settings.storage;
    let endpoint = &state.settings.endpoint;
    TestAdminAccessRequestDependencies {
        admin_sessions: Data::new(AdminSessionHandles::new(
            nazo_valkey::SessionStore::new(&state.valkey_connection()),
            nazo_postgres::UserRepository::new(state.diesel_db.clone()),
            SessionHttpConfig::new(
                &session.session_cookie_name,
                &session.csrf_cookie_name,
                session.cookie_secure,
            ),
        )),
        repository: Data::new(AccessRequestRepository::new(state.diesel_db.clone())),
        delivery_store: Data::new(DeliveryStore::new(&state.valkey_connection())),
        client_service: Data::new(ServerAdminClientService::new(
            nazo_postgres::OAuthClientRepository::new(state.diesel_db.clone()),
            ServerSectorIdentifierResolver,
            ServerAdminClientCrypto::new(state.keyset.clone()),
            admin_client_policy(&state.settings),
        )),
        config: Data::new(AdminAccessRequestConfig::new(
            &protocol.client_secret_pepper,
            storage.client_delivery_ttl_seconds,
        )),
        client_ip_config: Data::new(ClientIpConfig::new(
            &endpoint.trusted_proxy_cidrs,
            endpoint.client_ip_header_mode,
        )),
    }
}

async fn invoke_admin_access_requests(
    state: Data<TestAppState>,
    req: HttpRequest,
    query: Query<HashMap<String, String>>,
) -> HttpResponse {
    let dependencies = admin_access_request_dependencies(&state);
    admin_access_requests(
        dependencies.admin_sessions,
        dependencies.repository,
        req,
        query,
    )
    .await
}

async fn invoke_admin_approve_access_request(
    state: Data<TestAppState>,
    req: HttpRequest,
    path: actix_web::web::Path<Uuid>,
    payload: Json<CreateClientRequest>,
) -> HttpResponse {
    let dependencies = admin_access_request_dependencies(&state);
    admin_approve_access_request(
        dependencies.admin_sessions,
        (
            dependencies.repository,
            dependencies.delivery_store,
            dependencies.client_service,
            dependencies.config,
            dependencies.client_ip_config,
        ),
        req,
        path,
        payload,
    )
    .await
}

async fn invoke_admin_reject_access_request(
    state: Data<TestAppState>,
    req: HttpRequest,
    path: actix_web::web::Path<Uuid>,
    payload: Json<RejectAccessRequest>,
) -> HttpResponse {
    let dependencies = admin_access_request_dependencies(&state);
    admin_reject_access_request(
        dependencies.admin_sessions,
        dependencies.repository,
        req,
        path,
        payload,
    )
    .await
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

#[test]
fn delivery_tokens_are_deterministic_and_request_scoped() {
    let state = test_state();
    let user_id = Uuid::now_v7();
    let request_id = Uuid::now_v7();
    let first = access_delivery_token(
        &state.settings.protocol.client_secret_pepper,
        user_id,
        request_id,
    );

    assert_eq!(
        first,
        access_delivery_token(
            &state.settings.protocol.client_secret_pepper,
            user_id,
            request_id
        )
    );
    assert_ne!(
        first,
        access_delivery_token(
            &state.settings.protocol.client_secret_pepper,
            user_id,
            Uuid::now_v7()
        )
    );
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
    state: Data<TestAppState>,
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
            state: Data::new(TestAppState {
                diesel_db: create_pool(database_url, 4).expect("database pool should build"),
                valkey,
                settings: Arc::new(settings),
                keyset: crate::test_support::test_key_manager(),
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

    async fn restricted_valkey_client(
        &self,
        username: &str,
        password: &str,
    ) -> fred::prelude::Client {
        self.state
            .valkey
            .custom::<(), _>(
                fred::cmd!("ACL"),
                vec![
                    "SETUSER".to_owned(),
                    username.to_owned(),
                    "reset".to_owned(),
                    "on".to_owned(),
                    format!(">{password}"),
                    "~oauth:session:*".to_owned(),
                    "+@all".to_owned(),
                ],
            )
            .await
            .expect("restricted Valkey ACL user should be configured");
        let valkey_url = std::env::var("VALKEY_URL").expect("VALKEY_URL should be set");
        let restricted_url =
            valkey_url.replacen("redis://", &format!("redis://{username}:{password}@"), 1);
        let mut builder = ValkeyBuilder::from_config(
            ValkeyConfig::from_url(&restricted_url).expect("restricted VALKEY_URL should parse"),
        );
        builder.with_performance_config(|performance: &mut PerformanceConfig| {
            performance.default_command_timeout = StdDuration::from_millis(1000);
        });
        builder.with_connection_config(|connection: &mut ConnectionConfig| {
            connection.connection_timeout = StdDuration::from_millis(1000);
            connection.internal_command_timeout = StdDuration::from_millis(1000);
            connection.max_command_attempts = 1;
        });
        let client = builder
            .build()
            .expect("restricted Valkey client should build");
        client
            .init()
            .await
            .expect("restricted Valkey client should connect");
        client
    }

    async fn valkey_client_without_delete(
        &self,
        username: &str,
        password: &str,
    ) -> fred::prelude::Client {
        self.state
            .valkey
            .custom::<(), _>(
                fred::cmd!("ACL"),
                vec![
                    "SETUSER".to_owned(),
                    username.to_owned(),
                    "reset".to_owned(),
                    "on".to_owned(),
                    format!(">{password}"),
                    "~oauth:*".to_owned(),
                    "+@all".to_owned(),
                    "-del".to_owned(),
                ],
            )
            .await
            .expect("no-delete Valkey ACL user should be configured");
        let valkey_url = std::env::var("VALKEY_URL").expect("VALKEY_URL should be set");
        let restricted_url =
            valkey_url.replacen("redis://", &format!("redis://{username}:{password}@"), 1);
        let client = ValkeyBuilder::from_config(
            ValkeyConfig::from_url(&restricted_url).expect("restricted VALKEY_URL should parse"),
        )
        .build()
        .expect("restricted valkey client should build");
        client
            .init()
            .await
            .expect("restricted client should connect");
        client
    }

    fn state_with_valkey(&self, valkey: fred::prelude::Client) -> Data<TestAppState> {
        Data::new(TestAppState {
            diesel_db: self.state.diesel_db.clone(),
            valkey,
            settings: self.state.settings.clone(),
            keyset: self.state.keyset.clone(),
        })
    }

    async fn delete_acl_user(&self, username: &str) {
        let _: i64 = self
            .state
            .valkey
            .custom(
                fred::cmd!("ACL"),
                vec!["DELUSER".to_owned(), username.to_owned()],
            )
            .await
            .expect("restricted Valkey ACL user should be deleted");
    }

    async fn client_count(&self) -> i64 {
        let mut connection = get_conn(&self.state.diesel_db).await.unwrap();
        sql_query("SELECT COUNT(*)::bigint AS count FROM oauth_clients")
            .get_result::<CountRow>(&mut connection)
            .await
            .unwrap()
            .count
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

    async fn create_user(&self, suffix: &str, role: &str, admin_level: i32) -> DatabaseUserFixture {
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
        .get_result::<DatabaseUserFixture>(&mut conn)
        .await
        .expect("test user should insert")
    }

    async fn store_session(&self, user: &DatabaseUserFixture, sid: &str) {
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
            self.state.settings.session.session_ttl_seconds,
        )
        .await
        .expect("session should store");
    }

    fn admin_get_request(&self, sid: &str, uri: &str) -> HttpRequest {
        actix_web::test::TestRequest::get()
            .uri(uri)
            .cookie(Cookie::new(
                self.state.settings.session.session_cookie_name.clone(),
                sid.to_owned(),
            ))
            .to_http_request()
    }

    fn admin_post_request(&self, sid: &str, csrf: &str, uri: &str) -> HttpRequest {
        actix_web::test::TestRequest::post()
            .uri(uri)
            .cookie(Cookie::new(
                self.state.settings.session.session_cookie_name.clone(),
                sid.to_owned(),
            ))
            .cookie(Cookie::new(
                self.state.settings.session.csrf_cookie_name.clone(),
                csrf.to_owned(),
            ))
            .insert_header(("x-csrf-token", csrf))
            .to_http_request()
    }

    async fn insert_access_request(
        &self,
        user: &DatabaseUserFixture,
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
        nazo_postgres::OAuthClientRepository::new(self.state.diesel_db.clone())
            .by_id(approved_client_id)
            .await
            .expect("client lookup should succeed")
            .expect("approved client should exist")
    }

    async fn client_has_secret_hash(&self, approved_client_id: Uuid) -> bool {
        let mut conn = get_conn(&self.state.diesel_db)
            .await
            .expect("database connection");
        oauth_clients::table
            .find(approved_client_id)
            .select(oauth_clients::client_secret_hash)
            .first::<Option<String>>(&mut conn)
            .await
            .expect("approved client should exist")
            .is_some()
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

#[actix_web::test]
async fn approval_conflicts_distinguish_request_state_from_client_uniqueness() {
    let processed = access_request_approval_error_response(
        &nazo_identity::ports::RepositoryError::AlreadyProcessed,
    )
    .unwrap();
    let duplicate_client =
        access_request_approval_error_response(&nazo_identity::ports::RepositoryError::Conflict)
            .unwrap();

    assert_eq!(processed.status(), StatusCode::CONFLICT);
    assert_eq!(duplicate_client.status(), StatusCode::CONFLICT);
    assert_ne!(
        processed.headers().get("x-nazo-conflict-type"),
        duplicate_client.headers().get("x-nazo-conflict-type")
    );
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
            .expect_err("invalid status must not reach database filtering");

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
    let now = Utc::now();
    let response = access_requests_response(
        4,
        25,
        77,
        vec![nazo_identity::AccessRequest {
            id: request_id,
            tenant_id: nazo_identity::TenantId::new(DEFAULT_TENANT_ID).unwrap(),
            user_id: nazo_identity::UserId::new(Uuid::now_v7()).unwrap(),
            requester_email: Some("applicant@example.test".to_owned()),
            site_name: "Client App".to_owned(),
            site_url: "https://client.example".to_owned(),
            request_description: "Need API access".to_owned(),
            status: AccessRequestStatus::Pending,
            admin_note: None,
            approved_client_id: None,
            created_at: now,
            resolved_at: None,
        }],
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

    let response = invoke_admin_access_requests(
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

    let response = invoke_admin_access_requests(state, req, Query(HashMap::new())).await;

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
    let list_response = invoke_admin_access_requests(
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
    let invalid_response = invoke_admin_access_requests(
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
            state.settings.session.session_cookie_name.clone(),
            "session-id",
        ))
        .to_http_request();

    let response = invoke_admin_approve_access_request(
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

    let response = invoke_admin_approve_access_request(
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

    let response = invoke_admin_approve_access_request(
        fixture.state.clone(),
        req,
        actix_web::web::Path::from(request_id),
        Json(payload),
    )
    .await;
    let (status, body) = json_body(response).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");
    let row = nazo_postgres::AccessRequestRepository::new(fixture.state.diesel_db.clone())
        .by_id(
            nazo_identity::TenantId::new(DEFAULT_TENANT_ID).unwrap(),
            request_id,
        )
        .await
        .expect("access request should load")
        .expect("access request should remain present");
    assert_eq!(row.status, AccessRequestStatus::Pending);
    assert!(row.approved_client_id.is_none());
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

    let response = invoke_admin_approve_access_request(
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
    assert!(fixture.client_has_secret_hash(approved_client_id).await);
    assert!(body.get("delivery_token").is_none());
    assert!(body.get("delivery_url").is_none());

    let applicant_sid = format!("applicant-{suffix}");
    fixture.store_session(&applicant, &applicant_sid).await;
    let list_request = fixture.admin_get_request(&applicant_sid, "/auth/me/access-requests");
    let listed = profile_access_requests_from_state(fixture.state.clone(), list_request).await;
    let (list_status, list_body) = json_body(listed).await;
    assert_eq!(list_status, StatusCode::OK);
    let approved_item = list_body["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["id"] == json!(request_id))
        .expect("applicant should see the approved request");
    let delivery_token = approved_item["delivery_token"]
        .as_str()
        .expect("production owner response should provide the one-time token")
        .to_owned();
    assert!(
        approved_item["delivery_url"]
            .as_str()
            .is_some_and(|url| url.ends_with(&format!("/delivery?token={delivery_token}")))
    );
    let other_applicant = fixture
        .create_user(&format!("{suffix}-other-user"), "user", 0)
        .await;
    let other_sid = format!("other-applicant-{suffix}");
    fixture.store_session(&other_applicant, &other_sid).await;
    let other_list = profile_access_requests_from_state(
        fixture.state.clone(),
        fixture.admin_get_request(&other_sid, "/auth/me/access-requests"),
    )
    .await;
    let (_, other_body) = json_body(other_list).await;
    assert!(
        other_body["items"]
            .as_array()
            .unwrap()
            .iter()
            .all(|item| item.get("delivery_token").is_none())
    );
    let other_claim = profile_delivery_from_state(
        fixture.state.clone(),
        fixture.admin_get_request(
            &other_sid,
            &format!("/profile/access-delivery?token={delivery_token}"),
        ),
        Query(HashMap::from([(
            "token".to_owned(),
            delivery_token.clone(),
        )])),
    )
    .await;
    assert_eq!(other_claim.status(), StatusCode::NOT_FOUND);
    let delivery_key = format!("oauth:client_delivery:{}:{delivery_token}", applicant.id);
    let staged_raw: String = fixture
        .state
        .valkey
        .get(&delivery_key)
        .await
        .expect("committed delivery payload should exist");
    let mut staged: Value = serde_json::from_str(&staged_raw).unwrap();
    staged["delivery_state"] = json!("staged");
    staged
        .as_object_mut()
        .expect("delivery payload is an object")
        .remove("approved_client_id");
    valkey_set_ex(
        &fixture.state.valkey,
        &delivery_key,
        staged.to_string(),
        fixture.state.settings.storage.client_delivery_ttl_seconds,
    )
    .await
    .unwrap();
    let recovery_request =
        fixture.admin_post_request(&sid, &csrf, "/admin/access-requests/request/approve");
    let recovered = invoke_admin_approve_access_request(
        fixture.state.clone(),
        recovery_request,
        actix_web::web::Path::from(request_id),
        Json(create_client_request()),
    )
    .await;
    assert_eq!(recovered.status(), StatusCode::OK);
    let recovered_raw: String = fixture
        .state
        .valkey
        .get(&delivery_key)
        .await
        .expect("recovered delivery payload should exist");
    assert_eq!(
        serde_json::from_str::<Value>(&recovered_raw).unwrap()["delivery_state"],
        "committed"
    );
    let delivery_request = fixture.admin_get_request(
        &applicant_sid,
        &format!("/profile/access-delivery?token={delivery_token}"),
    );
    let delivered = profile_delivery_from_state(
        fixture.state.clone(),
        delivery_request,
        Query(HashMap::from([(
            "token".to_owned(),
            delivery_token.clone(),
        )])),
    )
    .await;
    let (delivery_status, delivery_body) = json_body(delivered).await;
    assert_eq!(delivery_status, StatusCode::OK);
    assert!(delivery_body["client_secret"].as_str().is_some());

    let after_claim = profile_access_requests_from_state(
        fixture.state.clone(),
        fixture.admin_get_request(&applicant_sid, "/auth/me/access-requests"),
    )
    .await;
    let (_, after_claim_body) = json_body(after_claim).await;
    let claimed_item = after_claim_body["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["id"] == json!(request_id))
        .unwrap();
    assert!(claimed_item.get("delivery_token").is_none());
    assert!(claimed_item.get("delivery_url").is_none());

    let replay_request = fixture.admin_get_request(
        &applicant_sid,
        &format!("/profile/access-delivery?token={delivery_token}"),
    );
    let replay = profile_delivery_from_state(
        fixture.state.clone(),
        replay_request,
        Query(HashMap::from([("token".to_owned(), delivery_token)])),
    )
    .await;
    assert_eq!(replay.status(), StatusCode::NOT_FOUND);

    let duplicate_req =
        fixture.admin_post_request(&sid, &csrf, "/admin/access-requests/request/approve");
    let duplicate = invoke_admin_approve_access_request(
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

    let response = invoke_admin_approve_access_request(
        fixture.state.clone(),
        req,
        actix_web::web::Path::from(request_id),
        Json(create_client_request()),
    )
    .await;
    let (status, body) = json_body(response).await;

    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["error"], "invalid_request");
    let row = nazo_postgres::AccessRequestRepository::new(fixture.state.diesel_db.clone())
        .by_id(
            nazo_identity::TenantId::new(DEFAULT_TENANT_ID).unwrap(),
            request_id,
        )
        .await
        .expect("access request should load")
        .expect("access request should remain present");
    assert_eq!(row.status, AccessRequestStatus::Rejected);
    assert!(row.approved_client_id.is_none());
}

#[actix_web::test]
async fn reject_access_request_rejects_missing_csrf_before_admin_or_database_lookup() {
    let state = Data::new(test_state());
    let req = actix_web::test::TestRequest::post()
        .uri("/admin/access-requests/request-id/reject")
        .cookie(actix_web::cookie::Cookie::new(
            state.settings.session.session_cookie_name.clone(),
            "session-id",
        ))
        .to_http_request();

    let response = invoke_admin_reject_access_request(
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

    let response = invoke_admin_reject_access_request(
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

    let response = invoke_admin_reject_access_request(
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
    let duplicate = invoke_admin_reject_access_request(
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
    let approved = invoke_admin_approve_access_request(
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
    let rejected = invoke_admin_reject_access_request(
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
    let row = nazo_postgres::AccessRequestRepository::new(fixture.state.diesel_db.clone())
        .by_id(
            nazo_identity::TenantId::new(DEFAULT_TENANT_ID).unwrap(),
            request_id,
        )
        .await
        .expect("access request should load")
        .expect("access request should remain present");
    assert_eq!(row.status, AccessRequestStatus::Approved);
    assert_eq!(row.approved_client_id, Some(approved_client_id));
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

    let response = invoke_admin_approve_access_request(
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
    let acl_user = format!("access_no_delete_{}", Uuid::now_v7().simple());
    let acl_password = format!("pw{}", Uuid::now_v7().simple());
    let no_delete = fixture
        .valkey_client_without_delete(&acl_user, &acl_password)
        .await;

    let response = invoke_admin_approve_access_request(
        fixture.state_with_valkey(no_delete),
        req,
        actix_web::web::Path::from(request_id),
        Json(payload),
    )
    .await;
    let state = fixture.access_request_state(request_id).await;
    let orphan_keys: Vec<String> = fixture
        .state
        .valkey
        .custom(
            fred::cmd!("KEYS"),
            vec![format!("oauth:client_delivery:{}:*", applicant.id)],
        )
        .await
        .expect("staged delivery keys should be inspectable");
    assert_eq!(orphan_keys.len(), 1);
    let orphan: String = fixture
        .state
        .valkey
        .get(&orphan_keys[0])
        .await
        .expect("staged delivery payload should remain after denied cleanup");
    let orphan: Value = serde_json::from_str(&orphan).expect("staged payload should be JSON");
    assert_eq!(orphan["delivery_state"], "staged");
    let delivery_token = orphan_keys[0]
        .rsplit(':')
        .next()
        .expect("delivery key contains token")
        .to_owned();
    let applicant_sid = format!("applicant-write-{}", Uuid::now_v7().simple());
    fixture.store_session(&applicant, &applicant_sid).await;
    let delivery_request = fixture.admin_get_request(
        &applicant_sid,
        &format!("/profile/access-delivery?token={delivery_token}"),
    );
    let delivery = profile_delivery_from_state(
        fixture.state.clone(),
        delivery_request,
        Query(HashMap::from([("token".to_owned(), delivery_token)])),
    )
    .await;
    assert_eq!(delivery.status(), StatusCode::NOT_FOUND);
    let removed: Option<String> = fixture
        .state
        .valkey
        .get(&orphan_keys[0])
        .await
        .expect("staged delivery cleanup read should succeed");
    assert!(removed.is_none());
    fixture.delete_acl_user(&acl_user).await;
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
async fn approve_access_request_delivery_failure_is_fail_closed_before_database_commit() {
    let schema = format!("admin_access_delivery_{}", Uuid::now_v7().simple());
    let Some(fixture) = LiveAdminAccessRequestFixture::new_isolated(&schema).await else {
        return;
    };
    let admin = fixture.create_user("delivery-admin", "admin", 10).await;
    let applicant = fixture.create_user("delivery-user", "user", 0).await;
    let sid = format!("sid-delivery-{}", Uuid::now_v7().simple());
    let csrf = format!("csrf-delivery-{}", Uuid::now_v7().simple());
    fixture.store_session(&admin, &sid).await;
    let request_id = fixture
        .insert_access_request(&applicant, "DeliveryFailure", AccessRequestStatus::Pending)
        .await;
    let before_clients = fixture.client_count().await;
    let acl_user = format!("access_delivery_{}", Uuid::now_v7().simple());
    let acl_password = format!("pw{}", Uuid::now_v7().simple());
    let restricted = fixture
        .restricted_valkey_client(&acl_user, &acl_password)
        .await;
    let req = fixture.admin_post_request(&sid, &csrf, "/admin/access-requests/request/approve");

    let response = invoke_admin_approve_access_request(
        fixture.state_with_valkey(restricted),
        req,
        actix_web::web::Path::from(request_id),
        Json(create_client_request()),
    )
    .await;
    let state = fixture.access_request_state(request_id).await;
    let after_clients = fixture.client_count().await;
    fixture.delete_acl_user(&acl_user).await;
    fixture.cleanup().await;
    let (status, body) = json_body(response).await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "body: {body}");
    assert_eq!(body["error"], "server_error");
    assert_eq!(state.status, AccessRequestStatus::Pending.code());
    assert!(state.approved_client_id.is_none());
    assert_eq!(after_clients, before_clients);
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

    let response = invoke_admin_reject_access_request(
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

    let response = invoke_admin_reject_access_request(
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
