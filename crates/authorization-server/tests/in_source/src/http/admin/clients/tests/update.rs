use super::admin_patch_client;
use crate::domain::tenancy::DEFAULT_ORGANIZATION_ID;
use crate::domain::tenancy::DEFAULT_REALM_ID;
use crate::domain::tenancy::DEFAULT_TENANT_ID;
use crate::domain::{ClientRow, DatabaseUserFixture, TestAppState};
use crate::http::admin::clients::test_support::{
    CreateClientRequest, InsertClientError, PreparedClientRegistration, admin_client_config,
    admin_client_service, admin_session_handles, insert_prepared_client,
    prepare_client_insert_with_secret_pepper, prepare_client_patch,
};
use crate::http::sessions::SessionPayload;
use crate::settings::Settings;
use crate::test_support::valkey::valkey_set_ex;
use actix_web::cookie::Cookie;
use actix_web::http::StatusCode;
use actix_web::web::{Data, Json};
use actix_web::{HttpRequest, HttpResponse};
use chrono::Utc;
use diesel::sql_query;
use diesel::sql_types::{Int4, Text, Uuid as SqlUuid};
use diesel_async::RunQueryDsl;
use fred::interfaces::ClientLike;
use fred::prelude::{
    Builder as ValkeyBuilder, Config as ValkeyConfig, ConnectionConfig, PerformanceConfig,
};
use std::sync::Arc;
use std::time::Duration as StdDuration;

use crate::config::ConfigSource;
use nazo_auth::PatchClientRequest;
use nazo_http_actix::OAuthJsonErrorFields;
use nazo_postgres::{create_pool, get_conn};
use serde_json::{Value, json};
use uuid::Uuid;

async fn prepare_client_insert_for_test(
    payload: CreateClientRequest,
    pairwise_subject_secret: Option<&str>,
    issuer: &str,
) -> Result<PreparedClientRegistration, InsertClientError> {
    prepare_client_insert_with_secret_pepper(
        payload,
        pairwise_subject_secret,
        crate::adapters::security::LOCAL_DEVELOPMENT_CLIENT_SECRET_PEPPER,
        issuer,
        crate::adapters::security::SUPPORTED_CLIENT_JWT_SIGNING_ALGS,
    )
    .await
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
            "postgres://nazo_admin_client_update_test_invalid:nazo_admin_client_update_test_invalid@127.0.0.1:1/nazo"
                .to_owned(),
            1,
        )
        .expect("pool construction should not connect"),
        valkey: unavailable_valkey_client(),
        settings: Arc::new(
            Settings::from_config(&ConfigSource::default()).expect("default settings should load"),
        ),
        keyset: crate::test_support::test_key_manager(),
    }
}

fn oauth_error_name(response: &HttpResponse) -> Option<String> {
    response
        .extensions()
        .get::<OAuthJsonErrorFields>()
        .map(|fields| fields.error.clone())
}

fn create_client_request(client_name: &str) -> CreateClientRequest {
    CreateClientRequest {
        client_name: client_name.to_owned(),
        client_type: "confidential".to_owned(),
        redirect_uris: vec!["https://client.example/callback".to_owned()],
        post_logout_redirect_uris: vec!["https://client.example/logout".to_owned()],
        scopes: vec!["openid".to_owned(), "payments".to_owned()],
        allowed_audiences: vec!["https://api.example".to_owned()],
        grant_types: vec!["authorization_code".to_owned(), "refresh_token".to_owned()],
        token_endpoint_auth_method: "client_secret_post".to_owned(),
        require_dpop_bound_tokens: false,
        allow_client_assertion_audience_array: false,
        allow_client_assertion_endpoint_audience: false,
        require_par_request_object: false,
        allow_authorization_code_without_pkce: false,
        backchannel_logout_uri: Some("https://client.example/backchannel".to_owned()),
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

fn database_url_with_search_path(schema: &str) -> Option<String> {
    let base = std::env::var("DATABASE_URL").ok()?;
    let separator = if base.contains('?') { "&" } else { "?" };
    Some(format!(
        "{base}{separator}options=-csearch_path%3D{schema}%2Cpublic"
    ))
}

struct LiveAdminClientUpdateFixture {
    state: Data<TestAppState>,
    schema: String,
}

impl LiveAdminClientUpdateFixture {
    async fn new_isolated(schema: &str) -> Option<Self> {
        let database_url = database_url_with_search_path(schema)?;
        let valkey_url = std::env::var("VALKEY_URL").ok()?;
        let config = ConfigSource::from_pairs_for_test([
            ("ISSUER", "https://issuer.example"),
            (
                "CLIENT_SECRET_PEPPER",
                "client-secret-pepper-for-tests-000000000001",
            ),
            ("COOKIE_SECURE", "true"),
            ("SESSION_COOKIE_NAME", "nazo_admin_client_update_session"),
            ("CSRF_COOKIE_NAME", "nazo_admin_client_update_csrf"),
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
        let fixture = Self {
            state: Data::new(TestAppState {
                diesel_db: create_pool(database_url, 4).expect("database pool should build"),
                valkey,
                settings: Arc::new(settings),
                keyset: crate::test_support::test_key_manager(),
            }),
            schema: schema.to_owned(),
        };
        fixture
            .create_isolated_schema(&["users", "oauth_clients"])
            .await;
        Some(fixture)
    }

    async fn create_isolated_schema(&self, tables: &[&str]) {
        self.exec_sql(&format!(r#"CREATE SCHEMA IF NOT EXISTS "{}""#, self.schema))
            .await;
        for table in tables {
            self.exec_sql(&format!(
                r#"CREATE TABLE "{}"."{}" (LIKE public."{}" INCLUDING ALL)"#,
                self.schema, table, table
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
        self.exec_sql(&format!(
            r#"ALTER TABLE "{}"."{}" RENAME COLUMN "{}" TO "{}""#,
            self.schema, table, from, to
        ))
        .await;
    }

    async fn cleanup(&self) {
        self.exec_sql(&format!(
            r#"DROP SCHEMA IF EXISTS "{}" CASCADE"#,
            self.schema
        ))
        .await;
    }

    async fn create_user(&self, suffix: &str, role: &str, admin_level: i32) -> DatabaseUserFixture {
        let email = format!("admin-client-update-{suffix}@example.com");
        let username = format!("admin-client-update-{suffix}");
        let mut conn = get_conn(&self.state.diesel_db)
            .await
            .expect("database connection");
        sql_query(
            r#"
            INSERT INTO users (
                tenant_id, realm_id, organization_id, username, email,
                password_hash, is_active, mfa_enabled, email_verified, role, admin_level
            )
            VALUES ($1, $2, $3, $4, $5, 'unused-admin-client-update-hash', true, false, true, $6, $7)
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

    fn admin_patch_request(&self, sid: &str, csrf: &str, uri: &str) -> HttpRequest {
        actix_web::test::TestRequest::patch()
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

    async fn insert_client(&self, client_name: &str) -> nazo_auth::OAuthClient {
        let prepared = prepare_client_insert_for_test(
            create_client_request(client_name),
            None,
            "http://localhost:8000",
        )
        .await
        .expect("client creation payload should be valid");
        insert_prepared_client(
            &nazo_postgres::OAuthClientRepository::new(self.state.diesel_db.clone()),
            &prepared,
        )
        .await
        .expect("client should insert")
    }

    async fn client_row(&self, client_id: &str) -> ClientRow {
        nazo_postgres::OAuthClientRepository::new(self.state.diesel_db.clone())
            .by_client_id(DEFAULT_TENANT_ID, client_id)
            .await
            .expect("client lookup should succeed")
            .expect("client should load")
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

fn current_client() -> ClientRow {
    crate::client_row! {
        id: Uuid::now_v7(),
        tenant_id: DEFAULT_TENANT_ID,
        realm_id: DEFAULT_REALM_ID,
        organization_id: DEFAULT_ORGANIZATION_ID,
        client_id: "client-1".to_owned(),
        client_name: "Existing client".to_owned(),
        client_type: "confidential".to_owned(),
        client_secret_hash: None,
        redirect_uris: json!(["https://client.example/callback"]),
        scopes: json!(["openid", "payments"]),
        allowed_audiences: json!(["https://api.example"]),
        grant_types: json!(["authorization_code", "refresh_token"]),
        token_endpoint_auth_method: "client_secret_basic".to_owned(),
        require_dpop_bound_tokens: true,
        require_mtls_bound_tokens: false,
        tls_client_auth_subject_dn: None,
        tls_client_auth_cert_sha256: None,
        tls_client_auth_san_dns: json!([]),
        tls_client_auth_san_uri: json!([]),
        tls_client_auth_san_ip: json!([]),
        tls_client_auth_san_email: json!([]),
        allow_client_assertion_audience_array: false,
        allow_client_assertion_endpoint_audience: false,
        require_par_request_object: true,
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
        post_logout_redirect_uris: json!(["https://client.example/logout"]),
        backchannel_logout_uri: Some("https://client.example/backchannel".to_owned()),
        backchannel_logout_session_required: true,
        frontchannel_logout_uri: None,
        frontchannel_logout_session_required: true,
        subject_type: "public".to_owned(),
        sector_identifier_uri: None,
        sector_identifier_host: None,
    }
}

fn pairwise_current_client() -> ClientRow {
    let mut client = current_client();
    client.subject_type = "pairwise".to_owned();
    client.sector_identifier_uri = Some("https://sector.example/client.json".to_owned());
    client.sector_identifier_host = Some("sector.example".to_owned());
    client
}

fn empty_patch() -> PatchClientRequest {
    PatchClientRequest {
        client_name: None,
        redirect_uris: None,
        post_logout_redirect_uris: None,
        scopes: None,
        allowed_audiences: None,
        grant_types: None,
        require_dpop_bound_tokens: None,
        allow_client_assertion_audience_array: None,
        allow_client_assertion_endpoint_audience: None,
        require_par_request_object: None,
        allow_authorization_code_without_pkce: None,
        backchannel_logout_uri: None,
        backchannel_logout_session_required: None,
        frontchannel_logout_uri: None,
        frontchannel_logout_session_required: None,
        tls_client_auth_subject_dn: None,
        tls_client_auth_cert_sha256: None,
        tls_client_auth_san_dns: None,
        tls_client_auth_san_uri: None,
        tls_client_auth_san_ip: None,
        tls_client_auth_san_email: None,
        jwks: None,
        introspection_encrypted_response_alg: None,
        introspection_encrypted_response_enc: None,
        userinfo_signed_response_alg: None,
        userinfo_encrypted_response_alg: None,
        userinfo_encrypted_response_enc: None,
        authorization_signed_response_alg: None,
        authorization_encrypted_response_alg: None,
        authorization_encrypted_response_enc: None,
        is_active: None,
        subject_type: None,
        sector_identifier_uri: None,
    }
}

#[actix_web::test]
async fn patch_preserves_unsubmitted_security_metadata() {
    let mut patch = empty_patch();
    patch.client_name = Some("Renamed client".to_owned());
    patch.is_active = Some(false);

    let prepared = prepare_client_patch(
        &current_client(),
        patch,
        None,
        "http://localhost:8000",
        crate::adapters::security::SUPPORTED_CLIENT_JWT_SIGNING_ALGS,
    )
    .await
    .expect("renaming a client must not require resubmitting security metadata");

    assert_eq!(prepared.client_name, "Renamed client");
    assert_eq!(
        prepared.redirect_uris,
        vec!["https://client.example/callback".to_owned()]
    );
    assert_eq!(
        prepared.post_logout_redirect_uris,
        vec!["https://client.example/logout".to_owned()]
    );
    assert_eq!(prepared.scopes, vec!["openid", "payments"]);
    assert_eq!(prepared.allowed_audiences, vec!["https://api.example"]);
    assert_eq!(
        prepared.grant_types,
        vec!["authorization_code", "refresh_token"]
    );
    assert!(prepared.require_dpop_bound_tokens);
    assert!(prepared.require_par_request_object);
    assert!(!prepared.allow_authorization_code_without_pkce);
    assert!(!prepared.is_active);
}

#[actix_web::test]
async fn patch_rejects_redirect_uri_with_surrounding_whitespace() {
    let mut patch = empty_patch();
    patch.redirect_uris = Some(vec![" https://client.example/callback ".to_owned()]);

    let error = prepare_client_patch(
        &current_client(),
        patch,
        None,
        "http://localhost:8000",
        crate::adapters::security::SUPPORTED_CLIENT_JWT_SIGNING_ALGS,
    )
    .await
    .expect_err("redirect_uri metadata must be an exact registered value");

    assert!(
        error.to_string().contains("redirect_uri"),
        "error should identify the exact redirect_uri metadata boundary: {error}"
    );
}

#[actix_web::test]
async fn patch_rejects_post_logout_redirect_uri_with_surrounding_whitespace() {
    let mut patch = empty_patch();
    patch.post_logout_redirect_uris = Some(vec![" https://client.example/logout ".to_owned()]);

    let error = prepare_client_patch(
        &current_client(),
        patch,
        None,
        "http://localhost:8000",
        crate::adapters::security::SUPPORTED_CLIENT_JWT_SIGNING_ALGS,
    )
    .await
    .expect_err("post_logout_redirect_uri metadata must not be silently normalized");

    assert!(
        error.to_string().contains("post_logout_redirect_uri"),
        "error should identify the exact post_logout_redirect_uri boundary: {error}"
    );
}

#[actix_web::test]
async fn patch_rejects_pairwise_when_secret_is_not_configured() {
    let mut patch = empty_patch();
    patch.subject_type = Some("pairwise".to_owned());

    let error = prepare_client_patch(
        &current_client(),
        patch,
        None,
        "http://localhost:8000",
        crate::adapters::security::SUPPORTED_CLIENT_JWT_SIGNING_ALGS,
    )
    .await
    .expect_err("pairwise subject update requires a configured server secret");

    assert!(
        error.to_string().contains("PAIRWISE_SUBJECT_SECRET"),
        "error should identify the missing pairwise server secret: {error}"
    );
}

#[actix_web::test]
async fn patch_derives_pairwise_sector_from_updated_single_redirect_host() {
    let mut patch = empty_patch();
    patch.subject_type = Some("pairwise".to_owned());
    patch.redirect_uris = Some(vec![
        "https://client.example/callback".to_owned(),
        "https://client.example/alternate".to_owned(),
    ]);

    let prepared = prepare_client_patch(
        &current_client(),
        patch,
        Some("01234567890123456789012345678901"),
        "http://localhost:8000",
        crate::adapters::security::SUPPORTED_CLIENT_JWT_SIGNING_ALGS,
    )
    .await
    .expect("pairwise update with one redirect host should be accepted");

    assert_eq!(prepared.subject_type, "pairwise");
    assert!(prepared.sector_identifier_uri.is_none());
    assert_eq!(
        prepared.sector_identifier_host.as_deref(),
        Some("client.example")
    );
}

#[actix_web::test]
async fn patch_rejects_pairwise_redirects_with_multiple_hosts_without_sector_uri() {
    let mut patch = empty_patch();
    patch.subject_type = Some("pairwise".to_owned());
    patch.redirect_uris = Some(vec![
        "https://client.example/callback".to_owned(),
        "https://other.example/callback".to_owned(),
    ]);

    let error = prepare_client_patch(
        &current_client(),
        patch,
        Some("01234567890123456789012345678901"),
        "http://localhost:8000",
        crate::adapters::security::SUPPORTED_CLIENT_JWT_SIGNING_ALGS,
    )
    .await
    .expect_err("multi-host pairwise redirect set requires a sector_identifier_uri");

    assert!(
        error.to_string().contains("sector_identifier_uri"),
        "error should identify the missing sector identifier boundary: {error}"
    );
}

#[actix_web::test]
async fn patch_reports_sector_identifier_fetch_failure_for_new_pairwise_uri() {
    let mut patch = empty_patch();
    patch.subject_type = Some("pairwise".to_owned());
    patch.redirect_uris = Some(vec![
        "https://client.example/callback".to_owned(),
        "https://other.example/callback".to_owned(),
    ]);
    patch.sector_identifier_uri = Some("https://sector.invalid/client.json".to_owned());

    let error = prepare_client_patch(
        &current_client(),
        patch,
        Some("01234567890123456789012345678901"),
        "http://localhost:8000",
        crate::adapters::security::SUPPORTED_CLIENT_JWT_SIGNING_ALGS,
    )
    .await
    .expect_err("unresolvable sector_identifier_uri must fail patch validation");

    assert!(
        error.to_string().contains("sector_identifier_uri 获取失败"),
        "error should identify sector identifier retrieval: {error}"
    );
}

#[actix_web::test]
async fn patch_preserves_existing_pairwise_sector_host_without_refetching_uri() {
    let mut patch = empty_patch();
    patch.client_name = Some("Renamed pairwise client".to_owned());

    let prepared = prepare_client_patch(
        &pairwise_current_client(),
        patch,
        Some("01234567890123456789012345678901"),
        "http://localhost:8000",
        crate::adapters::security::SUPPORTED_CLIENT_JWT_SIGNING_ALGS,
    )
    .await
    .expect("unrelated patch should preserve existing pairwise sector metadata");

    assert_eq!(prepared.client_name, "Renamed pairwise client");
    assert_eq!(
        prepared.sector_identifier_uri.as_deref(),
        Some("https://sector.example/client.json")
    );
    assert_eq!(
        prepared.sector_identifier_host.as_deref(),
        Some("sector.example")
    );
}

#[actix_web::test]
async fn patch_rejects_modifying_existing_sector_identifier_uri() {
    let mut patch = empty_patch();
    patch.sector_identifier_uri = Some("https://other-sector.example/client.json".to_owned());

    let error = prepare_client_patch(
        &pairwise_current_client(),
        patch,
        Some("01234567890123456789012345678901"),
        "http://localhost:8000",
        crate::adapters::security::SUPPORTED_CLIENT_JWT_SIGNING_ALGS,
    )
    .await
    .expect_err("existing sector_identifier_uri must be immutable");

    assert!(
        error.to_string().contains("不可修改"),
        "error should identify immutable sector identifier metadata: {error}"
    );
}

#[actix_web::test]
async fn patch_clears_pairwise_sector_metadata_when_subject_becomes_public() {
    let mut patch = empty_patch();
    patch.subject_type = Some("public".to_owned());

    let prepared = prepare_client_patch(
        &pairwise_current_client(),
        patch,
        Some("01234567890123456789012345678901"),
        "http://localhost:8000",
        crate::adapters::security::SUPPORTED_CLIENT_JWT_SIGNING_ALGS,
    )
    .await
    .expect("switching back to public should remove pairwise-only metadata");

    assert_eq!(prepared.subject_type, "public");
    assert!(prepared.sector_identifier_uri.is_none());
    assert!(prepared.sector_identifier_host.is_none());
}

#[actix_web::test]
async fn admin_patch_client_rejects_missing_csrf_before_admin_lookup() {
    let state = Data::new(test_state());
    let req = actix_web::test::TestRequest::patch()
        .uri("/admin/clients/client-1")
        .cookie(Cookie::new(
            state.settings.session.session_cookie_name.clone(),
            "session-id",
        ))
        .to_http_request();
    let sessions = admin_session_handles(
        state.diesel_db.clone(),
        state.valkey_connection(),
        &state.settings,
    );
    let service = admin_client_service(
        state.diesel_db.clone(),
        state.keyset.clone(),
        &state.settings,
    );
    let config = admin_client_config(&state.settings);

    let response = admin_patch_client(
        sessions,
        service,
        config,
        req,
        actix_web::web::Path::from("client-1".to_owned()),
        Json(empty_patch()),
    )
    .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        oauth_error_name(&response).as_deref(),
        Some("invalid_request")
    );
}

#[actix_web::test]
async fn admin_patch_client_reports_not_found_for_unknown_client_id() {
    let schema = format!("admin_client_update_missing_{}", Uuid::now_v7().simple());
    let Some(fixture) = LiveAdminClientUpdateFixture::new_isolated(&schema).await else {
        return;
    };
    let admin = fixture.create_user("missing", "admin", 10).await;
    fixture.store_session(&admin, "sid-missing").await;
    let req = fixture.admin_patch_request("sid-missing", "csrf-missing", "/admin/clients/missing");
    let sessions = admin_session_handles(
        fixture.state.diesel_db.clone(),
        fixture.state.valkey_connection(),
        &fixture.state.settings,
    );
    let service = admin_client_service(
        fixture.state.diesel_db.clone(),
        fixture.state.keyset.clone(),
        &fixture.state.settings,
    );
    let config = admin_client_config(&fixture.state.settings);

    let response = admin_patch_client(
        sessions,
        service,
        config,
        req,
        actix_web::web::Path::from("missing-client".to_owned()),
        Json(empty_patch()),
    )
    .await;
    fixture.cleanup().await;
    let (status, body) = json_body(response).await;

    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["error"], "invalid_request");
}

#[actix_web::test]
async fn admin_patch_client_validates_metadata_after_admin_authentication() {
    let schema = format!("admin_client_update_invalid_{}", Uuid::now_v7().simple());
    let Some(fixture) = LiveAdminClientUpdateFixture::new_isolated(&schema).await else {
        return;
    };
    let admin = fixture.create_user("invalid", "admin", 10).await;
    fixture.store_session(&admin, "sid-invalid").await;
    let client = fixture.insert_client("Client Invalid").await;
    let mut payload = empty_patch();
    payload.redirect_uris = Some(vec![" https://client.example/callback ".to_owned()]);
    let req = fixture.admin_patch_request("sid-invalid", "csrf-invalid", "/admin/clients/update");
    let sessions = admin_session_handles(
        fixture.state.diesel_db.clone(),
        fixture.state.valkey_connection(),
        &fixture.state.settings,
    );
    let service = admin_client_service(
        fixture.state.diesel_db.clone(),
        fixture.state.keyset.clone(),
        &fixture.state.settings,
    );
    let config = admin_client_config(&fixture.state.settings);

    let response = admin_patch_client(
        sessions,
        service,
        config,
        req,
        actix_web::web::Path::from(client.client_id.clone()),
        Json(payload),
    )
    .await;
    let stored_name = fixture
        .client_row(&client.client_id)
        .await
        .client_name
        .clone();
    fixture.cleanup().await;
    let (status, body) = json_body(response).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");
    assert_eq!(stored_name, "Client Invalid");
}

#[actix_web::test]
async fn admin_patch_client_surfaces_client_lookup_failure_after_admin_authentication() {
    let schema = format!("admin_client_update_lookup_{}", Uuid::now_v7().simple());
    let Some(fixture) = LiveAdminClientUpdateFixture::new_isolated(&schema).await else {
        return;
    };
    let admin = fixture.create_user("lookup", "admin", 10).await;
    let sid = format!("sid-lookup-{}", Uuid::now_v7().simple());
    let csrf = format!("csrf-lookup-{}", Uuid::now_v7().simple());
    fixture.store_session(&admin, &sid).await;
    let client = fixture.insert_client("Client Lookup").await;
    fixture
        .rename_column("oauth_clients", "client_id", "client_id_unavailable")
        .await;
    let req = fixture.admin_patch_request(&sid, &csrf, "/admin/clients/update");
    let sessions = admin_session_handles(
        fixture.state.diesel_db.clone(),
        fixture.state.valkey_connection(),
        &fixture.state.settings,
    );
    let service = admin_client_service(
        fixture.state.diesel_db.clone(),
        fixture.state.keyset.clone(),
        &fixture.state.settings,
    );
    let config = admin_client_config(&fixture.state.settings);

    let response = admin_patch_client(
        sessions,
        service,
        config,
        req,
        actix_web::web::Path::from(client.client_id.clone()),
        Json(empty_patch()),
    )
    .await;
    fixture.cleanup().await;
    let (status, body) = json_body(response).await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"], "server_error");
}

#[actix_web::test]
async fn admin_patch_client_surfaces_update_failure_without_mutating_current_client() {
    let schema = format!("admin_client_update_write_{}", Uuid::now_v7().simple());
    let Some(fixture) = LiveAdminClientUpdateFixture::new_isolated(&schema).await else {
        return;
    };
    let admin = fixture.create_user("write", "admin", 10).await;
    let sid = format!("sid-write-{}", Uuid::now_v7().simple());
    let csrf = format!("csrf-write-{}", Uuid::now_v7().simple());
    fixture.store_session(&admin, &sid).await;
    let client = fixture.insert_client("Client Write").await;
    fixture
        .rename_column("oauth_clients", "updated_at", "updated_at_unavailable")
        .await;
    let mut payload = empty_patch();
    payload.client_name = Some("Renamed After Failure".to_owned());
    let req = fixture.admin_patch_request(&sid, &csrf, "/admin/clients/update");
    let sessions = admin_session_handles(
        fixture.state.diesel_db.clone(),
        fixture.state.valkey_connection(),
        &fixture.state.settings,
    );
    let service = admin_client_service(
        fixture.state.diesel_db.clone(),
        fixture.state.keyset.clone(),
        &fixture.state.settings,
    );
    let config = admin_client_config(&fixture.state.settings);

    let response = admin_patch_client(
        sessions,
        service,
        config,
        req,
        actix_web::web::Path::from(client.client_id.clone()),
        Json(payload),
    )
    .await;
    let stored_name = fixture
        .client_row(&client.client_id)
        .await
        .client_name
        .clone();
    fixture.cleanup().await;
    let (status, body) = json_body(response).await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"], "server_error");
    assert_eq!(stored_name, "Client Write");
}
