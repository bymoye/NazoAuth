use super::{admin_get_client, client_detail_not_found_response, client_detail_response};
use crate::domain::tenancy::DEFAULT_ORGANIZATION_ID;
use crate::domain::tenancy::DEFAULT_REALM_ID;
use crate::domain::tenancy::DEFAULT_TENANT_ID;
use crate::domain::{ClientRow, DatabaseUserFixture, TestAppState};
use crate::http::admin::clients::test_support::{
    CreateClientRequest, InsertClientError, PreparedClientRegistration, admin_client_service,
    admin_session_handles, insert_prepared_client, prepare_client_insert_with_secret_pepper,
};
use crate::http::sessions::SessionPayload;
use crate::settings::Settings;
use crate::test_support::valkey::valkey_set_ex;
use actix_web::cookie::Cookie;
use actix_web::http::StatusCode;
use actix_web::web::Data;
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

fn client_row() -> ClientRow {
    crate::client_row! {
        id: Uuid::now_v7(),
        tenant_id: DEFAULT_TENANT_ID,
        realm_id: DEFAULT_REALM_ID,
        organization_id: DEFAULT_ORGANIZATION_ID,
        client_id: "client-1".to_owned(),
        client_name: "Client".to_owned(),
        client_type: "confidential".to_owned(),
        client_secret_hash: Some("client-secret-v1:salt:digest".to_owned()),
        redirect_uris: json!(["https://client.example/callback"]),
        scopes: json!(["openid"]),
        allowed_audiences: json!(["https://api.example"]),
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
            "postgres://nazo_admin_client_detail_test_invalid:nazo_admin_client_detail_test_invalid@127.0.0.1:1/nazo"
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

fn create_client_request(client_name: &str) -> CreateClientRequest {
    CreateClientRequest {
        client_name: client_name.to_owned(),
        client_type: "confidential".to_owned(),
        redirect_uris: vec!["https://client.example/callback".to_owned()],
        post_logout_redirect_uris: Vec::new(),
        scopes: vec!["openid".to_owned()],
        allowed_audiences: vec!["https://api.example".to_owned()],
        grant_types: vec!["authorization_code".to_owned()],
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

struct LiveAdminClientDetailFixture {
    state: Data<TestAppState>,
}

impl LiveAdminClientDetailFixture {
    async fn new() -> Option<Self> {
        let database_url = std::env::var("DATABASE_URL").ok()?;
        let valkey_url = std::env::var("VALKEY_URL").ok()?;
        let config = ConfigSource::from_pairs_for_test([
            ("ISSUER", "https://issuer.example"),
            (
                "CLIENT_SECRET_PEPPER",
                "client-secret-pepper-for-tests-000000000001",
            ),
            ("COOKIE_SECURE", "true"),
            ("SESSION_COOKIE_NAME", "nazo_admin_client_detail_session"),
            ("CSRF_COOKIE_NAME", "nazo_admin_client_detail_csrf"),
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
        })
    }

    async fn create_user(&self, suffix: &str, role: &str, admin_level: i32) -> DatabaseUserFixture {
        let email = format!("admin-client-detail-{suffix}@example.com");
        let username = format!("admin-client-detail-{suffix}");
        let mut conn = get_conn(&self.state.diesel_db)
            .await
            .expect("database connection");
        sql_query(
            r#"
            INSERT INTO users (
                tenant_id, realm_id, organization_id, username, email,
                password_hash, is_active, mfa_enabled, email_verified, role, admin_level
            )
            VALUES ($1, $2, $3, $4, $5, 'unused-admin-client-detail-hash', true, false, true, $6, $7)
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

    async fn insert_client(&self, client_name: &str) -> nazo_auth::OAuthClient {
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
        insert_prepared_client(
            &nazo_postgres::OAuthClientRepository::new(self.state.diesel_db.clone()),
            &prepared,
        )
        .await
        .expect("client should insert")
    }
}

#[actix_web::test]
async fn client_detail_response_does_not_expose_secret_hash_or_tenant_context() {
    let response = client_detail_response(client_row());

    assert_eq!(response.status(), StatusCode::OK);
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("client detail response body should collect");
    let body: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(body["client_id"], json!("client-1"));
    assert_eq!(
        body["token_endpoint_auth_method"],
        json!("client_secret_basic")
    );
    assert!(body.get("client_secret_hash").is_none());
    assert!(body.get("tenant_id").is_none());
    assert!(body.get("realm_id").is_none());
    assert!(body.get("organization_id").is_none());
}

#[test]
fn client_detail_not_found_response_uses_stable_oauth_error() {
    let response = client_detail_not_found_response();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        response
            .extensions()
            .get::<OAuthJsonErrorFields>()
            .map(|fields| fields.error.as_str()),
        Some("invalid_request")
    );
}

#[actix_web::test]
async fn admin_get_client_requires_admin_before_lookup() {
    let state = Data::new(test_state());
    let req = actix_web::test::TestRequest::get()
        .uri("/admin/clients/client-1")
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

    let response = admin_get_client(
        sessions,
        service,
        req,
        actix_web::web::Path::from("client-1".to_owned()),
    )
    .await;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        oauth_error_name(&response).as_deref(),
        Some("access_denied")
    );
}

#[actix_web::test]
async fn admin_get_client_returns_not_found_for_unknown_client_id() {
    let Some(fixture) = LiveAdminClientDetailFixture::new().await else {
        return;
    };
    let suffix = Uuid::now_v7().simple().to_string();
    let admin = fixture
        .create_user(&format!("{suffix}-admin"), "admin", 10)
        .await;
    let sid = format!("sid-{suffix}");
    fixture.store_session(&admin, &sid).await;

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
    let response = admin_get_client(
        sessions,
        service,
        fixture.admin_get_request(&sid, "/admin/clients/missing-client"),
        actix_web::web::Path::from("missing-client".to_owned()),
    )
    .await;

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        oauth_error_name(&response).as_deref(),
        Some("invalid_request")
    );
}

#[actix_web::test]
async fn admin_get_client_returns_sanitized_client_for_admin() {
    let Some(fixture) = LiveAdminClientDetailFixture::new().await else {
        return;
    };
    let suffix = Uuid::now_v7().simple().to_string();
    let admin = fixture
        .create_user(&format!("{suffix}-admin"), "admin", 10)
        .await;
    let sid = format!("sid-{suffix}");
    fixture.store_session(&admin, &sid).await;
    let client = fixture
        .insert_client(&format!("Detail Client {suffix}"))
        .await;

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
    let response = admin_get_client(
        sessions,
        service,
        fixture.admin_get_request(&sid, &format!("/admin/clients/{}", client.client_id)),
        actix_web::web::Path::from(client.client_id.clone()),
    )
    .await;

    let status = response.status();
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("response body should be readable");
    let body: Value = serde_json::from_slice(&body).expect("response should be JSON");

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["client_id"], client.client_id);
    assert_eq!(body["client_name"], client.client_name);
    assert!(body.get("client_secret_hash").is_none());
    assert!(body.get("tenant_id").is_none());
    assert!(body.get("realm_id").is_none());
    assert!(body.get("organization_id").is_none());
}
