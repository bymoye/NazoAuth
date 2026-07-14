use super::{admin_clients, clients_list_response};
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
use actix_web::web::{Data, Query};
use actix_web::{HttpRequest, HttpResponse};
use chrono::Utc;
use diesel::sql_query;
use diesel::sql_types::{Int4, Text, Uuid as SqlUuid};
use diesel_async::RunQueryDsl;
use fred::interfaces::ClientLike;
use fred::prelude::{
    Builder as ValkeyBuilder, Config as ValkeyConfig, ConnectionConfig, PerformanceConfig,
};
use std::collections::HashMap;
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

fn client_row(client_id: &str, secret_hash: Option<&str>) -> ClientRow {
    crate::client_row! {
        id: Uuid::now_v7(),
        tenant_id: DEFAULT_TENANT_ID,
        realm_id: DEFAULT_REALM_ID,
        organization_id: DEFAULT_ORGANIZATION_ID,
        client_id: client_id.to_owned(),
        client_name: format!("{client_id} name"),
        client_type: "confidential".to_owned(),
        client_secret_hash: secret_hash.map(ToOwned::to_owned),
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
            "postgres://nazo_admin_clients_list_test_invalid:nazo_admin_clients_list_test_invalid@127.0.0.1:1/nazo"
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
        post_logout_redirect_uris: vec!["https://client.example/logout".to_owned()],
        scopes: vec!["openid".to_owned(), "payments".to_owned()],
        allowed_audiences: vec!["https://api.example".to_owned()],
        grant_types: vec!["authorization_code".to_owned(), "refresh_token".to_owned()],
        token_endpoint_auth_method: "client_secret_post".to_owned(),
        require_dpop_bound_tokens: false,
        allow_client_assertion_audience_array: false,
        allow_client_assertion_endpoint_audience: false,
        require_par_request_object: true,
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

fn oauth_error_name(response: &HttpResponse) -> Option<String> {
    response
        .extensions()
        .get::<OAuthJsonErrorFields>()
        .map(|fields| fields.error.clone())
}

struct LiveAdminClientListFixture {
    state: Data<TestAppState>,
}

impl LiveAdminClientListFixture {
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
            ("SESSION_COOKIE_NAME", "nazo_admin_clients_list_session"),
            ("CSRF_COOKIE_NAME", "nazo_admin_clients_list_csrf"),
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
        let email = format!("admin-clients-list-{suffix}@example.com");
        let username = format!("admin-clients-list-{suffix}");
        let mut conn = get_conn(&self.state.diesel_db)
            .await
            .expect("database connection");
        sql_query(
            r#"
            INSERT INTO users (
                tenant_id, realm_id, organization_id, username, email,
                password_hash, is_active, mfa_enabled, email_verified, role, admin_level
            )
            VALUES ($1, $2, $3, $4, $5, 'unused-admin-clients-list-hash', true, false, true, $6, $7)
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
async fn clients_list_response_preserves_pagination_and_omits_secret_hashes() {
    let response = clients_list_response(
        2,
        3,
        20,
        vec![
            client_row("client-1", Some("client-secret-v1:salt:digest")),
            client_row("client-2", None),
        ],
    );

    assert_eq!(response.status(), StatusCode::OK);
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("client list response body should collect");
    let body: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(body["total"], json!(2));
    assert_eq!(body["page"], json!(3));
    assert_eq!(body["page_size"], json!(20));
    let items = body["items"].as_array().expect("items should be an array");
    assert_eq!(items.len(), 2);
    assert_eq!(items[0]["client_id"], json!("client-1"));
    assert_eq!(items[1]["client_id"], json!("client-2"));
    for item in items {
        assert!(item.get("client_secret_hash").is_none());
        assert!(item.get("tenant_id").is_none());
        assert!(item.get("realm_id").is_none());
        assert!(item.get("organization_id").is_none());
    }
}

#[test]
fn admin_client_handlers_use_focused_dependencies() {
    let handlers = [
        include_str!("../../../../../../../src/http/admin/clients/list.rs"),
        include_str!("../../../../../../../src/http/admin/clients/detail.rs"),
        include_str!("../../../../../../../src/http/admin/clients/create.rs"),
        include_str!("../../../../../../../src/http/admin/clients/update.rs"),
    ]
    .join("\n");

    assert!(!handlers.contains("Data<TestAppState>"));
    assert!(!handlers.contains("test_dependencies"));
    assert!(!handlers.contains("state.diesel_db"));
    assert!(!handlers.contains("state.valkey"));
    assert!(!handlers.contains("OAuthClientRepository"));
    assert!(!handlers.contains("KeyManager"));
    assert!(handlers.contains("Data<AdminSessionHandles>"));
    assert!(handlers.contains("Data<ServerAdminClientService>"));
}

#[actix_web::test]
async fn admin_clients_requires_admin_before_database_lookup() {
    let state = Data::new(test_state());
    let req = actix_web::test::TestRequest::get()
        .uri("/admin/clients")
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

    let response = admin_clients(sessions, service, req, Query(HashMap::new())).await;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        oauth_error_name(&response).as_deref(),
        Some("access_denied")
    );
}

#[actix_web::test]
async fn admin_clients_lists_persisted_clients_for_admin_without_secret_hashes() {
    let Some(fixture) = LiveAdminClientListFixture::new().await else {
        return;
    };
    let suffix = Uuid::now_v7().simple().to_string();
    let admin = fixture
        .create_user(&format!("{suffix}-admin"), "admin", 10)
        .await;
    let sid = format!("sid-{suffix}");
    fixture.store_session(&admin, &sid).await;
    let first = fixture.insert_client(&format!("First {suffix}")).await;
    let second = fixture.insert_client(&format!("Second {suffix}")).await;

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
    let response = admin_clients(
        sessions,
        service,
        fixture.admin_get_request(&sid, "/admin/clients?page=1&page_size=100"),
        Query(HashMap::from([
            ("page".to_owned(), "1".to_owned()),
            ("page_size".to_owned(), "100".to_owned()),
        ])),
    )
    .await;

    let status = response.status();
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("response body should be readable");
    let body: Value = serde_json::from_slice(&body).expect("response should be JSON");

    assert_eq!(status, StatusCode::OK);
    assert!(body["total"].as_i64().is_some_and(|total| total >= 2));
    let items = body["items"].as_array().expect("items should be an array");
    let client_ids = items
        .iter()
        .map(|item| item["client_id"].as_str().unwrap().to_owned())
        .collect::<Vec<_>>();
    assert!(client_ids.contains(&first.client_id));
    assert!(client_ids.contains(&second.client_id));
    for item in items.iter().filter(|item| {
        item["client_id"]
            .as_str()
            .is_some_and(|client_id| client_id == first.client_id || client_id == second.client_id)
    }) {
        assert!(item.get("client_secret_hash").is_none());
        assert!(item.get("tenant_id").is_none());
        assert!(item.get("realm_id").is_none());
        assert!(item.get("organization_id").is_none());
    }
}
