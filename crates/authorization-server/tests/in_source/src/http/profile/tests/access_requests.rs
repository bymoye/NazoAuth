use super::*;
use crate::domain::TestAppState;
use crate::test_support::{access_request_profiles, profile_sessions};
use uuid::Uuid;

use actix_web::cookie::Cookie;
use actix_web::test::TestRequest;
use diesel::sql_query;
use diesel::sql_types::{Text, Uuid as SqlUuid};
use diesel_async::RunQueryDsl;
use fred::interfaces::ClientLike;
use fred::prelude::{
    Builder as ValkeyBuilder, Config as ValkeyConfig, ConnectionConfig, PerformanceConfig,
};
use std::sync::Arc;
use std::time::Duration as StdDuration;

use crate::config::ConfigSource;
use nazo_postgres::{create_pool, get_conn};

async fn my_access_requests_from_state(
    state: Data<TestAppState>,
    req: HttpRequest,
) -> HttpResponse {
    my_access_requests(
        profile_sessions(&state),
        access_request_profiles(&state),
        req,
    )
    .await
}

async fn create_access_request_from_state(
    state: Data<TestAppState>,
    req: HttpRequest,
    payload: Json<CreateAccessRequest>,
) -> HttpResponse {
    create_access_request(
        profile_sessions(&state),
        access_request_profiles(&state),
        req,
        payload,
    )
    .await
}

fn test_state() -> TestAppState {
    TestAppState {
        diesel_db: create_pool(
            "postgres://nazo_access_request_test_invalid:nazo_access_request_test_invalid@127.0.0.1:1/nazo"
                .to_owned(),
            1,
        )
        .expect("pool construction should not connect"),
        valkey: ValkeyBuilder::default_centralized()
            .build()
            .expect("valkey client construction should not connect"),
        settings: Arc::new(
            Settings::from_config(&ConfigSource::default()).expect("default settings should load"),
        ),
        keyset: crate::test_support::test_key_manager(),
    }
}

struct LiveProfileAccessRequestFixture {
    state: Data<TestAppState>,
}

impl LiveProfileAccessRequestFixture {
    async fn new() -> Option<Self> {
        let database_url = std::env::var("DATABASE_URL").ok()?;
        let valkey_url = std::env::var("VALKEY_URL").ok()?;
        let config = ConfigSource::from_pairs_for_test([
            ("ISSUER", "https://example.com"),
            (
                "CLIENT_SECRET_PEPPER",
                "client-secret-pepper-for-tests-000000000001",
            ),
            ("COOKIE_SECURE", "true"),
            ("SESSION_COOKIE_NAME", "nazo_session_access_request_test"),
            ("CSRF_COOKIE_NAME", "nazo_csrf_access_request_test"),
            ("AUTH_RATE_LIMIT_MAX_REQUESTS", "100000"),
        ]);
        let settings = Settings::from_config(&config).expect("settings should load");
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

    async fn create_user(&self, suffix: &str) -> DatabaseUserFixture {
        let email = format!("access-request-{suffix}@example.com");
        let username = format!("access-request-{suffix}");
        let mut conn = get_conn(&self.state.diesel_db)
            .await
            .expect("database connection");
        sql_query(
            r#"
            INSERT INTO users (
                tenant_id, realm_id, organization_id, username, email,
                password_hash, is_active, mfa_enabled, email_verified, role, admin_level
            )
            VALUES ($1, $2, $3, $4, $5, 'unused-access-request-test-hash', true, false, true, 'user', 0)
            RETURNING *
            "#,
        )
        .bind::<SqlUuid, _>(DEFAULT_TENANT_ID)
        .bind::<SqlUuid, _>(DEFAULT_REALM_ID)
        .bind::<SqlUuid, _>(DEFAULT_ORGANIZATION_ID)
        .bind::<Text, _>(username)
        .bind::<Text, _>(email)
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

    fn request(&self, sid: &str, csrf: &str) -> HttpRequest {
        TestRequest::default()
            .cookie(Cookie::new(
                self.state.settings.session.session_cookie_name.clone(),
                sid.to_owned(),
            ))
            .cookie(Cookie::new(
                self.state.settings.session.csrf_cookie_name.clone(),
                csrf.to_owned(),
            ))
            .insert_header((header::CONTENT_TYPE, "application/json"))
            .insert_header(("x-csrf-token", csrf))
            .to_http_request()
    }
}

fn request_with_session_but_no_csrf(state: &TestAppState, sid: &str) -> HttpRequest {
    TestRequest::default()
        .cookie(Cookie::new(
            state.settings.session.session_cookie_name.clone(),
            sid.to_owned(),
        ))
        .to_http_request()
}

fn sample_access_request_payload() -> CreateAccessRequest {
    CreateAccessRequest {
        site_name: "My App".to_owned(),
        site_url: "https://app.example".to_owned(),
        request_description: "Need API scope".to_owned(),
    }
}

fn access_request_row(status: AccessRequestStatus) -> nazo_identity::AccessRequest {
    let now = Utc::now();
    nazo_identity::AccessRequest {
        id: Uuid::now_v7(),
        tenant_id: nazo_identity::TenantId::new(DEFAULT_TENANT_ID).unwrap(),
        user_id: nazo_identity::UserId::new(Uuid::now_v7()).unwrap(),
        requester_email: None,
        site_name: "Client App".to_owned(),
        site_url: "https://client.example".to_owned(),
        request_description: "Need OpenID access".to_owned(),
        status,
        admin_note: Some("review note".to_owned()),
        approved_client_id: Some(Uuid::now_v7()),
        created_at: now,
        resolved_at: Some(now),
    }
}

#[test]
fn user_access_request_json_omits_request_owner_and_client_secret_material() {
    let row = access_request_row(AccessRequestStatus::Approved);
    let value = user_access_request_json(row, None);

    assert_eq!(value["site_name"], "Client App");
    assert_eq!(value["site_url"], "https://client.example");
    assert_eq!(value["request_description"], "Need OpenID access");
    assert_eq!(value["status"], AccessRequestStatus::Approved.code());
    assert!(value.get("user_id").is_none());
    assert!(value.get("user_email").is_none());
    assert!(value.get("client_secret").is_none());
    assert!(value.get("client_secret_hash").is_none());
}

#[actix_web::test]
async fn my_access_requests_response_counts_only_pending_state() {
    let response = my_access_requests_response(vec![
        access_request_row(AccessRequestStatus::Pending),
        access_request_row(AccessRequestStatus::Approved),
        access_request_row(AccessRequestStatus::Rejected),
    ]);

    assert_eq!(response.status(), StatusCode::OK);
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("access request body should collect");
    let body: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(body["total"], json!(3));
    assert_eq!(body["pending_count"], json!(1));
    assert_eq!(
        body["items"]
            .as_array()
            .expect("items should be array")
            .len(),
        3
    );
    assert!(body.get("client_secret").is_none());
}

#[actix_web::test]
async fn create_access_request_response_uses_created_and_public_projection() {
    let response = create_access_request_response(access_request_row(AccessRequestStatus::Pending));

    assert_eq!(response.status(), StatusCode::CREATED);
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("create access request body should collect");
    let body: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(body["status"], AccessRequestStatus::Pending.code());
    assert!(body.get("user_id").is_none());
    assert!(body.get("client_secret").is_none());
}

#[actix_web::test]
async fn my_access_requests_rejects_requests_without_login() {
    let state = test_state();
    let request = TestRequest::default().to_http_request();
    let response = my_access_requests_from_state(Data::new(state), request).await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[actix_web::test]
async fn create_access_request_rejects_requests_without_csrf() {
    let state = test_state();
    let request = request_with_session_but_no_csrf(&state, "sid-without-csrf");
    let response = create_access_request_from_state(
        Data::new(state),
        request,
        Json(sample_access_request_payload()),
    )
    .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[actix_web::test]
async fn my_access_requests_response_with_live_data() {
    let Some(fixture) = LiveProfileAccessRequestFixture::new().await else {
        return;
    };
    let user = fixture.create_user(&Uuid::now_v7().to_string()).await;
    let sid = format!("access-request-success-{}", Uuid::now_v7());
    fixture.store_session(&user, &sid).await;

    let pending = Uuid::now_v7();
    let approved = Uuid::now_v7();
    let mut conn = get_conn(&fixture.state.diesel_db)
        .await
        .expect("database connection");
    sql_query(
        r#"
            INSERT INTO client_access_requests (
                tenant_id, user_id, site_name, site_url, request_description, status, id
            )
            VALUES
                ($1, $2, 'My App', 'https://app.example', 'Need API scope', 0, $3),
                ($1, $2, 'Other App', 'https://other.example', 'Need read scope', 1, $4)
        "#,
    )
    .bind::<SqlUuid, _>(DEFAULT_TENANT_ID)
    .bind::<SqlUuid, _>(user.id)
    .bind::<SqlUuid, _>(pending)
    .bind::<SqlUuid, _>(approved)
    .execute(&mut conn)
    .await
    .expect("fixture access requests should insert");

    let response = my_access_requests_from_state(
        Data::clone(&fixture.state),
        fixture.request(&sid, "csrf-live"),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("my_access_requests body should collect");
    let body: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(body["total"], json!(2));
    assert_eq!(body["pending_count"], json!(1));
    assert_eq!(
        body["items"]
            .as_array()
            .expect("items should be array")
            .len(),
        2
    );
}

#[actix_web::test]
async fn create_access_request_handles_duplicate_pending_request_as_conflict() {
    let Some(fixture) = LiveProfileAccessRequestFixture::new().await else {
        return;
    };
    let user = fixture.create_user(&Uuid::now_v7().to_string()).await;
    let sid = format!("access-request-dup-{}", Uuid::now_v7());
    fixture.store_session(&user, &sid).await;
    let payload = sample_access_request_payload();
    let request_payload = fixture.request(&sid, "csrf-dup");
    let first = create_access_request_from_state(
        Data::clone(&fixture.state),
        fixture.request(&sid, "csrf-dup"),
        Json(sample_access_request_payload()),
    )
    .await;
    assert_eq!(first.status(), StatusCode::CREATED);

    let second = create_access_request_from_state(
        Data::clone(&fixture.state),
        request_payload,
        Json(payload),
    )
    .await;
    assert_eq!(second.status(), StatusCode::CONFLICT);
    let body = actix_web::body::to_bytes(second.into_body())
        .await
        .expect("error body should collect");
    let body: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["error"], "invalid_request");
}
