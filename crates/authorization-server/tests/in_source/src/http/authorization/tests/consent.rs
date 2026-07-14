use super::*;
use actix_web::cookie::Cookie;
use actix_web::test::TestRequest;
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
use crate::domain::{DatabaseUserFixture, TestAppState};
use crate::http::sessions::SessionPayload;
use nazo_postgres::{create_pool, get_conn};

async fn authorize_consent(
    state: Data<TestAppState>,
    req: HttpRequest,
    Query(q): Query<HashMap<String, String>>,
) -> HttpResponse {
    let dependencies = crate::http::authorization::TestAuthorizationDependencies::new(&state);
    authorize_consent_with_context(&dependencies.context(), req, q).await
}

fn query(values: &[(&str, &str)]) -> std::collections::HashMap<String, String> {
    values
        .iter()
        .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
        .collect()
}

fn consent_payload(user_id: Uuid) -> ConsentPayload {
    ConsentPayload {
        request_id: "req-123".to_owned(),
        user_id,
        client_id: "client-a".to_owned(),
        client_name: "Client A".to_owned(),
        redirect_uri: "https://client.example/callback".to_owned(),
        redirect_uri_was_supplied: true,
        scopes: vec!["openid".to_owned(), "profile".to_owned()],
        resource_indicators: Vec::new(),
        authorization_details: json!([]),
        state: Some("opaque-state".to_owned()),
        response_mode: Some("query".to_owned()),
        nonce: Some("nonce-value".to_owned()),
        auth_time: 1_700_000_000,
        amr: vec!["pwd".to_owned()],
        oidc_sid: Some("sid-secret".to_owned()),
        acr: Some("urn:mace:incommon:iap:silver".to_owned()),
        userinfo_claims: vec!["email".to_owned()],
        userinfo_claim_requests: vec![],
        id_token_claims: vec!["auth_time".to_owned()],
        id_token_claim_requests: vec![],
        code_challenge: Some("challenge-material".to_owned()),
        code_challenge_method: Some("S256".to_owned()),
        dpop_jkt: Some("dpop-binding".to_owned()),
        mtls_x5t_s256: Some("mtls-binding".to_owned()),
        pushed_request_uri: Some("urn:ietf:params:oauth:request_uri:par-1".to_owned()),
        pushed_request_digest: None,
        issued_at: Utc::now(),
        expires_at: Utc::now() + Duration::minutes(5),
    }
}

fn uuid_fixture(value: u128) -> Uuid {
    Uuid::from_u128(value)
}

fn database_url_with_search_path(schema: &str) -> Option<String> {
    let base = std::env::var("DATABASE_URL").ok()?;
    let separator = if base.contains('?') { "&" } else { "?" };
    Some(format!(
        "{base}{separator}options=-csearch_path%3D{schema}%2Cpublic"
    ))
}

#[derive(Clone)]
struct ConsentLiveFixture {
    state: Data<TestAppState>,
    schema: Option<String>,
}

impl ConsentLiveFixture {
    async fn new() -> Option<Self> {
        let database_url = std::env::var("DATABASE_URL").ok()?;
        Self::from_database_url(database_url, None).await
    }

    async fn new_isolated(schema: &str) -> Option<Self> {
        let database_url = database_url_with_search_path(schema)?;
        let fixture = Self::from_database_url(database_url, Some(schema.to_owned())).await?;
        fixture.create_isolated_schema(&["users"]).await;
        Some(fixture)
    }

    async fn from_database_url(database_url: String, schema: Option<String>) -> Option<Self> {
        let valkey_url = std::env::var("VALKEY_URL").ok()?;
        let mut settings =
            Settings::from_config(&ConfigSource::default()).expect("test settings should load");
        settings.endpoint.issuer = "https://issuer.example".to_owned();
        settings.endpoint.frontend_base_url = "https://app.example".to_owned();
        settings.protocol.auth_code_ttl_seconds = 60;

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

    async fn restricted_valkey_client(
        &self,
        username: &str,
        password: &str,
        rules: Vec<String>,
    ) -> fred::prelude::Client {
        let mut args = vec!["SETUSER".to_owned(), username.to_owned()];
        args.extend(rules);
        self.state
            .valkey
            .custom::<(), _>(fred::cmd!("ACL"), args)
            .await
            .expect("restricted Valkey ACL user should be configured");
        let valkey_url = std::env::var("VALKEY_URL").expect("VALKEY_URL should be set");
        let restricted_url =
            valkey_url.replacen("redis://", &format!("redis://{username}:{password}@"), 1);
        let mut valkey_builder = ValkeyBuilder::from_config(
            ValkeyConfig::from_url(&restricted_url).expect("restricted VALKEY_URL should parse"),
        );
        valkey_builder.with_performance_config(|performance: &mut PerformanceConfig| {
            performance.default_command_timeout = StdDuration::from_millis(1000);
        });
        valkey_builder.with_connection_config(|connection: &mut ConnectionConfig| {
            connection.connection_timeout = StdDuration::from_millis(1000);
            connection.internal_command_timeout = StdDuration::from_millis(1000);
            connection.max_command_attempts = 1;
        });
        let valkey = valkey_builder
            .build()
            .expect("restricted Valkey client should build");
        valkey
            .init()
            .await
            .expect("restricted Valkey client should connect");
        valkey
    }

    fn state_with_valkey(&self, valkey: fred::prelude::Client) -> Data<TestAppState> {
        Data::new(TestAppState {
            diesel_db: self.state.diesel_db.clone(),
            valkey,
            settings: self.state.settings.clone(),
            keyset: self.state.keyset.clone(),
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

    async fn create_user(
        &self,
        suffix: &str,
        auth_role: &str,
        admin_level: i32,
    ) -> DatabaseUserFixture {
        let unique = Uuid::now_v7().simple();
        let email = format!("authorize-consent-{suffix}-{unique}@example.com");
        let username = format!("authorize-consent-{suffix}-{unique}");
        let mut conn = get_conn(&self.state.diesel_db)
            .await
            .expect("database connection");
        sql_query(
            r#"
            INSERT INTO users (
                tenant_id, realm_id, organization_id, username, email,
                password_hash, is_active, mfa_enabled, email_verified, role, admin_level
            )
            VALUES ($1, $2, $3, $4, $5, 'unused-consent-test-hash', true, false, true, $6, $7)
            RETURNING *
            "#,
        )
        .bind::<SqlUuid, _>(DEFAULT_TENANT_ID)
        .bind::<SqlUuid, _>(DEFAULT_REALM_ID)
        .bind::<SqlUuid, _>(DEFAULT_ORGANIZATION_ID)
        .bind::<Text, _>(username)
        .bind::<Text, _>(email)
        .bind::<Text, _>(auth_role.to_owned())
        .bind::<Int4, _>(admin_level)
        .get_result::<DatabaseUserFixture>(&mut conn)
        .await
        .expect("test user should insert")
    }

    async fn store_session(&self, user: &DatabaseUserFixture, sid: &str, auth_time: i64) {
        let payload = SessionPayload {
            user_id: user.id,
            auth_time,
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

    async fn store_consent_payload(&self, payload: &ConsentPayload) {
        valkey_set_ex(
            &self.state.valkey,
            format!("oauth:consent:{}", payload.request_id),
            serde_json::to_string(payload).expect("consent payload should serialize"),
            self.state.settings.protocol.auth_code_ttl_seconds,
        )
        .await
        .expect("consent payload should persist");
    }

    async fn store_raw_consent_payload(&self, request_id: &str, raw: &str) {
        valkey_set_ex(
            &self.state.valkey,
            format!("oauth:consent:{request_id}"),
            raw.to_owned(),
            self.state.settings.protocol.auth_code_ttl_seconds,
        )
        .await
        .expect("malformed consent payload should be written to valkey");
    }

    fn consent_request(&self, sid: &str, request_id: Option<&str>) -> TestRequest {
        let uri = if let Some(request_id) = request_id {
            format!("/authorize/consent?request_id={request_id}")
        } else {
            "/authorize/consent".to_owned()
        };
        TestRequest::get()
            .uri(&uri)
            .cookie(Cookie::new(
                self.state.settings.session.session_cookie_name.clone(),
                sid.to_owned(),
            ))
            .cookie(Cookie::new(
                self.state.settings.session.csrf_cookie_name.clone(),
                "csrf-token".to_owned(),
            ))
    }
}

async fn response_json(response: HttpResponse) -> (StatusCode, Value) {
    let status = response.status();
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("response body should be readable");
    let json = serde_json::from_slice(&body).expect("response should be json");
    (status, json)
}

#[test]
fn missing_or_malformed_consent_payload_fails_closed() {
    assert!(parse_consent_payload(None).is_none());
    assert!(parse_consent_payload(Some("not-json".to_owned())).is_none());
    assert!(parse_consent_payload(Some(r#"{"request_id":"req-123"}"#.to_owned())).is_none());
}

#[actix_web::test]
async fn missing_consent_state_returns_protocol_invalid_request_without_tokens() {
    let (status, body) = response_json(malformed_or_missing_consent_response()).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");
    assert_eq!(body["error_description"], "Request failed.");
    assert_ne!(
        body["error_description"],
        "授权请求不存在或已过期,请重新发起授权."
    );
    assert!(body.get("access_token").is_none());
    assert!(body.get("refresh_token").is_none());
    assert!(body.get("code").is_none());
}

#[actix_web::test]
async fn consent_payload_is_bound_to_current_user() {
    let current_user_id = uuid_fixture(0x11111111111111111111111111111111);
    let attacker_user_id = uuid_fixture(0x22222222222222222222222222222222);
    let payload = consent_payload(attacker_user_id);

    let err = validate_consent_payload_user(payload, current_user_id)
        .expect_err("payload owned by a different user must be rejected");
    let (status, body) = response_json(err).await;

    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"], "access_denied");
    assert_eq!(body["error_description"], "Request failed.");
    assert_ne!(body["error_description"], "当前会话与授权请求不匹配.");
    assert!(body.get("client_id").is_none());
    assert!(body.get("redirect_uri").is_none());
    assert!(body.get("request_id").is_none());
}

#[test]
fn matching_consent_payload_user_is_preserved_for_response_building() {
    let current_user_id = uuid_fixture(0x33333333333333333333333333333333);
    let payload = consent_payload(current_user_id);

    let validated = validate_consent_payload_user(payload.clone(), current_user_id)
        .expect("matching user should preserve the consent snapshot");

    assert_eq!(validated.request_id, payload.request_id);
    assert_eq!(validated.client_id, payload.client_id);
    assert_eq!(validated.redirect_uri, payload.redirect_uri);
    assert_eq!(validated.scopes, payload.scopes);
}

#[actix_web::test]
async fn consent_page_response_exposes_only_page_safe_fields() {
    let mut payload = consent_payload(uuid_fixture(0x44444444444444444444444444444444));
    payload.authorization_details = json!([
        {
            "type": "payment_initiation",
            "actions": ["write"],
            "instructedAmount": {
                "currency": "EUR",
                "amount": "123.45"
            },
            "creditorName": "Example Payee"
        }
    ]);

    let (status, body) = response_json(consent_page_response(
        payload,
        Some("csrf-token".to_owned()),
    ))
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["request_id"], "req-123");
    assert_eq!(body["client_id"], "client-a");
    assert_eq!(body["client_name"], "Client A");
    assert_eq!(body["redirect_uri"], "https://client.example/callback");
    assert_eq!(body["scopes"], json!(["openid", "profile"]));
    assert_eq!(body["userinfo_claims"], json!(["email"]));
    assert_eq!(body["id_token_claims"], json!(["auth_time"]));
    assert_eq!(
        body["authorization_details"],
        json!([
            {
                "type": "payment_initiation",
                "actions": ["write"],
                "instructedAmount": {
                    "currency": "EUR",
                    "amount": "123.45"
                },
                "creditorName": "Example Payee"
            }
        ])
    );
    assert_eq!(body["csrf_token"], "csrf-token");

    let object = body
        .as_object()
        .expect("consent response should be an object");
    assert_eq!(object.len(), 9);
    for forbidden in [
        "user_id",
        "state",
        "nonce",
        "auth_time",
        "amr",
        "oidc_sid",
        "acr",
        "code_challenge",
        "code_challenge_method",
        "dpop_jkt",
        "mtls_x5t_s256",
        "pushed_request_uri",
        "issued_at",
        "expires_at",
    ] {
        assert!(
            object.get(forbidden).is_none(),
            "{forbidden} must not be exposed to the browser consent page"
        );
    }
}

#[actix_web::test]
async fn authorize_consent_requires_login() {
    let state = TestAppState {
        diesel_db: create_pool(
            "postgres://nazo_consent_test_invalid:nazo_consent_test_invalid@127.0.0.1:1/nazo"
                .to_owned(),
            1,
        )
        .expect("pool construction should not connect"),
        valkey: ValkeyBuilder::default_centralized()
            .build()
            .expect("valkey client should construct"),
        settings: Arc::new(
            Settings::from_config(&ConfigSource::default()).expect("settings should load"),
        ),
        keyset: crate::test_support::test_key_manager(),
    };
    let state = Data::new(state);
    let req = TestRequest::get()
        .uri("/authorize/consent?request_id=req-login")
        .to_http_request();
    let (status, body) = response_json(
        authorize_consent(state, req, Query(query(&[("request_id", "req-login")]))).await,
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "login_required");
    assert_eq!(body["error_description"], "Request failed.");
}

#[actix_web::test]
async fn authorize_consent_fails_closed_when_session_user_lookup_fails() {
    let schema = format!("consent_user_lookup_failure_{}", Uuid::now_v7().simple());
    let Some(fixture) = ConsentLiveFixture::new_isolated(&schema).await else {
        return;
    };
    let user = fixture.create_user("lookup-failure", "user", 0).await;
    fixture
        .store_session(&user, "sid-user-lookup-failure", Utc::now().timestamp())
        .await;
    fixture
        .rename_column("users", "email", "email_broken")
        .await;

    let req = fixture
        .consent_request("sid-user-lookup-failure", Some("request-never-read"))
        .to_http_request();
    let response = authorize_consent(
        fixture.state.clone(),
        req,
        Query(query(&[("request_id", "request-never-read")])),
    )
    .await;
    let (status, body) = response_json(response).await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"], "server_error");
    fixture.cleanup().await;
}

#[actix_web::test]
async fn authorize_consent_fails_closed_when_consent_state_read_fails() {
    let Some(fixture) = ConsentLiveFixture::new().await else {
        return;
    };
    let user = fixture.create_user("consent-read-failure", "user", 0).await;
    let sid = format!("sid-consent-read-failure-{}", Uuid::now_v7());
    fixture
        .store_session(&user, &sid, Utc::now().timestamp())
        .await;
    let mut payload = consent_payload(user.id);
    payload.request_id = format!("request-consent-read-failure-{}", Uuid::now_v7());
    fixture.store_consent_payload(&payload).await;

    let username = format!("consent_read_failure_{}", Uuid::now_v7().simple());
    let password = format!("pw{}", Uuid::now_v7().simple());
    let restricted = fixture
        .restricted_valkey_client(
            &username,
            &password,
            vec![
                "reset".to_owned(),
                "on".to_owned(),
                format!(">{password}"),
                "~oauth:session:*".to_owned(),
                "+@all".to_owned(),
            ],
        )
        .await;
    let req = fixture
        .consent_request(&sid, Some(&payload.request_id))
        .to_http_request();
    let response = authorize_consent(
        fixture.state_with_valkey(restricted),
        req,
        Query(query(&[("request_id", payload.request_id.as_str())])),
    )
    .await;
    let (status, body) = response_json(response).await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"], "server_error");
    assert!(body.get("request_id").is_none());
    fixture.delete_acl_user(&username).await;
}

#[actix_web::test]
async fn authorize_consent_rejects_requests_without_request_id() {
    let Some(fixture) = ConsentLiveFixture::new().await else {
        return;
    };
    let user = fixture.create_user("missing-id", "user", 0).await;
    fixture
        .store_session(&user, "sid-no-request-id", Utc::now().timestamp())
        .await;
    let req = fixture
        .consent_request("sid-no-request-id", None)
        .to_http_request();
    let response =
        authorize_consent(fixture.state.clone(), req, Query(query(&[("foo", "bar")]))).await;
    let (status, body) = response_json(response).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");
}

#[actix_web::test]
async fn authorize_consent_rejects_missing_consent_payload() {
    let Some(fixture) = ConsentLiveFixture::new().await else {
        return;
    };
    let user = fixture.create_user("missing-payload", "user", 0).await;
    fixture
        .store_session(&user, "sid-missing-payload", Utc::now().timestamp())
        .await;
    let req = fixture
        .consent_request("sid-missing-payload", Some("request-missing"))
        .to_http_request();
    let response = authorize_consent(
        fixture.state.clone(),
        req,
        Query(query(&[("request_id", "request-missing")])),
    )
    .await;
    let (status, body) = response_json(response).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");
}

#[actix_web::test]
async fn authorize_consent_rejects_malformed_consent_payload() {
    let Some(fixture) = ConsentLiveFixture::new().await else {
        return;
    };
    let user = fixture.create_user("malformed-payload", "user", 0).await;
    fixture
        .store_session(&user, "sid-malformed-payload", Utc::now().timestamp())
        .await;
    fixture
        .store_raw_consent_payload("request-malformed", "not-json")
        .await;
    let req = fixture
        .consent_request("sid-malformed-payload", Some("request-malformed"))
        .to_http_request();
    let response = authorize_consent(
        fixture.state.clone(),
        req,
        Query(query(&[("request_id", "request-malformed")])),
    )
    .await;
    let (status, body) = response_json(response).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");
}

#[actix_web::test]
async fn authorize_consent_rejects_payload_owned_by_other_user() {
    let Some(fixture) = ConsentLiveFixture::new().await else {
        return;
    };
    let owner = fixture.create_user("payload-owner", "user", 0).await;
    let viewer = fixture.create_user("payload-viewer", "user", 0).await;
    fixture
        .store_session(&viewer, "sid-wrong-user", Utc::now().timestamp())
        .await;
    let mut payload = consent_payload(owner.id);
    payload.request_id = "request-other-user".to_owned();
    fixture.store_consent_payload(&payload).await;

    let req = fixture
        .consent_request("sid-wrong-user", Some("request-other-user"))
        .to_http_request();
    let response = authorize_consent(
        fixture.state.clone(),
        req,
        Query(query(&[("request_id", "request-other-user")])),
    )
    .await;
    let (status, body) = response_json(response).await;

    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"], "access_denied");
}

#[actix_web::test]
async fn authorize_consent_returns_payload_for_current_user() {
    let Some(fixture) = ConsentLiveFixture::new().await else {
        return;
    };
    let user = fixture.create_user("valid-owner", "user", 0).await;
    fixture
        .store_session(&user, "sid-valid-owner", Utc::now().timestamp())
        .await;
    let payload = consent_payload(user.id);
    fixture.store_consent_payload(&payload).await;
    let req = fixture
        .consent_request("sid-valid-owner", Some(&payload.request_id))
        .to_http_request();
    let response = authorize_consent(
        fixture.state.clone(),
        req,
        Query(query(&[("request_id", payload.request_id.as_str())])),
    )
    .await;
    let (status, body) = response_json(response).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["request_id"], payload.request_id);
    assert_eq!(body["client_id"], payload.client_id);
    assert_eq!(body["csrf_token"], "csrf-token");
}
