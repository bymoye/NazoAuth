use super::*;
use actix_web::cookie::Cookie;
use actix_web::test::TestRequest;
use diesel::QueryableByName;
use diesel::sql_query;
use diesel::sql_types::{Bool, Int4, Jsonb, Text, Uuid as SqlUuid};
use diesel_async::RunQueryDsl;
use fred::interfaces::ClientLike;
use fred::prelude::{
    Builder as ValkeyBuilder, Config as ValkeyConfig, ConnectionConfig, PerformanceConfig,
};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration as StdDuration;

use crate::config::ConfigSource;
use nazo_postgres::{create_pool, get_conn};

use crate::http::authorization::par::pushed_authorization_request_key;

async fn authorize_decision(
    state: Data<TestAppState>,
    req: HttpRequest,
    Form(form): Form<DecisionForm>,
) -> HttpResponse {
    let dependencies = crate::http::authorization::TestAuthorizationDependencies::new(&state);
    authorize_decision_with_context(&dependencies.context(), req, form).await
}

fn decision_state() -> TestAppState {
    let mut settings =
        Settings::from_config(&ConfigSource::default()).expect("default settings should load");
    settings.endpoint.issuer = "https://issuer.example".to_owned();
    settings.protocol.auth_code_ttl_seconds = 60;

    TestAppState {
        diesel_db: create_pool(
            "postgres://nazo_authorize_test_invalid:nazo_authorize_test_invalid@127.0.0.1:1/nazo"
                .to_owned(),
            1,
        )
        .expect("pool construction should not connect"),
        valkey: fred::prelude::Builder::default_centralized()
            .build()
            .expect("valkey client construction should not connect"),
        settings: Arc::new(settings),
        keyset: crate::test_support::test_key_manager(),
    }
}

fn consent_payload() -> ConsentPayload {
    let now = Utc::now();
    ConsentPayload {
        request_id: "request-1".to_owned(),
        user_id: Uuid::now_v7(),
        client_id: "client-1".to_owned(),
        client_name: "Client".to_owned(),
        redirect_uri: "https://client.example/callback?existing=1".to_owned(),
        redirect_uri_was_supplied: true,
        scopes: vec!["openid".to_owned()],
        resource_indicators: Vec::new(),
        authorization_details: json!([]),
        state: Some("opaque-state".to_owned()),
        response_mode: None,
        nonce: Some("nonce-1".to_owned()),
        auth_time: now.timestamp(),
        amr: vec!["pwd".to_owned()],
        oidc_sid: None,
        acr: None,
        userinfo_claims: Vec::new(),
        userinfo_claim_requests: Vec::new(),
        id_token_claims: Vec::new(),
        id_token_claim_requests: Vec::new(),
        code_challenge: Some("challenge".to_owned()),
        code_challenge_method: Some("S256".to_owned()),
        dpop_jkt: None,
        mtls_x5t_s256: None,
        pushed_request_uri: None,
        pushed_request_digest: None,
        issued_at: now,
        expires_at: now + Duration::seconds(60),
    }
}

fn consent_payload_for_user(client_id: &str, user_id: Uuid) -> ConsentPayload {
    let now = Utc::now();
    ConsentPayload {
        request_id: format!("request-{}", Uuid::now_v7()),
        user_id,
        client_id: client_id.to_owned(),
        client_name: "Client".to_owned(),
        redirect_uri: "https://client.example/callback".to_owned(),
        redirect_uri_was_supplied: true,
        scopes: vec!["openid".to_owned()],
        resource_indicators: Vec::new(),
        authorization_details: json!([]),
        state: Some("test-state".to_owned()),
        response_mode: None,
        nonce: Some("nonce-1".to_owned()),
        auth_time: now.timestamp(),
        amr: vec!["pwd".to_owned()],
        oidc_sid: Some("session-oidc".to_owned()),
        acr: None,
        userinfo_claims: Vec::new(),
        userinfo_claim_requests: Vec::new(),
        id_token_claims: Vec::new(),
        id_token_claim_requests: Vec::new(),
        code_challenge: Some("challenge".to_owned()),
        code_challenge_method: Some("S256".to_owned()),
        dpop_jkt: None,
        mtls_x5t_s256: None,
        pushed_request_uri: None,
        pushed_request_digest: None,
        issued_at: now,
        expires_at: now + Duration::seconds(60),
    }
}

fn database_url_with_search_path(schema: &str) -> Option<String> {
    let base = std::env::var("DATABASE_URL").ok()?;
    let separator = if base.contains('?') { "&" } else { "?" };
    Some(format!(
        "{base}{separator}options=-csearch_path%3D{schema}%2Cpublic"
    ))
}

#[derive(Clone)]
struct DecisionLiveFixture {
    state: Data<TestAppState>,
    schema: Option<String>,
}

impl DecisionLiveFixture {
    async fn new() -> Option<Self> {
        let database_url = std::env::var("DATABASE_URL").ok()?;
        Self::from_database_url(database_url, None).await
    }

    async fn new_isolated(schema: &str) -> Option<Self> {
        let database_url = database_url_with_search_path(schema)?;
        let fixture = Self::from_database_url(database_url, Some(schema.to_owned())).await?;
        fixture
            .create_isolated_schema(&["users", "oauth_clients", "user_client_grants"])
            .await;
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
            .expect("database connection should open");
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
        let email = format!("authorize-decision-{suffix}-{unique}@example.com");
        let username = format!("authorize-decision-{suffix}-{unique}");
        let mut conn = get_conn(&self.state.diesel_db)
            .await
            .expect("database connection should open");
        sql_query(
            r#"
            INSERT INTO users (
                tenant_id, realm_id, organization_id, username, email,
                password_hash, is_active, mfa_enabled, email_verified, role, admin_level
            )
            VALUES ($1, $2, $3, $4, $5, 'unused-authorize-test-hash', true, false, true, $6, $7)
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

    async fn insert_client(&self, client_id: &str, is_active: bool) {
        let mut conn = get_conn(&self.state.diesel_db)
            .await
            .expect("database connection should open");
        sql_query("DELETE FROM oauth_clients WHERE tenant_id = $1 AND client_id = $2")
            .bind::<SqlUuid, _>(DEFAULT_TENANT_ID)
            .bind::<Text, _>(client_id)
            .execute(&mut conn)
            .await
            .expect("test client cleanup should succeed");

        sql_query(
            r#"
            INSERT INTO oauth_clients (
                tenant_id, realm_id, organization_id, client_id, client_name, client_type,
                client_secret_hash, redirect_uris, scopes, allowed_audiences,
                grant_types, token_endpoint_auth_method, require_dpop_bound_tokens,
                require_mtls_bound_tokens, tls_client_auth_subject_dn, tls_client_auth_cert_sha256,
                tls_client_auth_san_dns, tls_client_auth_san_uri, tls_client_auth_san_ip,
                tls_client_auth_san_email, allow_client_assertion_audience_array,
                allow_client_assertion_endpoint_audience, require_par_request_object,
                allow_authorization_code_without_pkce, is_active,
                post_logout_redirect_uris, backchannel_logout_session_required
            )
            VALUES (
                $1, $2, $3, $4, 'Authorization Test Client', 'confidential',
                NULL, '["https://client.example/callback"]'::jsonb, '["openid","profile"]'::jsonb, '["resource://default"]'::jsonb,
                '["authorization_code"]'::jsonb, 'client_secret_basic', false,
                false, NULL, NULL,
                '[]'::jsonb, '[]'::jsonb,
                '[]'::jsonb, '[]'::jsonb,
                false,
                false, false,
                true, $5,
                '[]'::jsonb, true
            )
            "#,
        )
        .bind::<SqlUuid, _>(DEFAULT_TENANT_ID)
        .bind::<SqlUuid, _>(DEFAULT_REALM_ID)
        .bind::<SqlUuid, _>(DEFAULT_ORGANIZATION_ID)
        .bind::<Text, _>(client_id)
        .bind::<Bool, _>(is_active)
        .execute(&mut conn)
        .await
        .expect("test client insert should succeed");
    }

    async fn store_session(&self, user: &DatabaseUserFixture, sid: &str, auth_time: i64) {
        let payload = crate::http::sessions::SessionPayload {
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

    async fn store_raw_pushed_request(&self, request_uri: &str, raw: &str) {
        valkey_set_ex(
            &self.state.valkey,
            pushed_authorization_request_key(request_uri),
            raw.to_owned(),
            60,
        )
        .await
        .expect("raw PAR payload should persist");
    }

    fn auth_request(&self, sid: &str, csrf_token: Option<&str>) -> HttpRequest {
        let mut request = TestRequest::post().uri("/authorize/decision");
        request = request.cookie(Cookie::new(
            self.state.settings.session.session_cookie_name.clone(),
            sid.to_owned(),
        ));
        request = request.cookie(Cookie::new(
            self.state.settings.session.csrf_cookie_name.clone(),
            "csrf-session-token".to_owned(),
        ));
        if let Some(csrf_token) = csrf_token {
            request = request.insert_header(("x-csrf-token", csrf_token.to_owned()));
        }
        request.to_http_request()
    }
}

fn redirect_location(response: &HttpResponse) -> url::Url {
    let location = response
        .headers()
        .get(header::LOCATION)
        .expect("authorization response should redirect")
        .to_str()
        .expect("Location header should be valid UTF-8");
    url::Url::parse(location).expect("redirect location should remain absolute")
}

async fn json_error(response: HttpResponse) -> (StatusCode, Value) {
    let status = response.status();
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("response body should be readable");
    let value = serde_json::from_slice(&body).expect("response should return JSON");
    (status, value)
}

#[test]
fn authorization_decision_is_explicit_allowlist() {
    assert!(matches!(
        parse_authorization_decision("approve"),
        Some(AuthorizationDecision::Approve)
    ));
    assert!(matches!(
        parse_authorization_decision("deny"),
        Some(AuthorizationDecision::Deny)
    ));
    assert!(parse_authorization_decision("anything-else").is_none());
    assert!(parse_authorization_decision(" approve ").is_none());
}

#[test]
fn missing_or_malformed_consent_payload_is_rejected() {
    assert!(parse_consent_payload(None).is_none());
    assert!(parse_consent_payload(Some("not-json".to_owned())).is_none());
    assert!(parse_consent_payload(Some(r#"{"request_id":1}"#.to_owned())).is_none());
}

#[actix_web::test]
async fn denied_authorization_redirect_preserves_state_without_issuing_code() {
    let state = decision_state();
    let payload = consent_payload();
    let response = authorization_error_redirect(&state, &payload, "access_denied").await;

    assert_eq!(response.status(), StatusCode::FOUND);
    let parsed = redirect_location(&response);
    let pairs = parsed.query_pairs().into_owned().collect::<HashMap<_, _>>();

    assert_eq!(parsed.scheme(), "https");
    assert_eq!(
        pairs.get("error").map(String::as_str),
        Some("access_denied")
    );
    assert_eq!(pairs.get("state").map(String::as_str), Some("opaque-state"));
    assert_eq!(
        pairs.get("iss").map(String::as_str),
        Some("https://issuer.example")
    );
    assert!(
        !pairs.contains_key("code"),
        "authorization denial must never include an authorization code"
    );
}

#[actix_web::test]
async fn approved_authorization_redirect_omits_error_and_carries_only_the_new_code() {
    let state = decision_state();
    let response = authorization_response_redirect(
        &state,
        AuthorizationResponseRedirect {
            redirect_uri: "https://client.example/callback",
            client_id: "client-1",
            response_mode: None,
            code: Some("code-1"),
            error: None,
            state: Some("opaque-state"),
            oidc_sid: None,
        },
    )
    .await;

    assert_eq!(response.status(), StatusCode::FOUND);
    let parsed = redirect_location(&response);
    let pairs = parsed.query_pairs().into_owned().collect::<HashMap<_, _>>();

    assert_eq!(pairs.get("code").map(String::as_str), Some("code-1"));
    assert_eq!(pairs.get("state").map(String::as_str), Some("opaque-state"));
    assert_eq!(
        pairs.get("iss").map(String::as_str),
        Some("https://issuer.example")
    );
    assert!(
        !pairs.contains_key("error"),
        "successful authorization redirect must not include stale error state"
    );
}

#[actix_web::test]
async fn authorization_decision_requires_authentication_without_session() {
    let state = Data::new(decision_state());
    let form = DecisionForm {
        request_id: "request-no-session".to_owned(),
        decision: "approve".to_owned(),
        csrf_token: None,
    };
    let req = TestRequest::post()
        .uri("/authorize/decision")
        .to_http_request();
    let (status, body) = json_error(authorize_decision(state, req, Form(form)).await).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "login_required");
}

#[actix_web::test]
async fn authorization_decision_rejects_invalid_csrf_token_with_session_cookie() {
    let state = decision_state();
    let session_cookie = state.settings.session.session_cookie_name.clone();
    let csrf_cookie = state.settings.session.csrf_cookie_name.clone();
    let req = TestRequest::post()
        .uri("/authorize/decision")
        .cookie(Cookie::new(session_cookie, "sid-csrf-1"))
        .cookie(Cookie::new(csrf_cookie, "csrf-cookie"))
        .to_http_request();
    let form = DecisionForm {
        request_id: "request-1".to_owned(),
        decision: "approve".to_owned(),
        csrf_token: Some("csrf-body-mismatch".to_owned()),
    };
    let response = authorize_decision(Data::new(state), req, Form(form)).await;
    let (status, body) = json_error(response).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");
}

#[actix_web::test]
async fn authorization_decision_rejects_invalid_decision_after_auth() {
    let Some(fixture) = DecisionLiveFixture::new().await else {
        return;
    };
    let user = fixture.create_user("invalid-decision", "user", 0).await;
    fixture
        .store_session(&user, "sid-invalid-decision", Utc::now().timestamp())
        .await;
    let req = fixture.auth_request("sid-invalid-decision", Some("csrf-session-token"));
    let form = DecisionForm {
        request_id: "request-1".to_owned(),
        decision: "unexpected".to_owned(),
        csrf_token: None,
    };

    let (status, body) =
        json_error(authorize_decision(fixture.state.clone(), req, Form(form)).await).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");
}

#[actix_web::test]
async fn authorization_decision_rejects_missing_consent_payload_with_valid_session() {
    let Some(fixture) = DecisionLiveFixture::new().await else {
        return;
    };
    let user = fixture.create_user("missing-payload", "user", 0).await;
    fixture
        .store_session(&user, "sid-missing-payload", Utc::now().timestamp())
        .await;
    let req = fixture.auth_request("sid-missing-payload", Some("csrf-session-token"));
    let form = DecisionForm {
        request_id: "request-does-not-exist".to_owned(),
        decision: "approve".to_owned(),
        csrf_token: None,
    };
    let (status, body) =
        json_error(authorize_decision(fixture.state.clone(), req, Form(form)).await).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");
}

#[actix_web::test]
async fn authorization_decision_rejects_request_if_user_not_match() {
    let Some(fixture) = DecisionLiveFixture::new().await else {
        return;
    };
    let owner = fixture.create_user("mismatch-owner", "user", 0).await;
    let other = fixture.create_user("mismatch-other", "user", 0).await;
    fixture
        .store_session(&owner, "sid-user-mismatch", Utc::now().timestamp())
        .await;
    let payload = consent_payload_for_user("client-1", other.id);
    fixture.store_consent_payload(&payload).await;
    let req = fixture.auth_request("sid-user-mismatch", Some("csrf-session-token"));
    let form = DecisionForm {
        request_id: payload.request_id.clone(),
        decision: "approve".to_owned(),
        csrf_token: None,
    };

    let (status, body) =
        json_error(authorize_decision(fixture.state.clone(), req, Form(form)).await).await;

    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"], "access_denied");
}

#[actix_web::test]
async fn authorization_decision_fails_closed_when_consent_state_read_fails() {
    let Some(fixture) = DecisionLiveFixture::new().await else {
        return;
    };
    let user = fixture.create_user("consent-read-failure", "user", 0).await;
    let sid = format!("sid-consent-read-failure-{}", Uuid::now_v7());
    fixture
        .store_session(&user, &sid, Utc::now().timestamp())
        .await;
    let payload = consent_payload_for_user("client-1", user.id);
    fixture.store_consent_payload(&payload).await;

    let username = format!("decision_read_failure_{}", Uuid::now_v7().simple());
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
    let req = fixture.auth_request(&sid, Some("csrf-session-token"));
    let form = DecisionForm {
        request_id: payload.request_id.clone(),
        decision: "approve".to_owned(),
        csrf_token: None,
    };

    let response = authorize_decision(fixture.state_with_valkey(restricted), req, Form(form)).await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let (status, body) = json_error(response).await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"], "server_error");
    assert!(
        body.get("code").is_none(),
        "consent state read failures must not issue authorization codes"
    );
    fixture.delete_acl_user(&username).await;
}

#[actix_web::test]
async fn authorization_decision_fails_closed_when_consent_state_consume_fails() {
    let Some(fixture) = DecisionLiveFixture::new().await else {
        return;
    };
    let user = fixture
        .create_user("consent-consume-failure", "user", 0)
        .await;
    let sid = format!("sid-consent-consume-failure-{}", Uuid::now_v7());
    fixture
        .store_session(&user, &sid, Utc::now().timestamp())
        .await;
    let client_id = format!("client-consent-consume-failure-{}", Uuid::now_v7());
    fixture.insert_client(&client_id, true).await;
    let payload = consent_payload_for_user(&client_id, user.id);
    fixture.store_consent_payload(&payload).await;

    let username = format!("decision_consume_failure_{}", Uuid::now_v7().simple());
    let password = format!("pw{}", Uuid::now_v7().simple());
    let restricted = fixture
        .restricted_valkey_client(
            &username,
            &password,
            vec![
                "reset".to_owned(),
                "on".to_owned(),
                format!(">{password}"),
                "~oauth:*".to_owned(),
                "+@all".to_owned(),
                "-eval".to_owned(),
            ],
        )
        .await;
    let req = fixture.auth_request(&sid, Some("csrf-session-token"));
    let form = DecisionForm {
        request_id: payload.request_id.clone(),
        decision: "approve".to_owned(),
        csrf_token: None,
    };

    let response = authorize_decision(fixture.state_with_valkey(restricted), req, Form(form)).await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let (status, body) = json_error(response).await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"], "server_error");
    assert!(
        body.get("code").is_none(),
        "consent state consume failures must not issue authorization codes"
    );
    fixture.delete_acl_user(&username).await;
}

#[actix_web::test]
async fn authorization_decision_rejects_malformed_consent_payload() {
    let Some(fixture) = DecisionLiveFixture::new().await else {
        return;
    };
    let user = fixture.create_user("bad-consent-json", "user", 0).await;
    let sid = format!("sid-bad-consent-{}", Uuid::now_v7());
    fixture
        .store_session(&user, &sid, Utc::now().timestamp())
        .await;
    valkey_set_ex(
        &fixture.state.valkey,
        "oauth:consent:malformed-request",
        "not-valid-json",
        60,
    )
    .await
    .expect("malformed consent payload should store");
    let req = fixture.auth_request(&sid, Some("csrf-session-token"));
    let form = DecisionForm {
        request_id: "malformed-request".to_owned(),
        decision: "approve".to_owned(),
        csrf_token: None,
    };
    let (status, body) =
        json_error(authorize_decision(fixture.state.clone(), req, Form(form)).await).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");
}

#[actix_web::test]
async fn authorization_decision_rejects_request_with_invalid_pushed_request_uri() {
    let Some(fixture) = DecisionLiveFixture::new().await else {
        return;
    };
    let user = fixture.create_user("pushed-missing", "user", 0).await;
    fixture
        .store_session(&user, "sid-pushed-missing", Utc::now().timestamp())
        .await;

    let payload = ConsentPayload {
        pushed_request_uri: Some("urn:ietf:params:oauth:request_uri:missing".to_owned()),
        ..consent_payload_for_user("client-1", user.id)
    };
    fixture.store_consent_payload(&payload).await;
    let req = fixture.auth_request("sid-pushed-missing", Some("csrf-session-token"));
    let form = DecisionForm {
        request_id: payload.request_id.clone(),
        decision: "approve".to_owned(),
        csrf_token: None,
    };
    let response = authorize_decision(fixture.state.clone(), req, Form(form)).await;

    let location = redirect_location(&response);
    let pairs = location
        .query_pairs()
        .into_owned()
        .collect::<HashMap<_, _>>();
    assert_eq!(
        pairs.get("error").map(String::as_str),
        Some("invalid_request_uri")
    );
}

#[actix_web::test]
async fn authorization_decision_rejects_malformed_consumed_par_without_issuing_code() {
    let Some(fixture) = DecisionLiveFixture::new().await else {
        return;
    };
    let user = fixture.create_user("pushed-malformed", "user", 0).await;
    fixture
        .store_session(&user, "sid-pushed-malformed", Utc::now().timestamp())
        .await;

    let request_uri = format!(
        "urn:ietf:params:oauth:request_uri:malformed-{}",
        Uuid::now_v7()
    );
    let payload = ConsentPayload {
        pushed_request_uri: Some(request_uri.clone()),
        ..consent_payload_for_user("client-1", user.id)
    };
    fixture.store_consent_payload(&payload).await;
    fixture
        .store_raw_pushed_request(&request_uri, "not-json")
        .await;

    let req = fixture.auth_request("sid-pushed-malformed", Some("csrf-session-token"));
    let form = DecisionForm {
        request_id: payload.request_id.clone(),
        decision: "approve".to_owned(),
        csrf_token: None,
    };
    let response = authorize_decision(fixture.state.clone(), req, Form(form)).await;

    assert_eq!(response.status(), StatusCode::FOUND);
    let pairs = redirect_location(&response)
        .query_pairs()
        .into_owned()
        .collect::<HashMap<_, _>>();
    assert_eq!(pairs.get("error").map(String::as_str), Some("server_error"));
    assert!(
        !pairs.contains_key("code"),
        "malformed consumed PAR state must not result in an authorization code"
    );
}

#[actix_web::test]
async fn authorization_decision_accepts_deny_with_user_match() {
    let Some(fixture) = DecisionLiveFixture::new().await else {
        return;
    };
    let user = fixture.create_user("decision-deny", "user", 0).await;
    fixture
        .store_session(&user, "sid-decision-deny", Utc::now().timestamp())
        .await;
    let payload = consent_payload_for_user("client-1", user.id);
    fixture.store_consent_payload(&payload).await;
    let req = fixture.auth_request("sid-decision-deny", Some("csrf-session-token"));
    let form = DecisionForm {
        request_id: payload.request_id.clone(),
        decision: "deny".to_owned(),
        csrf_token: None,
    };

    let response = authorize_decision(fixture.state.clone(), req, Form(form)).await;
    assert_eq!(response.status(), StatusCode::FOUND);
    let pairs = redirect_location(&response)
        .query_pairs()
        .into_owned()
        .collect::<HashMap<_, _>>();
    assert_eq!(
        pairs.get("error").map(String::as_str),
        Some("access_denied")
    );
    assert!(!pairs.contains_key("code"));
}

#[actix_web::test]
async fn authorization_decision_issues_code_for_matching_user_and_client() {
    let Some(fixture) = DecisionLiveFixture::new().await else {
        return;
    };
    let user = fixture.create_user("decision-approve", "user", 0).await;
    let client_id = format!("client-decision-approve-{}", Uuid::now_v7());
    fixture.insert_client(&client_id, true).await;
    fixture
        .store_session(&user, "sid-decision-approve", Utc::now().timestamp())
        .await;
    let mut payload = consent_payload_for_user(&client_id, user.id);
    payload.resource_indicators = vec!["resource://default".to_owned()];
    fixture.store_consent_payload(&payload).await;

    let req = fixture.auth_request("sid-decision-approve", Some("csrf-session-token"));
    let form = DecisionForm {
        request_id: payload.request_id.clone(),
        decision: "approve".to_owned(),
        csrf_token: None,
    };

    let response = authorize_decision(fixture.state.clone(), req, Form(form)).await;
    assert_eq!(response.status(), StatusCode::FOUND);
    let pairs = redirect_location(&response)
        .query_pairs()
        .into_owned()
        .collect::<HashMap<_, _>>();
    assert!(pairs.contains_key("code"));
    assert!(pairs.contains_key("iss"));
    assert!(!pairs.contains_key("error"));

    let mut conn = get_conn(&fixture.state.diesel_db)
        .await
        .expect("database connection should open");
    let stored_resources = sql_query(
        r#"
        SELECT grants.last_resource_indicators
        FROM user_client_grants grants
        JOIN oauth_clients clients ON clients.id = grants.client_id
        WHERE grants.user_id = $1 AND clients.client_id = $2
        "#,
    )
    .bind::<SqlUuid, _>(user.id)
    .bind::<Text, _>(client_id)
    .get_result::<GrantResourceIndicators>(&mut conn)
    .await
    .expect("grant resource indicators should be persisted");
    assert_eq!(
        stored_resources.last_resource_indicators,
        json!(["resource://default"])
    );
}

#[derive(QueryableByName)]
struct GrantResourceIndicators {
    #[diesel(sql_type = Jsonb)]
    last_resource_indicators: Value,
}

#[actix_web::test]
async fn authorization_decision_fails_closed_when_authorization_code_store_fails() {
    let Some(fixture) = DecisionLiveFixture::new().await else {
        return;
    };
    let user = fixture.create_user("code-store-failure", "user", 0).await;
    let client_id = "client-decision-code-store-failure";
    fixture.insert_client(client_id, true).await;
    let sid = format!("sid-code-store-failure-{}", Uuid::now_v7());
    fixture
        .store_session(&user, &sid, Utc::now().timestamp())
        .await;
    let payload = consent_payload_for_user(client_id, user.id);
    fixture.store_consent_payload(&payload).await;

    let username = format!("decision_code_store_failure_{}", Uuid::now_v7().simple());
    let password = format!("pw{}", Uuid::now_v7().simple());
    let restricted = fixture
        .restricted_valkey_client(
            &username,
            &password,
            vec![
                "reset".to_owned(),
                "on".to_owned(),
                format!(">{password}"),
                "~oauth:*".to_owned(),
                "+@all".to_owned(),
                "-set".to_owned(),
            ],
        )
        .await;
    let req = fixture.auth_request(&sid, Some("csrf-session-token"));
    let form = DecisionForm {
        request_id: payload.request_id.clone(),
        decision: "approve".to_owned(),
        csrf_token: None,
    };

    let response = authorize_decision(fixture.state_with_valkey(restricted), req, Form(form)).await;
    let (status, body) = json_error(response).await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"], "server_error");
    assert!(
        body.get("code").is_none(),
        "authorization code store failures must not expose a redeemable code"
    );
    fixture.delete_acl_user(&username).await;
}

#[actix_web::test]
async fn authorization_decision_fails_closed_when_grant_persistence_fails() {
    let schema = format!("decision_grant_failure_{}", Uuid::now_v7().simple());
    let Some(fixture) = DecisionLiveFixture::new_isolated(&schema).await else {
        return;
    };

    let user = fixture.create_user("grant-failure", "user", 0).await;
    let client_id = "client-decision-grant-failure";
    fixture.insert_client(client_id, true).await;
    fixture
        .rename_column(
            "user_client_grants",
            "authorization_count",
            "authorization_count_broken",
        )
        .await;
    fixture
        .store_session(&user, "sid-grant-failure", Utc::now().timestamp())
        .await;
    let payload = consent_payload_for_user(client_id, user.id);
    fixture.store_consent_payload(&payload).await;

    let req = fixture.auth_request("sid-grant-failure", Some("csrf-session-token"));
    let form = DecisionForm {
        request_id: payload.request_id.clone(),
        decision: "approve".to_owned(),
        csrf_token: None,
    };

    let response = authorize_decision(fixture.state.clone(), req, Form(form)).await;
    let (status, body) = json_error(response).await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"], "server_error");
    assert!(
        body.get("code").is_none(),
        "grant persistence failure must not expose a redeemable authorization code"
    );
    fixture.cleanup().await;
}
