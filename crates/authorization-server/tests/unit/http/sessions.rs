use super::*;
use nazo_http_actix::OAuthJsonErrorFields;
use std::sync::Arc;

use crate::config::ConfigSource;
use crate::settings::Settings;
use crate::test_support::TestInfrastructure;
use crate::test_support::valkey::{valkey_get, valkey_set_ex};
use actix_web::http::header;
use nazo_postgres::create_pool;
use serde_json::{Value, json};

use actix_web::test::TestRequest;
use fred::interfaces::ClientLike;
use fred::prelude::{
    Builder as ValkeyBuilder, Config as ValkeyConfig, ConnectionConfig, PerformanceConfig,
};
use std::time::Duration as StdDuration;

fn valid_payload() -> SessionPayload {
    SessionPayload {
        user_id: Uuid::now_v7(),
        auth_time: 1_000,
        amr: vec!["password".to_owned()],
        pending_mfa: false,
        oidc_sid: Some("sid-1".to_owned()),
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

fn session_state() -> TestInfrastructure {
    TestInfrastructure {
        diesel_db: create_pool(
            "postgres://nazo_session_test_invalid:nazo_session_test_invalid@127.0.0.1:1/nazo"
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

async fn live_session_state() -> Option<TestInfrastructure> {
    let valkey_url = std::env::var("VALKEY_URL").ok()?;
    let mut state = session_state();
    let mut builder =
        ValkeyBuilder::from_config(ValkeyConfig::from_url(&valkey_url).expect("VALKEY_URL"));
    builder.with_performance_config(|performance: &mut PerformanceConfig| {
        performance.default_command_timeout = StdDuration::from_millis(1000);
    });
    builder.with_connection_config(|connection: &mut ConnectionConfig| {
        connection.connection_timeout = StdDuration::from_millis(1000);
        connection.internal_command_timeout = StdDuration::from_millis(1000);
        connection.max_command_attempts = 1;
    });
    let valkey = builder.build().expect("valkey client should build");
    valkey.init().await.expect("valkey should connect");
    state.valkey = valkey;
    Some(state)
}

fn session_request(state: &TestInfrastructure, sid: &str) -> HttpRequest {
    TestRequest::default()
        .cookie(actix_web::cookie::Cookie::new(
            state.settings.session.session_cookie_name.clone(),
            sid.to_owned(),
        ))
        .to_http_request()
}

async fn store_raw_session(state: &TestInfrastructure, sid: &str, raw: &str) {
    valkey_set_ex(
        &state.valkey,
        format!("oauth:session:{sid}"),
        raw.to_owned(),
        state.settings.session.session_ttl_seconds,
    )
    .await
    .expect("raw session payload should store");
}

#[test]
fn session_payload_requires_authentication_metadata_and_oidc_sid() {
    let valid = valid_payload();

    assert!(valid_session_payload(&valid, 1_001));
    assert!(!valid_session_payload(
        &SessionPayload {
            oidc_sid: None,
            ..valid.clone()
        },
        1_001
    ));
    assert!(!valid_session_payload(
        &SessionPayload {
            oidc_sid: Some(" ".to_owned()),
            ..valid.clone()
        },
        1_001
    ));
    assert!(!valid_session_payload(
        &SessionPayload {
            auth_time: 0,
            ..valid.clone()
        },
        1_001
    ));
    assert!(!valid_session_payload(
        &SessionPayload {
            auth_time: 2_000,
            ..valid.clone()
        },
        1_001
    ));
    assert!(!valid_session_payload(
        &SessionPayload {
            amr: Vec::new(),
            ..valid
        },
        1_001
    ));
}

#[test]
fn session_payload_allows_only_small_clock_skew_for_auth_time() {
    let mut payload = valid_payload();

    payload.auth_time = 1_030;
    assert!(valid_session_payload(&payload, 1_000));

    payload.auth_time = 1_031;
    assert!(!valid_session_payload(&payload, 1_000));
}

#[test]
fn session_payload_preserves_pending_mfa_as_metadata_not_validity() {
    let mut payload = valid_payload();
    payload.pending_mfa = true;

    assert!(valid_session_payload(&payload, 1_001));
}

#[test]
fn session_payload_requires_non_blank_oidc_sid_after_trimming() {
    for sid in ["", " ", "\t\n"] {
        let mut payload = valid_payload();
        payload.oidc_sid = Some(sid.to_owned());

        assert!(
            !valid_session_payload(&payload, 1_001),
            "blank sid {sid:?} must not produce an OIDC session"
        );
    }
}

fn oauth_error_code(response: &HttpResponse) -> String {
    response
        .extensions()
        .get::<OAuthJsonErrorFields>()
        .map(|fields| fields.error.clone())
        .expect("OAuth error response should record its error code")
}

#[test]
fn session_lookup_failures_are_server_errors_without_auth_material() {
    let response = session_lookup_error_response(anyhow::anyhow!("database unavailable"));

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(oauth_error_code(&response), "server_error");
    assert!(
        response.headers().get(header::WWW_AUTHENTICATE).is_none(),
        "backend session failures must not be exposed as client credentials challenges"
    );
}

#[actix_web::test]
async fn missing_session_cookie_is_anonymous_without_backend_lookup() {
    let state = session_state();
    let req = TestRequest::default().to_http_request();
    let sessions = test_support::admin_session_handles(&state);

    assert!(
        sessions
            .current_session(&req)
            .await
            .expect("missing cookie should not hit storage")
            .is_none()
    );
}

#[actix_web::test]
async fn missing_session_key_is_anonymous_even_when_cookie_is_present() {
    let Some(state) = live_session_state().await else {
        return;
    };
    let sid = format!("missing-session-{}", Uuid::now_v7());
    let req = session_request(&state, &sid);
    let sessions = test_support::admin_session_handles(&state);

    assert!(
        sessions
            .current_session(&req)
            .await
            .expect("missing session key should not be a backend failure")
            .is_none()
    );
}

#[actix_web::test]
async fn invalid_or_malformed_session_payloads_are_cleared_and_anonymous() {
    let Some(state) = live_session_state().await else {
        return;
    };
    let sessions = test_support::admin_session_handles(&state);

    let invalid_sid = format!("invalid-session-{}", Uuid::now_v7());
    let invalid_payload = SessionPayload {
        oidc_sid: None,
        ..valid_payload()
    };
    store_raw_session(
        &state,
        &invalid_sid,
        &serde_json::to_string(&invalid_payload).expect("invalid payload should serialize"),
    )
    .await;
    let invalid_req = session_request(&state, &invalid_sid);
    assert!(
        sessions
            .current_session(&invalid_req)
            .await
            .expect("invalid session payload should be handled")
            .is_none()
    );
    assert_eq!(
        valkey_get(&state.valkey, format!("oauth:session:{invalid_sid}"))
            .await
            .expect("invalid session cleanup lookup should succeed"),
        None
    );

    let invalid_pending_sid = format!("invalid-pending-mfa-{}", Uuid::now_v7());
    let invalid_pending_payload = SessionPayload {
        pending_mfa: true,
        oidc_sid: None,
        ..valid_payload()
    };
    store_raw_session(
        &state,
        &invalid_pending_sid,
        &serde_json::to_string(&invalid_pending_payload)
            .expect("invalid pending MFA payload should serialize"),
    )
    .await;
    let invalid_pending_req = session_request(&state, &invalid_pending_sid);
    assert!(
        sessions
            .current_session(&invalid_pending_req)
            .await
            .expect("invalid pending MFA payload should be handled")
            .is_none()
    );
    assert_eq!(
        valkey_get(
            &state.valkey,
            format!("oauth:session:{invalid_pending_sid}")
        )
        .await
        .expect("invalid pending MFA cleanup lookup should succeed"),
        None
    );

    let malformed_sid = format!("malformed-pending-mfa-{}", Uuid::now_v7());
    store_raw_session(&state, &malformed_sid, "not-json").await;
    let malformed_req = session_request(&state, &malformed_sid);
    assert!(
        sessions
            .current_session(&malformed_req)
            .await
            .expect("malformed pending MFA payload should be handled")
            .is_none()
    );
    assert_eq!(
        valkey_get(&state.valkey, format!("oauth:session:{malformed_sid}"))
            .await
            .expect("malformed pending MFA cleanup lookup should succeed"),
        None
    );
}

#[actix_web::test]
async fn missing_session_cookie_requires_login_or_admin_denial_without_storage_lookup() {
    let state = session_state();
    let req = TestRequest::default().to_http_request();
    let sessions = test_support::admin_session_handles(&state);

    let login = sessions
        .current_user_or_login_required(&req)
        .await
        .expect_err("anonymous user must be challenged to log in");
    assert_eq!(login.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(oauth_error_code(&login), "login_required");
    assert!(
        login.headers().get(header::SET_COOKIE).is_some(),
        "login-required response must clear stale session cookies"
    );
    assert!(login.headers().get(header::WWW_AUTHENTICATE).is_none());

    let forbidden = require_admin_or_forbidden_with_handles(&sessions, &req)
        .await
        .expect_err("anonymous user must not receive admin access");
    assert_eq!(forbidden.status(), StatusCode::FORBIDDEN);
    assert!(forbidden.headers().get(header::WWW_AUTHENTICATE).is_none());
    let body = actix_web::body::to_bytes(forbidden.into_body())
        .await
        .expect("forbidden response body should collect");
    let value: Value = serde_json::from_slice(&body).expect("OAuth error body should be JSON");
    assert_eq!(value.get("error"), Some(&json!("access_denied")));
}

#[actix_web::test]
async fn admin_gate_propagates_session_lookup_failures_as_server_errors() {
    let state = session_state();
    let req = session_request(&state, "session-backend-unavailable");
    let sessions = test_support::admin_session_handles(&state);

    let response = require_admin_or_forbidden_with_handles(&sessions, &req)
        .await
        .expect_err("backend session lookup failure must not become access_denied");

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(oauth_error_code(&response), "server_error");
    assert!(response.headers().get(header::WWW_AUTHENTICATE).is_none());
}
