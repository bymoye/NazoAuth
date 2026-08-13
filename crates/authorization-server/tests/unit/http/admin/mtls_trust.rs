use super::{normalized_decision_note, sha256_hex};

use actix_web::{HttpRequest, test::TestRequest, web};
use nazo_postgres::create_pool;
use std::sync::Arc;
use std::time::Duration;

use crate::config::ConfigSource;
use crate::http::sessions::test_support::admin_session_handles;
use crate::settings::Settings;
use crate::test_support::TestInfrastructure;

fn unavailable_valkey_client() -> fred::prelude::Client {
    let mut builder = fred::prelude::Builder::from_config(
        fred::prelude::Config::from_url("redis://127.0.0.1:1")
            .expect("unavailable Valkey URL should parse"),
    );
    builder.with_performance_config(|performance: &mut fred::prelude::PerformanceConfig| {
        performance.default_command_timeout = Duration::from_millis(200);
    });
    builder.with_connection_config(|connection: &mut fred::prelude::ConnectionConfig| {
        connection.connection_timeout = Duration::from_millis(200);
        connection.internal_command_timeout = Duration::from_millis(200);
        connection.max_command_attempts = 1;
    });
    builder
        .build()
        .expect("unavailable Valkey client construction should not connect")
}

fn test_state() -> TestInfrastructure {
    TestInfrastructure {
        diesel_db: create_pool(
            "postgres://nazo_mtls_trust_test_invalid:nazo_mtls_trust_test_invalid@127.0.0.1:1/nazo"
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

fn request_with_session_cookie(state: &TestInfrastructure) -> HttpRequest {
    TestRequest::default()
        .cookie(actix_web::cookie::Cookie::new(
            state.settings.session.session_cookie_name.clone(),
            "missing-session",
        ))
        .to_http_request()
}

#[test]
fn trust_decision_notes_are_bounded_and_rejections_require_a_reason() {
    assert_eq!(
        normalized_decision_note(Some("  reviewed  ".to_owned()), true)
            .expect("bounded approval note"),
        Some("reviewed".to_owned())
    );
    assert_eq!(
        normalized_decision_note(Some("  ".to_owned()), true).expect("empty approval note"),
        None
    );
    assert!(normalized_decision_note(None, false).is_err());
    assert!(normalized_decision_note(Some("x".repeat(1001)), true).is_err());
    assert!(normalized_decision_note(Some("x".repeat(1001)), false).is_err());
    assert_eq!(
        normalized_decision_note(Some("x".repeat(1000)), true)
            .expect("exactly bounded approval note"),
        Some("x".repeat(1000))
    );
}

#[test]
fn trust_bundle_digest_is_stable_and_redaction_safe() {
    assert_eq!(
        sha256_hex(b"certificate-bundle"),
        "8935d3d68f48b1f04e6a881317b91f734e45a10e7d13fd44873a4c4e8285d78f"
    );
    assert!(!sha256_hex(b"certificate-bundle").contains("certificate-bundle"));
}

#[actix_web::test]
async fn mtls_trust_handlers_fail_closed_before_touching_storage_for_anonymous_requests() {
    let state = test_state();
    let sessions = web::Data::new(admin_session_handles(&state));
    let service = web::Data::new(super::MtlsTrustAnchorService::new(state.diesel_db.clone()));
    let anonymous = TestRequest::default().to_http_request();

    let list = super::admin_mtls_trust_requests(
        sessions.clone(),
        service.clone(),
        anonymous.clone(),
        web::Query(std::collections::HashMap::new()),
    )
    .await;
    assert_eq!(list.status(), actix_web::http::StatusCode::FORBIDDEN);

    let approve = super::admin_approve_mtls_trust_request(
        sessions.clone(),
        service.clone(),
        anonymous.clone(),
        web::Path::from(uuid::Uuid::now_v7()),
        web::Json(serde_json::from_value(serde_json::json!({})).unwrap()),
    )
    .await;
    assert_eq!(approve.status(), actix_web::http::StatusCode::FORBIDDEN);

    let reject = super::admin_reject_mtls_trust_request(
        sessions.clone(),
        service.clone(),
        anonymous.clone(),
        web::Path::from(uuid::Uuid::now_v7()),
        web::Json(serde_json::from_value(serde_json::json!({})).unwrap()),
    )
    .await;
    assert_eq!(reject.status(), actix_web::http::StatusCode::FORBIDDEN);

    let revoke = super::admin_revoke_mtls_trust_anchor(
        sessions.clone(),
        service.clone(),
        anonymous.clone(),
        web::Path::from(uuid::Uuid::now_v7()),
        web::Json(
            serde_json::from_value(serde_json::json!({
                "reason": "operator decision"
            }))
            .unwrap(),
        ),
    )
    .await;
    assert_eq!(revoke.status(), actix_web::http::StatusCode::FORBIDDEN);

    let bundle = super::admin_mtls_trust_bundle(sessions, service, anonymous).await;
    assert_eq!(bundle.status(), actix_web::http::StatusCode::FORBIDDEN);
}

#[actix_web::test]
async fn mtls_trust_mutations_reject_missing_csrf_before_admin_lookup() {
    let state = test_state();
    let sessions = web::Data::new(admin_session_handles(&state));
    let service = web::Data::new(super::MtlsTrustAnchorService::new(state.diesel_db.clone()));
    let request = request_with_session_cookie(&state);
    let response = super::admin_approve_mtls_trust_request(
        sessions,
        service,
        request,
        web::Path::from(uuid::Uuid::now_v7()),
        web::Json(serde_json::from_value(serde_json::json!({})).unwrap()),
    )
    .await;

    assert_eq!(response.status(), actix_web::http::StatusCode::BAD_REQUEST);
}
