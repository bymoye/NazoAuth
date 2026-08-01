use actix_web::cookie::Cookie;
use actix_web::http::{StatusCode, header};
use serde_json::Value;

use super::*;

#[test]
fn csrf_validation_is_required_only_for_existing_sessions() {
    let anonymous = actix_web::test::TestRequest::default().to_http_request();
    assert!(has_valid_csrf_token_for_cookies(
        &anonymous, None, "session", "csrf"
    ));

    let matching_header = actix_web::test::TestRequest::default()
        .cookie(Cookie::new("session", "sid-1"))
        .cookie(Cookie::new("csrf", "csrf-1"))
        .insert_header(("x-csrf-token", " csrf-1 "))
        .to_http_request();
    assert!(has_valid_csrf_token_for_cookies(
        &matching_header,
        None,
        "session",
        "csrf"
    ));

    let matching_fallback = actix_web::test::TestRequest::default()
        .cookie(Cookie::new("session", "sid-1"))
        .cookie(Cookie::new("csrf", "csrf-1"))
        .to_http_request();
    assert!(has_valid_csrf_token_for_cookies(
        &matching_fallback,
        Some("csrf-1"),
        "session",
        "csrf"
    ));

    let missing_csrf = actix_web::test::TestRequest::default()
        .cookie(Cookie::new("session", "sid-1"))
        .to_http_request();
    assert!(!has_valid_csrf_token_for_cookies(
        &missing_csrf,
        Some("csrf-1"),
        "session",
        "csrf"
    ));

    let mismatched = actix_web::test::TestRequest::default()
        .cookie(Cookie::new("session", "sid-1"))
        .cookie(Cookie::new("csrf", "csrf-1"))
        .insert_header(("x-csrf-token", "attacker-token"))
        .to_http_request();
    assert!(!has_valid_csrf_token_for_cookies(
        &mismatched,
        None,
        "session",
        "csrf"
    ));
}

#[test]
fn token_comparison_matches_only_equal_bytes() {
    assert!(constant_time_eq(b"csrf-token", b"csrf-token"));
    assert!(!constant_time_eq(b"csrf-token", b"csrf-tokee"));
    assert!(!constant_time_eq(b"csrf-token", b"short"));
}

#[actix_web::test]
async fn csrf_error_preserves_status_body_and_cache_headers() {
    let response = csrf_error();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(response.headers().get(header::CACHE_CONTROL).is_none());
    assert!(response.headers().get(header::PRAGMA).is_none());
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("CSRF error body should collect");
    let body: Value = serde_json::from_slice(&body).expect("CSRF error must be JSON");
    assert_eq!(body["error"], "invalid_request");
    assert_eq!(body["error_description"], "Request failed.");
}
