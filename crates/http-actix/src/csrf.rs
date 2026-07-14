use actix_web::http::StatusCode;
use actix_web::{HttpRequest, HttpResponse};

use crate::{cookie_value, oauth_error};

#[must_use]
pub fn csrf_error() -> HttpResponse {
    oauth_error(
        StatusCode::BAD_REQUEST,
        "invalid_request",
        "CSRF 校验失败，请刷新页面后重试。",
    )
}

#[must_use]
pub fn has_valid_csrf_token_for_cookies(
    req: &HttpRequest,
    fallback_token: Option<&str>,
    session_cookie_name: &str,
    csrf_cookie_name: &str,
) -> bool {
    if cookie_value(req, session_cookie_name).is_none() {
        return true;
    }
    let header_token = req
        .headers()
        .get("x-csrf-token")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .or_else(|| {
            fallback_token
                .map(str::trim)
                .filter(|value| !value.is_empty())
        });
    let Some(header_token) = header_token else {
        return false;
    };
    let Some(cookie_token) = cookie_value(req, csrf_cookie_name) else {
        return false;
    };
    constant_time_eq(header_token.as_bytes(), cookie_token.trim().as_bytes())
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right.iter())
        .fold(0u8, |acc, (a, b)| acc | (a ^ b))
        == 0
}

#[cfg(test)]
mod tests {
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
}
