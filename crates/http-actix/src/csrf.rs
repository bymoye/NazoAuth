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
#[path = "../tests/unit/csrf.rs"]
mod tests;
