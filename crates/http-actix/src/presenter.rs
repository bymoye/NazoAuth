use std::borrow::Cow;

use actix_web::{
    HttpResponse,
    http::{
        StatusCode,
        header::{self, HeaderValue},
    },
};
use serde::Serialize;
use serde_json::json;

#[derive(Clone)]
pub struct OAuthJsonErrorFields {
    pub error: String,
}

pub fn oauth_error(status: StatusCode, error: &str, description: &str) -> HttpResponse {
    let description = oauth_error_description(description);
    let mut response = json_response_status(
        status,
        json!({"error": error, "error_description": description}),
    );
    response.extensions_mut().insert(OAuthJsonErrorFields {
        error: error.to_owned(),
    });
    response
}

pub fn authorization_error_response(
    status: StatusCode,
    error: &str,
    description: &str,
) -> HttpResponse {
    no_store(oauth_error(status, error, description))
}

pub fn oauth_token_error(
    status: StatusCode,
    error: &str,
    description: &str,
    basic_challenge: bool,
) -> HttpResponse {
    let description = oauth_error_description(description);
    let mut response = no_store(oauth_error(status, error, &description));
    if basic_challenge {
        response.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            HeaderValue::from_static(r#"Basic realm="nazo-oauth""#),
        );
    }
    response
}

pub fn oauth_bearer_error(status: StatusCode, error: &str, description: &str) -> HttpResponse {
    let mut response = oauth_error(status, error, description);
    response.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        bearer_challenge(error, description),
    );
    response
}

pub fn redirect_found(location: String) -> HttpResponse {
    let mut response = empty_response(StatusCode::FOUND);
    if let Ok(value) = HeaderValue::from_str(&location) {
        response.headers_mut().insert(header::LOCATION, value);
    }
    response
}

pub fn json_response<T: Serialize>(body: T) -> HttpResponse {
    HttpResponse::Ok().json(body)
}

pub fn json_response_status<T: Serialize>(status: StatusCode, body: T) -> HttpResponse {
    HttpResponse::build(status).json(body)
}

pub fn json_response_no_store<T: Serialize>(body: T) -> HttpResponse {
    no_store(json_response(body))
}

pub fn json_response_status_no_store<T: Serialize>(status: StatusCode, body: T) -> HttpResponse {
    no_store(json_response_status(status, body))
}

pub fn empty_response_no_store(status: StatusCode) -> HttpResponse {
    no_store(empty_response(status))
}

pub fn bytes_response(body: Vec<u8>) -> HttpResponse {
    HttpResponse::Ok().body(body)
}

pub fn empty_response(status: StatusCode) -> HttpResponse {
    HttpResponse::build(status).finish()
}

fn no_store(mut response: HttpResponse) -> HttpResponse {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    response
}

#[doc(hidden)]
pub fn bearer_challenge(error: &str, description: &str) -> HeaderValue {
    let description = oauth_error_description(description);
    HeaderValue::from_str(&format!(
        r#"Bearer error="{}", error_description="{}""#,
        oauth_challenge_param(error),
        oauth_challenge_param(&description)
    ))
    .unwrap_or_else(|_| HeaderValue::from_static("Bearer"))
}

#[doc(hidden)]
pub fn oauth_error_description(description: &str) -> Cow<'_, str> {
    if description.bytes().all(is_oauth_error_description_byte) {
        Cow::Borrowed(description)
    } else {
        Cow::Borrowed("Request failed.")
    }
}

fn oauth_challenge_param(value: &str) -> Cow<'_, str> {
    if value.bytes().all(is_oauth_error_description_byte) {
        Cow::Borrowed(value)
    } else {
        Cow::Borrowed("Request failed.")
    }
}

#[doc(hidden)]
pub fn is_oauth_error_description_byte(byte: u8) -> bool {
    matches!(
        byte,
        0x09 | 0x0A | 0x0D | 0x20..=0x21 | 0x23..=0x5B | 0x5D..=0x7E
    )
}

#[cfg(test)]
#[path = "../tests/unit/presenter.rs"]
mod tests;
