use actix_web::{
    HttpRequest, HttpResponse,
    error::InternalError,
    http::{
        Method,
        header::{self, HeaderMap},
    },
};
use serde_json::json;

use crate::{authorization_error_response, json_response_no_store};

pub fn mfa_json_config() -> actix_web::web::JsonConfig {
    actix_web::web::JsonConfig::default().error_handler(|_, _| {
        InternalError::from_response(
            "invalid MFA JSON payload",
            authorization_error_response(
                actix_web::http::StatusCode::BAD_REQUEST,
                "invalid_request",
                "MFA request body is invalid.",
            ),
        )
        .into()
    })
}

pub async fn mfa_options() -> HttpResponse {
    json_response_no_store(json!({"status": "ok"}))
}

pub async fn mfa_method_not_allowed() -> HttpResponse {
    authorization_error_response(
        actix_web::http::StatusCode::METHOD_NOT_ALLOWED,
        "invalid_request",
        "HTTP method is not allowed.",
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccessTokenAuthScheme {
    Bearer,
    DPoP,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ResourceAccessToken {
    Present(AccessTokenAuthScheme, String),
    Missing,
    InvalidRequest,
}

pub fn authorization_access_token(headers: &HeaderMap) -> Option<(AccessTokenAuthScheme, String)> {
    let raw = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let mut parts = raw.splitn(2, char::is_whitespace);
    let scheme = parts.next()?.trim();
    let token = parts.next()?.trim();
    if token.is_empty() || token.split_whitespace().count() != 1 {
        return None;
    }
    if scheme.eq_ignore_ascii_case("DPoP") {
        return Some((AccessTokenAuthScheme::DPoP, token.to_owned()));
    }
    if scheme.eq_ignore_ascii_case("Bearer") {
        return Some((AccessTokenAuthScheme::Bearer, token.to_owned()));
    }
    None
}

pub fn resource_access_token(
    request: &HttpRequest,
    body: &[u8],
    http_signatures_enabled: bool,
) -> ResourceAccessToken {
    let header_token = authorization_access_token(request.headers());
    let body_token = resource_form_body_access_token(request, body);
    if http_signatures_enabled && !matches!(&body_token, FormBodyAccessToken::Missing) {
        return ResourceAccessToken::InvalidRequest;
    }
    match (header_token, body_token) {
        (Some(_), FormBodyAccessToken::Present(_)) => ResourceAccessToken::InvalidRequest,
        (Some((scheme, token)), _) => ResourceAccessToken::Present(scheme, token),
        (None, FormBodyAccessToken::Present(token)) => {
            ResourceAccessToken::Present(AccessTokenAuthScheme::Bearer, token)
        }
        (None, FormBodyAccessToken::Missing) => ResourceAccessToken::Missing,
        (None, FormBodyAccessToken::InvalidRequest) => ResourceAccessToken::InvalidRequest,
    }
}

enum FormBodyAccessToken {
    Present(String),
    Missing,
    InvalidRequest,
}

fn resource_form_body_access_token(request: &HttpRequest, body: &[u8]) -> FormBodyAccessToken {
    if request.method() != Method::POST || body.is_empty() || !request_uses_form_urlencoded(request)
    {
        return FormBodyAccessToken::Missing;
    }
    let mut access_token = None;
    for (key, value) in url::form_urlencoded::parse(body) {
        if key == "access_token" {
            if access_token.is_some() {
                return FormBodyAccessToken::InvalidRequest;
            }
            let token = value.into_owned();
            if token.trim().is_empty() {
                return FormBodyAccessToken::Missing;
            }
            access_token = Some(token);
        }
    }
    access_token
        .map(FormBodyAccessToken::Present)
        .unwrap_or(FormBodyAccessToken::Missing)
}

pub fn request_uses_form_urlencoded(request: &HttpRequest) -> bool {
    request
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .split(';')
        .next()
        .is_some_and(|value| {
            value
                .trim()
                .eq_ignore_ascii_case("application/x-www-form-urlencoded")
        })
}

#[cfg(test)]
mod tests {
    use actix_web::{http::header, test::TestRequest};

    use super::{
        AccessTokenAuthScheme, ResourceAccessToken, request_uses_form_urlencoded,
        resource_access_token,
    };

    fn assert_present(
        actual: ResourceAccessToken,
        expected_scheme: AccessTokenAuthScheme,
        expected_token: &str,
    ) {
        let ResourceAccessToken::Present(scheme, token) = actual else {
            panic!("expected a presented access token");
        };
        assert_eq!(scheme, expected_scheme);
        assert_eq!(token, expected_token);
    }

    #[test]
    fn form_content_type_is_case_insensitive_and_accepts_parameters() {
        let request = TestRequest::default()
            .insert_header((
                header::CONTENT_TYPE,
                "Application/X-WWW-Form-Urlencoded; charset=utf-8",
            ))
            .to_http_request();
        assert!(request_uses_form_urlencoded(&request));

        let request = TestRequest::default()
            .insert_header((header::CONTENT_TYPE, "application/json"))
            .to_http_request();
        assert!(!request_uses_form_urlencoded(&request));
    }

    #[test]
    fn access_token_transport_rejects_duplicates_and_signed_form_transport() {
        let request = TestRequest::post()
            .insert_header((header::AUTHORIZATION, "Bearer header-token"))
            .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
            .to_http_request();
        assert_eq!(
            super::resource_access_token(&request, b"access_token=body-token", false),
            super::ResourceAccessToken::InvalidRequest
        );

        let request = TestRequest::post()
            .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
            .to_http_request();
        assert_eq!(
            super::resource_access_token(&request, b"access_token=body-token", true),
            super::ResourceAccessToken::InvalidRequest
        );
    }

    #[test]
    fn bearer_and_dpop_authorization_schemes_are_case_insensitive() {
        for (raw, expected) in [
            ("bearer token", super::AccessTokenAuthScheme::Bearer),
            ("dpop token", super::AccessTokenAuthScheme::DPoP),
        ] {
            let request = TestRequest::default()
                .insert_header((header::AUTHORIZATION, raw))
                .to_http_request();
            assert_eq!(
                super::authorization_access_token(request.headers()),
                Some((expected, "token".to_owned()))
            );
        }
    }

    #[test]
    fn form_access_token_accepts_one_value_and_content_type_parameters() {
        for content_type in [
            "application/x-www-form-urlencoded",
            "application/x-www-form-urlencoded; charset=utf-8",
        ] {
            let request = TestRequest::post()
                .insert_header((header::CONTENT_TYPE, content_type))
                .to_http_request();
            assert_present(
                resource_access_token(&request, b"access_token=token-1", false),
                AccessTokenAuthScheme::Bearer,
                "token-1",
            );
        }
    }

    #[test]
    fn form_access_token_requires_post_and_form_content_type() {
        for request in [
            TestRequest::post().to_http_request(),
            TestRequest::post()
                .insert_header((header::CONTENT_TYPE, "application/json"))
                .to_http_request(),
            TestRequest::get()
                .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
                .to_http_request(),
        ] {
            assert_eq!(
                resource_access_token(&request, b"access_token=token-1", false),
                ResourceAccessToken::Missing
            );
        }
    }

    #[test]
    fn form_access_token_rejects_duplicates_and_treats_blank_as_missing() {
        let request = TestRequest::post()
            .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
            .to_http_request();
        assert_eq!(
            resource_access_token(
                &request,
                b"access_token=token-1&access_token=token-2",
                false,
            ),
            ResourceAccessToken::InvalidRequest
        );
        assert_eq!(
            resource_access_token(&request, b"access_token=%20%20%09", false),
            ResourceAccessToken::Missing
        );
    }

    #[test]
    fn form_access_token_ignores_unrelated_fields() {
        let request = TestRequest::post()
            .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
            .to_http_request();
        assert_eq!(
            resource_access_token(&request, b"scope=openid&token_type=Bearer", false),
            ResourceAccessToken::Missing
        );
    }

    #[test]
    fn query_access_token_is_not_a_supported_transport() {
        let request = TestRequest::get()
            .uri("/resource?access_token=query-token")
            .to_http_request();
        assert_eq!(
            resource_access_token(&request, &[], false),
            ResourceAccessToken::Missing
        );
    }

    #[test]
    fn authorization_header_wins_only_when_form_transport_is_absent() {
        let request = TestRequest::post()
            .insert_header((header::AUTHORIZATION, "Bearer header-token"))
            .insert_header((header::CONTENT_TYPE, "application/json"))
            .to_http_request();
        assert_present(
            resource_access_token(&request, b"access_token=body-token", false),
            AccessTokenAuthScheme::Bearer,
            "header-token",
        );

        let request = TestRequest::post()
            .insert_header((header::AUTHORIZATION, "Bearer header-token"))
            .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
            .to_http_request();
        assert_eq!(
            resource_access_token(&request, b"access_token=body-token", false),
            ResourceAccessToken::InvalidRequest
        );
    }
}
