use actix_web::http::header::HeaderValue;
use actix_web::http::{StatusCode, header};
use nazo_http_actix::{
    authorization_error_response, bearer_challenge, bytes_response, empty_response,
    empty_response_no_store, is_oauth_error_description_byte, json_response_no_store,
    oauth_bearer_error, oauth_error, oauth_error_description, redirect_found,
    request_uses_form_urlencoded,
};
use proptest::prelude::*;
use serde_json::{Value, json};

#[test]
fn oauth_error_description_enforces_rfc_allowed_ascii() {
    assert_eq!(
        oauth_error_description("Authorization code has already been used.").as_ref(),
        "Authorization code has already been used."
    );
    assert_eq!(
        oauth_error_description("授权码已被使用.").as_ref(),
        "Request failed."
    );
    assert_eq!(
        oauth_error_description("invalid\\request").as_ref(),
        "Request failed."
    );
}

#[test]
fn bearer_error_preserves_and_sanitizes_challenge_fields() {
    let response = oauth_bearer_error(
        StatusCode::UNAUTHORIZED,
        "invalid_token",
        "Access token expired.",
    );
    assert_eq!(
        response.headers().get(header::WWW_AUTHENTICATE).unwrap(),
        HeaderValue::from_static(
            r#"Bearer error="invalid_token", error_description="Access token expired.""#
        )
    );

    let response = oauth_bearer_error(StatusCode::UNAUTHORIZED, "invalid_token", "访问令牌已失效.");
    assert_eq!(
        response.headers().get(header::WWW_AUTHENTICATE).unwrap(),
        HeaderValue::from_static(
            r#"Bearer error="invalid_token", error_description="Request failed.""#
        )
    );
}

#[actix_web::test]
async fn oauth_error_preserves_exact_body_and_existing_cache_contract() {
    let response = oauth_error(
        StatusCode::BAD_REQUEST,
        "invalid_grant",
        "Authorization code has expired.",
    );
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(response.headers().get(header::CACHE_CONTROL).is_none());
    assert!(response.headers().get(header::PRAGMA).is_none());
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("OAuth error body should collect");
    let body: Value = serde_json::from_slice(&body).expect("OAuth error should be JSON");
    assert_eq!(body["error"], "invalid_grant");
    assert_eq!(body["error_description"], "Authorization code has expired.");
    assert!(body.get("access_token").is_none());
    assert!(body.get("refresh_token").is_none());
}

#[actix_web::test]
async fn authorization_error_is_json_no_store_and_sanitized() {
    let response = authorization_error_response(
        StatusCode::BAD_REQUEST,
        "invalid_request",
        "redirect_uri 含有非法字符.",
    );
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    assert_eq!(response.headers().get(header::PRAGMA).unwrap(), "no-cache");
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/json"
    );
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("authorization error body should collect");
    let body: Value = serde_json::from_slice(&body).expect("authorization error should be JSON");
    assert_eq!(body["error"], "invalid_request");
    assert_eq!(body["error_description"], "Request failed.");
}

#[test]
fn form_detection_accepts_case_and_parameters_only() {
    let accepted = actix_web::test::TestRequest::default()
        .insert_header((
            header::CONTENT_TYPE,
            "Application/X-Www-Form-Urlencoded; charset=utf-8",
        ))
        .to_http_request();
    let rejected = actix_web::test::TestRequest::default()
        .insert_header((header::CONTENT_TYPE, "application/json"))
        .to_http_request();
    let missing = actix_web::test::TestRequest::default().to_http_request();
    assert!(request_uses_form_urlencoded(&accepted));
    assert!(!request_uses_form_urlencoded(&rejected));
    assert!(!request_uses_form_urlencoded(&missing));
}

#[test]
fn redirect_fails_closed_for_invalid_location_header() {
    let valid = redirect_found("https://client.example/cb?code=code-1".to_owned());
    assert_eq!(valid.status(), StatusCode::FOUND);
    assert_eq!(
        valid.headers().get(header::LOCATION).unwrap(),
        "https://client.example/cb?code=code-1"
    );

    let invalid = redirect_found("https://client.example/cb\nSet-Cookie: secret=1".to_owned());
    assert_eq!(invalid.status(), StatusCode::FOUND);
    assert!(invalid.headers().get(header::LOCATION).is_none());
}

#[actix_web::test]
async fn no_store_and_body_helpers_preserve_transport_shapes() {
    let json = json_response_no_store(json!({"active": false}));
    assert_eq!(
        json.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    assert_eq!(json.headers().get(header::PRAGMA).unwrap(), "no-cache");

    let empty = empty_response_no_store(StatusCode::NO_CONTENT);
    assert_eq!(empty.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        empty.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );

    let bytes = bytes_response(b"public-key-material".to_vec());
    let body = actix_web::body::to_bytes(bytes.into_body())
        .await
        .expect("bytes response should collect");
    assert_eq!(body.as_ref(), b"public-key-material");

    let empty = empty_response(StatusCode::ACCEPTED);
    let body = actix_web::body::to_bytes(empty.into_body())
        .await
        .expect("empty response should collect");
    assert!(body.is_empty());
}

proptest! {
    #[test]
    fn oauth_descriptions_preserve_only_rfc_allowed_ascii(
        allowed in "[\\t\\n\\r !#-\\[\\]-~]{0,128}",
        disallowed in "[^\\t\\n\\r !#-\\[\\]-~]{1,32}"
    ) {
        let allowed_description = oauth_error_description(&allowed);
        let disallowed_description = oauth_error_description(&disallowed);
        prop_assert_eq!(allowed_description.as_ref(), allowed.as_str());
        prop_assert_eq!(disallowed_description.as_ref(), "Request failed.");
    }

    #[test]
    fn bearer_challenge_never_serializes_non_ascii_descriptions(
        error in "[a-z_]{1,32}",
        description in "\\PC{1,64}"
    ) {
        let challenge = bearer_challenge(&error, &description);
        let rendered = challenge.to_str().expect("challenge should be an HTTP header value");
        if description.bytes().all(is_oauth_error_description_byte) {
            let expected = format!(r#"error_description="{}""#, description);
            prop_assert!(rendered.contains(&expected));
        } else {
            prop_assert!(rendered.contains(r#"error_description="Request failed.""#));
        }
    }
}
