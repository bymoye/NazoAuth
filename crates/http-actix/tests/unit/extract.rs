use actix_web::{http::header, test::TestRequest};

use super::{
    AccessTokenAuthScheme, ResourceAccessToken, request_uses_form_urlencoded, resource_access_token,
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
