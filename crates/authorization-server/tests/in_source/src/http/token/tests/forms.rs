use super::*;
use actix_web::test::TestRequest;
use proptest::prelude::*;

fn form_request() -> HttpRequest {
    TestRequest::default()
        .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
        .to_http_request()
}

fn token_management_form_with_client_auth() -> TokenOnlyForm {
    TokenOnlyForm {
        token: "token-1".to_owned(),
        token_type_hint: None,
        client_id: Some("client-1".to_owned()),
        client_secret: None,
        client_assertion_type: None,
        client_assertion: None,
    }
}

async fn response_json(response: HttpResponse) -> serde_json::Value {
    let body = actix_web::body::to_bytes(response.into_body())
        .await
        .expect("response body should collect");
    serde_json::from_slice(&body).expect("response body should be JSON")
}

#[test]
fn token_form_requires_form_content_type() {
    let req = TestRequest::default()
        .insert_header((header::CONTENT_TYPE, "application/json"))
        .to_http_request();

    let result = parse_token_form(&req, &Bytes::from_static(b"grant_type=client_credentials"));

    assert!(matches!(result, Err(TokenFormError::InvalidContentType)));
}

#[test]
fn token_form_accepts_form_content_type_with_charset() {
    let req = TestRequest::default()
        .insert_header((
            header::CONTENT_TYPE,
            "application/x-www-form-urlencoded; charset=utf-8",
        ))
        .to_http_request();

    let form = parse_token_form(&req, &Bytes::from_static(b"grant_type=client_credentials"))
        .expect("form content type parameters are allowed by RFC 6749");

    assert_eq!(form.grant_type, "client_credentials");
}

#[test]
fn token_form_rejects_invalid_utf8_before_parsing_parameters() {
    let req = form_request();

    let result = parse_token_form(&req, &Bytes::from_static(b"grant_type=\xff"));

    assert!(matches!(result, Err(TokenFormError::InvalidEncoding)));
}

#[test]
fn token_form_requires_non_empty_grant_type() {
    let req = form_request();

    let missing = parse_token_form(&req, &Bytes::from_static(b"client_id=client-1"));
    let empty = parse_token_form(&req, &Bytes::from_static(b"grant_type=%20%20"));

    assert!(matches!(missing, Err(TokenFormError::MissingGrantType)));
    assert!(matches!(empty, Err(TokenFormError::MissingGrantType)));
}

#[test]
fn token_form_maps_empty_optional_credentials_to_absent_values() {
    let req = form_request();

    let form = parse_token_form(
        &req,
        &Bytes::from_static(
            b"grant_type=authorization_code&code=&redirect_uri=&code_verifier=&client_id=&client_secret=&client_assertion_type=&client_assertion=&audience=",
        ),
    )
    .expect("empty optional values should not create credentials");

    assert_eq!(form.grant_type, "authorization_code");
    assert!(form.code.is_none());
    assert!(form.redirect_uri.is_none());
    assert!(form.code_verifier.is_none());
    assert!(form.client_id.is_none());
    assert!(form.client_secret.is_none());
    assert!(form.client_assertion_type.is_none());
    assert!(form.client_assertion.is_none());
    assert!(form.audiences.is_empty());
}

#[test]
fn token_form_extracts_authorization_code_exchange_fields_without_reordering() {
    let req = form_request();

    let form = parse_token_form(
        &req,
        &Bytes::from_static(
            b"grant_type=authorization_code&code=code-1&redirect_uri=https%3A%2F%2Fclient.example%2Fcb&code_verifier=verifier-1&scope=openid%20profile&client_id=client-1&client_secret=secret-1",
        ),
    )
    .expect("well-formed token request should parse");

    assert_eq!(form.grant_type, "authorization_code");
    assert_eq!(form.code.as_deref(), Some("code-1"));
    assert_eq!(
        form.redirect_uri.as_deref(),
        Some("https://client.example/cb")
    );
    assert_eq!(form.code_verifier.as_deref(), Some("verifier-1"));
    assert_eq!(form.scope.as_deref(), Some("openid profile"));
    assert_eq!(form.client_id.as_deref(), Some("client-1"));
    assert_eq!(form.client_secret.as_deref(), Some("secret-1"));
}

#[test]
fn token_form_extracts_jwt_bearer_grant_assertion_separately_from_client_assertion() {
    let req = form_request();

    let form = parse_token_form(
        &req,
        &Bytes::from_static(
            b"grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=grant-jwt&client_assertion=client-auth-jwt",
        ),
    )
    .expect("JWT bearer grant assertion should parse");

    assert_eq!(
        form.grant_type,
        "urn:ietf:params:oauth:grant-type:jwt-bearer"
    );
    assert_eq!(form.assertion.as_deref(), Some("grant-jwt"));
    assert_eq!(form.client_assertion.as_deref(), Some("client-auth-jwt"));
}

#[test]
fn token_form_extracts_device_code_grant_field_separately_from_authorization_code() {
    let req = form_request();

    let form = parse_token_form(
        &req,
        &Bytes::from_static(
            b"grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code&device_code=device-code-1&code=authorization-code-1",
        ),
    )
    .expect("device_code grant request should parse");

    assert_eq!(
        form.grant_type,
        "urn:ietf:params:oauth:grant-type:device_code"
    );
    assert_eq!(form.device_code.as_deref(), Some("device-code-1"));
    assert_eq!(form.code.as_deref(), Some("authorization-code-1"));
}

#[test]
fn token_form_extracts_native_sso_device_secret() {
    let req = form_request();

    let form = parse_token_form(
        &req,
        &Bytes::from_static(
            b"grant_type=authorization_code&code=code-1&device_secret=device-secret-1",
        ),
    )
    .expect("Native SSO device_secret should parse");

    assert_eq!(form.device_secret.as_deref(), Some("device-secret-1"));
}

#[test]
fn token_form_rejects_duplicate_defined_parameters() {
    let req = TestRequest::default()
        .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
        .to_http_request();

    let result = parse_token_form(
        &req,
        &Bytes::from_static(b"grant_type=authorization_code&grant_type=refresh_token"),
    );

    assert!(matches!(result, Err(TokenFormError::DuplicateParameter)));
}

#[test]
fn token_form_rejects_duplicate_device_secret() {
    let req = form_request();

    let result = parse_token_form(
        &req,
        &Bytes::from_static(b"grant_type=authorization_code&device_secret=a&device_secret=b"),
    );

    assert!(matches!(result, Err(TokenFormError::DuplicateParameter)));
}

#[test]
fn token_form_ignores_unknown_parameters() {
    let req = TestRequest::default()
        .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
        .to_http_request();

    let form = parse_token_form(
        &req,
        &Bytes::from_static(b"grant_type=client_credentials&unknown=a"),
    )
    .unwrap();

    assert_eq!(form.grant_type, "client_credentials");
}

#[test]
fn token_form_accepts_standard_resource_parameter_as_audience() {
    let req = TestRequest::default()
        .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
        .to_http_request();

    let form = parse_token_form(
        &req,
        &Bytes::from_static(
            b"grant_type=client_credentials&resource=https%3A%2F%2Fapi.example.com",
        ),
    )
    .unwrap();

    assert_eq!(form.audiences, vec!["https://api.example.com"]);
}

#[test]
fn token_form_accepts_multiple_resource_parameters_as_audiences() {
    let req = TestRequest::default()
        .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
        .to_http_request();

    let form = parse_token_form(
        &req,
        &Bytes::from_static(
            b"grant_type=client_credentials&resource=https%3A%2F%2Fapi.example.com&resource=https%3A%2F%2Fpayments.example.com",
        ),
    )
    .unwrap();

    assert_eq!(
        form.audiences,
        vec!["https://api.example.com", "https://payments.example.com"]
    );
}

#[test]
fn token_form_rejects_duplicate_resource_values() {
    let req = TestRequest::default()
        .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
        .to_http_request();

    let result = parse_token_form(
        &req,
        &Bytes::from_static(
            b"grant_type=client_credentials&resource=https%3A%2F%2Fapi.example.com&resource=https%3A%2F%2Fapi.example.com",
        ),
    );

    assert!(matches!(result, Err(TokenFormError::DuplicateParameter)));
}

#[test]
fn token_form_rejects_invalid_resource_parameter() {
    let req = TestRequest::default()
        .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
        .to_http_request();

    let result = parse_token_form(
        &req,
        &Bytes::from_static(b"grant_type=client_credentials&resource=api"),
    );

    assert!(matches!(
        result,
        Err(TokenFormError::InvalidResourceParameter)
    ));
}

#[test]
fn token_form_rejects_conflicting_resource_and_audience() {
    let req = TestRequest::default()
        .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
        .to_http_request();

    let result = parse_token_form(
        &req,
        &Bytes::from_static(
            b"grant_type=client_credentials&audience=resource%3A%2F%2Fdefault&resource=https%3A%2F%2Fapi.example.com",
        ),
    );

    assert!(matches!(result, Err(TokenFormError::DuplicateParameter)));

    let result = parse_token_form(
        &req,
        &Bytes::from_static(
            b"grant_type=client_credentials&resource=https%3A%2F%2Fapi.example.com&audience=resource%3A%2F%2Fdefault",
        ),
    );

    assert!(matches!(result, Err(TokenFormError::DuplicateParameter)));
}

#[test]
fn token_management_form_rejects_duplicate_defined_parameters() {
    let req = TestRequest::default()
        .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
        .to_http_request();

    let result =
        parse_token_management_form(&req, &Bytes::from_static(b"token=token-1&token=token-2"));

    assert!(matches!(
        result,
        Err(TokenManagementFormError::DuplicateParameter)
    ));
}

#[test]
fn token_management_form_tracks_token_type_hint_duplicates() {
    let req = TestRequest::default()
        .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
        .to_http_request();

    let result = parse_token_management_form(
        &req,
        &Bytes::from_static(
            b"token=token-1&token_type_hint=access_token&token_type_hint=refresh_token",
        ),
    );

    assert!(matches!(
        result,
        Err(TokenManagementFormError::DuplicateParameter)
    ));
}

#[test]
fn token_management_form_accepts_token_type_hint_without_requiring_known_value() {
    let req = TestRequest::default()
        .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
        .to_http_request();

    let form = parse_token_management_form(
        &req,
        &Bytes::from_static(b"token=token-1&token_type_hint=opaque_hint"),
    )
    .unwrap();

    assert_eq!(form.token, "token-1");
    assert_eq!(form.token_type_hint.as_deref(), Some("opaque_hint"));
}

#[test]
fn token_management_form_requires_form_content_type() {
    let req = TestRequest::default()
        .insert_header((header::CONTENT_TYPE, "application/json"))
        .to_http_request();

    let result = parse_token_management_form(&req, &Bytes::from_static(b"token=token-1"));

    assert!(matches!(
        result,
        Err(TokenManagementFormError::InvalidContentType)
    ));
}

#[test]
fn token_management_form_rejects_invalid_utf8() {
    let req = form_request();

    let result = parse_token_management_form(&req, &Bytes::from_static(b"token=\xff"));

    assert!(matches!(
        result,
        Err(TokenManagementFormError::InvalidEncoding)
    ));
}

#[test]
fn token_management_form_ignores_unknown_parameters_and_extracts_auth_fields() {
    let req = form_request();

    let form = parse_token_management_form(
        &req,
        &Bytes::from_static(
            b"token=token-1&token_type_hint=refresh_token&client_id=client-1&client_secret=secret-1&client_assertion_type=jwt-bearer&client_assertion=assertion-1&unknown=value",
        ),
    )
    .expect("well-formed token management request should parse");

    assert_eq!(form.token, "token-1");
    assert_eq!(form.token_type_hint.as_deref(), Some("refresh_token"));
    assert_eq!(form.client_id.as_deref(), Some("client-1"));
    assert_eq!(form.client_secret.as_deref(), Some("secret-1"));
    assert_eq!(form.client_assertion_type.as_deref(), Some("jwt-bearer"));
    assert_eq!(form.client_assertion.as_deref(), Some("assertion-1"));
}

#[test]
fn token_management_form_requires_non_empty_token() {
    let req = TestRequest::default()
        .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
        .to_http_request();

    let result = parse_token_management_form(&req, &Bytes::from_static(b"token="));

    assert!(matches!(
        result,
        Err(TokenManagementFormError::MissingToken)
    ));
}

#[test]
fn token_management_rejects_conflicting_client_auth_before_token_state_lookup() {
    let mut basic_with_post = token_management_form_with_client_auth();
    basic_with_post.client_secret = Some("secret".to_owned());
    assert!(token_management_has_conflicting_client_auth(
        true,
        &basic_with_post
    ));

    let mut basic_with_assertion = token_management_form_with_client_auth();
    basic_with_assertion.client_assertion_type = Some(CLIENT_ASSERTION_TYPE_JWT_BEARER.to_owned());
    basic_with_assertion.client_assertion = Some("assertion".to_owned());
    assert!(token_management_has_conflicting_client_auth(
        true,
        &basic_with_assertion
    ));

    let mut post_with_assertion = token_management_form_with_client_auth();
    post_with_assertion.client_secret = Some("secret".to_owned());
    post_with_assertion.client_assertion = Some("assertion".to_owned());
    assert!(token_management_has_conflicting_client_auth(
        false,
        &post_with_assertion
    ));
}

#[test]
fn token_management_allows_exactly_one_client_auth_method() {
    let basic_only = TokenOnlyForm {
        client_id: None,
        ..token_management_form_with_client_auth()
    };
    assert!(!token_management_has_conflicting_client_auth(
        true,
        &basic_only
    ));

    let post_secret = TokenOnlyForm {
        client_secret: Some("secret".to_owned()),
        ..token_management_form_with_client_auth()
    };
    assert!(!token_management_has_conflicting_client_auth(
        false,
        &post_secret
    ));

    let private_key_jwt = TokenOnlyForm {
        client_assertion_type: Some(CLIENT_ASSERTION_TYPE_JWT_BEARER.to_owned()),
        client_assertion: Some("assertion".to_owned()),
        ..token_management_form_with_client_auth()
    };
    assert!(!token_management_has_conflicting_client_auth(
        false,
        &private_key_jwt
    ));
}

#[actix_web::test]
async fn token_management_form_errors_are_exact_oauth_json_and_not_cacheable() {
    let cases = [
        TokenManagementFormError::InvalidContentType,
        TokenManagementFormError::InvalidEncoding,
        TokenManagementFormError::DuplicateParameter,
        TokenManagementFormError::MissingToken,
    ];

    for error in cases {
        let response = token_management_form_error(error);

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            HeaderValue::from_static("no-store")
        );
        assert_eq!(
            response.headers().get(header::PRAGMA).unwrap(),
            HeaderValue::from_static("no-cache")
        );
        assert!(response.headers().get(header::WWW_AUTHENTICATE).is_none());

        let body = response_json(response).await;
        assert_eq!(body["error"], "invalid_request");
        assert!(body["error_description"].as_str().is_some());
        assert!(body.get("access_token").is_none());
        assert!(body.get("refresh_token").is_none());
    }
}

proptest! {
    #[test]
    fn resource_parameter_accepts_absolute_uris_without_fragments(
        host in "[a-z][a-z0-9]{0,12}\\.example",
        path in "[a-zA-Z0-9/_-]{0,32}",
        query in prop::option::of("[a-zA-Z0-9_=&-]{1,32}")
    ) {
        let req = form_request();
        let query_suffix = query
            .as_deref()
            .map(|value| format!("?{value}"))
            .unwrap_or_default();
        let resource = format!("https://{host}/{path}{query_suffix}");
        let encoded = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("grant_type", "client_credentials")
            .append_pair("resource", &resource)
            .finish();

        let form = parse_token_form(&req, &Bytes::from(encoded)).unwrap();

        prop_assert_eq!(form.audiences, vec![resource]);
    }

    #[test]
    fn resource_parameter_rejects_relative_or_fragment_uris(
        resource in "[a-zA-Z0-9/_-]{1,32}",
        fragment in "[a-zA-Z0-9_-]{1,16}"
    ) {
        let req = form_request();
        let relative = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("grant_type", "client_credentials")
            .append_pair("resource", &resource)
            .finish();
        let with_fragment = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("grant_type", "client_credentials")
            .append_pair("resource", &format!("https://api.example/{resource}#{fragment}"))
            .finish();

        prop_assert!(matches!(
            parse_token_form(&req, &Bytes::from(relative)),
            Err(TokenFormError::InvalidResourceParameter)
        ));
        prop_assert!(matches!(
            parse_token_form(&req, &Bytes::from(with_fragment)),
            Err(TokenFormError::InvalidResourceParameter)
        ));
    }

    #[test]
    fn duplicate_defined_parameters_are_rejected_regardless_of_value(
        first in "[a-zA-Z0-9_-]{0,16}",
        second in "[a-zA-Z0-9_-]{0,16}"
    ) {
        let req = form_request();
        let body = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("grant_type", "client_credentials")
            .append_pair("client_id", &first)
            .append_pair("client_id", &second)
            .finish();

        prop_assert!(matches!(
            parse_token_form(&req, &Bytes::from(body)),
            Err(TokenFormError::DuplicateParameter)
        ));
    }
}
