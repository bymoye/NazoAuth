use super::*;
use base64::engine::general_purpose::STANDARD;

#[test]
fn basic_client_credentials_scheme_is_case_insensitive() {
    let encoded = STANDARD.encode("client-1:secret-1");
    let req = TestRequest::default()
        .insert_header((
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("basic {encoded}")).unwrap(),
        ))
        .to_http_request();
    let settings = test_settings();

    assert!(has_basic_authorization_scheme(req.headers()));
    let credentials = extract_client_credentials(&req, &settings, None, None, None, None);

    assert_eq!(credentials.method, "client_secret_basic");
    assert_eq!(credentials.client_id.as_deref(), Some("client-1"));
    assert_eq!(credentials.client_secret.as_deref(), Some("secret-1"));
}

#[test]
fn malformed_basic_authorization_scheme_is_detected() {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::AUTHORIZATION,
        HeaderValue::from_static("Basic not-base64 with-space"),
    );

    assert!(has_basic_authorization_scheme(&headers));
}

#[test]
fn malformed_basic_authorization_fails_closed_as_basic_credentials() {
    let req = TestRequest::default()
        .insert_header((header::AUTHORIZATION, "Basic not-base64 with-space"))
        .to_http_request();
    let settings = test_settings();

    let credentials = extract_client_credentials(&req, &settings, None, None, None, None);

    assert_eq!(credentials.method, "client_secret_basic");
    assert!(credentials.client_id.is_none());
    assert!(credentials.client_secret.is_none());
}

#[test]
fn non_utf8_basic_authorization_scheme_is_detected() {
    let req = TestRequest::default()
        .insert_header((
            header::AUTHORIZATION,
            HeaderValue::from_bytes(b"Basic \xff").unwrap(),
        ))
        .to_http_request();
    let settings = test_settings();

    assert!(has_basic_authorization_scheme(req.headers()));
    let credentials = extract_client_credentials(&req, &settings, None, None, None, None);
    assert_eq!(credentials.method, "client_secret_basic");
}
