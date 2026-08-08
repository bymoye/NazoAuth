use super::pre_authorized_parameters;
use actix_web::http::{StatusCode, header};
use actix_web::test::TestRequest;
use actix_web::web::Bytes;
use nazo_http_actix::{PreAuthorizedTokenParameters, parse_token_form_with_pre_authorized};

fn parsed_parameters(body: &str) -> PreAuthorizedTokenParameters {
    let body = format!("grant_type=client_credentials&{body}");
    let request = TestRequest::default()
        .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
        .to_http_request();
    parse_token_form_with_pre_authorized(&request, &Bytes::from(body))
        .expect("token form should parse")
        .pre_authorized
}

#[test]
fn parses_required_code_and_optional_tx_code_once() {
    let mut parameters = parsed_parameters("pre-authorized_code=code-1&tx_code=1234&ignored=value");
    let parsed =
        pre_authorized_parameters(&mut parameters).expect("valid pre-authorized token parameters");
    assert_eq!(parsed, ("code-1".to_owned(), Some("1234".to_owned())));
}

#[test]
fn rejects_missing_empty_and_repeated_issuance_parameters() {
    for body in [
        "",
        "tx_code=1234",
        "pre-authorized_code=",
        "pre-authorized_code=one&pre-authorized_code=two",
        "tx_code=one&tx_code=two",
    ] {
        let mut parameters = parsed_parameters(body);
        let error = pre_authorized_parameters(&mut parameters)
            .expect_err("invalid pre-authorized parameters must fail");
        assert_eq!(error.status(), StatusCode::BAD_REQUEST);
    }
}
