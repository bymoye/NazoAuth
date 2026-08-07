use super::pre_authorized_parameters;
use actix_web::http::StatusCode;
use actix_web::web::Bytes;

#[test]
fn parses_required_code_and_optional_tx_code_once() {
    let parsed = pre_authorized_parameters(&Bytes::from_static(
        b"pre-authorized_code=code-1&tx_code=1234&ignored=value",
    ))
    .expect("valid pre-authorized token parameters");
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
        let error = pre_authorized_parameters(&Bytes::from(body))
            .expect_err("invalid pre-authorized parameters must fail");
        assert_eq!(error.status(), StatusCode::BAD_REQUEST);
    }
}
