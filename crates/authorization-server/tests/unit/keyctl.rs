use super::*;

#[test]
fn parses_the_closed_purpose_scoped_key_operation() {
    let options = parse_generate_local(
        "ES256",
        &["credential".to_owned(), "presentation_request".to_owned()],
    )
    .unwrap();
    assert_eq!(options.alg, jsonwebtoken::Algorithm::ES256);
    assert_eq!(options.purposes.len(), 2);
}

#[test]
fn rejects_empty_duplicate_or_runtime_signing_purposes() {
    assert!(parse_generate_local("ES256", &[]).is_err());
    assert!(
        parse_generate_local("ES256", &["credential".to_owned(), "credential".to_owned()]).is_err()
    );
    assert!(parse_generate_local("ES256", &["access_token".to_owned()]).is_err());
}

#[test]
fn rejects_unsupported_algorithms() {
    assert!(parse_generate_local("none", &["credential".to_owned()]).is_err());
}
