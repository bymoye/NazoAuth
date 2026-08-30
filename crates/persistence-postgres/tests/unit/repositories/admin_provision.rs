use super::validate_identifier;

#[test]
fn identifiers_use_the_file_identifier_contract() {
    assert!(validate_identifier("admin-provision-01".to_owned(), 128).is_ok());
    assert!(validate_identifier("with+plus".to_owned(), 128).is_ok());
    assert!(validate_identifier(String::new(), 128).is_err());
    assert!(validate_identifier("contains space".to_owned(), 128).is_err());
    assert!(validate_identifier("x".repeat(129), 128).is_err());
}
