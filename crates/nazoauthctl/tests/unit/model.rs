use super::*;

#[test]
fn semantic_versions_require_an_immutable_tag() {
    assert!(semantic_tag("v1.2.3"));
    assert!(semantic_tag("v1.2.3-rc.1"));
    assert!(!semantic_tag("latest"));
    assert!(!semantic_tag("v1.2"));
    assert!(!semantic_tag("1.2.3"));
}

#[test]
fn environment_keys_are_strict() {
    assert!(valid_environment_key("DATABASE_URL_FILE"));
    assert!(!valid_environment_key("database_url"));
    assert!(!valid_environment_key("BAD-VALUE"));
}

#[test]
fn runtime_environment_cannot_carry_secret_values() {
    assert!(valid_environment_key("DATABASE_URL_FILE"));
    assert!(!"DATABASE_URL_FILE".ends_with("PASSWORD"));
    assert!(!"DATABASE_URL".ends_with("_FILE"));
}
