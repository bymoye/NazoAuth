use super::*;

#[test]
fn persisted_client_string_arrays_reject_non_array_json() {
    assert!(
        string_array(
            Value::String("authorization_code".to_owned()),
            "grant_types"
        )
        .is_err()
    );
}

#[test]
fn missing_client_rows_preserve_not_found_semantics() {
    assert_eq!(
        map_error(diesel::result::Error::NotFound),
        RepositoryError::NotFound
    );
}
