use super::*;

#[test]
fn authorization_repository_error_mapping_is_exhaustive() {
    let cases = [
        (
            RepositoryError::Unavailable,
            AuthorizationPortError::Unavailable,
        ),
        (RepositoryError::Conflict, AuthorizationPortError::Conflict),
        (
            RepositoryError::AlreadyProcessed,
            AuthorizationPortError::Conflict,
        ),
        (
            RepositoryError::Consistency("invalid row".to_owned()),
            AuthorizationPortError::CorruptData,
        ),
        (
            RepositoryError::NotFound,
            AuthorizationPortError::Unexpected,
        ),
        (
            RepositoryError::Unexpected("database".to_owned()),
            AuthorizationPortError::Unexpected,
        ),
    ];

    for (input, expected) in cases {
        assert_eq!(map_repository_error(input), expected);
    }
}

#[test]
fn device_grant_repository_error_mapping_is_exhaustive() {
    let cases = [
        (
            RepositoryError::Unavailable,
            DeviceGrantPortError::Unavailable,
        ),
        (RepositoryError::Conflict, DeviceGrantPortError::Conflict),
        (
            RepositoryError::AlreadyProcessed,
            DeviceGrantPortError::Conflict,
        ),
        (
            RepositoryError::Consistency("invalid row".to_owned()),
            DeviceGrantPortError::CorruptData,
        ),
        (RepositoryError::NotFound, DeviceGrantPortError::Unexpected),
        (
            RepositoryError::Unexpected("database".to_owned()),
            DeviceGrantPortError::Unexpected,
        ),
    ];

    for (input, expected) in cases {
        assert_eq!(map_device_repository_error(input), expected);
    }
}
