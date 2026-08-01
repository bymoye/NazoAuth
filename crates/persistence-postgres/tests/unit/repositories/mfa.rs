use super::*;

#[test]
fn enrollment_unique_violation_is_a_typed_conflict() {
    let error = diesel::result::Error::DatabaseError(
        diesel::result::DatabaseErrorKind::UniqueViolation,
        Box::new("duplicate enrollment".to_owned()),
    );
    assert_eq!(map_mfa_error(error), RepositoryError::Conflict);
}
