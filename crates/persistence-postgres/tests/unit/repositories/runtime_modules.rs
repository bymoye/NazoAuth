use super::*;

#[test]
fn desired_revision_exhaustion_is_rejected_without_saturation() {
    assert_eq!(next_desired_revision(None).unwrap(), 1);
    assert_eq!(
        next_desired_revision(Some(ModuleRevision::new(41))).unwrap(),
        42
    );
    assert!(matches!(
        next_desired_revision(Some(ModuleRevision::new(u64::MAX))),
        Err(RepositoryError::Consistency(message))
            if message == "desired revision space is exhausted"
    ));
}
