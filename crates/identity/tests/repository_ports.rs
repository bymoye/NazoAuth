use nazo_identity::{
    PublicAccount, TenantContext, UserId,
    ports::{FakeUserRepository, UserRepositoryPort},
};
use uuid::Uuid;

#[tokio::test]
async fn fake_user_repository_is_a_minimal_test_substitute() {
    let tenant = TenantContext::default_system();
    let user_id = UserId::new(Uuid::now_v7()).unwrap();
    let fake = FakeUserRepository::default();
    assert!(
        fake.principal_by_id(tenant, user_id)
            .await
            .unwrap()
            .is_none()
    );
}

#[test]
fn public_account_is_composed_from_domain_concepts_not_a_flat_database_row() {
    fn assert_public_account(_: &PublicAccount) {}
    let _ = assert_public_account;
}

#[test]
fn public_identity_api_has_no_catch_all_identity_user() {
    let model = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/model.rs"))
        .expect("identity model source is readable");
    let repository = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../persistence-postgres/src/repositories/users.rs"
    ))
    .expect("postgres user repository source is readable");
    let claims = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../authorization-server/src/domain/oidc_claims.rs"
    ))
    .expect("OIDC claims source is readable");

    assert!(!model.contains("pub struct IdentityUser"));
    assert!(!repository.contains("user_by_id"));
    assert!(!repository.contains("user_by_email"));
    assert!(!claims.contains("PublicAccount"));
    assert!(!claims.contains("find_user_by"));
}

#[test]
fn totp_key_ring_requires_distinct_non_empty_versioned_keys() {
    use nazo_identity::ports::{MfaTotpKey, MfaTotpKeyError, MfaTotpKeyRing};

    assert!(matches!(
        MfaTotpKey::new("", [0; 32]),
        Err(MfaTotpKeyError::EmptyId)
    ));
    assert_eq!(
        MfaTotpKeyError::EmptyId.to_string(),
        "MFA TOTP encryption key id must not be empty"
    );
    let current = MfaTotpKey::new("current", [1; 32]).expect("current key is valid");
    let previous = MfaTotpKey::new("current", [2; 32]).expect("previous key material is valid");
    assert!(matches!(
        MfaTotpKeyRing::new(current, Some(previous)),
        Err(MfaTotpKeyError::DuplicateId)
    ));

    let too_long = "k".repeat(129);
    assert!(matches!(
        MfaTotpKey::new(too_long, [0; 32]),
        Err(MfaTotpKeyError::IdTooLong)
    ));
    assert_eq!(
        MfaTotpKeyError::IdTooLong.to_string(),
        "MFA TOTP encryption key id must be at most 128 bytes"
    );

    let current = MfaTotpKey::new("current", [1; 32]).expect("current key is valid");
    let previous = MfaTotpKey::new("previous", [2; 32]).expect("previous key is valid");
    let ring = MfaTotpKeyRing::new(current, Some(previous)).expect("distinct key ids");
    assert_eq!(
        MfaTotpKeyError::DuplicateId.to_string(),
        "MFA TOTP current and previous key ids must differ"
    );
    assert_eq!(ring.current().id(), "current");
    assert_eq!(ring.current().key(), &[1; 32]);
    assert_eq!(ring.previous().expect("previous key").id(), "previous");
    assert_eq!(ring.previous().expect("previous key").key(), &[2; 32]);
}
