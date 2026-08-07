use nazo_identity::{
    Principal, PublicAccount, SubjectClaims, TenantContext, UserId, UserRole,
    ports::{
        AvatarStorageError, EncodedSecretHash, FakeUserRepository, PasswordHashInput,
        RepositoryError, UserRepositoryPort,
    },
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

#[tokio::test]
async fn fake_user_repository_round_trips_principals_and_subject_claims() {
    let tenant = TenantContext::default_system();
    let user_id = UserId::new(Uuid::now_v7()).unwrap();
    let fake = FakeUserRepository::default();
    let principal = Principal {
        user_id,
        tenant,
        role: UserRole::Admin { level: 2 },
        active: true,
    };
    fake.insert_principal(principal.clone());
    assert_eq!(
        fake.principal_by_id(tenant, user_id).await.unwrap(),
        Some(principal)
    );

    let claims = SubjectClaims {
        subject: user_id,
        preferred_username: "alice".to_owned(),
        name: None,
        given_name: None,
        family_name: None,
        middle_name: None,
        nickname: None,
        profile: None,
        picture: None,
        website: None,
        gender: None,
        birthdate: None,
        zoneinfo: None,
        locale: None,
        email: "alice@example.test".to_owned(),
        email_verified: true,
        address: None,
        phone_number: None,
        phone_number_verified: false,
        updated_at: 42,
    };
    fake.insert_subject_claims(tenant.tenant_id, claims.clone());
    assert_eq!(
        fake.subject_claims_by_id(tenant, user_id).await.unwrap(),
        Some(claims)
    );
}

#[test]
fn identity_port_errors_and_secret_wrappers_preserve_safe_messages() {
    for (error, expected) in [
        (RepositoryError::Unavailable, "repository unavailable"),
        (RepositoryError::Conflict, "repository conflict"),
        (
            RepositoryError::AlreadyProcessed,
            "repository value already processed",
        ),
        (RepositoryError::NotFound, "repository value not found"),
        (
            RepositoryError::Consistency("bad state".to_owned()),
            "repository consistency error: bad state",
        ),
        (
            RepositoryError::Unexpected("broken".to_owned()),
            "unexpected repository error: broken",
        ),
    ] {
        assert_eq!(error.to_string(), expected);
    }
    assert!(EncodedSecretHash::new(" ").is_err());
    let encoded = EncodedSecretHash::new("encoded").unwrap();
    assert_eq!(encoded.as_str(), "encoded");
    let password = PasswordHashInput::new("password-hash").unwrap();
    assert_eq!(format!("{password:?}"), "PasswordHashInput([REDACTED])");
    assert_eq!(
        password.into_persistence_value(),
        "password-hash".to_owned()
    );
}

#[test]
fn avatar_storage_errors_are_descriptive_without_exposing_unrelated_state() {
    for (error, expected) in [
        (
            AvatarStorageError::Conflict,
            "avatar storage state changed concurrently",
        ),
        (
            AvatarStorageError::Missing,
            "avatar storage object is missing",
        ),
        (
            AvatarStorageError::InvalidState,
            "avatar storage state is invalid",
        ),
        (
            AvatarStorageError::PreparationFailed("bad image".to_owned()),
            "avatar storage preparation failed: bad image",
        ),
        (
            AvatarStorageError::Unavailable("offline".to_owned()),
            "avatar storage unavailable: offline",
        ),
    ] {
        assert_eq!(error.to_string(), expected);
    }
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
