use super::*;
use nazo_identity::ports::MfaTotpKey;
use uuid::Uuid;

#[test]
fn enrollment_unique_violation_is_a_typed_conflict() {
    let error = diesel::result::Error::DatabaseError(
        diesel::result::DatabaseErrorKind::UniqueViolation,
        Box::new("duplicate enrollment".to_owned()),
    );
    assert_eq!(map_mfa_error(error), RepositoryError::Conflict);
}

#[test]
fn totp_envelope_authenticates_secret_and_identity_binding() {
    let tenant_id = TenantId::new(Uuid::now_v7()).expect("tenant id is valid");
    let user_id = UserId::new(Uuid::now_v7()).expect("user id is valid");
    let current = MfaTotpKey::new("current", [0x11; 32]).expect("key is valid");
    let key_ring = MfaTotpKeyRing::new(current, None).expect("key ring is valid");
    let (protected, key_id) =
        protect_totp_secret(&key_ring, tenant_id, user_id, "JBSWY3DPEHPK3PXP")
            .expect("encryption succeeds");

    assert_eq!(
        decode_totp_secret(
            Some(&key_ring),
            tenant_id,
            user_id,
            None,
            Some(protected.clone()),
            Some(key_id.clone()),
        )
        .expect("decryption succeeds"),
        "JBSWY3DPEHPK3PXP"
    );
    let other_user = UserId::new(Uuid::now_v7()).expect("user id is valid");
    assert!(matches!(
        decode_totp_secret(
            Some(&key_ring),
            tenant_id,
            other_user,
            None,
            Some(protected),
            Some(key_id),
        ),
        Err(RepositoryError::Consistency(_))
    ));
    assert!(matches!(
        decode_totp_secret(
            Some(&key_ring),
            tenant_id,
            user_id,
            Some("JBSWY3DPEHPK3PXP".to_owned()),
            None,
            None,
        ),
        Err(RepositoryError::Consistency(_))
    ));
}
