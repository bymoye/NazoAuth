use super::*;
use nazo_identity::ports::MfaTotpKey;
use uuid::Uuid;

fn single_key_ring() -> MfaTotpKeyRing {
    let current = MfaTotpKey::new("current", [0x11; 32]).expect("current key is valid");
    MfaTotpKeyRing::new(current, None).expect("key ring is valid")
}

fn protected_with_key(
    key: &MfaTotpKey,
    tenant_id: TenantId,
    user_id: UserId,
    key_id: &str,
    plaintext: &[u8],
) -> Vec<u8> {
    let cipher = Aes256Gcm::new_from_slice(key.key()).expect("key is valid");
    let nonce = [0x44; TOTP_NONCE_LEN];
    let ciphertext = cipher
        .encrypt(
            (&nonce).into(),
            Payload {
                msg: plaintext,
                aad: &totp_aad(tenant_id, user_id, key_id),
            },
        )
        .expect("encryption succeeds");
    let mut protected = vec![TOTP_ENVELOPE_VERSION];
    protected.extend_from_slice(&nonce);
    protected.extend_from_slice(&ciphertext);
    protected
}

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
    let key_ring = single_key_ring();
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

#[test]
fn totp_secret_validation_rejects_malformed_rows_and_uses_previous_keys() {
    let tenant_id = TenantId::new(Uuid::now_v7()).expect("tenant id is valid");
    let user_id = UserId::new(Uuid::now_v7()).expect("user id is valid");
    let current = MfaTotpKey::new("current", [0x11; 32]).expect("current key is valid");
    let previous = MfaTotpKey::new("previous", [0x22; 32]).expect("previous key is valid");
    let key_ring = MfaTotpKeyRing::new(current.clone(), Some(previous.clone()))
        .expect("rotating key ring is valid");

    assert!(matches!(
        protect_totp_secret(&key_ring, tenant_id, user_id, "short"),
        Err(RepositoryError::Consistency(_))
    ));
    assert!(matches!(
        protect_totp_secret(&key_ring, tenant_id, user_id, &"x".repeat(129)),
        Err(RepositoryError::Consistency(_))
    ));

    let previous_protected = protected_with_key(
        &previous,
        tenant_id,
        user_id,
        previous.id(),
        b"JBSWY3DPEHPK3PXP",
    );
    assert_eq!(
        decode_totp_secret(
            Some(&key_ring),
            tenant_id,
            user_id,
            None,
            Some(previous_protected.clone()),
            Some(previous.id().to_owned()),
        )
        .expect("previous key remains decryptable"),
        "JBSWY3DPEHPK3PXP"
    );
    assert!(matches!(
        decode_totp_secret(
            None,
            tenant_id,
            user_id,
            None,
            Some(previous_protected.clone()),
            Some(previous.id().to_owned()),
        ),
        Err(RepositoryError::Consistency(_))
    ));
    assert!(matches!(
        decode_totp_secret(
            Some(&key_ring),
            tenant_id,
            user_id,
            Some("plaintext".to_owned()),
            Some(previous_protected.clone()),
            Some(previous.id().to_owned()),
        ),
        Err(RepositoryError::Consistency(_))
    ));
    assert!(matches!(
        decode_totp_secret(Some(&key_ring), tenant_id, user_id, None, None, None,),
        Err(RepositoryError::Consistency(_))
    ));
    assert!(matches!(
        decode_totp_secret(
            Some(&key_ring),
            tenant_id,
            user_id,
            None,
            Some(previous_protected.clone()),
            None,
        ),
        Err(RepositoryError::Consistency(_))
    ));
    assert!(matches!(
        decode_totp_secret(
            Some(&key_ring),
            tenant_id,
            user_id,
            None,
            Some(vec![TOTP_ENVELOPE_VERSION; TOTP_MIN_PROTECTED_LEN - 1]),
            Some(previous.id().to_owned()),
        ),
        Err(RepositoryError::Consistency(_))
    ));
    assert!(matches!(
        decode_totp_secret(
            Some(&key_ring),
            tenant_id,
            user_id,
            None,
            Some(vec![TOTP_ENVELOPE_VERSION + 1; TOTP_MIN_PROTECTED_LEN]),
            Some(previous.id().to_owned()),
        ),
        Err(RepositoryError::Consistency(_))
    ));
    assert!(matches!(
        decode_totp_secret(
            Some(&key_ring),
            tenant_id,
            user_id,
            None,
            Some(previous_protected.clone()),
            Some("retired".to_owned()),
        ),
        Err(RepositoryError::Consistency(_))
    ));

    let invalid_utf8 =
        protected_with_key(&current, tenant_id, user_id, current.id(), &[0xff, 0xfe]);
    assert!(matches!(
        decode_totp_secret(
            Some(&key_ring),
            tenant_id,
            user_id,
            None,
            Some(invalid_utf8),
            Some(current.id().to_owned()),
        ),
        Err(RepositoryError::Consistency(_))
    ));
    let invalid_length = protected_with_key(&current, tenant_id, user_id, current.id(), b"short");
    assert!(matches!(
        decode_totp_secret(
            Some(&key_ring),
            tenant_id,
            user_id,
            None,
            Some(invalid_length),
            Some(current.id().to_owned()),
        ),
        Err(RepositoryError::Consistency(_))
    ));
}

#[test]
fn backup_hash_count_and_error_mappings_are_fail_closed() {
    assert_eq!(
        validate_backup_hash_count(&vec!["hash".to_owned(); MFA_BACKUP_CODE_COUNT]),
        Ok(())
    );
    assert_eq!(
        validate_backup_hash_count(&vec!["hash".to_owned(); MFA_BACKUP_CODE_COUNT + 1]),
        Err(RepositoryError::Conflict)
    );

    for error in [
        diesel::result::Error::NotFound,
        diesel::result::Error::RollbackTransaction,
        diesel::result::Error::DatabaseError(
            diesel::result::DatabaseErrorKind::UniqueViolation,
            Box::new("duplicate".to_owned()),
        ),
    ] {
        assert_eq!(map_mfa_error(error), RepositoryError::Conflict);
    }
    assert!(matches!(
        map_mfa_error(diesel::result::Error::AlreadyInTransaction),
        RepositoryError::Unexpected(_)
    ));
    assert_eq!(
        MfaAuditError::Repository(RepositoryError::Unavailable).into_repository(),
        RepositoryError::Unavailable
    );
    assert_eq!(
        MfaAuditError::Diesel(diesel::result::Error::NotFound).into_repository(),
        RepositoryError::Conflict
    );
    assert_eq!(
        MfaSecretMigrationError::Repository(RepositoryError::Conflict).into_repository(),
        RepositoryError::Conflict
    );
    assert_eq!(
        MfaSecretMigrationError::Diesel(diesel::result::Error::NotFound).into_repository(),
        RepositoryError::Conflict
    );
}

#[tokio::test]
async fn mfa_repository_key_requirement_precedes_database_access() {
    let pool = crate::create_pool("postgres://localhost/unused", 1).expect("pool builds");
    let repository = MfaRepository::new(pool);
    let tenant_id = TenantId::new(Uuid::now_v7()).expect("tenant id is valid");
    let user_id = UserId::new(Uuid::now_v7()).expect("user id is valid");

    let error = repository.totp_credential(tenant_id, user_id).await;
    assert!(
        matches!(error, Err(RepositoryError::Consistency(message)) if message.contains("not configured"))
    );
    assert!(matches!(
        repository
            .begin_totp_enrollment(
                tenant_id,
                user_id,
                "JBSWY3DPEHPK3PXP".to_owned(),
                "test".to_owned(),
            )
            .await,
        Err(RepositoryError::Consistency(message)) if message.contains("not configured")
    ));
    assert_eq!(
        repository
            .verify_and_confirm_totp(tenant_id, user_id, "000000", 0, Vec::new())
            .await,
        Err(RepositoryError::Conflict)
    );
}
