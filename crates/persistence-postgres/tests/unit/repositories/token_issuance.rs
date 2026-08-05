use super::*;

fn context<'a>(
    issuance_id: Uuid,
    tenant_id: Uuid,
    client_id: Uuid,
    digest: &'a str,
    envelope_version: &'a str,
    key_id: &'a str,
) -> ResponseEnvelopeContext<'a> {
    ResponseEnvelopeContext {
        issuance_id,
        tenant_id,
        client_id,
        grant_key_hash: "grant-hash",
        response_digest: digest,
        envelope_version,
        key_id,
    }
}

#[test]
fn response_envelope_round_trips_with_current_key_and_separate_format() {
    let ring = TokenIssuanceResponseKeyRing::new("current", [0x11; 32], None)
        .expect("current key ring is valid");
    let issuance_id = Uuid::now_v7();
    let tenant_id = Uuid::now_v7();
    let client_id = Uuid::now_v7();
    let body = br#"{"access_token":"opaque"}"#;
    let digest = blake3::hash(body).to_hex().to_string();
    let context = context(
        issuance_id,
        tenant_id,
        client_id,
        &digest,
        TOKEN_ISSUANCE_RESPONSE_ENVELOPE_VERSION,
        ring.current_id(),
    );

    let protected = seal_response(Some(&ring), &context, body).expect("encryption succeeds");
    assert_eq!(
        unseal_response(&ring, &context, &protected).expect("decryption succeeds"),
        body
    );
    assert_eq!(context.envelope_version, "v1");
    assert_eq!(context.key_id, "current");
    assert_ne!(&protected[..RESPONSE_NONCE_LEN], body);
}

#[test]
fn previous_key_decrypts_but_removed_key_fails_closed() {
    let previous_id = "previous".to_owned();
    let rotating_ring = TokenIssuanceResponseKeyRing::new(
        "current",
        [0x22; 32],
        Some((previous_id.clone(), [0x11; 32])),
    )
    .expect("rotating key ring is valid");
    let issuance_id = Uuid::now_v7();
    let tenant_id = Uuid::now_v7();
    let client_id = Uuid::now_v7();
    let body = b"previously encrypted response";
    let digest = blake3::hash(body).to_hex().to_string();
    let context = context(
        issuance_id,
        tenant_id,
        client_id,
        &digest,
        TOKEN_ISSUANCE_RESPONSE_ENVELOPE_VERSION,
        &previous_id,
    );
    let protected = seal_response(Some(&rotating_ring), &context, body)
        .expect("encryption with current key succeeds");

    // The helper intentionally only emits current-key envelopes. Re-encrypt
    // with the previous key directly to model a row written before rotation.
    let previous_key = rotating_ring
        .key_for(&previous_id)
        .expect("previous key is in the overlap ring");
    let cipher = Aes256Gcm::new_from_slice(&previous_key.key).expect("key is valid");
    let mut nonce = [0_u8; RESPONSE_NONCE_LEN];
    rand::rng().fill_bytes(&mut nonce);
    let ciphertext = cipher
        .encrypt(
            (&nonce).into(),
            Payload {
                msg: body,
                aad: &response_aad(&context),
            },
        )
        .expect("previous-key encryption succeeds");
    let mut previous_protected = vec![TOKEN_ISSUANCE_RESPONSE_ENVELOPE_VERSION_BYTE];
    previous_protected.extend_from_slice(&nonce);
    previous_protected.extend_from_slice(&ciphertext);

    assert_eq!(
        unseal_response(&rotating_ring, &context, &previous_protected)
            .expect("previous key remains decryptable"),
        body
    );
    let retired_ring = TokenIssuanceResponseKeyRing::new("current", [0x22; 32], None)
        .expect("retired ring is valid");
    assert!(matches!(
        unseal_response(&retired_ring, &context, &previous_protected),
        Err(RepositoryError::Consistency(_))
    ));
    // Avoid allowing a test helper to accidentally regress current-key use.
    assert_ne!(protected, previous_protected);
}

#[test]
fn unknown_format_and_unknown_key_are_rejected() {
    let ring = TokenIssuanceResponseKeyRing::new("current", [0x11; 32], None)
        .expect("current key ring is valid");
    let body = b"response";
    let digest = blake3::hash(body).to_hex().to_string();
    let issuance_id = Uuid::now_v7();
    let tenant_id = Uuid::now_v7();
    let client_id = Uuid::now_v7();
    let current_context = context(
        issuance_id,
        tenant_id,
        client_id,
        &digest,
        TOKEN_ISSUANCE_RESPONSE_ENVELOPE_VERSION,
        ring.current_id(),
    );
    let protected =
        seal_response(Some(&ring), &current_context, body).expect("encryption succeeds");
    let unknown_version = context(issuance_id, tenant_id, client_id, &digest, "v2", "current");
    assert!(matches!(
        unseal_response(&ring, &unknown_version, &protected),
        Err(RepositoryError::Consistency(_))
    ));
    let unknown_key = context(
        issuance_id,
        tenant_id,
        client_id,
        &digest,
        TOKEN_ISSUANCE_RESPONSE_ENVELOPE_VERSION,
        "retired",
    );
    assert!(matches!(
        unseal_response(&ring, &unknown_key, &protected),
        Err(RepositoryError::Consistency(_))
    ));
}

#[test]
fn key_ring_rejects_empty_long_and_duplicate_ids() {
    assert!(matches!(
        TokenIssuanceResponseKeyRing::new("", [0; 32], None),
        Err(TokenIssuanceResponseKeyError::EmptyId)
    ));
    assert!(matches!(
        TokenIssuanceResponseKeyRing::new(
            "current",
            [0; 32],
            Some(("current".to_owned(), [1; 32]))
        ),
        Err(TokenIssuanceResponseKeyError::DuplicateId)
    ));
    assert!(matches!(
        TokenIssuanceResponseKeyRing::new("x".repeat(129), [0; 32], None),
        Err(TokenIssuanceResponseKeyError::IdTooLong)
    ));
}

#[test]
fn response_key_ring_preflight_rejects_uncovered_ids() {
    let ring = TokenIssuanceResponseKeyRing::new(
        "current",
        [0x11; 32],
        Some(("previous".to_owned(), [0x22; 32])),
    )
    .expect("key ring is valid");
    assert!(
        validate_response_key_ids(
            &ring,
            [Some("current".to_owned()), Some("previous".to_owned())],
        )
        .is_ok()
    );
    assert!(matches!(
        validate_response_key_ids(&ring, [Some("retired".to_owned())]),
        Err(RepositoryError::Consistency(message)) if message.contains("retired")
    ));
    assert!(matches!(
        validate_response_key_ids(&ring, [None]),
        Err(RepositoryError::Consistency(message)) if message.contains("missing")
    ));
}
