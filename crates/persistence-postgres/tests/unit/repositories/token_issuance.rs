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

fn row(phase: &str) -> TokenIssuanceRow {
    let now = Utc::now();
    TokenIssuanceRow {
        issuance_id: Uuid::now_v7(),
        tenant_id: Uuid::now_v7(),
        client_id: Uuid::now_v7(),
        grant_key_blake3: "grant-hash".to_owned(),
        request_digest: "request-digest".to_owned(),
        phase: phase.to_owned(),
        claim_owner_id: None,
        claim_started_at: None,
        access_token_jti: None,
        access_token_expires_at: None,
        response_ciphertext: None,
        response_digest: None,
        response_envelope_version: None,
        response_key_id: None,
        expires_at: now + chrono::Duration::minutes(5),
        created_at: now,
        updated_at: now,
    }
}

fn row_with_response(
    phase: &str,
    ring: &TokenIssuanceResponseKeyRing,
    body: &[u8],
    digest: &str,
) -> TokenIssuanceRow {
    let mut row = row(phase);
    let envelope_context = context(
        row.issuance_id,
        row.tenant_id,
        row.client_id,
        digest,
        TOKEN_ISSUANCE_RESPONSE_ENVELOPE_VERSION,
        ring.current_id(),
    );
    row.response_ciphertext = Some(
        seal_response(Some(ring), &envelope_context, body).expect("response seals successfully"),
    );
    row.response_digest = Some(digest.to_owned());
    row.response_envelope_version = Some(TOKEN_ISSUANCE_RESPONSE_ENVELOPE_VERSION.to_owned());
    row.response_key_id = Some(ring.current_id().to_owned());
    row
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
    let base_context = context(
        issuance_id,
        tenant_id,
        client_id,
        &digest,
        TOKEN_ISSUANCE_RESPONSE_ENVELOPE_VERSION,
        ring.current_id(),
    );

    let protected = seal_response(Some(&ring), &base_context, body).expect("encryption succeeds");
    assert_eq!(
        unseal_response(&ring, &base_context, &protected).expect("decryption succeeds"),
        body
    );
    assert_eq!(base_context.envelope_version, "v1");
    assert_eq!(base_context.key_id, "current");
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
        TokenIssuanceResponseKeyRing::new("   ", [0; 32], None),
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

#[test]
fn key_ring_display_debug_and_lookup_do_not_expose_key_material() {
    let ring = TokenIssuanceResponseKeyRing::new(
        "current",
        [0x11; 32],
        Some(("previous".to_owned(), [0x22; 32])),
    )
    .expect("key ring is valid");

    assert_eq!(ring.current_id(), "current");
    assert!(ring.key_for("current").is_some());
    assert!(ring.key_for("previous").is_some());
    assert!(ring.key_for("retired").is_none());
    let debug = format!("{ring:?}");
    assert!(debug.contains("current"));
    assert!(debug.contains("previous"));
    assert!(!debug.contains("11".repeat(32).as_str()));

    assert_eq!(
        TokenIssuanceResponseKeyError::EmptyId.to_string(),
        "token issuance response encryption key id must not be empty"
    );
    assert_eq!(
        TokenIssuanceResponseKeyError::IdTooLong.to_string(),
        "token issuance response encryption key id must be at most 128 bytes"
    );
    assert_eq!(
        TokenIssuanceResponseKeyError::DuplicateId.to_string(),
        "token issuance response current and previous key ids must differ"
    );
}

#[test]
fn issuance_rows_map_phases_and_preserve_sealed_response_state() {
    let ring =
        TokenIssuanceResponseKeyRing::new("current", [0x11; 32], None).expect("key ring is valid");
    let body = b"signed response";
    let digest = blake3::hash(body).to_hex().to_string();

    let prepared = row("prepared")
        .into_record(None)
        .expect("prepared row has no response envelope");
    assert_eq!(prepared.phase, TokenIssuancePhase::Prepared);
    assert!(prepared.response_body.is_none());

    for phase in [
        TokenIssuancePhase::Signed,
        TokenIssuancePhase::Persisted,
        TokenIssuancePhase::Delivered,
    ] {
        let record = row_with_response(phase.as_str(), &ring, body, &digest)
            .into_record(Some(&ring))
            .expect("sealed response row is valid");
        assert_eq!(record.phase, phase);
        assert_eq!(record.response_body.as_deref(), Some(body.as_slice()));
        assert_eq!(record.response_digest.as_deref(), Some(digest.as_str()));
        assert_eq!(record.response_key_version.as_deref(), Some("v1"));
    }

    assert!(matches!(
        row("unknown").into_record(None),
        Err(RepositoryError::Consistency(message)) if message.contains("unknown phase")
    ));
}

#[test]
fn issuance_rows_reject_incomplete_or_inconsistent_response_envelopes() {
    let ring =
        TokenIssuanceResponseKeyRing::new("current", [0x11; 32], None).expect("key ring is valid");
    let body = b"response";
    let digest = blake3::hash(body).to_hex().to_string();

    let missing_envelope = row("signed");
    assert!(matches!(
        missing_envelope.into_record(None),
        Err(RepositoryError::Consistency(message)) if message.contains("phase and response")
    ));

    let mut incomplete = row("signed");
    incomplete.response_ciphertext = Some(vec![1, 2, 3]);
    assert!(matches!(
        incomplete.into_record(None),
        Err(RepositoryError::Consistency(message)) if message.contains("incomplete")
    ));

    let mut unsupported = row_with_response("signed", &ring, body, &digest);
    unsupported.response_envelope_version = Some("v2".to_owned());
    assert!(matches!(
        unsupported.into_record(Some(&ring)),
        Err(RepositoryError::Consistency(message)) if message.contains("unsupported")
    ));

    let no_keys = row_with_response("signed", &ring, body, &digest);
    assert!(matches!(
        no_keys.into_record(None),
        Err(RepositoryError::Consistency(message)) if message.contains("not configured")
    ));

    let prepared_with_response = row_with_response("prepared", &ring, body, &digest);
    assert!(matches!(
        prepared_with_response.into_record(Some(&ring)),
        Err(RepositoryError::Consistency(message)) if message.contains("phase and response")
    ));
}

#[test]
fn response_envelopes_fail_closed_on_missing_keys_tampering_and_digest_mismatch() {
    let ring =
        TokenIssuanceResponseKeyRing::new("current", [0x11; 32], None).expect("key ring is valid");
    let body = b"response";
    let digest = blake3::hash(body).to_hex().to_string();
    let base_context = context(
        Uuid::now_v7(),
        Uuid::now_v7(),
        Uuid::now_v7(),
        &digest,
        TOKEN_ISSUANCE_RESPONSE_ENVELOPE_VERSION,
        ring.current_id(),
    );
    assert!(matches!(
        seal_response(None, &base_context, body),
        Err(RepositoryError::Unavailable)
    ));
    assert!(matches!(
        unseal_response(&ring, &base_context, &[]),
        Err(RepositoryError::Consistency(message)) if message.contains("malformed")
    ));
    assert!(matches!(
        unseal_response(
            &ring,
            &base_context,
            &[TOKEN_ISSUANCE_RESPONSE_ENVELOPE_VERSION_BYTE + 1; RESPONSE_MIN_PROTECTED_LEN],
        ),
        Err(RepositoryError::Consistency(message)) if message.contains("malformed")
    ));

    let mut protected =
        seal_response(Some(&ring), &base_context, body).expect("seals successfully");
    let last = protected.len() - 1;
    protected[last] ^= 1;
    assert!(matches!(
        unseal_response(&ring, &base_context, &protected),
        Err(RepositoryError::Consistency(message)) if message.contains("authentication")
    ));

    let wrong_digest = "0".repeat(64);
    let wrong_context = context(
        base_context.issuance_id,
        base_context.tenant_id,
        base_context.client_id,
        &wrong_digest,
        TOKEN_ISSUANCE_RESPONSE_ENVELOPE_VERSION,
        ring.current_id(),
    );
    let wrong_digest_protected =
        seal_response(Some(&ring), &wrong_context, body).expect("seals successfully");
    assert!(matches!(
        unseal_response(&ring, &wrong_context, &wrong_digest_protected),
        Err(RepositoryError::Consistency(message)) if message.contains("digest mismatch")
    ));
}

#[test]
fn token_error_mappings_preserve_conflicts_and_corruption_boundaries() {
    assert!(matches!(
        map_repository_error(RepositoryError::Unavailable),
        TokenPortError::Unavailable
    ));
    assert!(matches!(
        map_repository_error(RepositoryError::Conflict),
        TokenPortError::Conflict
    ));
    assert!(matches!(
        map_repository_error(RepositoryError::AlreadyProcessed),
        TokenPortError::Conflict
    ));
    assert!(matches!(
        map_repository_error(RepositoryError::Consistency("bad row".to_owned())),
        TokenPortError::CorruptData
    ));
    assert!(matches!(
        map_repository_error(RepositoryError::NotFound),
        TokenPortError::Unexpected
    ));
    assert!(matches!(
        map_repository_error(RepositoryError::Unexpected("db".to_owned())),
        TokenPortError::Unexpected
    ));

    assert!(matches!(
        map_diesel_error(diesel::result::Error::DatabaseError(
            diesel::result::DatabaseErrorKind::UniqueViolation,
            Box::new("duplicate".to_owned()),
        )),
        TokenPortError::Conflict
    ));
    assert!(matches!(
        map_diesel_error(diesel::result::Error::NotFound),
        TokenPortError::CorruptData
    ));
    assert!(matches!(
        map_diesel_error(diesel::result::Error::RollbackTransaction),
        TokenPortError::Unexpected
    ));
}

#[test]
fn grant_hash_and_response_aad_bind_all_issuance_context_fields() {
    assert_eq!(grant_key_hash("grant-key"), grant_key_hash("grant-key"));
    assert_ne!(grant_key_hash("grant-key"), grant_key_hash("other-grant"));
    let issuance_id = Uuid::now_v7();
    let tenant_id = Uuid::now_v7();
    let client_id = Uuid::now_v7();
    let first = context(
        issuance_id,
        tenant_id,
        client_id,
        "digest-a",
        "v1",
        "current",
    );
    let mut second = context(
        issuance_id,
        tenant_id,
        client_id,
        "digest-a",
        "v1",
        "current",
    );
    second.key_id = "previous";
    assert_ne!(response_aad(&first), response_aad(&second));
}
