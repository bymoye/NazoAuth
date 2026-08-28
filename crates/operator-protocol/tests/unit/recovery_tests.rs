//! Recovery Root contract pins (04A D10/D11): secret transcription, pinned
//! KDF parameters, and the canonical challenge message binding.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

use super::{
    RECOVERY_CHALLENGE_ACTION, RECOVERY_CHALLENGE_ALLOCATION_ACTION, RECOVERY_KDF_ID,
    RECOVERY_SECRET_PREFIX, RecoveryProposal, RecoveryRootRotation, derive_recovery_seed,
    format_recovery_secret, hkdf_sha256_v1, parse_recovery_secret, recovery_kid,
    recovery_public_key_bytes,
};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn hkdf_matches_the_rfc_5869_sha256_vectors() {
    // RFC 5869 appendix A, test case 1.
    let okm = hkdf_sha256_v1(
        &[0x0bu8; 22],
        &[
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ],
        &[0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9],
        42,
    );
    assert_eq!(
        hex(&okm),
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
    );
    // RFC 5869 appendix A, test case 3: zero-length salt and info.
    let okm = hkdf_sha256_v1(&[0x0b; 22], &[], &[], 42);
    assert_eq!(
        hex(&okm),
        "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
    );
}

#[test]
fn recovery_secret_display_form_is_prefix_plus_sixtyfour_lowercase_hex() {
    let secret = [0xa5u8; 32];
    let rendered = format_recovery_secret(&secret);
    assert_eq!(rendered.len(), RECOVERY_SECRET_PREFIX.len() + 64);
    assert!(rendered.starts_with(RECOVERY_SECRET_PREFIX));
    assert!(
        rendered[RECOVERY_SECRET_PREFIX.len()..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    );
    // Round trip through the tolerant parser.
    assert_eq!(parse_recovery_secret(&rendered).unwrap(), secret);
}

#[test]
fn parsing_accepts_optional_prefix_grouping_whitespace_and_case() {
    let mut secret = [0u8; 32];
    for (index, byte) in secret.iter_mut().enumerate() {
        *byte = u8::try_from((index * 7 + 0x11) % 256).expect("in range");
    }
    let canonical = format_recovery_secret(&secret);
    let hex_only = &canonical[RECOVERY_SECRET_PREFIX.len()..];
    let grouped = {
        let mut grouped = String::new();
        for (index, character) in hex_only.chars().enumerate() {
            if index > 0 && index % 8 == 0 {
                grouped.push(' ');
            }
            grouped.push(character);
        }
        grouped
    };
    for variant in [
        format!("{canonical} "),
        canonical.replace(RECOVERY_SECRET_PREFIX, "nazo-recovery-"),
        grouped,
        canonical.to_ascii_uppercase(),
    ] {
        assert_eq!(
            parse_recovery_secret(&variant).unwrap(),
            secret,
            "variant {variant:?} must parse"
        );
    }
}

#[test]
fn parsing_rejects_everything_that_is_not_exactly_thirtytwo_bytes() {
    let short = format!("{}{}", RECOVERY_SECRET_PREFIX, "a".repeat(63));
    let long = "a".repeat(65);
    for invalid in [
        "",
        "NAZO-RECOVERY-",
        "NAZO-RECOVERY-00",
        // 63 digits.
        short.as_str(),
        // 65 digits.
        long.as_str(),
        // Non-hex payload.
        "NAZO-RECOVERY-zzzz",
        // Word-list style input is not part of this scheme.
        "abandon ability able about above absent absorb",
    ] {
        assert!(parse_recovery_secret(invalid).is_err(), "{invalid:?}");
    }
}

#[test]
fn derivation_is_deterministic_and_discriminates_secret_and_deployment() {
    let secret = [0x11u8; 32];
    let first = derive_recovery_seed(&secret, "deployment-a");
    assert_eq!(first, derive_recovery_seed(&secret, "deployment-a"));

    // One flipped hex digit of the displayed secret yields an unrelated key
    // (04A D10 acceptance #2).
    let mut mutated_display = format_recovery_secret(&secret);
    let last = mutated_display.pop().expect("non-empty");
    mutated_display.push(if last == '0' { '1' } else { '0' });
    let mutated_secret = parse_recovery_secret(&mutated_display).unwrap();
    assert_ne!(mutated_secret, secret);
    assert_ne!(
        recovery_public_key_bytes(&derive_recovery_seed(&mutated_secret, "deployment-a")),
        recovery_public_key_bytes(&first)
    );

    // The deployment salt participates.
    assert_ne!(first, derive_recovery_seed(&secret, "deployment-b"));
    // And so does the info string inside the raw KDF.
    assert_ne!(
        hkdf_sha256_v1(&secret, b"deployment-a", b"nazoauthctl/recovery", 32),
        hkdf_sha256_v1(&secret, b"deployment-a", b"nazoauthctl/recovery2", 32)
    );
}

#[test]
fn kdf_identifier_is_stable_and_challenge_action_is_frozen() {
    // Stored alongside every persisted root; changing it is a breaking
    // contract change, never a silent reinterpretation.
    assert_eq!(RECOVERY_KDF_ID, "hkdf-sha256-v1");
    assert_eq!(RECOVERY_CHALLENGE_ACTION, "controller-recovery");
    assert_eq!(
        RECOVERY_CHALLENGE_ALLOCATION_ACTION,
        "controller-recovery-allocate"
    );
    assert_eq!(super::RECOVERY_ROOT_ROTATE_ACTION, "recovery-root-rotate");
}

#[test]
fn allocation_proof_binds_nonce_deployment_and_complete_proposal() {
    let controller_public_key = recovery_public_key_bytes(&[21; 32]);
    let recovery_public_key = recovery_public_key_bytes(&[22; 32]);
    let proposal = RecoveryProposal {
        deployment_id: "deployment-a".to_owned(),
        controller_label: "recovered-primary".to_owned(),
        controller_kid: recovery_kid(&controller_public_key),
        controller_public_key,
        recovery_kid: recovery_kid(&recovery_public_key),
        recovery_public_key,
    };
    proposal.validate().expect("proposal should be well formed");
    let current_seed = derive_recovery_seed(&[0x33u8; 32], "deployment-a");
    let current_public_key = recovery_public_key_bytes(&current_seed);
    let allocation_nonce = [0x44u8; 32];
    let signature = proposal.sign_allocation(&allocation_nonce, &current_seed);

    assert!(proposal.verify_allocation_signature(
        &allocation_nonce,
        &current_public_key,
        &signature
    ));

    let mut other_nonce = allocation_nonce;
    other_nonce[0] ^= 1;
    assert!(!proposal.verify_allocation_signature(&other_nonce, &current_public_key, &signature));
    assert!(!proposal.verify_allocation_signature(
        &allocation_nonce,
        &recovery_public_key_bytes(&[0x55u8; 32]),
        &signature
    ));

    let mut mutations = Vec::new();
    let mut changed = proposal.clone();
    changed.deployment_id = "deployment-b".to_owned();
    mutations.push(changed);
    let mut changed = proposal.clone();
    changed.controller_label = "different".to_owned();
    mutations.push(changed);
    let mut changed = proposal.clone();
    changed.controller_public_key = recovery_public_key_bytes(&[23; 32]);
    changed.controller_kid = recovery_kid(&changed.controller_public_key);
    mutations.push(changed);
    let mut changed = proposal.clone();
    changed.recovery_public_key = recovery_public_key_bytes(&[24; 32]);
    changed.recovery_kid = recovery_kid(&changed.recovery_public_key);
    mutations.push(changed);
    for changed in mutations {
        assert!(!changed.verify_allocation_signature(
            &allocation_nonce,
            &current_public_key,
            &signature
        ));
    }
}

#[test]
fn rotation_digests_are_deterministic_and_discriminate_every_field() {
    let first = RecoveryRootRotation {
        deployment_id: "deployment-a".to_owned(),
        kid: recovery_kid(&recovery_public_key_bytes(&[31; 32])),
        public_key: recovery_public_key_bytes(&[31; 32]),
    };
    first.validate().expect("rotation should be well formed");
    let same = RecoveryRootRotation { ..first.clone() };
    assert_eq!(first.action_sha256(), same.action_sha256());
    let other_deployment = RecoveryRootRotation {
        deployment_id: "deployment-b".to_owned(),
        ..first.clone()
    };
    assert_ne!(first.action_sha256(), other_deployment.action_sha256());
    let other_key = RecoveryRootRotation {
        deployment_id: "deployment-a".to_owned(),
        kid: recovery_kid(&recovery_public_key_bytes(&[32; 32])),
        public_key: recovery_public_key_bytes(&[32; 32]),
    };
    assert_ne!(first.action_sha256(), other_key.action_sha256());
    for digest in [first.action_sha256(), other_key.action_sha256()] {
        assert_eq!(digest.len(), 64);
        assert!(
            digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        );
    }
}

#[test]
fn challenge_message_binds_every_field_and_signature_verifies_only_against_the_right_key() {
    let controller_public_key = recovery_public_key_bytes(&[21; 32]);
    let recovery_public_key = recovery_public_key_bytes(&[22; 32]);
    let proposal = RecoveryProposal {
        deployment_id: "deployment-a".to_owned(),
        controller_label: "recovered-primary".to_owned(),
        controller_kid: recovery_kid(&controller_public_key),
        controller_public_key,
        recovery_kid: recovery_kid(&recovery_public_key),
        recovery_public_key,
    };
    proposal.validate().expect("proposal should be well formed");
    let old_seed = derive_recovery_seed(&[0x33u8; 32], "deployment-a");
    let challenge_id = "019c8ca2-30a6-7cc9-9f2a-4f5a6b7c8d90";
    let nonce = [0x44u8; 32];

    let signature = proposal.sign_challenge(challenge_id, &nonce, &old_seed);
    assert!(proposal.verify_challenge_signature(
        challenge_id,
        &nonce,
        &recovery_public_key_bytes(&old_seed),
        &signature
    ));

    // A different key cannot verify.
    let wrong_key = recovery_public_key_bytes(&[0x55u8; 32]);
    assert!(!proposal.verify_challenge_signature(challenge_id, &nonce, &wrong_key, &signature));
    // A different nonce/challenge id breaks the binding.
    let mut other_nonce = nonce;
    other_nonce[0] ^= 1;
    assert!(!proposal.verify_challenge_signature(
        challenge_id,
        &other_nonce,
        &recovery_public_key_bytes(&old_seed),
        &signature
    ));
    assert!(!proposal.verify_challenge_signature(
        "019c8ca2-30a6-7cc9-9f2a-4f5a6b7c8d91",
        &nonce,
        &recovery_public_key_bytes(&old_seed),
        &signature
    ));
    // Garbage signatures fail closed instead of panicking.
    assert!(!proposal.verify_challenge_signature(
        challenge_id,
        &nonce,
        &recovery_public_key_bytes(&old_seed),
        &[0u8; 64]
    ));
}

#[test]
fn proposal_validation_rejects_unbound_kids_and_bad_shapes() {
    let controller_key = recovery_public_key_bytes(&[21; 32]);
    let recovery_key = recovery_public_key_bytes(&[22; 32]);
    let valid = RecoveryProposal {
        deployment_id: "deployment-a".to_owned(),
        controller_label: "recovered".to_owned(),
        controller_kid: recovery_kid(&controller_key),
        controller_public_key: controller_key,
        recovery_kid: recovery_kid(&recovery_key),
        recovery_public_key: recovery_key,
    };
    assert!(valid.validate().is_ok());
    let mut kid_mismatch = valid.clone();
    kid_mismatch.controller_kid = recovery_kid(&recovery_key);
    assert!(kid_mismatch.validate().is_err());
    let mut bad_deployment = valid.clone();
    bad_deployment.deployment_id = "bad/deployment".to_owned();
    assert!(bad_deployment.validate().is_err());
    let mut bad_label = valid;
    bad_label.controller_label = String::new();
    assert!(bad_label.validate().is_err());

    // Kids use the same material-binding convention as controller slots.
    assert_eq!(
        URL_SAFE_NO_PAD
            .decode(recovery_kid(&controller_key))
            .unwrap()
            .len(),
        32
    );
}
