//! Pure service-layer pins for the Recovery Root plane (04A D10-D12):
//! strict wire shapes, digest determinism, and the "no secret field exists"
//! boundary.  Storage invariants live in `nazo-postgres` tests.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest as _, Sha256};

use super::{RecoveryChallengeRequest, RecoveryRootChangeRequest};

fn key_text(seed: u8) -> String {
    URL_SAFE_NO_PAD.encode([seed; 32])
}

fn kid_text(seed: u8) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest([seed; 32]))
}

#[test]
fn rotation_request_shape_is_strict_and_rejects_secret_shaped_fields() {
    let well_formed = serde_json::json!({
        "deployment_id": "deployment-a",
        "recovery_public_key": key_text(1),
        "kid": kid_text(1),
    })
    .to_string();
    let parsed: RecoveryRootChangeRequest =
        serde_json::from_str(&well_formed).expect("well-formed request must parse");
    assert_eq!(parsed.deployment_id, "deployment-a");

    // Any unknown member — including a recovery-secret-shaped one — is a hard
    // parse error: NazoAuth has no field that could accept secret material.
    for smuggled in [
        r#""recovery_secret":"NAZO-RECOVERY-00""#,
        r#""secret":"x""#,
        r#""label":"extra""#,
    ] {
        let without_closing_brace = well_formed.strip_suffix('}').expect("json object");
        let smuggled_payload = format!("{without_closing_brace},{smuggled}}}");
        assert!(
            serde_json::from_str::<RecoveryRootChangeRequest>(&smuggled_payload).is_err(),
            "unknown field must be refused: {smuggled_payload}"
        );
    }
}

#[test]
fn challenge_request_shape_is_strict() {
    let well_formed = serde_json::json!({
        "deployment_id": "deployment-a",
        "label": "recovered",
        "controller_public_key": key_text(2),
        "kid": kid_text(2),
        "recovery_public_key": key_text(3),
        "recovery_kid": kid_text(3),
        "allocation_nonce": URL_SAFE_NO_PAD.encode([4u8; 32]),
        "allocation_signature": URL_SAFE_NO_PAD.encode([5u8; 64]),
    })
    .to_string();
    assert!(
        serde_json::from_str::<RecoveryChallengeRequest>(&well_formed).is_ok(),
        "well-formed challenge request must parse"
    );
    let without_closing_brace = well_formed.strip_suffix('}').expect("json object");
    let smuggled = format!("{without_closing_brace},\"recovery_secret\":\"x\"}}");
    assert!(
        serde_json::from_str::<RecoveryChallengeRequest>(&smuggled).is_err(),
        "unknown field must be refused"
    );
    let mut unsigned: serde_json::Value = serde_json::from_str(&well_formed).unwrap();
    unsigned
        .as_object_mut()
        .unwrap()
        .remove("allocation_signature");
    assert!(
        serde_json::from_value::<RecoveryChallengeRequest>(unsigned).is_err(),
        "the pre-proof request shape must be rejected instead of accepted through a fallback"
    );
}

#[test]
fn answer_material_decodes_only_exact_byte_lengths() {
    let nonce = URL_SAFE_NO_PAD.encode([7u8; 32]);
    let signature = URL_SAFE_NO_PAD.encode([8u8; 64]);
    assert!(super::decode_fixed::<32>(&nonce, "nonce").is_ok());
    assert!(super::decode_fixed::<64>(&signature, "signature").is_ok());
    // Off-by-one encodings are rejected before any storage is consulted.
    assert!(super::decode_fixed::<32>(&URL_SAFE_NO_PAD.encode([7u8; 31]), "nonce").is_err());
    assert!(super::decode_fixed::<64>(&URL_SAFE_NO_PAD.encode([8u8; 63]), "signature").is_err());
    assert!(super::decode_fixed::<32>("not-base64!!", "nonce").is_err());
}
