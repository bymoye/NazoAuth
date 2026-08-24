//! Pure-logic pins for the controller registry storage boundary (D01/D02).
//! Database-backed invariant and race tests live in `tests/controller_registry.rs`.

use super::{
    ControllerIdentityAction, ControllerRegistryError, ControllerSlotStatus, NewControllerSlot,
    RotateControllerKey, lowest_free_slot_index, validate_controller_id, validate_kid,
    validate_kid_binding, validate_label,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest as _, Sha256};

const CANONICAL_V7: &str = "018f6a52-3b7c-7cc9-9f2a-4f5a6b7c8d90";

fn kid_of(public_key: &[u8; 32]) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(public_key))
}

#[test]
fn controller_id_requires_canonical_lowercase_uuidv7() {
    assert!(validate_controller_id(CANONICAL_V7).is_ok());
    // Wrong version nibble (v4) is rejected: identity is time-ordered v7 only.
    let mut v4 = CANONICAL_V7.to_owned();
    v4.replace_range(14..15, "4");
    assert!(matches!(
        validate_controller_id(&v4),
        Err(ControllerRegistryError::InvalidIdentity(_))
    ));
    // Wrong RFC 9562 variant nibble is rejected.
    let mut bad_variant = CANONICAL_V7.to_owned();
    bad_variant.replace_range(19..20, "c");
    assert!(matches!(
        validate_controller_id(&bad_variant),
        Err(ControllerRegistryError::InvalidIdentity(_))
    ));
    // Uppercase is not canonical.
    assert!(validate_controller_id(&CANONICAL_V7.to_uppercase()).is_err());
    // Truncated/overlong shapes are rejected.
    assert!(validate_controller_id("").is_err());
    assert!(validate_controller_id("not-a-uuid").is_err());
}

#[test]
fn kid_shape_must_be_unpadded_base64url_sha256_length() {
    assert!(validate_kid(&kid_of(&[7u8; 32])).is_ok());
    assert!(validate_kid("").is_err());
    assert!(validate_kid(&"a".repeat(42)).is_err());
    assert!(validate_kid(&"a".repeat(44)).is_err());
    // '+' and '/' belong to padded standard base64, never to this alphabet.
    let mut padded = kid_of(&[9u8; 32]).into_bytes();
    padded[0] = b'+';
    assert!(validate_kid(std::str::from_utf8(&padded).unwrap()).is_err());
}

#[test]
fn kid_must_bind_to_public_key_material() {
    let key = [3u8; 32];
    assert!(validate_kid_binding(&kid_of(&key), &key).is_ok());
    let other = [4u8; 32];
    assert!(matches!(
        validate_kid_binding(&kid_of(&other), &key),
        Err(ControllerRegistryError::InvalidIdentity(_))
    ));
}

#[test]
fn label_bounds_are_enforced_before_storage() {
    assert!(validate_label("ops-a").is_ok());
    assert!(validate_label("").is_err());
    assert!(validate_label(&"x".repeat(129)).is_err());
    assert!(validate_label(&"x".repeat(128)).is_ok());
    assert!(validate_label("bad\u{0007}label").is_err());
}

#[test]
fn slot_index_selection_fills_lowest_free_and_stops_at_three() {
    let slots = |indices: &[i16]| -> Vec<super::StoredControllerSlot> {
        indices
            .iter()
            .map(|index| super::StoredControllerSlot {
                deployment_id: "d".to_owned(),
                controller_id: CANONICAL_V7.to_owned(),
                label: "l".to_owned(),
                kid: kid_of(&[0u8; 32]),
                public_key: vec![0u8; 32],
                slot_index: *index,
                issued_at: chrono::Utc::now(),
                expires_at: chrono::Utc::now(),
                last_used_at: None,
                status: ControllerSlotStatus::Active,
                revoked_at: None,
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
            })
            .collect()
    };
    assert_eq!(lowest_free_slot_index(&[]), Some(0));
    assert_eq!(lowest_free_slot_index(&slots(&[0])), Some(1));
    assert_eq!(lowest_free_slot_index(&slots(&[0, 1])), Some(2));
    assert_eq!(lowest_free_slot_index(&slots(&[2])), Some(0));
    assert_eq!(lowest_free_slot_index(&slots(&[0, 2])), Some(1));
    // Revoked rows are filtered out before this point by the SQL predicate;
    // three active rows exhaust the index space.
    assert_eq!(lowest_free_slot_index(&slots(&[0, 1, 2])), None);
}

#[test]
fn identity_action_catalog_is_closed() {
    for action in [
        ControllerIdentityAction::Bind,
        ControllerIdentityAction::Add,
        ControllerIdentityAction::Rotate,
        ControllerIdentityAction::Revoke,
        // D12 rotates the recovery root through the same approval machinery
        // under its own action value (04A).
        ControllerIdentityAction::RecoveryRootRotate,
    ] {
        assert_eq!(
            ControllerIdentityAction::parse(action.as_str()),
            Some(action)
        );
    }
    assert_eq!(ControllerIdentityAction::parse("recovery"), None);
    assert_eq!(ControllerIdentityAction::parse("recovery-root"), None);
    assert_eq!(ControllerIdentityAction::parse(""), None);
    assert_eq!(ControllerIdentityAction::parse("BIND"), None);
}

#[test]
fn status_catalog_is_closed() {
    assert_eq!(
        ControllerSlotStatus::from_str("active"),
        Some(ControllerSlotStatus::Active)
    );
    assert_eq!(
        ControllerSlotStatus::from_str("revoked"),
        Some(ControllerSlotStatus::Revoked)
    );
    assert_eq!(ControllerSlotStatus::from_str("expired"), None);
    assert_eq!(ControllerSlotStatus::from_str(""), None);
}

#[test]
fn summary_never_carries_public_key_bytes() {
    let slot = super::StoredControllerSlot {
        deployment_id: "dep".to_owned(),
        controller_id: CANONICAL_V7.to_owned(),
        label: "primary".to_owned(),
        kid: kid_of(&[11u8; 32]),
        public_key: vec![11u8; 32],
        slot_index: 0,
        issued_at: chrono::Utc::now(),
        expires_at: chrono::Utc::now(),
        last_used_at: None,
        status: ControllerSlotStatus::Active,
        revoked_at: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };
    let summary = slot.summary();
    let rendered = format!("{summary:?}");
    assert!(!rendered.contains("public_key"));
    assert_eq!(summary.kid, slot.kid);
    assert_eq!(summary.controller_id, slot.controller_id);
}

// Compile-time shape pin: private keys are not representable in write inputs
// because they carry exactly 32 public-key bytes.
const _: fn([u8; 32]) -> () = |_| ();

#[allow(dead_code)]
fn write_input_shapes(
    slot: NewControllerSlot,
    rotate: RotateControllerKey,
) -> ([u8; 32], [u8; 32]) {
    (slot.public_key, rotate.public_key)
}
