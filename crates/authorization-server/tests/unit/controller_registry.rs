//! D01/D02/D05 service-layer pins that need no database: identity formats,
//! kid/key binding, canonical action digests, and expiry-warning boundaries.
//! Storage invariants live in `nazo-postgres` tests.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{Duration, TimeZone, Utc};
use nazo_operator_protocol::validate_controller_id;
use sha2::{Digest as _, Sha256};

use super::{
    ControllerKeyWarning, IdentityChange, RevokeRequest, RotateRequest, SlotChangeRequest,
    ensure_local_deployment, expiry_warning, validate_slot_request,
};

fn public_key_text(seed: u8) -> String {
    URL_SAFE_NO_PAD.encode([seed; 32])
}

fn kid_text(seed: u8) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest([seed; 32]))
}

const CONTROLLER_ID: &str = "019c8ca2-30a6-7cc9-9f2a-4f5a6b7c8d90";

fn at(seconds: i64) -> chrono::DateTime<Utc> {
    Utc.timestamp_opt(1_800_000_000 + seconds, 0)
        .single()
        .expect("valid timestamp")
}

fn slot_request(deployment: &str, label: &str, seed: u8) -> SlotChangeRequest {
    SlotChangeRequest {
        deployment_id: deployment.to_owned(),
        label: label.to_owned(),
        kid: kid_text(seed),
        public_key: public_key_text(seed),
        recovery_public_key: None,
        recovery_kid: None,
    }
}

#[test]
fn controller_identity_is_a_canonical_lowercase_uuidv7() {
    // The authoritative D01 format, shared by the registry and the E03 journal
    // snapshot: canonical lowercase RFC 9562 UUIDv7.
    assert!(validate_controller_id(CONTROLLER_ID).is_ok());
    assert!(validate_controller_id("controller-test").is_err());
    assert!(validate_controller_id(&CONTROLLER_ID.to_uppercase()).is_err());
    let mut v4 = CONTROLLER_ID.to_owned();
    v4.replace_range(14..15, "4");
    assert!(validate_controller_id(&v4).is_err());
    assert!(validate_controller_id("").is_err());
    assert!(validate_controller_id("019c8ca2-30a6-7000-8000-00000000000").is_err());
}

#[test]
fn slot_requests_reject_kids_that_do_not_bind_to_their_key_material() {
    assert!(
        validate_slot_request(
            "deployment-ok",
            "primary",
            &kid_text(1),
            &public_key_text(1)
        )
        .is_ok()
    );
    let error = validate_slot_request(
        "deployment-ok",
        "primary",
        &kid_text(2),
        &public_key_text(1),
    )
    .expect_err("kid from a different key must be refused");
    let rendered = format!("{error:?}");
    assert!(
        rendered.starts_with("Invalid"),
        "unexpected error: {rendered}"
    );
    // Malformed key material is refused before storage sees it.
    assert!(validate_slot_request("deployment-ok", "primary", &kid_text(1), "***").is_err());
    assert!(validate_slot_request("deployment-ok", "primary", &kid_text(1), "").is_err());
    // 31-byte keys are not representable as Ed25519 public keys here.
    let short = URL_SAFE_NO_PAD.encode([1u8; 31]);
    assert!(validate_slot_request("deployment-ok", "primary", &kid_text(1), &short).is_err());
}

#[test]
fn action_digests_are_deterministic_and_discriminate_every_field() {
    let request = slot_request("deployment-a", "ops", 1);
    let bind = IdentityChange::Bind(request.clone());
    let same_again = IdentityChange::Bind(request.clone());
    assert_eq!(bind.action_sha256(), same_again.action_sha256());

    // A different action over identical key material has a different digest.
    let add = IdentityChange::Add(request.clone());
    assert_ne!(bind.action_sha256(), add.action_sha256());

    // Every payload field participates: deployment, label, kid, key bytes.
    let different_deployment = IdentityChange::Bind(slot_request("deployment-b", "ops", 1));
    assert_ne!(bind.action_sha256(), different_deployment.action_sha256());
    let different_label = IdentityChange::Bind(slot_request("deployment-a", "other", 1));
    assert_ne!(bind.action_sha256(), different_label.action_sha256());
    let different_key = IdentityChange::Bind(slot_request("deployment-a", "ops", 2));
    assert_ne!(bind.action_sha256(), different_key.action_sha256());

    let rotate = IdentityChange::Rotate(RotateRequest {
        deployment_id: "deployment-a".to_owned(),
        controller_id: CONTROLLER_ID.to_owned(),
        label: "rotated".to_owned(),
        kid: kid_text(3),
        public_key: public_key_text(3),
    });
    let revoke = IdentityChange::Revoke(RevokeRequest {
        deployment_id: "deployment-a".to_owned(),
        controller_id: CONTROLLER_ID.to_owned(),
    });
    for (left, right) in [
        (&bind, &add),
        (&bind, &rotate),
        (&bind, &revoke),
        (&rotate, &revoke),
    ] {
        assert_ne!(left.action_sha256(), right.action_sha256());
    }
    // Digests are lowercase sha256 hex.
    for change in [&bind, &rotate, &revoke] {
        let digest = change.action_sha256();
        assert_eq!(digest.len(), 64);
        assert!(
            digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        );
    }
}

#[test]
fn expiry_warnings_fire_at_seven_days_and_twenty_four_hours() {
    // A freshly issued slot sits a full 30-day TTL away from its deadline.
    let expires = at(0) + Duration::seconds(2_592_000);
    assert_eq!(expiry_warning(at(0), expires), None);
    // Exactly 7 days remaining: the expiring warning starts.
    assert_eq!(
        expiry_warning(expires - Duration::days(7), expires),
        Some(ControllerKeyWarning::Expiring)
    );
    // One second more remaining time than the warning window means no warning
    // yet: the 7-day band starts inclusively at exactly seven days.
    assert_eq!(
        expiry_warning(expires - Duration::days(7) - Duration::seconds(1), expires),
        None
    );
    // Exactly 24 hours remaining: urgent.
    assert_eq!(
        expiry_warning(expires - Duration::hours(24), expires),
        Some(ControllerKeyWarning::Urgent)
    );
    // Already expired remains urgent (status surfaces still render).
    assert_eq!(
        expiry_warning(expires + Duration::hours(1), expires),
        Some(ControllerKeyWarning::Urgent)
    );
}

#[test]
fn deployment_binding_accepts_local_and_rejects_foreign_callers() {
    assert!(ensure_local_deployment("deployment-a", "deployment-a").is_ok());
    assert!(ensure_local_deployment("deployment-a", "deployment-b").is_err());
}
