use super::{normalized_decision_note, sha256_hex};

#[test]
fn trust_decision_notes_are_bounded_and_rejections_require_a_reason() {
    assert_eq!(
        normalized_decision_note(Some("  reviewed  ".to_owned()), true)
            .expect("bounded approval note"),
        Some("reviewed".to_owned())
    );
    assert_eq!(
        normalized_decision_note(Some("  ".to_owned()), true).expect("empty approval note"),
        None
    );
    assert!(normalized_decision_note(None, false).is_err());
    assert!(normalized_decision_note(Some("x".repeat(1001)), true).is_err());
    assert!(normalized_decision_note(Some("x".repeat(1001)), false).is_err());
    assert_eq!(
        normalized_decision_note(Some("x".repeat(1000)), true)
            .expect("exactly bounded approval note"),
        Some("x".repeat(1000))
    );
}

#[test]
fn trust_bundle_digest_is_stable_and_redaction_safe() {
    assert_eq!(
        sha256_hex(b"certificate-bundle"),
        "8935d3d68f48b1f04e6a881317b91f734e45a10e7d13fd44873a4c4e8285d78f"
    );
    assert!(!sha256_hex(b"certificate-bundle").contains("certificate-bundle"));
}
