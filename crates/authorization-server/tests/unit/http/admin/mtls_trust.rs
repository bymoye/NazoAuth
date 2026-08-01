use super::normalized_decision_note;

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
}
