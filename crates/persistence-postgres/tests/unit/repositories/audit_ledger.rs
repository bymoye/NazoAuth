use super::*;

fn event(payload: Value) -> SecurityAuditEvent {
    SecurityAuditEvent {
        event_id: Uuid::now_v7(),
        event_type: "token_issued".to_owned(),
        event_category: "token_lifecycle".to_owned(),
        payload,
        occurred_at: Utc::now(),
    }
}

#[test]
fn audit_hash_is_domain_separated_and_chain_ordered() {
    let first = event(serde_json::json!({"subject_hash": "a"}));
    let first_payload = serde_json::to_vec(&first.payload).unwrap();
    let first_hash = hash_event(1, &[0; 32], &first, &first_payload);

    let second = event(serde_json::json!({"subject_hash": "a"}));
    let second_payload = serde_json::to_vec(&second.payload).unwrap();
    let second_hash = hash_event(2, &first_hash, &second, &second_payload);

    assert_ne!(first_hash, second_hash);
    assert_ne!(
        first_hash,
        hash_event(1, &[0; 32], &second, &second_payload)
    );
}

#[test]
fn audit_event_validation_rejects_non_object_and_invalid_names() {
    let mut invalid = event(Value::String("not-an-object".to_owned()));
    assert!(validate_event(&invalid).is_err());
    invalid.payload = serde_json::json!({});
    invalid.event_type = "TokenIssued".to_owned();
    assert!(validate_event(&invalid).is_err());
}
