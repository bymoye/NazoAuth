use super::*;
use chrono::Utc;
use serde_json::Value;
use std::{path::PathBuf, time::Duration};
use uuid::Uuid;

#[test]
fn checkpoint_signature_is_deterministic_and_url_safe() {
    let body = br#"{"sequence":7,"event_hash":"abc"}"#;
    let first = sign_body(b"anchor-secret-that-is-long-enough", body);
    let second = sign_body(b"anchor-secret-that-is-long-enough", body);

    assert_eq!(first, second);
    assert!(!first.is_empty());
    assert!(
        first
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    );
}

#[test]
fn retry_backoff_is_bounded() {
    assert_eq!(retry_delay(1), Duration::from_secs(1));
    assert_eq!(retry_delay(2), Duration::from_secs(2));
    assert_eq!(retry_delay(9), Duration::from_secs(256));
    assert_eq!(retry_delay(i32::MAX), MAX_RETRY_DELAY);
}

#[test]
fn preflight_configuration_rejects_invalid_identity_and_path() {
    let invalid_identity = AuditAnchorPreflightConfig {
        mode: AuditAnchorMode::Required,
        deployment_id: "deployment/with-slash".to_owned(),
        status_file: PathBuf::from("runtime/anchor-health.json"),
        freshness: Duration::from_secs(60),
        max_lag: Duration::from_secs(300),
    };
    assert!(invalid_identity.validate().is_err());

    let empty_path = AuditAnchorPreflightConfig {
        mode: AuditAnchorMode::Required,
        deployment_id: "deployment-1".to_owned(),
        status_file: PathBuf::new(),
        freshness: Duration::from_secs(60),
        max_lag: Duration::from_secs(300),
    };
    assert!(empty_path.validate().is_err());
}

#[test]
fn checkpoint_envelope_contains_identity_chain_and_time_without_event_payload() {
    let event_id = Uuid::now_v7();
    let envelope = AnchorCheckpointEnvelope {
        schema_version: CHECKPOINT_SCHEMA_VERSION,
        event_id,
        deployment_id: "deployment-1",
        sequence: 7,
        previous_hash: encode_hash(&[1; 32]),
        event_hash: encode_hash(&[2; 32]),
        occurred_at: Utc::now(),
        anchored_at: Utc::now(),
    };
    let value = serde_json::to_value(envelope).expect("checkpoint should serialize");
    let Value::Object(fields) = value else {
        panic!("checkpoint must be a JSON object");
    };
    assert_eq!(fields["deployment_id"], "deployment-1");
    assert_eq!(fields["sequence"], 7);
    assert!(fields.contains_key("previous_hash"));
    assert!(fields.contains_key("event_hash"));
    assert!(fields.contains_key("occurred_at"));
    assert!(fields.contains_key("anchored_at"));
    assert!(!fields.contains_key("payload"));
}
