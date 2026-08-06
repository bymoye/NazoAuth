use super::{
    config::{AuditAnchorMode, AuditAnchorPreflightConfig, AuditAnchorWorkerConfig},
    preflight::validate_health,
    protocol::{
        AnchorCheckpointEnvelope, CHECKPOINT_SCHEMA_VERSION, checkpoint_body, encode_hash,
        genesis_body, sign_body,
    },
    status::{AnchorHealth, HEALTH_SCHEMA_VERSION},
    worker::retry_delay,
};
use chrono::{Duration as ChronoDuration, Utc};
use nazo_postgres::SecurityAuditOutboxDelivery;
use serde_json::{Value, json};
use std::{path::PathBuf, time::Duration};
use url::Url;
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
    assert_eq!(retry_delay(i32::MAX), Duration::from_secs(300));
}

#[test]
fn mode_parser_and_preflight_configuration_reject_invalid_values() {
    assert_eq!(
        AuditAnchorMode::parse("disabled").unwrap(),
        AuditAnchorMode::Disabled
    );
    assert_eq!(
        AuditAnchorMode::parse("optional").unwrap(),
        AuditAnchorMode::Optional
    );
    assert_eq!(
        AuditAnchorMode::parse("required").unwrap(),
        AuditAnchorMode::Required
    );
    assert!(AuditAnchorMode::parse("unexpected").is_err());

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
fn worker_configuration_rejects_non_https_and_weak_secret() {
    let config = AuditAnchorWorkerConfig {
        preflight: required_config(),
        endpoint: Url::parse("http://anchor.example.test").unwrap(),
        auth_secret: vec![0; 15],
        poll_interval: Duration::from_secs(1),
        request_timeout: Duration::from_secs(1),
        batch_size: 1,
        lock_timeout_seconds: 1,
    };
    assert!(config.validate().is_err());
}

#[test]
fn checkpoint_body_is_stable_across_retries_and_contains_recomputable_event() {
    let delivery = SecurityAuditOutboxDelivery {
        event_id: Uuid::nil(),
        sequence: 7,
        event_type: "admin_user_updated".to_owned(),
        event_category: "administration".to_owned(),
        payload: json!({"user_id": "user-1"}),
        occurred_at: Utc::now(),
        previous_hash: vec![1; 32],
        event_hash: vec![2; 32],
        attempts: 1,
    };
    let first = checkpoint_body("deployment-1", &delivery).unwrap();
    let second = checkpoint_body("deployment-1", &delivery).unwrap();
    assert_eq!(first, second);
    assert_eq!(
        sign_body(b"anchor-secret-that-is-long-enough", &first),
        sign_body(b"anchor-secret-that-is-long-enough", &second)
    );

    let Value::Object(fields) = serde_json::from_slice(&first).unwrap() else {
        panic!("checkpoint must be a JSON object");
    };
    assert_eq!(fields["event_type"], "admin_user_updated");
    assert_eq!(fields["event_category"], "administration");
    assert_eq!(fields["payload"]["user_id"], "user-1");
    assert!(!fields.contains_key("anchored_at"));
}

#[test]
fn genesis_body_is_stable_and_has_explicit_kind() {
    let first = genesis_body("deployment-1", &[0; 32]).unwrap();
    let second = genesis_body("deployment-1", &[0; 32]).unwrap();
    assert_eq!(first, second);
    let value: Value = serde_json::from_slice(&first).unwrap();
    assert_eq!(value["checkpoint_kind"], "genesis");
    assert_eq!(value["sequence"], 0);
}

#[test]
fn checkpoint_envelope_contains_identity_chain_and_event_content() {
    let envelope = AnchorCheckpointEnvelope {
        schema_version: CHECKPOINT_SCHEMA_VERSION,
        event_id: Uuid::nil(),
        deployment_id: "deployment-1",
        sequence: 7,
        previous_hash: encode_hash(&[1; 32]),
        event_hash: encode_hash(&[2; 32]),
        event_type: "admin_user_updated",
        event_category: "administration",
        payload: json!({"user_id": "user-1"}),
        occurred_at: Utc::now(),
    };
    let Value::Object(fields) =
        serde_json::to_value(envelope).expect("checkpoint should serialize")
    else {
        panic!("checkpoint must be a JSON object");
    };
    assert_eq!(fields["deployment_id"], "deployment-1");
    assert_eq!(fields["sequence"], 7);
    assert!(fields.contains_key("previous_hash"));
    assert!(fields.contains_key("event_hash"));
    assert!(fields.contains_key("occurred_at"));
    assert!(fields.contains_key("event_type"));
    assert!(fields.contains_key("event_category"));
    assert!(fields.contains_key("payload"));
}

#[test]
fn preflight_accepts_current_health_and_rejects_stale_or_unanchored_health() {
    let config = required_config();
    let now = Utc::now();
    let current = AnchorHealth {
        schema_version: HEALTH_SCHEMA_VERSION.to_owned(),
        deployment_id: config.deployment_id.clone(),
        observed_at: now - ChronoDuration::seconds(1),
        head_sequence: 7,
        head_hash: encode_hash(&[2; 32]),
        pending_count: 0,
        oldest_pending_occurred_at: None,
        last_anchored_sequence: Some(7),
        last_anchored_hash: Some(encode_hash(&[2; 32])),
        last_anchored_occurred_at: Some(now - ChronoDuration::seconds(2)),
        last_anchored_at: Some(now - ChronoDuration::seconds(1)),
        anchor_lag_seconds: Some(1),
    };
    assert!(validate_health(&config, &current, 7, &[2; 32], now).is_ok());

    let mut stale = current.clone();
    stale.observed_at = now - ChronoDuration::seconds(61);
    assert!(validate_health(&config, &stale, 7, &[2; 32], now).is_err());

    let mut behind = current;
    behind.last_anchored_sequence = Some(6);
    assert!(validate_health(&config, &behind, 7, &[2; 32], now).is_err());
}

fn required_config() -> AuditAnchorPreflightConfig {
    AuditAnchorPreflightConfig {
        mode: AuditAnchorMode::Required,
        deployment_id: "deployment-1".to_owned(),
        status_file: PathBuf::from("runtime/anchor-health.json"),
        freshness: Duration::from_secs(60),
        max_lag: Duration::from_secs(300),
    }
}
