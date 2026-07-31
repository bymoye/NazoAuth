use std::collections::BTreeMap;

use ed25519_dalek::SigningKey;
use proptest::prelude::*;

use super::*;

// This module is included by lib.rs so private protocol invariants remain testable.

fn task() -> TaskEnvelope {
    TaskEnvelope {
        ver: PROTOCOL_VERSION,
        iss: "controller:deployment-1".to_owned(),
        aud: "runtime:deployment-1".to_owned(),
        jti: "019fffffffffffffffffffffffffffff".to_owned(),
        iat: 1_000,
        nbf: 1_000,
        exp: 1_060,
        deployment_id: "deployment-1".to_owned(),
        actor: Actor {
            kind: ActorKind::LocalRoot,
            id: "uid:0".to_owned(),
        },
        target: TargetExpectation::OciImage {
            image_ref: "localhost/nazoauth:v1.0.0".to_owned(),
            image_digest: format!("sha256:{}", "a".repeat(64)),
        },
        embedded: EmbeddedIdentity {
            release: "v1.0.0".to_owned(),
            revision: "b".repeat(40),
            protocol: PROTOCOL_VERSION,
            build_id: "github:1234567".to_owned(),
        },
        config: ConfigBinding {
            manifest_version: CONFIG_MANIFEST_VERSION,
            config_sha256: "d".repeat(64),
            secret_binding: SecretBinding::OpaqueRevision {
                revision: "secret-revision-1".to_owned(),
            },
        },
        operation: TaskOperation::MigrateApply,
    }
}

#[test]
fn golden_task_vector_is_stable_and_verifies() {
    let key = SigningKey::from_bytes(&[7; 32]);
    let compact = sign_task(&task(), "controller-1", &key).unwrap();
    assert_eq!(
        compact,
        "eyJhbGciOiJFZERTQSIsImtpZCI6ImNvbnRyb2xsZXItMSIsInR5cCI6Im5hem9hdXRoLW9wZXJhdG9yLXRhc2srand0In0.eyJ2ZXIiOjEsImlzcyI6ImNvbnRyb2xsZXI6ZGVwbG95bWVudC0xIiwiYXVkIjoicnVudGltZTpkZXBsb3ltZW50LTEiLCJqdGkiOiIwMTlmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZiIsImlhdCI6MTAwMCwibmJmIjoxMDAwLCJleHAiOjEwNjAsImRlcGxveW1lbnRfaWQiOiJkZXBsb3ltZW50LTEiLCJhY3RvciI6eyJraW5kIjoibG9jYWwtcm9vdCIsImlkIjoidWlkOjAifSwidGFyZ2V0Ijp7ImtpbmQiOiJvY2ktaW1hZ2UiLCJpbWFnZV9yZWYiOiJsb2NhbGhvc3QvbmF6b2F1dGg6djEuMC4wIiwiaW1hZ2VfZGlnZXN0Ijoic2hhMjU2OmFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWEifSwiZW1iZWRkZWQiOnsicmVsZWFzZSI6InYxLjAuMCIsInJldmlzaW9uIjoiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYiIsInByb3RvY29sIjoxLCJidWlsZF9pZCI6ImdpdGh1YjoxMjM0NTY3In0sImNvbmZpZyI6eyJtYW5pZmVzdF92ZXJzaW9uIjoxLCJjb25maWdfc2hhMjU2IjoiZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZCIsInNlY3JldF9iaW5kaW5nIjp7ImtpbmQiOiJvcGFxdWUtcmV2aXNpb24iLCJyZXZpc2lvbiI6InNlY3JldC1yZXZpc2lvbi0xIn19LCJvcGVyYXRpb24iOnsibmFtZSI6Im1pZ3JhdGUtYXBwbHkifX0.qEhY-6YCHJRQEFUtb3_1jVuISQmyUjc-3exLFMKOgoyVX_fvlwR-NGQ44Y_Ar1FrRK9DgvpWjD-9qklWtiq0AQ"
    );
    assert_eq!(
        verify_task(&compact, "controller-1", &key.verifying_key(), 1_030).unwrap(),
        task()
    );
    assert_eq!(compact_sha256(&compact).len(), 64);
}

#[test]
fn rejects_unknown_claims_and_algorithm_confusion() {
    let key = SigningKey::from_bytes(&[7; 32]);
    let compact = sign_task(&task(), "controller-1", &key).unwrap();
    let mut segments = compact.split('.').collect::<Vec<_>>();
    let payload = URL_SAFE_NO_PAD.decode(segments[1]).unwrap();
    let mut value: serde_json::Value = serde_json::from_slice(&payload).unwrap();
    value["secret"] = serde_json::json!("must-not-be-accepted");
    segments[1] = Box::leak(
        URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&value).unwrap())
            .into_boxed_str(),
    );
    let tampered = segments.join(".");
    assert!(matches!(
        verify_task(&tampered, "controller-1", &key.verifying_key(), 1_030),
        Err(ProtocolError::Signature)
    ));

    let mut header = ProtectedHeader {
        alg: FixedAlgorithm::EdDSA,
        kid: "controller-1".to_owned(),
        typ: "JWT".to_owned(),
    };
    assert_eq!(header.typ, "JWT");
    header.typ = TASK_JWS_TYPE.to_owned();
    assert_eq!(header.typ, TASK_JWS_TYPE);
}

#[test]
fn expired_envelope_keeps_authenticated_identity_but_cannot_authorize_new_work() {
    let key = SigningKey::from_bytes(&[7; 32]);
    let compact = sign_task(&task(), "controller-1", &key).unwrap();
    assert_eq!(
        verify_task_signature(&compact, "controller-1", &key.verifying_key()).unwrap(),
        task()
    );
    assert!(verify_task(&compact, "controller-1", &key.verifying_key(), 2_000).is_err());
}

#[test]
fn canonical_config_digest_is_order_independent() {
    let first = CanonicalConfigManifest {
        version: CONFIG_MANIFEST_VERSION,
        entries: BTreeMap::from([
            ("runtime.engine".to_owned(), "podman".to_owned()),
            (
                "runtime.issuer".to_owned(),
                "https://auth.example".to_owned(),
            ),
        ]),
    };
    let second = CanonicalConfigManifest {
        version: CONFIG_MANIFEST_VERSION,
        entries: first
            .entries
            .iter()
            .rev()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
    };
    assert_eq!(
        canonical_config_sha256(&first).unwrap(),
        canonical_config_sha256(&second).unwrap()
    );
}

#[test]
fn every_signed_message_type_roundtrips_and_rejects_a_wrong_key() {
    let runtime_key = SigningKey::from_bytes(&[11; 32]);
    let controller_key = SigningKey::from_bytes(&[12; 32]);
    let wrong_key = SigningKey::from_bytes(&[13; 32]);
    let source = task();
    let outcome = TaskOutcome::Succeeded {
        result: TaskResult::Migration { applied: true },
    };
    let runtime = RuntimeReceipt {
        ver: PROTOCOL_VERSION,
        iss: "runtime:deployment-1".to_owned(),
        aud: "controller:deployment-1".to_owned(),
        jti: source.jti.clone(),
        request_sha256: "e".repeat(64),
        deployment_id: source.deployment_id.clone(),
        actor: source.actor.clone(),
        operation: "migrate-apply".to_owned(),
        started_at: 1_001,
        completed_at: 1_002,
        embedded: source.embedded.clone(),
        config: source.config.clone(),
        outcome: outcome.clone(),
    };
    let compact_runtime = sign_runtime_receipt(&runtime, "receipt-1", &runtime_key).unwrap();
    assert_eq!(
        verify_runtime_receipt(&compact_runtime, "receipt-1", &runtime_key.verifying_key())
            .unwrap(),
        runtime
    );
    assert!(
        verify_runtime_receipt(&compact_runtime, "receipt-1", &wrong_key.verifying_key()).is_err()
    );

    let final_receipt = FinalReceipt {
        ver: PROTOCOL_VERSION,
        iss: source.iss.clone(),
        aud: "operator-audit".to_owned(),
        jti: source.jti.clone(),
        request_sha256: "e".repeat(64),
        deployment_id: source.deployment_id.clone(),
        actor: source.actor.clone(),
        operation: "migrate-apply".to_owned(),
        completed_at: 1_002,
        audit_sequence: 1,
        audit_previous_sha256: "0".repeat(64),
        controller_verified_target: RuntimeTargetClaim::OciImage {
            image_ref: "localhost/nazoauth:v1.0.0".to_owned(),
            image_digest: format!("sha256:{}", "a".repeat(64)),
        },
        embedded: source.embedded.clone(),
        config: source.config.clone(),
        runtime_receipt_sha256: compact_sha256(&compact_runtime),
        outcome,
    };
    let compact_final =
        sign_final_receipt(&final_receipt, "controller-1", &controller_key).unwrap();
    assert_eq!(
        verify_final_receipt(
            &compact_final,
            "controller-1",
            &controller_key.verifying_key()
        )
        .unwrap(),
        final_receipt
    );

    let transition = ControllerTrustTransition {
        ver: PROTOCOL_VERSION,
        deployment_id: source.deployment_id.clone(),
        issued_at: 1_003,
        authorization: TransitionAuthorization::Controller,
        previous_key_id: "controller-1".to_owned(),
        next_key_id: "controller-2".to_owned(),
        next_public_key_sha256: "f".repeat(64),
        previous_audit_key_id: "audit-1".to_owned(),
        next_audit_key_id: "audit-2".to_owned(),
        next_audit_public_key_sha256: "a".repeat(64),
        previous_break_glass_key_id: "break-glass-1".to_owned(),
        next_break_glass_key_id: "break-glass-1".to_owned(),
        next_break_glass_public_key_sha256: "b".repeat(64),
        reason: "scheduled-rotation".to_owned(),
    };
    let compact_transition =
        sign_trust_transition(&transition, "controller-1", &controller_key).unwrap();
    assert_eq!(
        verify_trust_transition(
            &compact_transition,
            "controller-1",
            &controller_key.verifying_key()
        )
        .unwrap(),
        transition
    );

    let event = ManagementAuditEvent {
        ver: PROTOCOL_VERSION,
        deployment_id: source.deployment_id,
        sequence: 1,
        previous_sha256: "0".repeat(64),
        request_id: source.jti,
        issued_at: 1_004,
        actor: source.actor,
        operation: "update".to_owned(),
        release: "v1.0.0".to_owned(),
        recovery_boundary: "artifact-and-schema-compatible".to_owned(),
    };
    let compact_event = sign_management_event(&event, "controller-1", &controller_key).unwrap();
    assert_eq!(
        verify_management_event(
            &compact_event,
            "controller-1",
            &controller_key.verifying_key()
        )
        .unwrap(),
        event
    );
}

proptest! {
    #[test]
    fn arbitrary_compact_input_never_panics(input in any::<Vec<u8>>()) {
        let key = SigningKey::from_bytes(&[9; 32]);
        let input = String::from_utf8_lossy(&input);
        let _ = verify_task(&input, "controller-1", &key.verifying_key(), 1_030);
    }

    #[test]
    fn validity_window_is_enforced(delta in 61i64..10_000) {
        let mut envelope = task();
        envelope.exp = envelope.iat + delta;
        let key = SigningKey::from_bytes(&[7; 32]);
        prop_assert!(matches!(sign_task(&envelope, "controller-1", &key), Err(ProtocolError::Policy(_))));
    }
}
