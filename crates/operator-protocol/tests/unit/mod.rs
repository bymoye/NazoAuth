use std::collections::BTreeMap;

use ed25519_dalek::SigningKey;
use proptest::prelude::*;

use super::*;
use crate::verification::*;

// This module is included by lib.rs so private protocol invariants remain testable.

mod control_operation_tests;

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

const TENANT_ID: &str = "00000000-0000-0000-0000-000000000001";

fn tenant_resource_task() -> TenantResourceTask {
    TenantResourceTask {
        ver: PROTOCOL_VERSION,
        iss: "controller:deployment-1".to_owned(),
        aud: "runtime:deployment-1".to_owned(),
        jti: "tenant-resource-task-1".to_owned(),
        iat: 1_000,
        nbf: 1_000,
        exp: 1_060,
        deployment_id: "deployment-1".to_owned(),
        tenant_id: TENANT_ID.to_owned(),
        capability_jti: "tenant-resource-capability-1".to_owned(),
        capability_sha256: "9".repeat(64),
        actor: Actor {
            kind: ActorKind::Automation,
            id: "ctl:resource-manager".to_owned(),
        },
        expected_revision: 7,
        change_set_id: "change-set-1".to_owned(),
        change_set_sha256: "a".repeat(64),
        operation: TenantResourceOperation::Apply,
        payload: TenantResourceTaskPayload::Apply {
            resources: vec![TenantResourceIdentity {
                kind: TenantResourceKind::OauthClient,
                resource_id: "client:primary".to_owned(),
                digest: "b".repeat(64),
            }],
        },
        baseline_manifest_sha256: "e".repeat(64),
        resource_manifest_sha256: "c".repeat(64),
    }
}

fn tenant_resource_capability() -> TenantResourceCapability {
    TenantResourceCapability {
        ver: PROTOCOL_VERSION,
        capability_version: TENANT_RESOURCE_CAPABILITY_VERSION,
        jti: "tenant-resource-capability-1".to_owned(),
        nonce: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8".to_owned(),
        deployment_id: "deployment-1".to_owned(),
        tenant_id: TENANT_ID.to_owned(),
        runtime_instance_id: "runtime-1".to_owned(),
        issuer: "runtime:deployment-1".to_owned(),
        instance_key_id: "instance-1".to_owned(),
        embedded: EmbeddedIdentity {
            release: "v1.0.0".to_owned(),
            revision: "d".repeat(40),
            protocol: PROTOCOL_VERSION,
            build_id: "github:resource-1".to_owned(),
        },
        revision: 7,
        resource_manifest_sha256: "e".repeat(64),
        resource_kinds: vec![
            TenantResourceKind::OauthClient,
            TenantResourceKind::MtlsTrustAnchor,
            TenantResourceKind::Openid4vcDataset,
            TenantResourceKind::Openid4vcTrustPolicy,
            TenantResourceKind::User,
        ],
        actions: vec![
            TenantResourceOperation::Apply,
            TenantResourceOperation::Enumerate,
            TenantResourceOperation::Revoke,
        ],
        issued_at: 1_000,
        expires_at: 1_060,
    }
}

fn tenant_resource_receipt() -> TenantResourceReceipt {
    let task = tenant_resource_task();
    TenantResourceReceipt {
        ver: PROTOCOL_VERSION,
        iss: "runtime:deployment-1".to_owned(),
        aud: "controller:deployment-1".to_owned(),
        jti: task.jti,
        request_sha256: "f".repeat(64),
        deployment_id: task.deployment_id,
        tenant_id: task.tenant_id,
        capability_jti: task.capability_jti,
        capability_sha256: task.capability_sha256,
        actor: task.actor,
        change_set_id: task.change_set_id,
        change_set_sha256: task.change_set_sha256,
        operation: task.operation,
        expected_revision: task.expected_revision,
        revision: 8,
        outcome: TenantResourceOutcome::Succeeded,
        resources: vec![TenantResourceIdentity {
            kind: TenantResourceKind::OauthClient,
            resource_id: "client:primary".to_owned(),
            digest: "b".repeat(64),
        }],
        resource_mappings: vec![TenantResourceMapping {
            kind: TenantResourceKind::OauthClient,
            resource_id: "client:primary".to_owned(),
            public_id: "client-public-1".to_owned(),
        }],
        baseline_manifest_sha256: "e".repeat(64),
        resource_manifest_sha256: task.resource_manifest_sha256,
        started_at: 1_001,
        completed_at: 1_010,
        exp: 1_060,
        audit_sequence: 7,
        audit_previous_sha256: "0".repeat(64),
    }
}

fn discovery_statement() -> DiscoveryStatement {
    DiscoveryStatement {
        schema: CONTROL_DISCOVERY_SCHEMA,
        product: CONTROL_DISCOVERY_PRODUCT.to_owned(),
        deployment_id: "deployment-1".to_owned(),
        runtime_instance_id: "runtime-1".to_owned(),
        issuer: "https://auth.example".to_owned(),
        release: "v0.1.19".to_owned(),
        revision: "a".repeat(40),
        build_id: "github:123".to_owned(),
        control_protocol_versions: vec![CONTROL_DISCOVERY_SCHEMA],
        operator_protocol_versions: vec![PROTOCOL_VERSION],
        instance_key_id: "instance-1".to_owned(),
        nonce: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8".to_owned(),
        issued_at: 1_000,
        expires_at: 1_060,
    }
}

fn deployment_statement() -> DeploymentStatement {
    let online = discovery_statement();
    DeploymentStatement {
        schema: online.schema,
        product: online.product,
        deployment_id: online.deployment_id,
        runtime_instance_id: online.runtime_instance_id,
        issuer: online.issuer,
        release: online.release,
        revision: online.revision,
        build_id: online.build_id,
        control_protocol_versions: online.control_protocol_versions,
        operator_protocol_versions: online.operator_protocol_versions,
        instance_key_id: online.instance_key_id,
        issued_at: online.issued_at,
    }
}

fn adoption_receipt() -> AdoptionReceipt {
    AdoptionReceipt {
        schema: CONTROL_DISCOVERY_SCHEMA,
        deployment_id: "deployment-1".to_owned(),
        issuer: "https://auth.example".to_owned(),
        runtime_instances: vec![AdoptedRuntimeIdentity {
            runtime_instance_id: "runtime-1".to_owned(),
            backend: "podman".to_owned(),
            object_reference: "container/nazoauth-manual".to_owned(),
            artifact_identity: format!("sha256:{}", "a".repeat(64)),
        }],
        verified_release: "v0.1.19".to_owned(),
        release_manifest_sha256: "b".repeat(64),
        instance_key_ids: vec!["instance-1".to_owned()],
        resource_references: BTreeMap::from([
            (
                "database".to_owned(),
                "provider/postgresql-primary".to_owned(),
            ),
            ("runtime".to_owned(), "container/nazoauth-manual".to_owned()),
        ]),
        capabilities: BTreeMap::from([
            ("database".to_owned(), "external:shared".to_owned()),
            ("runtime".to_owned(), "managed:deployment".to_owned()),
        ]),
        recovery_proven: true,
        recovery_evidence: vec!["snapshot/backup-1".to_owned()],
        plan_sha256: "c".repeat(64),
        adopted_at: 1_000,
    }
}

#[test]
fn golden_control_discovery_vector_is_stable_and_nonce_bound() {
    let key = SigningKey::from_bytes(&[17; 32]);
    let compact = sign_discovery_statement(&discovery_statement(), "instance-1", &key).unwrap();
    assert_eq!(
        compact,
        "eyJhbGciOiJFZERTQSIsImtpZCI6Imluc3RhbmNlLTEiLCJ0eXAiOiJuYXpvYXV0aC1jb250cm9sLWRpc2NvdmVyeStqd3QifQ.eyJzY2hlbWEiOjEsInByb2R1Y3QiOiJuYXpvYXV0aCIsImRlcGxveW1lbnRfaWQiOiJkZXBsb3ltZW50LTEiLCJydW50aW1lX2luc3RhbmNlX2lkIjoicnVudGltZS0xIiwiaXNzdWVyIjoiaHR0cHM6Ly9hdXRoLmV4YW1wbGUiLCJyZWxlYXNlIjoidjAuMS4xOSIsInJldmlzaW9uIjoiYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYSIsImJ1aWxkX2lkIjoiZ2l0aHViOjEyMyIsImNvbnRyb2xfcHJvdG9jb2xfdmVyc2lvbnMiOlsxXSwib3BlcmF0b3JfcHJvdG9jb2xfdmVyc2lvbnMiOlsxXSwiaW5zdGFuY2Vfa2V5X2lkIjoiaW5zdGFuY2UtMSIsIm5vbmNlIjoiQUFFQ0F3UUZCZ2NJQ1FvTERBME9EeEFSRWhNVUZSWVhHQmthR3h3ZEhoOCIsImlzc3VlZF9hdCI6MTAwMCwiZXhwaXJlc19hdCI6MTA2MH0.vhgW-rjLNlNkKqGvmGtvTOSyMgmrLTHbFo6m3ZMP_Hho7V5ME41CVgzz9S3HRB6WEDPVizGSWTP7nIODBkhQBg"
    );
    assert_eq!(
        verify_discovery_statement(
            &compact,
            "instance-1",
            &key.verifying_key(),
            &discovery_statement().nonce,
            1_030,
        )
        .unwrap(),
        discovery_statement()
    );
    assert!(
        verify_discovery_statement(
            &compact,
            "instance-1",
            &key.verifying_key(),
            "AQECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
            1_030,
        )
        .is_err()
    );
}

#[test]
fn offline_deployment_statement_is_identity_evidence_not_artifact_trust() {
    let key = SigningKey::from_bytes(&[17; 32]);
    let offline = deployment_statement();
    let compact = sign_deployment_statement(&offline, "instance-1", &key).unwrap();
    assert_eq!(
        verify_deployment_statement(&compact, "instance-1", &key.verifying_key()).unwrap(),
        offline
    );
    assert_eq!(
        protected_header(&compact).unwrap().typ,
        DEPLOYMENT_STATEMENT_JWS_TYPE
    );
}

#[test]
fn adoption_receipt_roundtrips_and_enforces_bounded_recovery_evidence() {
    let key = SigningKey::from_bytes(&[19; 32]);
    let receipt = adoption_receipt();
    let compact = sign_adoption_receipt(&receipt, "receipt-1", &key).unwrap();
    assert_eq!(
        verify_adoption_receipt(&compact, "receipt-1", &key.verifying_key()).unwrap(),
        receipt
    );
    assert_eq!(
        protected_header(&compact).unwrap().typ,
        ADOPTION_RECEIPT_JWS_TYPE
    );

    let mut invalid = adoption_receipt();
    invalid.schema += 1;
    assert!(sign_adoption_receipt(&invalid, "receipt-1", &key).is_err());

    let mut invalid = adoption_receipt();
    invalid.runtime_instances.clear();
    assert!(sign_adoption_receipt(&invalid, "receipt-1", &key).is_err());

    let mut invalid = adoption_receipt();
    invalid.runtime_instances = vec![invalid.runtime_instances[0].clone(); 129];
    assert!(sign_adoption_receipt(&invalid, "receipt-1", &key).is_err());

    let mut invalid = adoption_receipt();
    invalid.instance_key_ids.clear();
    assert!(sign_adoption_receipt(&invalid, "receipt-1", &key).is_err());

    let mut invalid = adoption_receipt();
    invalid
        .runtime_instances
        .push(invalid.runtime_instances[0].clone());
    invalid.instance_key_ids.push("instance-2".to_owned());
    assert!(sign_adoption_receipt(&invalid, "receipt-1", &key).is_err());

    let mut invalid = adoption_receipt();
    invalid
        .instance_key_ids
        .push(invalid.instance_key_ids[0].clone());
    invalid.runtime_instances.push(AdoptedRuntimeIdentity {
        runtime_instance_id: "runtime-2".to_owned(),
        ..invalid.runtime_instances[0].clone()
    });
    assert!(sign_adoption_receipt(&invalid, "receipt-1", &key).is_err());

    let mut invalid = adoption_receipt();
    invalid.resource_references = (0..65)
        .map(|index| (format!("resource-{index}"), "external/shared".to_owned()))
        .collect();
    assert!(sign_adoption_receipt(&invalid, "receipt-1", &key).is_err());

    let mut invalid = adoption_receipt();
    invalid.recovery_evidence = vec!["snapshot/evidence".to_owned(); 65];
    assert!(sign_adoption_receipt(&invalid, "receipt-1", &key).is_err());

    let mut invalid = adoption_receipt();
    invalid.recovery_evidence.clear();
    assert!(sign_adoption_receipt(&invalid, "receipt-1", &key).is_err());

    let mut invalid = adoption_receipt();
    invalid.runtime_instances[0].object_reference = "secret={must-not-be-recorded}".to_owned();
    assert!(sign_adoption_receipt(&invalid, "receipt-1", &key).is_err());
}

#[test]
fn discovery_and_offline_identity_fail_closed_on_invalid_claims() {
    let key = SigningKey::from_bytes(&[17; 32]);
    let nonce = discovery_statement().nonce;
    assert!(
        validate_discovery_request(&DiscoveryRequest {
            schema: CONTROL_DISCOVERY_SCHEMA + 1,
            nonce: nonce.clone(),
        })
        .is_err()
    );
    for invalid_nonce in ["short".to_owned(), "!".repeat(43)] {
        assert!(
            validate_discovery_request(&DiscoveryRequest {
                schema: CONTROL_DISCOVERY_SCHEMA,
                nonce: invalid_nonce,
            })
            .is_err()
        );
    }
    assert!(decode_instance_public_key("AA").is_err());

    let mut online = discovery_statement();
    online.instance_key_id = "instance-other".to_owned();
    assert!(sign_discovery_statement(&online, "instance-1", &key).is_err());
    let forged = sign_compact(&online, "instance-1", CONTROL_DISCOVERY_JWS_TYPE, &key).unwrap();
    assert!(
        verify_discovery_statement(&forged, "instance-1", &key.verifying_key(), &nonce, 1_030,)
            .is_err()
    );

    let mutations: [fn(&mut DiscoveryStatement); 5] = [
        |statement: &mut DiscoveryStatement| statement.schema += 1,
        |statement: &mut DiscoveryStatement| statement.product = "other".to_owned(),
        |statement: &mut DiscoveryStatement| statement.control_protocol_versions.clear(),
        |statement: &mut DiscoveryStatement| {
            statement.operator_protocol_versions = vec![PROTOCOL_VERSION, PROTOCOL_VERSION]
        },
        |statement: &mut DiscoveryStatement| statement.expires_at = statement.issued_at + 61,
    ];
    for mutate in mutations {
        let mut invalid = discovery_statement();
        mutate(&mut invalid);
        assert!(sign_discovery_statement(&invalid, "instance-1", &key).is_err());
    }

    let mut offline = deployment_statement();
    offline.instance_key_id = "instance-other".to_owned();
    assert!(sign_deployment_statement(&offline, "instance-1", &key).is_err());
    let forged = sign_compact(&offline, "instance-1", DEPLOYMENT_STATEMENT_JWS_TYPE, &key).unwrap();
    assert!(verify_deployment_statement(&forged, "instance-1", &key.verifying_key()).is_err());

    let mut offline = deployment_statement();
    offline.issued_at = 0;
    assert!(sign_deployment_statement(&offline, "instance-1", &key).is_err());
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
    assert_eq!(
        protected_header(&compact).unwrap(),
        ProtectedHeader {
            alg: FixedAlgorithm::EdDSA,
            kid: "controller-1".to_owned(),
            typ: TASK_JWS_TYPE.to_owned(),
        }
    );
}

#[test]
fn task_deployment_binding_requires_local_identity_and_exact_claims() {
    let valid = task();
    validate_task_deployment_binding(&valid, "deployment-1").unwrap();

    for (mut invalid, expected) in [
        (
            {
                let mut value = valid.clone();
                value.deployment_id = "deployment-2".to_owned();
                value
            },
            "deployment-1",
        ),
        (
            {
                let mut value = valid.clone();
                value.iss = "controller:deployment-2".to_owned();
                value
            },
            "deployment-1",
        ),
        (
            {
                let mut value = valid.clone();
                value.aud = "runtime:deployment-2".to_owned();
                value
            },
            "deployment-1",
        ),
    ] {
        assert!(validate_task_deployment_binding(&invalid, expected).is_err());
        invalid.deployment_id = expected.to_owned();
        invalid.iss = format!("controller:{expected}");
        invalid.aud = format!("runtime:{expected}");
        validate_task_deployment_binding(&invalid, expected).unwrap();
    }

    assert!(validate_task_deployment_binding(&valid, "").is_err());
}

#[test]
fn protected_header_rejects_untrusted_key_lookup_inputs() {
    for header in [
        serde_json::json!({
            "alg": "EdDSA",
            "kid": "../../controller",
            "typ": TASK_JWS_TYPE,
        }),
        serde_json::json!({
            "alg": "EdDSA",
            "kid": "controller-1",
            "typ": TASK_JWS_TYPE,
            "jku": "https://attacker.example/jwks.json",
        }),
        serde_json::json!({
            "alg": "none",
            "kid": "controller-1",
            "typ": TASK_JWS_TYPE,
        }),
    ] {
        let compact = format!(
            "{}.e30.AA",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap())
        );
        assert!(matches!(
            protected_header(&compact),
            Err(ProtocolError::Header)
        ));
    }
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
fn openid4vc_trust_policy_accepts_bounded_public_bundle_and_rejects_unknowns() {
    let coordinate = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let ec_key = |kid: &str| {
        serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": coordinate,
            "y": coordinate,
            "kid": kid,
        })
    };
    let certificate =
        |label: &str| format!("-----BEGIN CERTIFICATE-----\n{label}\n-----END CERTIFICATE-----\n");
    let policy = Openid4vcTrustPolicy {
        schema: 1,
        client_attestation_issuer: "https://issuer.example/attestation".to_owned(),
        client_attestation_jwks: serde_json::json!({"keys": [ec_key("client")]}),
        key_attestation_jwks: serde_json::json!({"keys": [ec_key("holder")]}),
        credential_trust_anchor_pem: format!("{}{}", certificate("MA=="), certificate("MDE=")),
        wallet_authorization_origins: vec!["https://wallet.example".to_owned()],
    };
    validate_openid4vc_trust_policy(&policy).unwrap();
    let mut no_trailing_newline = policy.clone();
    no_trailing_newline.credential_trust_anchor_pem = certificate("MA==").trim_end().to_owned();
    validate_openid4vc_trust_policy(&no_trailing_newline).unwrap();
    let mut crlf_bundle = policy.clone();
    crlf_bundle.credential_trust_anchor_pem = certificate("MA==").replace('\n', "\r\n");
    validate_openid4vc_trust_policy(&crlf_bundle).unwrap();

    let mut unknown_wire = serde_json::to_value(&policy).unwrap();
    unknown_wire["unexpected_wire_field"] = serde_json::json!(true);
    assert!(serde_json::from_value::<Openid4vcTrustPolicy>(unknown_wire).is_err());

    let mut invalid_schema = policy.clone();
    invalid_schema.schema = 2;
    assert!(validate_openid4vc_trust_policy(&invalid_schema).is_err());

    for issuer in [
        "",
        "http://issuer.example",
        "https://",
        "https://issuer.example/path?x=1",
    ] {
        let mut invalid = policy.clone();
        invalid.client_attestation_issuer = issuer.to_owned();
        assert!(validate_openid4vc_trust_policy(&invalid).is_err());
    }
    let mut oversized_issuer = policy.clone();
    oversized_issuer.client_attestation_issuer = format!("https://{}", "i".repeat(2048));
    assert!(validate_openid4vc_trust_policy(&oversized_issuer).is_err());

    let mut empty_jwks = policy.clone();
    empty_jwks.client_attestation_jwks = serde_json::json!({"keys": []});
    assert!(validate_openid4vc_trust_policy(&empty_jwks).is_err());

    let mut empty_origins = policy.clone();
    empty_origins.wallet_authorization_origins.clear();
    assert!(validate_openid4vc_trust_policy(&empty_origins).is_err());

    for origin in [
        "http://wallet.example",
        "https://wallet.example/",
        "https://user@wallet.example",
        "https://wallet.example/path",
        "https://wallet.example?query",
        "https://wallet.example#fragment",
        "https://wallet.example:443",
        "https://-wallet.example",
        "HTTPS://wallet.example",
    ] {
        let mut invalid = policy.clone();
        invalid.wallet_authorization_origins = vec![origin.to_owned()];
        assert!(validate_openid4vc_trust_policy(&invalid).is_err());
    }
    let mut duplicate_origins = policy.clone();
    duplicate_origins.wallet_authorization_origins = vec![
        "https://wallet.example".to_owned(),
        "https://wallet.example".to_owned(),
    ];
    assert!(validate_openid4vc_trust_policy(&duplicate_origins).is_err());

    let mut private_jwk = policy.clone();
    private_jwk.client_attestation_jwks["keys"][0]["d"] = serde_json::json!("secret");
    assert!(validate_openid4vc_trust_policy(&private_jwk).is_err());

    let mut unknown_jwks_member = policy.clone();
    unknown_jwks_member.client_attestation_jwks["unexpected"] = serde_json::json!(true);
    assert!(validate_openid4vc_trust_policy(&unknown_jwks_member).is_err());

    let mut unknown_jwk_member = policy.clone();
    unknown_jwk_member.client_attestation_jwks["keys"][0]["unexpected"] = serde_json::json!(true);
    assert!(validate_openid4vc_trust_policy(&unknown_jwk_member).is_err());

    for pem in [
        "",
        "public",
        "-----BEGIN PRIVATE KEY-----\nprivate\n-----END PRIVATE KEY-----\n",
        "-----BEGIN PUBLIC KEY-----\nMA==\n-----END PUBLIC KEY-----\n",
        "-----BEGIN CERTIFICATE-----\rMA==\r-----END CERTIFICATE-----",
    ] {
        let mut invalid = policy.clone();
        invalid.credential_trust_anchor_pem = pem.to_owned();
        assert!(validate_openid4vc_trust_policy(&invalid).is_err());
    }
    let mut oversized_pem = policy.clone();
    oversized_pem.credential_trust_anchor_pem = format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        "x".repeat(16 * 1024)
    );
    assert!(validate_openid4vc_trust_policy(&oversized_pem).is_err());

    let mut oversized_json = policy;
    oversized_json.client_attestation_jwks["keys"][0]["kid"] =
        serde_json::json!("k".repeat(33 * 1024));
    assert!(validate_openid4vc_trust_policy(&oversized_json).is_err());
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
    validate_runtime_receipt_deployment_binding(&runtime, "deployment-1").unwrap();
    assert!(validate_runtime_receipt_deployment_binding(&runtime, "deployment-2").is_err());
    let mut wrong_runtime = runtime.clone();
    wrong_runtime.aud = "controller:deployment-2".to_owned();
    assert!(validate_runtime_receipt_deployment_binding(&wrong_runtime, "deployment-1").is_err());
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
        event.clone()
    );

    let mut encoded_evidence = event.clone();
    encoded_evidence.recovery_boundary = format!("evidence-v1.{}", "_".repeat(300));
    assert!(sign_management_event(&encoded_evidence, "controller-1", &controller_key).is_ok());
    encoded_evidence.recovery_boundary = "{raw-json-is-not-an-audit-boundary}".to_owned();
    assert!(matches!(
        sign_management_event(&encoded_evidence, "controller-1", &controller_key),
        Err(ProtocolError::Policy(_))
    ));
}

#[test]
fn historic_conformance_receipt_remains_readable() {
    let controller_key = SigningKey::from_bytes(&[36; 32]);
    let source = task();
    let receipt = FinalReceipt {
        ver: PROTOCOL_VERSION,
        iss: source.iss.clone(),
        aud: "operator-audit".to_owned(),
        jti: source.jti.clone(),
        request_sha256: "e".repeat(64),
        deployment_id: source.deployment_id.clone(),
        actor: source.actor.clone(),
        operation: "conformance-lease-list".to_owned(),
        completed_at: 1_002,
        audit_sequence: 1,
        audit_previous_sha256: "0".repeat(64),
        controller_verified_target: RuntimeTargetClaim::OciImage {
            image_ref: "localhost/nazoauth:v1.0.0".to_owned(),
            image_digest: format!("sha256:{}", "a".repeat(64)),
        },
        embedded: source.embedded,
        config: source.config,
        runtime_receipt_sha256: "f".repeat(64),
        outcome: TaskOutcome::Succeeded {
            result: TaskResult::ConformanceLeaseList { leases: Vec::new() },
        },
    };
    let compact = sign_final_receipt(&receipt, "controller-1", &controller_key).unwrap();
    assert_eq!(
        verify_final_receipt(&compact, "controller-1", &controller_key.verifying_key()).unwrap(),
        receipt
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

#[test]
fn task_and_receipt_validation_covers_crypto_targets_and_versions() {
    let valid = task();
    validate_task(&valid).unwrap();

    let mut invalid = valid.clone();
    invalid.ver += 1;
    assert!(validate_task(&invalid).is_err());
    let mut invalid = valid.clone();
    invalid.actor.id = "uid 0".to_owned();
    assert!(validate_task(&invalid).is_err());
    let mut invalid = valid.clone();
    invalid.jti = "jti/with-slash".to_owned();
    assert!(validate_task(&invalid).is_err());
    let mut invalid = valid.clone();
    invalid.deployment_id = "deployment/1".to_owned();
    assert!(validate_task(&invalid).is_err());
    let mut invalid = valid.clone();
    invalid.exp = invalid.iat - 1;
    assert!(validate_task(&invalid).is_err());
    let mut invalid = valid.clone();
    invalid.exp = invalid.iat + MAX_TASK_LIFETIME_SECONDS + 1;
    assert!(validate_task(&invalid).is_err());
    let mut invalid = valid.clone();
    invalid.nbf = invalid.iat - 1;
    assert!(validate_task(&invalid).is_err());
    let mut invalid = valid.clone();
    invalid.config.manifest_version += 1;
    assert!(validate_task(&invalid).is_err());
    let mut invalid = valid.clone();
    invalid.config.config_sha256 = "D".repeat(64);
    assert!(validate_task(&invalid).is_err());
    let mut invalid = valid.clone();
    invalid.embedded.build_id = "build id".to_owned();
    assert!(validate_task(&invalid).is_err());
    let mut invalid = valid.clone();
    invalid.iat = 0;
    invalid.nbf = 0;
    assert!(validate_task(&invalid).is_err());
    let mut invalid = valid.clone();
    invalid.embedded.protocol = PROTOCOL_VERSION + 1;
    assert!(validate_task(&invalid).is_err());
    let mut invalid = valid.clone();
    invalid.embedded.release = "bad release".to_owned();
    assert!(validate_task(&invalid).is_err());

    let mut host_binary = valid.clone();
    host_binary.target = TargetExpectation::HostBinary {
        path: "/usr/local/bin/nazoauth".to_owned(),
        sha256: "e".repeat(64),
    };
    validate_task(&host_binary).unwrap();
    host_binary.target = TargetExpectation::HostBinary {
        path: "relative path with spaces".to_owned(),
        sha256: "e".repeat(64),
    };
    assert!(validate_task(&host_binary).is_err());
    host_binary.target = TargetExpectation::HostBinary {
        path: "/usr/local/bin/nazoauth".to_owned(),
        sha256: "E".repeat(64),
    };
    assert!(validate_task(&host_binary).is_err());
    let mut bad_oci = valid.clone();
    bad_oci.target = TargetExpectation::OciImage {
        image_ref: "localhost/nazoauth:v1".to_owned(),
        image_digest: "e".repeat(64),
    };
    assert!(validate_task(&bad_oci).is_err());

    let mut hmac = valid.clone();
    hmac.config.secret_binding = SecretBinding::HmacSha256 {
        key_id: "config-key".to_owned(),
        digest: "f".repeat(64),
    };
    validate_task(&hmac).unwrap();
    hmac.config.secret_binding = SecretBinding::HmacSha256 {
        key_id: "bad key".to_owned(),
        digest: "f".repeat(64),
    };
    assert!(validate_task(&hmac).is_err());
    hmac.config.secret_binding = SecretBinding::HmacSha256 {
        key_id: "config-key".to_owned(),
        digest: "F".repeat(64),
    };
    assert!(validate_task(&hmac).is_err());

    let source = task();
    let mut final_receipt = FinalReceipt {
        ver: PROTOCOL_VERSION,
        iss: source.iss.clone(),
        aud: "operator-audit".to_owned(),
        jti: source.jti.clone(),
        request_sha256: "a".repeat(64),
        deployment_id: source.deployment_id.clone(),
        actor: source.actor.clone(),
        operation: "migrate-apply".to_owned(),
        completed_at: 1_002,
        audit_sequence: 1,
        audit_previous_sha256: "0".repeat(64),
        controller_verified_target: RuntimeTargetClaim::HostBinary {
            path: "/usr/local/bin/nazoauth".to_owned(),
            sha256: "b".repeat(64),
        },
        embedded: source.embedded.clone(),
        config: source.config.clone(),
        runtime_receipt_sha256: "c".repeat(64),
        outcome: TaskOutcome::Succeeded {
            result: TaskResult::Migration { applied: true },
        },
    };
    validate_final_receipt(&final_receipt).unwrap();
    final_receipt.ver += 1;
    assert!(validate_final_receipt(&final_receipt).is_err());
    final_receipt.ver = PROTOCOL_VERSION;
    final_receipt.iss = "bad value".to_owned();
    assert!(validate_final_receipt(&final_receipt).is_err());
    final_receipt.iss = source.iss.clone();
    final_receipt.jti = "bad/jti".to_owned();
    assert!(validate_final_receipt(&final_receipt).is_err());
    final_receipt.jti = source.jti.clone();
    final_receipt.deployment_id = "bad/id".to_owned();
    assert!(validate_final_receipt(&final_receipt).is_err());
    final_receipt.deployment_id = source.deployment_id.clone();
    final_receipt.request_sha256 = "A".repeat(64);
    assert!(validate_final_receipt(&final_receipt).is_err());
    final_receipt.request_sha256 = "a".repeat(64);
    final_receipt.runtime_receipt_sha256 = "B".repeat(64);
    assert!(validate_final_receipt(&final_receipt).is_err());
    final_receipt.runtime_receipt_sha256 = "c".repeat(64);
    final_receipt.audit_previous_sha256 = "G".repeat(64);
    assert!(validate_final_receipt(&final_receipt).is_err());
    final_receipt.audit_previous_sha256 = "0".repeat(64);
    final_receipt.completed_at = 0;
    assert!(validate_final_receipt(&final_receipt).is_err());
    final_receipt.completed_at = 1_002;
    final_receipt.audit_sequence = 0;
    assert!(validate_final_receipt(&final_receipt).is_err());
    final_receipt.audit_sequence = 1;
    final_receipt.controller_verified_target = RuntimeTargetClaim::HostBinary {
        path: "bad path".to_owned(),
        sha256: "b".repeat(64),
    };
    assert!(validate_final_receipt(&final_receipt).is_err());

    let mut runtime = RuntimeReceipt {
        ver: PROTOCOL_VERSION,
        iss: "runtime:deployment-1".to_owned(),
        aud: "controller:deployment-1".to_owned(),
        jti: source.jti,
        request_sha256: "a".repeat(64),
        deployment_id: "deployment-1".to_owned(),
        actor: source.actor,
        operation: "migrate-apply".to_owned(),
        started_at: 1_001,
        completed_at: 1_002,
        embedded: source.embedded,
        config: source.config,
        outcome: TaskOutcome::Failed {
            code: "runtime-failure".to_owned(),
        },
    };
    let key = SigningKey::from_bytes(&[14; 32]);
    sign_runtime_receipt(&runtime, "receipt-1", &key).unwrap();
    runtime.completed_at = runtime.started_at - 1;
    assert!(sign_runtime_receipt(&runtime, "receipt-1", &key).is_err());
    runtime.completed_at = 1_002;
    runtime.embedded.protocol = PROTOCOL_VERSION + 1;
    assert!(sign_runtime_receipt(&runtime, "receipt-1", &key).is_err());
    runtime.embedded.protocol = PROTOCOL_VERSION;
    runtime.ver = PROTOCOL_VERSION + 1;
    let compact = sign_compact(&runtime, "receipt-1", RUNTIME_RECEIPT_JWS_TYPE, &key).unwrap();
    assert!(matches!(
        verify_runtime_receipt(&compact, "receipt-1", &key.verifying_key()),
        Err(ProtocolError::Policy("unsupported receipt version"))
    ));
}

#[test]
fn identity_transition_and_audit_boundaries_are_checked() {
    let statement = discovery_statement();
    validate_discovery_statement(&statement, 1_030, Some(&statement.nonce)).unwrap();
    let mut invalid = statement.clone();
    invalid.schema += 1;
    assert!(validate_discovery_statement(&invalid, 1_030, None).is_err());
    let mut invalid = statement.clone();
    invalid.product = "other".to_owned();
    assert!(validate_discovery_statement(&invalid, 1_030, None).is_err());
    for field in ["deployment/1", "runtime/1", "instance/1"] {
        let mut candidate = statement.clone();
        candidate.deployment_id = field.to_owned();
        assert!(validate_discovery_statement(&candidate, 1_030, None).is_err());
    }
    for field in [
        "issuer value",
        "release value",
        "revision value",
        "build value",
    ] {
        let mut candidate = statement.clone();
        candidate.issuer = field.to_owned();
        assert!(validate_discovery_statement(&candidate, 1_030, None).is_err());
    }
    let mut invalid = statement.clone();
    invalid.control_protocol_versions = vec![CONTROL_DISCOVERY_SCHEMA, CONTROL_DISCOVERY_SCHEMA];
    assert!(validate_discovery_statement(&invalid, 1_030, None).is_err());
    let mut invalid = statement.clone();
    invalid.control_protocol_versions = vec![CONTROL_DISCOVERY_SCHEMA + 1];
    assert!(validate_discovery_statement(&invalid, 1_030, None).is_err());
    let mut invalid = statement.clone();
    invalid.control_protocol_versions = (1..=17).collect();
    assert!(validate_discovery_statement(&invalid, 1_030, None).is_err());
    let mut invalid = statement.clone();
    invalid.operator_protocol_versions = vec![PROTOCOL_VERSION + 1];
    assert!(validate_discovery_statement(&invalid, 1_030, None).is_err());
    let mut invalid = statement.clone();
    invalid.instance_key_id = "instance/1".to_owned();
    assert!(validate_discovery_statement(&invalid, 1_030, None).is_err());
    assert!(validate_discovery_statement(&statement, 1_030, Some("different-nonce")).is_err());
    assert!(validate_discovery_statement(&statement, 999, None).is_err());
    assert!(validate_discovery_statement(&statement, 1_061, None).is_err());
    let mut invalid = statement.clone();
    invalid.expires_at = invalid.issued_at - 1;
    assert!(validate_discovery_statement(&invalid, 1_000, None).is_err());
    let mut invalid = statement.clone();
    invalid.expires_at = invalid.issued_at + MAX_DISCOVERY_LIFETIME_SECONDS + 1;
    assert!(validate_discovery_statement(&invalid, 1_000, None).is_err());
    assert!(
        validate_discovery_request(&DiscoveryRequest {
            schema: CONTROL_DISCOVERY_SCHEMA,
            nonce: URL_SAFE_NO_PAD.encode([1u8; 31]),
        })
        .is_err()
    );

    let mut deployment = deployment_statement();
    validate_deployment_statement(&deployment).unwrap();
    deployment.issued_at = 0;
    assert!(validate_deployment_statement(&deployment).is_err());
    let mut deployment = deployment_statement();
    deployment.product = "other".to_owned();
    assert!(validate_deployment_statement(&deployment).is_err());
    let mut deployment = deployment_statement();
    deployment.control_protocol_versions.clear();
    assert!(validate_deployment_statement(&deployment).is_err());

    let mut receipt = adoption_receipt();
    validate_adoption_receipt(&receipt).unwrap();
    receipt.schema += 1;
    assert!(validate_adoption_receipt(&receipt).is_err());
    let mut receipt = adoption_receipt();
    receipt.deployment_id = "deployment/1".to_owned();
    assert!(validate_adoption_receipt(&receipt).is_err());
    let mut receipt = adoption_receipt();
    receipt.issuer = "issuer value".to_owned();
    assert!(validate_adoption_receipt(&receipt).is_err());
    let mut receipt = adoption_receipt();
    receipt.verified_release = "release value".to_owned();
    assert!(validate_adoption_receipt(&receipt).is_err());
    let mut receipt = adoption_receipt();
    receipt.release_manifest_sha256 = "A".repeat(64);
    assert!(validate_adoption_receipt(&receipt).is_err());
    let mut receipt = adoption_receipt();
    receipt.plan_sha256 = "A".repeat(64);
    assert!(validate_adoption_receipt(&receipt).is_err());
    let mut receipt = adoption_receipt();
    receipt.adopted_at = 0;
    assert!(validate_adoption_receipt(&receipt).is_err());
    let mut receipt = adoption_receipt();
    receipt.runtime_instances[0].runtime_instance_id = "runtime/1".to_owned();
    assert!(validate_adoption_receipt(&receipt).is_err());
    let mut receipt = adoption_receipt();
    receipt.runtime_instances[0].backend = "backend\nvalue".to_owned();
    assert!(validate_adoption_receipt(&receipt).is_err());
    let mut receipt = adoption_receipt();
    receipt.instance_key_ids[0] = "instance/1".to_owned();
    assert!(validate_adoption_receipt(&receipt).is_err());
    let mut receipt = adoption_receipt();
    receipt
        .resource_references
        .insert("bad name".to_owned(), "value".to_owned());
    assert!(validate_adoption_receipt(&receipt).is_err());
    let mut receipt = adoption_receipt();
    receipt
        .resource_references
        .insert("name".to_owned(), "bad\nvalue".to_owned());
    assert!(validate_adoption_receipt(&receipt).is_err());

    let transition = ControllerTrustTransition {
        ver: PROTOCOL_VERSION,
        deployment_id: "deployment-1".to_owned(),
        issued_at: 1_003,
        authorization: TransitionAuthorization::Controller,
        previous_key_id: "controller-1".to_owned(),
        next_key_id: "controller-2".to_owned(),
        next_public_key_sha256: "a".repeat(64),
        previous_audit_key_id: "audit-1".to_owned(),
        next_audit_key_id: "audit-2".to_owned(),
        next_audit_public_key_sha256: "b".repeat(64),
        previous_break_glass_key_id: "break-glass-1".to_owned(),
        next_break_glass_key_id: "break-glass-2".to_owned(),
        next_break_glass_public_key_sha256: "c".repeat(64),
        reason: "scheduled-rotation".to_owned(),
    };
    validate_transition(&transition).unwrap();
    let mut invalid_transition = transition.clone();
    invalid_transition.ver += 1;
    assert!(validate_transition(&invalid_transition).is_err());
    let mut invalid_transition = transition.clone();
    invalid_transition.issued_at = 0;
    assert!(validate_transition(&invalid_transition).is_err());
    let mut invalid_transition = transition.clone();
    invalid_transition.next_public_key_sha256 = "A".repeat(64);
    assert!(validate_transition(&invalid_transition).is_err());
    let mut invalid_transition = transition.clone();
    invalid_transition.next_audit_public_key_sha256 = "B".repeat(64);
    assert!(validate_transition(&invalid_transition).is_err());
    let mut invalid_transition = transition;
    invalid_transition.next_break_glass_public_key_sha256 = "C".repeat(64);
    assert!(validate_transition(&invalid_transition).is_err());

    let event = ManagementAuditEvent {
        ver: PROTOCOL_VERSION,
        deployment_id: "deployment-1".to_owned(),
        sequence: 1,
        previous_sha256: "0".repeat(64),
        request_id: "request-1".to_owned(),
        issued_at: 1_004,
        actor: Actor {
            kind: ActorKind::Automation,
            id: "automation-1".to_owned(),
        },
        operation: "update".to_owned(),
        release: "v1.0.0".to_owned(),
        recovery_boundary: "artifact-and-schema-compatible".to_owned(),
    };
    validate_management_event(&event).unwrap();
    let mut invalid_event = event.clone();
    invalid_event.ver += 1;
    assert!(validate_management_event(&invalid_event).is_err());
    let mut invalid_event = event.clone();
    invalid_event.issued_at = 0;
    assert!(validate_management_event(&invalid_event).is_err());
    let mut invalid_event = event.clone();
    invalid_event.sequence = 0;
    assert!(validate_management_event(&invalid_event).is_err());
    let mut invalid_event = event.clone();
    invalid_event.deployment_id = "deployment/1".to_owned();
    assert!(validate_management_event(&invalid_event).is_err());
    let mut invalid_event = event.clone();
    invalid_event.request_id = "request/1".to_owned();
    assert!(validate_management_event(&invalid_event).is_err());
    let mut invalid_event = event.clone();
    invalid_event.previous_sha256 = "A".repeat(64);
    assert!(validate_management_event(&invalid_event).is_err());
    let mut invalid_event = event.clone();
    invalid_event.actor.id = "automation id".to_owned();
    assert!(validate_management_event(&invalid_event).is_err());
    let mut invalid_event = event.clone();
    invalid_event.operation = "operation value".to_owned();
    assert!(validate_management_event(&invalid_event).is_err());
    let mut invalid_event = event.clone();
    invalid_event.release = "release value".to_owned();
    assert!(validate_management_event(&invalid_event).is_err());
    let mut invalid_event = event;
    invalid_event.recovery_boundary = "boundary value".to_owned();
    assert!(validate_management_event(&invalid_event).is_err());

    validate_identifier("issuer:https://auth.example").unwrap();
    for value in [String::new(), "bad value".to_owned(), "x".repeat(257)] {
        assert!(validate_identifier(&value).is_err());
    }
    validate_file_identifier("deployment-1_v2").unwrap();
    for value in [String::new(), "deployment/1".to_owned(), "x".repeat(129)] {
        assert!(validate_file_identifier(&value).is_err());
    }
    assert!(validate_file_identifier_value("file-1").is_ok());
    assert!(validate_file_identifier_value("file/1").is_err());
}

#[test]
fn tenant_resource_contract_signs_and_binds_all_request_identity() {
    let controller_key = SigningKey::from_bytes(&[17; 32]);
    let runtime_key = SigningKey::from_bytes(&[19; 32]);
    let raw_nonce = rand::random::<[u8; 32]>();
    let expected_nonce = URL_SAFE_NO_PAD.encode(raw_nonce);
    let mut mismatched_raw_nonce = raw_nonce;
    mismatched_raw_nonce[0] ^= 1;
    let mismatched_nonce = URL_SAFE_NO_PAD.encode(mismatched_raw_nonce);
    let mut capability = tenant_resource_capability();
    capability.nonce = expected_nonce.clone();
    assert!(sign_tenant_resource_capability(&capability, "wrong-instance", &runtime_key).is_err());
    let compact_capability =
        sign_tenant_resource_capability(&capability, "instance-1", &runtime_key).unwrap();
    let capability_sha256 = compact_sha256(&compact_capability);
    let mut task = tenant_resource_task();
    task.capability_sha256 = capability_sha256.clone();
    let compact_task = sign_tenant_resource_task(&task, "controller-1", &controller_key).unwrap();
    assert_eq!(
        verify_tenant_resource_task(
            &compact_task,
            "controller-1",
            &controller_key.verifying_key(),
            1_030,
        )
        .unwrap(),
        task
    );
    validate_tenant_resource_task_deployment_binding(&task, "deployment-1", TENANT_ID).unwrap();

    validate_tenant_resource_task_capability_binding(&task, &capability).unwrap();
    validate_tenant_resource_task_capability_binding_with_digest(
        &task,
        &capability,
        &capability_sha256,
    )
    .unwrap();
    validate_tenant_resource_task_capability_binding_at(
        &task,
        &capability,
        &capability_sha256,
        1_030,
    )
    .unwrap();
    validate_tenant_resource_capability_request_binding(
        &capability,
        "deployment-1",
        TENANT_ID,
        "tenant-resource-capability-1",
        &expected_nonce,
    )
    .unwrap();
    assert!(
        validate_tenant_resource_capability_request_binding(
            &capability,
            "deployment-1",
            TENANT_ID,
            "tenant-resource-capability-1",
            &mismatched_nonce,
        )
        .is_err()
    );
    assert_eq!(
        verify_tenant_resource_capability(
            &compact_capability,
            "instance-1",
            &runtime_key.verifying_key(),
            1_030,
        )
        .unwrap(),
        capability
    );
    validate_tenant_resource_capability_binding(&capability, "deployment-1", TENANT_ID).unwrap();

    let mut receipt = tenant_resource_receipt();
    receipt.capability_sha256 = capability_sha256.clone();
    validate_tenant_resource_receipt(&receipt).unwrap();
    validate_tenant_resource_receipt_binding(&task, &receipt).unwrap();
    validate_tenant_resource_receipt_capability_binding(&receipt, &capability).unwrap();
    validate_tenant_resource_receipt_capability_binding_with_digest(
        &receipt,
        &capability,
        &capability_sha256,
    )
    .unwrap();
    validate_tenant_resource_receipt_capability_binding_at(
        &receipt,
        &capability,
        &capability_sha256,
        1_030,
    )
    .unwrap();
    validate_tenant_resource_receipt_request_binding(&receipt, &"f".repeat(64)).unwrap();
    let mut late_receipt = receipt.clone();
    late_receipt.started_at = 1_050;
    late_receipt.completed_at = 1_061;
    late_receipt.exp = 1_110;
    validate_tenant_resource_receipt(&late_receipt).unwrap();
    validate_tenant_resource_receipt_binding(&task, &late_receipt).unwrap();
    let compact_receipt =
        sign_tenant_resource_receipt(&receipt, "runtime-1", &runtime_key).unwrap();
    assert_eq!(
        verify_tenant_resource_receipt(
            &compact_receipt,
            "runtime-1",
            &runtime_key.verifying_key(),
            1_030,
        )
        .unwrap(),
        receipt
    );
    assert_eq!(
        verify_tenant_resource_receipt_signature(
            &compact_receipt,
            "runtime-1",
            &runtime_key.verifying_key(),
        )
        .unwrap(),
        receipt
    );
    assert!(
        verify_tenant_resource_receipt(
            &compact_receipt,
            "runtime-1",
            &runtime_key.verifying_key(),
            2_000,
        )
        .is_err()
    );
}

#[test]
fn tenant_resource_contract_rejects_temporal_scope_and_operation_confusion() {
    let valid = tenant_resource_task();
    validate_tenant_resource_task(&valid).unwrap();

    let mut invalid = valid.clone();
    invalid.tenant_id = "not-a-uuid".to_owned();
    assert!(validate_tenant_resource_task(&invalid).is_err());

    let mut invalid = valid.clone();
    invalid.tenant_id = "00000000-0000-0000-0000-00000000000A".to_owned();
    assert!(validate_tenant_resource_task(&invalid).is_err());

    let mut invalid = valid.clone();
    invalid.nbf = invalid.iat - 1;
    assert!(validate_tenant_resource_task(&invalid).is_err());

    let mut invalid = valid.clone();
    invalid.exp = invalid.nbf - 1;
    assert!(validate_tenant_resource_task(&invalid).is_err());

    let mut invalid = valid.clone();
    invalid.exp = invalid.iat + MAX_TASK_LIFETIME_SECONDS + 1;
    assert!(validate_tenant_resource_task(&invalid).is_err());

    let mut invalid = valid.clone();
    invalid.operation = TenantResourceOperation::Revoke;
    assert!(validate_tenant_resource_task(&invalid).is_err());

    let mut invalid = valid.clone();
    invalid.iss = "controller:deployment-2".to_owned();
    assert!(validate_tenant_resource_task(&invalid).is_err());

    let mut invalid = valid.clone();
    if let TenantResourceTaskPayload::Apply { resources } = &mut invalid.payload {
        resources.push(resources[0].clone());
    }
    assert!(validate_tenant_resource_task(&invalid).is_err());

    let mut invalid = valid.clone();
    invalid.resource_manifest_sha256 = "A".repeat(64);
    assert!(validate_tenant_resource_task(&invalid).is_err());

    let mut max_revision_task = valid.clone();
    max_revision_task.expected_revision = u64::MAX;
    validate_tenant_resource_task(&max_revision_task).unwrap();
    let mut max_revision_capability = tenant_resource_capability();
    max_revision_capability.revision = u64::MAX;
    validate_tenant_resource_task_capability_binding(&max_revision_task, &max_revision_capability)
        .unwrap();

    let capability = tenant_resource_capability();
    let mut invalid_baseline_task = valid.clone();
    invalid_baseline_task.baseline_manifest_sha256 = "f".repeat(64);
    assert!(
        validate_tenant_resource_task_capability_binding(&invalid_baseline_task, &capability)
            .is_err()
    );
    let mut invalid_capability = capability.clone();
    invalid_capability.revision = 8;
    assert!(validate_tenant_resource_task_capability_binding(&valid, &invalid_capability).is_err());
    let mut invalid_capability = capability.clone();
    invalid_capability
        .actions
        .retain(|action| *action != TenantResourceOperation::Apply);
    assert!(validate_tenant_resource_task_capability_binding(&valid, &invalid_capability).is_err());
    let mut invalid_task = valid.clone();
    invalid_task.capability_sha256 = "8".repeat(64);
    assert!(
        validate_tenant_resource_task_capability_binding_with_digest(
            &invalid_task,
            &capability,
            &"9".repeat(64),
        )
        .is_err()
    );
    let mut invalid_capability = capability.clone();
    invalid_capability.jti = "tenant-resource-capability-2".to_owned();
    assert!(validate_tenant_resource_task_capability_binding(&valid, &invalid_capability).is_err());
    let mut invalid_task = valid.clone();
    if let TenantResourceTaskPayload::Apply { resources } = &mut invalid_task.payload {
        resources[0].kind = TenantResourceKind::User;
    }
    let mut limited_capability = capability.clone();
    limited_capability.resource_kinds = vec![TenantResourceKind::OauthClient];
    assert!(
        validate_tenant_resource_task_capability_binding(&invalid_task, &limited_capability)
            .is_err()
    );

    let enumerate = TenantResourceTask {
        operation: TenantResourceOperation::Enumerate,
        payload: TenantResourceTaskPayload::Enumerate {
            selectors: Vec::new(),
        },
        ..valid.clone()
    };
    assert!(validate_tenant_resource_task(&enumerate).is_err());
    let enumerate = TenantResourceTask {
        resource_manifest_sha256: capability.resource_manifest_sha256.clone(),
        ..enumerate
    };
    validate_tenant_resource_task(&enumerate).unwrap();
    validate_tenant_resource_task_capability_binding(&enumerate, &capability).unwrap();
    let enumerate = TenantResourceTask {
        payload: TenantResourceTaskPayload::Enumerate {
            selectors: vec![TenantResourceSelector {
                kind: TenantResourceKind::User,
                resource_id: "user:1".to_owned(),
            }],
        },
        ..enumerate
    };
    assert!(
        validate_tenant_resource_task_capability_binding(&enumerate, &limited_capability).is_err()
    );
    let revoke = TenantResourceTask {
        operation: TenantResourceOperation::Revoke,
        payload: TenantResourceTaskPayload::Revoke {
            resources: vec![TenantResourceIdentity {
                kind: TenantResourceKind::OauthClient,
                resource_id: "client:primary".to_owned(),
                digest: "b".repeat(64),
            }],
        },
        ..valid
    };
    validate_tenant_resource_task(&revoke).unwrap();
    let revoke_receipt_task = revoke.clone();
    let mut revoke_receipt = tenant_resource_receipt();
    revoke_receipt.operation = TenantResourceOperation::Revoke;
    revoke_receipt.resources = match &revoke_receipt_task.payload {
        TenantResourceTaskPayload::Revoke { resources } => resources.clone(),
        _ => unreachable!(),
    };
    revoke_receipt.resource_mappings.clear();
    validate_tenant_resource_receipt(&revoke_receipt).unwrap();
    validate_tenant_resource_receipt_binding(&revoke_receipt_task, &revoke_receipt).unwrap();
    revoke_receipt.resources[0].digest = "d".repeat(64);
    assert!(
        validate_tenant_resource_receipt_binding(&revoke_receipt_task, &revoke_receipt).is_err()
    );
    assert!(
        serde_json::from_value::<TenantResourceOperation>(serde_json::json!("delete")).is_err()
    );
}

#[test]
fn tenant_resource_capability_and_receipt_fail_closed() {
    let capability = tenant_resource_capability();
    validate_tenant_resource_capability(&capability, 1_030).unwrap();

    let mut invalid = capability.clone();
    invalid.capability_version += 1;
    assert!(validate_tenant_resource_capability(&invalid, 1_030).is_err());
    let mut invalid = capability.clone();
    invalid.expires_at = invalid.issued_at + MAX_TASK_LIFETIME_SECONDS + 1;
    assert!(validate_tenant_resource_capability(&invalid, 1_030).is_err());
    let mut invalid = capability.clone();
    invalid.resource_kinds.push(TenantResourceKind::OauthClient);
    assert!(validate_tenant_resource_capability(&invalid, 1_030).is_err());
    let mut invalid = capability.clone();
    invalid.actions.push(TenantResourceOperation::Apply);
    assert!(validate_tenant_resource_capability(&invalid, 1_030).is_err());
    let mut invalid = capability.clone();
    invalid.issuer = "runtime:deployment-2".to_owned();
    assert!(validate_tenant_resource_capability(&invalid, 1_030).is_err());
    let mut invalid = capability.clone();
    invalid.jti = "capability/1".to_owned();
    assert!(validate_tenant_resource_capability(&invalid, 1_030).is_err());
    let mut invalid = capability.clone();
    invalid.nonce = "short".to_owned();
    assert!(validate_tenant_resource_capability(&invalid, 1_030).is_err());
    assert!(validate_tenant_resource_capability(&capability, 2_000).is_err());

    let receipt = tenant_resource_receipt();
    validate_tenant_resource_receipt(&receipt).unwrap();
    let mut invalid = receipt.clone();
    invalid.completed_at = invalid.exp + 1;
    assert!(validate_tenant_resource_receipt(&invalid).is_err());
    let mut invalid = receipt.clone();
    invalid.aud = "controller:deployment-2".to_owned();
    assert!(validate_tenant_resource_receipt(&invalid).is_err());
    let mut invalid = receipt.clone();
    invalid.outcome = TenantResourceOutcome::Failed {
        code: "apply-failed".to_owned(),
    };
    assert!(validate_tenant_resource_receipt(&invalid).is_err());
    let mut invalid = receipt.clone();
    invalid.revision = invalid.expected_revision;
    invalid.outcome = TenantResourceOutcome::Failed {
        code: "apply-failed".to_owned(),
    };
    invalid.resources.clear();
    invalid.resource_mappings.clear();
    validate_tenant_resource_receipt(&invalid).unwrap();
    let capability = tenant_resource_capability();
    let receipt = tenant_resource_receipt();
    let mut invalid = receipt.clone();
    invalid.resources[0].kind = TenantResourceKind::User;
    let mut client_only_capability = capability.clone();
    client_only_capability.resource_kinds = vec![TenantResourceKind::OauthClient];
    assert!(
        validate_tenant_resource_receipt_capability_binding(&invalid, &client_only_capability)
            .is_err()
    );
    let mut invalid = receipt.clone();
    invalid.capability_jti = "tenant-resource-capability-2".to_owned();
    assert!(validate_tenant_resource_receipt_capability_binding(&invalid, &capability).is_err());
    let mut invalid = receipt.clone();
    invalid.baseline_manifest_sha256 = "f".repeat(64);
    assert!(validate_tenant_resource_receipt_capability_binding(&invalid, &capability).is_err());
    let mut invalid = receipt.clone();
    invalid.operation = TenantResourceOperation::Enumerate;
    assert!(validate_tenant_resource_receipt(&invalid).is_err());
    let mut invalid = receipt.clone();
    invalid.started_at = invalid.exp + 1;
    assert!(validate_tenant_resource_receipt(&invalid).is_err());
    let mut invalid = receipt;
    invalid.resources.push(invalid.resources[0].clone());
    assert!(validate_tenant_resource_receipt(&invalid).is_err());
    assert!(serde_json::from_value::<TenantResourceKind>(serde_json::json!("bucket")).is_err());
}

#[test]
fn tenant_resource_receipt_mappings_are_apply_only_and_one_to_one() {
    let task = tenant_resource_task();
    let receipt = tenant_resource_receipt();
    validate_tenant_resource_receipt(&receipt).unwrap();
    validate_tenant_resource_receipt_binding(&task, &receipt).unwrap();

    let mut user_receipt = receipt.clone();
    user_receipt.resources = vec![TenantResourceIdentity {
        kind: TenantResourceKind::User,
        resource_id: "user:primary".to_owned(),
        digest: "c".repeat(64),
    }];
    user_receipt.resource_mappings = vec![TenantResourceMapping {
        kind: TenantResourceKind::User,
        resource_id: "user:primary".to_owned(),
        public_id: "00000000-0000-0000-0000-000000000002".to_owned(),
    }];
    validate_tenant_resource_receipt(&user_receipt).unwrap();

    let mut invalid = receipt.clone();
    invalid.resource_mappings.clear();
    assert!(validate_tenant_resource_receipt(&invalid).is_err());
    assert!(validate_tenant_resource_receipt_binding(&task, &invalid).is_err());
    let mut invalid = receipt.clone();
    invalid
        .resource_mappings
        .push(invalid.resource_mappings[0].clone());
    assert!(validate_tenant_resource_receipt(&invalid).is_err());
    let mut invalid = receipt.clone();
    invalid.resource_mappings[0].resource_id = "client:other".to_owned();
    assert!(validate_tenant_resource_receipt(&invalid).is_err());
    let mut invalid = receipt.clone();
    invalid.resource_mappings[0].kind = TenantResourceKind::MtlsTrustAnchor;
    assert!(validate_tenant_resource_receipt(&invalid).is_err());
    let mut invalid = receipt.clone();
    invalid.resource_mappings[0].kind = TenantResourceKind::Openid4vcTrustPolicy;
    assert!(validate_tenant_resource_receipt(&invalid).is_err());
    let mut invalid = user_receipt.clone();
    invalid.resource_mappings[0].public_id = "not-a-uuid".to_owned();
    assert!(validate_tenant_resource_receipt(&invalid).is_err());
    let mut invalid = receipt.clone();
    invalid.resource_mappings[0].public_id = "client id with spaces".to_owned();
    assert!(validate_tenant_resource_receipt(&invalid).is_err());

    let mut invalid = receipt.clone();
    invalid.operation = TenantResourceOperation::Revoke;
    assert!(validate_tenant_resource_receipt(&invalid).is_err());
    let mut invalid = receipt.clone();
    invalid.outcome = TenantResourceOutcome::Failed {
        code: "apply-failed".to_owned(),
    };
    invalid.revision = invalid.expected_revision;
    invalid.resources.clear();
    assert!(validate_tenant_resource_receipt(&invalid).is_err());

    let key = SigningKey::from_bytes(&[23; 32]);
    assert!(sign_tenant_resource_receipt(&invalid, "runtime-1", &key).is_err());
    let compact = sign_compact(
        &invalid,
        "runtime-1",
        TENANT_RESOURCE_RECEIPT_JWS_TYPE,
        &key,
    )
    .unwrap();
    assert!(
        verify_tenant_resource_receipt(&compact, "runtime-1", &key.verifying_key(), 1_030,)
            .is_err()
    );
}

#[test]
fn tenant_resource_receipt_resource_binding_is_order_independent() {
    let mut task = tenant_resource_task();
    let second = TenantResourceIdentity {
        kind: TenantResourceKind::User,
        resource_id: "user:secondary".to_owned(),
        digest: "d".repeat(64),
    };
    if let TenantResourceTaskPayload::Apply { resources } = &mut task.payload {
        resources.push(second.clone());
    } else {
        unreachable!();
    }
    let mut receipt = tenant_resource_receipt();
    receipt.resources.push(second);
    receipt.resource_mappings.push(TenantResourceMapping {
        kind: TenantResourceKind::User,
        resource_id: "user:secondary".to_owned(),
        public_id: "00000000-0000-0000-0000-000000000002".to_owned(),
    });
    receipt.resources.reverse();

    validate_tenant_resource_receipt_binding(&task, &receipt).unwrap();
}

#[test]
fn tenant_resource_manifest_digest_is_canonical_and_rejects_invalid_sets() {
    let resources = vec![
        TenantResourceIdentity {
            kind: TenantResourceKind::User,
            resource_id: "user:alice".to_owned(),
            digest: "a".repeat(64),
        },
        TenantResourceIdentity {
            kind: TenantResourceKind::OauthClient,
            resource_id: "client:primary".to_owned(),
            digest: "b".repeat(64),
        },
    ];
    let mut reversed = resources.clone();
    reversed.reverse();
    assert_eq!(
        canonical_tenant_resource_manifest_sha256(&resources).unwrap(),
        canonical_tenant_resource_manifest_sha256(&reversed).unwrap()
    );

    let mut changed = resources.clone();
    changed[0].digest = "c".repeat(64);
    assert_ne!(
        canonical_tenant_resource_manifest_sha256(&resources).unwrap(),
        canonical_tenant_resource_manifest_sha256(&changed).unwrap()
    );
    let mut changed_kind = resources.clone();
    changed_kind[0].kind = TenantResourceKind::Openid4vcTrustPolicy;
    assert_ne!(
        canonical_tenant_resource_manifest_sha256(&resources).unwrap(),
        canonical_tenant_resource_manifest_sha256(&changed_kind).unwrap()
    );
    let mut invalid = resources.clone();
    invalid[0].resource_id = "not an identifier".to_owned();
    assert!(canonical_tenant_resource_manifest_sha256(&invalid).is_err());
    let mut duplicate = resources.clone();
    duplicate.push(resources[0].clone());
    assert!(canonical_tenant_resource_manifest_sha256(&duplicate).is_err());

    let empty = canonical_tenant_resource_manifest_sha256(&[]).unwrap();
    assert_eq!(
        empty,
        canonical_tenant_resource_manifest_sha256(&[]).unwrap()
    );
    assert_eq!(
        empty,
        "b5872ae433b0e5470e831afe4d88a816996f28e6bcaf409a5a333107f00789f2"
    );
    assert_eq!(
        serde_json::to_value(TenantResourceKind::Openid4vcTrustPolicy).unwrap(),
        serde_json::json!("openid4vc-trust-policy")
    );
}

#[test]
fn tenant_resource_validation_rejects_every_state_machine_boundary() {
    let valid_task = tenant_resource_task();
    let assert_invalid_task = |task: TenantResourceTask| {
        assert!(validate_tenant_resource_task(&task).is_err());
    };
    assert_invalid_task(TenantResourceTask {
        ver: PROTOCOL_VERSION + 1,
        ..valid_task.clone()
    });
    for actor_id in ["", "bad actor", &"x".repeat(257)] {
        let mut task = valid_task.clone();
        task.actor.id = actor_id.to_owned();
        assert_invalid_task(task);
    }
    for (field, value) in [
        ("jti", "bad/jti"),
        ("deployment", "bad/deployment"),
        ("capability", "bad/capability"),
        ("change-set", "bad/change-set"),
    ] {
        let mut task = valid_task.clone();
        match field {
            "jti" => task.jti = value.to_owned(),
            "deployment" => task.deployment_id = value.to_owned(),
            "capability" => task.capability_jti = value.to_owned(),
            "change-set" => task.change_set_id = value.to_owned(),
            _ => unreachable!(),
        }
        assert_invalid_task(task);
    }
    let mut task = valid_task.clone();
    task.tenant_id = "00000000-0000-0000-0000-00000000000A".to_owned();
    assert_invalid_task(task);
    for field in ["capability", "change-set", "baseline", "manifest"] {
        let mut task = valid_task.clone();
        match field {
            "capability" => task.capability_sha256 = "A".repeat(64),
            "change-set" => task.change_set_sha256 = "A".repeat(64),
            "baseline" => task.baseline_manifest_sha256 = "A".repeat(64),
            "manifest" => task.resource_manifest_sha256 = "A".repeat(64),
            _ => unreachable!(),
        }
        assert_invalid_task(task);
    }
    let mut task = valid_task.clone();
    task.iss = "controller:other".to_owned();
    assert_invalid_task(task);
    for (iat, nbf, exp) in [
        (0, 1_000, 1_060),
        (1_000, 0, 1_060),
        (1_000, 1_000, 0),
        (1_000, 999, 1_060),
        (1_000, 1_001, 1_000),
        (1_000, 1_000, 1_061),
    ] {
        assert_invalid_task(TenantResourceTask {
            iat,
            nbf,
            exp,
            ..valid_task.clone()
        });
    }
    assert!(verify_tenant_resource_task_window(&valid_task, 999).is_err());
    assert!(verify_tenant_resource_task_window(&valid_task, 1_061).is_err());

    let enumerate = TenantResourceTask {
        operation: TenantResourceOperation::Enumerate,
        payload: TenantResourceTaskPayload::Enumerate {
            selectors: Vec::new(),
        },
        resource_manifest_sha256: valid_task.baseline_manifest_sha256.clone(),
        ..valid_task.clone()
    };
    validate_tenant_resource_task(&enumerate).unwrap();
    assert_invalid_task(TenantResourceTask {
        resource_manifest_sha256: "d".repeat(64),
        ..enumerate.clone()
    });
    assert_invalid_task(TenantResourceTask {
        payload: TenantResourceTaskPayload::Apply {
            resources: Vec::new(),
        },
        ..enumerate.clone()
    });
    let duplicate_selector = TenantResourceSelector {
        kind: TenantResourceKind::User,
        resource_id: "user:one".to_owned(),
    };
    assert_invalid_task(TenantResourceTask {
        payload: TenantResourceTaskPayload::Enumerate {
            selectors: vec![duplicate_selector.clone(), duplicate_selector],
        },
        ..enumerate.clone()
    });
    assert_invalid_task(TenantResourceTask {
        payload: TenantResourceTaskPayload::Enumerate {
            selectors: vec![TenantResourceSelector {
                kind: TenantResourceKind::User,
                resource_id: "bad/selector".to_owned(),
            }],
        },
        ..enumerate
    });

    let valid_capability = tenant_resource_capability();
    let assert_invalid_capability = |capability: TenantResourceCapability| {
        assert!(validate_tenant_resource_capability(&capability, 1_030).is_err());
    };
    assert_invalid_capability(TenantResourceCapability {
        ver: PROTOCOL_VERSION + 1,
        ..valid_capability.clone()
    });
    assert_invalid_capability(TenantResourceCapability {
        capability_version: TENANT_RESOURCE_CAPABILITY_VERSION + 1,
        ..valid_capability.clone()
    });
    for field in [
        "jti",
        "nonce",
        "deployment",
        "tenant",
        "runtime",
        "issuer",
        "key",
    ] {
        let mut capability = valid_capability.clone();
        match field {
            "jti" => capability.jti = "bad/jti".to_owned(),
            "nonce" => capability.nonce = "short".to_owned(),
            "deployment" => capability.deployment_id = "bad/deployment".to_owned(),
            "tenant" => capability.tenant_id = "not-a-uuid".to_owned(),
            "runtime" => capability.runtime_instance_id = "bad/runtime".to_owned(),
            "issuer" => capability.issuer = "runtime:other".to_owned(),
            "key" => capability.instance_key_id = "bad/key".to_owned(),
            _ => unreachable!(),
        }
        assert_invalid_capability(capability);
    }
    assert_invalid_capability(TenantResourceCapability {
        resource_manifest_sha256: "A".repeat(64),
        ..valid_capability.clone()
    });
    assert_invalid_capability(TenantResourceCapability {
        resource_kinds: Vec::new(),
        ..valid_capability.clone()
    });
    assert_invalid_capability(TenantResourceCapability {
        resource_kinds: vec![TenantResourceKind::User; MAX_TENANT_RESOURCE_KINDS + 1],
        ..valid_capability.clone()
    });
    assert_invalid_capability(TenantResourceCapability {
        resource_kinds: vec![TenantResourceKind::User, TenantResourceKind::User],
        ..valid_capability.clone()
    });
    assert_invalid_capability(TenantResourceCapability {
        actions: Vec::new(),
        ..valid_capability.clone()
    });
    assert_invalid_capability(TenantResourceCapability {
        actions: vec![TenantResourceOperation::Apply; 4],
        ..valid_capability.clone()
    });
    assert_invalid_capability(TenantResourceCapability {
        actions: vec![
            TenantResourceOperation::Apply,
            TenantResourceOperation::Apply,
        ],
        ..valid_capability.clone()
    });
    for (issued_at, expires_at) in [(0, 1_060), (1_060, 1_000), (1_000, 1_061)] {
        assert_invalid_capability(TenantResourceCapability {
            issued_at,
            expires_at,
            ..valid_capability.clone()
        });
    }
    assert_invalid_capability(TenantResourceCapability {
        embedded: EmbeddedIdentity {
            protocol: PROTOCOL_VERSION + 1,
            ..valid_capability.embedded.clone()
        },
        ..valid_capability.clone()
    });

    assert!(
        validate_tenant_resource_task_deployment_binding(&valid_task, "bad/deployment", TENANT_ID)
            .is_err()
    );
    assert!(
        validate_tenant_resource_task_deployment_binding(&valid_task, "deployment-1", "not-a-uuid")
            .is_err()
    );
    assert!(
        validate_tenant_resource_task_deployment_binding(&valid_task, "deployment-2", TENANT_ID)
            .is_err()
    );
    assert!(
        validate_tenant_resource_capability_binding(&valid_capability, "deployment-2", TENANT_ID)
            .is_err()
    );
    assert!(
        validate_tenant_resource_capability_request_binding(
            &valid_capability,
            "deployment-1",
            TENANT_ID,
            "bad/jti",
            &valid_capability.nonce,
        )
        .is_err()
    );
    assert!(
        validate_tenant_resource_capability_request_binding(
            &valid_capability,
            "deployment-1",
            TENANT_ID,
            &valid_capability.jti,
            "short",
        )
        .is_err()
    );
    assert!(
        validate_tenant_resource_capability_request_binding(
            &valid_capability,
            "deployment-1",
            TENANT_ID,
            "other-jti",
            &valid_capability.nonce,
        )
        .is_err()
    );

    let valid_receipt = tenant_resource_receipt();
    let assert_invalid_receipt = |receipt: TenantResourceReceipt| {
        assert!(validate_tenant_resource_receipt(&receipt).is_err());
    };
    assert_invalid_receipt(TenantResourceReceipt {
        ver: PROTOCOL_VERSION + 1,
        ..valid_receipt.clone()
    });
    for field in [
        "jti",
        "deployment",
        "tenant",
        "capability-jti",
        "capability-digest",
        "request",
        "change-set",
        "change-digest",
        "baseline",
        "manifest",
        "audit",
    ] {
        let mut receipt = valid_receipt.clone();
        match field {
            "jti" => receipt.jti = "bad/jti".to_owned(),
            "deployment" => receipt.deployment_id = "bad/deployment".to_owned(),
            "tenant" => receipt.tenant_id = "not-a-uuid".to_owned(),
            "capability-jti" => receipt.capability_jti = "bad/jti".to_owned(),
            "capability-digest" => receipt.capability_sha256 = "A".repeat(64),
            "request" => receipt.request_sha256 = "A".repeat(64),
            "change-set" => receipt.change_set_id = "bad/change-set".to_owned(),
            "change-digest" => receipt.change_set_sha256 = "A".repeat(64),
            "baseline" => receipt.baseline_manifest_sha256 = "A".repeat(64),
            "manifest" => receipt.resource_manifest_sha256 = "A".repeat(64),
            "audit" => receipt.audit_previous_sha256 = "A".repeat(64),
            _ => unreachable!(),
        }
        assert_invalid_receipt(receipt);
    }
    assert_invalid_receipt(TenantResourceReceipt {
        iss: "runtime:other".to_owned(),
        ..valid_receipt.clone()
    });
    for (started_at, completed_at, exp, audit_sequence) in [
        (0, 1_010, 1_060, 7),
        (1_011, 1_010, 1_060, 7),
        (1_001, 1_010, 1_009, 7),
        (1_001, 1_010, 1_071, 7),
        (1_001, 1_010, 1_060, 0),
    ] {
        assert_invalid_receipt(TenantResourceReceipt {
            started_at,
            completed_at,
            exp,
            audit_sequence,
            ..valid_receipt.clone()
        });
    }
    assert_invalid_receipt(TenantResourceReceipt {
        revision: valid_receipt.expected_revision,
        ..valid_receipt.clone()
    });
    let failed = TenantResourceReceipt {
        revision: valid_receipt.expected_revision,
        outcome: TenantResourceOutcome::Failed {
            code: "failed".to_owned(),
        },
        resources: Vec::new(),
        resource_mappings: Vec::new(),
        ..valid_receipt.clone()
    };
    validate_tenant_resource_receipt(&failed).unwrap();
    assert_invalid_receipt(TenantResourceReceipt {
        outcome: TenantResourceOutcome::Failed {
            code: "bad code".to_owned(),
        },
        ..failed.clone()
    });
    assert_invalid_receipt(TenantResourceReceipt {
        resources: valid_receipt.resources.clone(),
        ..failed.clone()
    });
    assert_invalid_receipt(TenantResourceReceipt {
        revision: failed.expected_revision + 1,
        ..failed
    });

    let enumerate_receipt = TenantResourceReceipt {
        operation: TenantResourceOperation::Enumerate,
        revision: valid_receipt.expected_revision,
        resources: Vec::new(),
        resource_mappings: Vec::new(),
        resource_manifest_sha256: valid_receipt.baseline_manifest_sha256.clone(),
        ..valid_receipt.clone()
    };
    validate_tenant_resource_receipt(&enumerate_receipt).unwrap();
    assert_invalid_receipt(TenantResourceReceipt {
        revision: enumerate_receipt.expected_revision + 1,
        ..enumerate_receipt.clone()
    });
    assert_invalid_receipt(TenantResourceReceipt {
        resource_manifest_sha256: "d".repeat(64),
        ..enumerate_receipt
    });
    let revoke_receipt = TenantResourceReceipt {
        operation: TenantResourceOperation::Revoke,
        resource_mappings: Vec::new(),
        ..valid_receipt.clone()
    };
    validate_tenant_resource_receipt(&revoke_receipt).unwrap();
    assert_invalid_receipt(TenantResourceReceipt {
        revision: revoke_receipt.expected_revision,
        ..revoke_receipt
    });

    assert!(validate_tenant_resource_receipt_request_binding(&valid_receipt, "A").is_err());
    assert!(
        validate_tenant_resource_receipt_request_binding(&valid_receipt, &"a".repeat(64)).is_err()
    );
    let mut wrong_binding = valid_receipt.clone();
    wrong_binding.actor.id = "other-actor".to_owned();
    assert!(validate_tenant_resource_receipt_binding(&valid_task, &wrong_binding).is_err());
    let mut wrong_resources = valid_receipt.clone();
    wrong_resources.resources[0].digest = "d".repeat(64);
    assert!(validate_tenant_resource_receipt_binding(&valid_task, &wrong_resources).is_err());

    let selective_task = TenantResourceTask {
        operation: TenantResourceOperation::Enumerate,
        payload: TenantResourceTaskPayload::Enumerate {
            selectors: vec![TenantResourceSelector {
                kind: TenantResourceKind::OauthClient,
                resource_id: "client:selected".to_owned(),
            }],
        },
        resource_manifest_sha256: valid_task.baseline_manifest_sha256.clone(),
        ..valid_task
    };
    let selective_receipt = TenantResourceReceipt {
        operation: TenantResourceOperation::Enumerate,
        revision: selective_task.expected_revision,
        resources: vec![TenantResourceIdentity {
            kind: TenantResourceKind::OauthClient,
            resource_id: "client:outside".to_owned(),
            digest: "b".repeat(64),
        }],
        resource_mappings: Vec::new(),
        resource_manifest_sha256: selective_task.baseline_manifest_sha256.clone(),
        ..valid_receipt
    };
    assert!(validate_tenant_resource_receipt_binding(&selective_task, &selective_receipt).is_err());
}

#[test]
fn openid4vc_trust_policy_rejects_ambiguous_origins_certificates_and_jwks() {
    let coordinate = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let key = |kid: &str| {
        serde_json::json!({
            "kty": "EC", "crv": "P-256", "x": coordinate, "y": coordinate, "kid": kid
        })
    };
    let certificate =
        |body: &str| format!("-----BEGIN CERTIFICATE-----\n{body}\n-----END CERTIFICATE-----\n");
    let policy = Openid4vcTrustPolicy {
        schema: 1,
        client_attestation_issuer: "https://issuer.example/attestation".to_owned(),
        client_attestation_jwks: serde_json::json!({"keys": [key("client")]}),
        key_attestation_jwks: serde_json::json!({"keys": [key("holder")]}),
        credential_trust_anchor_pem: certificate("MA=="),
        wallet_authorization_origins: vec!["https://wallet.example".to_owned()],
    };
    validate_openid4vc_trust_policy(&policy).unwrap();

    for issuer in [
        "https:///missing-host",
        "https://?query",
        "https://#fragment",
        "https://issuer.example/white space",
        "https://issuer.example\0",
    ] {
        let mut invalid = policy.clone();
        invalid.client_attestation_issuer = issuer.to_owned();
        assert!(validate_openid4vc_trust_policy(&invalid).is_err());
    }
    let invalid_origins = [
        "",
        "https://wallet.exämple",
        "https://wallet.example ",
        "https://wallet.example%25",
        "https://wallet.example\\bad",
        "https://",
        "https://.wallet.example",
        "https://wallet.example.",
        "https://wallet..example",
        "https://wallet_example",
        "https://wallet-.example",
        "https://[not-ipv6]",
        "https://[::1",
        "https://[::1]extra",
        "https://wallet.example:",
        "https://wallet.example:abc",
        "https://wallet.example:0",
        "https://wallet.example:0443",
        "https://wallet.example:65536",
    ];
    for origin in invalid_origins {
        let mut invalid = policy.clone();
        invalid.wallet_authorization_origins = vec![origin.to_owned()];
        assert!(
            validate_openid4vc_trust_policy(&invalid).is_err(),
            "{origin}"
        );
    }
    let mut too_many_origins = policy.clone();
    too_many_origins.wallet_authorization_origins = (0..17)
        .map(|index| format!("https://wallet-{index}.example"))
        .collect();
    assert!(validate_openid4vc_trust_policy(&too_many_origins).is_err());
    let mut long_origin = policy.clone();
    long_origin.wallet_authorization_origins = vec![format!("https://{}", "a".repeat(2048))];
    assert!(validate_openid4vc_trust_policy(&long_origin).is_err());
    for origin in ["https://wallet.example:8443", "https://[::1]:8443"] {
        let mut valid = policy.clone();
        valid.wallet_authorization_origins = vec![origin.to_owned()];
        validate_openid4vc_trust_policy(&valid).unwrap();
    }

    let five_certificates = (0..5)
        .map(|index| {
            certificate(&base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                [0x30, index],
            ))
        })
        .collect::<String>();
    let invalid_certificates = [
        "-----BEGIN CERTIFICATE-----\n\n-----END CERTIFICATE-----\n".to_owned(),
        "-----BEGIN CERTIFICATE-----\nMA==\n".to_owned(),
        "-----BEGIN CERTIFICATE-----\n%%%\n-----END CERTIFICATE-----\n".to_owned(),
        certificate("AA=="),
        format!("{}trailing", certificate("MA==")),
        format!("{}{}", certificate("MA=="), certificate("MA==")),
        format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            "-----BEGIN PUBLIC KEY-----"
        ),
        five_certificates,
    ];
    for pem in invalid_certificates {
        let mut invalid = policy.clone();
        invalid.credential_trust_anchor_pem = pem;
        assert!(validate_openid4vc_trust_policy(&invalid).is_err());
    }

    let invalid_jwks = [
        serde_json::json!([]),
        serde_json::json!({"keys": ["not-an-object"]}),
        serde_json::json!({"keys": [{"kty": "oct", "k": "secret", "kid": "s"}]}),
        serde_json::json!({"keys": [{"kty": "EC", "crv": "P-256", "x": coordinate, "y": coordinate}]}),
        serde_json::json!({"keys": [key("duplicate"), key("duplicate")]}),
        serde_json::json!({"keys": [{"kty": "EC", "crv": "P-384", "x": coordinate, "y": coordinate, "kid": "bad"}]}),
        serde_json::json!({"keys": [{"kty": "EC", "crv": "P-256", "x": "short", "y": coordinate, "kid": "bad"}]}),
    ];
    for jwks in invalid_jwks {
        let mut invalid = policy.clone();
        invalid.key_attestation_jwks = jwks;
        assert!(validate_openid4vc_trust_policy(&invalid).is_err());
    }
    let mut ed25519 = policy;
    ed25519.key_attestation_jwks = serde_json::json!({"keys": [{
        "kty": "OKP", "crv": "Ed25519", "x": coordinate, "kid": "holder"
    }]});
    validate_openid4vc_trust_policy(&ed25519).unwrap();
}

#[test]
fn tenant_resource_signed_evidence_and_collection_limits_fail_closed() {
    let runtime_key = SigningKey::from_bytes(&[31; 32]);
    let mut capability = tenant_resource_capability();
    capability.instance_key_id = "payload-key".to_owned();
    let compact = sign_compact(
        &capability,
        "signer-key",
        TENANT_RESOURCE_CAPABILITY_JWS_TYPE,
        &runtime_key,
    )
    .unwrap();
    assert!(
        verify_tenant_resource_capability(
            &compact,
            "signer-key",
            &runtime_key.verifying_key(),
            1_030,
        )
        .is_err()
    );
    assert!(
        verify_tenant_resource_capability_signature(
            &compact,
            "signer-key",
            &runtime_key.verifying_key(),
        )
        .is_err()
    );
    assert!(
        verify_tenant_resource_capability(
            "not-a-compact-jws",
            "signer-key",
            &runtime_key.verifying_key(),
            1_030,
        )
        .is_err()
    );
    assert!(
        verify_tenant_resource_capability_signature(
            "not-a-compact-jws",
            "signer-key",
            &runtime_key.verifying_key(),
        )
        .is_err()
    );
    assert!(
        verify_tenant_resource_receipt_signature(
            "not-a-compact-jws",
            "runtime-key",
            &runtime_key.verifying_key(),
        )
        .is_err()
    );

    let identity = TenantResourceIdentity {
        kind: TenantResourceKind::User,
        resource_id: "user:one".to_owned(),
        digest: "a".repeat(64),
    };
    let oversized_identities = vec![identity.clone(); MAX_TENANT_RESOURCE_IDENTITIES + 1];
    let oversized_task = TenantResourceTask {
        payload: TenantResourceTaskPayload::Apply {
            resources: oversized_identities,
        },
        ..tenant_resource_task()
    };
    assert!(validate_tenant_resource_task(&oversized_task).is_err());

    let selector = TenantResourceSelector {
        kind: TenantResourceKind::User,
        resource_id: "user:one".to_owned(),
    };
    let oversized_selectors = vec![selector; MAX_TENANT_RESOURCE_IDENTITIES + 1];
    let oversized_enumerate = TenantResourceTask {
        operation: TenantResourceOperation::Enumerate,
        payload: TenantResourceTaskPayload::Enumerate {
            selectors: oversized_selectors,
        },
        resource_manifest_sha256: tenant_resource_task().baseline_manifest_sha256,
        ..tenant_resource_task()
    };
    assert!(validate_tenant_resource_task(&oversized_enumerate).is_err());

    let mut oversized_mappings = tenant_resource_receipt();
    oversized_mappings.resource_mappings = vec![
        TenantResourceMapping {
            kind: TenantResourceKind::User,
            resource_id: "user:one".to_owned(),
            public_id: TENANT_ID.to_owned(),
        };
        MAX_TENANT_RESOURCE_IDENTITIES + 1
    ];
    assert!(validate_tenant_resource_receipt(&oversized_mappings).is_err());

    let capability = tenant_resource_capability();
    let revoke = TenantResourceTask {
        operation: TenantResourceOperation::Revoke,
        payload: TenantResourceTaskPayload::Revoke {
            resources: vec![TenantResourceIdentity {
                kind: TenantResourceKind::User,
                resource_id: "user:one".to_owned(),
                digest: "a".repeat(64),
            }],
        },
        ..tenant_resource_task()
    };
    let mut client_only = capability.clone();
    client_only.resource_kinds = vec![TenantResourceKind::OauthClient];
    assert!(validate_tenant_resource_task_capability_binding(&revoke, &client_only).is_err());

    let mut receipt = tenant_resource_receipt();
    receipt.resources = vec![identity.clone()];
    receipt.resource_mappings = vec![TenantResourceMapping {
        kind: TenantResourceKind::User,
        resource_id: identity.resource_id.clone(),
        public_id: TENANT_ID.to_owned(),
    }];
    assert!(validate_tenant_resource_receipt_capability_binding(&receipt, &client_only).is_err());
    receipt.capability_sha256 = "8".repeat(64);
    assert!(
        validate_tenant_resource_receipt_capability_binding_with_digest(
            &receipt,
            &capability,
            &"9".repeat(64),
        )
        .is_err()
    );

    let mut two_resource_task = tenant_resource_task();
    if let TenantResourceTaskPayload::Apply { resources } = &mut two_resource_task.payload {
        resources.push(identity);
    }
    assert!(
        validate_tenant_resource_receipt_binding(&two_resource_task, &tenant_resource_receipt())
            .is_err()
    );
}

#[test]
fn trust_policy_parser_rejects_multi_authority_and_inter_certificate_junk() {
    let coordinate = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let policy = Openid4vcTrustPolicy {
        schema: 1,
        client_attestation_issuer: "https://issuer.example".to_owned(),
        client_attestation_jwks: serde_json::json!({"keys": [{
            "kty": "EC", "crv": "P-256", "x": coordinate, "y": coordinate, "kid": "client"
        }]}),
        key_attestation_jwks: serde_json::json!({"keys": [{
            "kty": "EC", "crv": "P-256", "x": coordinate, "y": coordinate, "kid": "holder"
        }]}),
        credential_trust_anchor_pem:
            "-----BEGIN CERTIFICATE-----\nMA==\n-----END CERTIFICATE-----\n".to_owned(),
        wallet_authorization_origins: vec!["https://wallet.example".to_owned()],
    };
    let mut multiple_ports = policy.clone();
    multiple_ports.wallet_authorization_origins =
        vec!["https://wallet.example:8443:9443".to_owned()];
    assert!(validate_openid4vc_trust_policy(&multiple_ports).is_err());

    let mut junk_between_certificates = policy;
    junk_between_certificates.credential_trust_anchor_pem = concat!(
        "-----BEGIN CERTIFICATE-----\nMA==\n-----END CERTIFICATE-----\n",
        "junk\n",
        "-----BEGIN CERTIFICATE-----\nMDE=\n-----END CERTIFICATE-----\n"
    )
    .to_owned();
    assert!(validate_openid4vc_trust_policy(&junk_between_certificates).is_err());
}

fn openid4vp_verification_receipt() -> Openid4vpVerificationReceipt {
    Openid4vpVerificationReceipt {
        schema: 1,
        iss: "https://auth.example".to_owned(),
        aud: "https://auth.example/openid4vp/verification-receipts".to_owned(),
        jti: "019c8ca2-30a6-7000-8000-000000000001".to_owned(),
        iat: 1_787_367_660,
        exp: 1_787_367_960,
        deployment_id: "deployment-1".to_owned(),
        runtime_instance_id: "runtime-1".to_owned(),
        instance_key_id: "instance-key".to_owned(),
        tenant_id: "019c8ca2-30a6-7000-8000-000000000005".to_owned(),
        transaction_id: "019c8ca2-30a6-7000-8000-000000000002".to_owned(),
        issuance_request_jti: "019c8ca2-30a6-7000-8000-000000000006".to_owned(),
        status: Openid4vpVerificationStatus::Verified,
        evidence_context: Openid4vpEvidenceContext {
            run_jti: "run-jti-1".to_owned(),
            artifact_sha256: "a".repeat(64),
            matrix_sha256: "b".repeat(64),
            suite_plan_id: "Ab3dEf5gHi7Jk".to_owned(),
            suite_module_id: "Ab3dEf5gHi7JkLm".to_owned(),
            test_name: "openid4vp-test".to_owned(),
            variant_sha256: "c".repeat(64),
        },
        presentation_binding: Openid4vpPresentationBinding {
            presentation_request_sha256: "e".repeat(64),
            trust_policy: Openid4vpTrustPolicyBinding {
                binding_id: Some("019c8ca2-30a6-7000-8000-000000000007".to_owned()),
                resource_id: Some("vp-policy-1".to_owned()),
                resource_digest: Some("f".repeat(64)),
            },
        },
        intent_sha256: "1".repeat(64),
        completed_at: "2026-08-22T03:00:00Z".to_owned(),
        capability_sha256: "d".repeat(64),
    }
}

#[test]
fn openid4vp_evidence_context_accepts_opaque_suite_identifiers_with_safe_bounds() {
    let context = openid4vp_verification_receipt().evidence_context;
    canonical_openid4vp_evidence_context_sha256(&context)
        .expect("official-length opaque suite identifiers must be accepted");

    let mut invalid = context.clone();
    invalid.suite_plan_id = "unsafe/plan".to_owned();
    assert!(canonical_openid4vp_evidence_context_sha256(&invalid).is_err());

    let mut oversized = context;
    oversized.suite_module_id = "a".repeat(129);
    assert!(canonical_openid4vp_evidence_context_sha256(&oversized).is_err());
}

fn openid4vp_normalized_create_request() -> Openid4vpNormalizedCreateRequest {
    Openid4vpNormalizedCreateRequest {
        wallet_authorization_endpoint: "https://wallet.example/authorize".to_owned(),
        dcql_query: serde_json::from_str(
            r#"{"credentials":[{"meta":{"z":2,"a":1},"id":"credential-1"}]}"#,
        )
        .unwrap(),
        haip: true,
        client_id_prefix: "x509_san_dns".to_owned(),
        request_method: "request_uri_signed_get".to_owned(),
        response_mode: "direct_post.jwt".to_owned(),
        transaction_data: Some(vec![
            serde_json::from_str(r#"{"type":"payment","details":{"z":2,"a":1}}"#).unwrap(),
        ]),
        openid4vc_trust_policy_resource_id: Some("trust-policy-1".to_owned()),
        openid4vc_trust_policy_digest: Some("a".repeat(64)),
    }
}

#[test]
fn openid4vp_normalized_create_request_canonicalizes_recursive_object_order() {
    let first = openid4vp_normalized_create_request();
    let mut second = first.clone();
    second.dcql_query =
        serde_json::from_str(r#"{"credentials":[{"id":"credential-1","meta":{"a":1,"z":2}}]}"#)
            .unwrap();
    second.transaction_data = Some(vec![
        serde_json::from_str(r#"{"details":{"a":1,"z":2},"type":"payment"}"#).unwrap(),
    ]);

    let (first_json, first_sha256) = canonical_openid4vp_normalized_create_request(&first).unwrap();
    let (second_json, second_sha256) =
        canonical_openid4vp_normalized_create_request(&second).unwrap();

    assert_eq!(first_json, second_json);
    assert_eq!(first_sha256, second_sha256);
    assert_eq!(first_sha256.len(), 64);
    assert!(
        first_sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    );
    assert!(first_json.contains(r#""meta":{"a":1,"z":2}"#));
    assert!(first_json.contains(r#""details":{"a":1,"z":2}"#));
}

#[test]
fn openid4vp_normalized_create_request_hash_binds_every_field() {
    let baseline = openid4vp_normalized_create_request();
    let (_, baseline_sha256) = canonical_openid4vp_normalized_create_request(&baseline).unwrap();
    let mut changed = Vec::new();

    let mut request = baseline.clone();
    request.wallet_authorization_endpoint.push_str("/changed");
    changed.push(request);
    let mut request = baseline.clone();
    request.dcql_query = serde_json::json!({"credentials": []});
    changed.push(request);
    let mut request = baseline.clone();
    request.haip = false;
    changed.push(request);
    let mut request = baseline.clone();
    request.client_id_prefix.push_str("_changed");
    changed.push(request);
    let mut request = baseline.clone();
    request.request_method.push_str("_changed");
    changed.push(request);
    let mut request = baseline.clone();
    request.response_mode.push_str("_changed");
    changed.push(request);
    let mut request = baseline.clone();
    request.transaction_data = None;
    changed.push(request);
    let mut request = baseline.clone();
    request.openid4vc_trust_policy_resource_id = None;
    changed.push(request);
    let mut request = baseline.clone();
    request.openid4vc_trust_policy_digest = None;
    changed.push(request);

    for request in changed {
        let (_, changed_sha256) = canonical_openid4vp_normalized_create_request(&request).unwrap();
        assert_ne!(changed_sha256, baseline_sha256);
    }
}

#[test]
fn openid4vp_create_request_jti_requires_canonical_versioned_uuid() {
    for version in b'1'..=b'8' {
        let mut valid = b"00000000-0000-7000-8000-000000000001".to_vec();
        valid[14] = version;
        validate_openid4vp_create_request_jti(std::str::from_utf8(&valid).unwrap()).unwrap();
    }

    for malformed in [
        "00000000-0000-0000-8000-000000000001",
        "00000000-0000-9000-8000-000000000001",
        "00000000-0000-7000-7000-000000000001",
        "00000000-0000-7000-c000-000000000001",
        "00000000-0000-7000-8000-00000000000A",
        "00000000000070008000000000000001",
        "not-a-uuid",
    ] {
        assert!(validate_openid4vp_create_request_jti(malformed).is_err());
    }
}

#[test]
fn openid4vp_verification_receipt_is_server_bound_and_time_bounded() {
    let key = SigningKey::from_bytes(&[47; 32]);
    let key_id = instance_key_id(&key.verifying_key());
    let mut receipt = openid4vp_verification_receipt();
    receipt.instance_key_id.clone_from(&key_id);
    let compact = sign_openid4vp_verification_receipt(&receipt, &key_id, &key)
        .expect("valid verification receipt should sign");
    let context_sha256 =
        canonical_openid4vp_evidence_context_sha256(&receipt.evidence_context).unwrap();
    let presentation_binding_sha256 =
        canonical_openid4vp_presentation_binding_sha256(&receipt.presentation_binding).unwrap();
    let expected = Openid4vpVerificationReceiptExpectations {
        issuer: &receipt.iss,
        audience: &receipt.aud,
        deployment_id: &receipt.deployment_id,
        runtime_instance_id: &receipt.runtime_instance_id,
        instance_key_id: &key_id,
        tenant_id: &receipt.tenant_id,
        transaction_id: &receipt.transaction_id,
        receipt_id: &receipt.jti,
        issuance_request_jti: &receipt.issuance_request_jti,
        evidence_context_sha256: &context_sha256,
        presentation_binding_sha256: &presentation_binding_sha256,
        intent_sha256: &receipt.intent_sha256,
        capability_sha256: &receipt.capability_sha256,
    };
    assert_eq!(
        verify_openid4vp_verification_receipt(
            &compact,
            &expected,
            &key.verifying_key(),
            receipt.iat + 60,
        )
        .expect("valid verification receipt should verify"),
        receipt
    );
    assert!(
        verify_openid4vp_verification_receipt(
            &compact,
            &expected,
            &key.verifying_key(),
            receipt.exp,
        )
        .is_err(),
        "receipt must expire at the exclusive expiry boundary"
    );
}

#[test]
fn openid4vp_verification_receipt_rejects_context_or_signer_drift() {
    let key = SigningKey::from_bytes(&[48; 32]);
    let key_id = instance_key_id(&key.verifying_key());
    let mut receipt = openid4vp_verification_receipt();
    receipt.instance_key_id.clone_from(&key_id);
    receipt.evidence_context.matrix_sha256 = "A".repeat(64);
    assert!(sign_openid4vp_verification_receipt(&receipt, &key_id, &key).is_err());

    let mut receipt = openid4vp_verification_receipt();
    receipt.instance_key_id = "instance-other".to_owned();
    assert!(sign_openid4vp_verification_receipt(&receipt, &key_id, &key).is_err());

    let mut receipt = openid4vp_verification_receipt();
    receipt.instance_key_id.clone_from(&key_id);
    receipt.exp = receipt.iat - 1;
    assert!(sign_openid4vp_verification_receipt(&receipt, &key_id, &key).is_err());
}

#[test]
fn openid4vp_verification_receipt_rejects_signed_substitution() {
    let key = SigningKey::from_bytes(&[49; 32]);
    let key_id = instance_key_id(&key.verifying_key());
    let mut receipt = openid4vp_verification_receipt();
    receipt.instance_key_id.clone_from(&key_id);
    let compact = sign_openid4vp_verification_receipt(&receipt, &key_id, &key).unwrap();
    let context_sha256 =
        canonical_openid4vp_evidence_context_sha256(&receipt.evidence_context).unwrap();
    let presentation_binding_sha256 =
        canonical_openid4vp_presentation_binding_sha256(&receipt.presentation_binding).unwrap();
    let expected = Openid4vpVerificationReceiptExpectations {
        issuer: &receipt.iss,
        audience: &receipt.aud,
        deployment_id: &receipt.deployment_id,
        runtime_instance_id: &receipt.runtime_instance_id,
        instance_key_id: &key_id,
        tenant_id: &receipt.tenant_id,
        transaction_id: "019c8ca2-30a6-7000-8000-000000000099",
        receipt_id: &receipt.jti,
        issuance_request_jti: &receipt.issuance_request_jti,
        evidence_context_sha256: &context_sha256,
        presentation_binding_sha256: &presentation_binding_sha256,
        intent_sha256: &receipt.intent_sha256,
        capability_sha256: &receipt.capability_sha256,
    };
    assert!(
        verify_openid4vp_verification_receipt(
            &compact,
            &expected,
            &key.verifying_key(),
            receipt.iat,
        )
        .is_err(),
        "a valid receipt for another transaction must not substitute"
    );
}

#[test]
fn openid4vp_verification_intent_is_immutable_and_typed() {
    let key = SigningKey::from_bytes(&[50; 32]);
    let key_id = instance_key_id(&key.verifying_key());
    let receipt = openid4vp_verification_receipt();
    let transaction_id = receipt.transaction_id.clone();
    let context_sha256 =
        canonical_openid4vp_evidence_context_sha256(&receipt.evidence_context).unwrap();
    let presentation_binding_sha256 =
        canonical_openid4vp_presentation_binding_sha256(&receipt.presentation_binding).unwrap();
    let intent = Openid4vpVerificationIntent {
        schema: 1,
        iss: receipt.iss.clone(),
        aud: "https://auth.example/openid4vp/verification-intents".to_owned(),
        jti: transaction_id.clone(),
        iat: receipt.iat - 60,
        exp: receipt.exp,
        deployment_id: receipt.deployment_id.clone(),
        runtime_instance_id: receipt.runtime_instance_id.clone(),
        instance_key_id: key_id.clone(),
        tenant_id: "019c8ca2-30a6-7000-8000-000000000005".to_owned(),
        transaction_id: transaction_id.clone(),
        evidence_context: receipt.evidence_context,
        presentation_binding: receipt.presentation_binding,
    };
    let compact = sign_openid4vp_verification_intent(&intent, &key_id, &key).unwrap();
    let expected = Openid4vpVerificationIntentExpectations {
        issuer: &intent.iss,
        audience: &intent.aud,
        deployment_id: &intent.deployment_id,
        runtime_instance_id: &intent.runtime_instance_id,
        instance_key_id: &key_id,
        tenant_id: &intent.tenant_id,
        transaction_id: &transaction_id,
        evidence_context_sha256: &context_sha256,
        presentation_binding_sha256: &presentation_binding_sha256,
    };
    assert_eq!(
        verify_openid4vp_verification_intent(
            &compact,
            &expected,
            &key.verifying_key(),
            intent.iat,
        )
        .unwrap(),
        intent
    );
    let wrong_context = "f".repeat(64);
    let wrong = Openid4vpVerificationIntentExpectations {
        evidence_context_sha256: &wrong_context,
        ..expected
    };
    assert!(
        verify_openid4vp_verification_intent(&compact, &wrong, &key.verifying_key(), intent.iat,)
            .is_err()
    );
    let mut reversed = intent;
    reversed.exp = reversed.iat - 1;
    assert!(sign_openid4vp_verification_intent(&reversed, &key_id, &key).is_err());
}
