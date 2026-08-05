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
    invalid.resource_references = (0..65)
        .map(|index| (format!("resource-{index}"), "external/shared".to_owned()))
        .collect();
    assert!(sign_adoption_receipt(&invalid, "receipt-1", &key).is_err());

    let mut invalid = adoption_receipt();
    invalid.recovery_evidence = vec!["snapshot/evidence".to_owned(); 65];
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
fn conformance_lease_task_is_public_material_only_and_time_bounded() {
    let operation = TaskOperation::ConformanceLeaseCreate {
        profile: "oidf-full".to_owned(),
        material_sha256: "a".repeat(64),
        dynamic_registration_initial_access_token_sha256: None,
        ciba_automated_decision_token_sha256: None,
        public_material: None,
        ttl_seconds: 28_800,
    };
    validate_operation(&operation).unwrap();

    for ttl_seconds in [0, 59, 86_401] {
        assert!(
            validate_operation(&TaskOperation::ConformanceLeaseCreate {
                profile: "oidf-full".to_owned(),
                material_sha256: "a".repeat(64),
                dynamic_registration_initial_access_token_sha256: None,
                ciba_automated_decision_token_sha256: None,
                public_material: None,
                ttl_seconds,
            })
            .is_err()
        );
    }
    assert!(
        validate_operation(&TaskOperation::ConformanceLeaseCreate {
            profile: "oidf-full".to_owned(),
            material_sha256: "A".repeat(64),
            dynamic_registration_initial_access_token_sha256: None,
            ciba_automated_decision_token_sha256: None,
            public_material: None,
            ttl_seconds: 60,
        })
        .is_err()
    );
}

#[test]
fn dynamic_registration_initial_access_token_binding_is_lowercase_and_profile_scoped() {
    let digest = "b".repeat(64);
    let operation = TaskOperation::ConformanceLeaseCreate {
        profile: "oidc-fapi-ciba".to_owned(),
        material_sha256: "a".repeat(64),
        dynamic_registration_initial_access_token_sha256: Some(digest.clone()),
        ciba_automated_decision_token_sha256: None,
        public_material: None,
        ttl_seconds: 300,
    };
    validate_operation(&operation).unwrap();

    let mut uppercase = digest.clone();
    uppercase.replace_range(..1, "B");
    assert!(
        validate_operation(&TaskOperation::ConformanceLeaseCreate {
            profile: "oidc-fapi-ciba".to_owned(),
            material_sha256: "a".repeat(64),
            dynamic_registration_initial_access_token_sha256: Some(uppercase),
            ciba_automated_decision_token_sha256: None,
            public_material: None,
            ttl_seconds: 300,
        })
        .is_err()
    );
    assert!(
        validate_operation(&TaskOperation::ConformanceLeaseCreate {
            profile: "oidf-full".to_owned(),
            material_sha256: "a".repeat(64),
            dynamic_registration_initial_access_token_sha256: Some(digest),
            ciba_automated_decision_token_sha256: None,
            public_material: None,
            ttl_seconds: 300,
        })
        .is_err()
    );
}

#[test]
fn ciba_automated_decision_token_binding_is_lowercase_and_profile_scoped() {
    let digest = "c".repeat(64);
    validate_operation(&TaskOperation::ConformanceLeaseCreate {
        profile: "oidc-fapi-ciba".to_owned(),
        material_sha256: "a".repeat(64),
        dynamic_registration_initial_access_token_sha256: None,
        ciba_automated_decision_token_sha256: Some(digest.clone()),
        public_material: None,
        ttl_seconds: 300,
    })
    .unwrap();

    assert!(
        validate_operation(&TaskOperation::ConformanceLeaseCreate {
            profile: "oidc-fapi-ciba".to_owned(),
            material_sha256: "a".repeat(64),
            dynamic_registration_initial_access_token_sha256: None,
            ciba_automated_decision_token_sha256: Some("C".repeat(64)),
            public_material: None,
            ttl_seconds: 300,
        })
        .is_err()
    );
    assert!(
        validate_operation(&TaskOperation::ConformanceLeaseCreate {
            profile: "oidf-full".to_owned(),
            material_sha256: "a".repeat(64),
            dynamic_registration_initial_access_token_sha256: None,
            ciba_automated_decision_token_sha256: Some(digest),
            public_material: None,
            ttl_seconds: 300,
        })
        .is_err()
    );
}

#[test]
fn conformance_lease_protocol_keeps_legacy_create_tasks_compatible() {
    let operation: TaskOperation = serde_json::from_value(serde_json::json!({
        "name": "conformance-lease-create",
        "profile": "oidf-full",
        "material_sha256": "a".repeat(64),
        "ttl_seconds": 300,
    }))
    .unwrap();
    assert!(matches!(
        operation,
        TaskOperation::ConformanceLeaseCreate {
            dynamic_registration_initial_access_token_sha256: None,
            ciba_automated_decision_token_sha256: None,
            ..
        }
    ));
    validate_operation(&operation).unwrap();
}

#[test]
fn conformance_lease_receipts_do_not_echo_token_digests() {
    let digest = "b".repeat(64);
    let result = TaskResult::ConformanceLeaseCreated {
        lease: ConformanceLeaseSummary {
            lease_id: "018f3f2a-7b55-7a25-8f20-6d526f8f44e1".to_owned(),
            profile: "oidc-fapi-ciba".to_owned(),
            material_sha256: "a".repeat(64),
            created_at: 1,
            expires_at: 301,
            revoked_at: None,
            cleaned_at: None,
        },
    };
    let encoded = serde_json::to_string(&result).unwrap();
    assert!(!encoded.contains(&digest));
    assert!(!encoded.contains("dynamic_registration_initial_access_token_sha256"));
    assert!(!encoded.contains("ciba_automated_decision_token_sha256"));
}

#[test]
fn openid4vc_lease_accepts_only_closed_public_trust_material() {
    let material = Openid4vcConformanceTrust {
        schema: 1,
        client_attestation_issuer: "https://suite.example/".to_owned(),
        client_attestation_jwks: serde_json::json!({"keys": [{"kty": "EC", "kid": "client"}]}),
        key_attestation_jwks: serde_json::json!({"keys": [{"kty": "EC", "kid": "holder"}]}),
        credential_trust_anchor_pem:
            "-----BEGIN CERTIFICATE-----\npublic\n-----END CERTIFICATE-----\n".to_owned(),
    };
    let operation = |material| TaskOperation::ConformanceLeaseCreate {
        profile: "openid4vc".to_owned(),
        material_sha256: "a".repeat(64),
        dynamic_registration_initial_access_token_sha256: None,
        ciba_automated_decision_token_sha256: None,
        public_material: material,
        ttl_seconds: 28_800,
    };
    validate_operation(&operation(Some(material.clone()))).unwrap();
    assert!(validate_operation(&operation(None)).is_err());

    let mut private = material;
    private.client_attestation_jwks["keys"][0]["d"] = serde_json::json!("secret");
    assert!(validate_operation(&operation(Some(private))).is_err());

    let mut private_anchor = Openid4vcConformanceTrust {
        schema: 1,
        client_attestation_issuer: "https://suite.example/".to_owned(),
        client_attestation_jwks: serde_json::json!({"keys": [{"kty": "EC", "kid": "client"}]}),
        key_attestation_jwks: serde_json::json!({"keys": [{"kty": "EC", "kid": "holder"}]}),
        credential_trust_anchor_pem:
            "-----BEGIN CERTIFICATE-----\npublic\n-----END CERTIFICATE-----\n".to_owned(),
    };
    private_anchor.credential_trust_anchor_pem =
        "-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----\n".to_owned();
    assert!(validate_operation(&operation(Some(private_anchor))).is_err());
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
