//! E01/E02 unit coverage for the refrozen control-plane contract: canonical
//! determinism, hashing, signing, closed enums with strict unknown-field
//! rejection everywhere, tenant-resource payloads, and
//! journal-entry invariants.  Per 05 §2 the envelope carries no `iss`, `aud`,
//! `actor`, `iat`, `nbf`, or `exp`; admission-time key validity and replay
//! defense live in E04/E03, not in this wire model.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signer as _, SigningKey};
use sha2::{Digest as _, Sha256};

use super::*;
use crate::control_operation::canonicalize_json_value;
use crate::wire::{TenantResourceIdentity, TenantResourceKind, TenantResourceSelector};

fn controller_key() -> SigningKey {
    SigningKey::from_bytes(&[23; 32])
}

/// UUIDv7-shaped identifier (version nibble `7`, RFC 9562 variant `8`).
const OPERATION_ID: &str = "019c8ca2-30a6-7000-8000-000000000005";
const TENANT_ID: &str = "019c8ca2-30a6-7000-8000-000000000001";

fn operation() -> ControlOperation {
    ControlOperation {
        schema: CONTROL_OPERATION_SCHEMA,
        operation_id: OPERATION_ID.to_owned(),
        kid: controller_key_id(&controller_key().verifying_key()),
        deployment_id: "deployment-1".to_owned(),
        config_revision: "config-revision-1".to_owned(),
        operation: ControlOperationPayload::MigrateApply,
    }
}

fn resource(kind: TenantResourceKind, id: &str) -> TenantResourceIdentity {
    TenantResourceIdentity {
        kind,
        resource_id: id.to_owned(),
        digest: "d".repeat(64),
    }
}

fn result_entry() -> ControlResult {
    ControlResult {
        schema: CONTROL_RESULT_SCHEMA,
        operation_id: OPERATION_ID.to_owned(),
        request_hash: "a".repeat(64),
        outcome: ControlOutcome::Succeeded,
        error: None,
        accepted_at: 1_000,
        completed_at: Some(1_005),
        result: None,
    }
}

fn enumerate_result_data() -> ControlResultData {
    ControlResultData::TenantResourceEnumerate {
        revision: 7,
        resources: vec![resource(TenantResourceKind::User, "user-1")],
        resource_manifest_sha256: "f".repeat(64),
    }
}

#[test]
fn result_data_wire_validation_includes_the_complete_result_envelope() {
    validate_control_result_data_for_wire(&enumerate_result_data()).unwrap();

    let resources = (0..MAX_TENANT_RESOURCE_IDENTITIES)
        .map(|index| TenantResourceIdentity {
            kind: TenantResourceKind::User,
            resource_id: format!("resource-{index:03}-{}", "x".repeat(115)),
            digest: "f".repeat(64),
        })
        .collect::<Vec<_>>();
    let resource_mappings = resources
        .iter()
        .map(|resource| TenantResourceMapping {
            kind: resource.kind,
            resource_id: resource.resource_id.clone(),
            public_id: "00000000-0000-0000-0000-000000000001".to_owned(),
        })
        .collect();
    let oversized = ControlResultData::TenantResourceApply {
        revision: u64::MAX,
        resources,
        resource_mappings,
        resource_manifest_sha256: "f".repeat(64),
    };

    let error = validate_control_result_data_for_wire(&oversized).unwrap_err();
    assert!(matches!(error, ProtocolError::TooLarge), "{error:?}");
}

fn payload_of(compact: &str) -> serde_json::Value {
    let segment = compact.split('.').nth(1).unwrap();
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(segment).unwrap()).unwrap()
}

#[test]
fn golden_canonical_bytes_and_request_hash_are_stable() {
    let operation = operation();
    let bytes = canonical_control_operation_bytes(&operation).unwrap();
    assert_eq!(
        std::str::from_utf8(&bytes).unwrap(),
        "{\"config_revision\":\"config-revision-1\",\"deployment_id\":\"deployment-1\",\"kid\":\"43q81579CNuUUYqQOVL_6fivfotGhLY1kWMc746Iccg\",\"operation\":{\"name\":\"migrate-apply\"},\"operation_id\":\"019c8ca2-30a6-7000-8000-000000000005\",\"schema\":3}",
    );
    assert_eq!(
        control_operation_request_hash(&operation).unwrap(),
        "8261e7f3ece52ee7b063689c98ead4265f2f4e5e5b40c09b2fe3909af31eceff",
    );
    // Ed25519 is deterministic, so the full compact JWS is reproducible too.
    let compact = crate::sign_control_operation(&operation, &controller_key()).unwrap();
    assert_eq!(
        compact,
        "eyJhbGciOiJFZERTQSIsImtpZCI6IjQzcTgxNTc5Q051VVVZcVFPVkxfNmZpdmZvdEdoTFkxa1dNYzc0NkljY2ciLCJ0eXAiOiJuYXpvYXV0aC1jb250cm9sLW9wZXJhdGlvbitqd3QifQ.eyJjb25maWdfcmV2aXNpb24iOiJjb25maWctcmV2aXNpb24tMSIsImRlcGxveW1lbnRfaWQiOiJkZXBsb3ltZW50LTEiLCJraWQiOiI0M3E4MTU3OUNOdVVVWXFRT1ZMXzZmaXZmb3RHaExZMWtXTWM3NDZJY2NnIiwib3BlcmF0aW9uIjp7Im5hbWUiOiJtaWdyYXRlLWFwcGx5In0sIm9wZXJhdGlvbl9pZCI6IjAxOWM4Y2EyLTMwYTYtNzAwMC04MDAwLTAwMDAwMDAwMDAwNSIsInNjaGVtYSI6M30.__QjcrIzfNFJTfMmihviVhgwtlKJLsTPad71ZWHrpJmh_u99c4Qh0J9BphS1CedkdPLKRUFjDD6BCAcRFHYCBA"
    );
}

#[test]
fn two_encodings_of_one_logical_request_produce_identical_bytes() {
    let operation = operation();
    let direct = canonical_control_operation_bytes(&operation).unwrap();

    // Rebuild the same logical value as an untyped object with members
    // inserted in reverse declaration order, nested objects included.
    let mut root = serde_json::Map::new();
    root.insert(
        "operation".to_owned(),
        serde_json::json!({"name": "migrate-apply"}),
    );
    root.insert(
        "config_revision".to_owned(),
        serde_json::json!("config-revision-1"),
    );
    root.insert(
        "deployment_id".to_owned(),
        serde_json::json!("deployment-1"),
    );
    root.insert("kid".to_owned(), serde_json::json!(operation.kid));
    root.insert("operation_id".to_owned(), serde_json::json!(OPERATION_ID));
    root.insert(
        "schema".to_owned(),
        serde_json::json!(CONTROL_OPERATION_SCHEMA),
    );
    let reordered = canonicalize_json_value(serde_json::Value::Object(root));
    assert_eq!(
        serde_json::to_vec(&reordered).unwrap(),
        direct,
        "member insertion order must not change canonical bytes"
    );

    // Whitespace layout and \uXXXX escape spelling are equally irrelevant.
    let pretty = format!(
        r#"{{
            "schema": {CONTROL_OPERATION_SCHEMA},
            "operation_id": "{OPERATION_ID}",
            "kid": "{}",
            "deployment_id": "deployment-1",
            "config_revision": "config-re\u0076ision-1",
            "operation": {{"name": "migrate-apply"}}
        }}"#,
        operation.kid,
    );
    let parsed: serde_json::Value = serde_json::from_str(&pretty).unwrap();
    assert_eq!(
        serde_json::to_vec(&canonicalize_json_value(parsed)).unwrap(),
        direct,
        "whitespace and unicode-escape spellings must not change canonical bytes"
    );

    // The hash follows the bytes, never the encoding.
    let hash = control_operation_request_hash(&operation).unwrap();
    let reparsed: ControlOperation = serde_json::from_slice(&direct).unwrap();
    assert_eq!(reparsed, operation);
    assert_eq!(control_operation_request_hash(&reparsed).unwrap(), hash);
}

#[test]
fn distinct_requests_never_share_a_request_hash() {
    let baseline = control_operation_request_hash(&operation()).unwrap();
    let mutations: [fn(&mut ControlOperation); 5] = [
        |value| {
            value.operation_id = "019c8ca2-30a6-7000-8000-000000000006".to_owned();
        },
        |value| value.deployment_id = "deployment-2".to_owned(),
        |value| {
            value.config_revision = "config-revision-2".to_owned();
        },
        |value| {
            value.operation = ControlOperationPayload::TenantResourceEnumerate {
                tenant_id: TENANT_ID.to_owned(),
                selectors: Vec::new(),
            };
        },
        |value| {
            value.operation = tenant_apply_payload(TENANT_ID);
        },
    ];
    for mutate in mutations {
        let mut mutated = operation();
        mutate(&mut mutated);
        let hash = control_operation_request_hash(&mutated).unwrap();
        assert_ne!(hash, baseline);
        assert_eq!(hash.len(), 64);
    }
}

fn tenant_apply_payload(tenant_id: &str) -> ControlOperationPayload {
    ControlOperationPayload::TenantResourceApply {
        tenant_id: tenant_id.to_owned(),
        resources: vec![resource(TenantResourceKind::OauthClient, "client-1")],
    }
}

#[test]
fn kid_is_base64url_sha256_of_raw_public_key_bytes() {
    let key = controller_key();
    let expected = URL_SAFE_NO_PAD.encode(Sha256::digest(key.verifying_key().to_bytes()));
    let kid = controller_key_id(&key.verifying_key());
    assert_eq!(kid, expected);
    assert_eq!(kid.len(), 43);

    let operation = operation();
    assert_eq!(operation.kid, kid);
    validate_control_operation(&operation).unwrap();

    let mut short = operation.clone();
    short.kid = kid[..42].to_owned();
    assert!(validate_control_operation(&short).is_err());
    let mut foreign = operation.clone();
    foreign.kid = controller_key_id(&SigningKey::from_bytes(&[24; 32]).verifying_key());
    assert_ne!(foreign.kid, kid);
    validate_control_operation(&foreign).unwrap();
}

#[test]
fn sign_verify_roundtrip_binds_header_kid_and_media_type() {
    let key = controller_key();
    let operation = operation();
    let compact = crate::sign_control_operation(&operation, &key).unwrap();
    // There is no admission clock anywhere in verification: the same compact
    // verifies identically whenever it is presented, and the journal owns
    // replay defense after acceptance.
    assert_eq!(
        verify_control_operation_signature(&compact, &operation.kid, &key.verifying_key()).unwrap(),
        operation
    );
    let header = crate::protected_header(&compact).unwrap();
    assert_eq!(header.alg, FixedAlgorithm::EdDSA);
    assert_eq!(header.typ, CONTROL_OPERATION_JWS_TYPE);
    assert_eq!(header.kid, operation.kid);
}

#[test]
fn wrong_kid_and_wrong_signer_are_rejected() {
    let key = controller_key();
    let other = SigningKey::from_bytes(&[31; 32]);
    let operation = operation();
    let compact = crate::sign_control_operation(&operation, &key).unwrap();
    let other_kid = controller_key_id(&other.verifying_key());

    // Trusted lookup expects a different controller kid than the header.
    assert!(matches!(
        verify_control_operation_signature(&compact, &other_kid, &key.verifying_key()),
        Err(ProtocolError::Header)
    ));

    // Header rewritten to kid B while the payload still claims kid A:
    // correctly signed by B, rejected by policy because claims disagree.
    let foreign_header = serde_json::json!({
        "alg": "EdDSA",
        "kid": other_kid,
        "typ": CONTROL_OPERATION_JWS_TYPE,
    });
    let protected = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&foreign_header).unwrap());
    let payload = compact.split('.').nth(1).unwrap().to_owned();
    let signing_input = format!("{protected}.{payload}");
    let signature = other.sign(signing_input.as_bytes());
    let cross_signed = format!(
        "{signing_input}.{}",
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    );
    assert!(matches!(
        verify_control_operation_signature(&cross_signed, &other_kid, &other.verifying_key()),
        Err(ProtocolError::Policy(_))
    ));

    // Envelope kid not matching the signer is refused at signing time.
    let mut mismatched = operation.clone();
    mismatched.kid = other_kid;
    assert!(matches!(
        crate::sign_control_operation(&mismatched, &key),
        Err(ProtocolError::Policy(_))
    ));

    // An unrelated verifying key cannot verify the signature.
    let unrelated = SigningKey::from_bytes(&[32; 32]);
    assert!(matches!(
        verify_control_operation_signature(&compact, &operation.kid, &unrelated.verifying_key()),
        Err(ProtocolError::Signature)
    ));
}

#[test]
fn tampered_compact_bytes_are_rejected() {
    let key = controller_key();
    let operation = operation();
    let compact = crate::sign_control_operation(&operation, &key).unwrap();
    let mut tampered = compact.clone();
    let last = tampered.pop().unwrap();
    tampered.push(if last == 'A' { 'B' } else { 'A' });
    assert!(
        verify_control_operation_signature(&tampered, &operation.kid, &key.verifying_key())
            .is_err()
    );
}

#[test]
fn non_canonical_payload_encoding_is_rejected_even_when_correctly_signed() {
    let key = controller_key();
    let operation = operation();
    let compact = crate::sign_control_operation(&operation, &key).unwrap();
    let protected = compact.split('.').next().unwrap().to_owned();
    let pretty = serde_json::to_vec_pretty(&payload_of(&compact)).unwrap();

    // Cryptographically valid signature over a non-canonical encoding: the
    // verifier must refuse it, because exactly one encoding may exist.
    let signing_input = format!("{protected}.{}", URL_SAFE_NO_PAD.encode(&pretty));
    let signature = key.sign(signing_input.as_bytes());
    let forged_encoding = format!(
        "{signing_input}.{}",
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    );
    assert!(matches!(
        verify_control_operation_signature(&forged_encoding, &operation.kid, &key.verifying_key()),
        Err(ProtocolError::Policy(
            "control operation payload is not canonically encoded"
        ))
    ));
}

#[test]
fn unknown_fields_are_denied_everywhere() {
    let key = controller_key();
    let operation = operation();
    let compact = crate::sign_control_operation(&operation, &key).unwrap();

    let reject_parsed = |mutate: fn(&mut serde_json::Value)| {
        let mut parsed = payload_of(&compact);
        mutate(&mut parsed);
        serde_json::from_slice::<ControlOperation>(&serde_json::to_vec(&parsed).unwrap())
    };
    // Deleted identity/time fields are plain unknown fields now.
    assert!(
        reject_parsed(|value| value["actor"] = serde_json::json!({"kind": "local-root"})).is_err()
    );
    assert!(reject_parsed(|value| value["iat"] = serde_json::json!(1_000)).is_err());
    assert!(reject_parsed(|value| value["nbf"] = serde_json::json!(1_000)).is_err());
    assert!(reject_parsed(|value| value["exp"] = serde_json::json!(1_030)).is_err());
    assert!(reject_parsed(|value| value["opaque_revision"] = serde_json::json!("r1")).is_err());
    assert!(
        reject_parsed(|value| {
            value["target"] = serde_json::json!({
                "kind": "host-binary",
                "sha256": "a".repeat(64),
            })
        })
        .is_err()
    );
    assert!(
        reject_parsed(|value| value["operation"]["argv"] = serde_json::json!(["sh", "-c"]))
            .is_err()
    );

    // An unknown envelope field smuggled through a signed path breaks
    // deserialization inside the verifier as well.
    let mut smuggled = payload_of(&compact);
    smuggled["jti"] = serde_json::json!("extra");
    let smuggled_compact = format!(
        "{}.{}.{}",
        compact.split('.').next().unwrap(),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&smuggled).unwrap()),
        compact.split('.').nth(2).unwrap(),
    );
    assert!(matches!(
        verify_control_operation_signature(&smuggled_compact, &operation.kid, &key.verifying_key()),
        Err(ProtocolError::Json)
    ));

    // Protected headers stay closed as well.
    let header_with_jku = serde_json::json!({
        "alg": "EdDSA",
        "kid": operation.kid,
        "typ": CONTROL_OPERATION_JWS_TYPE,
        "jku": "https://attacker.example/jwks.json",
    });
    let forged = format!(
        "{}.e30.AA",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header_with_jku).unwrap())
    );
    assert!(matches!(
        verify_control_operation_signature(&forged, &operation.kid, &key.verifying_key()),
        Err(ProtocolError::Header)
    ));
}

#[test]
fn tenant_resource_payloads_are_bounded_typed_and_unique() {
    let base = || {
        let mut operation = operation();
        operation.operation = tenant_apply_payload(TENANT_ID);
        operation
    };
    validate_control_operation(&base()).unwrap();

    // Revoke mirrors apply.
    let mut revoke = base();
    let ControlOperationPayload::TenantResourceApply { resources, .. } = revoke.operation.clone()
    else {
        panic!("fixture must be an apply payload");
    };
    revoke.operation = ControlOperationPayload::TenantResourceRevoke {
        tenant_id: TENANT_ID.to_owned(),
        resources,
    };
    validate_control_operation(&revoke).unwrap();

    // Enumerate accepts an empty selector list (list everything).
    let mut enumerate_all = base();
    enumerate_all.operation = ControlOperationPayload::TenantResourceEnumerate {
        tenant_id: TENANT_ID.to_owned(),
        selectors: Vec::new(),
    };
    validate_control_operation(&enumerate_all).unwrap();

    // Enumerate accepts typed selectors.
    let mut enumerate = base();
    enumerate.operation = ControlOperationPayload::TenantResourceEnumerate {
        tenant_id: TENANT_ID.to_owned(),
        selectors: vec![TenantResourceSelector {
            kind: TenantResourceKind::User,
            resource_id: "user-1".to_owned(),
        }],
    };
    validate_control_operation(&enumerate).unwrap();

    let expect_policy_error = |payload: ControlOperationPayload| {
        let mut operation = operation();
        operation.operation = payload;
        let error = validate_control_operation(&operation)
            .unwrap_err()
            .to_string();
        assert!(error.contains("protocol policy"), "{error}");
    };

    // Empty apply/revoke sets are meaningless.
    expect_policy_error(ControlOperationPayload::TenantResourceApply {
        tenant_id: TENANT_ID.to_owned(),
        resources: Vec::new(),
    });

    // Over-large sets are refused.
    let flood = (0..=MAX_TENANT_RESOURCE_IDENTITIES)
        .map(|index| resource(TenantResourceKind::User, format!("user-{index}").as_str()))
        .collect::<Vec<_>>();
    assert_eq!(flood.len(), MAX_TENANT_RESOURCE_IDENTITIES + 1);
    expect_policy_error(ControlOperationPayload::TenantResourceApply {
        tenant_id: TENANT_ID.to_owned(),
        resources: flood,
    });

    // Duplicate identities are refused even when digests differ.
    expect_policy_error(ControlOperationPayload::TenantResourceApply {
        tenant_id: TENANT_ID.to_owned(),
        resources: vec![
            resource(TenantResourceKind::User, "user-1"),
            TenantResourceIdentity {
                kind: TenantResourceKind::User,
                resource_id: "user-1".to_owned(),
                digest: "0".repeat(64),
            },
        ],
    });

    // Digests must be lowercase hex SHA-256.
    let mut bad_digest = resource(TenantResourceKind::User, "user-1");
    bad_digest.digest = "D".repeat(64);
    expect_policy_error(ControlOperationPayload::TenantResourceRevoke {
        tenant_id: TENANT_ID.to_owned(),
        resources: vec![bad_digest],
    });

    // Tenant scope must be a canonical UUID.
    expect_policy_error(tenant_apply_payload("not-a-uuid"));

    // Duplicate selectors follow the same rule.
    let duplicate_selector =
        |selectors: Vec<TenantResourceSelector>| ControlOperationPayload::TenantResourceEnumerate {
            tenant_id: TENANT_ID.to_owned(),
            selectors,
        };
    expect_policy_error(duplicate_selector(vec![
        TenantResourceSelector {
            kind: TenantResourceKind::User,
            resource_id: "user-1".to_owned(),
        },
        TenantResourceSelector {
            kind: TenantResourceKind::User,
            resource_id: "user-1".to_owned(),
        },
    ]));

    // Nested objects reject unknown members instead of dropping them.
    let raw = serde_json::json!({
        "name": "tenant-resource-apply",
        "tenant_id": TENANT_ID,
        "resources": [{
            "kind": "user",
            "resource_id": "user-1",
            "digest": "d".repeat(64),
            "endpoint": "https://attacker.example",
        }],
    });
    let error = serde_json::from_value::<ControlOperationPayload>(raw)
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("unknown resource field 'endpoint'"),
        "{error}"
    );

    let raw = serde_json::json!({
        "name": "tenant-resource-enumerate",
        "tenant_id": TENANT_ID,
        "selectors": [{"kind": "wallet-provider", "resource_id": "x"}],
    });
    let error = serde_json::from_value::<ControlOperationPayload>(raw)
        .unwrap_err()
        .to_string();
    assert!(error.contains("unknown selector kind"), "{error}");
}

#[test]
fn recovery_invalidation_has_one_runtime_owned_tenant_and_strict_epoch_shape() {
    let epoch = "019c8ca2-30a6-7000-8000-000000000099";
    let payload = ControlOperationPayload::RecoveryInvalidate {
        state_epoch: epoch.to_owned(),
    };
    assert_eq!(
        serde_json::to_string(&payload).unwrap(),
        format!(r#"{{"name":"recovery-invalidate","state_epoch":"{epoch}"}}"#),
    );
    assert_eq!(
        serde_json::from_value::<ControlOperationPayload>(serde_json::json!({
            "name": "recovery-invalidate",
            "state_epoch": epoch,
        }))
        .unwrap(),
        payload
    );

    // The pre-cut shape is rejected: tenant ownership comes only from the
    // running server's validated configuration, never from ctl input.
    let old_shape = serde_json::json!({
        "name": "recovery-invalidate",
        "tenant_id": TENANT_ID,
        "state_epoch": epoch,
    });
    assert!(
        serde_json::from_value::<ControlOperationPayload>(old_shape)
            .unwrap_err()
            .to_string()
            .contains("unknown operation field 'tenant_id'")
    );

    for invalid in [
        "not-a-uuid",
        "00000000-0000-0000-0000-000000000000",
        "3d7d0c60-4a4d-4000-8000-000000000001",
    ] {
        let mut invalid_operation = operation();
        invalid_operation.operation = ControlOperationPayload::RecoveryInvalidate {
            state_epoch: invalid.to_owned(),
        };
        assert!(validate_control_operation(&invalid_operation).is_err());
    }
    let mut valid_operation = operation();
    valid_operation.operation = payload;
    validate_control_operation(&valid_operation).unwrap();

    let mut valid_result = result_entry();
    valid_result.result = Some(ControlResultData::RecoveryInvalidation {
        state_epoch: epoch.to_owned(),
        not_before: 1,
        revoked_refresh_tokens: 0,
    });
    validate_control_result(&valid_result).unwrap();
    for invalid in [
        "00000000-0000-0000-0000-000000000000",
        "3d7d0c60-4a4d-4000-8000-000000000001",
    ] {
        let mut invalid_result = valid_result.clone();
        invalid_result.result = Some(ControlResultData::RecoveryInvalidation {
            state_epoch: invalid.to_owned(),
            not_before: 1,
            revoked_refresh_tokens: 0,
        });
        assert!(validate_control_result(&invalid_result).is_err());
    }
}

#[test]
fn uuidv7_shape_is_enforced_for_ids() {
    let operation = operation();
    validate_control_operation(&operation).unwrap();

    let mut v4 = operation.clone();
    v4.operation_id = "3d7d0c60-4a4d-4000-8000-000000000001".to_owned();
    assert!(validate_control_operation(&v4).is_err());

    let mut variant = operation.clone();
    variant.operation_id = "019c8ca2-30a6-7000-c000-000000000001".to_owned();
    assert!(validate_control_operation(&variant).is_err());

    let mut uppercase = operation.clone();
    uppercase.operation_id = "019C8CA2-30A6-7000-8000-000000000005".to_owned();
    assert!(validate_control_operation(&uppercase).is_err());

    let mut unhyphenated = operation.clone();
    unhyphenated.operation_id = "019c8ca230a67000800000000000005".to_owned();
    assert!(validate_control_operation(&unhyphenated).is_err());

    let mut malformed = operation.clone();
    malformed.operation_id = "019c8ca2-30a6-7000-8000-00000000000g".to_owned();
    assert!(validate_control_operation(&malformed).is_err());

    let mut reused_result = result_entry();
    reused_result.operation_id = v4.operation_id;
    assert!(validate_control_result(&reused_result).is_err());
}

proptest! {
    #[test]
    fn arbitrary_text_kids_hashes_and_revisions_never_panic(input in any::<String>()) {
        let mut operation = operation();
        operation.kid = input.clone();
        let _ = validate_control_operation(&operation);
        operation.kid = controller_key_id(&controller_key().verifying_key());
        operation.config_revision = input.clone();
        let _ = validate_control_operation(&operation);
        let _ = config_revision_matches(&operation, input.as_bytes());
        let mut result = result_entry();
        result.request_hash = input;
        let _ = validate_control_result(&result);
    }
}

#[test]
fn control_results_roundtrip_through_journal_and_stdout_shapes() {
    let entry = result_entry();
    let bytes = encode_control_result(&entry).unwrap();
    assert_eq!(decode_control_result(&bytes).unwrap(), entry);

    let mut failed = result_entry();
    failed.outcome = ControlOutcome::Failed;
    failed.error = Some(ControlErrorCode::ExecutionFailed);
    assert_eq!(
        decode_control_result(&encode_control_result(&failed).unwrap()).unwrap(),
        failed
    );
    // Stable taxonomy spelling on the wire.
    let failed_wire = encode_control_result(&failed).unwrap();
    let wire = std::str::from_utf8(&failed_wire).unwrap();
    assert!(wire.contains("EXECUTION_FAILED"));

    let mut running = result_entry();
    running.outcome = ControlOutcome::InProgress;
    running.completed_at = None;
    assert_eq!(
        decode_control_result(&encode_control_result(&running).unwrap()).unwrap(),
        running
    );

    let mut missing_error = failed;
    missing_error.error = None;
    assert!(validate_control_result(&missing_error).is_err());
    let mut spurious_error = result_entry();
    spurious_error.error = Some(ControlErrorCode::ExecutionFailed);
    assert!(validate_control_result(&spurious_error).is_err());
    let mut premature_completion = running;
    premature_completion.completed_at = Some(1_001);
    assert!(validate_control_result(&premature_completion).is_err());
    let mut backwards_clock = result_entry();
    backwards_clock.outcome = ControlOutcome::Failed;
    backwards_clock.error = Some(ControlErrorCode::ExecutionFailed);
    backwards_clock.accepted_at = 2_000;
    assert!(validate_control_result(&backwards_clock).is_err());
    let mut stale_schema = result_entry();
    stale_schema.schema = CONTROL_RESULT_SCHEMA + 1;
    assert!(validate_control_result(&stale_schema).is_err());
    let mut foreign_id = result_entry();
    foreign_id.operation_id = "not-a-uuid".to_owned();
    assert!(validate_control_result(&foreign_id).is_err());
    let mut bad_hash = result_entry();
    bad_hash.request_hash = "A".repeat(64);
    assert!(validate_control_result(&bad_hash).is_err());

    let mut unknown_field: serde_json::Value = serde_json::to_value(result_entry()).unwrap();
    unknown_field["receiptSignature"] = serde_json::json!("must-not-exist");
    assert!(serde_json::from_value::<ControlResult>(unknown_field).is_err());

    let oversized = vec![b' '; MAX_CONTROL_RESULT_BYTES + 1];
    assert!(matches!(
        decode_control_result(&oversized),
        Err(ProtocolError::TooLarge)
    ));
}

#[test]
fn typed_result_data_is_closed_and_outcome_coupled() {
    // Succeeded results may carry the enumerate channel; the field is omitted
    // entirely when empty so pre-extension bytes stay stable.
    let plain = encode_control_result(&result_entry()).unwrap();
    assert!(!std::str::from_utf8(&plain).unwrap().contains("result"));

    let mut enumerated = result_entry();
    enumerated.result = Some(enumerate_result_data());
    let decoded = decode_control_result(&encode_control_result(&enumerated).unwrap()).unwrap();
    assert_eq!(decoded, enumerated);
    let wire_bytes = encode_control_result(&enumerated).unwrap();
    let wire = std::str::from_utf8(&wire_bytes).unwrap();
    assert!(wire.contains("\"kind\":\"tenant-resource-enumerate\""));

    // Failed and in-progress outcomes never carry result data.
    let mut failed = result_entry();
    failed.outcome = ControlOutcome::Failed;
    failed.error = Some(ControlErrorCode::ExecutionFailed);
    failed.result = Some(enumerate_result_data());
    assert!(validate_control_result(&failed).is_err());
    let mut running = result_entry();
    running.outcome = ControlOutcome::InProgress;
    running.completed_at = None;
    running.result = Some(enumerate_result_data());
    assert!(validate_control_result(&running).is_err());

    // The variant itself is strictly parsed: unknown kind, unknown member,
    // missing member, wrong scalar type, and duplicate identities are refused.
    let parse_data = |value: serde_json::Value| {
        serde_json::from_value::<ControlResultData>(value).map_err(|error| error.to_string())
    };
    let raw = serde_json::json!({"kind": "tenant-resource-old", "revision": 1, "resources": []});
    assert!(parse_data(raw).unwrap_err().contains("unknown result kind"));
    let raw = serde_json::json!({
        "kind": "tenant-resource-enumerate", "revision": 1, "resources": [],
        "resource_manifest_sha256": "f".repeat(64),
        "selectors": [],
    });
    assert!(
        parse_data(raw)
            .unwrap_err()
            .contains("unknown result field")
    );
    let raw = serde_json::json!({"kind": "tenant-resource-enumerate", "resources": []});
    assert!(
        parse_data(raw)
            .unwrap_err()
            .contains("requires unsigned field 'revision'")
    );
    let raw = serde_json::json!({
        "kind": "tenant-resource-enumerate",
        "revision": -1,
        "resources": [],
    });
    assert!(parse_data(raw).is_err());
    let raw = serde_json::json!({
        "kind": "tenant-resource-enumerate",
        "revision": 1,
        "resources": [
            {"kind": "user", "resource_id": "user-1", "digest": "d".repeat(64)},
            {"kind": "user", "resource_id": "user-1", "digest": "e".repeat(64)},
        ],
        "resource_manifest_sha256": "f".repeat(64),
    });
    // Shape-wise duplicates deserialize; the journal-entry validator refuses
    // them (asserted below through validate_control_result).
    assert!(parse_data(raw).is_ok());

    // Validation also runs through the journal-entry boundary.
    let mut duplicated = result_entry();
    duplicated.result = ControlResultData::TenantResourceEnumerate {
        revision: 1,
        resources: vec![
            resource(TenantResourceKind::User, "user-1"),
            TenantResourceIdentity {
                kind: TenantResourceKind::User,
                resource_id: "user-1".to_owned(),
                digest: "0".repeat(64),
            },
        ],
        resource_manifest_sha256: "f".repeat(64),
    }
    .into();
    assert!(validate_control_result(&duplicated).is_err());
    let mut malformed_digest = result_entry();
    malformed_digest.result = ControlResultData::TenantResourceEnumerate {
        revision: 1,
        resources: vec![TenantResourceIdentity {
            kind: TenantResourceKind::User,
            resource_id: "user-1".to_owned(),
            digest: "D".repeat(64),
        }],
        resource_manifest_sha256: "f".repeat(64),
    }
    .into();
    assert!(validate_control_result(&malformed_digest).is_err());
    let mut flooded = result_entry();
    flooded.result = ControlResultData::TenantResourceEnumerate {
        revision: 1,
        resources: (0..=MAX_TENANT_RESOURCE_IDENTITIES)
            .map(|index| resource(TenantResourceKind::User, format!("user-{index}").as_str()))
            .collect(),
        resource_manifest_sha256: "f".repeat(64),
    }
    .into();
    assert!(validate_control_result(&flooded).is_err());
}

#[test]
fn revoke_result_manifest_describes_remaining_active_set_not_revoked_delta() {
    let revoked = resource(TenantResourceKind::User, "revoked-user");
    let remaining = resource(TenantResourceKind::OauthClient, "active-client");
    let remaining_manifest = canonical_tenant_resource_manifest_sha256(&[remaining]).unwrap();
    assert_ne!(
        remaining_manifest,
        canonical_tenant_resource_manifest_sha256(std::slice::from_ref(&revoked)).unwrap()
    );

    let mut result = result_entry();
    result.result = Some(ControlResultData::TenantResourceRevoke {
        revision: 8,
        resources: vec![revoked],
        resource_manifest_sha256: remaining_manifest,
    });
    validate_control_result(&result).unwrap();
}

#[test]
fn config_revision_fencing_compares_constant_time() {
    let operation = operation();
    assert!(config_revision_matches(&operation, b"config-revision-1"));
    assert!(!config_revision_matches(&operation, b"config-revision-2"));
    assert!(!constant_time_eq(
        operation.config_revision.as_bytes(),
        b"short"
    ));
    assert!(constant_time_eq(b"digest", b"digest"));
    assert!(!constant_time_eq(b"digest", b"digesT"));
}

#[test]
fn oversize_canonical_payloads_are_refused() {
    let mut operation = operation();
    operation.operation = ControlOperationPayload::KeysGenerateLocal {
        alg: "ed25519".to_owned(),
        purposes: vec!["x".repeat(MAX_CONTROL_OPERATION_BYTES)],
    };
    assert!(matches!(
        canonical_control_operation_bytes(&operation),
        Err(ProtocolError::TooLarge)
    ));
    assert!(control_operation_request_hash(&operation).is_err());
}

#[test]
fn tenant_key_generation_is_tenant_bound_and_returns_public_material_only() {
    let mut operation = operation();
    operation.operation = ControlOperationPayload::TenantKeysGenerateLocal {
        tenant_id: "00000000-0000-0000-0000-000000000001".to_owned(),
        alg: "ES256".to_owned(),
        purposes: vec!["credential".to_owned(), "presentation_request".to_owned()],
    };
    validate_control_operation(&operation).unwrap();
    let encoded = serde_json::to_vec(&operation.operation).unwrap();
    let decoded: ControlOperationPayload = serde_json::from_slice(&encoded).unwrap();
    assert_eq!(decoded, operation.operation);

    let mut result = result_entry();
    result.result = Some(ControlResultData::TenantKeyGenerated {
        tenant_id: "00000000-0000-0000-0000-000000000001".to_owned(),
        kid: "tenant-key".to_owned(),
        keyset_revision: "2".to_owned(),
        certificate_chain_pem:
            "-----BEGIN CERTIFICATE-----\npublic-only\n-----END CERTIFICATE-----\n".to_owned(),
    });
    validate_control_result(&result).unwrap();

    for invalid_revision in ["0", "02", "-1", "a"] {
        let mut invalid = result.clone();
        let Some(ControlResultData::TenantKeyGenerated {
            keyset_revision, ..
        }) = invalid.result.as_mut()
        else {
            unreachable!("tenant key result")
        };
        *keyset_revision = invalid_revision.to_owned();
        assert!(matches!(
            validate_control_result(&invalid),
            Err(ProtocolError::Policy("invalid keyset revision"))
        ));
    }

    let mut invalid_operation = operation;
    invalid_operation.operation = ControlOperationPayload::TenantKeysGenerateLocal {
        tenant_id: "00000000-0000-0000-0000-000000000001".to_owned(),
        alg: "ES256".to_owned(),
        purposes: vec!["credential".to_owned()],
    };
    assert!(matches!(
        validate_control_operation(&invalid_operation),
        Err(ProtocolError::Policy(
            "tenant key generation requires the OpenID4VC signing profile"
        ))
    ));
}
