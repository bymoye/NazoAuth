//! E01/E02 unit coverage for the refrozen control-plane contract: canonical
//! determinism, hashing, signing, closed enums with strict unknown-field
//! rejection everywhere, typed targets, tenant-resource payloads, and
//! journal-entry invariants.  Per 05 §2 the envelope carries no `iss`, `aud`,
//! `actor`, `iat`, `nbf`, or `exp`; admission-time key validity and replay
//! defense live in E04/E03, not in this wire model.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer as _, SigningKey};
use proptest::prelude::*;
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

fn build_identity() -> ControlBuildIdentity {
    ControlBuildIdentity {
        product: "nazauth".to_owned(),
        version: "v0.2.0".to_owned(),
        commit: "b".repeat(40),
    }
}

fn host_binary_target() -> ControlTarget {
    ControlTarget::HostBinary {
        sha256: "a".repeat(64),
        embedded: build_identity(),
    }
}

fn oci_image_target() -> ControlTarget {
    ControlTarget::OciImage {
        image_digest: format!("sha256:{}", "e".repeat(64)),
        embedded: build_identity(),
    }
}

fn operation() -> ControlOperation {
    ControlOperation {
        schema: CONTROL_OPERATION_SCHEMA,
        operation_id: OPERATION_ID.to_owned(),
        kid: controller_key_id(&controller_key().verifying_key()),
        deployment_id: "deployment-1".to_owned(),
        target: host_binary_target(),
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
    }
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
        "{\"config_revision\":\"config-revision-1\",\"deployment_id\":\"deployment-1\",\"kid\":\"43q81579CNuUUYqQOVL_6fivfotGhLY1kWMc746Iccg\",\"operation\":{\"name\":\"migrate-apply\"},\"operation_id\":\"019c8ca2-30a6-7000-8000-000000000005\",\"schema\":1,\"target\":{\"embedded\":{\"commit\":\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",\"product\":\"nazauth\",\"version\":\"v0.2.0\"},\"kind\":\"host-binary\",\"sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}}",
    );
    assert_eq!(
        control_operation_request_hash(&operation).unwrap(),
        "1f67fb3521c42af3f9c80be4a944dec729656dfe2437da6653f7e9f7a3ae4f97",
    );
    // Ed25519 is deterministic, so the full compact JWS is reproducible too.
    let compact = crate::sign_control_operation(&operation, &controller_key()).unwrap();
    assert_eq!(
        compact,
        "eyJhbGciOiJFZERTQSIsImtpZCI6IjQzcTgxNTc5Q051VVVZcVFPVkxfNmZpdmZvdEdoTFkxa1dNYzc0NkljY2ciLCJ0eXAiOiJuYXpvYXV0aC1jb250cm9sLW9wZXJhdGlvbitqd3QifQ.eyJjb25maWdfcmV2aXNpb24iOiJjb25maWctcmV2aXNpb24tMSIsImRlcGxveW1lbnRfaWQiOiJkZXBsb3ltZW50LTEiLCJraWQiOiI0M3E4MTU3OUNOdVVVWXFRT1ZMXzZmaXZmb3RHaExZMWtXTWM3NDZJY2NnIiwib3BlcmF0aW9uIjp7Im5hbWUiOiJtaWdyYXRlLWFwcGx5In0sIm9wZXJhdGlvbl9pZCI6IjAxOWM4Y2EyLTMwYTYtNzAwMC04MDAwLTAwMDAwMDAwMDAwNSIsInNjaGVtYSI6MSwidGFyZ2V0Ijp7ImVtYmVkZGVkIjp7ImNvbW1pdCI6ImJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmIiLCJwcm9kdWN0IjoibmF6YXV0aCIsInZlcnNpb24iOiJ2MC4yLjAifSwia2luZCI6Imhvc3QtYmluYXJ5Iiwic2hhMjU2IjoiYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYSJ9fQ.x6KWKyEno58wXONrxV_QU2rsCh82WRUsecSSmmXyI0WfswH6NsqxlIS1eJhACuREqQGXwUrFMGZBYlDNdXZBBQ"
    );
}

#[test]
fn two_encodings_of_one_logical_request_produce_identical_bytes() {
    let operation = operation();
    let direct = canonical_control_operation_bytes(&operation).unwrap();

    // Rebuild the same logical value as an untyped object with members
    // inserted in reverse declaration order, nested objects included.
    let mut embedded = serde_json::Map::new();
    embedded.insert("commit".to_owned(), serde_json::json!("b".repeat(40)));
    embedded.insert("version".to_owned(), serde_json::json!("v0.2.0"));
    embedded.insert("product".to_owned(), serde_json::json!("nazauth"));
    let mut target = serde_json::Map::new();
    target.insert("sha256".to_owned(), serde_json::json!("a".repeat(64)));
    target.insert("kind".to_owned(), serde_json::json!("host-binary"));
    target.insert("embedded".to_owned(), serde_json::Value::Object(embedded));
    let mut root = serde_json::Map::new();
    root.insert(
        "operation".to_owned(),
        serde_json::json!({"name": "migrate-apply"}),
    );
    root.insert(
        "config_revision".to_owned(),
        serde_json::json!("config-revision-1"),
    );
    root.insert("target".to_owned(), serde_json::Value::Object(target));
    root.insert(
        "deployment_id".to_owned(),
        serde_json::json!("deployment-1"),
    );
    root.insert("kid".to_owned(), serde_json::json!(operation.kid));
    root.insert("operation_id".to_owned(), serde_json::json!(OPERATION_ID));
    root.insert("schema".to_owned(), serde_json::json!(1));
    let reordered = canonicalize_json_value(serde_json::Value::Object(root));
    assert_eq!(
        serde_json::to_vec(&reordered).unwrap(),
        direct,
        "member insertion order must not change canonical bytes"
    );

    // Whitespace layout and \uXXXX escape spelling are equally irrelevant.
    let pretty = format!(
        r#"{{
            "schema": 1,
            "operation_id": "{OPERATION_ID}",
            "kid": "{}",
            "deployment_id": "deployment-1",
            "target": {{"kind": "host-binary", "sha256": "{}", "embedded": {{"product": "nazauth", "version": "v0.2.0", "commit": "{}"}}}},
            "config_revision": "config-re\u0076ision-1",
            "operation": {{"name": "migrate-apply"}}
        }}"#,
        operation.kid,
        "a".repeat(64),
        "b".repeat(40),
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
    let mutations: [fn(&mut ControlOperation); 8] = [
        |value| {
            value.operation_id = "019c8ca2-30a6-7000-8000-000000000006".to_owned();
        },
        |value| value.deployment_id = "deployment-2".to_owned(),
        |value| value.target = oci_image_target(),
        |value| {
            let ControlTarget::HostBinary { sha256, .. } = &mut value.target else {
                panic!("fixture target must be a host binary");
            };
            *sha256 = "c".repeat(64);
        },
        |value| {
            value.config_revision = "config-revision-2".to_owned();
        },
        |value| {
            let ControlTarget::HostBinary { sha256, .. } = &mut value.target else {
                panic!("fixture target must be a host binary");
            };
            // Reuse the same digest bytes so only the embedded build identity
            // changes the canonical request.
            let same_digest = sha256.clone();
            value.target = ControlTarget::HostBinary {
                sha256: same_digest,
                embedded: ControlBuildIdentity {
                    product: "nazauth".to_owned(),
                    version: "v0.2.1".to_owned(),
                    commit: "b".repeat(40),
                },
            };
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
    assert!(matches!(
        verify_control_operation_signature(&tampered, &operation.kid, &key.verifying_key()),
        Err(ProtocolError::Signature)
    ));
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
        reject_parsed(
            |value| value["target"]["embedded"]["buildId"] = serde_json::json!("github:1")
        )
        .is_err()
    );
    assert!(
        reject_parsed(|value| value["target"]["path"] = serde_json::json!("/usr/bin/env")).is_err()
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
fn target_variants_are_closed_strictly_parsed_and_validated() {
    // Both classes accept their exact shape.
    let mut host = operation();
    validate_control_operation(&host).unwrap();
    host.target = oci_image_target();
    validate_control_operation(&host).unwrap();

    let parse_target = |value: serde_json::Value| {
        serde_json::from_value::<ControlTarget>(value).map_err(|error| error.to_string())
    };

    // Unknown kind.
    let mut value = serde_json::to_value(host_binary_target()).unwrap();
    value["kind"] = serde_json::json!("container-layer");
    assert!(
        parse_target(value)
            .unwrap_err()
            .contains("unknown target kind")
    );

    // Unknown member inside a variant.
    let mut value = serde_json::to_value(host_binary_target()).unwrap();
    value["argv"] = serde_json::json!(["sh"]);
    assert!(
        parse_target(value)
            .unwrap_err()
            .contains("unknown target field")
    );

    // Unknown member inside the embedded identity.
    let mut value = serde_json::to_value(host_binary_target()).unwrap();
    value["embedded"]["buildId"] = serde_json::json!("github:1");
    assert!(
        parse_target(value)
            .unwrap_err()
            .contains("unknown embedded field")
    );

    // Missing required member.
    let mut value = serde_json::to_value(host_binary_target()).unwrap();
    value.as_object_mut().unwrap().remove("sha256");
    assert!(
        parse_target(value)
            .unwrap_err()
            .contains("requires field 'sha256'")
    );

    // Wrong scalar type.
    let mut value = serde_json::to_value(oci_image_target()).unwrap();
    value["image_digest"] = serde_json::json!(7);
    assert!(parse_target(value).is_err());

    // Digest formats are enforced by envelope validation.
    let mut bad_prefix = operation();
    bad_prefix.target = ControlTarget::OciImage {
        image_digest: "docker.io/nazoauth:v1".to_owned(),
        embedded: build_identity(),
    };
    assert!(validate_control_operation(&bad_prefix).is_err());

    let mut uppercase = operation();
    uppercase.target = ControlTarget::OciImage {
        image_digest: format!("sha256:{}", "E".repeat(64)),
        embedded: build_identity(),
    };
    assert!(validate_control_operation(&uppercase).is_err());

    let mut short_hash = operation();
    short_hash.target = ControlTarget::HostBinary {
        sha256: "a".repeat(63),
        embedded: build_identity(),
    };
    assert!(validate_control_operation(&short_hash).is_err());

    let mut bad_commit = operation();
    bad_commit.target = ControlTarget::HostBinary {
        sha256: "a".repeat(64),
        embedded: ControlBuildIdentity {
            product: "nazauth".to_owned(),
            version: "v0.2.0".to_owned(),
            commit: String::new(),
        },
    };
    assert!(validate_control_operation(&bad_commit).is_err());
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
    failed.error = Some(ControlErrorCode::OperationIdConflict);
    assert_eq!(
        decode_control_result(&encode_control_result(&failed).unwrap()).unwrap(),
        failed
    );
    // Stable taxonomy spelling on the wire.
    let failed_wire = encode_control_result(&failed).unwrap();
    let wire = std::str::from_utf8(&failed_wire).unwrap();
    assert!(wire.contains("OPERATION_ID_CONFLICT"));

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
