use std::collections::BTreeMap;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use nazo_operator_protocol::{
    MAX_TENANT_RESOURCE_IDENTITIES, TenantResourceIdentity, TenantResourceKind,
    TenantResourceMapping,
};
use sha2::{Digest as _, Sha256};

use super::*;

fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[test]
fn change_set_decoder_requires_the_exact_signed_identity_set() {
    let payload = serde_json::to_vec(&serde_json::json!({
        "username": "alice",
        "email": "alice@example.com",
        "password": "correct horse battery staple",
        "email_verified": true
    }))
    .unwrap();
    let identity = TenantResourceIdentity {
        kind: TenantResourceKind::User,
        resource_id: "user-alice".to_owned(),
        digest: digest(&payload),
    };
    let manifest = serde_json::to_vec(&serde_json::json!({
        "schema": 1,
        "resources": [{
            "kind": "user",
            "resource_id": "user-alice",
            "payload_base64url": URL_SAFE_NO_PAD.encode(&payload)
        }]
    }))
    .unwrap();
    let authorized = BTreeMap::from([(
        (identity.kind, identity.resource_id.clone()),
        identity.clone(),
    )]);

    let decoded = decode_change_set_payloads(&manifest, &authorized).unwrap();
    assert_eq!(decoded.len(), 1);
    assert_eq!(decoded[0].identity, identity);

    let mut drifted = authorized;
    drifted.values_mut().next().unwrap().digest = "0".repeat(64);
    assert!(decode_change_set_payloads(&manifest, &drifted).is_err());
}

#[test]
fn change_set_identity_is_unique_by_kind_and_resource_id() {
    let user_payload = serde_json::to_vec(&serde_json::json!({
        "username": "shared",
        "email": "shared@example.com",
        "password": "correct horse battery staple",
        "email_verified": true
    }))
    .unwrap();
    let dataset_payload = serde_json::to_vec(&serde_json::json!({
        "user_resource_id": "shared",
        "configuration_id": "employee-card",
        "claims": {}
    }))
    .unwrap();
    let user = TenantResourceIdentity {
        kind: TenantResourceKind::User,
        resource_id: "shared".to_owned(),
        digest: digest(&user_payload),
    };
    let dataset = TenantResourceIdentity {
        kind: TenantResourceKind::Openid4vcDataset,
        resource_id: "shared".to_owned(),
        digest: digest(&dataset_payload),
    };
    let authorized = BTreeMap::from([
        ((user.kind, user.resource_id.clone()), user),
        ((dataset.kind, dataset.resource_id.clone()), dataset),
    ]);
    let resource = |kind: &str, payload: &[u8]| {
        serde_json::json!({
            "kind": kind,
            "resource_id": "shared",
            "payload_base64url": URL_SAFE_NO_PAD.encode(payload)
        })
    };

    let cross_kind = serde_json::to_vec(&serde_json::json!({
        "schema": 1,
        "resources": [
            resource("user", &user_payload),
            resource("openid4vc-dataset", &dataset_payload)
        ]
    }))
    .unwrap();
    assert_eq!(
        decode_change_set_payloads(&cross_kind, &authorized)
            .unwrap()
            .len(),
        2
    );

    let duplicate = serde_json::to_vec(&serde_json::json!({
        "schema": 1,
        "resources": [
            resource("user", &user_payload),
            resource("user", &user_payload)
        ]
    }))
    .unwrap();
    assert!(decode_change_set_payloads(&duplicate, &authorized).is_err());
}

#[test]
fn replay_outcome_json_is_closed() {
    let outcome = ControlTenantResourceOutcome {
        revision: 4,
        resources: Vec::new(),
        resource_mappings: Vec::new(),
        resource_manifest_sha256: "a".repeat(64),
    };
    let encoded = serde_json::to_value(&outcome).unwrap();
    assert_eq!(
        serde_json::from_value::<ControlTenantResourceOutcome>(encoded).unwrap(),
        outcome
    );
    assert!(
        serde_json::from_value::<ControlTenantResourceOutcome>(serde_json::json!({
            "revision": 4,
            "resources": [],
            "resource_mappings": [],
            "resource_manifest_sha256": "a".repeat(64),
            "legacy_receipt": "forbidden"
        }))
        .is_err()
    );
}

#[test]
fn executor_rejects_an_outcome_that_the_journal_cannot_publish() {
    let outcome = ControlTenantResourceOutcome {
        revision: u64::MAX,
        resources: (0..MAX_TENANT_RESOURCE_IDENTITIES)
            .map(|index| TenantResourceIdentity {
                kind: TenantResourceKind::User,
                resource_id: format!("resource-{index:03}-{}", "x".repeat(115)),
                digest: "f".repeat(64),
            })
            .collect(),
        resource_mappings: (0..MAX_TENANT_RESOURCE_IDENTITIES)
            .map(|index| TenantResourceMapping {
                kind: TenantResourceKind::User,
                resource_id: format!("resource-{index:03}-{}", "x".repeat(115)),
                public_id: "00000000-0000-0000-0000-000000000001".to_owned(),
            })
            .collect(),
        resource_manifest_sha256: "a".repeat(64),
    };

    assert_eq!(
        validate_control_outcome(TenantResourceAction::Apply, &outcome),
        Err(TenantResourceExecutorError::TooLarge)
    );
}

#[test]
fn current_action_names_are_closed() {
    assert_eq!(operation_name(TenantResourceAction::Apply), "apply");
    assert_eq!(operation_name(TenantResourceAction::Enumerate), "enumerate");
    assert_eq!(operation_name(TenantResourceAction::Revoke), "revoke");
}
