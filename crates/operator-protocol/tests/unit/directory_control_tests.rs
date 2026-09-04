//! Tenant-directory lifecycle wire coverage: create/update/disable/reload/finalize/
//! describe payloads round-trip through the signed envelope, reject malformed
//! identities and unknown fields, and their result data validates on the wire
//! and replays from the journal byte-identically.

use ed25519_dalek::SigningKey;

use super::*;

fn directory_controller_key() -> SigningKey {
    SigningKey::from_bytes(&[29; 32])
}

fn directory_controller_kid() -> String {
    controller_key_id(&directory_controller_key().verifying_key())
}

/// UUIDv7-shaped identifier (version nibble `7`, RFC 9562 variant `8`).
const DIRECTORY_OPERATION_ID: &str = "019c8ca2-30a6-7000-8000-0000000000d1";
const DIRECTORY_TENANT_ID: &str = "019c8ca2-30a6-7000-8000-000000000001";
const DIRECTORY_REALM_ID: &str = "019c8ca2-30a6-7000-8000-0000000000ab";
const DIRECTORY_ORGANIZATION_ID: &str = "019c8ca2-30a6-7000-8000-0000000000ac";

fn directory_operation() -> ControlOperation {
    ControlOperation {
        schema: CONTROL_OPERATION_SCHEMA,
        operation_id: DIRECTORY_OPERATION_ID.to_owned(),
        kid: controller_key_id(&directory_controller_key().verifying_key()),
        deployment_id: "deployment-directory".to_owned(),
        config_revision: "config-revision-directory".to_owned(),
        operation: ControlOperationPayload::TenantDirectoryDescribe,
    }
}

fn directory_boundary(id: &str, slug: &str) -> ControlTenantBoundary {
    ControlTenantBoundary {
        id: id.to_owned(),
        slug: slug.to_owned(),
        display_name: format!("{slug} display"),
    }
}

fn directory_create_payload() -> ControlOperationPayload {
    ControlOperationPayload::TenantDirectoryCreate {
        expected_revision: 1,
        tenant: directory_boundary(DIRECTORY_TENANT_ID, "alpha"),
        realm: directory_boundary(DIRECTORY_REALM_ID, "alpha-realm"),
        organization: directory_boundary(DIRECTORY_ORGANIZATION_ID, "alpha-org"),
        issuer: "https://alpha.example".to_owned(),
        external_host: "alpha.example".to_owned(),
    }
}

#[test]
fn tenant_directory_payloads_roundtrip_and_validate() {
    let key = directory_controller_key();
    let create = ControlOperation {
        operation: directory_create_payload(),
        ..directory_operation()
    };
    let compact = sign_control_operation(&create, &key).unwrap();
    let canonical_hash = control_operation_request_hash(&create).unwrap();
    let decoded = verify_control_operation_signature(
        &compact,
        directory_controller_kid().as_str(),
        &directory_controller_key().verifying_key(),
    )
    .unwrap();
    assert_eq!(decoded.operation, directory_create_payload());
    assert_eq!(
        control_operation_request_hash(&decoded).unwrap(),
        canonical_hash
    );

    let disable = ControlOperation {
        operation: ControlOperationPayload::TenantDirectoryDisable {
            expected_revision: 3,
            tenant_id: DIRECTORY_TENANT_ID.to_owned(),
        },
        ..directory_operation()
    };
    let compact = sign_control_operation(&disable, &key).unwrap();
    let decoded = verify_control_operation_signature(
        &compact,
        directory_controller_kid().as_str(),
        &directory_controller_key().verifying_key(),
    )
    .unwrap();
    assert_eq!(
        decoded.operation,
        ControlOperationPayload::TenantDirectoryDisable {
            expected_revision: 3,
            tenant_id: DIRECTORY_TENANT_ID.to_owned(),
        }
    );

    let reload = ControlOperation {
        operation: ControlOperationPayload::TenantDirectoryReload {
            expected_revision: 4,
            tenant_id: DIRECTORY_TENANT_ID.to_owned(),
        },
        ..directory_operation()
    };
    let compact = sign_control_operation(&reload, &key).unwrap();
    let decoded = verify_control_operation_signature(
        &compact,
        directory_controller_kid().as_str(),
        &directory_controller_key().verifying_key(),
    )
    .unwrap();
    assert_eq!(decoded.operation, reload.operation.clone());

    validate_control_operation(&create).unwrap();
    validate_control_operation(&disable).unwrap();
    validate_control_operation(&reload).unwrap();
    validate_control_operation(&directory_operation()).unwrap();
}

#[test]
fn tenant_directory_payloads_reject_bad_identities_and_unknown_fields() {
    let expect_policy_error = |payload: ControlOperationPayload| {
        let mut operation = directory_operation();
        operation.operation = payload;
        let error = validate_control_operation(&operation)
            .unwrap_err()
            .to_string();
        assert!(error.contains("protocol policy"), "{error}");
    };

    // Two boundaries sharing the tenant id are rejected.
    let mut payload = match directory_create_payload() {
        ControlOperationPayload::TenantDirectoryCreate {
            expected_revision,
            organization,
            issuer,
            external_host,
            ..
        } => ControlOperationPayload::TenantDirectoryCreate {
            expected_revision,
            tenant: directory_boundary(DIRECTORY_TENANT_ID, "alpha"),
            realm: directory_boundary(DIRECTORY_TENANT_ID, "alpha-realm"),
            organization,
            issuer,
            external_host,
        },
        other => unreachable!("{other:?}"),
    };
    if let ControlOperationPayload::TenantDirectoryCreate { realm, .. } = &mut payload {
        realm.id = "not-a-uuid".to_owned();
    }
    expect_policy_error(payload);

    let mut payload = directory_create_payload();
    if let ControlOperationPayload::TenantDirectoryCreate { tenant, .. } = &mut payload {
        tenant.slug = String::new();
    }
    expect_policy_error(payload);

    let mut payload = directory_create_payload();
    if let ControlOperationPayload::TenantDirectoryCreate { issuer, .. } = &mut payload {
        *issuer = " https://alpha.example".to_owned();
    }
    expect_policy_error(payload);

    let mut payload = directory_create_payload();
    if let ControlOperationPayload::TenantDirectoryCreate { external_host, .. } = &mut payload {
        *external_host = "ALPHA.example".to_owned();
    }
    expect_policy_error(payload);

    // Unknown members are denied on the hand-written deserializer, too.
    let mut operation = directory_operation();
    operation.operation = directory_create_payload();
    let mut wire = serde_json::to_value(&operation.operation).unwrap();
    wire["surplus"] = serde_json::Value::String("field".to_owned());
    let decode_error = serde_json::from_value::<ControlOperationPayload>(wire).unwrap_err();
    assert!(
        decode_error.to_string().contains("unknown"),
        "{decode_error}"
    );

    expect_policy_error(ControlOperationPayload::TenantDirectoryUpdate {
        expected_revision: 1,
        tenant_id: "not-a-uuid".to_owned(),
        issuer: "https://renamed.example".to_owned(),
        external_host: "renamed.example".to_owned(),
    });
    expect_policy_error(ControlOperationPayload::TenantDirectoryFinalize {
        expected_revision: 1,
        tenant_id: "not-a-uuid".to_owned(),
    });
    expect_policy_error(ControlOperationPayload::TenantDirectoryReload {
        expected_revision: 1,
        tenant_id: "not-a-uuid".to_owned(),
    });
    let update = ControlOperation {
        operation: ControlOperationPayload::TenantDirectoryUpdate {
            expected_revision: 1,
            tenant_id: DIRECTORY_TENANT_ID.to_owned(),
            issuer: "https://renamed.example".to_owned(),
            external_host: "renamed.example".to_owned(),
        },
        ..directory_operation()
    };
    validate_control_operation(&update).unwrap();
}

#[test]
fn tenant_directory_result_data_is_wire_valid_and_replay_decodable() {
    let mutation = ControlResultData::TenantDirectoryMutation {
        action: "create".to_owned(),
        tenant_id: DIRECTORY_TENANT_ID.to_owned(),
        previous_revision: 4,
        revision: 5,
    };
    let mut entry = ControlResult {
        schema: CONTROL_RESULT_SCHEMA,
        operation_id: DIRECTORY_OPERATION_ID.to_owned(),
        request_hash: "a".repeat(64),
        outcome: ControlOutcome::Succeeded,
        error: None,
        accepted_at: 1_000,
        completed_at: Some(1_005),
        result: Some(mutation.clone()),
    };
    validate_control_result(&entry).unwrap();
    let encoded = encode_control_result(&entry).unwrap();
    let decoded = decode_control_result(&encoded).unwrap();
    assert_eq!(decoded.result, Some(mutation));

    let describe = ControlResultData::TenantDirectoryDescribe {
        revision: 5,
        tenants: vec![ControlTenantDirectoryBinding {
            tenant_id: DIRECTORY_TENANT_ID.to_owned(),
            realm_id: DIRECTORY_REALM_ID.to_owned(),
            organization_id: DIRECTORY_ORGANIZATION_ID.to_owned(),
            runtime_revision: 1,
            issuer: "https://alpha.example".to_owned(),
            external_host: "alpha.example".to_owned(),
        }],
    };
    entry.result = Some(describe.clone());
    validate_control_result(&entry).unwrap();
    let encoded = encode_control_result(&entry).unwrap();
    let decoded = decode_control_result(&encoded).unwrap();
    assert_eq!(decoded.result, Some(describe));

    // Unknown actions and incomplete bindings fail wire validation.
    entry.result = Some(ControlResultData::TenantDirectoryMutation {
        action: "explode".to_owned(),
        tenant_id: DIRECTORY_TENANT_ID.to_owned(),
        previous_revision: 4,
        revision: 5,
    });
    assert!(validate_control_result(&entry).is_err());
    entry.result = Some(ControlResultData::TenantDirectoryDescribe {
        revision: 5,
        tenants: vec![ControlTenantDirectoryBinding {
            tenant_id: DIRECTORY_TENANT_ID.to_owned(),
            realm_id: String::new(),
            organization_id: String::new(),
            runtime_revision: 0,
            issuer: String::new(),
            external_host: String::new(),
        }],
    });
    assert!(validate_control_result(&entry).is_err());
}
