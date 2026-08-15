use nazo_operator_protocol::{
    Actor, ActorKind, CONTROL_DISCOVERY_SCHEMA, DiscoveryRequest,
    TENANT_RESOURCE_CAPABILITY_VERSION, TenantResourceCapability, TenantResourceKind,
    TenantResourceOperation, TenantResourceOutcome, TenantResourceReceipt,
    decode_instance_public_key, verify_deployment_statement, verify_discovery_statement,
    verify_tenant_resource_capability, verify_tenant_resource_receipt,
};
use std::path::PathBuf;

use super::*;
use crate::tenant_resource_provider::TenantResourceSigner as _;

fn temporary_root() -> PathBuf {
    std::env::temp_dir().join(format!(
        "nazoauth-control-discovery-test-{}",
        uuid::Uuid::now_v7()
    ))
}

#[test]
fn identity_is_stable_and_online_statement_is_nonce_bound() {
    let root = temporary_root();
    let endpoint = ControlDiscoveryEndpoint::initialize(
        &root,
        None,
        Some("deployment-test"),
        Some("runtime-test"),
        "https://auth.example",
    )
    .unwrap();
    let nonce = URL_SAFE_NO_PAD.encode([7_u8; 32]);
    let response = endpoint
        .respond(DiscoveryRequest {
            schema: CONTROL_DISCOVERY_SCHEMA,
            nonce: nonce.clone(),
        })
        .unwrap();
    let public_key = decode_instance_public_key(&response.instance_public_key).unwrap();
    let statement = verify_discovery_statement(
        &response.statement,
        &endpoint.identity.key_id,
        &public_key,
        &nonce,
        Utc::now().timestamp(),
    )
    .unwrap();
    assert_eq!(statement.deployment_id, "deployment-test");
    assert_eq!(statement.runtime_instance_id, "runtime-test");

    let reloaded = ControlDiscoveryEndpoint::initialize(
        &root,
        None,
        Some("deployment-test"),
        Some("runtime-test"),
        "https://auth.example",
    )
    .unwrap();
    assert_eq!(endpoint.identity.key_id, reloaded.identity.key_id);
    let offline = fs::read_to_string(
        root.join(INSTANCE_DIRECTORY)
            .join(DEPLOYMENT_STATEMENT_FILE),
    )
    .unwrap();
    let offline =
        verify_deployment_statement(offline.trim(), &reloaded.identity.key_id, &public_key)
            .unwrap();
    assert_eq!(offline.deployment_id, statement.deployment_id);
    assert_eq!(offline.runtime_instance_id, statement.runtime_instance_id);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn replicas_can_share_deployment_id_without_sharing_instance_keys() {
    let root = temporary_root();
    let replica_a = root.join("replica-a");
    let replica_b = root.join("replica-b");
    let first = ControlDiscoveryEndpoint::initialize(
        &root,
        Some(&replica_a),
        Some("deployment-shared"),
        Some("runtime-a"),
        "https://auth.example",
    )
    .unwrap();
    let second = ControlDiscoveryEndpoint::initialize(
        &root,
        Some(&replica_b),
        Some("deployment-shared"),
        Some("runtime-b"),
        "https://auth.example",
    )
    .unwrap();
    assert_eq!(
        first.identity.deployment.deployment_id,
        second.identity.deployment.deployment_id
    );
    assert_ne!(
        first.identity.deployment.runtime_instance_id,
        second.identity.deployment.runtime_instance_id
    );
    assert_ne!(first.identity.key_id, second.identity.key_id);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn persisted_deployment_identity_fails_closed_on_reconfiguration() {
    let root = temporary_root();
    ControlDiscoveryEndpoint::initialize(
        &root,
        None,
        Some("deployment-original"),
        Some("runtime-test"),
        "https://auth.example",
    )
    .unwrap();
    let error = ControlDiscoveryEndpoint::initialize(
        &root,
        None,
        Some("deployment-substitute"),
        Some("runtime-test"),
        "https://auth.example",
    )
    .err()
    .unwrap()
    .to_string();
    assert!(error.contains("refusing to change deployment identity"));
    fs::remove_dir_all(root).unwrap();
}

#[actix_web::test]
async fn http_discovery_rejects_invalid_challenges_without_exposing_identity() {
    let root = temporary_root();
    let endpoint = ControlDiscoveryEndpoint::initialize(
        &root,
        None,
        Some("deployment-test"),
        Some("runtime-test"),
        "https://auth.example",
    )
    .unwrap();
    let response = control_discovery(
        web::Data::new(endpoint),
        web::Json(DiscoveryRequest {
            schema: CONTROL_DISCOVERY_SCHEMA + 1,
            nonce: URL_SAFE_NO_PAD.encode([7_u8; 32]),
        }),
    )
    .await;
    assert_eq!(response.status(), actix_web::http::StatusCode::BAD_REQUEST);
    fs::remove_dir_all(root).unwrap();
}

#[actix_web::test]
async fn http_discovery_returns_signed_response_for_valid_challenges() {
    let root = temporary_root();
    let endpoint = ControlDiscoveryEndpoint::initialize(
        &root,
        None,
        Some("deployment-test"),
        Some("runtime-test"),
        "https://auth.example",
    )
    .unwrap();
    let response = control_discovery(
        web::Data::new(endpoint),
        web::Json(DiscoveryRequest {
            schema: CONTROL_DISCOVERY_SCHEMA,
            nonce: URL_SAFE_NO_PAD.encode([8_u8; 32]),
        }),
    )
    .await;
    assert_eq!(response.status(), actix_web::http::StatusCode::OK);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn initialization_rejects_unusable_identity_roots_and_identifiers() {
    let data_root = temporary_root();
    fs::write(&data_root, b"not-a-directory").unwrap();
    let error = ControlDiscoveryEndpoint::initialize(
        &data_root,
        None,
        Some("deployment-test"),
        Some("runtime-test"),
        "https://auth.example",
    )
    .err()
    .unwrap()
    .to_string();
    assert!(error.contains("failed to create deployment identity directory"));
    fs::remove_file(data_root).unwrap();

    let root = temporary_root();
    fs::create_dir_all(&root).unwrap();
    let identity_file = root.join("identity-file");
    fs::write(&identity_file, b"not-a-directory").unwrap();
    let error = ControlDiscoveryEndpoint::initialize(
        &root,
        Some(&identity_file),
        Some("deployment-test"),
        Some("runtime-test"),
        "https://auth.example",
    )
    .err()
    .unwrap()
    .to_string();
    assert!(error.contains("failed to create runtime instance identity directory"));
    fs::remove_dir_all(root).unwrap();

    let root = temporary_root();
    let error = ControlDiscoveryEndpoint::initialize(
        &root,
        None,
        Some("deployment-test"),
        Some("invalid/runtime-id"),
        "https://auth.example",
    )
    .err()
    .unwrap()
    .to_string();
    assert!(error.contains("invalid file identifier"));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn initialization_rejects_corrupt_identity_key_and_statement() {
    let root = temporary_root();
    ControlDiscoveryEndpoint::initialize(
        &root,
        None,
        Some("deployment-test"),
        Some("runtime-test"),
        "https://auth.example",
    )
    .unwrap();
    let identity_dir = root.join(INSTANCE_DIRECTORY);
    let original_key = fs::read_to_string(identity_dir.join(IDENTITY_KEY_FILE)).unwrap();
    fs::write(
        identity_dir.join(IDENTITY_KEY_FILE),
        "!".repeat(32).as_bytes(),
    )
    .unwrap();
    let error = ControlDiscoveryEndpoint::initialize(
        &root,
        None,
        Some("deployment-test"),
        Some("runtime-test"),
        "https://auth.example",
    )
    .err()
    .unwrap()
    .to_string();
    assert!(error.contains("not valid base64url"));

    fs::write(
        identity_dir.join(IDENTITY_KEY_FILE),
        URL_SAFE_NO_PAD.encode([3; 31]),
    )
    .unwrap();
    let error = ControlDiscoveryEndpoint::initialize(
        &root,
        None,
        Some("deployment-test"),
        Some("runtime-test"),
        "https://auth.example",
    )
    .err()
    .unwrap()
    .to_string();
    assert!(error.contains("must contain 32 bytes"));

    fs::write(identity_dir.join(IDENTITY_KEY_FILE), original_key).unwrap();
    fs::write(
        identity_dir.join(DEPLOYMENT_STATEMENT_FILE),
        b"not-a-deployment-statement",
    )
    .unwrap();
    let error = ControlDiscoveryEndpoint::initialize(
        &root,
        None,
        Some("deployment-test"),
        Some("runtime-test"),
        "https://auth.example",
    )
    .err()
    .unwrap()
    .to_string();
    assert!(!error.is_empty());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn generated_identifiers_are_stable_without_controller_configuration() {
    let root = temporary_root();
    let first =
        ControlDiscoveryEndpoint::initialize(&root, None, None, None, "https://auth.example")
            .unwrap();
    let second =
        ControlDiscoveryEndpoint::initialize(&root, None, None, None, "https://auth.example")
            .unwrap();
    assert_eq!(
        first.identity.deployment.deployment_id,
        second.identity.deployment.deployment_id
    );
    assert_eq!(
        first.identity.deployment.runtime_instance_id,
        second.identity.deployment.runtime_instance_id
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn public_identity_key_cannot_be_substituted_independently() {
    let root = temporary_root();
    ControlDiscoveryEndpoint::initialize(
        &root,
        None,
        Some("deployment-test"),
        Some("runtime-test"),
        "https://auth.example",
    )
    .unwrap();
    let identity_dir = root.join(INSTANCE_DIRECTORY);
    let substitute = SigningKey::from_bytes(&[31; 32]);
    fs::write(
        identity_dir.join(IDENTITY_PUBLIC_FILE),
        encode_instance_public_key(&substitute.verifying_key()),
    )
    .unwrap();
    let error = ControlDiscoveryEndpoint::initialize(
        &root,
        None,
        Some("deployment-test"),
        Some("runtime-test"),
        "https://auth.example",
    )
    .err()
    .unwrap()
    .to_string();
    assert!(error.contains("restore the identity as one unit"));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn concurrent_immutable_publication_accepts_only_identical_contents() {
    let root = temporary_root();
    fs::create_dir_all(&root).unwrap();
    let path = root.join("immutable-identity");

    publish_new_file(&path, b"first").unwrap();
    publish_new_file(&path, b"first").unwrap();
    let error = publish_new_file(&path, b"substitute")
        .err()
        .unwrap()
        .to_string();

    assert!(error.contains("different contents"));
    assert_eq!(fs::read(&path).unwrap(), b"first");
    assert_eq!(fs::read_dir(&root).unwrap().count(), 1);
    fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
#[test]
fn concurrent_immutable_publication_rejects_symlink_targets() {
    use std::os::unix::fs::symlink;

    let root = temporary_root();
    fs::create_dir_all(&root).unwrap();
    let target = root.join("attacker-controlled");
    let path = root.join("immutable-identity");
    fs::write(&target, b"first").unwrap();
    symlink(&target, &path).unwrap();

    let error = publish_new_file(&path, b"first").err().unwrap().to_string();

    assert!(error.contains("not a regular file"));
    assert_eq!(fs::read(&target).unwrap(), b"first");
    assert_eq!(fs::read_dir(&root).unwrap().count(), 2);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn changed_public_deployment_claim_preserves_the_previous_signed_statement() {
    let root = temporary_root();
    let first = ControlDiscoveryEndpoint::initialize(
        &root,
        None,
        Some("deployment-test"),
        Some("runtime-test"),
        "https://old-auth.example",
    )
    .unwrap();
    let second = ControlDiscoveryEndpoint::initialize(
        &root,
        None,
        Some("deployment-test"),
        Some("runtime-test"),
        "https://new-auth.example",
    )
    .unwrap();
    let identity_dir = root.join(INSTANCE_DIRECTORY);
    let current = fs::read_to_string(identity_dir.join(DEPLOYMENT_STATEMENT_FILE)).unwrap();
    let previous =
        fs::read_to_string(identity_dir.join("deployment-statement.previous.jws")).unwrap();
    let current = verify_deployment_statement(
        current.trim(),
        &second.identity.key_id,
        &second.identity.signing_key.verifying_key(),
    )
    .unwrap();
    let previous = verify_deployment_statement(
        previous.trim(),
        &first.identity.key_id,
        &first.identity.signing_key.verifying_key(),
    )
    .unwrap();
    assert_eq!(current.issuer, "https://new-auth.example");
    assert_eq!(previous.issuer, "https://old-auth.example");
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn instance_identity_signs_and_exposes_tenant_resource_contracts() {
    let root = temporary_root();
    let endpoint = ControlDiscoveryEndpoint::initialize(
        &root,
        None,
        Some("deployment-test"),
        Some("runtime-test"),
        "https://auth.example",
    )
    .unwrap();
    let now = Utc::now().timestamp();
    let tenant_id = "00000000-0000-7000-8000-000000000001";
    let capability = TenantResourceCapability {
        ver: PROTOCOL_VERSION,
        capability_version: TENANT_RESOURCE_CAPABILITY_VERSION,
        jti: "capability-test".to_owned(),
        nonce: URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>()),
        deployment_id: endpoint.deployment_id().to_owned(),
        tenant_id: tenant_id.to_owned(),
        runtime_instance_id: endpoint.runtime_instance_id().to_owned(),
        issuer: format!("runtime:{}", endpoint.deployment_id()),
        instance_key_id: endpoint.instance_key_id().to_owned(),
        embedded: endpoint.embedded_identity(),
        revision: 0,
        resource_manifest_sha256: "0".repeat(64),
        resource_kinds: vec![TenantResourceKind::User],
        actions: vec![TenantResourceOperation::Apply],
        issued_at: now,
        expires_at: now + 60,
    };
    let direct_capability = endpoint
        .sign_tenant_resource_capability(&capability)
        .unwrap();
    let trait_capability = endpoint.sign_capability(&capability).unwrap();
    assert_eq!(direct_capability, trait_capability);
    assert_eq!(
        endpoint.instance_verifying_key(),
        endpoint.identity.signing_key.verifying_key()
    );
    assert_eq!(
        verify_tenant_resource_capability(
            &direct_capability,
            endpoint.instance_key_id(),
            &endpoint.instance_verifying_key(),
            now,
        )
        .unwrap(),
        capability
    );
    let mut invalid_capability = capability.clone();
    invalid_capability.resource_manifest_sha256 = "g".repeat(64);
    assert!(matches!(
        endpoint.sign_capability(&invalid_capability),
        Err(
            crate::tenant_resource_provider::TenantResourceProviderError::Unavailable(
                "runtime capability signing failed"
            )
        )
    ));

    let receipt = TenantResourceReceipt {
        ver: PROTOCOL_VERSION,
        iss: format!("runtime:{}", endpoint.deployment_id()),
        aud: format!("controller:{}", endpoint.deployment_id()),
        jti: "request-test".to_owned(),
        request_sha256: "1".repeat(64),
        deployment_id: endpoint.deployment_id().to_owned(),
        tenant_id: tenant_id.to_owned(),
        capability_jti: capability.jti.clone(),
        capability_sha256: "2".repeat(64),
        actor: Actor {
            kind: ActorKind::Automation,
            id: "controller-test".to_owned(),
        },
        change_set_id: "change-test".to_owned(),
        change_set_sha256: "3".repeat(64),
        operation: TenantResourceOperation::Apply,
        expected_revision: 0,
        revision: 0,
        outcome: TenantResourceOutcome::Failed {
            code: "rejected".to_owned(),
        },
        resources: Vec::new(),
        resource_mappings: Vec::new(),
        baseline_manifest_sha256: "0".repeat(64),
        resource_manifest_sha256: "0".repeat(64),
        started_at: now,
        completed_at: now,
        exp: now + 60,
        audit_sequence: 1,
        audit_previous_sha256: "0".repeat(64),
    };
    let direct_receipt = endpoint.sign_tenant_resource_receipt(&receipt).unwrap();
    let trait_receipt = endpoint.sign_receipt(&receipt).unwrap();
    assert_eq!(direct_receipt, trait_receipt);
    assert_eq!(
        verify_tenant_resource_receipt(
            &direct_receipt,
            endpoint.instance_key_id(),
            &endpoint.instance_verifying_key(),
            now,
        )
        .unwrap(),
        receipt
    );
    let mut invalid_receipt = receipt.clone();
    invalid_receipt.resource_manifest_sha256 = "g".repeat(64);
    assert!(matches!(
        endpoint.sign_receipt(&invalid_receipt),
        Err(
            crate::tenant_resource_provider::TenantResourceProviderError::Unavailable(
                "runtime receipt signing failed"
            )
        )
    ));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn stale_previous_statement_is_not_silently_removed_when_it_is_not_a_file() {
    let root = temporary_root();
    ControlDiscoveryEndpoint::initialize(
        &root,
        None,
        Some("deployment-test"),
        Some("runtime-test"),
        "https://old-auth.example",
    )
    .unwrap();
    let previous = root
        .join(INSTANCE_DIRECTORY)
        .join("deployment-statement.previous.jws");
    fs::create_dir(&previous).unwrap();
    let error = ControlDiscoveryEndpoint::initialize(
        &root,
        None,
        Some("deployment-test"),
        Some("runtime-test"),
        "https://new-auth.example",
    )
    .err()
    .unwrap()
    .to_string();
    assert!(error.contains("failed to remove stale statement"));
    fs::remove_dir_all(root).unwrap();
}
