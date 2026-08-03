use nazo_operator_protocol::{
    CONTROL_DISCOVERY_SCHEMA, DiscoveryRequest, decode_instance_public_key,
    verify_deployment_statement, verify_discovery_statement,
};

use super::*;

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
