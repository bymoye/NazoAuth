use nazo_operator_protocol::{
    CONTROL_DISCOVERY_SCHEMA, DiscoveryRequest, decode_instance_public_key,
    verify_deployment_statement, verify_discovery_statement,
};
use std::path::PathBuf;

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
