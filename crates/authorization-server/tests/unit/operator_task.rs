use std::{collections::BTreeMap, fs, sync::Arc, thread};

use super::*;

fn temporary_directory() -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "nazoauth-operator-task-test-{}",
        rand::random::<u64>()
    ));
    fs::create_dir(&path).unwrap();
    path
}

fn task(operation: TaskOperation) -> TaskEnvelope {
    TaskEnvelope {
        ver: nazo_operator_protocol::PROTOCOL_VERSION,
        iss: "controller:deployment-test".to_owned(),
        aud: "runtime:deployment-test".to_owned(),
        jti: "request-test".to_owned(),
        iat: 1,
        nbf: 1,
        exp: 61,
        deployment_id: "deployment-test".to_owned(),
        actor: nazo_operator_protocol::Actor {
            kind: nazo_operator_protocol::ActorKind::LocalRoot,
            id: "uid:0".to_owned(),
        },
        target: nazo_operator_protocol::TargetExpectation::HostBinary {
            path: "/usr/local/bin/nazoauth".to_owned(),
            sha256: "a".repeat(64),
        },
        embedded: embedded_identity(),
        config: nazo_operator_protocol::ConfigBinding {
            manifest_version: nazo_operator_protocol::CONFIG_MANIFEST_VERSION,
            config_sha256: "b".repeat(64),
            secret_binding: SecretBinding::OpaqueRevision {
                revision: "secret-revision".to_owned(),
            },
        },
        operation,
    }
}

#[test]
fn concurrent_replay_claims_are_idempotent_and_conflicts_are_rejected() {
    let directory = temporary_directory();
    for iteration in 0..64 {
        let path = Arc::new(directory.join(format!("request-{iteration}.sha256")));
        let threads = (0..16)
            .map(|_| {
                let path = Arc::clone(&path);
                thread::spawn(move || claim_request(&path, &"a".repeat(64)))
            })
            .collect::<Vec<_>>();
        for thread in threads {
            thread.join().unwrap().unwrap();
        }
        assert!(claim_request(&path, &"b".repeat(64)).is_err());
    }
    assert!(fs::read_dir(&directory).unwrap().all(|entry| {
        !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .ends_with(".tmp")
    }));
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn retry_after_kill_window_reuses_claim_and_atomically_finishes_receipt() {
    let directory = temporary_directory();
    let request = directory.join("request.sha256");
    let receipt = directory.join("request.receipt.jws");
    let digest = "c".repeat(64);
    claim_request(&request, &digest).unwrap();
    claim_request(&request, &digest).unwrap();
    fs::write(receipt.with_extension("receipt.jws.tmp"), b"partial").unwrap();
    write_receipt_atomic(&receipt, b"complete.receipt.value").unwrap();
    assert_eq!(
        fs::read_to_string(receipt).unwrap(),
        "complete.receipt.value"
    );
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn embedded_identity_and_operation_names_are_closed() {
    for (operation, expected) in [
        (TaskOperation::MigrateApply, "migrate-apply"),
        (TaskOperation::KeysList, "keys-list"),
        (TaskOperation::KeysValidate, "keys-validate"),
        (
            TaskOperation::KeysGenerateLocal {
                alg: "ES256".to_owned(),
                purposes: vec!["credential".to_owned()],
            },
            "keys-generate-local",
        ),
        (
            TaskOperation::KeysRegisterExternal {
                kid: "external-1".to_owned(),
                alg: "ES256".to_owned(),
                key_ref: "provider:key-1".to_owned(),
                public_jwk_sha256: "c".repeat(64),
            },
            "keys-register-external",
        ),
    ] {
        assert_eq!(operation_name(&operation), expected);
    }

    let valid = task(TaskOperation::KeysValidate);
    validate_embedded_identity(&valid).unwrap();

    let mut wrong_build = valid.clone();
    wrong_build.embedded.build_id.push_str("-other");
    assert!(validate_embedded_identity(&wrong_build).is_err());

    let mut wrong_manifest = valid.clone();
    wrong_manifest.config.manifest_version += 1;
    assert!(validate_embedded_identity(&wrong_manifest).is_err());

    let mut empty_revision = valid.clone();
    empty_revision.config.secret_binding = SecretBinding::OpaqueRevision {
        revision: String::new(),
    };
    assert!(validate_embedded_identity(&empty_revision).is_err());

    let mut hmac_binding = valid;
    hmac_binding.config.secret_binding = SecretBinding::HmacSha256 {
        key_id: "provider-key".to_owned(),
        digest: "d".repeat(64),
    };
    validate_embedded_identity(&hmac_binding).unwrap();
}

#[test]
fn canonical_manifest_binds_only_the_authorized_non_secret_configuration() {
    let directory = temporary_directory();
    let manifest_path = directory.join("manifest.json");
    let server_config_path = directory.join("server.yaml");
    fs::write(&server_config_path, b"issuer: https://auth.example\n").unwrap();
    let server_config_sha256: String = Sha256::digest(fs::read(&server_config_path).unwrap())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let manifest = nazo_operator_protocol::CanonicalConfigManifest {
        version: nazo_operator_protocol::CONFIG_MANIFEST_VERSION,
        entries: BTreeMap::from([
            ("deployment_id".to_owned(), "deployment-test".to_owned()),
            ("operation".to_owned(), "keys-validate".to_owned()),
            ("server_config_sha256".to_owned(), server_config_sha256),
        ]),
    };
    fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();
    let mut task = task(TaskOperation::KeysValidate);
    task.config.config_sha256 = nazo_operator_protocol::canonical_config_sha256(&manifest).unwrap();
    validate_config_manifest_at(&task, &manifest_path, &server_config_path).unwrap();

    let mut wrong_digest = task.clone();
    wrong_digest.config.config_sha256 = "0".repeat(64);
    assert!(
        validate_config_manifest_at(&wrong_digest, &manifest_path, &server_config_path).is_err()
    );

    let mut open_manifest = manifest.clone();
    open_manifest
        .entries
        .insert("unexpected".to_owned(), "value".to_owned());
    fs::write(&manifest_path, serde_json::to_vec(&open_manifest).unwrap()).unwrap();
    task.config.config_sha256 =
        nazo_operator_protocol::canonical_config_sha256(&open_manifest).unwrap();
    assert!(validate_config_manifest_at(&task, &manifest_path, &server_config_path).is_err());

    let mut wrong_operation = manifest.clone();
    wrong_operation
        .entries
        .insert("operation".to_owned(), "keys-list".to_owned());
    fs::write(
        &manifest_path,
        serde_json::to_vec(&wrong_operation).unwrap(),
    )
    .unwrap();
    task.config.config_sha256 =
        nazo_operator_protocol::canonical_config_sha256(&wrong_operation).unwrap();
    assert!(validate_config_manifest_at(&task, &manifest_path, &server_config_path).is_err());

    fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();
    task.config.config_sha256 = nazo_operator_protocol::canonical_config_sha256(&manifest).unwrap();
    fs::write(&server_config_path, b"issuer: https://other.example\n").unwrap();
    assert!(validate_config_manifest_at(&task, &manifest_path, &server_config_path).is_err());

    fs::write(&manifest_path, b"not-json").unwrap();
    assert!(validate_config_manifest_at(&task, &manifest_path, &server_config_path).is_err());
    fs::remove_file(&manifest_path).unwrap();
    assert!(validate_config_manifest_at(&task, &manifest_path, &server_config_path).is_err());
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn mounted_public_material_and_operator_keys_are_digest_bound() {
    let directory = temporary_directory();
    let jwk_path = directory.join("public.jwk");
    fs::write(&jwk_path, br#"{"kty":"EC","kid":"external-1"}"#).unwrap();
    let jwk_sha256: String = Sha256::digest(fs::read(&jwk_path).unwrap())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert_eq!(
        verify_public_jwk_at(&jwk_sha256, jwk_path.clone()).unwrap(),
        jwk_path
    );
    assert!(verify_public_jwk_at(&"0".repeat(64), jwk_path.clone()).is_err());
    assert!(verify_public_jwk_at(&jwk_sha256, directory.join("missing.jwk")).is_err());

    let key = SigningKey::from_bytes(&[7; 32]);
    let private_path = directory.join("receipt.key");
    let public_path = directory.join("controller.pub");
    fs::write(&private_path, URL_SAFE_NO_PAD.encode(key.to_bytes())).unwrap();
    fs::write(
        &public_path,
        URL_SAFE_NO_PAD.encode(key.verifying_key().to_bytes()),
    )
    .unwrap();
    assert_eq!(read_signing_key(&private_path).unwrap().to_bytes(), [7; 32]);
    assert_eq!(
        read_verifying_key(&public_path).unwrap(),
        key.verifying_key()
    );

    fs::write(&private_path, "not-base64url!").unwrap();
    assert!(read_signing_key(&private_path).is_err());
    fs::write(&private_path, URL_SAFE_NO_PAD.encode([1; 31])).unwrap();
    assert!(read_signing_key(&private_path).is_err());
    fs::write(&public_path, URL_SAFE_NO_PAD.encode([1; 31])).unwrap();
    assert!(read_verifying_key(&public_path).is_err());

    let first = stable_error_code(&anyhow::anyhow!("stable failure"));
    let second = stable_error_code(&anyhow::anyhow!("stable failure"));
    assert_eq!(first, second);
    assert!(first.starts_with("operation-failed-"));
    assert_eq!(first.len(), "operation-failed-".len() + 8);
    fs::remove_dir_all(directory).unwrap();
}
