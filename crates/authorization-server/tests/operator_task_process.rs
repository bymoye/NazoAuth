use std::{
    collections::BTreeMap,
    fs,
    io::Write as _,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use ed25519_dalek::SigningKey;
use nazo_operator_protocol::{
    Actor, ActorKind, CanonicalConfigManifest, ConfigBinding, EmbeddedIdentity, SecretBinding,
    TargetExpectation, TaskEnvelope, TaskOperation, TaskOutcome, canonical_config_sha256,
    sign_task, verify_runtime_receipt,
};
use sha2::{Digest as _, Sha256};

fn temporary_directory() -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "nazoauth-operator-process-test-{}",
        rand::random::<u64>()
    ));
    fs::create_dir(&path).unwrap();
    path
}

fn sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn run_operator_task(root: &Path, compact: &str) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_nazoauth"));
    command
        .arg("operator-task")
        .env_clear()
        .env("NAZOAUTH_OPERATOR_CONTEXT_FILE", root.join("context.json"))
        .env(
            "NAZOAUTH_OPERATOR_CONTROLLER_PUBLIC_KEY_FILE",
            root.join("controller.pub"),
        )
        .env(
            "NAZOAUTH_OPERATOR_RECEIPT_PRIVATE_KEY_FILE",
            root.join("receipt.key"),
        )
        .env(
            "NAZOAUTH_OPERATOR_CONFIG_MANIFEST_FILE",
            root.join("config-manifest.json"),
        )
        .env("NAZOAUTH_SERVER_CONFIG_FILE", root.join("server.yaml"))
        .env(
            "NAZOAUTH_OPERATOR_PUBLIC_JWK_FILE",
            root.join("missing-public.jwk"),
        )
        .env("NAZOAUTH_OPERATOR_STATE_DIRECTORY", root.join("state"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(windows)]
    for name in ["PATH", "SystemRoot", "WINDIR"] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    if let Some(value) = std::env::var_os("LLVM_PROFILE_FILE") {
        command.env("LLVM_PROFILE_FILE", value);
    }
    let mut child = command.spawn().unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(compact.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn signed_process_task_is_replay_safe_and_returns_a_verifiable_failure_receipt() {
    let root = temporary_directory();
    fs::create_dir(root.join("state")).unwrap();
    let controller = SigningKey::from_bytes(&[11; 32]);
    let receipt = SigningKey::from_bytes(&[12; 32]);
    fs::write(
        root.join("controller.pub"),
        URL_SAFE_NO_PAD.encode(controller.verifying_key().to_bytes()),
    )
    .unwrap();
    fs::write(
        root.join("receipt.key"),
        URL_SAFE_NO_PAD.encode(receipt.to_bytes()),
    )
    .unwrap();
    fs::write(
        root.join("context.json"),
        br#"{"controller_key_id":"controller-test","receipt_key_id":"receipt-test"}"#,
    )
    .unwrap();
    let server_config = b"issuer: https://auth.example\n";
    fs::write(root.join("server.yaml"), server_config).unwrap();
    let manifest = CanonicalConfigManifest {
        version: nazo_operator_protocol::CONFIG_MANIFEST_VERSION,
        entries: BTreeMap::from([
            ("deployment_id".to_owned(), "deployment-test".to_owned()),
            ("operation".to_owned(), "keys-register-external".to_owned()),
            ("server_config_sha256".to_owned(), sha256(server_config)),
        ]),
    };
    fs::write(
        root.join("config-manifest.json"),
        serde_json::to_vec(&manifest).unwrap(),
    )
    .unwrap();
    let now = Utc::now().timestamp();
    let task = TaskEnvelope {
        ver: nazo_operator_protocol::PROTOCOL_VERSION,
        iss: "controller:deployment-test".to_owned(),
        aud: "runtime:deployment-test".to_owned(),
        jti: "request-process-test".to_owned(),
        iat: now,
        nbf: now,
        exp: now + nazo_operator_protocol::MAX_TASK_LIFETIME_SECONDS,
        deployment_id: "deployment-test".to_owned(),
        actor: Actor {
            kind: ActorKind::LocalRoot,
            id: "uid:0".to_owned(),
        },
        target: TargetExpectation::HostBinary {
            path: "/usr/local/bin/nazoauth".to_owned(),
            sha256: "a".repeat(64),
        },
        embedded: EmbeddedIdentity {
            release: "development".to_owned(),
            revision: "development".to_owned(),
            protocol: nazo_operator_protocol::PROTOCOL_VERSION,
            build_id: "local:development".to_owned(),
        },
        config: ConfigBinding {
            manifest_version: nazo_operator_protocol::CONFIG_MANIFEST_VERSION,
            config_sha256: canonical_config_sha256(&manifest).unwrap(),
            secret_binding: SecretBinding::OpaqueRevision {
                revision: "secret-process-test".to_owned(),
            },
        },
        operation: TaskOperation::KeysRegisterExternal {
            kid: "external-process-test".to_owned(),
            alg: "ES256".to_owned(),
            key_ref: "provider:key-process-test".to_owned(),
            public_jwk_sha256: "b".repeat(64),
        },
    };
    let compact = sign_task(&task, "controller-test", &controller).unwrap();

    let first = run_operator_task(&root, &compact);
    assert!(
        first.status.success(),
        "status={} stdout={} stderr={}",
        first.status,
        String::from_utf8_lossy(&first.stdout),
        String::from_utf8_lossy(&first.stderr),
    );
    let first_compact = String::from_utf8(first.stdout).unwrap();
    let runtime_receipt =
        verify_runtime_receipt(&first_compact, "receipt-test", &receipt.verifying_key()).unwrap();
    assert_eq!(runtime_receipt.jti, task.jti);
    assert!(matches!(
        runtime_receipt.outcome,
        TaskOutcome::Failed { .. }
    ));

    let retry = run_operator_task(&root, &compact);
    assert!(retry.status.success());
    assert_eq!(retry.stdout, first_compact.as_bytes());

    let mut conflict = task.clone();
    conflict.actor.id = "uid:other".to_owned();
    let conflicting_compact = sign_task(&conflict, "controller-test", &controller).unwrap();
    let conflict = run_operator_task(&root, &conflicting_compact);
    assert!(!conflict.status.success());
    assert!(
        String::from_utf8_lossy(&conflict.stderr)
            .contains("request identifier was already claimed by a different envelope")
    );

    let mut expired = task;
    expired.jti = "request-expired-process-test".to_owned();
    expired.iat = 1;
    expired.nbf = 1;
    expired.exp = 61;
    let expired = run_operator_task(
        &root,
        &sign_task(&expired, "controller-test", &controller).unwrap(),
    );
    assert!(!expired.status.success());
    assert!(
        String::from_utf8_lossy(&expired.stderr).contains("operator task authorization failed")
    );
    assert!(
        root.join("state/request-expired-process-test.request.sha256")
            .is_file()
    );
    assert!(
        !root
            .join("state/request-expired-process-test.receipt.jws")
            .exists()
    );
    fs::remove_dir_all(root).unwrap();
}
