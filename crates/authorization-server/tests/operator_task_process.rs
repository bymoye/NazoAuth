use std::{
    collections::BTreeMap,
    fs,
    io::Write as _,
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    thread,
    time::Duration,
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use ed25519_dalek::SigningKey;
use nazo_operator_protocol::{
    Actor, ActorKind, CanonicalConfigManifest, ConfigBinding, EmbeddedIdentity, RuntimeReceipt,
    SecretBinding, TargetExpectation, TaskEnvelope, TaskOperation, TaskOutcome,
    canonical_config_sha256, compact_sha256, sign_runtime_receipt, sign_task,
    verify_runtime_receipt,
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
    spawn_operator_task(root, compact)
        .wait_with_output()
        .unwrap()
}

fn spawn_operator_task(root: &Path, compact: &str) -> Child {
    spawn_operator_task_inner(root, compact, None)
}

fn spawn_operator_task_at_failpoint(
    root: &Path,
    compact: &str,
    failpoint: &str,
    marker: &Path,
) -> Child {
    spawn_operator_task_inner(root, compact, Some((failpoint, marker)))
}

fn spawn_operator_task_inner(
    root: &Path,
    compact: &str,
    failpoint: Option<(&str, &Path)>,
) -> Child {
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
            "NAZOAUTH_OPERATOR_SECRET_REVISION_FILE",
            root.join("secret-revision"),
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
    if let Some((name, marker)) = failpoint {
        command
            .env("NAZOAUTH_OPERATOR_TEST_FAILPOINT", name)
            .env("NAZOAUTH_OPERATOR_TEST_FAILPOINT_MARKER", marker);
    }
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
    child
}

fn wait_for_marker(path: &Path) {
    for _ in 0..500 {
        if path.is_file() {
            return;
        }
        thread::sleep(Duration::from_millis(10));
    }
    panic!(
        "operator test failpoint was not reached: {}",
        path.display()
    );
}

#[test]
fn signed_process_task_is_replay_safe_and_returns_a_verifiable_failure_receipt() {
    let root = temporary_directory();
    fs::create_dir(root.join("state")).unwrap();
    fs::write(root.join("state/deployment-id"), b"deployment-test\n").unwrap();
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
    fs::write(root.join("secret-revision"), b"secret-process-test").unwrap();
    fs::write(
        root.join("context.json"),
        br#"{"controller_key_id":"controller-test","receipt_key_id":"receipt-test"}"#,
    )
    .unwrap();
    let server_config = b"ISSUER: https://auth.example\nDEPLOYMENT_ID: deployment-test\n";
    fs::write(root.join("server.yaml"), server_config).unwrap();
    fs::create_dir_all(root.join("runtime/instance")).unwrap();
    fs::write(
        root.join("runtime/instance/deployment-id"),
        b"deployment-test\n",
    )
    .unwrap();
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

    // The receipt is authoritative once published.  An interrupted later
    // lifecycle bookkeeping write must not hide the signed result.
    let stale_lifecycle_temporary =
        root.join("state/request-process-test.lifecycle.lifecycle.json.tmp");
    fs::write(&stale_lifecycle_temporary, b"partial").unwrap();
    let retry = run_operator_task(&root, &compact);
    assert!(retry.status.success());
    assert_eq!(retry.stdout, first_compact.as_bytes());
    assert!(stale_lifecycle_temporary.exists());

    // Two independently started runtimes use the durable file lock.  One
    // produces the receipt; the other must observe that exact receipt rather
    // than execute the signed operation a second time.
    let mut concurrent = task.clone();
    concurrent.jti = "request-concurrent-process-test".to_owned();
    let concurrent_compact = sign_task(&concurrent, "controller-test", &controller).unwrap();
    let first_concurrent = spawn_operator_task(&root, &concurrent_compact);
    let second_concurrent = spawn_operator_task(&root, &concurrent_compact);
    let first_concurrent = first_concurrent.wait_with_output().unwrap();
    let second_concurrent = second_concurrent.wait_with_output().unwrap();
    assert!(first_concurrent.status.success());
    assert!(second_concurrent.status.success());
    assert_eq!(first_concurrent.stdout, second_concurrent.stdout);
    assert!(
        verify_runtime_receipt(
            std::str::from_utf8(&first_concurrent.stdout).unwrap(),
            "receipt-test",
            &receipt.verifying_key(),
        )
        .is_ok()
    );

    // Kill a real child after Executing was fsynced and before the operation
    // begins.  Restart must conservatively preserve the unknown state and
    // must not execute the envelope.
    let mut killed_before_operation = task.clone();
    killed_before_operation.jti = "request-killed-before-operation".to_owned();
    let killed_before_operation_compact =
        sign_task(&killed_before_operation, "controller-test", &controller).unwrap();
    let executing_marker = root.join("after-executing.marker");
    let mut killed = spawn_operator_task_at_failpoint(
        &root,
        &killed_before_operation_compact,
        "after-executing",
        &executing_marker,
    );
    wait_for_marker(&executing_marker);
    killed.kill().unwrap();
    assert!(!killed.wait().unwrap().success());
    let restarted = run_operator_task(&root, &killed_before_operation_compact);
    assert!(!restarted.status.success());
    assert!(
        String::from_utf8_lossy(&restarted.stderr).contains("may have executed without a receipt")
    );
    assert!(
        !root
            .join("state/request-killed-before-operation.receipt.jws")
            .exists()
    );

    // Kill a second real child after the signed receipt temporary file was
    // fsynced but before publication. Restart must validate and publish that
    // authoritative receipt without replaying the operation.
    let mut killed_before_receipt_publish = task.clone();
    killed_before_receipt_publish.jti = "request-killed-before-receipt-publish".to_owned();
    let killed_before_receipt_compact = sign_task(
        &killed_before_receipt_publish,
        "controller-test",
        &controller,
    )
    .unwrap();
    let receipt_marker = root.join("after-receipt-sync.marker");
    let mut killed = spawn_operator_task_at_failpoint(
        &root,
        &killed_before_receipt_compact,
        "after-receipt-sync",
        &receipt_marker,
    );
    wait_for_marker(&receipt_marker);
    killed.kill().unwrap();
    assert!(!killed.wait().unwrap().success());
    let receipt_temporary =
        root.join("state/request-killed-before-receipt-publish.receipt.receipt.jws.tmp");
    assert!(receipt_temporary.is_file());
    let restarted = run_operator_task(&root, &killed_before_receipt_compact);
    assert!(
        restarted.status.success(),
        "{}",
        String::from_utf8_lossy(&restarted.stderr)
    );
    assert!(!receipt_temporary.exists());
    assert!(
        root.join("state/request-killed-before-receipt-publish.receipt.jws")
            .is_file()
    );

    // This is the restart boundary after a SIGKILL.  There is intentionally
    // no receipt, but the durable executing state means the operation might
    // already have made its change.  The restarted process must not invoke it.
    let mut unknown = task.clone();
    unknown.jti = "request-unknown-process-test".to_owned();
    let unknown_compact = sign_task(&unknown, "controller-test", &controller).unwrap();
    let unknown_digest = compact_sha256(&unknown_compact);
    fs::write(
        root.join("state/request-unknown-process-test.lifecycle.json"),
        serde_json::to_vec(&serde_json::json!({
            "phase": "executing",
            "request_sha256": &unknown_digest,
        }))
        .unwrap(),
    )
    .unwrap();
    fs::write(
        root.join("state/request-unknown-process-test.request.sha256"),
        format!("nazoauth-operator-request-v1:{unknown_digest}\n"),
    )
    .unwrap();
    let unknown = run_operator_task(&root, &unknown_compact);
    assert!(!unknown.status.success());
    assert!(
        String::from_utf8_lossy(&unknown.stderr).contains("may have executed without a receipt")
    );
    assert!(
        !root
            .join("state/request-unknown-process-test.receipt.jws")
            .exists()
    );
    let unknown_retry = run_operator_task(&root, &unknown_compact);
    assert!(!unknown_retry.status.success());
    assert!(
        String::from_utf8_lossy(&unknown_retry.stderr)
            .contains("may have executed without a receipt")
    );
    assert_eq!(
        fs::read_to_string(root.join("state/request-unknown-process-test.lifecycle.json")).unwrap(),
        serde_json::to_string(&serde_json::json!({
            "phase": "executing",
            "request_sha256": &unknown_digest,
        }))
        .unwrap()
    );

    // An invalid receipt temporary must remain on disk and fail closed before
    // the binary can invoke the operation again.
    let mut partial = task.clone();
    partial.jti = "request-partial-process-test".to_owned();
    let partial_compact = sign_task(&partial, "controller-test", &controller).unwrap();
    let partial_digest = compact_sha256(&partial_compact);
    fs::write(
        root.join("state/request-partial-process-test.lifecycle.json"),
        serde_json::to_vec(&serde_json::json!({
            "phase": "executing",
            "request_sha256": &partial_digest,
        }))
        .unwrap(),
    )
    .unwrap();
    fs::write(
        root.join("state/request-partial-process-test.request.sha256"),
        format!("nazoauth-operator-request-v1:{partial_digest}\n"),
    )
    .unwrap();
    let partial_temporary = root.join("state/request-partial-process-test.receipt.receipt.jws.tmp");
    fs::write(&partial_temporary, b"partial").unwrap();
    let partial = run_operator_task(&root, &partial_compact);
    assert!(!partial.status.success());
    assert!(String::from_utf8_lossy(&partial.stderr).contains("operator task receipt is invalid"));
    assert!(partial_temporary.exists());
    assert!(matches!(
        serde_json::from_slice::<serde_json::Value>(
            &fs::read(root.join("state/request-partial-process-test.lifecycle.json")).unwrap()
        )
        .unwrap()["phase"],
        serde_json::Value::String(ref phase) if phase == "executing"
    ));

    // A complete, signed receipt temporary is recoverable.  It is validated
    // against the request and deployment before being renamed into place;
    // arbitrary or partial temporary bytes remain fail-closed.
    let mut completed_temporary = task.clone();
    completed_temporary.jti = "request-complete-receipt-temporary".to_owned();
    let completed_digest =
        compact_sha256(&sign_task(&completed_temporary, "controller-test", &controller).unwrap());
    let completed_receipt = RuntimeReceipt {
        ver: nazo_operator_protocol::PROTOCOL_VERSION,
        iss: "runtime:deployment-test".to_owned(),
        aud: completed_temporary.iss.clone(),
        jti: completed_temporary.jti.clone(),
        request_sha256: completed_digest.clone(),
        deployment_id: completed_temporary.deployment_id.clone(),
        actor: completed_temporary.actor.clone(),
        operation: "keys-register-external".to_owned(),
        started_at: Utc::now().timestamp(),
        completed_at: Utc::now().timestamp(),
        embedded: completed_temporary.embedded.clone(),
        config: completed_temporary.config.clone(),
        outcome: TaskOutcome::Failed {
            code: "operation-failed-test".to_owned(),
        },
    };
    let completed_compact =
        sign_runtime_receipt(&completed_receipt, "receipt-test", &receipt).unwrap();
    fs::write(
        root.join("state/request-complete-receipt-temporary.receipt.receipt.jws.tmp"),
        completed_compact.as_bytes(),
    )
    .unwrap();
    let completed = run_operator_task(
        &root,
        &sign_task(&completed_temporary, "controller-test", &controller).unwrap(),
    );
    assert!(completed.status.success());
    assert_eq!(completed.stdout, completed_compact.as_bytes());
    assert!(
        root.join("state/request-complete-receipt-temporary.receipt.jws")
            .is_file()
    );
    assert!(
        !root
            .join("state/request-complete-receipt-temporary.receipt.receipt.jws.tmp")
            .exists()
    );

    let mut conflict = task.clone();
    conflict.actor.id = "uid:other".to_owned();
    let conflicting_compact = sign_task(&conflict, "controller-test", &controller).unwrap();
    let lifecycle_before =
        fs::read(root.join("state/request-process-test.lifecycle.json")).unwrap();
    let conflict = run_operator_task(&root, &conflicting_compact);
    assert!(!conflict.status.success());
    assert!(
        String::from_utf8_lossy(&conflict.stderr)
            .contains("request identifier was already claimed by a different envelope")
    );
    assert_eq!(
        fs::read(root.join("state/request-process-test.lifecycle.json")).unwrap(),
        lifecycle_before
    );

    let retired_controller = SigningKey::from_bytes(&[13; 32]);
    let retired = run_operator_task(
        &root,
        &sign_task(&task, "controller-test", &retired_controller).unwrap(),
    );
    assert!(!retired.status.success());
    assert!(
        String::from_utf8_lossy(&retired.stderr)
            .contains("nazoauth-operator-rejection=authorization")
    );

    // A versioned request claim is published only after the runtime has
    // validated the original 60-second authorization window.  If the process
    // is killed before it moves Prepared to Executing, a later restart may
    // finish that already accepted task with the same JTI even after expiry.
    let mut accepted = task.clone();
    accepted.jti = "request-accepted-process-test".to_owned();
    accepted.iat = 1;
    accepted.nbf = 1;
    accepted.exp = 61;
    let accepted_compact = sign_task(&accepted, "controller-test", &controller).unwrap();
    let accepted_digest = compact_sha256(&accepted_compact);
    fs::write(
        root.join("state/request-accepted-process-test.request.sha256"),
        format!("nazoauth-operator-request-v1:{accepted_digest}\n"),
    )
    .unwrap();
    fs::write(
        root.join("state/request-accepted-process-test.lifecycle.json"),
        serde_json::to_vec(&serde_json::json!({
            "phase": "prepared",
            "request_sha256": &accepted_digest,
        }))
        .unwrap(),
    )
    .unwrap();
    let accepted = run_operator_task(&root, &accepted_compact);
    assert!(accepted.status.success());
    assert!(
        verify_runtime_receipt(
            std::str::from_utf8(&accepted.stdout).unwrap(),
            "receipt-test",
            &receipt.verifying_key(),
        )
        .is_ok()
    );

    // Rotation revokes even a previously durable claim.  The claim proves
    // that this exact envelope was accepted before a restart, but it cannot
    // override the current deployment secret authority.
    fs::write(root.join("secret-revision"), b"rotated-secret-process-test").unwrap();
    let rotated = run_operator_task(&root, &accepted_compact);
    assert!(!rotated.status.success());
    assert!(
        String::from_utf8_lossy(&rotated.stderr)
            .contains("operator task secret revision binding mismatch")
    );
    fs::write(root.join("secret-revision"), b"secret-process-test").unwrap();

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
        !root
            .join("state/request-expired-process-test.request.sha256")
            .exists()
    );
    assert!(
        !root
            .join("state/request-expired-process-test.lifecycle.json")
            .exists()
    );
    assert!(
        !root
            .join("state/request-expired-process-test.receipt.jws")
            .exists()
    );
    fs::remove_dir_all(root).unwrap();
}
