use fs2::FileExt as _;
use std::{
    collections::BTreeMap,
    fs,
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

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
fn local_deployment_identity_rejects_cross_deployment_replay() {
    let directory = temporary_directory();
    let config_path = directory.join("server.yaml");
    fs::write(
        &config_path,
        b"DATA_DIR: runtime\nDEPLOYMENT_ID: deployment-test\n",
    )
    .unwrap();
    let identity_path = directory.join("runtime/instance/deployment-id");
    fs::create_dir_all(identity_path.parent().unwrap()).unwrap();
    fs::write(&identity_path, b"deployment-test\n").unwrap();
    let state_directory = directory.join("state");
    fs::create_dir_all(&state_directory).unwrap();

    let valid = task(TaskOperation::KeysValidate);
    assert!(
        validate_local_task_identity_at(&valid, &config_path, None, Some(&state_directory))
            .is_err()
    );
    let bootstrap = task(TaskOperation::MigrateApply);
    let expected =
        validate_local_task_identity_at(&bootstrap, &config_path, None, Some(&state_directory))
            .unwrap();
    persist_operator_state_identity(&state_directory, &expected).unwrap();
    validate_local_task_identity_at(&valid, &config_path, None, Some(&state_directory)).unwrap();

    let mut wrong = valid.clone();
    wrong.deployment_id = "deployment-other".to_owned();
    wrong.iss = "controller:deployment-other".to_owned();
    wrong.aud = "runtime:deployment-other".to_owned();
    assert!(
        validate_local_task_identity_at(&wrong, &config_path, None, Some(&state_directory))
            .is_err()
    );

    let state_identity_path = state_directory.join("deployment-id");
    fs::remove_file(&state_identity_path).unwrap();
    fs::write(&state_identity_path, b"deployment-other\n").unwrap();
    assert!(
        validate_local_task_identity_at(&valid, &config_path, None, Some(&state_directory))
            .is_err()
    );

    fs::remove_file(&state_identity_path).unwrap();
    fs::write(&state_identity_path, b"deployment-test\n").unwrap();
    fs::write(&identity_path, b"deployment-other\n").unwrap();
    assert!(
        validate_local_task_identity_at(&valid, &config_path, None, Some(&state_directory))
            .is_err()
    );

    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn local_deployment_identity_rejects_missing_or_malformed_bootstrap_sources() {
    let directory = temporary_directory();
    let config_path = directory.join("server.yaml");
    let valid = task(TaskOperation::KeysValidate);

    assert!(
        validate_local_task_identity_at(
            &valid,
            &config_path,
            None,
            Some(&directory.join("state")),
        )
        .unwrap_err()
        .to_string()
        .contains("failed to read server configuration")
    );

    fs::write(&config_path, b"- not-a-mapping\n").unwrap();
    assert!(
        validate_local_task_identity_at(
            &valid,
            &config_path,
            None,
            Some(&directory.join("state")),
        )
        .unwrap_err()
        .to_string()
        .contains("top-level key/value mapping")
    );

    fs::write(
        &config_path,
        b"DATA_DIR: runtime\nDEPLOYMENT_ID: deployment-test\n",
    )
    .unwrap();
    let explicit_identity = directory.join("explicit-deployment-id");
    assert!(
        validate_local_task_identity_at(
            &valid,
            &config_path,
            Some(&explicit_identity),
            Some(&directory.join("state")),
        )
        .unwrap_err()
        .to_string()
        .contains("configured persisted deployment identity is unavailable")
    );

    let persisted_identity = directory.join("runtime/instance/deployment-id");
    fs::create_dir_all(persisted_identity.parent().unwrap()).unwrap();
    fs::write(&persisted_identity, b"deployment-test\n").unwrap();
    let state_directory = directory.join("state");
    fs::create_dir_all(&state_directory).unwrap();
    assert!(
        validate_local_task_identity_at(&valid, &config_path, None, Some(&state_directory))
            .unwrap_err()
            .to_string()
            .contains("operator state deployment identity is unavailable")
    );

    fs::remove_file(&persisted_identity).unwrap();
    fs::write(&config_path, b"DATA_DIR: runtime\n").unwrap();
    let bootstrap = task(TaskOperation::MigrateApply);
    assert!(
        validate_local_task_identity_at(&bootstrap, &config_path, None, None)
            .unwrap_err()
            .to_string()
            .contains("no local deployment identity is available")
    );
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn local_deployment_identity_accepts_yaml_scalar_types_and_rejects_sequences() {
    let directory = temporary_directory();
    let config_path = directory.join("server.yaml");
    let bootstrap = task(TaskOperation::MigrateApply);

    fs::write(&config_path, b"DEPLOYMENT_ID: true\n").unwrap();
    assert!(validate_local_task_identity_at(&bootstrap, &config_path, None, None).is_err());
    fs::write(&config_path, b"DEPLOYMENT_ID: 42\n").unwrap();
    assert!(validate_local_task_identity_at(&bootstrap, &config_path, None, None).is_err());
    fs::write(
        &config_path,
        b"DATA_DIR: [runtime]\nDEPLOYMENT_ID: deployment-test\n",
    )
    .unwrap();
    assert!(
        validate_local_task_identity_at(&bootstrap, &config_path, None, None)
            .unwrap_err()
            .to_string()
            .contains("must be a scalar")
    );
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn operator_state_identity_is_immutable_after_first_publication() {
    let directory = temporary_directory();
    persist_operator_state_identity(&directory, "deployment-test").unwrap();
    persist_operator_state_identity(&directory, "deployment-test").unwrap();
    let error = persist_operator_state_identity(&directory, "deployment-other")
        .unwrap_err()
        .to_string();
    assert!(error.contains("changed unexpectedly"));
    assert_eq!(
        fs::read_to_string(directory.join("deployment-id"))
            .unwrap()
            .trim(),
        "deployment-test"
    );
    fs::remove_dir_all(directory).unwrap();
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
fn lifecycle_refuses_to_replay_an_unknown_executing_task() {
    let directory = temporary_directory();
    let request = directory.join("request.sha256");
    let lifecycle = directory.join("request.lifecycle.json");
    let receipt = directory.join("request.receipt.jws");
    let digest = "c".repeat(64);

    assert_eq!(
        load_or_prepare_lifecycle(&lifecycle, &digest).unwrap(),
        TaskLifecycle::Prepared {
            request_sha256: digest.clone()
        }
    );
    assert_eq!(
        claim_request(&request, &digest).unwrap(),
        RequestClaim::Created
    );
    assert_eq!(
        claim_request(&request, &digest).unwrap(),
        RequestClaim::Current
    );

    write_lifecycle_atomic(
        &lifecycle,
        &TaskLifecycle::Executing {
            request_sha256: digest.clone(),
        },
    )
    .unwrap();
    let restarted = load_or_prepare_lifecycle(&lifecycle, &digest).unwrap();
    assert!(matches!(&restarted, TaskLifecycle::Executing { .. }));

    // This models SIGKILL after the durable executing transition.  The
    // missing receipt is not evidence that the operation did not happen.
    assert!(!receipt.exists());
    let error = mark_task_executing(&lifecycle, &restarted, &digest).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("may have executed without a receipt")
    );
    assert!(matches!(
        read_lifecycle(&lifecycle).unwrap(),
        TaskLifecycle::Executing { .. }
    ));
    fs::write(receipt_temporary_path(&receipt), b"partial").unwrap();
    assert!(write_receipt_atomic(&receipt, b"complete.receipt.value").is_err());
    assert!(receipt_temporary_path(&receipt).exists());
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn lifecycle_claims_are_versioned_and_legacy_claims_fail_closed_without_a_receipt() {
    let directory = temporary_directory();
    let request = directory.join("request.sha256");
    let lifecycle = directory.join("request.lifecycle.json");
    let digest = "d".repeat(64);

    fs::write(&request, &digest).unwrap();
    assert_eq!(
        load_or_prepare_lifecycle(&lifecycle, &digest).unwrap(),
        TaskLifecycle::Prepared {
            request_sha256: digest.clone()
        }
    );
    let claim = claim_request(&request, &digest).unwrap();
    assert_eq!(claim, RequestClaim::Legacy);
    assert!(ensure_current_claim(claim).is_err());
    assert!(!directory.join("request.receipt.jws").exists());
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn incomplete_lifecycle_transition_is_never_deleted_or_recovered_implicitly() {
    let directory = temporary_directory();
    let lifecycle = directory.join("request.lifecycle.json");
    let temporary = lifecycle_temporary_path(&lifecycle);
    fs::write(&temporary, br#"{\"phase\":\"executing\"}"#).unwrap();

    assert!(load_or_prepare_lifecycle(&lifecycle, &"e".repeat(64)).is_err());
    assert!(
        write_lifecycle_atomic(
            &lifecycle,
            &TaskLifecycle::Prepared {
                request_sha256: "e".repeat(64),
            },
        )
        .is_err()
    );
    assert!(
        write_initial_lifecycle(
            &lifecycle,
            &TaskLifecycle::Prepared {
                request_sha256: "e".repeat(64),
            },
        )
        .is_err()
    );
    assert!(temporary.exists());
    assert!(ensure_real_state_directory(&directory.join("missing-state")).is_err());
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn equivalent_prepared_lifecycle_temporary_is_safe_to_clean_and_continue() {
    let directory = temporary_directory();
    let lifecycle = directory.join("request.lifecycle.json");
    let digest = "prepared".repeat(16);
    let prepared = TaskLifecycle::Prepared {
        request_sha256: digest.clone(),
    };
    write_initial_lifecycle(&lifecycle, &prepared).unwrap();
    fs::write(
        lifecycle_temporary_path(&lifecycle),
        serde_json::to_vec(&prepared).unwrap(),
    )
    .unwrap();

    assert_eq!(
        load_or_prepare_lifecycle(&lifecycle, &digest).unwrap(),
        prepared
    );
    assert!(!lifecycle_temporary_path(&lifecycle).exists());
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn prepared_lifecycle_temporary_without_published_record_is_recovered() {
    let directory = temporary_directory();
    let lifecycle = directory.join("request.lifecycle.json");
    let digest = "prepared-without-record".repeat(4);
    let prepared = TaskLifecycle::Prepared {
        request_sha256: digest.clone(),
    };
    fs::write(
        lifecycle_temporary_path(&lifecycle),
        serde_json::to_vec(&prepared).unwrap(),
    )
    .unwrap();

    assert_eq!(
        load_or_prepare_lifecycle(&lifecycle, &digest).unwrap(),
        prepared
    );
    assert!(lifecycle.exists());
    assert!(!lifecycle_temporary_path(&lifecycle).exists());
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn nonprepared_lifecycle_temporary_fails_closed_without_a_published_record() {
    let directory = temporary_directory();
    let lifecycle = directory.join("request.lifecycle.json");
    let temporary = lifecycle_temporary_path(&lifecycle);
    fs::write(
        &temporary,
        serde_json::to_vec(&TaskLifecycle::Executing {
            request_sha256: "executing".repeat(16),
        })
        .unwrap(),
    )
    .unwrap();

    let error = load_or_prepare_lifecycle(&lifecycle, &"executing".repeat(16))
        .unwrap_err()
        .to_string();
    assert!(error.contains("incomplete durable transition"));
    assert!(temporary.exists());
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn signed_receipts_are_recovered_and_bound_to_the_request() {
    let directory = temporary_directory();
    let receipt_key = SigningKey::from_bytes(&[11; 32]);
    let receipt_key_path = directory.join("receipt.key");
    fs::write(
        &receipt_key_path,
        URL_SAFE_NO_PAD.encode(receipt_key.to_bytes()),
    )
    .unwrap();
    let request = task(TaskOperation::KeysValidate);
    let digest = "r".repeat(64);
    let compact = sign_task_outcome(
        &request,
        &digest,
        TaskOutcome::Failed {
            code: "operation-failed-test".to_owned(),
        },
        "receipt-key",
        &receipt_key_path,
        10,
        11,
    )
    .unwrap();
    validate_receipt_for_task(
        &compact,
        &request,
        &digest,
        "deployment-test",
        "receipt-key",
        &receipt_key_path,
    )
    .unwrap();

    let mut wrong_request = request.clone();
    wrong_request.jti.push_str("-other");
    let error = validate_receipt_for_task(
        &compact,
        &wrong_request,
        &digest,
        "deployment-test",
        "receipt-key",
        &receipt_key_path,
    )
    .unwrap_err()
    .to_string();
    assert!(error.contains("not bound to this request"));
    assert!(
        validate_receipt_for_task(
            &compact,
            &request,
            &digest,
            "deployment-other",
            "receipt-key",
            &receipt_key_path,
        )
        .is_err()
    );

    let receipt_path = directory.join("request.receipt.jws");
    assert_eq!(
        read_published_receipt(
            &receipt_path,
            &request,
            &digest,
            "deployment-test",
            "receipt-key",
            &receipt_key_path,
        )
        .unwrap(),
        None
    );
    fs::write(&receipt_path, &compact).unwrap();
    assert_eq!(
        read_published_receipt(
            &receipt_path,
            &request,
            &digest,
            "deployment-test",
            "receipt-key",
            &receipt_key_path,
        )
        .unwrap(),
        Some(compact.clone())
    );

    fs::remove_file(&receipt_path).unwrap();
    fs::write(receipt_temporary_path(&receipt_path), &compact).unwrap();
    assert_eq!(
        recover_receipt_temporary(
            &receipt_path,
            &request,
            &digest,
            "deployment-test",
            "receipt-key",
            &receipt_key_path,
        )
        .unwrap(),
        Some(compact)
    );
    assert!(receipt_path.exists());
    assert!(!receipt_temporary_path(&receipt_path).exists());
    fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
async fn task_lock_acquisition_is_bounded() {
    let directory = temporary_directory();
    let path = directory.join("task.lock");
    let holder = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    holder.lock_exclusive().unwrap();
    let contender = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();

    let started = Instant::now();
    let error = acquire_task_lock_with_timeout(contender, Duration::from_millis(20))
        .await
        .expect_err("contended lock must time out");
    assert!(error.to_string().contains("timed out"), "{error:#}");
    assert!(started.elapsed() < Duration::from_secs(1));
    holder.unlock().unwrap();
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn only_migration_reenters_an_executing_lifecycle() {
    let digest = "reentry".repeat(16);
    let executing = TaskLifecycle::Executing {
        request_sha256: digest,
    };
    assert!(can_reenter_migration(
        &TaskOperation::MigrateApply,
        &executing
    ));
    assert!(!can_reenter_migration(
        &TaskOperation::KeysValidate,
        &executing
    ));
    assert!(!can_reenter_migration(
        &TaskOperation::MigrateApply,
        &TaskLifecycle::Prepared {
            request_sha256: "reentry".repeat(16),
        }
    ));
}

#[cfg(unix)]
#[test]
fn operator_state_paths_reject_symlink_roots_files_and_temporaries() {
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    let directory = temporary_directory();
    let real_state = directory.join("real-state");
    fs::create_dir(&real_state).unwrap();
    let linked_state = directory.join("linked-state");
    symlink(&real_state, &linked_state).unwrap();
    assert!(ensure_real_state_directory(&linked_state).is_err());

    let external = directory.join("external.json");
    fs::write(&external, b"{}").unwrap();
    let lifecycle = real_state.join("request.lifecycle.json");
    symlink(&external, &lifecycle).unwrap();
    assert!(load_or_prepare_lifecycle(&lifecycle, &"e".repeat(64)).is_err());
    fs::remove_file(&lifecycle).unwrap();

    let temporary = lifecycle_temporary_path(&lifecycle);
    symlink(directory.join("missing-target"), &temporary).unwrap();
    assert!(load_or_prepare_lifecycle(&lifecycle, &"e".repeat(64)).is_err());
    assert!(state_path_present(&temporary).unwrap());

    let lock = real_state.join("task.lock");
    symlink(&external, &lock).unwrap();
    assert!(regular_state_file_present(&lock, "operator task lock").is_err());

    let denied = directory.join("denied");
    fs::create_dir(&denied).unwrap();
    fs::set_permissions(&denied, fs::Permissions::from_mode(0o000)).unwrap();
    let denied_child = denied.join("state");
    assert!(regular_state_file_present(&denied_child, "denied state").is_err());
    assert!(state_path_present(&denied_child).is_err());
    fs::set_permissions(&denied, fs::Permissions::from_mode(0o700)).unwrap();
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn completed_lifecycle_without_its_receipt_is_also_non_replayable() {
    let directory = temporary_directory();
    let lifecycle = directory.join("request.lifecycle.json");
    let digest = "f".repeat(64);
    write_initial_lifecycle(
        &lifecycle,
        &TaskLifecycle::Completed {
            request_sha256: digest.clone(),
        },
    )
    .unwrap();

    let completed = load_or_prepare_lifecycle(&lifecycle, &digest).unwrap();
    assert!(load_or_prepare_lifecycle(&lifecycle, &"0".repeat(64)).is_err());
    assert!(
        write_initial_lifecycle(
            &lifecycle,
            &TaskLifecycle::Prepared {
                request_sha256: digest.clone(),
            },
        )
        .is_err()
    );
    assert!(!lifecycle_temporary_path(&lifecycle).exists());
    let error = mark_task_executing(&lifecycle, &completed, &digest).unwrap_err();
    assert!(error.to_string().contains("completed without a receipt"));
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn embedded_identity_and_operation_names_are_closed() {
    for (operation, expected) in [
        (TaskOperation::MigrateApply, "migrate-apply"),
        (
            TaskOperation::ConformanceLeaseCreate {
                profile: "oidf-full".to_owned(),
                material_sha256: "a".repeat(64),
                dynamic_registration_initial_access_token_sha256: None,
                ciba_automated_decision_token_sha256: None,
                public_material: None,
                ttl_seconds: 3_600,
            },
            "conformance-lease-create",
        ),
        (
            TaskOperation::ConformanceLeaseList,
            "conformance-lease-list",
        ),
        (
            TaskOperation::ConformanceLeaseRevoke {
                lease_id: "018f3f2a-7b55-7a25-8f20-6d526f8f44e1".to_owned(),
            },
            "conformance-lease-revoke",
        ),
        (
            TaskOperation::ConformanceLeaseCleanup,
            "conformance-lease-cleanup",
        ),
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
fn secret_binding_requires_the_local_revision_authority_and_rejects_rotation() {
    let directory = temporary_directory();
    let revision_path = directory.join("secret-revision");
    fs::write(&revision_path, b"secret-revision").unwrap();

    let valid = task(TaskOperation::KeysValidate);
    validate_secret_binding_at(&valid, &revision_path).unwrap();

    fs::write(&revision_path, b"rotated-revision").unwrap();
    let error = validate_secret_binding_at(&valid, &revision_path).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("secret revision binding mismatch")
    );

    let mut hmac = valid;
    hmac.config.secret_binding = SecretBinding::HmacSha256 {
        key_id: "provider-key".to_owned(),
        digest: "d".repeat(64),
    };
    let error = validate_secret_binding_at(&hmac, &revision_path).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("HMAC secret binding has no local provider")
    );

    fs::remove_dir_all(directory).unwrap();
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

#[tokio::test]
async fn conformance_operations_execute_through_the_closed_task_dispatch() {
    if std::env::var_os("DATABASE_URL").is_none() {
        if std::env::var_os("CI").is_some() {
            panic!("CI requires DATABASE_URL for conformance task dispatch coverage");
        }
        return;
    }

    let nonce = uuid::Uuid::now_v7().simple().to_string();
    let profile = format!("task-coverage-{nonce}");
    let material_sha256 = format!("{nonce}{nonce}");
    let created = execute(&TaskOperation::ConformanceLeaseCreate {
        profile: profile.clone(),
        material_sha256: material_sha256.clone(),
        dynamic_registration_initial_access_token_sha256: None,
        ciba_automated_decision_token_sha256: None,
        public_material: None,
        ttl_seconds: 60,
    })
    .await;
    let lease_id = match created {
        TaskOutcome::Succeeded {
            result: TaskResult::ConformanceLeaseCreated { lease },
        } => {
            assert_eq!(lease.profile, profile);
            assert_eq!(lease.material_sha256, material_sha256);
            lease.lease_id
        }
        other => panic!("unexpected create outcome: {other:?}"),
    };

    match execute(&TaskOperation::ConformanceLeaseList).await {
        TaskOutcome::Succeeded {
            result: TaskResult::ConformanceLeaseList { leases },
        } => assert!(leases.iter().any(|lease| lease.lease_id == lease_id)),
        other => panic!("unexpected list outcome: {other:?}"),
    }

    assert_eq!(
        execute(&TaskOperation::ConformanceLeaseRevoke {
            lease_id: lease_id.clone(),
        })
        .await,
        TaskOutcome::Succeeded {
            result: TaskResult::ConformanceLeaseRevoked {
                lease_id: lease_id.clone(),
                deactivated_clients: 0,
            },
        }
    );
    assert!(matches!(
        execute(&TaskOperation::ConformanceLeaseCleanup).await,
        TaskOutcome::Succeeded {
            result: TaskResult::ConformanceLeaseCleaned { .. }
        }
    ));
    assert!(matches!(
        execute(&TaskOperation::ConformanceLeaseRevoke {
            lease_id: "not-a-uuid".to_owned(),
        })
        .await,
        TaskOutcome::Failed { .. }
    ));
}

#[tokio::test]
async fn external_key_dispatch_rejects_unmounted_public_material() {
    let outcome = execute(&TaskOperation::KeysRegisterExternal {
        kid: "external-1".to_owned(),
        alg: "ES256".to_owned(),
        key_ref: "provider:key-1".to_owned(),
        public_jwk_sha256: "a".repeat(64),
    })
    .await;
    assert!(matches!(outcome, TaskOutcome::Failed { .. }));
}
