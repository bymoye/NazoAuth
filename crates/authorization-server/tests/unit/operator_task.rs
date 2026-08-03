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
