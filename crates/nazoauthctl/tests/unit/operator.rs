use std::{collections::BTreeMap, fs};

use serde_json::json;

use super::*;
use crate::{
    filesystem::PrivateTempDir,
    model::{Dependencies, Operator, Postgres, Runtime as RuntimeConfig, Ui, Valkey},
    runtime::Runtime,
};

fn keypair(directory: &Path, name: &str, seed: u8) -> (String, PathBuf, PathBuf) {
    let key = SigningKey::from_bytes(&[seed; 32]);
    let private = directory.join(format!("{name}.key"));
    let public = directory.join(format!("{name}.pub"));
    fs::write(&private, URL_SAFE_NO_PAD.encode(key.to_bytes())).unwrap();
    fs::write(
        &public,
        URL_SAFE_NO_PAD.encode(key.verifying_key().to_bytes()),
    )
    .unwrap();
    (format!("{name}-test"), private, public)
}

fn config(work: &PrivateTempDir) -> UpdateConfig {
    let operator = work.path().join("operator");
    let audit = work.path().join("audit");
    let state = work.path().join("state");
    fs::create_dir(&operator).unwrap();
    fs::create_dir(&audit).unwrap();
    fs::create_dir(&state).unwrap();
    let (controller_key_id, controller_private_key, controller_public_key) =
        keypair(&operator, "controller", 1);
    let (receipt_key_id, receipt_private_key, receipt_public_key) =
        keypair(&operator, "receipt", 2);
    let (audit_key_id, audit_private_key, audit_public_key) = keypair(&operator, "audit", 3);
    let (break_glass_key_id, break_glass_private_key, break_glass_public_key) =
        keypair(&operator, "break-glass", 4);
    let secret_revision_file = operator.join("secret-revision");
    fs::write(&secret_revision_file, "secret-test").unwrap();
    UpdateConfig {
        schema: 2,
        managed_install: true,
        install_profile: "baseline".to_owned(),
        repository: "nazozero/NazoAuth".to_owned(),
        updater_install_path: work.path().join("nazoauthctl"),
        backup_root: work.path().join("backups"),
        deployment_root: work.path().join("deployments"),
        operator: Operator {
            deployment_id: "deployment-test".to_owned(),
            controller_key_id,
            controller_private_key,
            controller_public_key,
            receipt_key_id,
            receipt_private_key,
            receipt_public_key,
            audit_key_id,
            audit_private_key,
            audit_public_key,
            break_glass_key_id,
            break_glass_private_key,
            break_glass_public_key,
            secret_revision_file,
            state_directory: state,
            audit_directory: audit,
            trust_state_file: operator.join("release-trust.json"),
        },
        dependencies: Dependencies::default(),
        runtime: RuntimeConfig {
            engine: "host".to_owned(),
            dependency_engine: String::new(),
            container_name: "nazoauth".to_owned(),
            network: "nazoauth".to_owned(),
            ip_address: String::new(),
            publish_address: String::new(),
            health_url: "http://127.0.0.1/ready".to_owned(),
            readiness_attempts: 1,
            readiness_interval_seconds: 0,
            public_discovery_url: "https://auth.example/.well-known/openid-configuration"
                .to_owned(),
            expected_issuer: "https://auth.example".to_owned(),
            mounts: Vec::new(),
            snapshot_paths: vec![work.path().join("keys")],
            environment: BTreeMap::new(),
            service_name: "nazoauth".to_owned(),
            service_user: "nazoauth".to_owned(),
            binary_path: work.path().join("nazoauth"),
            binary_releases: work.path().join("releases"),
            working_directory: work.path().to_owned(),
        },
        postgres: Postgres {
            container_name: "postgres".to_owned(),
            database: "oauth".to_owned(),
            user: "migrator".to_owned(),
            image: String::new(),
            validation_image: String::new(),
        },
        valkey: Valkey {
            container_name: "valkey".to_owned(),
            image: String::new(),
            rdb_path: "/data/dump.rdb".to_owned(),
            password_file: PathBuf::new(),
        },
        ui: Ui {
            releases_root: work.path().join("ui-releases"),
        },
    }
}

fn task_parts() -> (
    nazo_operator_protocol::TargetExpectation,
    EmbeddedIdentity,
    ConfigBinding,
    TaskOperation,
) {
    (
        nazo_operator_protocol::TargetExpectation::HostBinary {
            path: "/opt/nazoauth".to_owned(),
            sha256: "a".repeat(64),
        },
        EmbeddedIdentity {
            release: "v1.0.0".to_owned(),
            revision: "b".repeat(40),
            protocol: nazo_operator_protocol::PROTOCOL_VERSION,
            build_id: "build:test".to_owned(),
        },
        ConfigBinding {
            manifest_version: nazo_operator_protocol::CONFIG_MANIFEST_VERSION,
            config_sha256: "c".repeat(64),
            secret_binding: SecretBinding::OpaqueRevision {
                revision: "secret-test".to_owned(),
            },
        },
        TaskOperation::KeysValidate,
    )
}

#[test]
fn host_task_uses_transient_credentials_and_hides_unrelated_state() {
    let work = PrivateTempDir::new("host-task-command").unwrap();
    let mut config = config(&work);
    let app = work.path().join("app");
    let keys = app.join("keys");
    fs::create_dir_all(&keys).unwrap();
    config.runtime.snapshot_paths = vec![keys];
    config.runtime.working_directory = work.path().join("config");
    fs::create_dir(&config.runtime.working_directory).unwrap();
    let dependency_secrets = config.runtime.working_directory.join("secrets");
    fs::create_dir(&dependency_secrets).unwrap();
    config.dependencies.migration_database_url_file =
        dependency_secrets.join("database-migration-url");
    fs::write(
        &config.dependencies.migration_database_url_file,
        "postgresql://migration.invalid/db",
    )
    .unwrap();
    let binary = work.path().join("nazoauth");
    fs::write(&binary, b"test binary").unwrap();

    let prepared = Runtime::new(&config)
        .prepare_app_task(
            &binary.to_string_lossy(),
            &TaskOperation::MigrateApply,
            None,
            b"{}",
        )
        .unwrap();
    let joined = format!("{prepared:?}").replace("\\\\", "\\");

    assert!(joined.contains("--property=PrivateMounts=yes"));
    assert!(joined.contains("--property=LoadCredential=operator-receipt-key:"));
    assert!(joined.contains("--property=LoadCredential=migration-database-url:"));
    assert!(
        joined.contains(
            "--setenv=NAZOAUTH_OPERATOR_RECEIPT_PRIVATE_KEY_FILE=%d/operator-receipt-key"
        )
    );
    assert!(joined.contains("--setenv=DATABASE_URL_FILE=%d/migration-database-url"));
    assert!(joined.contains(&app.join("avatars").display().to_string()));
    assert!(joined.contains(&app.join("secrets").display().to_string()));
    assert!(joined.contains(&app.join("bootstrap").display().to_string()));
    assert!(!joined.contains("postgresql://migration.invalid/db"));
}

#[test]
fn pending_intent_reuses_jti_and_expired_uncommitted_intent_is_reissued() {
    let work = PrivateTempDir::new("nazoauth-intent-test").unwrap();
    let config = config(&work);
    let (target, embedded, binding, operation) = task_parts();
    let (first, compact, path) = load_or_issue_task(
        &config,
        target.clone(),
        embedded.clone(),
        binding.clone(),
        operation.clone(),
    )
    .unwrap();
    let (same, same_compact, _) = load_or_issue_task(
        &config,
        target.clone(),
        embedded.clone(),
        binding.clone(),
        operation.clone(),
    )
    .unwrap();
    assert_eq!(first.jti, same.jti);
    assert_eq!(compact, same_compact);

    let mut expired = first.clone();
    expired.iat = 1;
    expired.nbf = 1;
    expired.exp = 61;
    let key = read_signing_key(&config.operator.controller_private_key).unwrap();
    atomic_write(
        &path,
        sign_task(&expired, &config.operator.controller_key_id, &key)
            .unwrap()
            .as_bytes(),
        0o400,
    )
    .unwrap();
    let (reissued, _, _) =
        load_or_issue_task(&config, target, embedded, binding, operation).unwrap();
    assert_ne!(reissued.jti, expired.jti);
}

#[test]
fn stale_audit_head_repairs_forward_but_tampering_fails_closed() {
    let work = PrivateTempDir::new("nazoauth-audit-test").unwrap();
    let config = config(&work);
    let event = append_management_event(&config, "install", "v1.0.0", "backup").unwrap();
    atomic_write(
        &config.operator.audit_directory.join("management-head.json"),
        &serde_json::to_vec(&AuditHead {
            sequence: 0,
            sha256: "0".repeat(64),
        })
        .unwrap(),
        0o600,
    )
    .unwrap();
    verify_audit(&config).unwrap();
    let repaired: AuditHead = serde_json::from_slice(
        &fs::read(config.operator.audit_directory.join("management-head.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(repaired.sequence, 1);
    let mut compact = fs::read_to_string(&event).unwrap();
    compact.push('x');
    atomic_write(&event, compact.as_bytes(), 0o400).unwrap();
    assert!(verify_audit(&config).is_err());
}

#[test]
fn audit_show_document_is_closed_json_without_verifier_presentation() {
    let work = PrivateTempDir::new("nazoauth-audit-show-test").unwrap();
    let config = config(&work);
    let empty = serde_json::to_string(&audit_entries(&config, None).unwrap()).unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&empty).unwrap(),
        json!([])
    );

    append_management_event(&config, "install", "v1.0.0", "backup").unwrap();
    let document = serde_json::to_string(&audit_entries(&config, None).unwrap()).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&document).unwrap();
    assert_eq!(parsed.as_array().unwrap().len(), 1);
    assert_eq!(parsed[0]["kind"], json!("management-event"));
}

#[test]
fn management_event_request_id_is_idempotent_and_content_bound() {
    let work = PrivateTempDir::new("nazoauth-audit-idempotency-test").unwrap();
    let config = config(&work);
    let request_id = "update-0123456789abcdef0123456789abcdef-complete";
    let first = append_management_event_idempotent(
        &config,
        request_id,
        "update-completed",
        "v0.2.0",
        "schema-compatible",
    )
    .unwrap();
    let retry = append_management_event_idempotent(
        &config,
        request_id,
        "update-completed",
        "v0.2.0",
        "schema-compatible",
    )
    .unwrap();
    assert_eq!(first, retry);
    assert_eq!(
        fs::read_dir(config.operator.audit_directory.join("management"))
            .unwrap()
            .count(),
        1
    );
    assert!(
        append_management_event_idempotent(
            &config,
            request_id,
            "update-failed",
            "v0.2.0",
            "schema-compatible",
        )
        .is_err()
    );
}

#[test]
fn controller_and_audit_rotation_chain_survives_normal_and_break_glass_recovery() {
    let work = PrivateTempDir::new("nazoauth-rotation-test").unwrap();
    let config_path = work.path().join("update.json");
    let config = config(&work);
    fs::write(&config_path, serde_json::to_vec(&config).unwrap()).unwrap();
    append_management_event(&config, "install", "v1.0.0", "backup").unwrap();
    let first_controller = config.operator.controller_key_id.clone();
    let first_audit = config.operator.audit_key_id.clone();
    let first_break_glass = config.operator.break_glass_key_id.clone();
    rotate_controller(&config_path, &config, false, "normal").unwrap();
    let rotated: UpdateConfig = serde_json::from_slice(&fs::read(&config_path).unwrap()).unwrap();
    assert_ne!(rotated.operator.controller_key_id, first_controller);
    assert_ne!(rotated.operator.audit_key_id, first_audit);
    assert_eq!(rotated.operator.break_glass_key_id, first_break_glass);
    append_management_event(&rotated, "identity-rotated", "v1.0.0", "normal").unwrap();
    verify_audit(&rotated).unwrap();

    let second_controller = rotated.operator.controller_key_id.clone();
    let second_audit = rotated.operator.audit_key_id.clone();
    let second_break_glass = rotated.operator.break_glass_key_id.clone();
    rotate_controller(&config_path, &rotated, true, "stolen").unwrap();
    let mut recovered: UpdateConfig =
        serde_json::from_slice(&fs::read(&config_path).unwrap()).unwrap();
    assert_ne!(recovered.operator.controller_key_id, second_controller);
    assert_ne!(recovered.operator.break_glass_key_id, second_break_glass);
    verify_audit(&recovered).unwrap();
    let transition_files =
        fs::read_dir(recovered.operator.audit_directory.join("trust-transitions"))
            .unwrap()
            .count();
    assert_eq!(transition_files, 2);

    let mut transitions =
        fs::read_dir(recovered.operator.audit_directory.join("trust-transitions"))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
    transitions.sort_by_key(std::fs::DirEntry::file_name);
    let last = transitions.last().unwrap();
    let intent = RotationIntent {
        schema: 1,
        previous_key_id: second_controller,
        next_key_id: recovered.operator.controller_key_id.clone(),
        previous_audit_key_id: second_audit,
        next_audit_key_id: recovered.operator.audit_key_id.clone(),
        previous_break_glass_key_id: second_break_glass,
        next_break_glass_key_id: recovered.operator.break_glass_key_id.clone(),
        transition_file: last.file_name().to_string_lossy().into_owned(),
        compact_transition: fs::read_to_string(last.path()).unwrap(),
    };
    let intent_path = recovered
        .operator
        .controller_private_key
        .parent()
        .unwrap()
        .join("rotation-intent.json");
    fs::write(&intent_path, serde_json::to_vec(&intent).unwrap()).unwrap();
    recover_pending_rotation(&config_path, &mut recovered).unwrap();
    assert!(!intent_path.exists());
}

#[test]
fn operator_target_and_receipt_bindings_are_closed_over_every_claim() {
    let work = PrivateTempDir::new("nazoauth-operator-binding-test").unwrap();
    let config = config(&work);
    let (target, embedded, binding, operation) = task_parts();
    let (task, compact, _) = load_or_issue_task(
        &config,
        target.clone(),
        embedded.clone(),
        binding.clone(),
        operation,
    )
    .unwrap();
    let host_claim = RuntimeTargetClaim::HostBinary {
        path: "/opt/nazoauth".to_owned(),
        sha256: "a".repeat(64),
    };
    let expected = ExpectedReleaseTarget {
        embedded,
        image_digest: format!("sha256:{}", "d".repeat(64)),
        binary_digest: "a".repeat(64),
    };
    verify_target_expectation(&host_claim, &expected).unwrap();
    assert_eq!(target_expectation(&host_claim), target);

    let oci_claim = RuntimeTargetClaim::OciImage {
        image_ref: format!("ghcr.io/nazozero/nazoauth@sha256:{}", "d".repeat(64)),
        image_digest: format!("sha256:{}", "d".repeat(64)),
    };
    verify_target_expectation(&oci_claim, &expected).unwrap();
    assert!(matches!(
        target_expectation(&oci_claim),
        nazo_operator_protocol::TargetExpectation::OciImage { .. }
    ));

    let mut bad_expected = expected.clone();
    bad_expected.binary_digest = "b".repeat(64);
    assert!(verify_target_expectation(&host_claim, &bad_expected).is_err());
    bad_expected.image_digest = format!("sha256:{}", "e".repeat(64));
    assert!(verify_target_expectation(&oci_claim, &bad_expected).is_err());

    let mut receipt = RuntimeReceipt {
        ver: nazo_operator_protocol::PROTOCOL_VERSION,
        iss: format!("runtime:{}", task.deployment_id),
        aud: format!("controller:{}", task.deployment_id),
        jti: task.jti.clone(),
        request_sha256: compact_sha256(&compact),
        deployment_id: task.deployment_id.clone(),
        actor: task.actor.clone(),
        operation: operation_name(&task.operation).to_owned(),
        started_at: task.iat,
        completed_at: task.iat + 1,
        embedded: task.embedded.clone(),
        config: task.config.clone(),
        outcome: TaskOutcome::Succeeded {
            result: TaskResult::KeyValidation {
                keyset_revision: "test".to_owned(),
            },
        },
    };
    validate_runtime_receipt(&receipt, &task, &compact).unwrap();
    receipt.completed_at = receipt.started_at - 1;
    assert!(validate_runtime_receipt(&receipt, &task, &compact).is_err());
    receipt.completed_at = receipt.started_at + 1;
    receipt.request_sha256 = "0".repeat(64);
    assert!(validate_runtime_receipt(&receipt, &task, &compact).is_err());
}

#[test]
fn release_target_policy_and_operation_names_are_explicit() {
    let work = PrivateTempDir::new("nazoauth-expected-release-test").unwrap();
    let mut config = config(&work);
    let embedded = EmbeddedIdentity {
        release: "v0.2.0".to_owned(),
        revision: "a".repeat(40),
        protocol: nazo_operator_protocol::PROTOCOL_VERSION,
        build_id: "build:test".to_owned(),
    };
    expected_release_target(
        &config,
        embedded.clone(),
        format!("sha256:{}", "b".repeat(64)),
        "c".repeat(64),
    )
    .unwrap();

    assert!(
        expected_release_target(
            &config,
            EmbeddedIdentity {
                protocol: nazo_operator_protocol::PROTOCOL_VERSION + 1,
                ..embedded.clone()
            },
            String::new(),
            "c".repeat(64),
        )
        .is_err()
    );
    assert!(
        expected_release_target(&config, embedded.clone(), String::new(), "short".to_owned())
            .is_err()
    );
    config.runtime.engine = "podman".to_owned();
    expected_release_target(&config, embedded, "image".to_owned(), "short".to_owned()).unwrap();

    assert_eq!(
        operation_name(&TaskOperation::MigrateApply),
        "migrate-apply"
    );
    assert_eq!(operation_name(&TaskOperation::KeysList), "keys-list");
    assert_eq!(
        operation_name(&TaskOperation::KeysValidate),
        "keys-validate"
    );
    assert_eq!(
        operation_name(&TaskOperation::KeysGenerateLocal {
            alg: "ES256".to_owned(),
            purposes: vec!["signing".to_owned()],
        }),
        "keys-generate-local"
    );
    assert_eq!(
        operation_name(&TaskOperation::KeysRegisterExternal {
            kid: "external".to_owned(),
            alg: "ES256".to_owned(),
            key_ref: "provider:key".to_owned(),
            public_jwk_sha256: "d".repeat(64),
        }),
        "keys-register-external"
    );
}

#[test]
fn canonical_manifest_hashes_only_the_closed_non_secret_configuration() {
    let work = PrivateTempDir::new("nazoauth-canonical-config-test").unwrap();
    let mut config = config(&work);
    fs::create_dir_all(&config.runtime.working_directory).unwrap();
    let server_config = config.runtime.working_directory.join(".env.yaml");
    fs::write(&server_config, "issuer: https://auth.example\n").unwrap();
    let manifest = canonical_manifest(&config, &TaskOperation::MigrateApply).unwrap();
    assert_eq!(
        manifest.entries["server_config_sha256"],
        crate::filesystem::sha256(&server_config).unwrap()
    );
    assert_eq!(manifest.entries["operation"], "migrate-apply");
    assert_eq!(manifest.entries["deployment_id"], "deployment-test");

    config.runtime.engine = "podman".to_owned();
    config.runtime.mounts.clear();
    assert!(canonical_manifest(&config, &TaskOperation::KeysList).is_err());
    config.runtime.mounts.push(crate::model::Mount {
        source: server_config.clone(),
        target: "/app/.env.yaml".into(),
        mode: "ro".to_owned(),
    });
    assert_eq!(
        canonical_manifest(&config, &TaskOperation::KeysList)
            .unwrap()
            .entries["operation"],
        "keys-list"
    );
}

#[test]
fn key_and_audit_file_readers_reject_ambiguous_or_unsafe_input() {
    let work = PrivateTempDir::new("nazoauth-operator-reader-test").unwrap();
    let config = config(&work);
    assert!(audit_head(&config).unwrap().0 == 1);
    verify_audit(&config).unwrap();

    let invalid = work.path().join("invalid-key");
    fs::write(&invalid, "not-base64!").unwrap();
    assert!(read_key(&invalid).is_err());
    fs::write(&invalid, URL_SAFE_NO_PAD.encode([1_u8; 31])).unwrap();
    assert!(read_signing_key(&invalid).is_err());
    assert!(read_verifying_key(&invalid).is_err());

    let line = work.path().join("line");
    fs::write(&line, "one\ntwo").unwrap();
    assert!(read_single_line(&line).is_err());
    assert!(load_management_event(&config, "../escape.jws").is_err());
}

#[test]
fn nonempty_receipt_chain_and_public_audit_rendering_are_verified() {
    let work = PrivateTempDir::new("nazoauth-audit-receipt-test").unwrap();
    let config = config(&work);
    let (target, embedded, binding, operation) = task_parts();
    let (task, compact_task, _) =
        load_or_issue_task(&config, target, embedded, binding, operation).unwrap();
    let receipt = nazo_operator_protocol::FinalReceipt {
        ver: nazo_operator_protocol::PROTOCOL_VERSION,
        iss: task.iss.clone(),
        aud: "operator-audit".to_owned(),
        jti: task.jti.clone(),
        request_sha256: compact_sha256(&compact_task),
        deployment_id: task.deployment_id.clone(),
        actor: task.actor.clone(),
        operation: operation_name(&task.operation).to_owned(),
        completed_at: task.iat + 1,
        audit_sequence: 1,
        audit_previous_sha256: "0".repeat(64),
        controller_verified_target: RuntimeTargetClaim::HostBinary {
            path: "/opt/nazoauth".to_owned(),
            sha256: "a".repeat(64),
        },
        embedded: task.embedded,
        config: task.config,
        runtime_receipt_sha256: "d".repeat(64),
        outcome: TaskOutcome::Succeeded {
            result: TaskResult::KeyValidation {
                keyset_revision: "test".to_owned(),
            },
        },
    };
    let key = read_signing_key(&config.operator.audit_private_key).unwrap();
    let compact = sign_final_receipt(&receipt, &config.operator.audit_key_id, &key).unwrap();
    append_audit(&config, 1, &task.jti, &compact).unwrap();

    verify_audit(&config).unwrap();
    show_audit(&config, Some(&task.jti)).unwrap();
}

#[test]
fn duplicate_management_request_ids_fail_before_untrusted_files_are_parsed() {
    let work = PrivateTempDir::new("nazoauth-management-duplicate-test").unwrap();
    let config = config(&work);
    let directory = config.operator.audit_directory.join("management");
    fs::create_dir_all(&directory).unwrap();
    let request_id = "update-0123456789abcdef0123456789abcdef-complete";
    let key = read_signing_key(&config.operator.audit_private_key).unwrap();
    let event = |sequence, previous_sha256| ManagementAuditEvent {
        ver: nazo_operator_protocol::PROTOCOL_VERSION,
        deployment_id: config.operator.deployment_id.clone(),
        sequence,
        previous_sha256,
        request_id: request_id.to_owned(),
        issued_at: Utc::now().timestamp(),
        actor: Actor {
            kind: ActorKind::LocalRoot,
            id: "uid:0".to_owned(),
        },
        operation: "update-completed".to_owned(),
        release: "v0.2.0".to_owned(),
        recovery_boundary: "schema-compatible".to_owned(),
    };
    let first = sign_management_event(
        &event(1, "0".repeat(64)),
        &config.operator.audit_key_id,
        &key,
    )
    .unwrap();
    let second = sign_management_event(
        &event(2, compact_sha256(&first)),
        &config.operator.audit_key_id,
        &key,
    )
    .unwrap();
    fs::write(
        directory.join(format!("00000000000000000001-{request_id}.jws")),
        first.as_bytes(),
    )
    .unwrap();
    fs::write(
        directory.join(format!("00000000000000000002-{request_id}.jws")),
        second.as_bytes(),
    )
    .unwrap();
    fs::write(
        config.operator.audit_directory.join("management-head.json"),
        serde_json::to_vec(&AuditHead {
            sequence: 2,
            sha256: compact_sha256(&second),
        })
        .unwrap(),
    )
    .unwrap();

    let error = append_management_event_idempotent(
        &config,
        request_id,
        "update-completed",
        "v0.2.0",
        "schema-compatible",
    )
    .unwrap_err();
    assert!(error.to_string().contains("request id is not unique"));
}

#[test]
fn interrupted_rotation_activates_staged_controller_audit_and_break_glass_keys() {
    let work = PrivateTempDir::new("nazoauth-staged-rotation-test").unwrap();
    let config_path = work.path().join("update.json");
    let mut config = config(&work);
    fs::write(&config_path, serde_json::to_vec(&config).unwrap()).unwrap();
    let directory = config
        .operator
        .controller_private_key
        .parent()
        .unwrap()
        .to_owned();
    let write_staged = |private: &Path, public: &Path, seed: u8| {
        let key = SigningKey::from_bytes(&[seed; 32]);
        fs::write(private, URL_SAFE_NO_PAD.encode(key.to_bytes())).unwrap();
        fs::write(
            public,
            URL_SAFE_NO_PAD.encode(key.verifying_key().to_bytes()),
        )
        .unwrap();
    };
    write_staged(
        &directory.join("controller.next.key"),
        &directory.join("controller.next.pub"),
        5,
    );
    write_staged(
        &directory.join("audit.next.key"),
        &directory.join("audit.next.pub"),
        6,
    );
    write_staged(
        &config
            .operator
            .break_glass_private_key
            .with_file_name("break-glass.next.key"),
        &directory.join("break-glass.next.pub"),
        7,
    );
    let intent = RotationIntent {
        schema: 1,
        previous_key_id: config.operator.controller_key_id.clone(),
        next_key_id: "controller-next".to_owned(),
        previous_audit_key_id: config.operator.audit_key_id.clone(),
        next_audit_key_id: "audit-next".to_owned(),
        previous_break_glass_key_id: config.operator.break_glass_key_id.clone(),
        next_break_glass_key_id: "break-glass-next".to_owned(),
        transition_file: "staged-transition.jws".to_owned(),
        compact_transition: "staged-transition".to_owned(),
    };
    fs::write(
        directory.join("rotation-intent.json"),
        serde_json::to_vec(&intent).unwrap(),
    )
    .unwrap();

    recover_pending_rotation(&config_path, &mut config).unwrap();
    assert_eq!(config.operator.controller_key_id, "controller-next");
    assert_eq!(config.operator.audit_key_id, "audit-next");
    assert_eq!(config.operator.break_glass_key_id, "break-glass-next");
    assert!(!directory.join("rotation-intent.json").exists());
}
