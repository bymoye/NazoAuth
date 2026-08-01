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
    let digest = encode_hex(&Sha256::digest(key.verifying_key().to_bytes()));
    (format!("{name}-{}", &digest[..16]), private, public)
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
            active_identity_file: operator.join("active-generation.json"),
            identity_generations_directory: operator.join("generations"),
            recovery_generations_directory: work.path().join("recovery/generations"),
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

fn test_binary_path() -> String {
    std::env::temp_dir()
        .join("nazoauth")
        .to_string_lossy()
        .into_owned()
}

fn test_runtime_rejects_retired_controller(
    config: &UpdateConfig,
    probe: &str,
) -> anyhow::Result<RetirementProbeExecution> {
    let current = read_verifying_key(&config.operator.controller_public_key)?;
    if verify_task_signature(probe, &config.operator.controller_key_id, &current).is_ok() {
        anyhow::bail!("test runtime accepted retired controller")
    }
    Ok(RetirementProbeExecution {
        controller_verified_target: RuntimeTargetClaim::HostBinary {
            path: test_binary_path(),
            sha256: "a".repeat(64),
        },
        application_reported_embedded_identity: EmbeddedIdentity {
            release: "v0.1.5".to_owned(),
            revision: "b".repeat(40),
            protocol: nazo_operator_protocol::PROTOCOL_VERSION,
            build_id: "build:test".to_owned(),
        },
    })
}

#[test]
fn retirement_probe_audit_evidence_is_closed_and_target_bound() {
    let embedded = EmbeddedIdentity {
        release: "v0.1.9".to_owned(),
        revision: "b".repeat(40),
        protocol: nazo_operator_protocol::PROTOCOL_VERSION,
        build_id: "github:test".to_owned(),
    };
    for target in [
        RuntimeTargetClaim::HostBinary {
            path: test_binary_path(),
            sha256: "a".repeat(64),
        },
        RuntimeTargetClaim::OciImage {
            image_ref: "ghcr.io/nazozero/nazoauth:v0.1.9".to_owned(),
            image_digest: format!("sha256:{}", "c".repeat(64)),
        },
    ] {
        let encoded = encode_retirement_probe_audit_evidence(
            &RetirementProbeAuditEvidence::RuntimeAuthorizationRejected {
                schema: 1,
                previous_controller_key_id: "controller-previous".to_owned(),
                active_controller_key_id: "controller-active".to_owned(),
                probe_sha256: "d".repeat(64),
                controller_verified_target: target,
                application_reported_embedded_identity: embedded.clone(),
            },
        )
        .unwrap();
        validate_retirement_probe_audit_evidence(&encoded).unwrap();
    }

    let not_issued =
        encode_retirement_probe_audit_evidence(&RetirementProbeAuditEvidence::NotIssued {
            schema: 1,
            previous_controller_key_id: "controller-previous".to_owned(),
            previous_controller_public_sha256: "e".repeat(64),
            reason: "controller-private-unavailable".to_owned(),
        })
        .unwrap();
    validate_retirement_probe_audit_evidence(&not_issued).unwrap();

    for invalid in ["not-evidence", "evidence-v1.not-base64!", "evidence-v1.e30"] {
        assert!(validate_retirement_probe_audit_evidence(invalid).is_err());
    }

    for evidence in [
        RetirementProbeAuditEvidence::RuntimeAuthorizationRejected {
            schema: 2,
            previous_controller_key_id: "controller-previous".to_owned(),
            active_controller_key_id: "controller-active".to_owned(),
            probe_sha256: "d".repeat(64),
            controller_verified_target: RuntimeTargetClaim::HostBinary {
                path: test_binary_path(),
                sha256: "a".repeat(64),
            },
            application_reported_embedded_identity: embedded.clone(),
        },
        RetirementProbeAuditEvidence::RuntimeAuthorizationRejected {
            schema: 1,
            previous_controller_key_id: "controller-previous".to_owned(),
            active_controller_key_id: "controller-active".to_owned(),
            probe_sha256: "d".repeat(64),
            controller_verified_target: RuntimeTargetClaim::HostBinary {
                path: "relative/nazoauth".to_owned(),
                sha256: "a".repeat(64),
            },
            application_reported_embedded_identity: embedded.clone(),
        },
        RetirementProbeAuditEvidence::RuntimeAuthorizationRejected {
            schema: 1,
            previous_controller_key_id: "controller-previous".to_owned(),
            active_controller_key_id: "controller-active".to_owned(),
            probe_sha256: "d".repeat(64),
            controller_verified_target: RuntimeTargetClaim::OciImage {
                image_ref: String::new(),
                image_digest: format!("sha256:{}", "c".repeat(64)),
            },
            application_reported_embedded_identity: embedded,
        },
    ] {
        let encoded = encode_retirement_probe_audit_evidence(&evidence).unwrap();
        assert!(validate_retirement_probe_audit_evidence(&encoded).is_err());
    }

    let invalid_not_issued =
        encode_retirement_probe_audit_evidence(&RetirementProbeAuditEvidence::NotIssued {
            schema: 1,
            previous_controller_key_id: "controller-previous".to_owned(),
            previous_controller_public_sha256: "e".repeat(64),
            reason: "copied-key-status-unknown".to_owned(),
        })
        .unwrap();
    assert!(validate_retirement_probe_audit_evidence(&invalid_not_issued).is_err());
}

#[test]
fn static_identity_files_are_idempotent_and_fail_closed_on_partial_state() {
    let work = PrivateTempDir::new("operator-static-identity").unwrap();
    let identity = work.path().join("identity");
    fs::create_dir(&identity).unwrap();

    ensure_static_identity_files(&identity).unwrap();
    ensure_static_identity_files(&identity).unwrap();
    for name in [
        "deployment-id",
        "secret-revision",
        "receipt.key",
        "receipt.pub",
        "receipt.kid",
    ] {
        assert!(identity.join(name).is_file());
    }

    fs::remove_file(identity.join("receipt.pub")).unwrap();
    assert!(ensure_static_identity_files(&identity).is_err());

    let invalid = work.path().join("invalid-static");
    fs::create_dir(&invalid).unwrap();
    fs::write(invalid.join("deployment-id"), "x".repeat(129)).unwrap();
    assert!(ensure_static_identity_files(&invalid).is_err());

    let inconsistent = work.path().join("inconsistent-receipt");
    fs::create_dir(&inconsistent).unwrap();
    ensure_static_identity_files(&inconsistent).unwrap();
    let receipt_kid = inconsistent.join("receipt.kid");
    crate::filesystem::set_mode(&receipt_kid, 0o600).unwrap();
    fs::write(receipt_kid, "receipt-wrong").unwrap();
    assert!(ensure_static_identity_files(&inconsistent).is_err());
}

#[test]
fn identity_initialization_and_adoption_records_are_restart_closed() {
    let work = PrivateTempDir::new("operator-identity-initialization").unwrap();
    let operator = work.path().join("operator");
    let recovery = work.path().join("recovery");
    initialize_identity_generation(&operator, &recovery).unwrap();
    initialize_identity_generation(&operator, &recovery).unwrap();
    let active_file = operator.join("active-generation.json");
    assert!(read_active_identity(&active_file).is_ok());

    assert!(read_active_identity(&work.path().join("missing-active.json")).is_err());
    let non_regular = work.path().join("non-regular-active");
    fs::create_dir(&non_regular).unwrap();
    assert!(read_active_identity(&non_regular).is_err());

    let legacy_operator = work.path().join("legacy-operator");
    fs::create_dir(&legacy_operator).unwrap();
    fs::write(legacy_operator.join("controller.key"), b"ambiguous").unwrap();
    assert!(
        initialize_identity_generation(&legacy_operator, &work.path().join("legacy-recovery"))
            .is_err()
    );

    let adoption_work = PrivateTempDir::new("operator-adoption-record").unwrap();
    let config_path = adoption_work.path().join("update.json");
    let mut config = config(&adoption_work);
    fs::write(&config_path, serde_json::to_vec(&config).unwrap()).unwrap();
    recover_pending_rotation(&config_path, &mut config).unwrap();
    let layout = identity_layout(&config).unwrap();
    let active = read_active_identity(&layout.active_file).unwrap();
    let adoption_path = layout.operator_directory.join("legacy-adoption.json");
    let mut adoption = LegacyAdoptionIntent {
        schema: 2,
        generation: active.generation.clone(),
        controller_key_id: active.controller_key_id.clone(),
        audit_key_id: active.audit_key_id.clone(),
        break_glass_key_id: active.break_glass_key_id.clone(),
    };
    atomic_write(
        &adoption_path,
        &serde_json::to_vec_pretty(&adoption).unwrap(),
        0o600,
    )
    .unwrap();
    assert!(recover_pending_rotation(&config_path, &mut config).is_err());

    adoption.schema = 1;
    atomic_write(
        &adoption_path,
        &serde_json::to_vec_pretty(&adoption).unwrap(),
        0o600,
    )
    .unwrap();
    atomic_write(
        &layout.operator_directory.join("rotation-intent.json"),
        b"{}",
        0o600,
    )
    .unwrap();
    assert!(recover_pending_rotation(&config_path, &mut config).is_err());
}

#[test]
fn legacy_generation_boundaries_accept_only_the_expected_regular_tree() {
    let work = PrivateTempDir::new("operator-generation-boundaries").unwrap();
    let missing = work.path().join("missing");
    ensure_only_expected_generation(&missing, "generation-expected").unwrap();
    remove_allowlisted_generation_directory(&missing, &["controller.key"]).unwrap();

    let generations = work.path().join("generations");
    fs::create_dir(&generations).unwrap();
    fs::create_dir(generations.join("generation-expected")).unwrap();
    ensure_only_expected_generation(&generations, "generation-expected").unwrap();
    fs::write(generations.join("unexpected"), b"x").unwrap();
    assert!(ensure_only_expected_generation(&generations, "generation-expected").is_err());

    let not_directory = work.path().join("not-directory");
    fs::write(&not_directory, b"x").unwrap();
    assert!(ensure_only_expected_generation(&not_directory, "generation-expected").is_err());
    assert!(remove_allowlisted_generation_directory(&not_directory, &["controller.key"]).is_err());

    let removable = work.path().join("removable");
    fs::create_dir(&removable).unwrap();
    fs::write(removable.join("controller.key"), b"key").unwrap();
    fs::write(removable.join("controller.pub"), b"public").unwrap();
    remove_allowlisted_generation_directory(&removable, &["controller.key", "controller.pub"])
        .unwrap();
    assert!(!removable.exists());

    let unexpected = work.path().join("unexpected-entry");
    fs::create_dir(&unexpected).unwrap();
    fs::write(unexpected.join("controller.key"), b"key").unwrap();
    fs::write(unexpected.join("extra"), b"extra").unwrap();
    assert!(remove_allowlisted_generation_directory(&unexpected, &["controller.key"]).is_err());
    assert!(unexpected.join("extra").exists());
}

#[test]
fn legacy_adoption_rejects_ambiguous_state_and_removes_only_staged_identity() {
    let work = PrivateTempDir::new("operator-legacy-adoption-boundaries").unwrap();
    let value = config(&work);
    let layout = identity_layout(&value).unwrap();
    let intent_path = layout.operator_directory.join("legacy-adoption.json");
    let expected = LegacyAdoptionIntent {
        schema: 1,
        generation: "generation-expected".to_owned(),
        controller_key_id: value.operator.controller_key_id.clone(),
        audit_key_id: value.operator.audit_key_id.clone(),
        break_glass_key_id: value.operator.break_glass_key_id.clone(),
    };

    refuse_ambiguous_legacy_adoption(&value, &layout, &intent_path, &expected).unwrap();

    fs::create_dir_all(&layout.generations).unwrap();
    fs::write(layout.generations.join("orphan"), b"unexpected").unwrap();
    assert!(refuse_ambiguous_legacy_adoption(&value, &layout, &intent_path, &expected).is_err());
    fs::remove_file(layout.generations.join("orphan")).unwrap();

    fs::create_dir(layout.generations.join(&expected.generation)).unwrap();
    fs::create_dir_all(layout.recovery_generations.join(&expected.generation)).unwrap();
    fs::write(&intent_path, serde_json::to_vec(&expected).unwrap()).unwrap();
    refuse_ambiguous_legacy_adoption(&value, &layout, &intent_path, &expected).unwrap();

    let conflicting = LegacyAdoptionIntent {
        generation: "generation-conflicting".to_owned(),
        ..expected
    };
    assert!(refuse_ambiguous_legacy_adoption(&value, &layout, &intent_path, &conflicting).is_err());

    fs::write(
        layout.operator_directory.join("rotation-intent.json"),
        b"pending",
    )
    .unwrap();
    assert!(refuse_ambiguous_legacy_adoption(&value, &layout, &intent_path, &conflicting).is_err());
}

#[test]
fn staged_identity_cleanup_and_controller_availability_match_managed_files() {
    let work = PrivateTempDir::new("operator-staged-identity-cleanup").unwrap();
    let value = config(&work);
    let layout = identity_layout(&value).unwrap();
    let controller = read_signing_key(&value.operator.controller_private_key).unwrap();
    let audit = read_signing_key(&value.operator.audit_private_key).unwrap();
    let break_glass = read_signing_key(&value.operator.break_glass_private_key).unwrap();
    let active = new_active_identity(&controller, &audit, &break_glass);

    write_generation(&layout, &active, &controller, &audit, &break_glass).unwrap();
    let (generation, recovery_generation) = generation_paths(&layout, &active);
    remove_uncommitted_generation(&layout, &active).unwrap();
    assert!(!generation.exists());
    assert!(!recovery_generation.exists());

    assert!(report_controller_availability(&value).unwrap());
    fs::write(&value.operator.controller_public_key, b"invalid").unwrap();
    assert!(!report_controller_availability(&value).unwrap());
}

fn task_parts() -> (
    nazo_operator_protocol::TargetExpectation,
    EmbeddedIdentity,
    ConfigBinding,
    TaskOperation,
) {
    (
        nazo_operator_protocol::TargetExpectation::HostBinary {
            path: test_binary_path(),
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
fn pending_intent_reuses_jti_and_only_unobserved_expired_intent_is_reissued() {
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
    let (reissued, _, _) = load_or_issue_task(
        &config,
        target.clone(),
        embedded.clone(),
        binding.clone(),
        operation.clone(),
    )
    .unwrap();
    assert_ne!(reissued.jti, expired.jti);

    let mut observed = reissued.clone();
    observed.iat = 1;
    observed.nbf = 1;
    observed.exp = 61;
    atomic_write(
        &path,
        sign_task(&observed, &config.operator.controller_key_id, &key)
            .unwrap()
            .as_bytes(),
        0o400,
    )
    .unwrap();
    fs::create_dir_all(&config.operator.state_directory).unwrap();
    fs::write(
        config
            .operator
            .state_directory
            .join(format!("{}.request.sha256", observed.jti)),
        b"runtime-observed",
    )
    .unwrap();
    let (preserved, preserved_compact, _) =
        load_or_issue_task(&config, target, embedded, binding, operation).unwrap();
    assert_eq!(preserved.jti, observed.jti);
    assert_eq!(
        verify_task_signature(
            &preserved_compact,
            &config.operator.controller_key_id,
            &key.verifying_key(),
        )
        .unwrap(),
        observed
    );
}

#[cfg(unix)]
#[test]
fn persisted_operator_intent_symlink_fails_closed() {
    use std::os::unix::fs::symlink;

    let work = PrivateTempDir::new("nazoauth-intent-symlink-test").unwrap();
    let config = config(&work);
    let (target, embedded, binding, operation) = task_parts();
    let (_, compact, path) = load_or_issue_task(
        &config,
        target.clone(),
        embedded.clone(),
        binding.clone(),
        operation.clone(),
    )
    .unwrap();
    fs::remove_file(&path).unwrap();
    let external = work.path().join("external-intent.jws");
    fs::write(&external, compact).unwrap();
    symlink(&external, &path).unwrap();

    assert!(load_or_issue_task(&config, target, embedded, binding, operation).is_err());
    assert!(path.symlink_metadata().unwrap().file_type().is_symlink());
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
fn missing_audit_directories_with_residual_heads_fail_closed() {
    let work = PrivateTempDir::new("nazoauth-audit-truncation-test").unwrap();
    let config = config(&work);
    let receipts = config.operator.audit_directory.join("receipts");
    fs::create_dir(&receipts).unwrap();
    atomic_write(
        &config.operator.audit_directory.join("head.json"),
        &serde_json::to_vec(&AuditHead {
            sequence: 1,
            sha256: "a".repeat(64),
        })
        .unwrap(),
        0o600,
    )
    .unwrap();
    fs::remove_dir(&receipts).unwrap();
    assert!(verify_audit(&config).is_err());

    fs::remove_file(config.operator.audit_directory.join("head.json")).unwrap();
    let management = config.operator.audit_directory.join("management");
    fs::create_dir(&management).unwrap();
    atomic_write(
        &config.operator.audit_directory.join("management-head.json"),
        &serde_json::to_vec(&AuditHead {
            sequence: 1,
            sha256: "b".repeat(64),
        })
        .unwrap(),
        0o600,
    )
    .unwrap();
    fs::remove_dir(&management).unwrap();
    assert!(verify_audit(&config).is_err());
}

#[test]
fn broken_audit_preflight_blocks_runtime_preparation() {
    let work = PrivateTempDir::new("nazoauth-audit-preflight-test").unwrap();
    let config = config(&work);
    atomic_write(
        &config.operator.audit_directory.join("head.json"),
        &serde_json::to_vec(&AuditHead {
            sequence: 1,
            sha256: "a".repeat(64),
        })
        .unwrap(),
        0o600,
    )
    .unwrap();
    let expected = ExpectedReleaseTarget {
        embedded: EmbeddedIdentity {
            release: "v0.1.6".to_owned(),
            revision: "f".repeat(40),
            protocol: nazo_operator_protocol::PROTOCOL_VERSION,
            build_id: "build:audit-preflight".to_owned(),
        },
        image_digest: format!("sha256:{}", "d".repeat(64)),
        binary_digest: "b".repeat(64),
    };
    let error = execute(
        &config,
        "/definitely/missing/nazoauth",
        &expected,
        TaskOperation::KeysValidate,
        None,
    )
    .unwrap_err();
    assert!(format!("{error:#}").contains("operator audit preflight failed"));
    assert!(!config.operator.audit_directory.join("intents").exists());
}

#[test]
fn audit_heads_without_receipt_directories_do_not_auto_heal() {
    let work = PrivateTempDir::new("nazoauth-audit-head-residue-test").unwrap();
    let config = config(&work);
    atomic_write(
        &config.operator.audit_directory.join("head.json"),
        &serde_json::to_vec(&AuditHead {
            sequence: 0,
            sha256: "0".repeat(64),
        })
        .unwrap(),
        0o600,
    )
    .unwrap();
    assert!(verify_audit(&config).is_err());

    fs::remove_file(config.operator.audit_directory.join("head.json")).unwrap();
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
    assert!(verify_audit(&config).is_err());
}

#[test]
fn truly_empty_audit_state_verifies_without_creating_heads() {
    let work = PrivateTempDir::new("nazoauth-empty-audit-test").unwrap();
    let config = config(&work);
    verify_audit(&config).unwrap();
    assert!(!config.operator.audit_directory.join("receipts").exists());
    assert!(!config.operator.audit_directory.join("head.json").exists());
    assert!(!config.operator.audit_directory.join("management").exists());
    assert!(
        !config
            .operator
            .audit_directory
            .join("management-head.json")
            .exists()
    );
}

#[test]
fn audit_directories_must_be_real_directories() {
    let work = PrivateTempDir::new("nazoauth-audit-directory-type-test").unwrap();
    let receipt_config = config(&work);
    fs::write(
        receipt_config.operator.audit_directory.join("receipts"),
        b"not a directory",
    )
    .unwrap();
    assert!(verify_audit(&receipt_config).is_err());

    let work = PrivateTempDir::new("nazoauth-management-directory-type-test").unwrap();
    let management_config = config(&work);
    fs::write(
        management_config
            .operator
            .audit_directory
            .join("management"),
        b"not a directory",
    )
    .unwrap();
    assert!(verify_audit(&management_config).is_err());
}

#[cfg(unix)]
#[test]
fn audit_directory_symlinks_fail_closed() {
    use std::os::unix::fs::symlink;

    let work = PrivateTempDir::new("nazoauth-audit-valid-symlink-test").unwrap();
    let receipt_config = config(&work);
    let target = work.path().join("audit-receipt-target");
    fs::create_dir(&target).unwrap();
    symlink(
        &target,
        receipt_config.operator.audit_directory.join("receipts"),
    )
    .unwrap();
    assert!(verify_audit(&receipt_config).is_err());

    let work = PrivateTempDir::new("nazoauth-management-dangling-symlink-test").unwrap();
    let management_config = config(&work);
    symlink(
        work.path().join("missing-management-target"),
        management_config
            .operator
            .audit_directory
            .join("management"),
    )
    .unwrap();
    assert!(verify_audit(&management_config).is_err());
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
    let mut config = config(&work);
    fs::write(&config_path, serde_json::to_vec(&config).unwrap()).unwrap();
    recover_pending_rotation(&config_path, &mut config).unwrap();
    append_management_event(&config, "install", "v1.0.0", "backup").unwrap();
    let first_controller = config.operator.controller_key_id.clone();
    let first_audit = config.operator.audit_key_id.clone();
    let first_break_glass = config.operator.break_glass_key_id.clone();
    rotate_controller(&config_path, &config, false, "normal").unwrap();
    let rotated: UpdateConfig = serde_json::from_slice(&fs::read(&config_path).unwrap()).unwrap();
    assert_ne!(rotated.operator.controller_key_id, first_controller);
    assert_ne!(rotated.operator.audit_key_id, first_audit);
    assert_ne!(rotated.operator.break_glass_key_id, first_break_glass);
    append_management_event(&rotated, "identity-rotated", "v1.0.0", "normal").unwrap();
    verify_audit(&rotated).unwrap();

    let second_controller = rotated.operator.controller_key_id.clone();
    let second_audit = rotated.operator.audit_key_id.clone();
    let second_break_glass = rotated.operator.break_glass_key_id.clone();
    recover_controller_without_controller_key(&config_path, &rotated, "stolen").unwrap();
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
        next_generation: recovered
            .operator
            .controller_private_key
            .parent()
            .unwrap()
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned(),
        previous_key_id: second_controller,
        next_key_id: recovered.operator.controller_key_id.clone(),
        previous_audit_key_id: second_audit,
        next_audit_key_id: recovered.operator.audit_key_id.clone(),
        previous_break_glass_key_id: second_break_glass,
        next_break_glass_key_id: recovered.operator.break_glass_key_id.clone(),
        transition_file: last.file_name().to_string_lossy().into_owned(),
        compact_transition: fs::read_to_string(last.path()).unwrap(),
    };
    let intent_path = identity_layout(&recovered)
        .unwrap()
        .operator_directory
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
        path: test_binary_path(),
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
            path: test_binary_path(),
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
fn interrupted_rotation_activates_one_complete_staged_generation() {
    let work = PrivateTempDir::new("nazoauth-staged-rotation-test").unwrap();
    let config_path = work.path().join("update.json");
    let mut config = config(&work);
    fs::write(&config_path, serde_json::to_vec(&config).unwrap()).unwrap();
    recover_pending_rotation(&config_path, &mut config).unwrap();
    let layout = identity_layout(&config).unwrap();
    let controller = SigningKey::from_bytes(&[5; 32]);
    let audit = SigningKey::from_bytes(&[6; 32]);
    let break_glass = SigningKey::from_bytes(&[7; 32]);
    let next = new_active_identity(&controller, &audit, &break_glass);
    write_generation(&layout, &next, &controller, &audit, &break_glass).unwrap();
    let transition = ControllerTrustTransition {
        ver: nazo_operator_protocol::PROTOCOL_VERSION,
        deployment_id: config.operator.deployment_id.clone(),
        issued_at: Utc::now().timestamp(),
        authorization: TransitionAuthorization::Controller,
        previous_key_id: config.operator.controller_key_id.clone(),
        next_key_id: next.controller_key_id.clone(),
        next_public_key_sha256: encode_hex(&Sha256::digest(controller.verifying_key().to_bytes())),
        previous_audit_key_id: config.operator.audit_key_id.clone(),
        next_audit_key_id: next.audit_key_id.clone(),
        next_audit_public_key_sha256: encode_hex(&Sha256::digest(audit.verifying_key().to_bytes())),
        previous_break_glass_key_id: config.operator.break_glass_key_id.clone(),
        next_break_glass_key_id: next.break_glass_key_id.clone(),
        next_break_glass_public_key_sha256: encode_hex(&Sha256::digest(
            break_glass.verifying_key().to_bytes(),
        )),
        reason: "normal".to_owned(),
    };
    let current_controller = read_signing_key(&config.operator.controller_private_key).unwrap();
    let compact_transition = sign_trust_transition(
        &transition,
        &config.operator.controller_key_id,
        &current_controller,
    )
    .unwrap();
    let intent = RotationIntent {
        schema: 1,
        next_generation: next.generation.clone(),
        previous_key_id: config.operator.controller_key_id.clone(),
        next_key_id: next.controller_key_id.clone(),
        previous_audit_key_id: config.operator.audit_key_id.clone(),
        next_audit_key_id: next.audit_key_id.clone(),
        previous_break_glass_key_id: config.operator.break_glass_key_id.clone(),
        next_break_glass_key_id: next.break_glass_key_id.clone(),
        transition_file: "staged-transition.jws".to_owned(),
        compact_transition,
    };
    fs::write(
        layout.operator_directory.join("rotation-intent.json"),
        serde_json::to_vec(&intent).unwrap(),
    )
    .unwrap();
    assert!(identity_recovery_required(&config).unwrap());

    recover_pending_rotation(&config_path, &mut config).unwrap();
    assert!(!identity_recovery_required(&config).unwrap());
    assert_eq!(config.operator.controller_key_id, next.controller_key_id);
    assert_eq!(config.operator.audit_key_id, next.audit_key_id);
    assert_eq!(config.operator.break_glass_key_id, next.break_glass_key_id);
    assert!(
        !layout
            .operator_directory
            .join("rotation-intent.json")
            .exists()
    );
}

#[test]
fn retired_controller_probe_is_rejected_and_audited_after_rotation() {
    let work = PrivateTempDir::new("nazoauth-retirement-probe-test").unwrap();
    let config_path = work.path().join("update.json");
    let mut config = config(&work);
    fs::write(&config_path, serde_json::to_vec(&config).unwrap()).unwrap();
    recover_pending_rotation(&config_path, &mut config).unwrap();
    let rotation = rotate_controller(&config_path, &config, false, "normal").unwrap();
    let mut current: UpdateConfig =
        serde_json::from_slice(&fs::read(&config_path).unwrap()).unwrap();
    recover_pending_rotation(&config_path, &mut current).unwrap();
    current.dependencies.migration_database_url_file =
        work.path().join("secrets/migration-database-url");
    fs::write(
        current.runtime.working_directory.join(".env.yaml"),
        "server: {}\n",
    )
    .unwrap();
    fs::write(&current.runtime.binary_path, b"not-the-signed-release").unwrap();
    let expected = ExpectedReleaseTarget {
        embedded: EmbeddedIdentity {
            release: "v0.1.5".to_owned(),
            revision: "b".repeat(40),
            protocol: nazo_operator_protocol::PROTOCOL_VERSION,
            build_id: "build:test".to_owned(),
        },
        image_digest: format!("sha256:{}", "d".repeat(64)),
        binary_digest: "a".repeat(64),
    };
    let error = verify_retired_controller_probe(&current, &rotation, "v0.1.5", &expected)
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("actual host binary digest does not match the signed Release manifest"),
        "{error}"
    );
    verify_retired_controller_probe_with(&current, &rotation, "v0.1.5", |probe| {
        test_runtime_rejects_retired_controller(&current, probe)
    })
    .unwrap();
    verify_audit(&current).unwrap();
    let entries = audit_entries(&current, None).unwrap();
    assert!(entries.iter().any(|entry| {
        entry["kind"] == json!("management-event")
            && entry["event"]["operation"] == json!("controller-retirement-probe")
    }));
}

#[test]
fn controller_loss_rehearsal_rotates_with_controller_signing_forbidden_and_probes_retirement() {
    let work = PrivateTempDir::new("nazoauth-controller-loss-rehearsal-test").unwrap();
    let config_path = work.path().join("update.json");
    let mut config = config(&work);
    fs::write(&config_path, serde_json::to_vec(&config).unwrap()).unwrap();
    recover_pending_rotation(&config_path, &mut config).unwrap();
    let previous = config.operator.controller_key_id.clone();

    let rotation = rehearse_controller_loss(&config_path, &config).unwrap();
    let mut current: UpdateConfig =
        serde_json::from_slice(&fs::read(&config_path).unwrap()).unwrap();
    recover_pending_rotation(&config_path, &mut current).unwrap();
    assert_ne!(current.operator.controller_key_id, previous);
    assert!(rotation.retirement_probe.is_some());
    verify_retired_controller_probe_with(&current, &rotation, "v0.1.5", |probe| {
        test_runtime_rejects_retired_controller(&current, probe)
    })
    .unwrap();
    verify_audit(&current).unwrap();
}

#[test]
fn controller_loss_recovery_does_not_require_the_controller_private_key() {
    let work = PrivateTempDir::new("nazoauth-controller-loss-recovery-test").unwrap();
    let config_path = work.path().join("update.json");
    let mut config = config(&work);
    fs::write(&config_path, serde_json::to_vec(&config).unwrap()).unwrap();
    recover_pending_rotation(&config_path, &mut config).unwrap();
    fs::remove_file(&config.operator.controller_private_key).unwrap();

    let rotation =
        recover_controller_without_controller_key(&config_path, &config, "lost").unwrap();
    assert!(rotation.retirement_probe.is_none());
    let mut current: UpdateConfig =
        serde_json::from_slice(&fs::read(&config_path).unwrap()).unwrap();
    recover_pending_rotation(&config_path, &mut current).unwrap();
    verify_retired_controller_probe_with(&current, &rotation, "v0.1.5", |probe| {
        test_runtime_rejects_retired_controller(&current, probe)
    })
    .unwrap();
    verify_audit(&current).unwrap();
}

#[test]
fn active_pointer_recovers_a_stale_config_without_multiple_active_private_generations() {
    let work = PrivateTempDir::new("nazoauth-active-pointer-recovery-test").unwrap();
    let config_path = work.path().join("update.json");
    let mut config = config(&work);
    fs::write(&config_path, serde_json::to_vec(&config).unwrap()).unwrap();
    recover_pending_rotation(&config_path, &mut config).unwrap();
    let layout = identity_layout(&config).unwrap();
    let previous_generation = read_active_identity(&layout.active_file)
        .unwrap()
        .generation;
    let controller = SigningKey::from_bytes(&[21; 32]);
    let audit = SigningKey::from_bytes(&[22; 32]);
    let break_glass = SigningKey::from_bytes(&[23; 32]);
    let next = new_active_identity(&controller, &audit, &break_glass);
    write_generation(&layout, &next, &controller, &audit, &break_glass).unwrap();
    write_active_identity(&layout, &next).unwrap();

    // This models SIGKILL after the sole active-pointer commit and before the
    // compatibility mirror in update.json is rewritten.
    recover_pending_rotation(&config_path, &mut config).unwrap();
    assert_eq!(config.operator.controller_key_id, next.controller_key_id);
    assert_eq!(config.operator.audit_key_id, next.audit_key_id);
    assert_eq!(config.operator.break_glass_key_id, next.break_glass_key_id);
    assert!(
        !layout
            .generations
            .join(&previous_generation)
            .join("controller.key")
            .exists()
    );
    assert!(
        !layout
            .recovery_generations
            .join(&previous_generation)
            .join("break-glass.key")
            .exists()
    );
}

#[test]
fn restart_discards_uncommitted_partial_generation_without_touching_active_identity() {
    let work = PrivateTempDir::new("nazoauth-partial-generation-recovery-test").unwrap();
    let config_path = work.path().join("update.json");
    let mut config = config(&work);
    fs::write(&config_path, serde_json::to_vec(&config).unwrap()).unwrap();
    recover_pending_rotation(&config_path, &mut config).unwrap();
    let layout = identity_layout(&config).unwrap();
    let abandoned = layout.generations.join("generation-abandoned");
    fs::create_dir_all(&abandoned).unwrap();
    fs::write(abandoned.join("controller.key"), b"partial").unwrap();
    let active_before = read_active_identity(&layout.active_file).unwrap();
    assert!(identity_recovery_required(&config).unwrap());

    recover_pending_rotation(&config_path, &mut config).unwrap();
    assert!(!identity_recovery_required(&config).unwrap());

    assert_eq!(
        read_active_identity(&layout.active_file)
            .unwrap()
            .generation,
        active_before.generation
    );
    assert!(!abandoned.join("controller.key").exists());
}

#[test]
fn fresh_identity_initialization_retires_precommit_private_material() {
    let work = PrivateTempDir::new("nazoauth-fresh-identity-kill-window-test").unwrap();
    let operator = work.path().join("operator");
    let recovery = work.path().join("recovery");
    let abandoned = operator.join("generations/generation-abandoned");
    let abandoned_recovery = recovery.join("generations/generation-abandoned");
    fs::create_dir_all(&abandoned).unwrap();
    fs::create_dir_all(&abandoned_recovery).unwrap();
    fs::write(abandoned.join("controller.key"), b"partial").unwrap();
    fs::write(abandoned_recovery.join("break-glass.key"), b"partial").unwrap();
    fs::write(operator.join("receipt.key"), b"partial").unwrap();

    initialize_identity_generation(&operator, &recovery).unwrap();

    let layout = IdentityLayout {
        operator_directory: operator.clone(),
        active_file: operator.join("active-generation.json"),
        generations: operator.join("generations"),
        recovery_generations: recovery.join("generations"),
    };
    let active = read_active_identity(&layout.active_file).unwrap();
    validate_generation(&layout, &active).unwrap();
    assert!(!abandoned.join("controller.key").exists());
    assert!(!abandoned_recovery.join("break-glass.key").exists());
    assert!(operator.join("receipt.key").is_file());
}

#[test]
fn missing_active_pointer_with_rotation_history_fails_closed() {
    let work = PrivateTempDir::new("nazoauth-missing-active-pointer-test").unwrap();
    let config_path = work.path().join("update.json");
    let mut config = config(&work);
    fs::write(&config_path, serde_json::to_vec(&config).unwrap()).unwrap();
    recover_pending_rotation(&config_path, &mut config).unwrap();
    rotate_controller(&config_path, &config, false, "normal").unwrap();
    let mut current: UpdateConfig =
        serde_json::from_slice(&fs::read(&config_path).unwrap()).unwrap();
    fs::remove_file(&current.operator.active_identity_file).unwrap();

    let error = recover_pending_rotation(&config_path, &mut current).unwrap_err();
    assert!(error.to_string().contains("ambiguous rotation state"));
}

#[cfg(unix)]
#[test]
fn generation_cleanup_refuses_symlink_escape() {
    use std::os::unix::fs::symlink;

    let work = PrivateTempDir::new("nazoauth-generation-symlink-test").unwrap();
    let config_path = work.path().join("update.json");
    let mut config = config(&work);
    fs::write(&config_path, serde_json::to_vec(&config).unwrap()).unwrap();
    recover_pending_rotation(&config_path, &mut config).unwrap();
    let layout = identity_layout(&config).unwrap();
    let outside = work.path().join("outside");
    fs::create_dir(&outside).unwrap();
    fs::write(outside.join("controller.key"), b"must-survive").unwrap();
    symlink(&outside, layout.generations.join("generation-escape")).unwrap();

    let error = recover_pending_rotation(&config_path, &mut config).unwrap_err();
    assert!(error.to_string().contains("unsafe entry"));
    assert_eq!(
        fs::read(outside.join("controller.key")).unwrap(),
        b"must-survive"
    );
}
