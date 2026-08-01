use std::{collections::BTreeMap, fs, path::PathBuf};

use super::*;
use crate::{
    filesystem::PrivateTempDir,
    model::{
        Artifact, DatabaseRestore, Dependencies, FrontendRelease, OciRelease, Operator, Postgres,
        Rollback, Runtime as RuntimeConfig, Ui, Valkey,
    },
};

fn manifest(version: &str, revision: char) -> ReleaseManifest {
    let target = crate::model::release_target().unwrap().to_owned();
    let suffix = if target.contains("windows") {
        ".exe"
    } else {
        ""
    };
    let binary = Artifact {
        repository: "nazozero/NazoAuth".to_owned(),
        name: format!("nazoauth-{target}{suffix}"),
        sha256: "a".repeat(64),
        size: 1,
    };
    ReleaseManifest {
        schema: 4,
        version: version.to_owned(),
        target: target.clone(),
        backend_commit: revision.to_string().repeat(40),
        release_identity: format!(
            "https://github.com/nazozero/NazoAuth/.github/workflows/release-security.yml@refs/tags/{version}"
        ),
        embedded: nazo_operator_protocol::EmbeddedIdentity {
            release: version.to_owned(),
            revision: revision.to_string().repeat(40),
            protocol: nazo_operator_protocol::PROTOCOL_VERSION,
            build_id: format!("build:{version}"),
        },
        artifacts: BTreeMap::from([
            ("binary".to_owned(), binary),
            (
                "updater".to_owned(),
                Artifact {
                    repository: "nazozero/NazoAuth".to_owned(),
                    name: format!("nazoauthctl-{target}{suffix}"),
                    sha256: "e".repeat(64),
                    size: 1,
                },
            ),
        ]),
        frontend: FrontendRelease {
            repository: "nazozero/NazoAuthWeb".to_owned(),
            version: "v0.2.0".to_owned(),
            commit: "c".repeat(40),
            release_identity: "https://github.com/nazozero/NazoAuthWeb/.github/workflows/release.yml@refs/tags/v0.2.0".to_owned(),
            artifact: Artifact {
                repository: "nazozero/NazoAuthWeb".to_owned(),
                name: "nazoauth-web.tar.gz".to_owned(),
                sha256: "f".repeat(64),
                size: 1,
            },
        },
        oci: OciRelease {
            repository: "ghcr.io/nazozero/nazoauth".to_owned(),
            index_digest: format!("sha256:{}", "d".repeat(64)),
            platform_manifests: BTreeMap::from([
                ("linux/amd64".to_owned(), format!("sha256:{}", "1".repeat(64))),
                ("linux/arm64".to_owned(), format!("sha256:{}", "2".repeat(64))),
            ]),
        },
        rollback: Rollback {
            artifact: true,
            schema_compatible: true,
            database_restore: DatabaseRestore::Backup,
            irreversible_migration: false,
            minimum_supported_version: "0.0.0".to_owned(),
            migration_floor: "20260731000200".to_owned(),
            rationale: "additive migration".to_owned(),
        },
    }
}

fn config(work: &PrivateTempDir) -> UpdateConfig {
    let absolute = |name: &str| work.path().join(name);
    UpdateConfig {
        schema: 2,
        managed_install: true,
        install_profile: "baseline".to_owned(),
        repository: "nazozero/NazoAuth".to_owned(),
        updater_install_path: absolute("installed-nazoauthctl"),
        backup_root: absolute("backups"),
        deployment_root: absolute("deployments"),
        operator: Operator {
            deployment_id: "deployment-test".to_owned(),
            controller_key_id: "controller-test".to_owned(),
            controller_private_key: absolute("operator/controller.key"),
            controller_public_key: absolute("operator/controller.pub"),
            receipt_key_id: "receipt-test".to_owned(),
            receipt_private_key: absolute("operator/receipt.key"),
            receipt_public_key: absolute("operator/receipt.pub"),
            audit_key_id: "audit-test".to_owned(),
            audit_private_key: absolute("operator/audit.key"),
            audit_public_key: absolute("operator/audit.pub"),
            break_glass_key_id: "break-glass-test".to_owned(),
            break_glass_private_key: absolute("operator/break-glass.key"),
            break_glass_public_key: absolute("operator/break-glass.pub"),
            secret_revision_file: absolute("operator/secret-revision"),
            state_directory: absolute("operator-state"),
            audit_directory: absolute("audit"),
            trust_state_file: absolute("operator/release-trust.json"),
        },
        dependencies: Dependencies::default(),
        runtime: RuntimeConfig {
            engine: "host".to_owned(),
            dependency_engine: String::new(),
            container_name: "nazoauth".to_owned(),
            network: "nazoauth".to_owned(),
            ip_address: String::new(),
            publish_address: String::new(),
            health_url: "http://127.0.0.1:8000/ready".to_owned(),
            readiness_attempts: 1,
            readiness_interval_seconds: 0,
            public_discovery_url: "https://auth.example/.well-known/openid-configuration"
                .to_owned(),
            expected_issuer: "https://auth.example".to_owned(),
            mounts: Vec::new(),
            snapshot_paths: Vec::new(),
            environment: BTreeMap::new(),
            service_name: "nazoauth.service".to_owned(),
            service_user: "nazoauth".to_owned(),
            binary_path: absolute("nazoauth"),
            binary_releases: absolute("releases"),
            working_directory: work.path().to_owned(),
        },
        postgres: Postgres {
            container_name: "postgres".to_owned(),
            database: "oauth".to_owned(),
            user: "migrator".to_owned(),
            image: "postgres".to_owned(),
            validation_image: "postgres".to_owned(),
        },
        valkey: Valkey {
            container_name: "valkey".to_owned(),
            image: "valkey".to_owned(),
            rdb_path: "/data/dump.rdb".to_owned(),
            password_file: PathBuf::new(),
        },
        ui: Ui {
            releases_root: absolute("ui-releases"),
        },
    }
}

fn journal(config: &UpdateConfig, phase: UpdatePhase) -> UpdateJournal {
    UpdateJournal {
        schema: 1,
        transaction_id: "update-test".to_owned(),
        started_at: "2026-08-01T00:00:00Z".to_owned(),
        phase,
        from_release: manifest("v0.1.2", 'b'),
        to_release: manifest("v0.2.0", 'e'),
        previous_runtime: config
            .runtime
            .binary_releases
            .join("b".repeat(40))
            .join("nazoauth")
            .display()
            .to_string(),
        previous_ui: Some(config.ui.releases_root.join("f".repeat(64))),
        candidate_runtime: config
            .runtime
            .binary_releases
            .join("e".repeat(40))
            .join("nazoauth")
            .display()
            .to_string(),
        candidate_ui: config.ui.releases_root.join("f".repeat(64)),
        staged_updater: config
            .deployment_root
            .join(format!("candidate-nazoauthctl-{}", "e".repeat(40))),
        backup: (phase >= UpdatePhase::BackupCreated)
            .then(|| config.backup_root.join("v0.2.0-test")),
    }
}

fn assert_invalid_journal(config: &UpdateConfig, value: &UpdateJournal, expected_message: &str) {
    let error = validate_update_journal(config, value).unwrap_err();
    assert!(
        error.to_string().contains(expected_message),
        "unexpected error: {error:#}"
    );
}

#[test]
fn every_pre_migration_fault_window_restores_the_previous_runtime() {
    let work = PrivateTempDir::new("nazoauth-update-phase").unwrap();
    let config = config(&work);
    for phase in [
        UpdatePhase::Prepared,
        UpdatePhase::WriterStopping,
        UpdatePhase::WriterStopped,
        UpdatePhase::BackupCreating,
        UpdatePhase::BackupCreated,
    ] {
        assert_eq!(
            recovery_action(&journal(&config, phase), false),
            UpdateRecoveryAction::RestorePrevious,
            "phase {phase:?}"
        );
    }
}

#[test]
fn migration_faults_obey_the_signed_schema_boundary() {
    let work = PrivateTempDir::new("nazoauth-update-migration").unwrap();
    let config = config(&work);
    let compatible = journal(&config, UpdatePhase::MigrationRunning);
    assert_eq!(
        recovery_action(&compatible, false),
        UpdateRecoveryAction::RestorePrevious
    );

    let mut barrier = compatible;
    barrier.to_release.rollback.schema_compatible = false;
    barrier.to_release.rollback.irreversible_migration = true;
    assert_eq!(
        recovery_action(&barrier, false),
        UpdateRecoveryAction::ContinueForward
    );
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn container_target_binds_the_platform_manifest_not_the_index() {
    let work = PrivateTempDir::new("nazoauth-platform-target").unwrap();
    let mut config = config(&work);
    config.runtime.engine = "docker".to_owned();
    let manifest = manifest("v0.2.0", 'e');

    assert_eq!(
        manifest.image_ref().unwrap(),
        format!("ghcr.io/nazozero/nazoauth@sha256:{}", "1".repeat(64))
    );
    assert_eq!(
        expected_target(&config, &manifest).unwrap().image_digest,
        format!("sha256:{}", "1".repeat(64))
    );
    assert_ne!(
        manifest.runtime_oci_digest().unwrap(),
        manifest.image_oci_digest()
    );
}

#[test]
fn an_activated_target_always_finishes_state_trust_and_audit_commit() {
    let work = PrivateTempDir::new("nazoauth-update-active").unwrap();
    let config = config(&work);
    for phase in [
        UpdatePhase::MigrationRunning,
        UpdatePhase::MigrationApplied,
        UpdatePhase::CandidateActivating,
        UpdatePhase::CandidateActive,
        UpdatePhase::UiActivating,
        UpdatePhase::UiActive,
        UpdatePhase::HealthChecking,
        UpdatePhase::HealthVerified,
        UpdatePhase::StateCommitting,
        UpdatePhase::StateCommitted,
        UpdatePhase::TrustCommitting,
        UpdatePhase::TrustCommitted,
        UpdatePhase::AuditCommitting,
        UpdatePhase::AuditCommitted,
    ] {
        assert_eq!(
            recovery_action(&journal(&config, phase), true),
            UpdateRecoveryAction::ContinueForward,
            "phase {phase:?}"
        );
    }
}

#[test]
fn a_persisted_candidate_active_phase_finishes_even_if_runtime_inspection_is_unavailable() {
    let work = PrivateTempDir::new("nazoauth-update-persisted-active").unwrap();
    let config = config(&work);
    for phase in [
        UpdatePhase::CandidateActive,
        UpdatePhase::UiActivating,
        UpdatePhase::UiActive,
        UpdatePhase::HealthChecking,
        UpdatePhase::HealthVerified,
        UpdatePhase::StateCommitting,
        UpdatePhase::StateCommitted,
        UpdatePhase::TrustCommitting,
        UpdatePhase::TrustCommitted,
        UpdatePhase::AuditCommitting,
        UpdatePhase::AuditCommitted,
    ] {
        assert_eq!(
            recovery_action(&journal(&config, phase), false),
            UpdateRecoveryAction::ContinueForward,
            "phase {phase:?}"
        );
    }
}

#[test]
fn journal_is_durable_closed_and_monotonic() {
    let work = PrivateTempDir::new("nazoauth-update-journal").unwrap();
    let config = config(&work);
    fs::create_dir_all(&config.deployment_root).unwrap();
    fs::create_dir_all(&config.backup_root).unwrap();
    fs::create_dir_all(&config.ui.releases_root).unwrap();
    fs::create_dir_all(&config.runtime.binary_releases).unwrap();
    let mut value = journal(&config, UpdatePhase::Prepared);
    write_update_journal(&config, &value).unwrap();
    let loaded = load_update_journal(&config).unwrap().unwrap();
    assert_eq!(loaded.phase, UpdatePhase::Prepared);
    assert_eq!(loaded.transaction_id, "update-test");

    set_update_phase(&config, &mut value, UpdatePhase::WriterStopping).unwrap();
    assert_eq!(
        load_update_journal(&config).unwrap().unwrap().phase,
        UpdatePhase::WriterStopping
    );
    assert!(set_update_phase(&config, &mut value, UpdatePhase::Prepared).is_err());

    let mut document: serde_json::Value =
        serde_json::from_slice(&fs::read(update_journal_path(&config)).unwrap()).unwrap();
    document["unknown"] = serde_json::json!(true);
    fs::write(
        update_journal_path(&config),
        serde_json::to_vec(&document).unwrap(),
    )
    .unwrap();
    assert!(load_update_journal(&config).is_err());
}

#[test]
fn every_external_fault_window_round_trips_the_last_durable_phase() {
    let work = PrivateTempDir::new("nazoauth-update-fault-windows").unwrap();
    let config = config(&work);
    fs::create_dir_all(&config.deployment_root).unwrap();
    fs::create_dir_all(&config.backup_root).unwrap();
    fs::create_dir_all(&config.ui.releases_root).unwrap();
    fs::create_dir_all(&config.runtime.binary_releases).unwrap();
    let mut value = journal(&config, UpdatePhase::Prepared);
    write_update_journal(&config, &value).unwrap();

    for phase in [
        UpdatePhase::WriterStopping,
        UpdatePhase::WriterStopped,
        UpdatePhase::BackupCreating,
        UpdatePhase::BackupCreated,
        UpdatePhase::MigrationRunning,
        UpdatePhase::MigrationApplied,
        UpdatePhase::CandidateActivating,
        UpdatePhase::CandidateActive,
        UpdatePhase::UiActivating,
        UpdatePhase::UiActive,
        UpdatePhase::HealthChecking,
        UpdatePhase::HealthVerified,
        UpdatePhase::StateCommitting,
        UpdatePhase::StateCommitted,
        UpdatePhase::TrustCommitting,
        UpdatePhase::TrustCommitted,
        UpdatePhase::AuditCommitting,
        UpdatePhase::AuditCommitted,
    ] {
        if phase == UpdatePhase::BackupCreated {
            value.backup = Some(config.backup_root.join("v0.2.0-test"));
        }
        set_update_phase(&config, &mut value, phase).unwrap();
        let restarted = load_update_journal(&config).unwrap().unwrap();
        assert_eq!(restarted.phase, phase, "phase {phase:?}");
        assert_eq!(restarted.transaction_id, value.transaction_id);
        assert_eq!(restarted.previous_runtime, value.previous_runtime);
        assert_eq!(restarted.candidate_runtime, value.candidate_runtime);
        assert_eq!(restarted.backup, value.backup);
    }
}

#[test]
fn a_committed_backup_is_required_after_the_backup_phase() {
    let work = PrivateTempDir::new("nazoauth-update-backup").unwrap();
    let config = config(&work);
    let mut value = journal(&config, UpdatePhase::MigrationRunning);
    value.backup = None;
    assert!(validate_update_journal(&config, &value).is_err());
}

#[test]
fn journal_rejects_runtime_and_ui_paths_outside_managed_roots() {
    let work = PrivateTempDir::new("nazoauth-update-paths").unwrap();
    let config = config(&work);
    let mut value = journal(&config, UpdatePhase::Prepared);
    value.previous_runtime = work.path().join("outside-runtime").display().to_string();
    assert!(validate_update_journal(&config, &value).is_err());

    let mut value = journal(&config, UpdatePhase::Prepared);
    value.previous_ui = Some(work.path().join("outside-ui"));
    assert!(validate_update_journal(&config, &value).is_err());
}

#[test]
fn journal_validation_is_closed_over_headers_manifests_and_every_managed_path() {
    let work = PrivateTempDir::new("nazoauth-update-closed-journal").unwrap();
    let config = config(&work);
    let baseline = journal(&config, UpdatePhase::Prepared);
    validate_update_journal(&config, &baseline).unwrap();

    for transaction_id in [String::new(), "a".repeat(97), "unsafe/request".to_owned()] {
        let mut value = baseline.clone();
        value.transaction_id = transaction_id;
        assert_invalid_journal(&config, &value, "journal header is invalid");
    }
    for started_at in [String::new(), "a".repeat(65), "not-a-timestamp".to_owned()] {
        let mut value = baseline.clone();
        value.started_at = started_at;
        assert_invalid_journal(&config, &value, "journal header is invalid");
    }

    let mut value = baseline.clone();
    value.schema = 2;
    assert_invalid_journal(&config, &value, "journal header is invalid");

    let mut value = baseline.clone();
    value.to_release.release_identity = "https://attacker.example/release".to_owned();
    assert!(validate_update_journal(&config, &value).is_err());

    for clear_previous in [true, false] {
        let mut value = baseline.clone();
        if clear_previous {
            value.previous_runtime.clear();
        } else {
            value.candidate_runtime.clear();
        }
        assert_invalid_journal(&config, &value, "unsafe candidate path");
    }

    let mut value = baseline.clone();
    value.candidate_ui = work.path().join("wrong-candidate-ui");
    assert_invalid_journal(&config, &value, "candidate artifacts do not match");

    let mut value = baseline.clone();
    value.staged_updater = work.path().join("wrong-updater");
    assert_invalid_journal(&config, &value, "candidate artifacts do not match");

    let mut value = baseline.clone();
    value.previous_ui = Some(work.path().join("wrong-previous-ui"));
    assert_invalid_journal(&config, &value, "previous UI does not match");

    let mut value = baseline.clone();
    value.previous_runtime = work.path().join("wrong-previous").display().to_string();
    assert_invalid_journal(&config, &value, "host runtime does not match");

    let mut value = baseline.clone();
    value.candidate_runtime = work.path().join("wrong-candidate").display().to_string();
    assert_invalid_journal(&config, &value, "host runtime does not match");

    let mut value = baseline;
    value.backup = Some(work.path().join("outside-backup-root"));
    assert_invalid_journal(&config, &value, "backup is outside");
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[test]
fn container_journal_binds_both_runtime_images_to_the_signed_platform_digest() {
    let work = PrivateTempDir::new("nazoauth-update-container-journal").unwrap();
    let mut config = config(&work);
    config.runtime.engine = "podman".to_owned();
    let mut value = journal(&config, UpdatePhase::Prepared);
    value.previous_runtime = value.from_release.image_ref().unwrap();
    value.candidate_runtime = value.to_release.image_ref().unwrap();
    validate_update_journal(&config, &value).unwrap();

    value.candidate_runtime = format!(
        "{}@sha256:{}",
        value.to_release.oci.repository,
        "9".repeat(64)
    );
    assert_invalid_journal(&config, &value, "image runtime does not match");

    value.candidate_runtime = value.to_release.image_ref().unwrap();
    value.previous_runtime = format!(
        "{}@sha256:{}",
        value.from_release.oci.repository,
        "8".repeat(64)
    );
    assert_invalid_journal(&config, &value, "image runtime does not match");
}

#[test]
fn failed_phase_persistence_restores_the_in_memory_phase() {
    let work = PrivateTempDir::new("nazoauth-update-phase-write-failure").unwrap();
    let config = config(&work);
    fs::write(&config.deployment_root, b"not a directory").unwrap();
    let mut value = journal(&config, UpdatePhase::Prepared);

    assert!(set_update_phase(&config, &mut value, UpdatePhase::WriterStopping).is_err());
    assert_eq!(value.phase, UpdatePhase::Prepared);
}

#[test]
fn loading_a_journal_distinguishes_absent_non_regular_invalid_and_valid_state() {
    let work = PrivateTempDir::new("nazoauth-update-load-journal").unwrap();
    let config = config(&work);
    let path = update_journal_path(&config);

    assert!(load_update_journal(&config).unwrap().is_none());

    fs::create_dir_all(&path).unwrap();
    assert!(load_update_journal(&config).is_err());
    fs::remove_dir(&path).unwrap();

    fs::write(&path, b"not-json").unwrap();
    assert!(load_update_journal(&config).is_err());
    fs::remove_file(&path).unwrap();

    let value = journal(&config, UpdatePhase::Prepared);
    write_update_journal(&config, &value).unwrap();
    let loaded = load_update_journal(&config).unwrap().unwrap();
    assert_eq!(loaded.transaction_id, value.transaction_id);
    assert_eq!(loaded.phase, value.phase);
}

#[cfg(unix)]
#[test]
fn loading_a_journal_rejects_a_symlink_even_when_its_target_is_valid() {
    let work = PrivateTempDir::new("nazoauth-update-journal-symlink").unwrap();
    let config = config(&work);
    fs::create_dir_all(&config.deployment_root).unwrap();
    let target = work.path().join("journal-target.json");
    fs::write(
        &target,
        serde_json::to_vec(&journal(&config, UpdatePhase::Prepared)).unwrap(),
    )
    .unwrap();
    std::os::unix::fs::symlink(&target, update_journal_path(&config)).unwrap();

    assert!(load_update_journal(&config).is_err());
}

#[test]
fn verified_journal_backup_is_opened_only_from_the_configured_root() {
    let work = PrivateTempDir::new("nazoauth-update-journal-backup").unwrap();
    let config = config(&work);
    fs::create_dir_all(&config.backup_root).unwrap();
    let mut value = journal(&config, UpdatePhase::Prepared);
    assert!(journal_backup(&config, &value).is_err());

    let backup = config.backup_root.join("verified-backup");
    fs::create_dir(&backup).unwrap();
    fs::write(backup.join("state.bin"), b"durable-state").unwrap();
    fs::write(
        backup.join("SHA256SUMS"),
        format!(
            "{}  state.bin\n",
            crate::filesystem::sha256(&backup.join("state.bin")).unwrap()
        ),
    )
    .unwrap();
    value.backup = Some(backup.clone());

    assert_eq!(
        journal_backup(&config, &value).unwrap().path(),
        fs::canonicalize(backup).unwrap()
    );
}

#[test]
fn no_pending_update_is_an_idempotent_recovery_noop() {
    let work = PrivateTempDir::new("nazoauth-update-recovery-noop").unwrap();
    let config = config(&work);
    recover_pending_update(&work.path().join("config.json"), &config).unwrap();
    assert!(!update_journal_path(&config).exists());
}

#[test]
fn early_update_faults_leave_the_last_durable_phase_for_restart() {
    for (initial, expected) in [
        (UpdatePhase::Prepared, UpdatePhase::WriterStopping),
        (UpdatePhase::WriterStopped, UpdatePhase::BackupCreating),
        (UpdatePhase::BackupCreated, UpdatePhase::MigrationRunning),
    ] {
        let work = PrivateTempDir::new("nazoauth-update-early-fault").unwrap();
        let config = config(&work);
        fs::create_dir_all(&config.deployment_root).unwrap();
        let mut value = journal(&config, initial);
        write_update_journal(&config, &value).unwrap();

        assert!(
            advance_update_transaction(&work.path().join("config.json"), &config, &mut value)
                .is_err(),
            "phase {initial:?} unexpectedly completed"
        );
        assert_eq!(value.phase, expected, "phase {initial:?}");
        assert_eq!(
            load_update_journal(&config).unwrap().unwrap().phase,
            expected,
            "phase {initial:?} was not durable"
        );
    }
}

#[test]
fn finishing_a_transaction_durably_removes_only_its_journal_and_staged_updater() {
    let work = PrivateTempDir::new("nazoauth-update-finish").unwrap();
    let config = config(&work);
    fs::create_dir_all(&config.deployment_root).unwrap();
    let value = journal(&config, UpdatePhase::AuditCommitted);
    fs::write(&value.staged_updater, b"updater").unwrap();
    write_update_journal(&config, &value).unwrap();
    let unrelated = config.deployment_root.join("keep.json");
    fs::write(&unrelated, b"keep").unwrap();

    finish_update_journal(&config, &value).unwrap();
    assert!(!value.staged_updater.exists());
    assert!(!update_journal_path(&config).exists());
    assert!(unrelated.exists());
    finish_update_journal(&config, &value).unwrap();
}

#[test]
fn transaction_ids_are_fixed_width_lower_hex_and_non_repeating() {
    let first = encode_transaction_id();
    let second = encode_transaction_id();
    for value in [&first, &second] {
        assert_eq!(value.len(), 32);
        assert!(value.chars().all(|character| character.is_ascii_hexdigit()));
        assert_eq!(value, &value.to_ascii_lowercase());
    }
    assert_ne!(first, second);
}

#[test]
fn active_release_round_trip_revalidates_the_release_identity() {
    let work = PrivateTempDir::new("nazoauth-active-release").unwrap();
    let mut config = config(&work);
    fs::create_dir_all(&config.deployment_root).unwrap();
    let release = manifest("v0.2.0", 'e');
    write_active_release(&config, &release).unwrap();
    let loaded = load_active_release(&config).unwrap();
    assert_eq!(loaded.version, release.version);
    assert_eq!(loaded.backend_commit, release.backend_commit);

    config.repository = "attacker/NazoAuth".to_owned();
    assert!(load_active_release(&config).is_err());

    fs::write(active_release_path(&config), b"not-json").unwrap();
    assert!(load_active_release(&config).is_err());
}

#[test]
fn expected_target_separates_host_binary_and_release_aggregate_identity() {
    let work = PrivateTempDir::new("nazoauth-expected-host-target").unwrap();
    let config = config(&work);
    let mut release = manifest("v0.2.0", 'e');
    let expected = expected_target(&config, &release).unwrap();
    assert_eq!(expected.embedded, release.embedded);
    assert_eq!(expected.image_digest, release.oci.index_digest);
    assert_eq!(expected.binary_digest, "a".repeat(64));

    release.artifacts.remove("binary");
    assert!(expected_target(&config, &release).is_err());
}

#[test]
fn ui_cache_validation_rejects_missing_non_regular_and_malformed_artifacts() {
    let work = PrivateTempDir::new("nazoauth-frontend-cache-boundaries").unwrap();
    let config = config(&work);
    let value = journal(&config, UpdatePhase::UiActivating);
    assert!(!target_ui_is_active(&value));

    fs::create_dir_all(value.candidate_ui.parent().unwrap()).unwrap();
    fs::write(&value.candidate_ui, b"not a directory").unwrap();
    assert!(!target_ui_is_active(&value));
    fs::remove_file(&value.candidate_ui).unwrap();

    fs::create_dir_all(&value.candidate_ui).unwrap();
    assert!(!target_ui_is_active(&value));
    fs::write(value.candidate_ui.join("index.html"), b"ui").unwrap();
    assert!(!target_ui_is_active(&value));
    fs::write(value.candidate_ui.join(".nazoauth-ui.json"), b"not-json").unwrap();
    assert!(!target_ui_is_active(&value));
}

#[cfg(unix)]
#[test]
fn ui_cache_validation_rejects_symlinked_index_and_marker_files() {
    let work = PrivateTempDir::new("nazoauth-frontend-cache-symlinks").unwrap();
    let config = config(&work);
    let value = journal(&config, UpdatePhase::UiActivating);
    fs::create_dir_all(&value.candidate_ui).unwrap();
    let external_index = work.path().join("external-index.html");
    fs::write(&external_index, b"ui").unwrap();
    std::os::unix::fs::symlink(&external_index, value.candidate_ui.join("index.html")).unwrap();
    assert!(!target_ui_is_active(&value));

    fs::remove_file(value.candidate_ui.join("index.html")).unwrap();
    fs::write(value.candidate_ui.join("index.html"), b"ui").unwrap();
    let external_marker = work.path().join("external-marker.json");
    fs::write(&external_marker, b"{}").unwrap();
    std::os::unix::fs::symlink(
        &external_marker,
        value.candidate_ui.join(".nazoauth-ui.json"),
    )
    .unwrap();
    assert!(!target_ui_is_active(&value));
}

#[cfg(unix)]
fn host_identity_fixture(
    work: &PrivateTempDir,
    actual_identity: &nazo_operator_protocol::EmbeddedIdentity,
) -> (UpdateConfig, ReleaseManifest) {
    use std::os::unix::fs::PermissionsExt as _;

    let mut config = config(work);
    config.dependencies.mode = "external".to_owned();
    let mut release = manifest("v0.2.0", 'e');
    let directory = config.runtime.binary_releases.join(&release.backend_commit);
    fs::create_dir_all(&directory).unwrap();
    let binary = directory.join("nazoauth");
    let identity = serde_json::to_string(actual_identity).unwrap();
    assert!(!identity.contains('\''));
    fs::write(
        &binary,
        format!(
            "#!/bin/sh\nif [ \"${{1:-}}\" = build-identity ]; then\n  printf '%s\\n' '{identity}'\n  exit 0\nfi\nexit 1\n"
        ),
    )
    .unwrap();
    let mut permissions = fs::metadata(&binary).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&binary, permissions).unwrap();
    let metadata = fs::metadata(&binary).unwrap();
    let artifact = release.artifacts.get_mut("binary").unwrap();
    artifact.sha256 = crate::filesystem::sha256(&binary).unwrap();
    artifact.size = metadata.len();
    config.runtime.binary_path = binary;
    fs::create_dir_all(&config.deployment_root).unwrap();
    write_active_release(&config, &release).unwrap();
    (config, release)
}

#[cfg(unix)]
fn health_server() -> (String, std::thread::JoinHandle<()>) {
    use std::io::{Read as _, Write as _};
    use std::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = [0_u8; 1024];
        let _ = stream.read(&mut request).unwrap();
        stream
            .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .unwrap();
    });
    (format!("http://{address}/ready"), handle)
}

#[cfg(unix)]
fn public_server(requests: usize) -> (String, std::thread::JoinHandle<()>) {
    use std::io::{Read as _, Write as _};
    use std::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let issuer = format!("http://{address}");
    let response_issuer = issuer.clone();
    let handle = std::thread::spawn(move || {
        for _ in 0..requests {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 2048];
            let length = stream.read(&mut request).unwrap();
            let request = String::from_utf8_lossy(&request[..length]);
            let body = if request.starts_with("GET /.well-known/openid-configuration ") {
                serde_json::json!({"issuer": response_issuer}).to_string()
            } else {
                "ok".to_owned()
            };
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    )
                    .as_bytes(),
                )
                .unwrap();
        }
    });
    (issuer, handle)
}

#[cfg(unix)]
fn fake_container_runtime(
    work: &PrivateTempDir,
    candidate_commit: &str,
    candidate_active: bool,
) -> PathBuf {
    use std::os::unix::fs::PermissionsExt as _;

    let engine = work.path().join(if candidate_active {
        "active-container-engine"
    } else {
        "inactive-container-engine"
    });
    fs::write(
        &engine,
        format!(
            "#!/bin/sh\nif [ \"${{1:-}}\" = inspect ]; then\n  if [ \"{candidate_active}\" != true ]; then exit 1; fi\n  if [ \"$#\" -gt 2 ]; then printf '%s\\n' '{candidate_commit}'; fi\n  exit 0\nfi\nexit 0\n"
        ),
    )
    .unwrap();
    let mut permissions = fs::metadata(&engine).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&engine, permissions).unwrap();
    engine
}

#[cfg(unix)]
fn install_audit_key(config: &UpdateConfig) {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use ed25519_dalek::SigningKey;

    let key = SigningKey::from_bytes(&[7; 32]);
    fs::create_dir_all(config.operator.audit_private_key.parent().unwrap()).unwrap();
    fs::write(
        &config.operator.audit_private_key,
        URL_SAFE_NO_PAD.encode(key.to_bytes()),
    )
    .unwrap();
    fs::write(
        &config.operator.audit_public_key,
        URL_SAFE_NO_PAD.encode(key.verifying_key().to_bytes()),
    )
    .unwrap();
}

#[cfg(unix)]
fn configure_public_checks(config: &mut UpdateConfig, issuer: &str) {
    config.runtime.health_url = format!("{issuer}/ready");
    config.runtime.public_discovery_url = format!("{issuer}/.well-known/openid-configuration");
    config.runtime.expected_issuer = issuer.to_owned();
}

#[cfg(unix)]
fn materialize_candidate_ui(value: &UpdateJournal) {
    fs::create_dir_all(&value.candidate_ui).unwrap();
    fs::write(value.candidate_ui.join("index.html"), b"ui").unwrap();
    fs::write(
        value.candidate_ui.join(".nazoauth-ui.json"),
        serde_json::to_vec(&serde_json::json!({
            "schema": 1,
            "repository": value.to_release.frontend.repository,
            "version": value.to_release.frontend.version,
            "commit": value.to_release.frontend.commit,
            "release_identity": value.to_release.frontend.release_identity,
            "artifact": value.to_release.frontend.artifact,
        }))
        .unwrap(),
    )
    .unwrap();
}

#[cfg(unix)]
fn materialize_verified_backup(config: &UpdateConfig, path: &std::path::Path) {
    fs::create_dir_all(&config.backup_root).unwrap();
    fs::create_dir(path).unwrap();
    fs::write(path.join("state.bin"), b"durable-state").unwrap();
    fs::write(
        path.join("SHA256SUMS"),
        format!(
            "{}  state.bin\n",
            crate::filesystem::sha256(&path.join("state.bin")).unwrap()
        ),
    )
    .unwrap();
}

#[cfg(unix)]
#[test]
fn host_status_reports_signed_binary_and_embedded_identity_match() {
    let work = PrivateTempDir::new("nazoauth-host-status").unwrap();
    let release = manifest("v0.2.0", 'e');
    let (mut config, _) = host_identity_fixture(&work, &release.embedded);
    let (health_url, server) = health_server();
    config.runtime.health_url = health_url;

    status(&config).unwrap();
    server.join().unwrap();
}

#[cfg(unix)]
#[test]
fn host_status_remains_observable_when_embedded_identity_mismatches() {
    let work = PrivateTempDir::new("nazoauth-host-status-mismatch").unwrap();
    let release = manifest("v0.2.0", 'e');
    let mut actual = release.embedded.clone();
    actual.build_id = "build:substituted".to_owned();
    let (mut config, _) = host_identity_fixture(&work, &actual);
    let (health_url, server) = health_server();
    config.runtime.health_url = health_url;

    status(&config).unwrap();
    server.join().unwrap();
}

#[cfg(unix)]
#[test]
fn host_doctor_accepts_the_exact_signed_binary_and_embedded_identity() {
    let work = PrivateTempDir::new("nazoauth-host-doctor").unwrap();
    let release = manifest("v0.2.0", 'e');
    let (mut config, _) = host_identity_fixture(&work, &release.embedded);
    let (health_url, server) = health_server();
    config.runtime.health_url = health_url;

    doctor(&config).unwrap();
    server.join().unwrap();
}

#[cfg(unix)]
#[test]
fn host_doctor_rejects_embedded_identity_substitution_before_health_checks() {
    let work = PrivateTempDir::new("nazoauth-host-doctor-identity-mismatch").unwrap();
    let release = manifest("v0.2.0", 'e');
    let mut actual = release.embedded.clone();
    actual.revision = "9".repeat(40);
    let (config, _) = host_identity_fixture(&work, &actual);

    let error = doctor(&config).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("runtime embedded build identity differs")
    );
}

#[cfg(unix)]
#[test]
fn pending_pre_migration_update_restores_previous_artifact_and_closes_the_journal() {
    let work = PrivateTempDir::new("nazoauth-recover-previous").unwrap();
    let mut config = config(&work);
    let mut value = journal(&config, UpdatePhase::WriterStopped);
    config.runtime.engine = fake_container_runtime(&work, &value.to_release.backend_commit, false)
        .display()
        .to_string();
    value.previous_runtime = value.from_release.image_ref().unwrap();
    value.candidate_runtime = value.to_release.image_ref().unwrap();
    fs::create_dir_all(&config.deployment_root).unwrap();
    fs::write(&value.staged_updater, b"staged-updater").unwrap();
    install_audit_key(&config);
    let (issuer, server) = public_server(3);
    configure_public_checks(&mut config, &issuer);
    write_update_journal(&config, &value).unwrap();

    let result = recover_pending_update(&work.path().join("config.json"), &config);
    assert!(result.is_ok(), "recovery failed: {result:#?}");
    server.join().unwrap();
    assert_eq!(
        load_active_release(&config).unwrap().version,
        value.from_release.version
    );
    assert!(!update_journal_path(&config).exists());
    assert!(!value.staged_updater.exists());
    crate::operator::verify_audit(&config).unwrap();
}

#[cfg(unix)]
#[test]
fn pending_active_candidate_continues_all_commits_and_closes_the_journal() {
    let work = PrivateTempDir::new("nazoauth-recover-forward").unwrap();
    let mut config = config(&work);
    let mut value = journal(&config, UpdatePhase::CandidateActive);
    config.runtime.engine = fake_container_runtime(&work, &value.to_release.backend_commit, true)
        .display()
        .to_string();
    value.previous_runtime = value.from_release.image_ref().unwrap();
    value.candidate_runtime = value.to_release.image_ref().unwrap();
    fs::create_dir_all(&config.deployment_root).unwrap();
    fs::write(&value.staged_updater, b"staged-updater").unwrap();
    materialize_candidate_ui(&value);
    materialize_verified_backup(&config, value.backup.as_deref().unwrap());
    install_audit_key(&config);
    let (issuer, server) = public_server(5);
    configure_public_checks(&mut config, &issuer);
    write_update_journal(&config, &value).unwrap();

    let result = recover_pending_update(&work.path().join("config.json"), &config);
    assert!(result.is_ok(), "recovery failed: {result:#?}");
    server.join().unwrap();
    assert_eq!(
        load_active_release(&config).unwrap().version,
        value.to_release.version
    );
    assert_eq!(
        fs::read(&config.updater_install_path).unwrap(),
        b"staged-updater"
    );
    assert!(!update_journal_path(&config).exists());
    assert!(!value.staged_updater.exists());
    crate::operator::verify_audit(&config).unwrap();
}

#[test]
fn update_deployment_record_is_idempotent_for_a_transaction() {
    let work = PrivateTempDir::new("nazoauth-update-record").unwrap();
    let config = config(&work);
    let value = journal(&config, UpdatePhase::StateCommitting);
    let backup = value.backup.as_deref().unwrap();

    write_update_record(&config, &value, "deployment-success", Some(backup)).unwrap();
    let path = config.deployment_root.join("update-update-test.json");
    let first = fs::read(&path).unwrap();
    write_update_record(&config, &value, "deployment-success", Some(backup)).unwrap();

    assert_eq!(fs::read(&path).unwrap(), first);
    assert_eq!(
        fs::read_dir(&config.deployment_root)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name() == "update-update-test.json")
            .count(),
        1
    );
}

#[test]
fn frontend_cache_marker_must_exactly_match_the_signed_release() {
    let work = PrivateTempDir::new("nazoauth-frontend-marker").unwrap();
    let config = config(&work);
    let value = journal(&config, UpdatePhase::UiActivating);
    fs::create_dir_all(&value.candidate_ui).unwrap();
    fs::write(value.candidate_ui.join("index.html"), b"ui").unwrap();
    let expected = serde_json::json!({
        "schema": 1,
        "repository": value.to_release.frontend.repository,
        "version": value.to_release.frontend.version,
        "commit": value.to_release.frontend.commit,
        "release_identity": value.to_release.frontend.release_identity,
        "artifact": value.to_release.frontend.artifact,
    });
    fs::write(
        value.candidate_ui.join(".nazoauth-ui.json"),
        serde_json::to_vec(&expected).unwrap(),
    )
    .unwrap();
    assert!(target_ui_is_active(&value));

    let mut changed = expected;
    changed["unexpected"] = serde_json::json!(true);
    fs::write(
        value.candidate_ui.join(".nazoauth-ui.json"),
        serde_json::to_vec(&changed).unwrap(),
    )
    .unwrap();
    assert!(!target_ui_is_active(&value));
}
