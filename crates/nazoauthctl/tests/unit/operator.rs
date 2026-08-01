use std::{collections::BTreeMap, fs};

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
            active_path: work.path().join("ui"),
            releases_root: work.path().join("ui-releases"),
            serve_from_application: false,
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
