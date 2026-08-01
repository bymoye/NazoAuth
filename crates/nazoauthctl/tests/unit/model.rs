use super::*;

fn valid_config() -> UpdateConfig {
    let root = std::env::temp_dir().join("nazoauthctl-model-test");
    UpdateConfig {
        schema: 2,
        managed_install: true,
        install_profile: "baseline".to_owned(),
        repository: "nazozero/NazoAuth".to_owned(),
        updater_install_path: root.join("bin/nazoauthctl"),
        backup_root: root.join("backups"),
        deployment_root: root.join("deployments"),
        operator: Operator {
            deployment_id: "deployment-test".to_owned(),
            controller_key_id: "controller-test".to_owned(),
            controller_private_key: root.join("operator/controller.key"),
            controller_public_key: root.join("operator/controller.pub"),
            receipt_key_id: "receipt-test".to_owned(),
            receipt_private_key: root.join("operator/receipt.key"),
            receipt_public_key: root.join("operator/receipt.pub"),
            audit_key_id: "audit-test".to_owned(),
            audit_private_key: root.join("operator/audit.key"),
            audit_public_key: root.join("operator/audit.pub"),
            break_glass_key_id: "break-glass-test".to_owned(),
            break_glass_private_key: root.join("recovery/break-glass.key"),
            break_glass_public_key: root.join("operator/break-glass.pub"),
            secret_revision_file: root.join("operator/secret-revision"),
            state_directory: root.join("state"),
            audit_directory: root.join("audit"),
            trust_state_file: root.join("operator/release-trust.json"),
        },
        dependencies: Dependencies::default(),
        runtime: Runtime {
            engine: "host".to_owned(),
            dependency_engine: "podman".to_owned(),
            container_name: "nazoauth".to_owned(),
            network: "nazoauth-net".to_owned(),
            ip_address: String::new(),
            publish_address: "127.0.0.1:8000".to_owned(),
            health_url: "http://127.0.0.1:8000/ready".to_owned(),
            readiness_attempts: 1,
            readiness_interval_seconds: 0,
            public_discovery_url: "https://auth.example/.well-known/openid-configuration"
                .to_owned(),
            expected_issuer: "https://auth.example".to_owned(),
            mounts: vec![Mount {
                source: root.join("config/.env.yaml"),
                target: root.join("mounted/.env.yaml"),
                mode: "ro".to_owned(),
            }],
            snapshot_paths: vec![root.join("keys")],
            environment: BTreeMap::from([(
                "DATABASE_URL_FILE".to_owned(),
                root.join("secrets/database-url").display().to_string(),
            )]),
            service_name: "nazoauth".to_owned(),
            service_user: "nazoauth".to_owned(),
            binary_path: root.join("bin/nazoauth"),
            binary_releases: root.join("releases"),
            working_directory: root.join("config"),
        },
        postgres: Postgres {
            container_name: "nazoauth-postgres".to_owned(),
            database: "nazoauth".to_owned(),
            user: "nazoauth".to_owned(),
            image: "postgres:test".to_owned(),
            validation_image: "postgres:test".to_owned(),
        },
        valkey: Valkey {
            container_name: "nazoauth-valkey".to_owned(),
            image: "valkey:test".to_owned(),
            rdb_path: "/data/dump.rdb".to_owned(),
            password_file: root.join("secrets/valkey-password"),
        },
        ui: Ui {
            releases_root: root.join("ui-releases"),
        },
    }
}

fn valid_manifest() -> ReleaseManifest {
    let target = release_target().unwrap().to_owned();
    let suffix = if target.contains("windows") {
        ".exe"
    } else {
        ""
    };
    let artifact = |name: String| Artifact {
        repository: "nazozero/NazoAuth".to_owned(),
        name,
        sha256: "a".repeat(64),
        size: 1,
    };
    ReleaseManifest {
        schema: 4,
        version: "v0.2.0".to_owned(),
        target: target.clone(),
        backend_commit: "b".repeat(40),
        release_identity: "release-identity".to_owned(),
        embedded: nazo_operator_protocol::EmbeddedIdentity {
            release: "v0.2.0".to_owned(),
            revision: "b".repeat(40),
            protocol: nazo_operator_protocol::PROTOCOL_VERSION,
            build_id: "build:test".to_owned(),
        },
        artifacts: BTreeMap::from([
            (
                "binary".to_owned(),
                artifact(format!("nazoauth-{target}{suffix}")),
            ),
            (
                "updater".to_owned(),
                artifact(format!("nazoauthctl-{target}{suffix}")),
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
                sha256: "d".repeat(64),
                size: 1,
            },
        },
        oci: OciRelease {
            repository: "ghcr.io/nazozero/nazoauth".to_owned(),
            index_digest: format!("sha256:{}", "e".repeat(64)),
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
            minimum_supported_version: "0.1.2".to_owned(),
            migration_floor: "1".to_owned(),
            rationale: "compatible".to_owned(),
        },
    }
}

#[test]
fn semantic_versions_require_an_immutable_tag() {
    assert!(semantic_tag("v1.2.3"));
    assert!(semantic_tag("v1.2.3-rc.1"));
    assert!(!semantic_tag("latest"));
    assert!(!semantic_tag("v1.2"));
    assert!(!semantic_tag("1.2.3"));
}

#[test]
fn environment_keys_are_strict() {
    assert!(valid_environment_key("DATABASE_URL_FILE"));
    assert!(!valid_environment_key("database_url"));
    assert!(!valid_environment_key("BAD-VALUE"));
}

#[test]
fn runtime_environment_cannot_carry_secret_values() {
    assert!(valid_environment_key("DATABASE_URL_FILE"));
    assert!(!"DATABASE_URL_FILE".ends_with("PASSWORD"));
    assert!(!"DATABASE_URL".ends_with("_FILE"));
}

#[test]
fn update_config_accepts_only_closed_safe_runtime_boundaries() {
    let config = valid_config();
    config.validate().unwrap();
    assert_eq!(config.container_engine(), Some("podman"));
    UpdateConfig::parse(&serde_json::to_vec(&config).unwrap()).unwrap();

    let mut invalid = config.clone();
    invalid.schema = 1;
    assert!(invalid.validate().is_err());
    let mut invalid = config.clone();
    invalid.install_profile = "custom".to_owned();
    assert!(invalid.validate().is_err());
    let mut invalid = config.clone();
    invalid.repository = "unsafe".to_owned();
    assert!(invalid.validate().is_err());
    let mut invalid = config.clone();
    invalid.runtime.engine = "shell".to_owned();
    assert!(invalid.validate().is_err());
    let mut invalid = config.clone();
    invalid.dependencies.mode = "shared".to_owned();
    assert!(invalid.validate().is_err());
    let mut invalid = config.clone();
    invalid.runtime.container_name = "bad/name".to_owned();
    assert!(invalid.validate().is_err());
    let mut invalid = config.clone();
    invalid.operator.controller_key_id = "bad key".to_owned();
    assert!(invalid.validate().is_err());
    let mut invalid = config.clone();
    invalid.runtime.service_name.clear();
    assert!(invalid.validate().is_err());
    let mut invalid = config.clone();
    invalid.runtime.service_user = "unsafe/user".to_owned();
    assert!(invalid.validate().is_err());
    let mut invalid = config.clone();
    invalid.runtime.readiness_attempts = 0;
    assert!(invalid.validate().is_err());
    let mut invalid = config.clone();
    invalid.runtime.mounts[0].mode = "private".to_owned();
    assert!(invalid.validate().is_err());
    let mut invalid = config.clone();
    invalid.runtime.environment = BTreeMap::from([(
        "DATABASE_URL".to_owned(),
        config.backup_root.display().to_string(),
    )]);
    assert!(invalid.validate().is_err());
    assert!(UpdateConfig::parse(b"not-json").is_err());
}

#[test]
fn external_and_container_dependency_modes_resolve_explicitly() {
    let mut config = valid_config();
    config.runtime.engine = "docker".to_owned();
    config.runtime.service_name.clear();
    config.runtime.service_user.clear();
    config.dependencies.mode = "external".to_owned();
    let root = std::env::temp_dir().join("nazoauthctl-external-model-test");
    config.dependencies.database_url_file = root.join("database-url");
    config.dependencies.migration_database_url_file = root.join("migration-database-url");
    config.dependencies.valkey_url_file = root.join("valkey-url");
    config.validate().unwrap();
    assert_eq!(config.container_engine(), Some("docker"));

    config.dependencies.database_url_file = "relative".into();
    assert!(config.validate().is_err());
    assert!(safe_absolute(std::path::Path::new("relative")).is_err());
    assert!(safe_absolute(std::path::Path::new(&std::path::MAIN_SEPARATOR.to_string())).is_err());
}

#[test]
fn release_manifest_binds_every_binary_frontend_and_oci_identity() {
    let manifest = valid_manifest();
    manifest.validate("v0.2.0", "release-identity").unwrap();
    assert_eq!(
        manifest.image_oci_digest(),
        format!("sha256:{}", "e".repeat(64))
    );
    assert_eq!(manifest.frontend_commit(), "c".repeat(40));

    if cfg!(target_os = "linux") {
        assert!(
            manifest
                .image_ref()
                .unwrap()
                .starts_with("ghcr.io/nazozero/nazoauth@sha256:")
        );
        assert!(manifest.runtime_oci_digest().is_ok());
    } else {
        assert!(manifest.image_ref().is_err());
        assert!(manifest.runtime_oci_digest().is_err());
    }

    let mut invalid = manifest.clone();
    invalid.rollback.irreversible_migration = true;
    assert!(invalid.validate("v0.2.0", "release-identity").is_err());
    let mut invalid = manifest.clone();
    invalid.rollback.artifact = false;
    assert!(invalid.validate("v0.2.0", "release-identity").is_err());
    let mut invalid = manifest.clone();
    invalid.artifacts.remove("updater");
    assert!(invalid.validate("v0.2.0", "release-identity").is_err());
    let mut invalid = manifest.clone();
    invalid.artifacts.get_mut("binary").unwrap().name = "nazoauth-wrong-target".to_owned();
    assert!(invalid.validate("v0.2.0", "release-identity").is_err());
    let mut invalid = manifest.clone();
    invalid.artifacts.get_mut("binary").unwrap().size = 0;
    assert!(invalid.validate("v0.2.0", "release-identity").is_err());
    let mut invalid = manifest.clone();
    invalid.frontend.artifact.name = "index.html".to_owned();
    assert!(invalid.validate("v0.2.0", "release-identity").is_err());
    let mut invalid = manifest.clone();
    invalid.oci.platform_manifests.remove("linux/arm64");
    assert!(invalid.validate("v0.2.0", "release-identity").is_err());
}

#[test]
fn platform_mapping_is_total_over_every_published_release_target() {
    assert_eq!(executable_suffix("x86_64-pc-windows-msvc"), ".exe");
    assert_eq!(executable_suffix("x86_64-unknown-linux-gnu"), "");
    assert_eq!(
        runtime_oci_platform("linux", "x86_64").unwrap(),
        "linux/amd64"
    );
    assert_eq!(
        runtime_oci_platform("linux", "aarch64").unwrap(),
        "linux/arm64"
    );
    assert!(runtime_oci_platform("windows", "x86_64").is_err());

    for (arch, os, env, expected) in [
        ("x86_64", "linux", "musl", Some("x86_64-unknown-linux-musl")),
        (
            "aarch64",
            "linux",
            "musl",
            Some("aarch64-unknown-linux-musl"),
        ),
        ("x86_64", "linux", "gnu", Some("x86_64-unknown-linux-gnu")),
        ("aarch64", "linux", "gnu", Some("aarch64-unknown-linux-gnu")),
        ("x86_64", "windows", "msvc", Some("x86_64-pc-windows-msvc")),
        (
            "aarch64",
            "windows",
            "msvc",
            Some("aarch64-pc-windows-msvc"),
        ),
        ("x86_64", "macos", "", Some("x86_64-apple-darwin")),
        ("aarch64", "macos", "", Some("aarch64-apple-darwin")),
        ("wasm32", "unknown", "", None),
    ] {
        assert_eq!(release_target_for(arch, os, env), expected);
    }
}
