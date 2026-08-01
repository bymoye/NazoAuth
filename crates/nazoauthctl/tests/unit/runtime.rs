use std::{collections::BTreeMap, path::PathBuf};

#[cfg(unix)]
use std::fs;

use super::*;
use crate::{
    filesystem::PrivateTempDir,
    model::{Dependencies, Operator, Postgres, Runtime as RuntimeConfig, Ui, Valkey},
};

fn config(work: &PrivateTempDir) -> UpdateConfig {
    let config_dir = work.path().join("config");
    let operator_dir = config_dir.join("operator");
    let app = work.path().join("app");
    let secrets = config_dir.join("secrets");
    UpdateConfig {
        schema: 2,
        managed_install: true,
        install_profile: "baseline".to_owned(),
        repository: "nazozero/NazoAuth".to_owned(),
        updater_install_path: work.path().join("bin/nazoauthctl"),
        backup_root: work.path().join("backups"),
        deployment_root: work.path().join("deployments"),
        operator: Operator {
            deployment_id: "deployment-test".to_owned(),
            controller_key_id: "controller-test".to_owned(),
            controller_private_key: operator_dir.join("controller.key"),
            controller_public_key: operator_dir.join("controller.pub"),
            receipt_key_id: "receipt-test".to_owned(),
            receipt_private_key: operator_dir.join("receipt.key"),
            receipt_public_key: operator_dir.join("receipt.pub"),
            audit_key_id: "audit-test".to_owned(),
            audit_private_key: operator_dir.join("audit.key"),
            audit_public_key: operator_dir.join("audit.pub"),
            break_glass_key_id: "break-glass-test".to_owned(),
            break_glass_private_key: work.path().join("recovery/break-glass.key"),
            break_glass_public_key: operator_dir.join("break-glass.pub"),
            secret_revision_file: operator_dir.join("secret-revision"),
            state_directory: app.join("operator-state"),
            audit_directory: work.path().join("audit"),
            trust_state_file: operator_dir.join("release-trust.json"),
        },
        dependencies: Dependencies {
            mode: "external".to_owned(),
            database_url_file: secrets.join("database-url"),
            migration_database_url_file: secrets.join("database-migration-url"),
            valkey_url_file: secrets.join("valkey-url"),
        },
        runtime: RuntimeConfig {
            engine: "podman".to_owned(),
            dependency_engine: "podman".to_owned(),
            container_name: "nazo-oauth-server".to_owned(),
            network: "nazo_oauth_net".to_owned(),
            ip_address: "10.89.0.20".to_owned(),
            publish_address: "127.0.0.1:8000:8000".to_owned(),
            health_url: "http://127.0.0.1:8000/ready".to_owned(),
            readiness_attempts: 60,
            readiness_interval_seconds: 1,
            public_discovery_url: "https://auth.example/.well-known/openid-configuration"
                .to_owned(),
            expected_issuer: "https://auth.example".to_owned(),
            mounts: vec![
                Mount {
                    source: config_dir.join(".env.yaml"),
                    target: PathBuf::from("/app/.env.yaml"),
                    mode: "ro,Z".to_owned(),
                },
                Mount {
                    source: app.join("keys"),
                    target: PathBuf::from("/var/lib/nazo_oauth/keys"),
                    mode: "rw,Z".to_owned(),
                },
                Mount {
                    source: secrets.join("database-url"),
                    target: PathBuf::from("/run/nazoauth-secrets/database-url"),
                    mode: "ro,Z".to_owned(),
                },
                Mount {
                    source: secrets.join("valkey-url"),
                    target: PathBuf::from("/run/nazoauth-secrets/valkey-url"),
                    mode: "ro,Z".to_owned(),
                },
            ],
            snapshot_paths: vec![app.join("keys"), app.join("secrets"), app.join("bootstrap")],
            environment: BTreeMap::from([
                (
                    "DATABASE_URL_FILE".to_owned(),
                    "/run/nazoauth-secrets/database-url".to_owned(),
                ),
                (
                    "VALKEY_URL_FILE".to_owned(),
                    "/run/nazoauth-secrets/valkey-url".to_owned(),
                ),
            ]),
            service_name: String::new(),
            service_user: String::new(),
            binary_path: PathBuf::new(),
            binary_releases: PathBuf::new(),
            working_directory: PathBuf::new(),
        },
        postgres: Postgres {
            container_name: "nazo-oauth-postgres".to_owned(),
            database: "oauth".to_owned(),
            user: "nazoauth_migrator".to_owned(),
            image: "postgres-image".to_owned(),
            validation_image: "postgres-image".to_owned(),
        },
        valkey: Valkey {
            container_name: "nazo-oauth-valkey".to_owned(),
            image: "valkey-image".to_owned(),
            rdb_path: "/data/dump.rdb".to_owned(),
            password_file: PathBuf::new(),
        },
        ui: Ui {
            releases_root: work.path().join("ui-releases"),
        },
    }
}

#[test]
fn privileged_container_task_mounts_are_operation_scoped_and_file_only() {
    let work = PrivateTempDir::new("runtime-task-mounts").unwrap();
    let config = config(&work);
    let runtime = Runtime::new(&config);
    let migration = runtime
        .append_task_mounts(Process::new("podman"), &TaskOperation::MigrateApply, None)
        .unwrap();
    let migration = format!("{migration:?}").replace("\\\\", "\\");

    assert!(migration.contains("DATABASE_URL_FILE=/run/nazoauth-secrets/database-url"));
    assert!(migration.contains("database-migration-url"));
    assert!(!migration.contains("/var/lib/nazo_oauth/keys"));
    assert!(!migration.contains("postgresql://"));

    let public_jwk = work.path().join("public.jwk");
    let keys = runtime
        .append_task_mounts(
            Process::new("podman"),
            &TaskOperation::KeysValidate,
            Some(&public_jwk),
        )
        .unwrap();
    let keys = format!("{keys:?}").replace("\\\\", "\\");

    assert!(keys.contains("/var/lib/nazo_oauth/keys"));
    assert!(keys.contains("/run/nazoauth-operator/public.jwk"));
    assert!(!keys.contains("database-migration-url"));
    assert!(!keys.contains("DATABASE_URL="));
}

#[test]
fn privileged_task_fails_closed_without_required_config_mount() {
    let work = PrivateTempDir::new("runtime-missing-mount").unwrap();
    let mut config = config(&work);
    config
        .runtime
        .mounts
        .retain(|mount| mount.target != Path::new("/app/.env.yaml"));

    let error = Runtime::new(&config)
        .append_task_mounts(Process::new("podman"), &TaskOperation::KeysList, None)
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("runtime mount /app/.env.yaml is unavailable")
    );
}

#[cfg(unix)]
#[test]
fn application_container_command_uses_hardening_and_secret_file_references() {
    use std::os::unix::fs::PermissionsExt as _;

    let work = PrivateTempDir::new("runtime-start-command").unwrap();
    let mut config = config(&work);
    let engine = work.path().join("fake-container-engine");
    let argv = work.path().join("argv.txt");
    fs::write(
        &engine,
        format!("#!/bin/sh\nprintf '%s\\n' \"$@\" > '{}'\n", argv.display()),
    )
    .unwrap();
    fs::set_permissions(&engine, fs::Permissions::from_mode(0o700)).unwrap();
    config.runtime.engine = engine.to_string_lossy().into_owned();
    let raw_secret = "secret-canary-that-must-not-enter-argv";
    fs::create_dir_all(config.dependencies.database_url_file.parent().unwrap()).unwrap();
    fs::write(&config.dependencies.database_url_file, raw_secret).unwrap();

    Runtime::new(&config)
        .start_container("ghcr.io/nazozero/nazoauth@sha256:aaaaaaaa")
        .unwrap();
    let arguments = fs::read_to_string(argv).unwrap();

    for expected in [
        "run",
        "-d",
        "--cap-drop",
        "ALL",
        "no-new-privileges",
        "--read-only",
        "--network",
        "nazo_oauth_net",
        "--ip",
        "10.89.0.20",
        "127.0.0.1:8000:8000",
        "DATABASE_URL_FILE=/run/nazoauth-secrets/database-url",
        "VALKEY_URL_FILE=/run/nazoauth-secrets/valkey-url",
        "ghcr.io/nazozero/nazoauth@sha256:aaaaaaaa",
        "nazoauth",
        "server",
    ] {
        assert!(arguments.lines().any(|argument| argument == expected));
    }
    assert!(!arguments.contains(raw_secret));
    assert!(!arguments.contains("DATABASE_URL="));
    assert!(!arguments.contains("VALKEY_URL="));
}

#[cfg(unix)]
fn write_executable(path: &Path, body: &str) {
    use std::os::unix::fs::PermissionsExt as _;

    fs::write(path, format!("#!/bin/sh\nset -eu\n{body}\n")).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}

#[cfg(unix)]
#[test]
fn pull_image_executes_the_selected_engine_without_secret_arguments() {
    let work = PrivateTempDir::new("runtime-pull-image").unwrap();
    let mut config = config(&work);
    let engine = work.path().join("fake-engine");
    let argv = work.path().join("argv.txt");
    write_executable(
        &engine,
        &format!("printf '%s\\n' \"$@\" > '{}'", argv.display()),
    );
    config.runtime.engine = engine.to_string_lossy().into_owned();
    let image = "ghcr.io/nazozero/nazoauth@sha256:aaaaaaaa";

    Runtime::new(&config).pull_image(image).unwrap();

    assert_eq!(
        fs::read_to_string(argv).unwrap(),
        format!("pull\n{image}\n")
    );
}

#[cfg(unix)]
#[test]
fn image_digest_accepts_an_exact_repo_digest() {
    let work = PrivateTempDir::new("runtime-repo-digest").unwrap();
    let mut config = config(&work);
    let engine = work.path().join("fake-engine");
    let digest = format!("sha256:{}", "a".repeat(64));
    write_executable(
        &engine,
        &format!("printf '%s\\n' '[\"ghcr.io/nazozero/nazoauth@{digest}\"]'"),
    );
    config.runtime.engine = engine.to_string_lossy().into_owned();
    let image = format!("ghcr.io/nazozero/nazoauth@{digest}");

    assert_eq!(Runtime::new(&config).image_digest(&image).unwrap(), digest);
}

#[cfg(unix)]
#[test]
fn image_digest_rejects_unpinned_invalid_and_unretained_references() {
    let work = PrivateTempDir::new("runtime-rejected-digests").unwrap();
    let mut config = config(&work);
    let engine = work.path().join("fake-engine");
    write_executable(&engine, "printf '%s\\n' '[]'");
    config.runtime.engine = engine.to_string_lossy().into_owned();
    let runtime = Runtime::new(&config);

    for (image, expected) in [
        (
            "ghcr.io/nazozero/nazoauth:v0.2.0".to_owned(),
            "managed OCI image reference is not pinned by digest",
        ),
        (
            format!("ghcr.io/nazozero/nazoauth@sha256:{}", "a".repeat(63)),
            "managed OCI image reference has an invalid digest",
        ),
        (
            format!("ghcr.io/nazozero/nazoauth@sha256:{}g", "a".repeat(63)),
            "managed OCI image reference has an invalid digest",
        ),
    ] {
        assert_eq!(
            runtime.image_digest(&image).unwrap_err().to_string(),
            expected
        );
    }

    let valid_but_missing = format!("ghcr.io/nazozero/nazoauth@sha256:{}", "b".repeat(64));
    assert_eq!(
        runtime
            .image_digest(&valid_but_missing)
            .unwrap_err()
            .to_string(),
        "container engine did not retain the signed OCI digest"
    );

    write_executable(&engine, "printf '%s\\n' 'not-json'");
    assert_eq!(
        runtime
            .image_digest(&valid_but_missing)
            .unwrap_err()
            .to_string(),
        "container engine did not retain the signed OCI digest"
    );
}

#[cfg(unix)]
#[test]
fn podman_image_digest_uses_the_engine_digest_fallback() {
    const CHILD: &str = "NAZOAUTHCTL_TEST_PODMAN_DIGEST_FALLBACK";
    let digest = format!("sha256:{}", "c".repeat(64));
    if std::env::var_os(CHILD).is_some() {
        let work = PrivateTempDir::new("runtime-podman-digest-child").unwrap();
        let mut config = config(&work);
        config.runtime.engine = "podman".to_owned();
        let image = format!("ghcr.io/nazozero/nazoauth@{digest}");
        assert_eq!(Runtime::new(&config).image_digest(&image).unwrap(), digest);
        return;
    }

    let work = PrivateTempDir::new("runtime-podman-digest").unwrap();
    let bin = work.path().join("bin");
    fs::create_dir(&bin).unwrap();
    let engine = bin.join("podman");
    write_executable(
        &engine,
        &format!(
            "case \"$5\" in\n  *RepoDigests*) printf '%s\\n' '[]' ;;\n  *) printf '%s\\n' '{digest}' ;;\nesac"
        ),
    );
    let mut paths = vec![bin];
    if let Some(path) = std::env::var_os("PATH") {
        paths.extend(std::env::split_paths(&path));
    }
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "runtime::tests::podman_image_digest_uses_the_engine_digest_fallback",
            "--nocapture",
        ])
        .env("PATH", std::env::join_paths(paths).unwrap())
        .env("NAZOAUTHCTL_TESTING", "1")
        .env(CHILD, "1")
        .status()
        .unwrap();
    assert!(status.success());
}

#[cfg(unix)]
#[test]
fn podman_image_digest_rejects_a_mismatched_fallback_digest() {
    const CHILD: &str = "NAZOAUTHCTL_TEST_PODMAN_DIGEST_MISMATCH";
    let image = format!("ghcr.io/nazozero/nazoauth@sha256:{}", "e".repeat(64));
    if std::env::var_os(CHILD).is_some() {
        let work = PrivateTempDir::new("runtime-podman-mismatch-child").unwrap();
        let mut config = config(&work);
        config.runtime.engine = "podman".to_owned();
        assert_eq!(
            Runtime::new(&config)
                .image_digest(&image)
                .unwrap_err()
                .to_string(),
            "container engine did not retain the signed OCI digest"
        );
        return;
    }

    let work = PrivateTempDir::new("runtime-podman-mismatch").unwrap();
    let bin = work.path().join("bin");
    fs::create_dir(&bin).unwrap();
    write_executable(
        &bin.join("podman"),
        &format!(
            "case \"$5\" in\n  *RepoDigests*) printf '%s\\n' '[]' ;;\n  *) printf '%s\\n' 'sha256:{}' ;;\nesac",
            "d".repeat(64)
        ),
    );
    let mut paths = vec![bin];
    if let Some(path) = std::env::var_os("PATH") {
        paths.extend(std::env::split_paths(&path));
    }
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "runtime::tests::podman_image_digest_rejects_a_mismatched_fallback_digest",
            "--nocapture",
        ])
        .env("PATH", std::env::join_paths(paths).unwrap())
        .env("NAZOAUTHCTL_TESTING", "1")
        .env(CHILD, "1")
        .status()
        .unwrap();
    assert!(status.success());
}

#[cfg(unix)]
fn embedded_identity_json() -> String {
    serde_json::to_string(&nazo_operator_protocol::EmbeddedIdentity {
        release: "v0.2.0".to_owned(),
        revision: "f".repeat(40),
        protocol: nazo_operator_protocol::PROTOCOL_VERSION,
        build_id: "build:test".to_owned(),
    })
    .unwrap()
}

#[cfg(unix)]
#[test]
fn embedded_identity_executes_host_binary_directly() {
    let work = PrivateTempDir::new("runtime-host-identity").unwrap();
    let mut config = config(&work);
    config.runtime.engine = "host".to_owned();
    let binary = work.path().join("nazoauth");
    let argv = work.path().join("argv.txt");
    write_executable(
        &binary,
        &format!(
            "printf '%s\\n' \"$@\" > '{}'\nprintf '%s\\n' '{}'",
            argv.display(),
            embedded_identity_json()
        ),
    );

    let identity = Runtime::new(&config)
        .embedded_identity(&binary.to_string_lossy())
        .unwrap();

    assert_eq!(identity.release, "v0.2.0");
    assert_eq!(fs::read_to_string(argv).unwrap(), "build-identity\n");
}

#[cfg(unix)]
#[test]
fn embedded_identity_container_is_networkless_and_hardened() {
    let work = PrivateTempDir::new("runtime-container-identity").unwrap();
    let mut config = config(&work);
    let engine = work.path().join("fake-engine");
    let argv = work.path().join("argv.txt");
    write_executable(
        &engine,
        &format!(
            "printf '%s\\n' \"$@\" > '{}'\nprintf '%s\\n' '{}'",
            argv.display(),
            embedded_identity_json()
        ),
    );
    config.runtime.engine = engine.to_string_lossy().into_owned();
    let image = "ghcr.io/nazozero/nazoauth@sha256:ffffffff";

    let identity = Runtime::new(&config).embedded_identity(image).unwrap();
    let arguments = fs::read_to_string(argv).unwrap();

    assert_eq!(identity.release, "v0.2.0");
    for expected in [
        "run",
        "--rm",
        "--network",
        "none",
        "--cap-drop",
        "ALL",
        "no-new-privileges",
        "--read-only",
        image,
        "nazoauth",
        "build-identity",
    ] {
        assert!(arguments.lines().any(|argument| argument == expected));
    }
}

#[cfg(unix)]
#[test]
fn embedded_identity_rejects_invalid_application_output() {
    let work = PrivateTempDir::new("runtime-invalid-identity").unwrap();
    let mut config = config(&work);
    config.runtime.engine = "host".to_owned();
    let binary = work.path().join("nazoauth");
    write_executable(&binary, "printf '%s\\n' 'not-json'");

    let error = Runtime::new(&config)
        .embedded_identity(&binary.to_string_lossy())
        .unwrap_err();
    assert!(format!("{error:#}").contains("runtime embedded build identity is invalid"));
}
