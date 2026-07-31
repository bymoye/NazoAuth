use std::fs;

use super::*;
use crate::filesystem::PrivateTempDir;

#[test]
fn managed_dependency_credentials_are_outside_runtime_secret_directory() {
    let work = PrivateTempDir::new("managed-secret-boundaries").unwrap();
    let secrets = work.path().join("secrets");
    fs::create_dir(&secrets).unwrap();

    assert_eq!(write_managed_secrets(&secrets).unwrap(), "managed");

    let dependencies = secrets.join("dependencies");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(
            fs::metadata(&dependencies).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }
    for name in [
        "postgres-password",
        "postgres-runtime-password",
        "valkey-password",
        "valkey.acl",
    ] {
        assert!(dependencies.join(name).is_file());
        assert!(!secrets.join(name).exists());
    }
    for name in ["database-url", "database-migration-url", "valkey-url"] {
        assert!(secrets.join(name).is_file());
    }

    let runtime_url = fs::read_to_string(secrets.join("database-url")).unwrap();
    let migration_url = fs::read_to_string(secrets.join("database-migration-url")).unwrap();
    assert!(runtime_url.contains("nazoauth_runtime"));
    assert!(migration_url.contains("nazoauth_migrator"));
    assert_ne!(runtime_url, migration_url);
}

#[test]
fn systemd_version_parser_is_closed() {
    assert_eq!(
        parse_systemd_version("systemd 252 (252.39-1)\n+PAM").unwrap(),
        252
    );
    assert!(parse_systemd_version("252\n").is_err());
    assert!(parse_systemd_version("systemd unknown\n").is_err());
}

#[test]
fn host_service_unit_exposes_only_runtime_state() {
    let unit = HostSystemdUnit {
        user: "nazoauth",
        working: Path::new("/etc/nazoauth"),
        binary: Path::new("/usr/local/bin/nazoauth"),
        app_root: Path::new("/var/lib/nazoauth/app"),
        ui_releases: Path::new("/var/lib/nazoauth/ui-releases"),
        operator_state: Path::new("/var/lib/nazoauth/app/operator-state"),
        operator_dir: Path::new("/etc/nazoauth/operator"),
        migration_url: Path::new("/etc/nazoauth/secrets/database-migration-url"),
    }
    .render()
    .replace('\\', "/");

    assert!(unit.contains("User=nazoauth\nGroup=nazoauth"));
    assert!(unit.contains(
        "ReadWritePaths=/var/lib/nazoauth/app/keys /var/lib/nazoauth/app/avatars /var/lib/nazoauth/app/secrets /var/lib/nazoauth/app/bootstrap"
    ));
    assert!(unit.contains("ReadOnlyPaths=/var/lib/nazoauth/ui-releases"));
    assert!(unit.contains(
        "InaccessiblePaths=/var/lib/nazoauth/app/operator-state /etc/nazoauth/operator /etc/nazoauth/secrets/database-migration-url"
    ));
    assert!(!unit.contains("ReadWritePaths=/var/lib/nazoauth/app\n"));
}
