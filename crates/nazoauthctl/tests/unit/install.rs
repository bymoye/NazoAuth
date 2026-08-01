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
fn generated_install_paths_are_safe_for_yaml_systemd_and_container_mounts() {
    validate_install_path(Path::new("/var/lib/nazoauth-0.2/app_data"), "data root").unwrap();
    for path in [
        "/var/lib/nazo auth",
        "/var/lib/nazoauth\nINJECTED: true",
        "/var/lib/nazoauth:other",
        "/var/lib/nazoauth\"",
    ] {
        assert!(validate_install_path(Path::new(path), "data root").is_err());
    }
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
        recovery_dir: Path::new("/var/lib/nazoauth/recovery"),
        migration_url: Path::new("/etc/nazoauth/secrets/database-migration-url"),
    }
    .render()
    .replace('\\', "/");

    assert!(unit.contains("User=nazoauth\nGroup=nazoauth"));
    assert!(unit.contains(
        "ReadWritePaths=/var/lib/nazoauth/app/keys /var/lib/nazoauth/app/avatars /var/lib/nazoauth/app/secrets /var/lib/nazoauth/app/bootstrap /var/lib/nazoauth/ui-releases"
    ));
    assert!(!unit.contains("ReadOnlyPaths=/var/lib/nazoauth/ui-releases"));
    assert!(unit.contains(
        "InaccessiblePaths=/var/lib/nazoauth/app/operator-state /etc/nazoauth/operator /var/lib/nazoauth/recovery /etc/nazoauth/secrets/database-migration-url"
    ));
    assert!(!unit.contains("ReadWritePaths=/var/lib/nazoauth/app\n"));
}

#[test]
fn oidf_profile_material_generates_only_file_references_for_secrets() {
    let work = PrivateTempDir::new("oidf-install-profile").unwrap();
    let config = work.path().join("config");
    let app = work.path().join("app");
    fs::create_dir(&config).unwrap();
    fs::create_dir(config.join("secrets")).unwrap();
    fs::create_dir(&app).unwrap();
    fs::create_dir(app.join("keys")).unwrap();
    let material = work.path().join("profile.json");
    fs::write(
        &material,
        serde_json::to_vec(&serde_json::json!({
            "client_attestation_issuer": "https://attester.example/",
            "client_attestation_jwks": {"keys":[{"kty":"EC","crv":"P-256","x":"x","y":"y"}]},
            "key_attestation_jwks": {"keys":[{"kty":"EC","crv":"P-256","x":"x","y":"y"}]},
            "credential_configurations": {"example":{"format":"dc+sd-jwt","scope":"example"}},
            "wallet_authorization_origins": ["https://suite.example"],
            "ciba_notification_private_origins": ["https://suite.example"],
            "backchannel_logout_private_origins": ["https://suite.example"],
            "trust_anchors_pem": "-----BEGIN CERTIFICATE-----\nY2E=\n-----END CERTIFICATE-----\n"
        }))
        .unwrap(),
    )
    .unwrap();
    let options = InstallOptions {
        runtime: "podman".to_owned(),
        public_url: "https://auth.example".to_owned(),
        profile: "standards-full".to_owned(),
        profile_material: Some(material),
        data_root: work.path().join("data"),
        port: 8000,
        database_url: None,
        migration_database_url: None,
        valkey_url: None,
        external_dependencies: false,
        secrets_stdin: false,
        secret_fd: None,
        version: Some("v1.2.3".to_owned()),
    };

    let rendered = write_install_profile(&config, &app, &options)
        .unwrap()
        .unwrap();

    for name in STANDARDS_PROFILE_SECRET_NAMES {
        let value = fs::read_to_string(config.join("secrets").join(name)).unwrap();
        assert!(!rendered.contains(&value));
        assert!(rendered.contains(&format!("${{PROFILE_SECRET_ROOT}}/{name}")));
    }
    assert!(rendered.contains("ENABLE_OPENID4VCI_ISSUER: true"));
    assert!(rendered.contains("ENABLE_OPENID4VP_VERIFIER: true"));
    assert!(!rendered.contains("PRIVATE KEY"));
}

#[test]
fn oidf_profile_rejects_private_jwk_material() {
    assert!(
        validate_public_jwks(
            &serde_json::json!({"keys":[{"kty":"EC","d":"private"}]}),
            "test JWKS"
        )
        .is_err()
    );
}

#[test]
fn oidf_profile_origins_are_strict_https_origins() {
    for accepted in ["https://suite.example", "https://suite.example:8443/"] {
        validate_https_origin(accepted, "suite origin").unwrap();
    }
    for rejected in [
        "http://suite.example",
        "https://user@suite.example",
        "https://suite.example/path",
        "https://suite.example?query=1",
        "https://suite.example/#fragment",
    ] {
        assert!(
            validate_https_origin(rejected, "suite origin").is_err(),
            "accepted invalid origin {rejected}"
        );
    }
}

#[test]
fn trusted_proxy_gateway_uses_a_single_host_prefix_for_each_address_family() {
    assert_eq!(host_cidr("10.89.0.1".parse().unwrap()), "10.89.0.1/32");
    assert_eq!(host_cidr("fd00::1".parse().unwrap()), "fd00::1/128");
}
