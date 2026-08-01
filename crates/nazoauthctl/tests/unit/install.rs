use std::fs;

use super::*;
use crate::filesystem::PrivateTempDir;

fn install_options(data_root: PathBuf) -> InstallOptions {
    InstallOptions {
        runtime: "podman".to_owned(),
        public_url: "https://auth.example".to_owned(),
        profile: "baseline".to_owned(),
        profile_material: None,
        data_root,
        port: 8000,
        database_url: None,
        migration_database_url: None,
        valkey_url: None,
        external_dependencies: false,
        secrets_stdin: false,
        secret_fd: None,
        profile_secrets_stdin: false,
        profile_secret_fd: None,
        profile_secrets: None,
        version: Some("v0.2.0".to_owned()),
    }
}

#[test]
fn public_origin_rejects_embedded_credentials() {
    for value in [
        "https://operator@auth.example",
        "https://operator:secret@auth.example",
    ] {
        let error = validate_public_url(value).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("--public-url must be an absolute HTTP(S) origin"),
            "unexpected error for {value}: {error:#}"
        );
    }
}

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
    fs::create_dir(&config).unwrap();
    fs::create_dir(config.join("secrets")).unwrap();
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
            "backchannel_logout_private_origins": ["https://suite.example"]
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
        profile_secrets_stdin: false,
        profile_secret_fd: None,
        profile_secrets: None,
        version: Some("v1.2.3".to_owned()),
    };

    let rendered = write_install_profile(&config, &options).unwrap().unwrap();

    for name in STANDARDS_PROFILE_SECRET_NAMES {
        let value = fs::read_to_string(config.join("secrets").join(name)).unwrap();
        if *name != "openid4vc-data-encryption-key" {
            assert!(value.len() >= MIN_PROFILE_SECRET_VALUE_BYTES);
        }
        assert!(!rendered.contains(&value));
        assert!(rendered.contains(&format!("${{PROFILE_SECRET_ROOT}}/{name}")));
    }
    assert!(rendered.contains("ENABLE_OPENID4VCI_ISSUER: true"));
    assert!(rendered.contains("ENABLE_OPENID4VP_VERIFIER: true"));
    assert_eq!(
        rendered.matches("openid4vc-certificate-bundle.pem").count(),
        2
    );
    assert!(!rendered.contains("PRIVATE KEY"));
}

#[test]
fn oidf_profile_secret_override_is_strict_private_and_resumable() {
    let work = PrivateTempDir::new("oidf-install-profile-secret-override").unwrap();
    let config = work.path().join("config");
    fs::create_dir(&config).unwrap();
    fs::create_dir(config.join("secrets")).unwrap();
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
            "backchannel_logout_private_origins": ["https://suite.example"]
        }))
        .unwrap(),
    )
    .unwrap();
    let canary = "x".repeat(32);
    let mut options = install_options(work.path().join("data"));
    options.profile = "standards-full".to_owned();
    options.profile_material = Some(material);
    options.profile_secrets = Some(StandardsProfileSecrets {
        dynamic_registration_initial_access_token: format!("dynamic-{canary}"),
        ciba_automated_decision_token: format!("ciba-{canary}"),
        openid4vci_management_token: format!("issuer-{canary}"),
        openid4vp_management_token: format!("verifier-{canary}"),
    });

    let rendered = write_install_profile(&config, &options).unwrap().unwrap();
    assert!(!rendered.contains(&canary));
    assert_eq!(
        fs::read_to_string(config.join("secrets/dynamic-registration-token")).unwrap(),
        format!("dynamic-{canary}")
    );
    assert_eq!(
        fs::read_to_string(config.join("secrets/openid4vp-management-token")).unwrap(),
        format!("verifier-{canary}")
    );
    assert!(write_install_profile(&config, &options).is_ok());

    let mut mismatched = install_options(work.path().join("data"));
    mismatched.profile = "standards-full".to_owned();
    mismatched.profile_material = options.profile_material.clone();
    mismatched.profile_secrets = Some(StandardsProfileSecrets {
        dynamic_registration_initial_access_token: "other-secret-value-that-is-at-least-32"
            .to_owned(),
        ciba_automated_decision_token: format!("ciba-{canary}"),
        openid4vci_management_token: format!("issuer-{canary}"),
        openid4vp_management_token: format!("verifier-{canary}"),
    });
    let error = write_install_profile(&config, &mismatched).unwrap_err();
    assert!(!format!("{error:#}").contains(&canary));
}

#[test]
fn profile_secret_input_is_closed_bounded_and_never_echoed() {
    let work = PrivateTempDir::new("profile-secret-input").unwrap();
    let canary = "profile-secret-canary-that-is-long-enough";
    let valid = serde_json::json!({
        "dynamic_registration_initial_access_token": canary,
        "ciba_automated_decision_token": canary,
        "openid4vci_management_token": canary,
        "openid4vp_management_token": canary,
    });
    let mut options = install_options(work.path().join("data"));
    options.profile = "standards-full".to_owned();
    read_profile_secrets(
        &mut options,
        std::io::Cursor::new(serde_json::to_vec(&valid).unwrap()),
    )
    .unwrap();
    assert_eq!(
        options
            .profile_secrets
            .as_ref()
            .unwrap()
            .openid4vci_management_token,
        canary
    );

    for invalid in [
        br#"{"dynamic_registration_initial_access_token":"profile-secret-canary-that-is-long-enough","ciba_automated_decision_token":"profile-secret-canary-that-is-long-enough","openid4vci_management_token":"profile-secret-canary-that-is-long-enough","openid4vp_management_token":"profile-secret-canary-that-is-long-enough","unexpected":"profile-secret-canary-that-is-long-enough"}"#.as_slice(),
        br#"{"dynamic_registration_initial_access_token":"short","ciba_automated_decision_token":"profile-secret-canary-that-is-long-enough","openid4vci_management_token":"profile-secret-canary-that-is-long-enough","openid4vp_management_token":"profile-secret-canary-that-is-long-enough"}"#.as_slice(),
        br#"{"dynamic_registration_initial_access_token":"profile-secret-canary-that-is-long-enough\n","ciba_automated_decision_token":"profile-secret-canary-that-is-long-enough","openid4vci_management_token":"profile-secret-canary-that-is-long-enough","openid4vp_management_token":"profile-secret-canary-that-is-long-enough"}"#.as_slice(),
    ] {
        let mut options = install_options(work.path().join("invalid-data"));
        let error = read_profile_secrets(&mut options, std::io::Cursor::new(invalid)).unwrap_err();
        assert!(!format!("{error:#}").contains("profile-secret-canary"));
        assert!(options.profile_secrets.is_none());
    }

    let mut oversized = install_options(work.path().join("oversized-data"));
    let error = read_profile_secrets(
        &mut oversized,
        std::io::Cursor::new(vec![b' '; 32 * 1024 + 1]),
    )
    .unwrap_err();
    assert_eq!(error.to_string(), "profile secret input exceeds 32 KiB");
}

#[test]
fn profile_secret_channels_fail_closed_without_consuming_ambiguous_stdin() {
    let work = PrivateTempDir::new("profile-secret-channels").unwrap();
    let mut stdin_conflict = install_options(work.path().join("stdin-conflict"));
    stdin_conflict.profile = "standards-full".to_owned();
    stdin_conflict.secrets_stdin = true;
    stdin_conflict.profile_secrets_stdin = true;
    assert_eq!(
        normalize_profile_secrets(&mut stdin_conflict)
            .unwrap_err()
            .to_string(),
        "--secrets-stdin and --profile-secrets-stdin both consume stdin; use separate FDs instead"
    );

    let mut fd_conflict = install_options(work.path().join("fd-conflict"));
    fd_conflict.profile = "standards-full".to_owned();
    fd_conflict.secret_fd = Some(7);
    fd_conflict.profile_secret_fd = Some(7);
    assert_eq!(
        normalize_profile_secrets(&mut fd_conflict)
            .unwrap_err()
            .to_string(),
        "--secret-fd and --profile-secret-fd must use different FDs"
    );

    let mut baseline = install_options(work.path().join("baseline"));
    baseline.profile_secrets_stdin = true;
    assert_eq!(
        normalize_profile_secrets(&mut baseline)
            .unwrap_err()
            .to_string(),
        "secure profile secret input requires --profile standards-full"
    );
}

#[test]
fn oidf_profile_rejects_legacy_external_openid4vc_trust_anchors() {
    let work = PrivateTempDir::new("oidf-install-profile-legacy-anchor").unwrap();
    let config = work.path().join("config");
    fs::create_dir(&config).unwrap();
    fs::create_dir(config.join("secrets")).unwrap();
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
            "trust_anchors_pem": "-----BEGIN CERTIFICATE-----\\nlegacy\\n-----END CERTIFICATE-----\\n"
        }))
        .unwrap(),
    )
    .unwrap();
    let mut options = install_options(work.path().join("data"));
    options.profile = "standards-full".to_owned();
    options.profile_material = Some(material);

    let error = write_install_profile(&config, &options).unwrap_err();
    assert!(error.to_string().contains("strict JSON"));
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

#[test]
fn external_dependency_secret_input_is_bounded_closed_and_value_opaque() {
    let work = PrivateTempDir::new("external-secret-input").unwrap();
    let valid = br#"{
        "database_url":"postgresql://runtime:runtime-secret@db.example/oauth",
        "migration_database_url":"postgresql://migrator:migration-secret@db.example/oauth",
        "valkey_url":"rediss://default:valkey-secret@cache.example/0"
    }"#;
    let mut options = install_options(work.path().join("data"));
    read_external_dependency_secrets(&mut options, std::io::Cursor::new(valid)).unwrap();
    assert_eq!(
        options.database_url.as_deref(),
        Some("postgresql://runtime:runtime-secret@db.example/oauth")
    );
    assert_eq!(
        options.migration_database_url.as_deref(),
        Some("postgresql://migrator:migration-secret@db.example/oauth")
    );
    assert_eq!(
        options.valkey_url.as_deref(),
        Some("rediss://default:valkey-secret@cache.example/0")
    );

    for invalid in [
        br#"{"database_url":"postgresql://db.example/oauth","migration_database_url":"postgresql://db.example/oauth"}"#.as_slice(),
        br#"{"database_url":"postgresql://db.example/oauth","migration_database_url":"postgresql://db.example/oauth","valkey_url":"redis://cache.example/0","unexpected":"secret-canary"}"#.as_slice(),
        br#"{"database_url":"postgresql://db.example/oauth","migration_database_url":"postgresql://db.example/oauth","valkey_url":"redis://cache.example/0"} trailing"#.as_slice(),
    ] {
        let mut options = install_options(work.path().join("invalid-data"));
        let error = read_external_dependency_secrets(&mut options, std::io::Cursor::new(invalid))
            .unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("dependency secret input must be strict JSON"));
        assert!(!message.contains("secret-canary"));
        assert!(options.database_url.is_none());
        assert!(options.migration_database_url.is_none());
        assert!(options.valkey_url.is_none());
    }

    let mut options = install_options(work.path().join("oversized-data"));
    let error = read_external_dependency_secrets(
        &mut options,
        std::io::Cursor::new(vec![b' '; 64 * 1024 + 1]),
    )
    .unwrap_err();
    assert_eq!(error.to_string(), "dependency secret input exceeds 64 KiB");
}

#[test]
fn dependency_secret_channels_and_url_set_fail_closed() {
    let work = PrivateTempDir::new("external-secret-boundaries").unwrap();

    let mut without_external = install_options(work.path().join("without-external"));
    without_external.secrets_stdin = true;
    assert_eq!(
        normalize_external_dependencies(&mut without_external)
            .unwrap_err()
            .to_string(),
        "secure dependency secret input requires --external-dependencies"
    );

    let mut conflicting = install_options(work.path().join("conflicting"));
    conflicting.external_dependencies = true;
    conflicting.secrets_stdin = true;
    conflicting.secret_fd = Some(3);
    assert_eq!(
        normalize_external_dependencies(&mut conflicting)
            .unwrap_err()
            .to_string(),
        "choose exactly one of --secrets-stdin or --secret-fd"
    );

    let mut partial = install_options(work.path().join("partial"));
    partial.database_url = Some("postgresql://runtime@db.example/oauth".to_owned());
    assert!(
        normalize_external_dependencies(&mut partial)
            .unwrap_err()
            .to_string()
            .contains("require runtime PostgreSQL, migration PostgreSQL, and Valkey URLs")
    );

    let mut invalid_scheme = install_options(work.path().join("invalid-scheme"));
    invalid_scheme.database_url = Some("https://db.example/oauth".to_owned());
    invalid_scheme.migration_database_url =
        Some("postgresql://migrator@db.example/oauth".to_owned());
    invalid_scheme.valkey_url = Some("redis://cache.example/0".to_owned());
    assert!(
        normalize_external_dependencies(&mut invalid_scheme)
            .unwrap_err()
            .to_string()
            .contains("PostgreSQL URL has an unsupported scheme or no host")
    );
}

#[test]
fn external_urls_are_persisted_only_as_private_secret_files() {
    let work = PrivateTempDir::new("external-url-files").unwrap();
    let secrets = work.path().join("secrets");
    fs::create_dir(&secrets).unwrap();
    let mut options = install_options(work.path().join("data"));
    options.database_url = Some("postgresql://runtime:one@db.example/oauth".to_owned());
    options.migration_database_url = Some("postgresql://migrator:two@db.example/oauth".to_owned());
    options.valkey_url = Some("rediss://default:three@cache.example/0".to_owned());

    assert_eq!(write_external_urls(&secrets, &options).unwrap(), "external");
    assert_eq!(
        fs::read_to_string(secrets.join("database-url")).unwrap(),
        options.database_url.unwrap()
    );
    assert_eq!(
        fs::read_to_string(secrets.join("database-migration-url")).unwrap(),
        options.migration_database_url.unwrap()
    );
    assert_eq!(
        fs::read_to_string(secrets.join("valkey-url")).unwrap(),
        options.valkey_url.unwrap()
    );
    #[cfg(unix)]
    for name in ["database-url", "database-migration-url", "valkey-url"] {
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(
            fs::metadata(secrets.join(name))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o440
        );
    }
}

#[cfg(unix)]
#[test]
fn generated_container_config_exposes_secret_files_but_not_secret_values() {
    let work = PrivateTempDir::new("container-config-boundary").unwrap();
    let config_dir = work.path().join("config");
    let mut options = install_options(work.path().join("data"));
    operator::initialize_identity_generation(
        &config_dir.join("operator"),
        &options.data_root.join("recovery"),
    )
    .unwrap();
    options.profile = "standards-full".to_owned();
    let config_path = config_dir.join("update.json");
    let config = build_config(&config_path, &options, "podman", "podman", "external").unwrap();
    let rendered = serde_json::to_string(&config).unwrap();

    assert_eq!(config.runtime.publish_address, "127.0.0.1:8000:8000");
    assert_eq!(
        config.runtime.environment.get("DATABASE_URL_FILE"),
        Some(&"/run/nazoauth-secrets/database-url".to_owned())
    );
    assert_eq!(
        config.runtime.environment.get("VALKEY_URL_FILE"),
        Some(&"/run/nazoauth-secrets/valkey-url".to_owned())
    );
    assert!(config.runtime.mounts.iter().any(|mount| {
        mount.target == Path::new("/run/nazoauth-secrets/database-url") && mount.mode == "ro,Z"
    }));
    assert!(!config.runtime.mounts.iter().any(|mount| {
        mount.target == Path::new("/run/nazoauth-secrets/database-migration-url")
    }));
    for name in STANDARDS_PROFILE_SECRET_NAMES {
        let expected = PathBuf::from(format!("/run/nazoauth-secrets/{name}"));
        assert!(
            config
                .runtime
                .mounts
                .iter()
                .any(|mount| { mount.target == expected && mount.mode == "ro,Z" })
        );
    }
    assert!(
        !config
            .runtime
            .snapshot_paths
            .contains(&config_dir.join("secrets"))
    );
    assert!(
        !config
            .runtime
            .snapshot_paths
            .contains(&options.data_root.join("recovery"))
    );
    assert!(!rendered.contains("postgresql://"));
    assert!(!rendered.contains("redis://"));

    let error = build_config(
        &config_path,
        &options,
        "unsupported-runtime",
        "podman",
        "external",
    )
    .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("runtime engine must be podman, docker, or host")
    );
}

#[cfg(unix)]
#[test]
fn managed_directory_rejects_symlink_targets() {
    use std::os::unix::fs::symlink;

    let work = PrivateTempDir::new("install-directory-symlink").unwrap();
    let real = work.path().join("real");
    let linked = work.path().join("linked");
    fs::create_dir(&real).unwrap();
    symlink(&real, &linked).unwrap();

    let error = create_directory(&linked, 0o700).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("managed directory must not be a symlink")
    );
}

#[test]
fn lifecycle_install_platform_boundary_is_linux_x86_64_and_arm64_only() {
    assert!(install_platform_supported("linux", "x86_64"));
    assert!(install_platform_supported("linux", "aarch64"));
    for (os, arch) in [
        ("linux", "arm"),
        ("linux", "s390x"),
        ("windows", "x86_64"),
        ("windows", "aarch64"),
        ("macos", "x86_64"),
        ("macos", "aarch64"),
    ] {
        assert!(!install_platform_supported(os, arch));
    }
}
