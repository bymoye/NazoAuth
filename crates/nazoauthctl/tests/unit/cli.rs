use super::*;

fn parse(values: &[&str]) -> anyhow::Result<Option<Cli>> {
    Cli::parse(values.iter().map(|value| (*value).to_owned()))
}

#[test]
fn parses_container_install_with_secure_dependency_input() {
    let cli = parse(&[
        "nazoauthctl",
        "--config",
        "/tmp/update.json",
        "install",
        "--runtime",
        "docker",
        "--external-dependencies",
        "--secrets-stdin",
    ])
    .unwrap()
    .unwrap();
    assert_eq!(cli.config, PathBuf::from("/tmp/update.json"));
    let Command::Install(options) = cli.command else {
        panic!("expected install");
    };
    assert_eq!(options.runtime, "docker");
    assert!(options.external_dependencies);
    assert!(options.secrets_stdin);
    assert!(options.database_url.is_none());
    assert!(options.profile_secrets.is_none());
}

#[test]
fn dependency_secrets_are_rejected_in_argv() {
    assert!(
        parse(&[
            "nazoauthctl",
            "install",
            "--external-dependencies",
            "--database-url",
            "postgresql://user:password@db/oauth",
        ])
        .is_err()
    );
}

#[test]
fn bootstrap_admin_accepts_only_explicit_secret_input_modes() {
    let command = parse(&[
        "nazoauthctl",
        "bootstrap-admin",
        "--credentials-stdin",
        "--yes",
    ])
    .unwrap()
    .unwrap()
    .command;
    assert!(matches!(
        command,
        Command::BootstrapAdmin(BootstrapAdminOptions {
            credentials_stdin: true,
            yes: true,
        })
    ));

    assert!(matches!(
        parse(&["nazoauthctl", "bootstrap-admin"])
            .unwrap()
            .unwrap()
            .command,
        Command::BootstrapAdmin(BootstrapAdminOptions {
            credentials_stdin: false,
            yes: false,
        })
    ));

    for arguments in [
        &[
            "nazoauthctl",
            "bootstrap-admin",
            "--email",
            "admin@example.com",
        ][..],
        &["nazoauthctl", "bootstrap-admin", "--password", "secret"][..],
        &["nazoauthctl", "bootstrap-admin", "--yes", "--yes"][..],
        &[
            "nazoauthctl",
            "bootstrap-admin",
            "--credentials-stdin",
            "--credentials-stdin",
        ][..],
    ] {
        assert!(parse(arguments).is_err(), "accepted {arguments:?}");
    }
}

#[test]
fn update_rejects_mutable_versions() {
    assert!(parse(&["nazoauthctl", "update", "--to", "latest"]).is_err());
}

#[test]
fn audit_show_accepts_only_a_safe_optional_request_id() {
    let cli = parse(&[
        "nazoauthctl",
        "audit",
        "show",
        "--request-id",
        "request-0123",
    ])
    .unwrap()
    .unwrap();
    assert!(matches!(
        cli.command,
        Command::AuditShow {
            request_id: Some(ref value)
        } if value == "request-0123"
    ));
    assert!(parse(&["nazoauthctl", "audit", "show", "--request-id", "../key"]).is_err());
}

#[test]
fn parses_every_read_only_command_and_help_boundary() {
    assert!(parse(&["nazoauthctl"]).unwrap().is_none());
    assert!(parse(&["nazoauthctl", "--help"]).unwrap().is_none());

    for (arguments, expected) in [
        (&["nazoauthctl", "status"][..], "status"),
        (&["nazoauthctl", "doctor"][..], "doctor"),
        (&["nazoauthctl", "check"][..], "check"),
        (&["nazoauthctl", "keys", "list"][..], "keys-list"),
        (&["nazoauthctl", "keys", "validate"][..], "keys-validate"),
        (&["nazoauthctl", "audit", "verify"][..], "audit-verify"),
        (&["nazoauthctl", "audit", "show"][..], "audit-show"),
    ] {
        let command = parse(arguments).unwrap().unwrap().command;
        assert!(matches!(
            (expected, command),
            ("status", Command::Status)
                | ("doctor", Command::Doctor)
                | ("check", Command::Check(None))
                | ("keys-list", Command::Keys(KeysCommand::List))
                | ("keys-validate", Command::Keys(KeysCommand::Validate))
                | ("audit-verify", Command::AuditVerify)
                | ("audit-show", Command::AuditShow { request_id: None })
        ));
    }

    let command = parse(&["nazoauthctl", "check", "--to", "v1.2.3"])
        .unwrap()
        .unwrap()
        .command;
    assert!(matches!(command, Command::Check(Some(version)) if version == "v1.2.3"));
}

#[test]
fn help_topics_follow_user_intent_even_with_an_explicit_config() {
    let values = |parts: &[&str]| {
        parts
            .iter()
            .map(|value| (*value).to_owned())
            .collect::<Vec<_>>()
    };
    assert_eq!(
        help_topic(&values(&["nazoauthctl", "--help"])),
        Some(HelpTopic::TopLevel)
    );
    assert_eq!(
        help_topic(&values(&["nazoauthctl", "install", "--help"])),
        Some(HelpTopic::Install)
    );
    assert_eq!(
        help_topic(&values(&["nazoauthctl", "bootstrap-admin", "--help"])),
        Some(HelpTopic::BootstrapAdmin)
    );
    assert_eq!(
        help_topic(&values(&[
            "nazoauthctl",
            "--config",
            "/tmp/update.json",
            "update",
            "--help",
        ])),
        Some(HelpTopic::Update)
    );
    assert_eq!(help_topic(&values(&["nazoauthctl", "status"])), None);
}

#[test]
fn parses_complete_install_contract_and_rejects_invalid_boundaries() {
    let command = parse(&[
        "nazoauthctl",
        "install",
        "--runtime",
        "host",
        "--public-url",
        "https://auth.example",
        "--profile",
        "standards-full",
        "--profile-material",
        "/srv/oidf-profile.json",
        "--data-root",
        "/srv/nazoauth",
        "--port",
        "8443",
        "--external-dependencies",
        "--secret-fd",
        "9",
        "--profile-secret-fd",
        "10",
        "--to",
        "v1.2.3",
    ])
    .unwrap()
    .unwrap()
    .command;
    let Command::Install(options) = command else {
        panic!("expected install");
    };
    assert_eq!(options.runtime, "host");
    assert_eq!(options.public_url, "https://auth.example");
    assert_eq!(options.profile, "standards-full");
    assert_eq!(
        options.profile_material,
        Some(PathBuf::from("/srv/oidf-profile.json"))
    );
    assert_eq!(options.data_root, PathBuf::from("/srv/nazoauth"));
    assert_eq!(options.port, 8443);
    assert_eq!(options.secret_fd, Some(9));
    assert_eq!(options.profile_secret_fd, Some(10));
    assert_eq!(options.version.as_deref(), Some("v1.2.3"));

    for arguments in [
        &["nazoauthctl", "install", "--runtime", "other"][..],
        &["nazoauthctl", "install", "--port", "0"][..],
        &["nazoauthctl", "install", "--port", "text"][..],
        &["nazoauthctl", "install", "--secret-fd", "text"][..],
        &["nazoauthctl", "install", "--secret-fd", "0"][..],
        &[
            "nazoauthctl",
            "install",
            "--profile",
            "standards-full",
            "--profile-material",
            "/tmp/material.json",
            "--profile-secret-fd",
            "2",
        ][..],
        &["nazoauthctl", "install", "--profile", "standards-full"][..],
        &[
            "nazoauthctl",
            "install",
            "--profile-material",
            "/tmp/material.json",
        ][..],
        &["nazoauthctl", "install", "--public-url"][..],
        &["nazoauthctl", "install", "--unknown", "value"][..],
        &["nazoauthctl", "--config"][..],
    ] {
        assert!(parse(arguments).is_err(), "accepted {arguments:?}");
    }
}

#[test]
fn parses_update_and_recovery_authorization_without_weakening_plan_mode() {
    let command = parse(&[
        "nazoauthctl",
        "update",
        "--yes",
        "--to",
        "v2.0.0",
        "--accept-migration-barrier",
    ])
    .unwrap()
    .unwrap()
    .command;
    let Command::Update(options) = command else {
        panic!("expected update");
    };
    assert!(options.yes);
    assert!(options.accept_migration_barrier);
    assert_eq!(options.version.as_deref(), Some("v2.0.0"));

    let command = parse(&["nazoauthctl", "update", "--plan", "--to", "v2.0.0"])
        .unwrap()
        .unwrap()
        .command;
    assert!(matches!(command, Command::Update(options) if options.plan && !options.yes));

    for arguments in [
        &["nazoauthctl", "update", "--plan", "--yes"][..],
        &[
            "nazoauthctl",
            "update",
            "--plan",
            "--accept-migration-barrier",
        ][..],
        &["nazoauthctl", "update", "--unknown"][..],
        &["nazoauthctl", "check", "extra"][..],
    ] {
        assert!(parse(arguments).is_err(), "accepted {arguments:?}");
    }

    assert!(matches!(
        parse(&["nazoauthctl", "rollback", "--yes"])
            .unwrap()
            .unwrap()
            .command,
        Command::Rollback { yes: true }
    ));

    let command = parse(&[
        "nazoauthctl",
        "keys",
        "export-openid4vc-trust",
        "--output",
        "/run/nazoauth/oidf-request-object-trust.pem",
    ])
    .unwrap()
    .unwrap()
    .command;
    assert!(matches!(
        command,
        Command::Keys(KeysCommand::ExportOpenid4vcTrust { output })
            if output == std::path::Path::new("/run/nazoauth/oidf-request-object-trust.pem")
    ));
    assert!(matches!(
        parse(&["nazoauthctl", "recover", "--yes"])
            .unwrap()
            .unwrap()
            .command,
        Command::Recover { yes: true }
    ));
    assert!(matches!(
        parse(&["nazoauthctl", "migrate", "--yes"])
            .unwrap()
            .unwrap()
            .command,
        Command::Migrate { yes: true }
    ));
    assert!(parse(&["nazoauthctl", "rollback", "unexpected"]).is_err());
}

#[test]
fn parses_key_mutations_identity_rotation_and_break_glass() {
    let command = parse(&[
        "nazoauthctl",
        "keys",
        "generate-local",
        "--alg",
        "ES256",
        "--purposes",
        "credential,jarm",
        "--yes",
    ])
    .unwrap()
    .unwrap()
    .command;
    assert!(matches!(
        command,
        Command::Keys(KeysCommand::GenerateLocal { alg, purposes, yes })
            if alg == "ES256" && purposes == ["credential", "jarm"] && yes
    ));

    let command = parse(&[
        "nazoauthctl",
        "keys",
        "register-external",
        "--kid",
        "external-1",
        "--alg",
        "ES256",
        "--key-ref",
        "provider:key-1",
        "--public-jwk",
        "/run/public.jwk",
        "--yes",
    ])
    .unwrap()
    .unwrap()
    .command;
    assert!(matches!(
        command,
        Command::Keys(KeysCommand::RegisterExternal {
            kid,
            alg,
            key_ref,
            public_jwk,
            yes,
        }) if kid == "external-1"
            && alg == "ES256"
            && key_ref == "provider:key-1"
            && public_jwk == std::path::Path::new("/run/public.jwk")
            && yes
    ));

    assert!(matches!(
        parse(&["nazoauthctl", "identity", "rotate", "--yes"])
            .unwrap()
            .unwrap()
            .command,
        Command::IdentityRotate { yes: true }
    ));
    assert!(matches!(
        parse(&[
            "nazoauthctl",
            "break-glass",
            "recover-controller",
            "--reason",
            "stolen",
            "--yes",
        ])
        .unwrap()
        .unwrap()
        .command,
        Command::BreakGlassRecover { yes: true, reason } if reason == "stolen"
    ));

    for arguments in [
        &["nazoauthctl", "keys"][..],
        &["nazoauthctl", "keys", "generate-local", "--yes", "--yes"][..],
        &[
            "nazoauthctl",
            "keys",
            "generate-local",
            "--alg",
            "ES256",
            "--alg",
            "ES256",
        ][..],
        &[
            "nazoauthctl",
            "keys",
            "export-openid4vc-trust",
            "--output",
            "/tmp/a",
            "--output",
            "/tmp/b",
        ][..],
        &["nazoauthctl", "keys", "unknown"][..],
        &["nazoauthctl", "identity", "rotate", "extra"][..],
        &[
            "nazoauthctl",
            "break-glass",
            "recover-controller",
            "--reason",
            "other",
            "--yes",
        ][..],
        &[
            "nazoauthctl",
            "break-glass",
            "recover-controller",
            "--unknown",
        ][..],
        &["nazoauthctl", "unknown"][..],
    ] {
        assert!(parse(arguments).is_err(), "accepted {arguments:?}");
    }
}
