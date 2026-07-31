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
