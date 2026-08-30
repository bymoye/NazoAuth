use super::*;

fn parse(args: &[&str]) -> anyhow::Result<Command> {
    Command::parse(args.iter().map(|value| (*value).to_owned()))
}

#[test]
fn requires_an_explicit_command() {
    assert_eq!(parse(&["nazoauth"]).unwrap_err().to_string(), USAGE);
}

#[test]
fn parses_all_product_commands() {
    assert_eq!(parse(&["nazoauth", "server"]).unwrap(), Command::Server);
    assert_eq!(
        parse(&["nazoauth", "operator-task"]).unwrap(),
        Command::OperatorTask
    );
    assert_eq!(
        parse(&["nazoauth", "audit-anchor-worker"]).unwrap(),
        Command::AuditAnchorWorker
    );
    assert_eq!(
        parse(&["nazoauth", "release-identity"]).unwrap(),
        Command::ReleaseIdentity
    );
    assert_eq!(parse(&["nazoauth", "migrate"]).unwrap(), Command::Migrate);
}

#[test]
fn help_is_available_without_starting_a_runtime() {
    assert_eq!(parse(&["nazoauth", "--help"]).unwrap(), Command::Help);
}

#[tokio::test]
async fn public_help_command_completes_without_loading_runtime_configuration() {
    run(["nazoauth".to_owned(), "help".to_owned()])
        .await
        .unwrap();
}

#[tokio::test]
async fn release_identity_completes_without_loading_runtime_configuration() {
    run(["nazoauth".to_owned(), "release-identity".to_owned()])
        .await
        .unwrap();
}

#[test]
fn public_commands_reject_accidental_arguments() {
    assert_eq!(
        parse(&["nazoauth", "server", "--detach"])
            .unwrap_err()
            .to_string(),
        "server does not accept argument --detach"
    );
    assert_eq!(
        parse(&["nazoauth", "operator-task", "now"])
            .unwrap_err()
            .to_string(),
        "operator-task does not accept argument now"
    );
    assert_eq!(
        parse(&["nazoauth", "migrate", "now"])
            .unwrap_err()
            .to_string(),
        "migrate does not accept argument now"
    );
}

#[test]
fn removed_mutation_command_is_unknown() {
    assert!(
        parse(&["nazoauth", "keyctl"])
            .unwrap_err()
            .to_string()
            .starts_with("unknown command keyctl")
    );
}

#[test]
fn unknown_command_reports_usage() {
    assert_eq!(
        parse(&["nazoauth", "serve"]).unwrap_err().to_string(),
        format!("unknown command serve\n{USAGE}")
    );
}
