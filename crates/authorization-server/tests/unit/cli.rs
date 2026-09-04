use super::*;

struct UnusedLauncher;

impl PersistenceLauncher for UnusedLauncher {
    fn default_database_url(&self) -> &'static str {
        "adapter://unused"
    }

    fn server_bindings<'a>(
        &'a self,
        _config: &'a ConfigSource,
    ) -> LauncherFuture<'a, crate::bootstrap::ServerPersistenceBindings> {
        unreachable!("help and release identity do not initialize persistence")
    }

    fn operator_persistence<'a>(
        &'a self,
        _config: &'a ConfigSource,
    ) -> LauncherFuture<'a, Arc<dyn crate::operator_task::OperatorPersistence>> {
        unreachable!("help and release identity do not initialize persistence")
    }

    fn audit_exporter<'a>(
        &'a self,
        _database_url: &'a str,
        _database_max_connections: usize,
    ) -> LauncherFuture<'a, Arc<dyn nazo_persistence::SecurityAuditExporter>> {
        unreachable!("help and release identity do not initialize persistence")
    }

    fn admin_provisioner<'a>(
        &'a self,
        _config: &'a ConfigSource,
    ) -> LauncherFuture<'a, Arc<dyn nazo_persistence::AdminProvisionStore>> {
        unreachable!("help and release identity do not initialize persistence")
    }
}

struct UnusedTransientStateLauncher;

impl TransientStateLauncher for UnusedTransientStateLauncher {
    fn server_config_extension(&self) -> crate::config::ServerConfigExtension {
        crate::config::ServerConfigExtension::new(
            "VALKEY_URL: \"redis://127.0.0.1:6379/0\"\n".to_owned(),
            vec![
                "VALKEY_COMMAND_TIMEOUT_MS",
                "VALKEY_STATE_EPOCH",
                "VALKEY_URL",
            ],
            "VALKEY_STATE_EPOCH",
        )
    }

    fn server_bindings<'a>(
        &'a self,
        _config: &'a ConfigSource,
        _deployment_id: &'a str,
    ) -> LauncherFuture<'a, crate::bootstrap::ServerStateBackendBindings> {
        unreachable!("help and release identity do not initialize transient state")
    }
}

fn unused_launcher() -> Arc<dyn PersistenceLauncher> {
    Arc::new(UnusedLauncher)
}

fn unused_transient_state_launcher() -> Arc<dyn TransientStateLauncher> {
    Arc::new(UnusedTransientStateLauncher)
}

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
    assert_eq!(
        parse(&["nazoauth", "tenant-bootstrap"]).unwrap(),
        Command::TenantBootstrap
    );
    assert_eq!(
        parse(&["nazoauth", "admin-provision"]).unwrap(),
        Command::AdminProvision
    );
}

#[test]
fn help_is_available_without_starting_a_runtime() {
    assert_eq!(parse(&["nazoauth", "--help"]).unwrap(), Command::Help);
}

#[tokio::test]
async fn public_help_command_completes_without_loading_runtime_configuration() {
    run(
        ["nazoauth".to_owned(), "help".to_owned()],
        unused_launcher(),
        unused_transient_state_launcher(),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn release_identity_completes_without_loading_runtime_configuration() {
    run(
        ["nazoauth".to_owned(), "release-identity".to_owned()],
        unused_launcher(),
        unused_transient_state_launcher(),
    )
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
    assert_eq!(
        parse(&["nazoauth", "tenant-bootstrap", "now"])
            .unwrap_err()
            .to_string(),
        "tenant-bootstrap does not accept argument now"
    );
    assert_eq!(
        parse(&["nazoauth", "admin-provision", "now"])
            .unwrap_err()
            .to_string(),
        "admin-provision does not accept argument now"
    );
}

#[test]
fn admin_provision_credentials_require_the_exact_schema() {
    let directory = std::env::temp_dir().join(format!("nazoauth-cli-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir(&directory).unwrap();
    let valid = directory.join("valid.json");
    std::fs::write(
        &valid,
        br#"{"schema":1,"email":" Admin@Example.COM ","password":"long-enough-password"}"#,
    )
    .unwrap();
    assert!(super::read_admin_provision_credentials_at(&valid).is_ok());

    let unknown = directory.join("unknown.json");
    std::fs::write(
        &unknown,
        br#"{"schema":1,"email":"admin@example.com","password":"long-enough-password","extra":true}"#,
    )
    .unwrap();
    assert!(super::read_admin_provision_credentials_at(&unknown).is_err());

    let invalid_schema = directory.join("schema.json");
    std::fs::write(
        &invalid_schema,
        br#"{"schema":2,"email":"admin@example.com","password":"long-enough-password"}"#,
    )
    .unwrap();
    assert!(super::read_admin_provision_credentials_at(&invalid_schema).is_err());

    let oversized = directory.join("oversized.json");
    std::fs::write(&oversized, vec![b'x'; 16 * 1024 + 1]).unwrap();
    assert!(super::read_admin_provision_credentials_at(&oversized).is_err());

    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn admin_provision_rejection_markers_close_only_deterministic_failures() {
    assert_eq!(
        super::admin_provision_rejection_for_error(
            &nazo_persistence::AdminProvisionError::InvalidInput
        ),
        Some("input")
    );
    assert_eq!(
        super::admin_provision_rejection_for_error(
            &nazo_persistence::AdminProvisionError::EmailConflict
        ),
        Some("email-conflict")
    );
    assert_eq!(
        super::admin_provision_rejection_for_error(
            &nazo_persistence::AdminProvisionError::OperationConflict
        ),
        Some("operation-conflict")
    );
    assert_eq!(
        super::admin_provision_rejection_for_error(
            &nazo_persistence::AdminProvisionError::Unavailable
        ),
        None
    );
    assert_eq!(
        super::admin_provision_rejection_for_error(&nazo_persistence::AdminProvisionError::Storage),
        None
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
