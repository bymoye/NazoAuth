//! Unified NazoAuth command-line entry point.

use std::{future::Future, pin::Pin, sync::Arc};

use anyhow::bail;
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File},
    io::Read,
    path::Path,
};

use crate::{
    adapters::security::{
        configure_password_hash_limits, default_password_hash_max_concurrency,
        default_password_hash_queue_timeout_ms, initialize_dummy_password_hash,
    },
    bootstrap::RegistrationSecretHasher,
    config::{ConfigSource, ServerConfigPreparation},
    settings::Settings,
};
use zeroize::Zeroizing;

const USAGE: &str = "usage: nazoauth <server|operator-task|audit-anchor-worker|release-identity|migrate|tenant-bootstrap|admin-provision>";
const ADMIN_PROVISION_CREDENTIAL_FILE_ENV: &str = "NAZOAUTH_ADMIN_PROVISION_FILE";
const ADMIN_PROVISION_OPERATION_ID_ENV: &str = "NAZOAUTH_ADMIN_PROVISION_OPERATION_ID";
const ADMIN_PROVISION_DEPLOYMENT_ID_ENV: &str = "NAZOAUTH_ADMIN_PROVISION_DEPLOYMENT_ID";
const ADMIN_PROVISION_REJECTION_PREFIX: &str = "nazoauth-admin-provision-rejection=";
const MAX_ADMIN_PROVISION_CREDENTIAL_FILE_BYTES: u64 = 16 * 1024;

pub type LauncherFuture<'a, T> = Pin<Box<dyn Future<Output = anyhow::Result<T>> + Send + 'a>>;

/// Database-specific lifecycle supplied by a statically linked launcher.
/// Application commands only receive semantic capability bundles.
pub trait PersistenceLauncher: Send + Sync {
    fn default_database_url(&self) -> &'static str;

    fn server_bindings<'a>(
        &'a self,
        config: &'a ConfigSource,
    ) -> LauncherFuture<'a, crate::bootstrap::ServerPersistenceBindings>;

    fn operator_persistence<'a>(
        &'a self,
        config: &'a ConfigSource,
    ) -> LauncherFuture<'a, Arc<dyn crate::operator_task::OperatorPersistence>>;

    fn audit_exporter<'a>(
        &'a self,
        database_url: &'a str,
        database_max_connections: usize,
    ) -> LauncherFuture<'a, Arc<dyn nazo_persistence::SecurityAuditExporter>>;

    fn admin_provisioner<'a>(
        &'a self,
        config: &'a ConfigSource,
    ) -> LauncherFuture<'a, Arc<dyn nazo_persistence::AdminProvisionStore>>;
}

/// KV/transient-state lifecycle supplied independently from persistence.
///
/// Implementations own backend configuration, connection topology,
/// namespace/epoch policy, and tenant binding. They return semantic state
/// capabilities rather than a generic key/value client.
pub trait TransientStateLauncher: Send + Sync {
    fn server_config_extension(&self) -> crate::config::ServerConfigExtension;

    fn server_bindings<'a>(
        &'a self,
        config: &'a ConfigSource,
        deployment_id: &'a str,
    ) -> LauncherFuture<'a, crate::bootstrap::ServerStateBackendBindings>;
}

pub async fn run(
    args: impl IntoIterator<Item = String>,
    persistence: Arc<dyn PersistenceLauncher>,
    transient_state: Arc<dyn TransientStateLauncher>,
) -> anyhow::Result<()> {
    crate::config::install_server_config_extension(transient_state.server_config_extension())?;
    let args = args.into_iter().collect::<Vec<_>>();
    let usage = usage_for_args(&args);
    match Command::parse(args)? {
        Command::Help => {
            println!("{usage}");
            Ok(())
        }
        Command::Server => run_server(persistence.as_ref(), transient_state.as_ref()).await,
        Command::OperatorTask => {
            let config = ConfigSource::load_for_migrations()?;
            let operator_persistence = persistence.operator_persistence(&config).await?;
            crate::operator_task::run(operator_persistence).await
        }
        Command::AuditAnchorWorker => run_audit_anchor_worker(persistence.as_ref()).await,
        Command::ReleaseIdentity => {
            println!(
                "{}",
                serde_json::to_string(&crate::operator_task::release_identity())?
            );
            Ok(())
        }
        Command::Migrate => {
            let config = ConfigSource::load_for_migrations()?;
            let operator_persistence = persistence.operator_persistence(&config).await?;
            crate::operator_task::migrate_and_initialize_tenant_directory(
                operator_persistence.as_ref(),
            )
            .await?;
            Ok(())
        }
        Command::TenantBootstrap => {
            let config = ConfigSource::load_for_migrations()?;
            let initial_binding = Settings::initial_tenant_directory_binding(&config)?;
            persistence
                .operator_persistence(&config)
                .await?
                .initialize_tenant_directory(initial_binding)
                .await?;
            Ok(())
        }
        Command::AdminProvision => run_admin_provision(persistence.as_ref()).await,
    }
}

async fn run_admin_provision(launcher: &dyn PersistenceLauncher) -> anyhow::Result<()> {
    let config = ConfigSource::load().map_err(|_| admin_provision_input_error())?;
    let configured_deployment_id = config
        .required_string("DEPLOYMENT_ID")
        .map_err(|_| admin_provision_input_error())?;
    let operation_id = required_admin_provision_input(ADMIN_PROVISION_OPERATION_ID_ENV)?;
    let deployment_id = required_admin_provision_input(ADMIN_PROVISION_DEPLOYMENT_ID_ENV)?;
    validate_admin_provision_operation_id(&operation_id)?;
    validate_admin_provision_deployment_id(&deployment_id)?;
    if deployment_id != configured_deployment_id {
        return Err(admin_provision_input_error());
    }

    let credentials = read_admin_provision_credentials()?;
    let email = nazo_identity::email::normalize_email_address(&credentials.email)
        .map_err(|_| admin_provision_input_error())?;
    if !(12..=1024).contains(&credentials.password.len()) {
        return Err(admin_provision_input_error());
    }

    configure_password_hash_limits(
        config
            .parse(
                "PASSWORD_HASH_MAX_CONCURRENCY",
                default_password_hash_max_concurrency(),
            )
            .map_err(|_| admin_provision_error())?,
        config
            .parse(
                "PASSWORD_HASH_QUEUE_TIMEOUT_MS",
                default_password_hash_queue_timeout_ms(),
            )
            .map_err(|_| admin_provision_error())?,
    )
    .map_err(|_| admin_provision_error())?;
    initialize_dummy_password_hash().map_err(|_| admin_provision_error())?;
    let password_hash = nazo_identity::ports::SecretHashPort::hash_secret(
        &RegistrationSecretHasher,
        credentials.password,
    )
    .await
    .map_err(|_| admin_provision_error())?;

    let receipt = launcher
        .admin_provisioner(&config)
        .await
        .map_err(|_| admin_provision_error())?
        .provision(nazo_persistence::AdminProvisionRequest {
            tenant: nazo_identity::TenantContext::default_system(),
            operation_id,
            deployment_id,
            email,
            password_hash,
        })
        .await
        .map_err(admin_provision_repository_error)?;
    let output = AdminProvisionOutput {
        schema: 1,
        operation_id: receipt.operation_id,
        deployment_id: receipt.deployment_id,
        user_id: receipt.user_id,
        email: receipt.email,
    };
    println!(
        "{}",
        serde_json::to_string(&output).map_err(|_| admin_provision_error())?
    );
    Ok(())
}

fn required_admin_provision_input(name: &str) -> anyhow::Result<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .ok_or_else(admin_provision_input_error)
}

fn validate_admin_provision_operation_id(value: &str) -> anyhow::Result<()> {
    nazo_operator_protocol::validate_file_identifier_value(value)
        .map_err(|_| admin_provision_input_error())
}

fn validate_admin_provision_deployment_id(value: &str) -> anyhow::Result<()> {
    nazo_operator_protocol::validate_file_identifier_value(value)
        .map_err(|_| admin_provision_input_error())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AdminProvisionCredentials {
    schema: u8,
    email: String,
    password: String,
}

#[derive(Serialize)]
struct AdminProvisionOutput {
    schema: u8,
    operation_id: String,
    deployment_id: String,
    user_id: uuid::Uuid,
    email: String,
}

fn read_admin_provision_credentials() -> anyhow::Result<AdminProvisionCredentials> {
    let path = required_admin_provision_input(ADMIN_PROVISION_CREDENTIAL_FILE_ENV)?;
    read_admin_provision_credentials_at(Path::new(&path))
}

fn read_admin_provision_credentials_at(path: &Path) -> anyhow::Result<AdminProvisionCredentials> {
    let metadata = fs::symlink_metadata(path).map_err(|_| admin_provision_input_error())?;
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_file()
        || metadata.len() > MAX_ADMIN_PROVISION_CREDENTIAL_FILE_BYTES
    {
        return Err(admin_provision_input_error());
    }
    let mut file = File::open(path).map_err(|_| admin_provision_input_error())?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(
        usize::try_from(
            metadata
                .len()
                .min(MAX_ADMIN_PROVISION_CREDENTIAL_FILE_BYTES),
        )
        .map_err(|_| admin_provision_error())?,
    ));
    file.by_ref()
        .take(MAX_ADMIN_PROVISION_CREDENTIAL_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| admin_provision_input_error())?;
    if bytes.len() as u64 > MAX_ADMIN_PROVISION_CREDENTIAL_FILE_BYTES {
        return Err(admin_provision_input_error());
    }
    let credentials: AdminProvisionCredentials =
        serde_json::from_slice(&bytes).map_err(|_| admin_provision_input_error())?;
    if credentials.schema != 1 {
        return Err(admin_provision_input_error());
    }
    Ok(credentials)
}

fn admin_provision_error() -> anyhow::Error {
    anyhow::anyhow!("administrator provisioning failed")
}

fn admin_provision_input_error() -> anyhow::Error {
    eprintln!("{ADMIN_PROVISION_REJECTION_PREFIX}input");
    admin_provision_error()
}

fn admin_provision_repository_error(error: nazo_persistence::AdminProvisionError) -> anyhow::Error {
    let rejection = admin_provision_rejection_for_error(&error);
    if let Some(rejection) = rejection {
        eprintln!("{ADMIN_PROVISION_REJECTION_PREFIX}{rejection}");
    }
    admin_provision_error()
}

fn admin_provision_rejection_for_error(
    error: &nazo_persistence::AdminProvisionError,
) -> Option<&'static str> {
    match error {
        nazo_persistence::AdminProvisionError::InvalidInput => Some("input"),
        nazo_persistence::AdminProvisionError::EmailConflict => Some("email-conflict"),
        nazo_persistence::AdminProvisionError::OperationConflict => Some("operation-conflict"),
        nazo_persistence::AdminProvisionError::Unavailable
        | nazo_persistence::AdminProvisionError::Storage => None,
    }
}

async fn run_audit_anchor_worker(launcher: &dyn PersistenceLauncher) -> anyhow::Result<()> {
    let config = ConfigSource::load_for_audit_anchor_worker()?;
    let (database_url, database_max_connections, worker_config) =
        crate::adapters::audit_anchor::worker_config_from_source(&config)?;
    let repository = launcher
        .audit_exporter(&database_url, database_max_connections)
        .await?;
    tokio::select! {
        result = crate::adapters::audit_anchor::run_worker(repository, worker_config) => result,
        signal = tokio::signal::ctrl_c() => {
            signal?;
            Ok(())
        }
    }
}

async fn run_server(
    persistence: &dyn PersistenceLauncher,
    transient_state: &dyn TransientStateLauncher,
) -> anyhow::Result<()> {
    match crate::config::prepare_server_config(persistence.default_database_url())? {
        ServerConfigPreparation::Ready => {}
        ServerConfigPreparation::Created(path) => {
            eprintln!(
                "Created initial configuration at {}. Continuing with secure generated defaults.",
                path.display()
            );
        }
    }
    let config = ConfigSource::load()?;
    let bindings = persistence.server_bindings(&config).await?;
    crate::bootstrap::run(config, bindings, transient_state).await
}

#[derive(Debug, Eq, PartialEq)]
enum Command {
    Help,
    Server,
    OperatorTask,
    AuditAnchorWorker,
    ReleaseIdentity,
    Migrate,
    TenantBootstrap,
    AdminProvision,
}

impl Command {
    fn parse(args: impl IntoIterator<Item = String>) -> anyhow::Result<Self> {
        let args = args.into_iter().collect::<Vec<_>>();
        let usage = usage_for_args(&args);
        let mut args = args.into_iter();
        let _program = args.next();
        let Some(command) = args.next() else {
            bail!(usage);
        };
        match command.as_str() {
            "-h" | "--help" | "help" => {
                ensure_no_extra_args(args, command.as_str())?;
                Ok(Self::Help)
            }
            "server" => {
                ensure_no_extra_args(args, "server")?;
                Ok(Self::Server)
            }
            "operator-task" => {
                ensure_no_extra_args(args, "operator-task")?;
                Ok(Self::OperatorTask)
            }
            "audit-anchor-worker" => {
                ensure_no_extra_args(args, "audit-anchor-worker")?;
                Ok(Self::AuditAnchorWorker)
            }
            "release-identity" => {
                ensure_no_extra_args(args, "release-identity")?;
                Ok(Self::ReleaseIdentity)
            }
            "migrate" => {
                ensure_no_extra_args(args, "migrate")?;
                Ok(Self::Migrate)
            }
            "tenant-bootstrap" => {
                ensure_no_extra_args(args, "tenant-bootstrap")?;
                Ok(Self::TenantBootstrap)
            }
            "admin-provision" => {
                ensure_no_extra_args(args, "admin-provision")?;
                Ok(Self::AdminProvision)
            }
            _ => bail!("unknown command {command}\n{usage}"),
        }
    }
}

fn usage_for_args(args: &[String]) -> String {
    let program = args
        .first()
        .and_then(|value| std::path::Path::new(value).file_name())
        .and_then(std::ffi::OsStr::to_str)
        .filter(|value| !value.is_empty())
        .unwrap_or("nazoauth");
    if program == "nazoauth" {
        return USAGE.to_owned();
    }
    format!(
        "usage: {program} <server|operator-task|audit-anchor-worker|release-identity|migrate|admin-provision>"
    )
}

fn ensure_no_extra_args(
    mut args: impl Iterator<Item = String>,
    command: &str,
) -> anyhow::Result<()> {
    if let Some(argument) = args.next() {
        bail!("{command} does not accept argument {argument}");
    }
    Ok(())
}

#[cfg(test)]
#[path = "../tests/unit/cli.rs"]
mod tests;
