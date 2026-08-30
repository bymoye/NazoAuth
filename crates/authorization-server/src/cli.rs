//! Unified NazoAuth command-line entry point.

use std::{future::Future, pin::Pin, sync::Arc};

use anyhow::bail;

use crate::config::{ConfigSource, ServerConfigPreparation};

const USAGE: &str =
    "usage: nazoauth <server|operator-task|audit-anchor-worker|release-identity|migrate>";

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
}

pub async fn run(
    args: impl IntoIterator<Item = String>,
    launcher: Arc<dyn PersistenceLauncher>,
) -> anyhow::Result<()> {
    let args = args.into_iter().collect::<Vec<_>>();
    let usage = usage_for_args(&args);
    match Command::parse(args)? {
        Command::Help => {
            println!("{usage}");
            Ok(())
        }
        Command::Server => run_server(launcher.as_ref()).await,
        Command::OperatorTask => {
            let config = ConfigSource::load_for_migrations()?;
            let persistence = launcher.operator_persistence(&config).await?;
            crate::operator_task::run(persistence).await
        }
        Command::AuditAnchorWorker => run_audit_anchor_worker(launcher.as_ref()).await,
        Command::ReleaseIdentity => {
            println!(
                "{}",
                serde_json::to_string(&crate::operator_task::release_identity())?
            );
            Ok(())
        }
        Command::Migrate => {
            let config = ConfigSource::load_for_migrations()?;
            launcher
                .operator_persistence(&config)
                .await?
                .run_migrations()
                .await?;
            Ok(())
        }
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

async fn run_server(launcher: &dyn PersistenceLauncher) -> anyhow::Result<()> {
    match crate::config::prepare_server_config(launcher.default_database_url())? {
        ServerConfigPreparation::Ready => {}
        ServerConfigPreparation::Created(path) => {
            eprintln!(
                "Created initial configuration at {}. Continuing with secure generated defaults.",
                path.display()
            );
        }
    }
    let config = ConfigSource::load()?;
    let bindings = launcher.server_bindings(&config).await?;
    crate::bootstrap::run(config, bindings).await
}

#[derive(Debug, Eq, PartialEq)]
enum Command {
    Help,
    Server,
    OperatorTask,
    AuditAnchorWorker,
    ReleaseIdentity,
    Migrate,
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
    format!("usage: {program} <server|operator-task|audit-anchor-worker|release-identity|migrate>")
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
