//! Unified NazoAuth command-line entry point.

use anyhow::bail;

use crate::config::{ConfigSource, ServerConfigPreparation, database_url};

const USAGE: &str = "usage: nazoauth <server|operator-task|audit-anchor-worker|build-identity>";

pub async fn run(args: impl IntoIterator<Item = String>) -> anyhow::Result<()> {
    match Command::parse(args)? {
        Command::Help => {
            println!("{USAGE}");
            Ok(())
        }
        Command::Server => run_server().await,
        Command::OperatorTask => crate::operator_task::run().await,
        Command::AuditAnchorWorker => run_audit_anchor_worker().await,
        Command::BuildIdentity => {
            println!(
                "{}",
                serde_json::to_string(&crate::operator_task::embedded_identity())?
            );
            Ok(())
        }
    }
}

async fn run_audit_anchor_worker() -> anyhow::Result<()> {
    let config = ConfigSource::load_for_audit_anchor_worker()?;
    let (database_url, database_max_connections, worker_config) =
        crate::adapters::audit_anchor::worker_config_from_source(&config)?;
    let pool = nazo_postgres::create_pool(database_url, database_max_connections)?;
    let repository = nazo_postgres::AuditLedgerRepository::new(pool);
    tokio::select! {
        result = crate::adapters::audit_anchor::run_worker(repository, worker_config) => result,
        signal = tokio::signal::ctrl_c() => {
            signal?;
            Ok(())
        }
    }
}

async fn run_server() -> anyhow::Result<()> {
    match crate::config::prepare_server_config()? {
        ServerConfigPreparation::Ready => {}
        ServerConfigPreparation::Created(path) => {
            eprintln!(
                "Created initial configuration at {}. Continuing with secure generated defaults.",
                path.display()
            );
        }
    }
    crate::bootstrap::run().await
}

pub(crate) async fn run_migrations() -> anyhow::Result<bool> {
    // Migration ownership needs only the database secret. Materializing unrelated
    // application secrets here would couple a least-privilege one-shot task to the
    // long-running runtime's writable data directories.
    let config = ConfigSource::load_for_migrations()?;
    let database_url = database_url(&config);
    let applied = nazo_postgres::run_pending_migrations(&database_url).await?;
    nazo_postgres::cleanup_expired_security_state(&database_url).await?;
    Ok(applied)
}

#[derive(Debug, Eq, PartialEq)]
enum Command {
    Help,
    Server,
    OperatorTask,
    AuditAnchorWorker,
    BuildIdentity,
}

impl Command {
    fn parse(args: impl IntoIterator<Item = String>) -> anyhow::Result<Self> {
        let mut args = args.into_iter();
        let _program = args.next();
        let Some(command) = args.next() else {
            bail!("{USAGE}");
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
            "build-identity" => {
                ensure_no_extra_args(args, "build-identity")?;
                Ok(Self::BuildIdentity)
            }
            _ => bail!("unknown command {command}\n{USAGE}"),
        }
    }
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
