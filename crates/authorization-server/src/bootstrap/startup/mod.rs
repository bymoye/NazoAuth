use super::*;

mod background;
mod configuration;
mod services;

// Keep the existing bootstrap unit-test source boundary while the
// implementation lives with the background-task lifecycle.
#[allow(unused_imports)]
pub(crate) use background::{load_revocation_policy, read_revocation_snapshot};

/// Public bootstrap contract retained for the binary entry point.  The
/// configuration phase owns process-wide resources before service assembly;
/// the service phase owns the Actix server factory and all request handles.
pub async fn run(
    config: ConfigSource,
    persistence: super::ServerPersistenceBindings,
) -> anyhow::Result<()> {
    let _observability = observability::init(&config)?;
    let startup = configuration::load(config, persistence).await?;
    services::run(startup).await
}
