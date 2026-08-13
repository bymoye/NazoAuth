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
pub(crate) async fn run() -> anyhow::Result<()> {
    let config = ConfigSource::load()?;
    let _observability = observability::init(&config)?;
    let startup = configuration::load(config).await?;
    services::run(startup).await
}
