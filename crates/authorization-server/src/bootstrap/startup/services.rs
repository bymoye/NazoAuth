use super::configuration::StartupConfiguration;
use super::*;

mod dependencies;
mod factory;
mod identity;

/// The service phase is deliberately a small composition facade.  Process-wide
/// resources are initialized by [`super::configuration`]; this phase wires
/// request-facing adapters and hands the resulting graph to the Actix factory.
pub(super) async fn run(startup: StartupConfiguration) -> anyhow::Result<()> {
    let core = dependencies::build(&startup).await?;
    let identity = identity::build(&startup, &core).await?;

    factory::run(ServiceAssembly {
        startup,
        core,
        identity,
    })
    .await
}

pub(super) struct ServiceAssembly {
    startup: StartupConfiguration,
    core: dependencies::CoreServices,
    identity: identity::IdentityServices,
}
