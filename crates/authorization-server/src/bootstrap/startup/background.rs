use super::*;

/// Start tasks whose ownership is the process lifetime rather than an HTTP
/// worker.  Keeping these calls here prevents the server factory from
/// accidentally starting one copy per Actix worker.
pub(super) fn spawn_key_lifecycle(
    keyset: nazo_key_management::KeyManager,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(keyset.run_lifecycle())
}

pub(super) fn spawn_ciba_ping_worker(
    deliveries: Arc<dyn crate::bootstrap::CibaPingDeliveryPort>,
    settings: &Settings,
    _runtime_modules: &RuntimeModules,
) -> anyhow::Result<Option<tokio::task::JoinHandle<()>>> {
    // Tenant capabilities can change after this runtime starts; the delivery
    // queue, rather than the startup snapshot, determines whether work exists.
    Ok(Some(spawn_ciba_ping_delivery_worker(
        CibaPingDeliveryWorker::new(deliveries, &settings.ciba.ciba_notification_private_origins)?,
    )))
}

#[cfg(not(test))]
pub(super) fn spawn_backchannel_logout_worker(
    logout_deliveries: Arc<dyn nazo_persistence::BackchannelLogoutDeliveryStore>,
    settings: &Settings,
) -> anyhow::Result<tokio::task::JoinHandle<()>> {
    Ok(spawn_backchannel_logout_delivery_worker(
        BackchannelLogoutWorker::from_port(
            logout_deliveries,
            &settings.modules.backchannel_logout_private_origins,
        )?,
    ))
}

#[cfg(test)]
#[path = "../../../tests/unit/bootstrap/startup/background.rs"]
mod tests;
