use super::*;

pub(crate) async fn load_revocation_policy(
    settings: &crate::settings::Openid4vcSettings,
) -> anyhow::Result<CertificateRevocationPolicy> {
    let Some(path) = settings.revocation_snapshot_file.as_ref() else {
        return Ok(CertificateRevocationPolicy::disabled());
    };
    let snapshot = read_revocation_snapshot(path).await.with_context(|| {
        format!(
            "failed to load OpenID4VC revocation snapshot from {}",
            path.display()
        )
    })?;
    let policy = match settings.revocation_policy {
        Openid4vcRevocationPolicy::Disabled => CertificateRevocationPolicy::disabled(),
        Openid4vcRevocationPolicy::Optional => {
            CertificateRevocationPolicy::optional(Arc::new(snapshot))
        }
        Openid4vcRevocationPolicy::Required => {
            CertificateRevocationPolicy::required(Arc::new(snapshot))
        }
    };
    Ok(policy)
}

pub(crate) async fn read_revocation_snapshot(
    path: &std::path::Path,
) -> anyhow::Result<CertificateRevocationSnapshot> {
    use tokio::io::AsyncReadExt as _;

    let file = tokio::fs::File::open(path).await?;
    let mut bytes = Vec::new();
    file.take(MAX_REVOCATION_SNAPSHOT_BYTES + 1)
        .read_to_end(&mut bytes)
        .await?;
    if bytes.len() as u64 > MAX_REVOCATION_SNAPSHOT_BYTES {
        anyhow::bail!("revocation snapshot exceeds {MAX_REVOCATION_SNAPSHOT_BYTES} bytes");
    }
    let snapshot =
        CertificateRevocationSnapshot::from_json(&bytes).map_err(|error| anyhow::anyhow!(error))?;
    snapshot
        .validate_freshness_at(chrono::Utc::now())
        .map_err(|error| anyhow::anyhow!(error))?;
    Ok(snapshot)
}

pub(crate) fn spawn_revocation_snapshot_reloader(
    policy: CertificateRevocationPolicy,
    path: PathBuf,
    interval: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        ticker.tick().await;
        loop {
            ticker.tick().await;
            match read_revocation_snapshot(&path).await {
                Ok(snapshot) => {
                    if let Err(error) =
                        policy.replace_snapshot(Arc::new(snapshot), chrono::Utc::now())
                    {
                        tracing::warn!(
                            target: "openid4vc.revocation",
                            snapshot_path = %path.display(),
                            %error,
                            "rejected OpenID4VC revocation snapshot reload"
                        );
                    }
                }
                Err(error) => tracing::warn!(
                    target: "openid4vc.revocation",
                    snapshot_path = %path.display(),
                    %error,
                    "failed to reload OpenID4VC revocation snapshot; retaining previous snapshot"
                ),
            }
        }
    })
}

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
