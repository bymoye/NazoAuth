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
mod tests {
    use super::*;
    use crate::{
        bootstrap::{
            CibaPingDelivery, CibaPingDeliveryPort, CibaPingFinishOutcome, CibaPingFinishResult,
            TransientStateFuture,
        },
        config::ConfigSource,
    };
    use std::collections::BTreeSet;

    struct EmptyDeliveries;

    impl CibaPingDeliveryPort for EmptyDeliveries {
        fn claim_due(
            &self,
            _now: i64,
            _lock_until: i64,
            _limit: usize,
        ) -> TransientStateFuture<'_, Vec<CibaPingDelivery>> {
            Box::pin(async { Ok(Vec::new()) })
        }

        fn finish<'a>(
            &'a self,
            _delivery: &'a CibaPingDelivery,
            _outcome: CibaPingFinishOutcome,
        ) -> TransientStateFuture<'a, CibaPingFinishResult> {
            Box::pin(async { Ok(CibaPingFinishResult::Missing) })
        }
    }

    #[tokio::test]
    async fn worker_starts_when_ciba_is_disabled_in_startup_snapshot() {
        let settings =
            Settings::from_config(&ConfigSource::default()).expect("default settings load");
        let pool = nazo_postgres::create_pool("not a postgres url", 1)
            .expect("a lazy test pool should build");
        let runtime_modules =
            crate::runtime_modules::test_support::runtime_modules_with_modules_for_test(
                pool,
                &settings,
                BTreeSet::new(),
            )
            .expect("disabled runtime-module snapshot should build");
        assert!(!nazo_auth::module_admissible(
            runtime_modules.registry.snapshot().as_ref(),
            nazo_runtime_modules::ModuleId::Ciba,
            nazo_auth::CapabilityAdmission::NewRequest,
        ));

        let worker = spawn_ciba_ping_worker(Arc::new(EmptyDeliveries), &settings, &runtime_modules)
            .expect("worker construction should succeed")
            .expect("CIBA delivery worker must not follow the startup module snapshot");
        worker.abort();
        assert!(
            worker
                .await
                .expect_err("aborted worker should stop")
                .is_cancelled()
        );
    }
}
