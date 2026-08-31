use super::*;
use crate::config::DEFAULT_DATA_DIR;

use super::tenant_runtime::{
    ProcessRuntime, TenantDirectoryRefreshOutcome, TenantRuntimeBuilder, TenantRuntimeRefresher,
    TenantRuntimeRegistry,
};

/// Tenant-scoped values used to assemble one immutable request graph.
pub(super) struct StartupConfiguration {
    pub(super) config: ConfigSource,
    pub(super) persistence: super::super::ServerPersistenceBindings,
    pub(super) transient_state: super::super::ServerTransientStateBindings,
    pub(super) settings: Arc<Settings>,
    pub(super) token_issuance_response_keys: nazo_persistence::TokenIssuanceResponseKeyRing,
    pub(super) control_discovery: web::Data<crate::control_discovery::ControlDiscoveryEndpoint>,
    pub(super) mtls_certificate_source: web::Data<crate::http::mtls::MtlsCertificateSource>,
    pub(super) readiness_dependencies: web::Data<crate::http::well_known::ReadinessDependencies>,
    pub(super) remote_client_documents:
        Arc<crate::domain::remote_client_documents::RemoteClientDocumentResolver>,
    pub(super) runtime_modules: web::Data<RuntimeModules>,
    pub(super) keyset: nazo_key_management::KeyManager,
}

/// Values which survive process startup. Tenant request graphs live only in
/// the immutable registry and can be replaced without restarting the server.
pub(super) struct StartupRuntime {
    pub(super) process: Arc<ProcessRuntime>,
    pub(super) registry: TenantRuntimeRegistry,
    pub(super) refresher: Arc<TenantRuntimeRefresher>,
    pub(super) backchannel_logout_worker: Option<tokio::task::JoinHandle<()>>,
}

pub(super) async fn load(
    config: ConfigSource,
    persistence: super::super::ServerPersistenceBindings,
    transient_state_launcher: &dyn crate::cli::TransientStateLauncher,
) -> anyhow::Result<StartupRuntime> {
    let perf_metrics_enabled = config.bool("PERF_METRICS_ENABLED", false)?;
    let password_hash_max_concurrency = config.parse::<usize>(
        "PASSWORD_HASH_MAX_CONCURRENCY",
        default_password_hash_max_concurrency(),
    )?;
    let password_hash_queue_timeout_ms = config.parse::<u64>(
        "PASSWORD_HASH_QUEUE_TIMEOUT_MS",
        default_password_hash_queue_timeout_ms(),
    )?;
    configure_password_hash_limits(
        password_hash_max_concurrency,
        password_hash_queue_timeout_ms,
    )?;
    initialize_dummy_password_hash()?;

    // Always read the authoritative snapshot first. The shared cache is never
    // trusted for a cold start, so a stale cache cannot resurrect a tenant.
    let directory = persistence.provider().tenant_directory();
    let database_snapshot = directory
        .load_active()
        .await
        .map_err(|error| anyhow::anyhow!("tenant directory initial read failed: {error}"))?;
    let database_initial = database_snapshot.revision != 0 || !database_snapshot.tenants.is_empty();

    // This baseline is process identity only (static route set, module catalog,
    // control discovery). It never supplies request tenant settings or CORS.
    // Its issuer therefore remains stable when directory ordering changes.
    let legacy_settings = legacy_settings(&config)?;
    let route_settings = Arc::new(
        legacy_settings
            .first()
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("legacy baseline is empty"))?,
    );
    // TENANTS_JSON is a revision-zero bootstrap source only. Once PostgreSQL
    // has any directory history, its snapshot is the complete tenant index.
    let legacy_bootstrap = !database_initial;
    // Deployment-global control routes must not follow directory ordering. A
    // legacy deployment retains its configured tenant identity; a dynamic
    // directory always reserves the fixed system tenant. If that tenant has no
    // active binding, its host cannot reach deployment-level HTTP control.
    let control_tenant_id = if legacy_bootstrap {
        route_settings.tenant.context.tenant_id
    } else {
        nazo_identity::TenantContext::default_system().tenant_id
    };

    let audit_anchor_data_dir = config.persistent_path("DATA_DIR", Some(DEFAULT_DATA_DIR))?;
    let audit_anchor_preflight = crate::adapters::audit_anchor::AuditAnchorPreflight::new(
        crate::adapters::audit_anchor::preflight_config_from_source(
            &config,
            &audit_anchor_data_dir,
        )?,
    )?;
    let control_discovery = web::Data::new(
        crate::control_discovery::ControlDiscoveryEndpoint::initialize(
            &route_settings.storage.data_dir,
            config
                .optional_string("INSTANCE_IDENTITY_DIR")
                .map(|_| config.persistent_path("INSTANCE_IDENTITY_DIR", None))
                .transpose()?
                .as_deref(),
            config.optional_string("DEPLOYMENT_ID").as_deref(),
            config.optional_string("RUNTIME_INSTANCE_ID").as_deref(),
            &route_settings.endpoint.issuer,
        )?,
    );

    let require_audit_least_privilege =
        config.bool("SECURITY_AUDIT_REQUIRE_LEAST_PRIVILEGE", true)?;
    let audit_repository = persistence.provider().security_audit_ledger();
    audit_repository
        .check_available(require_audit_least_privilege)
        .await
        .map_err(|error| anyhow::anyhow!("security audit writer preflight failed: {error}"))?;
    crate::adapters::audit::install_persistent_audit_sink(
        audit_repository,
        require_audit_least_privilege,
        audit_anchor_preflight,
    )?;

    let token_issuance_response_keys = token_issuance_response_key_ring(&config)?;
    let runtime_modules = web::Data::new(
        RuntimeModules::initialize(
            persistence.provider().runtime_modules(),
            &route_settings,
            control_discovery.runtime_instance_id(),
        )
        .await?,
    );
    background::spawn_runtime_reconciler(runtime_modules.clone());

    let state_backend = transient_state_launcher
        .server_bindings(&config, control_discovery.deployment_id())
        .await
        .map_err(|error| anyhow::anyhow!("transient-state deployment preflight failed: {error}"))?;

    let directory_cache = state_backend.tenant_directory_cache();
    let database_pool_metrics: web::Data<dyn nazo_persistence::DatabasePoolMetricsPort> =
        web::Data::from(persistence.provider().database_pool_metrics());
    let process = Arc::new(ProcessRuntime {
        config,
        perf_metrics_enabled,
        control_tenant_id,
        persistence,
        state_backend,
        token_issuance_response_keys,
        control_discovery,
        runtime_modules,
        database_pool_metrics,
        route_settings,
        legacy_bootstrap,
    });

    let registry = TenantRuntimeRegistry::empty();
    let refresher = Arc::new(TenantRuntimeRefresher::new(
        registry.clone(),
        directory,
        directory_cache.clone(),
        TenantRuntimeBuilder::production(process.clone()),
    ));
    let outcome = if database_initial {
        if process.route_settings.endpoint.transport_mode
            == crate::settings::TransportMode::DirectTls
        {
            tracing::error!(
                "tenant directory has revision history but DirectTLS cannot host a dynamic tenant index; starting with an empty last-good index"
            );
            TenantDirectoryRefreshOutcome::Unchanged
        } else {
            refresher.install_initial(database_snapshot.clone()).await?
        }
    } else {
        refresher.install_legacy_initial(legacy_settings).await?
    };
    if database_initial
        && matches!(outcome, TenantDirectoryRefreshOutcome::Applied { .. })
        && let Err(error) = directory_cache
            .publish_authoritative(&database_snapshot)
            .await
    {
        tracing::warn!(%error, "tenant directory cache initial publish failed");
    }

    // The queue is process-global, so exactly one worker claims it. Start it
    // only after every initial tenant graph has been built successfully.
    #[cfg(not(test))]
    let backchannel_logout_worker = match background::spawn_backchannel_logout_worker(
        process.persistence.provider().logout_delivery_store(),
        &process.route_settings,
    ) {
        Ok(worker) => Some(worker),
        Err(error) => {
            refresher.shutdown().await;
            return Err(error);
        }
    };
    #[cfg(test)]
    let backchannel_logout_worker = None;

    Ok(StartupRuntime {
        process,
        registry,
        refresher,
        backchannel_logout_worker,
    })
}

fn legacy_settings(config: &ConfigSource) -> anyhow::Result<Vec<Settings>> {
    Settings::from_config_all(config)
}
