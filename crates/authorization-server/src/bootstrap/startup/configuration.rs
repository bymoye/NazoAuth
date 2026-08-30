use super::*;
use crate::config::DEFAULT_DATA_DIR;

/// Values initialized once for the process and shared by all service
/// adapters.  The persistence and transient-state providers, settings,
/// runtime registry, and keyset have one owner here; service assembly only
/// requests focused semantic handles.
pub(super) struct StartupConfiguration {
    pub(super) config: ConfigSource,
    pub(super) perf_metrics_enabled: bool,
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

pub(super) async fn load(
    config: ConfigSource,
    persistence: super::super::ServerPersistenceBindings,
    transient_state_launcher: &dyn crate::cli::TransientStateLauncher,
) -> anyhow::Result<StartupConfiguration> {
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

    // 配置只在启动阶段读取；运行期只向 handler 注入其所需的 focused handles。
    let settings = Arc::new(Settings::from_config(&config)?);
    let audit_anchor_data_dir = config.persistent_path("DATA_DIR", Some(DEFAULT_DATA_DIR))?;
    let audit_anchor_preflight = crate::adapters::audit_anchor::AuditAnchorPreflight::new(
        crate::adapters::audit_anchor::preflight_config_from_source(
            &config,
            &audit_anchor_data_dir,
        )?,
    )?;
    let control_discovery = web::Data::new(
        crate::control_discovery::ControlDiscoveryEndpoint::initialize(
            &settings.storage.data_dir,
            config
                .optional_string("INSTANCE_IDENTITY_DIR")
                .map(|_| config.persistent_path("INSTANCE_IDENTITY_DIR", None))
                .transpose()?
                .as_deref(),
            config.optional_string("DEPLOYMENT_ID").as_deref(),
            config.optional_string("RUNTIME_INSTANCE_ID").as_deref(),
            &settings.endpoint.issuer,
        )?,
    );
    // The database tenant boundary must succeed before the launcher may bind
    // its transient-state namespace. Some backends persist that ownership
    // claim, so reversing this order could bind the wrong tenant permanently.
    persistence
        .provider()
        .active_tenant_boundary()
        .preflight(settings.tenant.context)
        .await
        .map_err(|error| anyhow::anyhow!("active tenant boundary preflight failed: {error}"))?;
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
    let transient_state = transient_state_launcher
        .server_bindings(
            &config,
            control_discovery.deployment_id(),
            settings.tenant.context.tenant_id,
        )
        .await
        .map_err(|error| anyhow::anyhow!("transient-state preflight failed: {error}"))?;

    let token_issuance_response_keys = token_issuance_response_key_ring(&config)?;
    let mtls_certificate_source = web::Data::new(crate::http::mtls::MtlsCertificateSource::new(
        settings.endpoint.mtls_certificate_source,
    ));
    let keyset = nazo_key_management::KeyManager::load_or_create(settings.key_settings()).await?;
    let readiness_dependencies =
        web::Data::new(crate::http::well_known::ReadinessDependencies::new(
            persistence.provider().database_health(),
            transient_state.provider().health(),
            keyset.clone(),
        ));
    let remote_client_documents = Arc::new(
        crate::domain::remote_client_documents::RemoteClientDocumentResolver::new(
            &settings.modules.remote_client_document_private_origins,
        )
        .map_err(anyhow::Error::msg)?,
    );
    let runtime_modules = web::Data::new(
        RuntimeModules::initialize(
            persistence.provider().runtime_modules(),
            &settings,
            control_discovery.runtime_instance_id(),
        )
        .await?,
    );
    background::spawn_runtime_reconciler(runtime_modules.clone());
    tokio::fs::create_dir_all(&settings.storage.avatar_storage_dir).await?;
    background::spawn_key_lifecycle(keyset.clone());

    Ok(StartupConfiguration {
        config,
        perf_metrics_enabled,
        persistence,
        transient_state,
        settings,
        token_issuance_response_keys,
        control_discovery,
        mtls_certificate_source,
        readiness_dependencies,
        remote_client_documents,
        runtime_modules,
        keyset,
    })
}
