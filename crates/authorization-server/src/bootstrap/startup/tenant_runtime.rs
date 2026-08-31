//! Process-local, immutable tenant runtime snapshots.
//!
//! PostgreSQL owns the directory. Valkey may accelerate propagation, but a
//! request only resolves its host in the immutable index owned here.

use std::{
    collections::{BTreeSet, HashMap},
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
    time::Duration,
};

use arc_swap::ArcSwap;
use nazo_identity::{TenantDirectoryBinding, TenantDirectorySnapshot, canonical_tenant_host};
use tokio::task::JoinHandle;

use super::{
    configuration::StartupConfiguration,
    services::{self, ServiceAssembly},
    *,
};

const DIRECTORY_CACHE_REFRESH_INTERVAL: Duration = Duration::from_secs(1);
const DIRECTORY_DATABASE_RECONCILE_INTERVAL: Duration = Duration::from_secs(5);

/// Process-wide resources independent from a tenant selection. `route_settings`
/// only describes the static route set and global module switches; it is never
/// used as a request tenant or CORS policy.
pub(super) struct ProcessRuntime {
    pub(super) config: ConfigSource,
    pub(super) perf_metrics_enabled: bool,
    /// The sole tenant allowed to reach deployment-global HTTP control routes.
    pub(super) control_tenant_id: nazo_identity::TenantId,
    pub(super) persistence: super::super::ServerPersistenceBindings,
    pub(super) state_backend: super::super::ServerStateBackendBindings,
    pub(super) token_issuance_response_keys: nazo_persistence::TokenIssuanceResponseKeyRing,
    pub(super) control_discovery: web::Data<crate::control_discovery::ControlDiscoveryEndpoint>,
    pub(super) runtime_modules: web::Data<RuntimeModules>,
    pub(super) database_pool_metrics: web::Data<dyn nazo_persistence::DatabasePoolMetricsPort>,
    pub(super) route_settings: Arc<Settings>,
}

/// A completely built tenant graph. It remains immutable while published;
/// replacements are new graphs that enter a new host-index snapshot.
pub(in crate::bootstrap) struct TenantRuntime {
    pub(in crate::bootstrap) binding: TenantDirectoryBinding,
    // `None` is solely a control-plane test runtime. Production construction
    // is private and always supplies an assembled HTTP graph.
    assembly: Option<Arc<ServiceAssembly>>,
    lifecycle: Arc<Mutex<TenantRuntimeLifecycle>>,
}

#[derive(Default)]
struct TenantRuntimeLifecycle {
    key_lifecycle: Option<JoinHandle<()>>,
    ciba_ping_worker: Option<JoinHandle<()>>,
    openid4vc_revocation_worker: Option<JoinHandle<()>>,
}

impl TenantRuntime {
    fn new(
        binding: TenantDirectoryBinding,
        assembly: Arc<ServiceAssembly>,
        lifecycle: Arc<Mutex<TenantRuntimeLifecycle>>,
    ) -> Self {
        Self {
            binding,
            assembly: Some(assembly),
            lifecycle,
        }
    }

    #[cfg(test)]
    pub(super) fn for_test(binding: TenantDirectoryBinding) -> Arc<Self> {
        Arc::new(Self {
            binding,
            assembly: None,
            lifecycle: Arc::new(Mutex::new(TenantRuntimeLifecycle::default())),
        })
    }

    #[cfg(test)]
    pub(super) fn for_test_reusing(
        binding: TenantDirectoryBinding,
        previous: &Arc<Self>,
    ) -> Arc<Self> {
        Arc::new(Self {
            binding,
            assembly: None,
            lifecycle: previous.lifecycle.clone(),
        })
    }

    #[cfg(test)]
    pub(super) fn shares_lifecycle_with(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.lifecycle, &other.lifecycle)
    }

    pub(super) fn assembly(&self) -> &Arc<ServiceAssembly> {
        self.assembly
            .as_ref()
            .expect("test tenant runtime has no HTTP service assembly")
    }

    /// Used only by the HTTP CORS predicate after a host lookup in this same
    /// in-process registry. It never reads an external source.
    pub(in crate::bootstrap) fn cors_allowed_origins(&self) -> &[String] {
        &self
            .assembly()
            .startup
            .settings
            .endpoint
            .cors_allowed_origins
    }

    async fn start_lifecycle(&self) -> anyhow::Result<()> {
        let Some(assembly) = self.assembly.as_ref() else {
            return Ok(());
        };
        let mut lifecycle = self
            .lifecycle
            .lock()
            .expect("tenant runtime lifecycle mutex is not poisoned");
        if lifecycle.key_lifecycle.is_some() {
            return Ok(());
        }

        // Construct the only fallible worker before starting the key worker.
        // If it rejects configuration, no candidate has started a lifecycle.
        #[cfg(not(test))]
        let ciba_ping_worker = background::spawn_ciba_ping_worker(
            assembly
                .startup
                .transient_state
                .provider()
                .ciba_ping_deliveries(),
            &assembly.startup.settings,
            assembly.startup.runtime_modules.get_ref(),
        )?;
        #[cfg(test)]
        let ciba_ping_worker = None;

        let openid4vc_revocation_worker = assembly
            .openid4vc_revocation_policy()
            .filter(|policy| policy.is_enabled())
            .zip(
                assembly
                    .startup
                    .settings
                    .openid4vc
                    .revocation_snapshot_file
                    .as_ref(),
            )
            .map(|(policy, path)| {
                background::spawn_revocation_snapshot_reloader(
                    policy.clone(),
                    path.clone(),
                    Duration::from_secs(
                        assembly
                            .startup
                            .settings
                            .openid4vc
                            .revocation_reload_interval_seconds,
                    ),
                )
            });

        let key_lifecycle = background::spawn_key_lifecycle(assembly.startup.keyset.clone());
        lifecycle.key_lifecycle = Some(key_lifecycle);
        lifecycle.ciba_ping_worker = ciba_ping_worker;
        lifecycle.openid4vc_revocation_worker = openid4vc_revocation_worker;
        Ok(())
    }

    async fn stop_lifecycle(&self) {
        let Some(assembly) = self.assembly.as_ref() else {
            return;
        };

        // Remove this graph from the index before calling this method. The key
        // manager first receives its cooperative stop signal; its task is not
        // aborted while it may be writing key material.
        assembly.startup.keyset.stop_lifecycle();
        let (key_lifecycle, ciba_ping_worker, openid4vc_revocation_worker) = {
            let mut lifecycle = self
                .lifecycle
                .lock()
                .expect("tenant runtime lifecycle mutex is not poisoned");
            (
                lifecycle.key_lifecycle.take(),
                lifecycle.ciba_ping_worker.take(),
                lifecycle.openid4vc_revocation_worker.take(),
            )
        };
        if let Some(worker) = openid4vc_revocation_worker {
            worker.abort();
            if let Err(error) = worker.await
                && !error.is_cancelled()
            {
                tracing::warn!(%error, "tenant OpenID4VC revocation worker stopped unexpectedly");
            }
        }
        if let Some(worker) = ciba_ping_worker {
            worker.abort();
            if let Err(error) = worker.await
                && !error.is_cancelled()
            {
                tracing::warn!(%error, "tenant CIBA ping worker stopped unexpectedly");
            }
        }
        if let Some(worker) = key_lifecycle
            && let Err(error) = worker.await
        {
            tracing::warn!(%error, "tenant key lifecycle stopped unexpectedly");
        }
    }
}

/// Immutable mapping used by every request in one process.
pub(in crate::bootstrap) struct TenantHostIndex {
    pub(in crate::bootstrap) revision: u64,
    pub(in crate::bootstrap) by_host: HashMap<String, Arc<TenantRuntime>>,
}

impl TenantHostIndex {
    fn empty() -> Self {
        Self {
            revision: 0,
            by_host: HashMap::new(),
        }
    }
}

/// The one process-local tenant registry. A load returns a single immutable
/// snapshot, so a worker cannot observe a half-applied directory change.
#[derive(Clone)]
pub(crate) struct TenantRuntimeRegistry {
    current: Arc<ArcSwap<TenantHostIndex>>,
}

impl TenantRuntimeRegistry {
    pub(super) fn empty() -> Self {
        Self {
            current: Arc::new(ArcSwap::from_pointee(TenantHostIndex::empty())),
        }
    }

    pub(in crate::bootstrap) fn load(&self) -> Arc<TenantHostIndex> {
        self.current.load_full()
    }

    pub(in crate::bootstrap) fn revision(&self) -> u64 {
        self.load().revision
    }

    pub(in crate::bootstrap) fn resolve(&self, host: &str) -> Option<Arc<TenantRuntime>> {
        self.load().by_host.get(host).cloned()
    }

    pub(crate) fn contains_tenant(&self, tenant_id: nazo_identity::TenantId) -> bool {
        self.load()
            .by_host
            .values()
            .any(|runtime| runtime.binding.tenant.tenant_id == tenant_id)
    }

    fn replace(&self, next: TenantHostIndex) -> Arc<TenantHostIndex> {
        // Refreshes are serialized by TenantRuntimeRefresher. Loading before
        // the store lets retirement act only on old, displaced graphs.
        let previous = self.load();
        self.current.store(Arc::new(next));
        previous
    }
}

pub(super) type TenantRuntimeBuildFuture<'a> =
    Pin<Box<dyn Future<Output = anyhow::Result<Arc<TenantRuntime>>> + Send + 'a>>;

/// Control-plane boundary for candidate construction. The refresher only
/// knows that a complete tenant graph is returned or an error occurs; this
/// makes the all-or-nothing swap independently testable without weakening the
/// production construction path.
pub(super) trait TenantRuntimeBuildPort: Send + Sync {
    fn build(
        &self,
        binding: &TenantDirectoryBinding,
        previous_same_tenant: Option<Arc<TenantRuntime>>,
    ) -> TenantRuntimeBuildFuture<'_>;
}

#[derive(Clone)]
pub(super) struct TenantRuntimeBuilder {
    port: Arc<dyn TenantRuntimeBuildPort>,
}

impl TenantRuntimeBuilder {
    #[allow(dead_code)]
    pub(super) fn new(port: Arc<dyn TenantRuntimeBuildPort>) -> Self {
        Self { port }
    }

    pub(super) fn production(process: Arc<ProcessRuntime>) -> Self {
        Self {
            port: Arc::new(ServiceAssemblyTenantRuntimeBuilder { process }),
        }
    }

    async fn build(
        &self,
        binding: &TenantDirectoryBinding,
        previous_same_tenant: Option<Arc<TenantRuntime>>,
    ) -> anyhow::Result<Arc<TenantRuntime>> {
        self.port.build(binding, previous_same_tenant).await
    }
}

struct ServiceAssemblyTenantRuntimeBuilder {
    process: Arc<ProcessRuntime>,
}

impl TenantRuntimeBuildPort for ServiceAssemblyTenantRuntimeBuilder {
    fn build(
        &self,
        binding: &TenantDirectoryBinding,
        _previous_same_tenant: Option<Arc<TenantRuntime>>,
    ) -> TenantRuntimeBuildFuture<'_> {
        let process = self.process.clone();
        let binding = binding.clone();
        Box::pin(async move {
            let settings = Arc::new(Settings::from_directory_binding(&process.config, &binding)?);
            build_service_runtime(process, binding, settings).await
        })
    }
}

async fn build_service_runtime(
    process: Arc<ProcessRuntime>,
    binding: TenantDirectoryBinding,
    settings: Arc<Settings>,
) -> anyhow::Result<Arc<TenantRuntime>> {
    process
        .persistence
        .provider()
        .active_tenant_boundary()
        .preflight(settings.tenant.context)
        .await
        .map_err(|error| {
            anyhow::anyhow!(
                "active tenant boundary preflight failed for {}: {error}",
                settings.tenant.context.tenant_id.as_uuid()
            )
        })?;
    let transient_state = process
        .state_backend
        .for_tenant(settings.tenant.context.tenant_id)
        .map_err(|error| anyhow::anyhow!("tenant transient state binding failed: {error}"))?;
    let keyset = nazo_key_management::KeyManager::load_or_create(settings.key_settings()).await?;
    let lifecycle = Arc::new(Mutex::new(TenantRuntimeLifecycle::default()));
    tokio::fs::create_dir_all(&settings.storage.avatar_storage_dir).await?;
    let readiness_dependencies =
        web::Data::new(crate::http::well_known::ReadinessDependencies::new(
            process.persistence.provider().database_health(),
            transient_state.provider().health(),
            keyset.clone(),
        ));
    let remote_client_documents = Arc::new(
        crate::domain::remote_client_documents::RemoteClientDocumentResolver::new(
            &settings.modules.remote_client_document_private_origins,
        )
        .map_err(anyhow::Error::msg)?,
    );
    let mtls_certificate_source = web::Data::new(crate::http::mtls::MtlsCertificateSource::new(
        settings.endpoint.mtls_certificate_source,
    ));
    let startup = StartupConfiguration {
        config: process.config.clone(),
        persistence: process.persistence.clone(),
        transient_state,
        settings,
        token_issuance_response_keys: process.token_issuance_response_keys.clone(),
        control_discovery: process.control_discovery.clone(),
        mtls_certificate_source,
        readiness_dependencies,
        remote_client_documents,
        runtime_modules: process.runtime_modules.clone(),
        keyset,
    };
    let assembly = Arc::new(services::build(startup).await?);
    Ok(Arc::new(TenantRuntime::new(binding, assembly, lifecycle)))
}

/// Observable result for one refresh attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum TenantDirectoryRefreshOutcome {
    Applied { revision: u64 },
    Unchanged,
}

#[derive(Default)]
struct TenantDirectoryRefreshState {
    // Cache-applied revisions deliberately do not advance this fence. The DB
    // reconciler must eventually read the authoritative payload for them.
    last_database_revision: u64,
    // A cache revision proven ahead of PostgreSQL is ignored until the DB
    // catches up, rather than being re-applied every one-second cache tick.
    rejected_cache_revision: Option<u64>,
}

#[derive(Clone, Copy)]
enum SnapshotSource {
    Cache,
    Database,
}

/// Coordinates cache and authoritative-directory refreshes. Its mutex is
/// control-plane-only and prevents concurrent builds/retirements.
pub(super) struct TenantRuntimeRefresher {
    registry: TenantRuntimeRegistry,
    directory: Arc<dyn nazo_persistence::TenantDirectoryStore>,
    cache: Arc<dyn super::super::TenantDirectoryCachePort>,
    builder: TenantRuntimeBuilder,
    gate: tokio::sync::Mutex<()>,
    state: Mutex<TenantDirectoryRefreshState>,
}

impl TenantRuntimeRefresher {
    pub(super) fn new(
        registry: TenantRuntimeRegistry,
        directory: Arc<dyn nazo_persistence::TenantDirectoryStore>,
        cache: Arc<dyn super::super::TenantDirectoryCachePort>,
        builder: TenantRuntimeBuilder,
    ) -> Self {
        Self {
            registry,
            directory,
            cache,
            builder,
            gate: tokio::sync::Mutex::new(()),
            state: Mutex::new(TenantDirectoryRefreshState::default()),
        }
    }

    pub(super) async fn install_initial(
        &self,
        snapshot: TenantDirectorySnapshot,
    ) -> anyhow::Result<TenantDirectoryRefreshOutcome> {
        let _guard = self.gate.lock().await;
        let outcome = self
            .apply_snapshot(snapshot.clone(), SnapshotSource::Database)
            .await?;
        self.state
            .lock()
            .expect("tenant directory refresh state mutex is not poisoned")
            .last_database_revision = snapshot.revision;
        Ok(outcome)
    }

    /// High-frequency cache path. An equal/older hit never touches PostgreSQL;
    /// a miss, corrupt value, or unavailable cache uses the DB reconciliation.
    pub(super) async fn refresh_cache_once(&self) -> anyhow::Result<TenantDirectoryRefreshOutcome> {
        let _guard = self.gate.lock().await;
        let local_revision = self.registry.revision();
        match self.cache.load().await {
            Ok(Some(snapshot))
                if snapshot.revision > local_revision
                    && self
                        .state
                        .lock()
                        .expect("tenant directory refresh state mutex is not poisoned")
                        .rejected_cache_revision
                        != Some(snapshot.revision) =>
            {
                // The cache can decode a snapshot whose routing identity is
                // nevertheless invalid. Treat that as cache corruption, not
                // as an authority error: repair from PostgreSQL and avoid
                // retrying an ahead-of-DB value every cache tick.
                if let Err(error) = validate_snapshot(&snapshot) {
                    tracing::warn!(%error, revision = snapshot.revision, "tenant directory cache snapshot is invalid; reconciling from database");
                    let candidate_revision = snapshot.revision;
                    let outcome = self.reconcile_database_locked(true).await?;
                    let last_database_revision = self
                        .state
                        .lock()
                        .expect("tenant directory refresh state mutex is not poisoned")
                        .last_database_revision;
                    if last_database_revision < candidate_revision {
                        self.state
                            .lock()
                            .expect("tenant directory refresh state mutex is not poisoned")
                            .rejected_cache_revision = Some(candidate_revision);
                    }
                    return Ok(outcome);
                }
                self.apply_snapshot(snapshot, SnapshotSource::Cache).await
            }
            Ok(Some(_)) => Ok(TenantDirectoryRefreshOutcome::Unchanged),
            Ok(None) | Err(_) => self.reconcile_database_locked(true).await,
        }
    }

    /// Low-frequency authoritative reconciliation. It loads the full directory
    /// only after its compact revision fence proves a newer value exists.
    pub(super) async fn reconcile_database_once(
        &self,
    ) -> anyhow::Result<TenantDirectoryRefreshOutcome> {
        let _guard = self.gate.lock().await;
        self.reconcile_database_locked(false).await
    }

    /// Stops every tenant-owned lifecycle after the HTTP server has stopped.
    /// The refresh task is aborted first by `services::run`, so this owns the
    /// only remaining registry mutation during shutdown.
    pub(super) async fn shutdown(&self) {
        let _guard = self.gate.lock().await;
        let previous = self.registry.replace(TenantHostIndex::empty());
        for runtime in previous.by_host.values() {
            runtime.stop_lifecycle().await;
        }
    }

    async fn reconcile_database_locked(
        &self,
        repair_cache: bool,
    ) -> anyhow::Result<TenantDirectoryRefreshOutcome> {
        let local_revision = self.registry.revision();
        let last_database_revision = self
            .state
            .lock()
            .expect("tenant directory refresh state mutex is not poisoned")
            .last_database_revision;
        let revision =
            self.directory.current_revision().await.map_err(|error| {
                anyhow::anyhow!("tenant directory revision read failed: {error}")
            })?;
        if !repair_cache && revision == last_database_revision && revision == local_revision {
            return Ok(TenantDirectoryRefreshOutcome::Unchanged);
        }
        let snapshot = self
            .directory
            .load_active()
            .await
            .map_err(|error| anyhow::anyhow!("tenant directory read failed: {error}"))?;
        if snapshot.revision != revision {
            anyhow::bail!(
                "tenant directory revision changed during read (expected {revision}, got {})",
                snapshot.revision
            );
        }
        let cache_was_ahead = local_revision > revision;
        let outcome = self
            .apply_snapshot(snapshot.clone(), SnapshotSource::Database)
            .await?;
        {
            let mut state = self
                .state
                .lock()
                .expect("tenant directory refresh state mutex is not poisoned");
            state.last_database_revision = revision;
            if cache_was_ahead {
                state.rejected_cache_revision = Some(local_revision);
            } else if state
                .rejected_cache_revision
                .is_some_and(|rejected| revision >= rejected)
            {
                state.rejected_cache_revision = None;
            }
        }
        if (repair_cache || matches!(outcome, TenantDirectoryRefreshOutcome::Applied { .. }))
            && let Err(error) = self.cache.publish_authoritative(&snapshot).await
        {
            tracing::warn!(%error, "tenant directory cache update failed after local publish");
        }
        Ok(outcome)
    }

    async fn apply_snapshot(
        &self,
        snapshot: TenantDirectorySnapshot,
        source: SnapshotSource,
    ) -> anyhow::Result<TenantDirectoryRefreshOutcome> {
        let current = self.registry.load();
        if matches!(source, SnapshotSource::Cache) && snapshot.revision <= current.revision {
            return Ok(TenantDirectoryRefreshOutcome::Unchanged);
        }
        validate_snapshot(&snapshot)?;

        let existing = current
            .by_host
            .values()
            .map(|runtime| (runtime.binding.tenant.tenant_id, runtime.clone()))
            .collect::<HashMap<_, _>>();
        let mut by_host = HashMap::with_capacity(snapshot.tenants.len());
        let mut newly_built = Vec::new();
        for binding in &snapshot.tenants {
            let runtime = match existing.get(&binding.tenant.tenant_id) {
                Some(runtime) if runtime.binding == *binding => runtime.clone(),
                _ => {
                    let runtime = self
                        .builder
                        .build(binding, existing.get(&binding.tenant.tenant_id).cloned())
                        .await?;
                    newly_built.push(runtime.clone());
                    runtime
                }
            };
            by_host.insert(binding.external_host.clone(), runtime);
        }

        self.publish_candidate(snapshot, by_host, newly_built).await
    }

    async fn publish_candidate(
        &self,
        snapshot: TenantDirectorySnapshot,
        by_host: HashMap<String, Arc<TenantRuntime>>,
        newly_built: Vec<Arc<TenantRuntime>>,
    ) -> anyhow::Result<TenantDirectoryRefreshOutcome> {
        // Candidate lifecycles have no request visibility yet. If any start
        // fails, retire the already-started candidates and retain last-good.
        let mut started: Vec<Arc<TenantRuntime>> = Vec::with_capacity(newly_built.len());
        for runtime in &newly_built {
            if let Err(error) = runtime.start_lifecycle().await {
                for started_runtime in started {
                    started_runtime.stop_lifecycle().await;
                }
                return Err(error);
            }
            started.push(runtime.clone());
        }

        let previous = self.registry.replace(TenantHostIndex {
            revision: snapshot.revision,
            by_host,
        });
        let next = self.registry.load();
        for runtime in previous.by_host.values() {
            let retained = next
                .by_host
                .values()
                .any(|candidate| Arc::ptr_eq(candidate, runtime));
            let lifecycle_reused = next
                .by_host
                .values()
                .any(|candidate| Arc::ptr_eq(&candidate.lifecycle, &runtime.lifecycle));
            if !retained && !lifecycle_reused {
                runtime.stop_lifecycle().await;
            }
        }
        Ok(TenantDirectoryRefreshOutcome::Applied {
            revision: snapshot.revision,
        })
    }
}

/// Starts the bounded cache and database refresh loops for the process lifetime.
pub(super) fn spawn_directory_refresher(refresher: Arc<TenantRuntimeRefresher>) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut cache = tokio::time::interval(DIRECTORY_CACHE_REFRESH_INTERVAL);
        cache.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut database = tokio::time::interval(DIRECTORY_DATABASE_RECONCILE_INTERVAL);
        database.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        cache.tick().await;
        database.tick().await;
        loop {
            tokio::select! {
                _ = cache.tick() => {
                    if let Err(error) = refresher.refresh_cache_once().await {
                        tracing::warn!(%error, "tenant directory cache refresh failed; retaining last-good index");
                    }
                }
                _ = database.tick() => {
                    if let Err(error) = refresher.reconcile_database_once().await {
                        tracing::warn!(%error, "tenant directory database reconciliation failed; retaining last-good index");
                    }
                }
            }
        }
    })
}

fn validate_snapshot(snapshot: &TenantDirectorySnapshot) -> anyhow::Result<()> {
    let mut tenant_ids = BTreeSet::new();
    let mut issuers = BTreeSet::new();
    let mut hosts = BTreeSet::new();
    for binding in &snapshot.tenants {
        if binding.runtime_revision == 0 {
            anyhow::bail!("tenant runtime revision must be positive");
        }
        let external_host = canonical_tenant_host(&binding.external_host).map_err(|error| {
            anyhow::anyhow!("tenant directory external_host is invalid: {error}")
        })?;
        if external_host != binding.external_host {
            anyhow::bail!("tenant directory external_host must be canonical");
        }
        nazo_auth::validate_issuer_url(&binding.issuer)
            .map_err(|error| anyhow::anyhow!("tenant directory issuer is invalid: {error}"))?;
        let issuer = url::Url::parse(&binding.issuer)?;
        let issuer_host = issuer
            .host()
            .ok_or_else(|| anyhow::anyhow!("tenant directory issuer must include a host"))?;
        let issuer_host = match issuer_host {
            url::Host::Domain(domain) => canonical_tenant_host(domain),
            url::Host::Ipv4(address) => canonical_tenant_host(&address.to_string()),
            url::Host::Ipv6(address) => canonical_tenant_host(&format!("[{address}]")),
        }
        .map_err(|error| anyhow::anyhow!("tenant directory issuer host is invalid: {error}"))?;
        if issuer_host != external_host {
            anyhow::bail!(
                "tenant directory issuer host {issuer_host} does not match external_host {external_host}"
            );
        }
        if !tenant_ids.insert(binding.tenant.tenant_id.as_uuid()) {
            anyhow::bail!("tenant directory contains duplicate tenant_id");
        }
        if !issuers.insert(issuer.to_string()) {
            anyhow::bail!("tenant directory contains duplicate issuer");
        }
        if !hosts.insert(external_host) {
            anyhow::bail!("tenant directory contains duplicate external_host");
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "../../../tests/unit/bootstrap/startup/tenant_runtime.rs"]
mod tests;
