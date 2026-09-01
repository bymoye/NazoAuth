use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use actix_web::web;
use nazo_http_actix::{
    RuntimeModuleAdminError, RuntimeModuleAdminFuture, RuntimeModuleAdministration,
};
use nazo_runtime_modules::{
    ActiveModuleSnapshot, CasOutcome, CatalogDurations, DesiredRevisionGuard, DesiredStateChange,
    DesiredStateRecord, DesiredStateUpdate, DesiredStateUpdateOutcome, InstanceStateMutation,
    InstanceStateRecord, ModuleCatalog, ModuleEventPage, ModuleId, ModuleLifecycle, ModuleRevision,
    ModuleState, ModuleStateRepository, ReconcileOutcome, RegistryError, RuntimeModuleManagement,
    RuntimeModuleManagementError, RuntimeModuleRegistry, RuntimeModuleView,
};

use crate::settings::Settings;

pub(crate) type ServerRuntimeModuleRegistry =
    RuntimeModuleRegistry<PersistenceRuntimeModuleRepository, ServerModuleLifecycle>;

#[derive(Clone)]
pub(crate) struct PersistenceRuntimeModuleRepository {
    store: Arc<dyn nazo_persistence::RuntimeModuleStore>,
}

impl PersistenceRuntimeModuleRepository {
    pub(crate) fn new(store: Arc<dyn nazo_persistence::RuntimeModuleStore>) -> Self {
        Self { store }
    }
}

impl ModuleStateRepository for PersistenceRuntimeModuleRepository {
    type Error = nazo_identity::ports::RepositoryError;

    async fn read_desired(
        &self,
        module_id: ModuleId,
    ) -> Result<Option<DesiredStateRecord>, Self::Error> {
        self.store.read_desired(module_id).await
    }

    async fn read_all_desired(&self) -> Result<Vec<DesiredStateRecord>, Self::Error> {
        self.store.read_all_desired().await
    }

    async fn compare_and_set_desired(
        &self,
        change: DesiredStateChange,
    ) -> Result<CasOutcome<DesiredStateRecord>, Self::Error> {
        self.store.compare_and_set_desired(change).await
    }

    async fn compare_and_set_desired_guarded(
        &self,
        change: DesiredStateChange,
        required_revisions: Vec<DesiredRevisionGuard>,
    ) -> Result<CasOutcome<DesiredStateRecord>, Self::Error> {
        self.store
            .compare_and_set_desired_guarded(change, required_revisions)
            .await
    }

    async fn read_instance(
        &self,
        instance_id: &str,
        module_id: ModuleId,
    ) -> Result<Option<InstanceStateRecord>, Self::Error> {
        self.store.read_instance(instance_id, module_id).await
    }

    async fn read_all_instances(
        &self,
        instance_id: &str,
    ) -> Result<Vec<InstanceStateRecord>, Self::Error> {
        self.store.read_all_instances(instance_id).await
    }

    async fn page_events(&self, offset: i64, limit: i64) -> Result<ModuleEventPage, Self::Error> {
        self.store.page_events(offset, limit).await
    }

    async fn compare_and_set_instance(
        &self,
        required_desired_revision: ModuleRevision,
        mutation: InstanceStateMutation,
    ) -> Result<CasOutcome<InstanceStateRecord>, Self::Error> {
        self.store
            .compare_and_set_instance(required_desired_revision, mutation)
            .await
    }

    async fn validate_revision(
        &self,
        module_id: ModuleId,
        expected: ModuleRevision,
    ) -> Result<bool, Self::Error> {
        self.store.validate_revision(module_id, expected).await
    }
}

#[derive(Clone)]
pub(crate) struct ServerModuleLifecycle {
    repository: Arc<PersistenceRuntimeModuleRepository>,
}

impl ModuleLifecycle for ServerModuleLifecycle {
    fn initialize(
        &self,
        _module_id: ModuleId,
    ) -> nazo_runtime_modules::LifecycleFuture<'_, Result<(), nazo_runtime_modules::LifecycleFailure>>
    {
        Box::pin(async { Ok(()) })
    }

    fn stop(
        &self,
        _module_id: ModuleId,
    ) -> nazo_runtime_modules::LifecycleFuture<'_, Result<(), nazo_runtime_modules::LifecycleFailure>>
    {
        Box::pin(async { Ok(()) })
    }

    fn drain_stored_transactions(
        &self,
        module_id: ModuleId,
        revision: ModuleRevision,
        remaining_duration: Duration,
    ) -> nazo_runtime_modules::LifecycleFuture<
        '_,
        Result<bool, nazo_runtime_modules::LifecycleFailure>,
    > {
        Box::pin(async move {
            let deadline = tokio::time::Instant::now() + remaining_duration;
            loop {
                if !self
                    .repository
                    .validate_revision(module_id, revision)
                    .await
                    .map_err(|_| nazo_runtime_modules::LifecycleFailure {
                        code: "drain_revision_lookup_failed",
                    })?
                {
                    return Err(nazo_runtime_modules::LifecycleFailure {
                        code: "revision_changed",
                    });
                }
                let now = tokio::time::Instant::now();
                if now >= deadline {
                    return Ok(true);
                }
                tokio::time::sleep((deadline - now).min(Duration::from_secs(1))).await;
            }
        })
    }
}

pub(crate) struct RuntimeModules {
    pub(crate) repository: Arc<PersistenceRuntimeModuleRepository>,
    pub(crate) registry: Arc<ServerRuntimeModuleRegistry>,
    pub(crate) catalog: ModuleCatalog,
    pub(crate) instance_id: String,
}

impl RuntimeModules {
    pub(crate) async fn initialize(
        store: Arc<dyn nazo_persistence::RuntimeModuleStore>,
        settings: &Settings,
        instance_id: &str,
    ) -> anyhow::Result<Self> {
        let repository = Arc::new(PersistenceRuntimeModuleRepository::new(store));
        let catalog = module_catalog(settings)?;
        let lifecycle = Arc::new(ServerModuleLifecycle {
            repository: repository.clone(),
        });
        let instance_id = instance_id.to_owned();
        let (accepting, draining) =
            load_explicit_desired_states(&repository, &catalog, &instance_id).await?;
        let registry = Arc::new(RuntimeModuleRegistry::new(
            repository.clone(),
            lifecycle,
            catalog.clone(),
            instance_id.clone(),
            ActiveModuleSnapshot {
                revision: ModuleRevision::new(0),
                accepting,
                draining,
            },
        ));
        let modules = Self {
            repository,
            registry,
            catalog,
            instance_id,
        };
        Ok(modules)
    }

    pub(crate) fn administration(&self) -> Arc<dyn RuntimeModuleAdministration> {
        Arc::new(ServerRuntimeModuleAdministration {
            management: RuntimeModuleManagement::new(
                self.repository.clone(),
                self.registry.clone(),
                self.catalog.clone(),
                self.instance_id.clone(),
            ),
        })
    }

    pub(crate) fn spawn_reconciler(modules: web::Data<Self>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(1));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                interval.tick().await;
                for module_id in ModuleId::ALL {
                    match modules.registry.reconcile_once(module_id).await {
                        Ok(ReconcileOutcome::NoChange) => {}
                        Ok(outcome) => {
                            tracing::info!(?module_id, ?outcome, "runtime module reconciled");
                        }
                        Err(error) => {
                            tracing::error!(?module_id, ?error, "runtime module reconcile failed");
                        }
                    }
                }
            }
        })
    }
}

struct ServerRuntimeModuleAdministration {
    management: RuntimeModuleManagement<PersistenceRuntimeModuleRepository, ServerModuleLifecycle>,
}

impl RuntimeModuleAdministration for ServerRuntimeModuleAdministration {
    fn list(&self) -> RuntimeModuleAdminFuture<'_, Vec<RuntimeModuleView>> {
        Box::pin(async { self.management.list().await.map_err(map_management_error) })
    }

    fn events(&self, offset: i64, limit: i64) -> RuntimeModuleAdminFuture<'_, ModuleEventPage> {
        Box::pin(async move {
            self.management
                .events(offset, limit)
                .await
                .map_err(map_management_error)
        })
    }

    fn update_desired(
        &self,
        update: DesiredStateUpdate,
    ) -> RuntimeModuleAdminFuture<'_, DesiredStateUpdateOutcome> {
        Box::pin(async move {
            self.management
                .update_desired(update)
                .await
                .map_err(map_management_error)
        })
    }
}

fn map_management_error(
    error: RuntimeModuleManagementError<nazo_identity::ports::RepositoryError>,
) -> RuntimeModuleAdminError {
    match error {
        RuntimeModuleManagementError::Repository(error)
        | RuntimeModuleManagementError::Registry(RegistryError::Repository(error)) => {
            tracing::warn!(%error, "runtime module administration repository failed");
            RuntimeModuleAdminError::Unavailable
        }
        RuntimeModuleManagementError::Registry(
            RegistryError::RuntimeDisableBlocked(_)
            | RegistryError::ActiveDependent { .. }
            | RegistryError::DependencyUnavailable { .. },
        ) => RuntimeModuleAdminError::PolicyConflict,
        RuntimeModuleManagementError::Registry(
            RegistryError::MissingDesiredState(_) | RegistryError::MissingCatalogSpec(_),
        )
        | RuntimeModuleManagementError::Registry(
            RegistryError::RevisionExhausted(_) | RegistryError::SnapshotRevisionExhausted,
        )
        | RuntimeModuleManagementError::MissingCatalogSpec(_)
        | RuntimeModuleManagementError::MissingDesiredState(_) => {
            tracing::error!(?error, "runtime module catalog is inconsistent");
            RuntimeModuleAdminError::CatalogInconsistent
        }
    }
}

fn module_catalog(settings: &Settings) -> anyhow::Result<ModuleCatalog> {
    let protocol = &settings.protocol;
    let session = &settings.session;
    let mut catalog = ModuleCatalog::fixed(CatalogDurations {
        device_authorization: Duration::from_secs(settings.device.device_authorization_ttl_seconds),
        ciba: Duration::from_secs(settings.ciba.ciba_auth_req_id_ttl_seconds),
        authorization_code: Duration::from_secs(protocol.auth_code_ttl_seconds),
        refresh_token: Duration::from_secs(
            u64::try_from(protocol.refresh_token_ttl_seconds)
                .map_err(|_| anyhow::anyhow!("REFRESH_TOKEN_TTL_SECONDS cannot be negative"))?,
        ),
        session: Duration::from_secs(session.session_ttl_seconds),
        scim_security_events: Duration::from_secs(settings.storage.scim_event_retention_seconds),
    })?;
    let mut runtime_disable_blocked = BTreeSet::new();
    if protocol
        .authorization_server_profile
        .requires_signed_authorization_request()
    {
        runtime_disable_blocked.insert(ModuleId::RequestObjects);
    }
    if protocol
        .authorization_server_profile
        .requires_signed_authorization_response()
    {
        runtime_disable_blocked.insert(ModuleId::Jarm);
    }
    catalog = catalog
        .with_dependencies(ModuleId::ScimSecurityEvents, [ModuleId::Scim])?
        .with_dependencies(
            ModuleId::Openid4vciIssuer,
            [ModuleId::AuthorizationDetails, ModuleId::RequestObjects],
        )?
        .with_dependencies(ModuleId::Openid4vpVerifier, [ModuleId::RequestObjects])?
        .with_dependencies(ModuleId::NativeSso, [ModuleId::TokenExchange])?
        .with_runtime_disable_blocked(runtime_disable_blocked);
    Ok(catalog)
}

async fn load_explicit_desired_states(
    repository: &PersistenceRuntimeModuleRepository,
    catalog: &ModuleCatalog,
    instance_id: &str,
) -> anyhow::Result<(BTreeSet<ModuleId>, BTreeSet<ModuleId>)> {
    let mut accepting = BTreeSet::new();
    let mut draining = BTreeSet::new();
    for module_id in ModuleId::ALL {
        let desired = repository
            .read_desired(module_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("runtime desired state is missing"))?;
        let enabled = desired.mode.is_enabled();
        if catalog.runtime_disable_blocked(module_id) && !enabled {
            anyhow::bail!(
                "runtime module {module_id:?} is required by the active security profile"
            );
        }
        if enabled {
            accepting.insert(module_id);
        } else if repository
            .read_instance(instance_id, module_id)
            .await?
            .is_some_and(|instance| {
                matches!(instance.state, ModuleState::Enabled | ModuleState::Draining)
                    && matches!(
                        catalog.spec(module_id).map(|spec| spec.disable_policy),
                        Some(nazo_runtime_modules::DisablePolicy::DrainStoredTransactions { .. })
                    )
            })
        {
            draining.insert(module_id);
        }
    }
    Ok((accepting, draining))
}

#[cfg(test)]
#[path = "../tests/support/runtime_modules.rs"]
pub(crate) mod test_support;

#[cfg(test)]
#[path = "../tests/unit/runtime_modules.rs"]
mod tests;
