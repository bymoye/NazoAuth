use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use actix_web::web;
use nazo_http_actix::{
    RuntimeModuleAdminError, RuntimeModuleAdminFuture, RuntimeModuleAdministration,
};
use nazo_postgres::{DbPool, RuntimeModuleRepository};
use nazo_runtime_modules::{
    ActiveModuleSnapshot, CasOutcome, CatalogDurations, DesiredMode, DesiredStateUpdate,
    DesiredStateUpdateOutcome, ModuleCatalog, ModuleEventPage, ModuleId, ModuleLifecycle,
    ModuleRevision, ModuleState, ModuleStateRepository, ReconcileOutcome, RegistryError,
    RuntimeModuleManagement, RuntimeModuleManagementError, RuntimeModuleRegistry,
    RuntimeModuleView,
};

use crate::settings::Settings;

pub(crate) type ServerRuntimeModuleRegistry =
    RuntimeModuleRegistry<RuntimeModuleRepository, ServerModuleLifecycle>;

#[derive(Clone)]
pub(crate) struct ServerModuleLifecycle {
    repository: Arc<RuntimeModuleRepository>,
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
    pub(crate) repository: Arc<RuntimeModuleRepository>,
    pub(crate) registry: Arc<ServerRuntimeModuleRegistry>,
    pub(crate) catalog: ModuleCatalog,
    pub(crate) instance_id: String,
}

impl RuntimeModules {
    pub(crate) async fn initialize(pool: DbPool, settings: &Settings) -> anyhow::Result<Self> {
        let inherited_enabled = inherited_enabled(settings);
        let catalog = module_catalog(settings, inherited_enabled.clone())?;
        let repository = Arc::new(RuntimeModuleRepository::new(pool));
        let lifecycle = Arc::new(ServerModuleLifecycle {
            repository: repository.clone(),
        });
        let instance_id = runtime_instance_id()?;
        let seed_registry = Arc::new(RuntimeModuleRegistry::new(
            repository.clone(),
            lifecycle.clone(),
            catalog.clone(),
            instance_id.clone(),
            ActiveModuleSnapshot {
                revision: ModuleRevision::new(0),
                accepting: inherited_enabled,
                draining: BTreeSet::new(),
            },
        ));
        let (accepting, draining) =
            seed_desired_states(&repository, &seed_registry, &catalog, &instance_id).await?;
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

    pub(crate) fn spawn_reconciler(modules: web::Data<Self>) {
        for module_id in ModuleId::ALL {
            let modules = modules.clone();
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(1));
                interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                loop {
                    interval.tick().await;
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
            });
        }
    }
}

struct ServerRuntimeModuleAdministration {
    management: RuntimeModuleManagement<RuntimeModuleRepository, ServerModuleLifecycle>,
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
        | RuntimeModuleManagementError::MissingCatalogSpec(_) => {
            tracing::error!(?error, "runtime module catalog is inconsistent");
            RuntimeModuleAdminError::CatalogInconsistent
        }
    }
}

fn module_catalog(
    settings: &Settings,
    inherited_enabled: BTreeSet<ModuleId>,
) -> anyhow::Result<ModuleCatalog> {
    let protocol = &settings.protocol;
    let session = &settings.session;
    let mut catalog = ModuleCatalog::fixed(
        CatalogDurations {
            device_authorization: Duration::from_secs(
                settings.device.device_authorization_ttl_seconds,
            ),
            ciba: Duration::from_secs(settings.ciba.ciba_auth_req_id_ttl_seconds),
            authorization_code: Duration::from_secs(protocol.auth_code_ttl_seconds),
            refresh_token: Duration::from_secs(
                u64::try_from(protocol.refresh_token_ttl_seconds)
                    .map_err(|_| anyhow::anyhow!("REFRESH_TOKEN_TTL_SECONDS cannot be negative"))?,
            ),
            session: Duration::from_secs(session.session_ttl_seconds),
        },
        inherited_enabled,
    )?;
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
    catalog = catalog.with_runtime_disable_blocked(runtime_disable_blocked);
    Ok(catalog)
}

#[cfg(test)]
pub(crate) fn runtime_module_registry_for_test(
    pool: DbPool,
    settings: &Settings,
) -> anyhow::Result<Arc<ServerRuntimeModuleRegistry>> {
    let inherited_enabled = inherited_enabled(settings);
    let catalog = module_catalog(settings, inherited_enabled.clone())?;
    let repository = Arc::new(RuntimeModuleRepository::new(pool));
    let lifecycle = Arc::new(ServerModuleLifecycle {
        repository: repository.clone(),
    });
    Ok(Arc::new(RuntimeModuleRegistry::new(
        repository,
        lifecycle,
        catalog,
        "token-test".to_owned(),
        ActiveModuleSnapshot {
            revision: ModuleRevision::new(0),
            accepting: inherited_enabled,
            draining: BTreeSet::new(),
        },
    )))
}

async fn seed_desired_states(
    repository: &RuntimeModuleRepository,
    registry: &ServerRuntimeModuleRegistry,
    catalog: &ModuleCatalog,
    instance_id: &str,
) -> anyhow::Result<(BTreeSet<ModuleId>, BTreeSet<ModuleId>)> {
    let mut accepting = BTreeSet::new();
    let mut draining = BTreeSet::new();
    for module_id in ModuleId::ALL {
        if repository.read_desired(module_id).await?.is_none() {
            match registry
                .set_desired_mode(
                    module_id,
                    DesiredMode::Inherit,
                    None,
                    None,
                    Some("initial configuration inheritance".to_owned()),
                    SystemTime::now(),
                )
                .await
                .map_err(|error| anyhow::anyhow!("runtime desired-state seed failed: {error:?}"))?
            {
                CasOutcome::Applied(_) | CasOutcome::Stale { .. } => {}
            }
        }
        let desired = repository
            .read_desired(module_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("runtime desired state is missing after seed"))?;
        let enabled = desired.mode.resolve(catalog.inherited_enabled(module_id));
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

pub(crate) fn inherited_enabled(settings: &Settings) -> BTreeSet<ModuleId> {
    let settings = &settings.modules;
    let mut enabled = BTreeSet::from([
        ModuleId::TokenExchange,
        ModuleId::JwtBearerGrant,
        ModuleId::Jarm,
        ModuleId::Scim,
    ]);
    let configured = [
        (
            ModuleId::DeviceAuthorization,
            settings.enable_device_authorization_grant,
        ),
        (ModuleId::Ciba, settings.enable_ciba),
        (
            ModuleId::DynamicClientRegistration,
            settings.enable_dynamic_client_registration,
        ),
        (
            ModuleId::RequestObjects,
            settings.enable_request_object || settings.enable_par_request_object,
        ),
        (
            ModuleId::AuthorizationDetails,
            settings.enable_authorization_details,
        ),
        (
            ModuleId::HttpMessageSignatures,
            settings.enable_fapi_http_signatures,
        ),
        (ModuleId::NativeSso, settings.enable_native_sso),
        (
            ModuleId::FrontchannelLogout,
            settings.enable_frontchannel_logout,
        ),
        (
            ModuleId::SessionManagement,
            settings.enable_session_management,
        ),
    ];
    enabled.extend(
        configured
            .into_iter()
            .filter_map(|(module_id, configured)| configured.then_some(module_id)),
    );
    enabled
}

fn runtime_instance_id() -> anyhow::Result<String> {
    let configured =
        std::env::var("NAZO_RUNTIME_INSTANCE_ID").unwrap_or_else(|_| "primary".to_owned());
    if configured.is_empty()
        || configured.len() > 255
        || !configured.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.')
        })
    {
        anyhow::bail!(
            "NAZO_RUNTIME_INSTANCE_ID must be 1..=255 ASCII letters, digits, dots, dashes, or underscores"
        );
    }
    Ok(configured)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ConfigSource;

    #[test]
    fn instance_id_is_nonempty_and_storage_bounded() {
        let instance_id = runtime_instance_id().expect("default runtime instance id is valid");
        assert!(!instance_id.trim().is_empty());
        assert!(instance_id.len() <= 255);
    }

    #[test]
    fn par_request_objects_enable_the_shared_request_object_capability() {
        let mut settings =
            Settings::from_config(&ConfigSource::default()).expect("default settings should load");
        settings.modules.enable_request_object = false;
        settings.modules.enable_par_request_object = true;

        assert!(inherited_enabled(&settings).contains(&ModuleId::RequestObjects));
    }
}
