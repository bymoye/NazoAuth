use super::*;
use nazo_postgres::{DbPool, RuntimeModuleRepository};

pub(crate) fn runtime_module_registry_for_test(
    pool: DbPool,
    settings: &Settings,
) -> anyhow::Result<Arc<ServerRuntimeModuleRegistry>> {
    runtime_module_registry_with_modules_for_test(
        pool,
        settings,
        crate::test_support::persisted_runtime_modules_fixture(),
    )
}

pub(crate) fn runtime_module_registry_with_modules_for_test(
    pool: DbPool,
    settings: &Settings,
    active_modules: BTreeSet<ModuleId>,
) -> anyhow::Result<Arc<ServerRuntimeModuleRegistry>> {
    let catalog = module_catalog(settings)?;
    let store = Arc::new(RuntimeModuleRepository::new(pool));
    let repository = Arc::new(PersistenceRuntimeModuleRepository::new(store));
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
            accepting: active_modules,
            draining: BTreeSet::new(),
        },
    )))
}
