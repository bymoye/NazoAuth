use super::*;

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
