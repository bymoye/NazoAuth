use crate::{
    InstanceStateRecord, LifecycleFailure, ModuleId, ModuleLifecycle, ModuleStateRepository,
    ReconcileOutcome, RegistryError,
};

use super::RuntimeModuleRegistry;

impl<R, L> RuntimeModuleRegistry<R, L>
where
    R: ModuleStateRepository,
    L: ModuleLifecycle,
{
    pub(super) async fn first_unavailable_dependency(
        &self,
        module_id: ModuleId,
    ) -> Result<Option<ModuleId>, RegistryError<R::Error>> {
        let spec = self
            .catalog
            .spec(module_id)
            .ok_or(RegistryError::MissingCatalogSpec(module_id))?;
        let snapshot = self.snapshot();
        for dependency in &spec.dependencies {
            let desired = self
                .repository
                .read_desired(*dependency)
                .await
                .map_err(RegistryError::Repository)?
                .ok_or(RegistryError::MissingDesiredState(*dependency))?;
            if !desired
                .mode
                .resolve(self.catalog.inherited_enabled(*dependency))
                || !snapshot.admits(*dependency)
            {
                return Ok(Some(*dependency));
            }
        }
        Ok(None)
    }

    pub(super) async fn first_enabled_dependent(
        &self,
        module_id: ModuleId,
    ) -> Result<Option<ModuleId>, RegistryError<R::Error>> {
        let snapshot = self.snapshot();
        for dependent in self
            .catalog
            .specs()
            .values()
            .filter(|candidate| candidate.dependencies.contains(&module_id))
        {
            let desired = self
                .repository
                .read_desired(dependent.id)
                .await
                .map_err(RegistryError::Repository)?
                .ok_or(RegistryError::MissingDesiredState(dependent.id))?;
            if desired
                .mode
                .resolve(self.catalog.inherited_enabled(dependent.id))
                || snapshot.admits(dependent.id)
            {
                return Ok(Some(dependent.id));
            }
        }
        Ok(None)
    }

    pub(super) async fn fail_dependency_loss(
        &self,
        current: &InstanceStateRecord,
        initialized: bool,
    ) -> Result<ReconcileOutcome, RegistryError<R::Error>> {
        if self.snapshot().admits(current.module_id) {
            self.publish(current.module_id, false, false)?;
        }
        let failure = if initialized {
            self.lifecycle
                .stop(current.module_id)
                .await
                .err()
                .unwrap_or(LifecycleFailure {
                    code: "dependency_unavailable",
                })
        } else {
            LifecycleFailure {
                code: "dependency_unavailable",
            }
        };
        let failed = self.persist_failure(current, failure).await?;
        Ok(if failed {
            ReconcileOutcome::Failed
        } else {
            ReconcileOutcome::StaleDiscarded
        })
    }
}
