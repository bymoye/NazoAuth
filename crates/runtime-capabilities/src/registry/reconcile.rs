use crate::{
    ModuleId, ModuleLifecycle, ModuleState, ModuleStateRepository, ReconcileOutcome, RegistryError,
};

use super::RuntimeModuleRegistry;

impl<R, L> RuntimeModuleRegistry<R, L>
where
    R: ModuleStateRepository,
    L: ModuleLifecycle,
{
    pub async fn reconcile_once(
        &self,
        module_id: ModuleId,
    ) -> Result<ReconcileOutcome, RegistryError<R::Error>> {
        let transition_lock = self
            .transition_locks
            .get(&module_id)
            .expect("the closed module catalog must have a transition lock");
        let _transition_guard = transition_lock.lock().await;
        self.reconcile_once_serialized(module_id).await
    }

    async fn reconcile_once_serialized(
        &self,
        module_id: ModuleId,
    ) -> Result<ReconcileOutcome, RegistryError<R::Error>> {
        let desired = self
            .repository
            .read_desired(module_id)
            .await
            .map_err(RegistryError::Repository)?
            .ok_or(RegistryError::MissingDesiredState(module_id))?;
        let enabled = desired
            .mode
            .resolve(self.catalog.inherited_enabled(module_id));
        let current = self
            .repository
            .read_instance(&self.instance_id, module_id)
            .await
            .map_err(RegistryError::Repository)?;
        if enabled {
            if let Some(dependency) = self.first_unavailable_dependency(module_id).await? {
                if self.snapshot().admits(module_id) {
                    self.publish(module_id, false, false)?;
                }
                if let Some(current) = current.as_ref()
                    && current.transition_revision == desired.revision
                {
                    return self.fail_dependency_loss(current, true).await;
                }
                return Err(RegistryError::DependencyUnavailable {
                    module_id,
                    dependency,
                });
            }
        } else if let Some(dependent) = self.first_enabled_dependent(module_id).await? {
            return Err(RegistryError::ActiveDependent {
                module_id,
                dependent,
            });
        }
        if current.as_ref().is_some_and(|instance| {
            instance.applied_revision == Some(desired.revision)
                && ((enabled && instance.state == ModuleState::Enabled)
                    || (!enabled && instance.state == ModuleState::Disabled))
        }) {
            return Ok(ReconcileOutcome::NoChange);
        }

        if enabled {
            self.enable(module_id, desired.revision, current).await
        } else {
            self.disable(module_id, desired.revision, current).await
        }
    }
}
