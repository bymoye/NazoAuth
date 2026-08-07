use crate::{
    CasOutcome, DesiredMode, DesiredRevisionGuard, DesiredStateChange, DesiredStateRecord,
    DisablePolicy, ModuleId, ModuleLifecycle, ModuleRevision, ModuleStateRepository, RegistryError,
};

use super::RuntimeModuleRegistry;

impl<R, L> RuntimeModuleRegistry<R, L>
where
    R: ModuleStateRepository,
    L: ModuleLifecycle,
{
    /// Applies a desired-state change only after validating the dependency
    /// policy against one coherent admission snapshot.
    pub async fn set_desired_mode(
        &self,
        module_id: ModuleId,
        mode: DesiredMode,
        expected_revision: Option<ModuleRevision>,
        actor_id: Option<String>,
        reason: Option<String>,
        changed_at: std::time::SystemTime,
    ) -> Result<CasOutcome<DesiredStateRecord>, RegistryError<R::Error>> {
        let _policy_guard = self.desired_policy_lock.lock().await;
        let spec = self
            .catalog
            .spec(module_id)
            .ok_or(RegistryError::MissingCatalogSpec(module_id))?;
        let disable_policy = self
            .catalog
            .effective_disable_policy(module_id)
            .ok_or(RegistryError::MissingCatalogSpec(module_id))?;
        let enabling = mode.resolve(self.catalog.inherited_enabled(module_id));
        let snapshot = self.snapshot();
        let mut required_revisions = Vec::new();
        if enabling {
            for dependency in &spec.dependencies {
                let dependency_desired = self
                    .repository
                    .read_desired(*dependency)
                    .await
                    .map_err(RegistryError::Repository)?
                    .ok_or(RegistryError::MissingDesiredState(*dependency))?;
                if !dependency_desired
                    .mode
                    .resolve(self.catalog.inherited_enabled(*dependency))
                    || !snapshot.admits(*dependency)
                {
                    return Err(RegistryError::DependencyUnavailable {
                        module_id,
                        dependency: *dependency,
                    });
                }
                required_revisions.push(DesiredRevisionGuard {
                    module_id: *dependency,
                    expected_revision: Some(dependency_desired.revision),
                });
            }
        } else {
            if matches!(disable_policy, DisablePolicy::NotRuntimeDisableable) {
                return Err(RegistryError::RuntimeDisableBlocked(module_id));
            }
            for dependent in self
                .catalog
                .specs()
                .values()
                .filter(|candidate| candidate.dependencies.contains(&module_id))
            {
                let dependent_desired = self
                    .repository
                    .read_desired(dependent.id)
                    .await
                    .map_err(RegistryError::Repository)?
                    .ok_or(RegistryError::MissingDesiredState(dependent.id))?;
                if dependent_desired
                    .mode
                    .resolve(self.catalog.inherited_enabled(dependent.id))
                    || snapshot.admits(dependent.id)
                {
                    return Err(RegistryError::ActiveDependent {
                        module_id,
                        dependent: dependent.id,
                    });
                }
                required_revisions.push(DesiredRevisionGuard {
                    module_id: dependent.id,
                    expected_revision: Some(dependent_desired.revision),
                });
            }
        }
        let current = self
            .repository
            .read_desired(module_id)
            .await
            .map_err(RegistryError::Repository)?;
        if current.as_ref().map(|record| record.revision) != expected_revision {
            return Ok(CasOutcome::Stale { current });
        }
        let next_revision = ModuleRevision::new(match expected_revision {
            None => 1,
            Some(revision) => revision
                .get()
                .checked_add(1)
                .ok_or(RegistryError::RevisionExhausted(module_id))?,
        });
        self.repository
            .compare_and_set_desired_guarded(
                DesiredStateChange {
                    expected_revision,
                    next: DesiredStateRecord {
                        module_id,
                        mode,
                        revision: next_revision,
                        actor_id,
                        reason,
                        updated_at: changed_at,
                    },
                },
                required_revisions,
            )
            .await
            .map_err(RegistryError::Repository)
    }
}
