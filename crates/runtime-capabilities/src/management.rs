use std::{collections::BTreeMap, sync::Arc, time::SystemTime};

use crate::{
    CasOutcome, DesiredMode, DesiredStateRecord, DisablePolicy, InstanceStateRecord, ModuleCatalog,
    ModuleEventPage, ModuleId, ModuleLifecycle, ModuleRevision, ModuleState, ModuleStateRepository,
    RegistryError, RuntimeModuleRegistry,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeModuleView {
    pub module_id: ModuleId,
    pub desired_state: DesiredMode,
    pub resolved_enabled: bool,
    pub actual_state: ModuleState,
    pub revision: Option<ModuleRevision>,
    pub transition_revision: Option<ModuleRevision>,
    pub applied_revision: Option<ModuleRevision>,
    pub dependencies: Vec<ModuleId>,
    pub dependents: Vec<ModuleId>,
    pub allowed_actions: Vec<DesiredMode>,
    pub disable_policy: DisablePolicy,
    pub drain_deadline: Option<SystemTime>,
    pub failure_code: Option<String>,
    pub updated_at: SystemTime,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DesiredStateUpdate {
    pub module_id: ModuleId,
    pub desired_state: DesiredMode,
    pub expected_revision: Option<ModuleRevision>,
    pub actor_id: String,
    pub reason: String,
    pub changed_at: SystemTime,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DesiredStateUpdateOutcome {
    Accepted {
        desired: DesiredStateRecord,
        actual_state: ModuleState,
    },
    Stale {
        current_revision: Option<ModuleRevision>,
    },
}

#[derive(Debug)]
pub enum RuntimeModuleManagementError<E> {
    Repository(E),
    Registry(RegistryError<E>),
    MissingCatalogSpec(ModuleId),
}

pub struct RuntimeModuleManagement<R, L> {
    repository: Arc<R>,
    registry: Arc<RuntimeModuleRegistry<R, L>>,
    catalog: ModuleCatalog,
    instance_id: Box<str>,
}

impl<R, L> RuntimeModuleManagement<R, L>
where
    R: ModuleStateRepository,
    L: ModuleLifecycle,
{
    #[must_use]
    pub fn new(
        repository: Arc<R>,
        registry: Arc<RuntimeModuleRegistry<R, L>>,
        catalog: ModuleCatalog,
        instance_id: impl Into<Box<str>>,
    ) -> Self {
        Self {
            repository,
            registry,
            catalog,
            instance_id: instance_id.into(),
        }
    }

    pub async fn list(
        &self,
    ) -> Result<Vec<RuntimeModuleView>, RuntimeModuleManagementError<R::Error>> {
        let desired = self
            .repository
            .read_all_desired()
            .await
            .map_err(RuntimeModuleManagementError::Repository)?
            .into_iter()
            .map(|record| (record.module_id, record))
            .collect::<BTreeMap<_, _>>();
        let instances = self
            .repository
            .read_all_instances(&self.instance_id)
            .await
            .map_err(RuntimeModuleManagementError::Repository)?
            .into_iter()
            .map(|record| (record.module_id, record))
            .collect::<BTreeMap<_, _>>();
        let snapshot = self.registry.snapshot();
        ModuleId::ALL
            .into_iter()
            .map(|module_id| {
                self.module_view(
                    module_id,
                    desired.get(&module_id),
                    instances.get(&module_id),
                    &snapshot.accepting,
                )
            })
            .collect()
    }

    pub async fn events(
        &self,
        offset: i64,
        limit: i64,
    ) -> Result<ModuleEventPage, RuntimeModuleManagementError<R::Error>> {
        self.repository
            .page_events(offset, limit)
            .await
            .map_err(RuntimeModuleManagementError::Repository)
    }

    pub async fn update_desired(
        &self,
        update: DesiredStateUpdate,
    ) -> Result<DesiredStateUpdateOutcome, RuntimeModuleManagementError<R::Error>> {
        let outcome = self
            .registry
            .set_desired_mode(
                update.module_id,
                update.desired_state,
                update.expected_revision,
                Some(update.actor_id),
                Some(update.reason),
                update.changed_at,
            )
            .await
            .map_err(RuntimeModuleManagementError::Registry)?;
        let desired = match outcome {
            CasOutcome::Applied(desired) => desired,
            CasOutcome::Stale { current } => {
                return Ok(DesiredStateUpdateOutcome::Stale {
                    current_revision: current.map(|record| record.revision),
                });
            }
        };
        let actual_state = self
            .repository
            .read_instance(&self.instance_id, update.module_id)
            .await
            .map_err(RuntimeModuleManagementError::Repository)?
            .map_or(ModuleState::Disabled, |record| record.state);
        Ok(DesiredStateUpdateOutcome::Accepted {
            desired,
            actual_state,
        })
    }

    fn module_view(
        &self,
        module_id: ModuleId,
        desired: Option<&DesiredStateRecord>,
        instance: Option<&InstanceStateRecord>,
        active: &std::collections::BTreeSet<ModuleId>,
    ) -> Result<RuntimeModuleView, RuntimeModuleManagementError<R::Error>> {
        let spec = self
            .catalog
            .spec(module_id)
            .ok_or(RuntimeModuleManagementError::MissingCatalogSpec(module_id))?;
        let desired_state = desired.map_or(DesiredMode::Inherit, |record| record.mode);
        let actual_state = instance.map_or_else(
            || {
                if active.contains(&module_id) {
                    ModuleState::Enabled
                } else {
                    ModuleState::Disabled
                }
            },
            |record| record.state,
        );
        let dependents = self
            .catalog
            .specs()
            .values()
            .filter(|candidate| candidate.dependencies.contains(&module_id))
            .map(|candidate| candidate.id)
            .collect();
        let updated_at = instance
            .map(|record| record.updated_at)
            .or_else(|| desired.map(|record| record.updated_at))
            .unwrap_or(SystemTime::UNIX_EPOCH);
        Ok(RuntimeModuleView {
            module_id,
            desired_state,
            resolved_enabled: desired_state.resolve(self.catalog.inherited_enabled(module_id)),
            actual_state,
            revision: desired.map(|record| record.revision),
            transition_revision: instance.map(|record| record.transition_revision),
            applied_revision: instance.and_then(|record| record.applied_revision),
            dependencies: spec.dependencies.iter().copied().collect(),
            dependents,
            allowed_actions: self.allowed_actions(module_id, desired_state, active),
            disable_policy: self
                .catalog
                .effective_disable_policy(module_id)
                .ok_or(RuntimeModuleManagementError::MissingCatalogSpec(module_id))?,
            drain_deadline: instance.and_then(|record| record.drain_deadline),
            failure_code: instance.and_then(|record| record.error_code.clone()),
            updated_at,
        })
    }

    fn allowed_actions(
        &self,
        module_id: ModuleId,
        mode: DesiredMode,
        active: &std::collections::BTreeSet<ModuleId>,
    ) -> Vec<DesiredMode> {
        let mut actions = Vec::with_capacity(3);
        if mode != DesiredMode::Inherit {
            actions.push(DesiredMode::Inherit);
        }
        if mode != DesiredMode::Enabled
            && self.catalog.spec(module_id).is_some_and(|spec| {
                spec.dependencies
                    .iter()
                    .all(|dependency| active.contains(dependency))
            })
        {
            actions.push(DesiredMode::Enabled);
        }
        if mode != DesiredMode::Disabled
            && !matches!(
                self.catalog.effective_disable_policy(module_id),
                Some(DisablePolicy::NotRuntimeDisableable) | None
            )
            && self.catalog.active_dependents(module_id, active).is_empty()
        {
            actions.push(DesiredMode::Disabled);
        }
        actions
    }
}

#[cfg(test)]
#[path = "../tests/unit/management.rs"]
mod tests;
