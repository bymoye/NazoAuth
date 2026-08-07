use std::time::SystemTime;
use uuid::Uuid;

use crate::{
    CasOutcome, InstanceStateChange, InstanceStateMutation, InstanceStateRecord, LifecycleFailure,
    ModuleEventRecord, ModuleEventState, ModuleEventType, ModuleId, ModuleLifecycle,
    ModuleRevision, ModuleState, ModuleStateRepository, RegistryError,
};

use super::RuntimeModuleRegistry;

impl<R, L> RuntimeModuleRegistry<R, L>
where
    R: ModuleStateRepository,
    L: ModuleLifecycle,
{
    pub(super) async fn revision_is_current(
        &self,
        module_id: ModuleId,
        revision: ModuleRevision,
    ) -> Result<bool, RegistryError<R::Error>> {
        self.repository
            .validate_revision(module_id, revision)
            .await
            .map_err(RegistryError::Repository)
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) async fn persist_state(
        &self,
        module_id: ModuleId,
        revision: ModuleRevision,
        expected_revision: Option<ModuleRevision>,
        state: ModuleState,
        applied_revision: Option<ModuleRevision>,
        event_type: ModuleEventType,
        before: Option<ModuleState>,
        drain_deadline: Option<SystemTime>,
        outcome_code: Option<&'static str>,
    ) -> Result<CasOutcome<InstanceStateRecord>, RegistryError<R::Error>> {
        let now = SystemTime::now();
        let next = InstanceStateRecord {
            instance_id: self.instance_id.clone(),
            module_id,
            state,
            transition_revision: revision,
            applied_revision,
            drain_deadline,
            error_code: outcome_code.map(str::to_owned),
            updated_at: now,
        };
        let event = self.event(&next, event_type, before, outcome_code);
        self.repository
            .compare_and_set_instance(
                revision,
                InstanceStateMutation {
                    change: InstanceStateChange {
                        expected_revision,
                        next,
                    },
                    applied_event: event.clone(),
                    stale_event: self.event_from(event, ModuleEventType::StaleTransitionDiscarded),
                },
            )
            .await
            .map_err(RegistryError::Repository)
    }

    pub(super) async fn discard_stale(
        &self,
        current: InstanceStateRecord,
    ) -> Result<(), RegistryError<R::Error>> {
        let event = self.event(
            &current,
            ModuleEventType::StaleTransitionDiscarded,
            Some(current.state),
            Some("revision_changed"),
        );
        self.repository
            .compare_and_set_instance(
                current.transition_revision,
                InstanceStateMutation {
                    change: InstanceStateChange {
                        expected_revision: Some(current.transition_revision),
                        next: current,
                    },
                    applied_event: event.clone(),
                    stale_event: event,
                },
            )
            .await
            .map_err(RegistryError::Repository)?;
        Ok(())
    }

    pub(super) async fn persist_failure(
        &self,
        current: &InstanceStateRecord,
        failure: LifecycleFailure,
    ) -> Result<bool, RegistryError<R::Error>> {
        let outcome = self
            .persist_state(
                current.module_id,
                current.transition_revision,
                Some(current.transition_revision),
                ModuleState::Failed,
                None,
                ModuleEventType::TransitionFailed,
                Some(current.state),
                current.drain_deadline,
                Some(failure.code),
            )
            .await?;
        Ok(matches!(outcome, CasOutcome::Applied(_)))
    }

    fn event(
        &self,
        state: &InstanceStateRecord,
        event_type: ModuleEventType,
        before: Option<ModuleState>,
        outcome_code: Option<&'static str>,
    ) -> ModuleEventRecord {
        ModuleEventRecord {
            event_id: Uuid::now_v7().to_string(),
            module_id: state.module_id,
            event_type,
            revision: state.transition_revision,
            instance_id: Some(self.instance_id.clone()),
            actor_id: None,
            reason: None,
            before: before.map(ModuleEventState::Actual),
            after: Some(ModuleEventState::Actual(state.state)),
            outcome_code: outcome_code.map(str::to_owned),
            occurred_at: state.updated_at,
        }
    }

    fn event_from(
        &self,
        mut event: ModuleEventRecord,
        event_type: ModuleEventType,
    ) -> ModuleEventRecord {
        event.event_id = Uuid::now_v7().to_string();
        event.event_type = event_type;
        event
    }
}
