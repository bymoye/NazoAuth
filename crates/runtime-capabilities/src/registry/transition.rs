use std::time::{Duration, SystemTime};

use crate::{
    CasOutcome, DisablePolicy, InstanceStateRecord, LifecycleFailure, ModuleEventType, ModuleId,
    ModuleLifecycle, ModuleRevision, ModuleState, ModuleStateRepository, ReconcileOutcome,
    RegistryError,
};

use super::RuntimeModuleRegistry;

impl<R, L> RuntimeModuleRegistry<R, L>
where
    R: ModuleStateRepository,
    L: ModuleLifecycle,
{
    pub(super) async fn enable(
        &self,
        module_id: ModuleId,
        revision: ModuleRevision,
        current: Option<InstanceStateRecord>,
    ) -> Result<ReconcileOutcome, RegistryError<R::Error>> {
        let starting = self
            .persist_state(
                module_id,
                revision,
                current.as_ref().map(|state| state.transition_revision),
                ModuleState::Starting,
                None,
                ModuleEventType::TransitionStarted,
                current.as_ref().map(|state| state.state),
                None,
                None,
            )
            .await?;
        let CasOutcome::Applied(starting) = starting else {
            return Ok(ReconcileOutcome::StaleDiscarded);
        };
        if self
            .first_unavailable_dependency(module_id)
            .await?
            .is_some()
        {
            return self.fail_dependency_loss(&starting, false).await;
        }
        if let Err(failure) = self.lifecycle.initialize(module_id).await {
            return Ok(if self.persist_failure(&starting, failure).await? {
                ReconcileOutcome::Failed
            } else {
                ReconcileOutcome::StaleDiscarded
            });
        }
        if self
            .first_unavailable_dependency(module_id)
            .await?
            .is_some()
        {
            return self.fail_dependency_loss(&starting, true).await;
        }
        if !self.revision_is_current(module_id, revision).await? {
            self.discard_stale(starting).await?;
            return Ok(ReconcileOutcome::StaleDiscarded);
        }
        self.publish(module_id, true, false)?;
        if self
            .first_unavailable_dependency(module_id)
            .await?
            .is_some()
        {
            self.publish(module_id, false, false)?;
            return self.fail_dependency_loss(&starting, true).await;
        }
        if !self.revision_is_current(module_id, revision).await? {
            self.publish(module_id, false, false)?;
            self.discard_stale(starting).await?;
            return Ok(ReconcileOutcome::StaleDiscarded);
        }
        let completed = self
            .persist_state(
                module_id,
                revision,
                Some(revision),
                ModuleState::Enabled,
                Some(revision),
                ModuleEventType::TransitionCompleted,
                Some(ModuleState::Starting),
                None,
                None,
            )
            .await?;
        Ok(match completed {
            CasOutcome::Applied(_) => ReconcileOutcome::Enabled,
            CasOutcome::Stale { .. } => {
                // A desired-state revision can change after the last explicit
                // check but before the repository CAS. The per-module guard
                // ensures this rollback cannot erase a newer reconciler's
                // publication.
                self.publish(module_id, false, false)?;
                ReconcileOutcome::StaleDiscarded
            }
        })
    }

    pub(super) async fn disable(
        &self,
        module_id: ModuleId,
        revision: ModuleRevision,
        current: Option<InstanceStateRecord>,
    ) -> Result<ReconcileOutcome, RegistryError<R::Error>> {
        let disable_policy = self
            .catalog
            .effective_disable_policy(module_id)
            .ok_or(RegistryError::MissingCatalogSpec(module_id))?;
        if current
            .as_ref()
            .is_none_or(|instance| instance.state == ModuleState::Disabled)
        {
            if !self.revision_is_current(module_id, revision).await? {
                return Ok(ReconcileOutcome::StaleDiscarded);
            }
            let completed = self
                .persist_state(
                    module_id,
                    revision,
                    current.as_ref().map(|state| state.transition_revision),
                    ModuleState::Disabled,
                    Some(revision),
                    ModuleEventType::TransitionCompleted,
                    current.as_ref().map(|state| state.state),
                    None,
                    None,
                )
                .await?;
            return match completed {
                CasOutcome::Applied(_) => {
                    if !self.revision_is_current(module_id, revision).await? {
                        Ok(ReconcileOutcome::StaleDiscarded)
                    } else {
                        self.publish(module_id, false, false)?;
                        Ok(ReconcileOutcome::Disabled)
                    }
                }
                CasOutcome::Stale { .. } => Ok(ReconcileOutcome::StaleDiscarded),
            };
        }
        let prior_generation = self.snapshot().revision;
        let drain_deadline = match disable_policy {
            DisablePolicy::DrainStoredTransactions { max_duration } => current
                .as_ref()
                .filter(|instance| {
                    instance.state == ModuleState::Draining
                        && instance.transition_revision == revision
                })
                .and_then(|instance| instance.drain_deadline)
                .or_else(|| SystemTime::now().checked_add(max_duration)),
            _ => None,
        };
        let draining = self
            .persist_state(
                module_id,
                revision,
                current.as_ref().map(|state| state.transition_revision),
                ModuleState::Draining,
                None,
                ModuleEventType::TransitionStarted,
                current.as_ref().map(|state| state.state),
                drain_deadline,
                None,
            )
            .await?;
        let CasOutcome::Applied(draining) = draining else {
            return Ok(ReconcileOutcome::StaleDiscarded);
        };
        if self.first_enabled_dependent(module_id).await?.is_some() {
            let failed = self
                .persist_failure(
                    &draining,
                    LifecycleFailure {
                        code: "active_dependent",
                    },
                )
                .await?;
            return Ok(if failed {
                ReconcileOutcome::Failed
            } else {
                ReconcileOutcome::StaleDiscarded
            });
        }
        if !self.revision_is_current(module_id, revision).await? {
            self.discard_stale(draining).await?;
            return Ok(ReconcileOutcome::StaleDiscarded);
        }
        self.publish(module_id, false, true)?;
        if !self.revision_is_current(module_id, revision).await? {
            self.discard_stale(draining).await?;
            self.restore_admission_after_stale_disable(module_id)
                .await?;
            return Ok(ReconcileOutcome::StaleDiscarded);
        }
        if !matches!(disable_policy, DisablePolicy::Immediate) {
            if !matches!(
                self.persist_state(
                    module_id,
                    revision,
                    Some(revision),
                    ModuleState::Draining,
                    None,
                    ModuleEventType::DrainStarted,
                    Some(ModuleState::Draining),
                    drain_deadline,
                    None,
                )
                .await?,
                CasOutcome::Applied(_)
            ) {
                self.restore_admission_after_stale_disable(module_id)
                    .await?;
                return Ok(ReconcileOutcome::StaleDiscarded);
            }
            self.leases
                .wait_until_zero(module_id, prior_generation)
                .await;
            if matches!(
                disable_policy,
                DisablePolicy::DrainStoredTransactions { .. }
            ) {
                let remaining_duration = drain_deadline
                    .and_then(|deadline| deadline.duration_since(SystemTime::now()).ok())
                    .unwrap_or(Duration::ZERO);
                match self
                    .lifecycle
                    .drain_stored_transactions(module_id, revision, remaining_duration)
                    .await
                {
                    Ok(true) => {}
                    Ok(false) => {
                        let failed = self
                            .persist_failure(
                                &draining,
                                LifecycleFailure {
                                    code: "drain_deadline_elapsed",
                                },
                            )
                            .await?;
                        if !failed {
                            self.restore_admission_after_stale_disable(module_id)
                                .await?;
                        }
                        return Ok(if failed {
                            ReconcileOutcome::Failed
                        } else {
                            ReconcileOutcome::StaleDiscarded
                        });
                    }
                    Err(failure) => {
                        let failed = self.persist_failure(&draining, failure).await?;
                        if !failed {
                            self.restore_admission_after_stale_disable(module_id)
                                .await?;
                        }
                        return Ok(if failed {
                            ReconcileOutcome::Failed
                        } else {
                            ReconcileOutcome::StaleDiscarded
                        });
                    }
                }
            }
            if !self.revision_is_current(module_id, revision).await? {
                self.discard_stale(draining).await?;
                self.restore_admission_after_stale_disable(module_id)
                    .await?;
                return Ok(ReconcileOutcome::StaleDiscarded);
            }
            if !matches!(
                self.persist_state(
                    module_id,
                    revision,
                    Some(revision),
                    ModuleState::Draining,
                    None,
                    ModuleEventType::DrainCompleted,
                    Some(ModuleState::Draining),
                    drain_deadline,
                    None,
                )
                .await?,
                CasOutcome::Applied(_)
            ) {
                self.restore_admission_after_stale_disable(module_id)
                    .await?;
                return Ok(ReconcileOutcome::StaleDiscarded);
            }
            if !self.revision_is_current(module_id, revision).await? {
                self.discard_stale(draining).await?;
                self.restore_admission_after_stale_disable(module_id)
                    .await?;
                return Ok(ReconcileOutcome::StaleDiscarded);
            }
        }
        if let Err(failure) = self.lifecycle.stop(module_id).await {
            let failed = self.persist_failure(&draining, failure).await?;
            if !failed {
                self.restore_admission_after_stale_disable(module_id)
                    .await?;
            }
            return Ok(if failed {
                ReconcileOutcome::Failed
            } else {
                ReconcileOutcome::StaleDiscarded
            });
        }
        if !self.revision_is_current(module_id, revision).await? {
            self.discard_stale(draining).await?;
            // `stop` already ran, so admission cannot be restored safely.
            // Remove the obsolete draining marker; the newer revision will
            // initialize and republish the module if it resolves to enabled.
            self.publish(module_id, false, false)?;
            return Ok(ReconcileOutcome::StaleDiscarded);
        }
        let completed = self
            .persist_state(
                module_id,
                revision,
                Some(revision),
                ModuleState::Disabled,
                Some(revision),
                ModuleEventType::TransitionCompleted,
                Some(ModuleState::Draining),
                None,
                None,
            )
            .await?;
        match completed {
            CasOutcome::Applied(_) => {
                if !self.revision_is_current(module_id, revision).await? {
                    self.publish(module_id, false, false)?;
                    return Ok(ReconcileOutcome::StaleDiscarded);
                }
                self.publish(module_id, false, false)?;
                Ok(ReconcileOutcome::Disabled)
            }
            CasOutcome::Stale { .. } => {
                self.publish(module_id, false, false)?;
                Ok(ReconcileOutcome::StaleDiscarded)
            }
        }
    }

    /// A superseded disable has not stopped the module yet, so align request
    /// admission with the latest durable intent instead of leaving the stale
    /// draining publication in force. Revalidation after each publication
    /// closes the read/publish race with a concurrent administrator update.
    pub(super) async fn restore_admission_after_stale_disable(
        &self,
        module_id: ModuleId,
    ) -> Result<(), RegistryError<R::Error>> {
        loop {
            let desired = self
                .repository
                .read_desired(module_id)
                .await
                .map_err(RegistryError::Repository)?
                .ok_or(RegistryError::MissingDesiredState(module_id))?;
            let accepting = desired
                .mode
                .resolve(self.catalog.inherited_enabled(module_id));
            self.publish(module_id, accepting, !accepting)?;
            if self
                .revision_is_current(module_id, desired.revision)
                .await?
            {
                return Ok(());
            }
        }
    }
}
