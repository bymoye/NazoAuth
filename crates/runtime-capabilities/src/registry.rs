use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use uuid::Uuid;

use crate::{
    ActiveModuleSnapshot, CasOutcome, DesiredMode, DesiredRevisionGuard, DesiredStateChange,
    DesiredStateRecord, DisablePolicy, InstanceStateChange, InstanceStateMutation,
    InstanceStateRecord, LifecycleFailure, ModuleCatalog, ModuleEventRecord, ModuleEventState,
    ModuleEventType, ModuleId, ModuleLifecycle, ModuleRevision, ModuleState, ModuleStateRepository,
    ReconcileOutcome, RegistryError, RequestLease, RequestLeaseTracker, SnapshotStore,
};

pub struct RuntimeModuleRegistry<R, L> {
    repository: Arc<R>,
    lifecycle: Arc<L>,
    catalog: ModuleCatalog,
    instance_id: String,
    snapshots: Arc<SnapshotStore>,
    leases: RequestLeaseTracker,
    desired_policy_lock: futures_util::lock::Mutex<()>,
    transition_locks: BTreeMap<ModuleId, Arc<futures_util::lock::Mutex<()>>>,
}

impl<R, L> RuntimeModuleRegistry<R, L>
where
    R: ModuleStateRepository,
    L: ModuleLifecycle,
{
    #[must_use]
    pub fn new(
        repository: Arc<R>,
        lifecycle: Arc<L>,
        catalog: ModuleCatalog,
        instance_id: String,
        initial_snapshot: ActiveModuleSnapshot,
    ) -> Self {
        Self {
            repository,
            lifecycle,
            catalog,
            instance_id,
            snapshots: Arc::new(SnapshotStore::new(initial_snapshot)),
            leases: RequestLeaseTracker::default(),
            desired_policy_lock: futures_util::lock::Mutex::new(()),
            transition_locks: ModuleId::ALL
                .into_iter()
                .map(|module_id| (module_id, Arc::new(futures_util::lock::Mutex::new(()))))
                .collect(),
        }
    }

    #[must_use]
    pub fn snapshot(&self) -> Arc<ActiveModuleSnapshot> {
        self.snapshots.load_full()
    }

    #[must_use]
    pub fn lease(&self, module_id: ModuleId) -> Option<RequestLease> {
        self.leases.acquire(self.snapshot(), module_id)
    }

    pub async fn set_desired_mode(
        &self,
        module_id: ModuleId,
        mode: DesiredMode,
        expected_revision: Option<ModuleRevision>,
        actor_id: Option<String>,
        reason: Option<String>,
        changed_at: SystemTime,
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

    async fn enable(
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

    async fn disable(
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
    async fn restore_admission_after_stale_disable(
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

    async fn first_unavailable_dependency(
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

    async fn first_enabled_dependent(
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

    async fn fail_dependency_loss(
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

    async fn revision_is_current(
        &self,
        module_id: ModuleId,
        revision: ModuleRevision,
    ) -> Result<bool, RegistryError<R::Error>> {
        self.repository
            .validate_revision(module_id, revision)
            .await
            .map_err(RegistryError::Repository)
    }

    fn publish(
        &self,
        module_id: ModuleId,
        accepting: bool,
        draining: bool,
    ) -> Result<(), RegistryError<R::Error>> {
        loop {
            let current = self.snapshots.load_full();
            let mut accepting_set = current.accepting.clone();
            let mut draining_set = current.draining.clone();
            set_membership(&mut accepting_set, module_id, accepting);
            set_membership(&mut draining_set, module_id, draining);
            let next_revision = current
                .revision
                .get()
                .checked_add(1)
                .ok_or(RegistryError::SnapshotRevisionExhausted)?;
            let next = ActiveModuleSnapshot {
                revision: ModuleRevision::new(next_revision),
                accepting: accepting_set,
                draining: draining_set,
            };
            if self
                .snapshots
                .compare_and_publish(current.revision, next)
                .is_ok()
            {
                return Ok(());
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn persist_state(
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

    async fn discard_stale(
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

    async fn persist_failure(
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

fn set_membership(set: &mut BTreeSet<ModuleId>, module_id: ModuleId, present: bool) {
    if present {
        set.insert(module_id);
    } else {
        set.remove(&module_id);
    }
}
