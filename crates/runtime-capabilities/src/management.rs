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
mod tests {
    use std::{
        collections::BTreeSet,
        future::Future,
        sync::{
            Arc, Mutex,
            atomic::{AtomicBool, AtomicUsize, Ordering},
            mpsc,
        },
        task::{Context, Poll, Waker},
        time::Duration,
    };

    use crate::{
        ActiveModuleSnapshot, CasOutcome, CatalogDurations, DesiredRevisionGuard,
        DesiredStateChange, InstanceStateChange, InstanceStateMutation, LifecycleFailure,
        LifecycleFuture, ModuleEventRecord, NoopModuleLifecycle, ReconcileOutcome,
    };

    use super::*;

    fn block_on<F: Future>(future: F) -> F::Output {
        let waker = Waker::noop();
        let mut context = Context::from_waker(waker);
        let mut future = std::pin::pin!(future);
        loop {
            match future.as_mut().poll(&mut context) {
                Poll::Ready(output) => return output,
                Poll::Pending => std::thread::yield_now(),
            }
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum TestError {
        Unavailable,
    }

    #[derive(Default)]
    struct RepositoryState {
        desired: Vec<DesiredStateRecord>,
        instances: Vec<InstanceStateRecord>,
        events: Vec<ModuleEventRecord>,
    }

    struct CasPause {
        module_id: ModuleId,
        entered: mpsc::SyncSender<()>,
        release: mpsc::Receiver<()>,
    }

    struct ReadPause {
        module_id: ModuleId,
        entered: mpsc::SyncSender<()>,
        release: mpsc::Receiver<()>,
    }

    struct InitializePause {
        entered: mpsc::SyncSender<()>,
        release: Mutex<mpsc::Receiver<()>>,
        stopped: AtomicBool,
    }

    impl ModuleLifecycle for InitializePause {
        fn initialize(
            &self,
            _module_id: ModuleId,
        ) -> LifecycleFuture<'_, Result<(), LifecycleFailure>> {
            Box::pin(async move {
                self.entered.send(()).unwrap();
                self.release.lock().unwrap().recv().unwrap();
                Ok(())
            })
        }

        fn stop(&self, _module_id: ModuleId) -> LifecycleFuture<'_, Result<(), LifecycleFailure>> {
            self.stopped.store(true, Ordering::Release);
            Box::pin(async { Ok(()) })
        }

        fn drain_stored_transactions(
            &self,
            _module_id: ModuleId,
            _revision: ModuleRevision,
            _remaining_duration: Duration,
        ) -> LifecycleFuture<'_, Result<bool, LifecycleFailure>> {
            Box::pin(async { Ok(true) })
        }
    }

    #[derive(Default)]
    struct TestRepository {
        state: Mutex<RepositoryState>,
        fail_bulk_desired: AtomicBool,
        single_desired_reads: AtomicUsize,
        single_instance_reads: AtomicUsize,
        bulk_desired_reads: AtomicUsize,
        bulk_instance_reads: AtomicUsize,
        cas_pause: Mutex<Option<CasPause>>,
        read_pauses: Mutex<Vec<ReadPause>>,
        desired_transaction: Mutex<()>,
    }

    impl ModuleStateRepository for TestRepository {
        type Error = TestError;

        async fn read_desired(
            &self,
            module_id: ModuleId,
        ) -> Result<Option<DesiredStateRecord>, Self::Error> {
            self.single_desired_reads.fetch_add(1, Ordering::Relaxed);
            let current = self
                .state
                .lock()
                .unwrap()
                .desired
                .iter()
                .find(|record| record.module_id == module_id)
                .cloned();
            let pause = {
                let mut configured = self.read_pauses.lock().unwrap();
                configured
                    .iter()
                    .position(|pause| pause.module_id == module_id)
                    .map(|position| configured.remove(position))
            };
            if let Some(pause) = pause {
                pause.entered.send(()).unwrap();
                pause.release.recv().unwrap();
            }
            Ok(current)
        }

        async fn read_all_desired(&self) -> Result<Vec<DesiredStateRecord>, Self::Error> {
            self.bulk_desired_reads.fetch_add(1, Ordering::Relaxed);
            if self.fail_bulk_desired.load(Ordering::Relaxed) {
                return Err(TestError::Unavailable);
            }
            Ok(self.state.lock().unwrap().desired.clone())
        }

        async fn compare_and_set_desired(
            &self,
            change: DesiredStateChange,
        ) -> Result<CasOutcome<DesiredStateRecord>, Self::Error> {
            self.compare_and_set_desired_guarded(change, Vec::new())
                .await
        }

        async fn compare_and_set_desired_guarded(
            &self,
            change: DesiredStateChange,
            required_revisions: Vec<DesiredRevisionGuard>,
        ) -> Result<CasOutcome<DesiredStateRecord>, Self::Error> {
            let _transaction = self.desired_transaction.lock().unwrap();
            let pause = {
                let mut configured = self.cas_pause.lock().unwrap();
                if configured
                    .as_ref()
                    .is_some_and(|pause| pause.module_id == change.next.module_id)
                {
                    configured.take()
                } else {
                    None
                }
            };
            if let Some(pause) = pause {
                pause.entered.send(()).unwrap();
                pause.release.recv().unwrap();
            }
            let mut state = self.state.lock().unwrap();
            let current = state
                .desired
                .iter()
                .position(|record| record.module_id == change.next.module_id)
                .map(|position| (position, state.desired[position].clone()));
            if current.as_ref().map(|(_, record)| record.revision) != change.expected_revision {
                return Ok(CasOutcome::Stale {
                    current: current.map(|(_, record)| record),
                });
            }
            let guards_match = required_revisions.iter().all(|guard| {
                state
                    .desired
                    .iter()
                    .find(|record| record.module_id == guard.module_id)
                    .map(|record| record.revision)
                    == guard.expected_revision
            });
            if !guards_match {
                return Ok(CasOutcome::Stale {
                    current: current.map(|(_, record)| record),
                });
            }
            if let Some((position, _)) = current {
                state.desired[position] = change.next.clone();
            } else {
                state.desired.push(change.next.clone());
            }
            Ok(CasOutcome::Applied(change.next))
        }

        async fn read_instance(
            &self,
            instance_id: &str,
            module_id: ModuleId,
        ) -> Result<Option<InstanceStateRecord>, Self::Error> {
            self.single_instance_reads.fetch_add(1, Ordering::Relaxed);
            Ok(self
                .state
                .lock()
                .unwrap()
                .instances
                .iter()
                .find(|record| record.instance_id == instance_id && record.module_id == module_id)
                .cloned())
        }

        async fn read_all_instances(
            &self,
            instance_id: &str,
        ) -> Result<Vec<InstanceStateRecord>, Self::Error> {
            self.bulk_instance_reads.fetch_add(1, Ordering::Relaxed);
            Ok(self
                .state
                .lock()
                .unwrap()
                .instances
                .iter()
                .filter(|record| record.instance_id == instance_id)
                .cloned()
                .collect())
        }

        async fn page_events(
            &self,
            offset: i64,
            limit: i64,
        ) -> Result<ModuleEventPage, Self::Error> {
            let state = self.state.lock().unwrap();
            let events = state
                .events
                .iter()
                .skip(usize::try_from(offset).unwrap())
                .take(usize::try_from(limit).unwrap())
                .cloned()
                .collect();
            Ok(ModuleEventPage {
                total: i64::try_from(state.events.len()).unwrap(),
                events,
            })
        }

        async fn compare_and_set_instance(
            &self,
            _required_desired_revision: ModuleRevision,
            mutation: InstanceStateMutation,
        ) -> Result<CasOutcome<InstanceStateRecord>, Self::Error> {
            let InstanceStateChange { next, .. } = mutation.change;
            Ok(CasOutcome::Applied(next))
        }

        async fn validate_revision(
            &self,
            module_id: ModuleId,
            expected: ModuleRevision,
        ) -> Result<bool, Self::Error> {
            Ok(self
                .state
                .lock()
                .unwrap()
                .desired
                .iter()
                .find(|record| record.module_id == module_id)
                .is_some_and(|record| record.revision == expected))
        }
    }

    fn management(
        repository: Arc<TestRepository>,
    ) -> RuntimeModuleManagement<TestRepository, NoopModuleLifecycle> {
        let inherited = BTreeSet::from([ModuleId::Ciba]);
        let catalog = ModuleCatalog::fixed(
            CatalogDurations {
                device_authorization: Duration::from_secs(60),
                ciba: Duration::from_secs(120),
                authorization_code: Duration::from_secs(30),
                refresh_token: Duration::from_secs(300),
                session: Duration::from_secs(600),
            },
            inherited.clone(),
        )
        .unwrap();
        let registry = Arc::new(RuntimeModuleRegistry::new(
            repository.clone(),
            Arc::new(NoopModuleLifecycle),
            catalog.clone(),
            "instance-a".to_owned(),
            ActiveModuleSnapshot {
                revision: ModuleRevision::new(3),
                accepting: inherited,
                draining: BTreeSet::new(),
            },
        ));
        RuntimeModuleManagement::new(repository, registry, catalog, "instance-a")
    }

    fn desired(revision: u64, mode: DesiredMode) -> DesiredStateRecord {
        DesiredStateRecord {
            module_id: ModuleId::Ciba,
            mode,
            revision: ModuleRevision::new(revision),
            actor_id: Some("admin-a".to_owned()),
            reason: Some("initial".to_owned()),
            updated_at: SystemTime::UNIX_EPOCH,
        }
    }

    fn instance() -> InstanceStateRecord {
        InstanceStateRecord {
            instance_id: "instance-a".to_owned(),
            module_id: ModuleId::Ciba,
            state: ModuleState::Draining,
            transition_revision: ModuleRevision::new(3),
            applied_revision: Some(ModuleRevision::new(2)),
            drain_deadline: Some(SystemTime::UNIX_EPOCH + Duration::from_secs(120)),
            error_code: None,
            updated_at: SystemTime::UNIX_EPOCH + Duration::from_secs(10),
        }
    }

    #[test]
    fn list_uses_two_bulk_reads_and_preserves_typed_state() {
        let repository = Arc::new(TestRepository::default());
        {
            let mut state = repository.state.lock().unwrap();
            state.desired.push(desired(3, DesiredMode::Disabled));
            state.instances.push(instance());
        }
        let views = block_on(management(repository.clone()).list()).unwrap();
        let ciba = views
            .iter()
            .find(|view| view.module_id == ModuleId::Ciba)
            .unwrap();

        assert_eq!(views.len(), ModuleId::ALL.len());
        assert_eq!(ciba.desired_state, DesiredMode::Disabled);
        assert_eq!(ciba.actual_state, ModuleState::Draining);
        assert_eq!(ciba.revision, Some(ModuleRevision::new(3)));
        assert_eq!(ciba.applied_revision, Some(ModuleRevision::new(2)));
        assert_eq!(repository.bulk_desired_reads.load(Ordering::Relaxed), 1);
        assert_eq!(repository.bulk_instance_reads.load(Ordering::Relaxed), 1);
        assert_eq!(repository.single_desired_reads.load(Ordering::Relaxed), 0);
        assert_eq!(repository.single_instance_reads.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn stale_update_reports_the_revision_that_won_without_mutation() {
        let repository = Arc::new(TestRepository::default());
        repository
            .state
            .lock()
            .unwrap()
            .desired
            .push(desired(3, DesiredMode::Enabled));
        let outcome = block_on(
            management(repository.clone()).update_desired(DesiredStateUpdate {
                module_id: ModuleId::Ciba,
                desired_state: DesiredMode::Disabled,
                expected_revision: Some(ModuleRevision::new(2)),
                actor_id: "admin-b".to_owned(),
                reason: "maintenance".to_owned(),
                changed_at: SystemTime::UNIX_EPOCH + Duration::from_secs(20),
            }),
        )
        .unwrap();

        assert_eq!(
            outcome,
            DesiredStateUpdateOutcome::Stale {
                current_revision: Some(ModuleRevision::new(3))
            }
        );
        assert_eq!(
            repository.state.lock().unwrap().desired[0].mode,
            DesiredMode::Enabled
        );
    }

    #[test]
    fn repository_failure_remains_distinct_from_policy_and_catalog_errors() {
        let repository = Arc::new(TestRepository::default());
        repository.fail_bulk_desired.store(true, Ordering::Relaxed);

        assert!(matches!(
            block_on(management(repository).list()),
            Err(RuntimeModuleManagementError::Repository(
                TestError::Unavailable
            ))
        ));
    }

    #[test]
    fn management_view_reports_the_security_profiles_effective_disable_policy() {
        let repository = Arc::new(TestRepository::default());
        repository
            .state
            .lock()
            .unwrap()
            .desired
            .push(desired(1, DesiredMode::Enabled));
        let inherited = BTreeSet::from([ModuleId::Ciba]);
        let catalog = ModuleCatalog::fixed(
            CatalogDurations {
                device_authorization: Duration::from_secs(60),
                ciba: Duration::from_secs(120),
                authorization_code: Duration::from_secs(30),
                refresh_token: Duration::from_secs(300),
                session: Duration::from_secs(600),
            },
            inherited.clone(),
        )
        .unwrap()
        .with_runtime_disable_blocked([ModuleId::Ciba]);
        let registry = Arc::new(RuntimeModuleRegistry::new(
            repository.clone(),
            Arc::new(NoopModuleLifecycle),
            catalog.clone(),
            "instance-a".to_owned(),
            ActiveModuleSnapshot {
                revision: ModuleRevision::new(1),
                accepting: inherited,
                draining: BTreeSet::new(),
            },
        ));
        let views = block_on(
            RuntimeModuleManagement::new(repository, registry, catalog, "instance-a").list(),
        )
        .unwrap();
        let ciba = views
            .iter()
            .find(|view| view.module_id == ModuleId::Ciba)
            .unwrap();

        assert_eq!(ciba.disable_policy, DisablePolicy::NotRuntimeDisableable);
        assert!(!ciba.allowed_actions.contains(&DesiredMode::Disabled));
    }

    #[test]
    fn desired_revision_exhaustion_fails_without_wrapping_or_mutating() {
        let repository = Arc::new(TestRepository::default());
        repository
            .state
            .lock()
            .unwrap()
            .desired
            .push(desired(u64::MAX, DesiredMode::Enabled));
        let result = block_on(
            management(repository.clone()).update_desired(DesiredStateUpdate {
                module_id: ModuleId::Ciba,
                desired_state: DesiredMode::Disabled,
                expected_revision: Some(ModuleRevision::new(u64::MAX)),
                actor_id: "admin-b".to_owned(),
                reason: "maintenance".to_owned(),
                changed_at: SystemTime::UNIX_EPOCH,
            }),
        );

        assert!(matches!(
            result,
            Err(RuntimeModuleManagementError::Registry(
                RegistryError::RevisionExhausted(ModuleId::Ciba)
            ))
        ));
        assert_eq!(
            repository.state.lock().unwrap().desired[0].revision,
            ModuleRevision::new(u64::MAX)
        );
    }

    #[test]
    fn concurrent_dependency_disable_and_dependent_enable_cannot_both_commit() {
        let repository = Arc::new(TestRepository::default());
        {
            let mut state = repository.state.lock().unwrap();
            state.desired.extend([
                DesiredStateRecord {
                    module_id: ModuleId::RequestObjects,
                    mode: DesiredMode::Enabled,
                    revision: ModuleRevision::new(1),
                    actor_id: None,
                    reason: None,
                    updated_at: SystemTime::UNIX_EPOCH,
                },
                DesiredStateRecord {
                    module_id: ModuleId::Jarm,
                    mode: DesiredMode::Disabled,
                    revision: ModuleRevision::new(1),
                    actor_id: None,
                    reason: None,
                    updated_at: SystemTime::UNIX_EPOCH,
                },
            ]);
        }
        let catalog = ModuleCatalog::fixed(
            CatalogDurations {
                device_authorization: Duration::from_secs(60),
                ciba: Duration::from_secs(120),
                authorization_code: Duration::from_secs(30),
                refresh_token: Duration::from_secs(300),
                session: Duration::from_secs(600),
            },
            BTreeSet::from([ModuleId::RequestObjects]),
        )
        .unwrap()
        .with_dependencies(ModuleId::Jarm, [ModuleId::RequestObjects])
        .unwrap();
        let initial_snapshot = ActiveModuleSnapshot {
            revision: ModuleRevision::new(1),
            accepting: BTreeSet::from([ModuleId::RequestObjects]),
            draining: BTreeSet::new(),
        };
        let disabling_registry = Arc::new(RuntimeModuleRegistry::new(
            repository.clone(),
            Arc::new(NoopModuleLifecycle),
            catalog.clone(),
            "instance-a".to_owned(),
            initial_snapshot.clone(),
        ));
        let enabling_registry = Arc::new(RuntimeModuleRegistry::new(
            repository.clone(),
            Arc::new(NoopModuleLifecycle),
            catalog,
            "instance-b".to_owned(),
            initial_snapshot,
        ));
        let (entered_tx, entered_rx) = mpsc::sync_channel(1);
        let (release_tx, release_rx) = mpsc::sync_channel(1);
        *repository.cas_pause.lock().unwrap() = Some(CasPause {
            module_id: ModuleId::RequestObjects,
            entered: entered_tx,
            release: release_rx,
        });

        let disabling = {
            let registry = disabling_registry;
            std::thread::spawn(move || {
                block_on(registry.set_desired_mode(
                    ModuleId::RequestObjects,
                    DesiredMode::Disabled,
                    Some(ModuleRevision::new(1)),
                    Some("admin-a".to_owned()),
                    Some("disable dependency".to_owned()),
                    SystemTime::UNIX_EPOCH,
                ))
            })
        };
        entered_rx.recv().unwrap();
        let (dependency_read_tx, dependency_read_rx) = mpsc::sync_channel(1);
        let (dependency_release_tx, dependency_release_rx) = mpsc::sync_channel(1);
        let (target_read_tx, target_read_rx) = mpsc::sync_channel(1);
        let (target_release_tx, target_release_rx) = mpsc::sync_channel(1);
        repository.read_pauses.lock().unwrap().extend([
            ReadPause {
                module_id: ModuleId::RequestObjects,
                entered: dependency_read_tx,
                release: dependency_release_rx,
            },
            ReadPause {
                module_id: ModuleId::Jarm,
                entered: target_read_tx,
                release: target_release_rx,
            },
        ]);
        let enabling = {
            let registry = enabling_registry;
            std::thread::spawn(move || {
                block_on(registry.set_desired_mode(
                    ModuleId::Jarm,
                    DesiredMode::Enabled,
                    Some(ModuleRevision::new(1)),
                    Some("admin-b".to_owned()),
                    Some("enable dependent".to_owned()),
                    SystemTime::UNIX_EPOCH,
                ))
            })
        };
        dependency_read_rx.recv().unwrap();
        dependency_release_tx.send(()).unwrap();
        target_read_rx.recv().unwrap();
        target_release_tx.send(()).unwrap();
        release_tx.send(()).unwrap();

        assert!(matches!(
            disabling.join().unwrap(),
            Ok(CasOutcome::Applied(_))
        ));
        assert!(matches!(
            enabling.join().unwrap(),
            Ok(CasOutcome::Stale { current: Some(current) })
                if current.module_id == ModuleId::Jarm
                    && current.revision == ModuleRevision::new(1)
        ));
        let state = repository.state.lock().unwrap();
        assert_eq!(
            state
                .desired
                .iter()
                .find(|record| record.module_id == ModuleId::Jarm)
                .unwrap()
                .mode,
            DesiredMode::Disabled
        );
    }

    #[test]
    fn snapshot_revision_exhaustion_returns_instead_of_spinning() {
        let repository = Arc::new(TestRepository::default());
        repository
            .state
            .lock()
            .unwrap()
            .desired
            .push(desired(1, DesiredMode::Disabled));
        let catalog = ModuleCatalog::fixed(
            CatalogDurations {
                device_authorization: Duration::from_secs(60),
                ciba: Duration::from_secs(120),
                authorization_code: Duration::from_secs(30),
                refresh_token: Duration::from_secs(300),
                session: Duration::from_secs(600),
            },
            BTreeSet::from([ModuleId::Ciba]),
        )
        .unwrap();
        let registry = RuntimeModuleRegistry::new(
            repository,
            Arc::new(NoopModuleLifecycle),
            catalog,
            "instance-a".to_owned(),
            ActiveModuleSnapshot {
                revision: ModuleRevision::new(u64::MAX),
                accepting: BTreeSet::from([ModuleId::Ciba]),
                draining: BTreeSet::new(),
            },
        );

        assert!(matches!(
            block_on(registry.reconcile_once(ModuleId::Ciba)),
            Err(RegistryError::SnapshotRevisionExhausted)
        ));
    }

    #[test]
    fn dependency_loss_during_initialize_is_rechecked_and_fails_closed() {
        let repository = Arc::new(TestRepository::default());
        {
            let mut state = repository.state.lock().unwrap();
            state.desired.extend([
                DesiredStateRecord {
                    module_id: ModuleId::RequestObjects,
                    mode: DesiredMode::Enabled,
                    revision: ModuleRevision::new(1),
                    actor_id: None,
                    reason: None,
                    updated_at: SystemTime::UNIX_EPOCH,
                },
                DesiredStateRecord {
                    module_id: ModuleId::Jarm,
                    mode: DesiredMode::Enabled,
                    revision: ModuleRevision::new(1),
                    actor_id: None,
                    reason: None,
                    updated_at: SystemTime::UNIX_EPOCH,
                },
            ]);
        }
        let catalog = ModuleCatalog::fixed(
            CatalogDurations {
                device_authorization: Duration::from_secs(60),
                ciba: Duration::from_secs(120),
                authorization_code: Duration::from_secs(30),
                refresh_token: Duration::from_secs(300),
                session: Duration::from_secs(600),
            },
            BTreeSet::from([ModuleId::RequestObjects, ModuleId::Jarm]),
        )
        .unwrap()
        .with_dependencies(ModuleId::Jarm, [ModuleId::RequestObjects])
        .unwrap();
        let (entered_tx, entered_rx) = mpsc::sync_channel(1);
        let (release_tx, release_rx) = mpsc::sync_channel(1);
        let lifecycle = Arc::new(InitializePause {
            entered: entered_tx,
            release: Mutex::new(release_rx),
            stopped: AtomicBool::new(false),
        });
        let registry = Arc::new(RuntimeModuleRegistry::new(
            repository.clone(),
            lifecycle.clone(),
            catalog,
            "instance-a".to_owned(),
            ActiveModuleSnapshot {
                revision: ModuleRevision::new(1),
                accepting: BTreeSet::from([ModuleId::RequestObjects, ModuleId::Jarm]),
                draining: BTreeSet::new(),
            },
        ));
        let reconciling = {
            let registry = registry.clone();
            std::thread::spawn(move || block_on(registry.reconcile_once(ModuleId::Jarm)))
        };
        entered_rx.recv().unwrap();
        repository
            .state
            .lock()
            .unwrap()
            .desired
            .iter_mut()
            .find(|record| record.module_id == ModuleId::RequestObjects)
            .unwrap()
            .mode = DesiredMode::Disabled;
        release_tx.send(()).unwrap();

        assert!(matches!(
            reconciling.join().unwrap(),
            Ok(ReconcileOutcome::Failed)
        ));
        assert!(!registry.snapshot().admits(ModuleId::Jarm));
        assert!(lifecycle.stopped.load(Ordering::Acquire));
    }
}
