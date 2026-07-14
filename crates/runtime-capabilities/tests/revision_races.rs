use std::collections::BTreeSet;
use std::convert::Infallible;
use std::future::Future;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Barrier, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, SystemTime};

use nazo_runtime_modules::{
    ActiveModuleSnapshot, CasOutcome, CatalogDurations, DesiredMode, DesiredRevisionGuard,
    DesiredStateChange, DesiredStateRecord, InstanceStateMutation, InstanceStateRecord,
    LifecycleFailure, LifecycleFuture, ModuleCatalog, ModuleEventPage, ModuleEventRecord,
    ModuleEventType, ModuleId, ModuleLifecycle, ModuleRevision, ModuleState, ModuleStateRepository,
    NoopModuleLifecycle, ReconcileOutcome, RuntimeModuleRegistry,
};

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

struct Pause {
    call: usize,
    entered: Barrier,
    release: Barrier,
}

#[derive(Default)]
struct State {
    desired: Option<DesiredStateRecord>,
    instance: Option<InstanceStateRecord>,
    events: Vec<ModuleEventRecord>,
    validations: usize,
}

struct Repository {
    state: Mutex<State>,
    pause: Pause,
}

impl Repository {
    fn new(pause_at_validation: usize) -> Self {
        Self {
            state: Mutex::new(State::default()),
            pause: Pause {
                call: pause_at_validation,
                entered: Barrier::new(2),
                release: Barrier::new(2),
            },
        }
    }

    fn force_desired(&self, revision: u64, mode: DesiredMode) {
        self.state.lock().unwrap().desired = Some(DesiredStateRecord {
            module_id: ModuleId::Ciba,
            mode,
            revision: ModuleRevision::new(revision),
            actor_id: Some("admin".to_owned()),
            reason: Some("race test".to_owned()),
            updated_at: SystemTime::UNIX_EPOCH,
        });
    }

    fn event_types(&self) -> Vec<ModuleEventType> {
        self.state
            .lock()
            .unwrap()
            .events
            .iter()
            .map(|event| event.event_type)
            .collect()
    }

    fn force_instance(&self, revision: u64, state: ModuleState) {
        self.state.lock().unwrap().instance = Some(InstanceStateRecord {
            instance_id: "instance-a".to_owned(),
            module_id: ModuleId::Ciba,
            state,
            transition_revision: ModuleRevision::new(revision),
            applied_revision: Some(ModuleRevision::new(revision)),
            drain_deadline: None,
            error_code: None,
            updated_at: SystemTime::UNIX_EPOCH,
        });
    }

    fn force_draining_instance(&self, revision: u64, deadline: SystemTime) {
        self.force_instance(revision, ModuleState::Draining);
        self.state
            .lock()
            .unwrap()
            .instance
            .as_mut()
            .unwrap()
            .drain_deadline = Some(deadline);
    }
}

impl ModuleStateRepository for Repository {
    type Error = Infallible;

    async fn read_desired(
        &self,
        _module_id: ModuleId,
    ) -> Result<Option<DesiredStateRecord>, Self::Error> {
        Ok(self.state.lock().unwrap().desired.clone())
    }

    async fn read_all_desired(&self) -> Result<Vec<DesiredStateRecord>, Self::Error> {
        Ok(self
            .state
            .lock()
            .unwrap()
            .desired
            .clone()
            .into_iter()
            .collect())
    }

    async fn compare_and_set_desired(
        &self,
        change: DesiredStateChange,
    ) -> Result<CasOutcome<DesiredStateRecord>, Self::Error> {
        let mut state = self.state.lock().unwrap();
        let current = state.desired.clone();
        if current.as_ref().map(|desired| desired.revision) != change.expected_revision {
            return Ok(CasOutcome::Stale { current });
        }
        state.desired = Some(change.next.clone());
        state.events.push(ModuleEventRecord {
            event_id: format!("desired-{}", change.next.revision.get()),
            module_id: change.next.module_id,
            event_type: ModuleEventType::DesiredStateChanged,
            revision: change.next.revision,
            instance_id: None,
            actor_id: change.next.actor_id.clone(),
            reason: change.next.reason.clone(),
            before: current
                .as_ref()
                .map(|record| nazo_runtime_modules::ModuleEventState::Desired(record.mode)),
            after: Some(nazo_runtime_modules::ModuleEventState::Desired(
                change.next.mode,
            )),
            outcome_code: None,
            occurred_at: change.next.updated_at,
        });
        Ok(CasOutcome::Applied(change.next))
    }

    async fn compare_and_set_desired_guarded(
        &self,
        change: DesiredStateChange,
        required_revisions: Vec<DesiredRevisionGuard>,
    ) -> Result<CasOutcome<DesiredStateRecord>, Self::Error> {
        assert!(required_revisions.is_empty());
        self.compare_and_set_desired(change).await
    }

    async fn read_instance(
        &self,
        _instance_id: &str,
        _module_id: ModuleId,
    ) -> Result<Option<InstanceStateRecord>, Self::Error> {
        Ok(self.state.lock().unwrap().instance.clone())
    }

    async fn read_all_instances(
        &self,
        _instance_id: &str,
    ) -> Result<Vec<InstanceStateRecord>, Self::Error> {
        Ok(self
            .state
            .lock()
            .unwrap()
            .instance
            .clone()
            .into_iter()
            .collect())
    }

    async fn page_events(&self, offset: i64, limit: i64) -> Result<ModuleEventPage, Self::Error> {
        let state = self.state.lock().unwrap();
        Ok(ModuleEventPage {
            total: i64::try_from(state.events.len()).unwrap(),
            events: state
                .events
                .iter()
                .skip(usize::try_from(offset).unwrap())
                .take(usize::try_from(limit).unwrap())
                .cloned()
                .collect(),
        })
    }

    async fn compare_and_set_instance(
        &self,
        required_desired_revision: ModuleRevision,
        mutation: InstanceStateMutation,
    ) -> Result<CasOutcome<InstanceStateRecord>, Self::Error> {
        let mut state = self.state.lock().unwrap();
        let current = state.instance.clone();
        if state
            .desired
            .as_ref()
            .is_none_or(|desired| desired.revision != required_desired_revision)
        {
            state.events.push(mutation.stale_event);
            return Ok(CasOutcome::Stale { current });
        }
        if current.as_ref().map(|value| value.transition_revision)
            != mutation.change.expected_revision
        {
            state.events.push(mutation.stale_event);
            return Ok(CasOutcome::Stale { current });
        }
        state.instance = Some(mutation.change.next.clone());
        state.events.push(mutation.applied_event);
        Ok(CasOutcome::Applied(mutation.change.next))
    }

    async fn validate_revision(
        &self,
        _module_id: ModuleId,
        expected: ModuleRevision,
    ) -> Result<bool, Self::Error> {
        let should_pause = {
            let mut state = self.state.lock().unwrap();
            state.validations += 1;
            state.validations == self.pause.call
        };
        if should_pause {
            self.pause.entered.wait();
            self.pause.release.wait();
        }
        Ok(self
            .state
            .lock()
            .unwrap()
            .desired
            .as_ref()
            .is_some_and(|desired| desired.revision == expected))
    }
}

fn catalog() -> ModuleCatalog {
    ModuleCatalog::fixed(
        CatalogDurations {
            device_authorization: Duration::from_secs(30),
            ciba: Duration::from_secs(30),
            authorization_code: Duration::from_secs(30),
            refresh_token: Duration::from_secs(30),
            session: Duration::from_secs(30),
        },
        BTreeSet::new(),
    )
    .unwrap()
}

fn registry(
    repository: Arc<Repository>,
    accepting: bool,
) -> RuntimeModuleRegistry<Repository, NoopModuleLifecycle> {
    RuntimeModuleRegistry::new(
        repository,
        Arc::new(NoopModuleLifecycle),
        catalog(),
        "instance-a".to_owned(),
        ActiveModuleSnapshot {
            revision: ModuleRevision::new(6),
            accepting: if accepting {
                BTreeSet::from([ModuleId::Ciba])
            } else {
                BTreeSet::new()
            },
            draining: BTreeSet::new(),
        },
    )
}

struct PausingLifecycle {
    calls: AtomicUsize,
    entered: mpsc::Sender<usize>,
    release_first: Barrier,
}

impl ModuleLifecycle for PausingLifecycle {
    fn initialize(
        &self,
        _module_id: ModuleId,
    ) -> LifecycleFuture<'_, Result<(), LifecycleFailure>> {
        Box::pin(async move {
            let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
            self.entered.send(call).unwrap();
            if call == 1 {
                self.release_first.wait();
            }
            Ok(())
        })
    }

    fn stop(&self, _module_id: ModuleId) -> LifecycleFuture<'_, Result<(), LifecycleFailure>> {
        Box::pin(async { Ok(()) })
    }

    fn drain_stored_transactions(
        &self,
        _module_id: ModuleId,
        _revision: ModuleRevision,
        _max_duration: Duration,
    ) -> LifecycleFuture<'_, Result<bool, LifecycleFailure>> {
        Box::pin(async { Ok(true) })
    }
}

#[derive(Default)]
struct RecordingDrainLifecycle {
    remaining: Mutex<Option<Duration>>,
}

impl ModuleLifecycle for RecordingDrainLifecycle {
    fn initialize(
        &self,
        _module_id: ModuleId,
    ) -> LifecycleFuture<'_, Result<(), LifecycleFailure>> {
        Box::pin(async { Ok(()) })
    }

    fn stop(&self, _module_id: ModuleId) -> LifecycleFuture<'_, Result<(), LifecycleFailure>> {
        Box::pin(async { Ok(()) })
    }

    fn drain_stored_transactions(
        &self,
        _module_id: ModuleId,
        _revision: ModuleRevision,
        remaining_duration: Duration,
    ) -> LifecycleFuture<'_, Result<bool, LifecycleFailure>> {
        *self.remaining.lock().unwrap() = Some(remaining_duration);
        Box::pin(async { Ok(true) })
    }
}

#[test]
fn resumed_drain_uses_the_persisted_deadline_instead_of_extending_the_ttl() {
    let repository = Arc::new(Repository::new(usize::MAX));
    repository.force_desired(7, DesiredMode::Disabled);
    repository.force_draining_instance(
        7,
        SystemTime::now()
            .checked_add(Duration::from_secs(1))
            .unwrap(),
    );
    let lifecycle = Arc::new(RecordingDrainLifecycle::default());
    let registry = RuntimeModuleRegistry::new(
        Arc::clone(&repository),
        Arc::clone(&lifecycle),
        catalog(),
        "instance-a".to_owned(),
        ActiveModuleSnapshot {
            revision: ModuleRevision::new(6),
            accepting: BTreeSet::new(),
            draining: BTreeSet::from([ModuleId::Ciba]),
        },
    );

    assert_eq!(
        block_on(registry.reconcile_once(ModuleId::Ciba)).unwrap(),
        ReconcileOutcome::Disabled,
    );
    let remaining = lifecycle
        .remaining
        .lock()
        .unwrap()
        .expect("stored transaction drain should run");
    assert!(remaining <= Duration::from_secs(1));
}

#[test]
fn concurrent_reconciles_for_one_module_execute_one_lifecycle_transition() {
    let repository = Arc::new(Repository::new(usize::MAX));
    repository.force_desired(7, DesiredMode::Enabled);
    let (entered_tx, entered_rx) = mpsc::channel();
    let lifecycle = Arc::new(PausingLifecycle {
        calls: AtomicUsize::new(0),
        entered: entered_tx,
        release_first: Barrier::new(2),
    });
    let registry = Arc::new(RuntimeModuleRegistry::new(
        Arc::clone(&repository),
        Arc::clone(&lifecycle),
        catalog(),
        "instance-a".to_owned(),
        ActiveModuleSnapshot {
            revision: ModuleRevision::new(6),
            accepting: BTreeSet::new(),
            draining: BTreeSet::new(),
        },
    ));

    let first = {
        let registry = Arc::clone(&registry);
        std::thread::spawn(move || block_on(registry.reconcile_once(ModuleId::Ciba)))
    };
    assert_eq!(entered_rx.recv().unwrap(), 1);
    let second_started = Arc::new(Barrier::new(2));
    let second = {
        let registry = Arc::clone(&registry);
        let second_started = Arc::clone(&second_started);
        std::thread::spawn(move || {
            second_started.wait();
            block_on(registry.reconcile_once(ModuleId::Ciba))
        })
    };
    second_started.wait();
    assert!(entered_rx.recv_timeout(Duration::from_millis(25)).is_err());
    lifecycle.release_first.wait();

    assert_eq!(first.join().unwrap().unwrap(), ReconcileOutcome::Enabled);
    assert_eq!(second.join().unwrap().unwrap(), ReconcileOutcome::NoChange);
    assert_eq!(lifecycle.calls.load(Ordering::SeqCst), 1);
}

#[test]
fn stale_enable_is_discarded_before_snapshot_publication() {
    let repository = Arc::new(Repository::new(1));
    repository.force_desired(7, DesiredMode::Enabled);
    let registry = Arc::new(registry(Arc::clone(&repository), false));
    let worker = {
        let registry = Arc::clone(&registry);
        std::thread::spawn(move || block_on(registry.reconcile_once(ModuleId::Ciba)))
    };

    repository.pause.entered.wait();
    repository.force_desired(8, DesiredMode::Disabled);
    repository.pause.release.wait();

    assert_eq!(
        worker.join().unwrap().unwrap(),
        ReconcileOutcome::StaleDiscarded
    );
    assert!(!registry.snapshot().admits(ModuleId::Ciba));
    assert_eq!(
        repository.event_types(),
        vec![
            ModuleEventType::TransitionStarted,
            ModuleEventType::StaleTransitionDiscarded,
        ]
    );
}

#[test]
fn stale_enable_is_rolled_back_before_final_state_persistence() {
    let repository = Arc::new(Repository::new(2));
    repository.force_desired(7, DesiredMode::Enabled);
    let registry = Arc::new(registry(Arc::clone(&repository), false));
    let worker = {
        let registry = Arc::clone(&registry);
        std::thread::spawn(move || block_on(registry.reconcile_once(ModuleId::Ciba)))
    };

    repository.pause.entered.wait();
    repository.force_desired(8, DesiredMode::Disabled);
    repository.pause.release.wait();

    assert_eq!(
        worker.join().unwrap().unwrap(),
        ReconcileOutcome::StaleDiscarded
    );
    assert!(!registry.snapshot().admits(ModuleId::Ciba));
    assert_eq!(
        repository.event_types(),
        vec![
            ModuleEventType::TransitionStarted,
            ModuleEventType::StaleTransitionDiscarded,
        ]
    );
}

fn run_stale_disable(
    pause_at: usize,
) -> (
    Arc<Repository>,
    Arc<RuntimeModuleRegistry<Repository, NoopModuleLifecycle>>,
) {
    let repository = Arc::new(Repository::new(pause_at));
    repository.force_desired(7, DesiredMode::Disabled);
    repository.force_instance(6, ModuleState::Enabled);
    let registry = Arc::new(registry(Arc::clone(&repository), true));
    let worker = {
        let registry = Arc::clone(&registry);
        std::thread::spawn(move || block_on(registry.reconcile_once(ModuleId::Ciba)))
    };
    repository.pause.entered.wait();
    repository.force_desired(8, DesiredMode::Enabled);
    repository.pause.release.wait();
    assert_eq!(
        worker.join().unwrap().unwrap(),
        ReconcileOutcome::StaleDiscarded
    );
    (repository, registry)
}

#[test]
fn stale_disable_before_snapshot_publication_preserves_previous_admission() {
    let (repository, registry) = run_stale_disable(1);
    assert!(registry.snapshot().admits(ModuleId::Ciba));
    assert_eq!(
        repository.event_types(),
        vec![
            ModuleEventType::TransitionStarted,
            ModuleEventType::StaleTransitionDiscarded,
        ]
    );
}

#[test]
fn stale_disable_after_snapshot_publication_restores_newer_enabled_intent() {
    let (repository, registry) = run_stale_disable(2);
    assert!(registry.snapshot().admits(ModuleId::Ciba));
    assert_eq!(
        repository.event_types(),
        vec![
            ModuleEventType::TransitionStarted,
            ModuleEventType::StaleTransitionDiscarded,
        ]
    );
}

#[test]
fn stale_disable_cannot_complete_drain() {
    let (repository, registry) = run_stale_disable(3);
    assert!(registry.snapshot().admits(ModuleId::Ciba));
    assert_eq!(
        repository.event_types(),
        vec![
            ModuleEventType::TransitionStarted,
            ModuleEventType::DrainStarted,
            ModuleEventType::StaleTransitionDiscarded,
        ]
    );
}

#[test]
fn stale_disable_cannot_persist_final_state() {
    let (repository, registry) = run_stale_disable(4);
    assert!(registry.snapshot().admits(ModuleId::Ciba));
    assert_eq!(
        repository.event_types(),
        vec![
            ModuleEventType::TransitionStarted,
            ModuleEventType::DrainStarted,
            ModuleEventType::DrainCompleted,
            ModuleEventType::StaleTransitionDiscarded,
        ]
    );
}

#[test]
fn successful_enable_and_disable_emit_exhaustive_ordered_audit() {
    let enabling_repository = Arc::new(Repository::new(usize::MAX));
    enabling_repository.force_desired(7, DesiredMode::Enabled);
    let enabling_registry = registry(Arc::clone(&enabling_repository), false);
    assert_eq!(
        block_on(enabling_registry.reconcile_once(ModuleId::Ciba)).unwrap(),
        ReconcileOutcome::Enabled
    );
    assert_eq!(
        enabling_repository.event_types(),
        vec![
            ModuleEventType::TransitionStarted,
            ModuleEventType::TransitionCompleted,
        ]
    );
    assert!(
        enabling_repository
            .state
            .lock()
            .unwrap()
            .events
            .iter()
            .all(|event| uuid::Uuid::parse_str(&event.event_id).is_ok()),
        "durable transition event identifiers must use the PostgreSQL UUID wire format",
    );
    assert_eq!(
        enabling_registry.snapshot().admits(ModuleId::Ciba),
        enabling_registry.snapshot().advertises(ModuleId::Ciba)
    );

    let disabling_repository = Arc::new(Repository::new(usize::MAX));
    disabling_repository.force_desired(7, DesiredMode::Disabled);
    disabling_repository.force_instance(6, ModuleState::Enabled);
    let disabling_registry = registry(Arc::clone(&disabling_repository), true);
    assert_eq!(
        block_on(disabling_registry.reconcile_once(ModuleId::Ciba)).unwrap(),
        ReconcileOutcome::Disabled
    );
    assert_eq!(
        disabling_repository.event_types(),
        vec![
            ModuleEventType::TransitionStarted,
            ModuleEventType::DrainStarted,
            ModuleEventType::DrainCompleted,
            ModuleEventType::TransitionCompleted,
        ]
    );
    assert!(!disabling_registry.snapshot().admits(ModuleId::Ciba));
    assert!(!disabling_registry.snapshot().advertises(ModuleId::Ciba));
}

#[test]
fn desired_api_records_only_intent_and_blocks_active_profile_dependency() {
    let repository = Arc::new(Repository::new(usize::MAX));
    let blocked_catalog = catalog().with_runtime_disable_blocked([ModuleId::Ciba]);
    let blocked_registry = RuntimeModuleRegistry::new(
        Arc::clone(&repository),
        Arc::new(NoopModuleLifecycle),
        blocked_catalog,
        "instance-a".to_owned(),
        ActiveModuleSnapshot {
            revision: ModuleRevision::new(0),
            accepting: BTreeSet::from([ModuleId::Ciba]),
            draining: BTreeSet::new(),
        },
    );
    assert!(matches!(
        block_on(blocked_registry.set_desired_mode(
            ModuleId::Ciba,
            DesiredMode::Disabled,
            None,
            Some("admin".to_owned()),
            Some("profile requires CIBA".to_owned()),
            SystemTime::UNIX_EPOCH,
        )),
        Err(nazo_runtime_modules::RegistryError::RuntimeDisableBlocked(
            ModuleId::Ciba
        ))
    ));
    assert!(repository.event_types().is_empty());

    let registry = registry(Arc::clone(&repository), false);
    let accepted = block_on(registry.set_desired_mode(
        ModuleId::Ciba,
        DesiredMode::Enabled,
        None,
        Some("admin".to_owned()),
        Some("enable for test".to_owned()),
        SystemTime::UNIX_EPOCH,
    ))
    .unwrap();
    assert!(
        matches!(accepted, CasOutcome::Applied(record) if record.revision == ModuleRevision::new(1))
    );
    assert_eq!(
        repository.event_types(),
        vec![ModuleEventType::DesiredStateChanged]
    );
    assert!(!registry.snapshot().admits(ModuleId::Ciba));
}

#[test]
fn disable_waits_for_the_removed_snapshot_generations_request_lease() {
    let repository = Arc::new(Repository::new(usize::MAX));
    repository.force_desired(7, DesiredMode::Disabled);
    repository.force_instance(6, ModuleState::Enabled);
    let registry = registry(Arc::clone(&repository), true);
    let lease = registry
        .lease(ModuleId::Ciba)
        .expect("active snapshot should admit CIBA");
    let mut future = std::pin::pin!(registry.reconcile_once(ModuleId::Ciba));
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);

    assert!(matches!(future.as_mut().poll(&mut context), Poll::Pending));
    assert_eq!(
        repository.event_types(),
        vec![
            ModuleEventType::TransitionStarted,
            ModuleEventType::DrainStarted,
        ]
    );
    assert!(!registry.snapshot().admits(ModuleId::Ciba));
    assert_eq!(lease.snapshot().revision, ModuleRevision::new(6));

    drop(lease);
    assert!(matches!(
        future.as_mut().poll(&mut context),
        Poll::Ready(Ok(ReconcileOutcome::Disabled))
    ));
    assert_eq!(
        repository.event_types(),
        vec![
            ModuleEventType::TransitionStarted,
            ModuleEventType::DrainStarted,
            ModuleEventType::DrainCompleted,
            ModuleEventType::TransitionCompleted,
        ]
    );
}
