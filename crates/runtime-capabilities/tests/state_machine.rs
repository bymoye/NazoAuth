use std::collections::BTreeSet;
use std::convert::Infallible;
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, SystemTime};

use nazo_runtime_modules::{
    ActiveModuleSnapshot, CasOutcome, DesiredMode, DesiredRevisionGuard, DesiredStateChange,
    DesiredStateRecord, DisablePolicy, InstanceStateChange, InstanceStateMutation,
    InstanceStateRecord, ModuleEventPage, ModuleEventRecord, ModuleEventState, ModuleEventType,
    ModuleId, ModuleRevision, ModuleSpec, ModuleState, ModuleStateRepository, SnapshotStore,
    StaleTransition, TransitionGuard, validate_module_specs,
};

fn complete_fixture_catalog() -> Vec<ModuleSpec> {
    ModuleId::ALL
        .into_iter()
        .map(|id| ModuleSpec {
            id,
            dependencies: BTreeSet::new(),
            // Fixture only: production policies are supplied by the composition root.
            disable_policy: DisablePolicy::Immediate,
        })
        .collect()
}

#[test]
fn desired_modes_resolve_against_the_inherited_default() {
    assert!(!DesiredMode::Inherit.resolve(false));
    assert!(DesiredMode::Inherit.resolve(true));
    assert!(DesiredMode::Enabled.resolve(false));
    assert!(!DesiredMode::Disabled.resolve(true));
}

#[test]
fn only_legal_state_transitions_are_accepted() {
    assert!(ModuleState::Disabled.can_transition_to(ModuleState::Starting));
    assert!(!ModuleState::Enabled.can_transition_to(ModuleState::Starting));
}

#[test]
fn lifecycle_transition_matrix_is_closed() {
    use ModuleState::{Disabled, Draining, Enabled, Failed, Starting};

    let states = [Disabled, Starting, Enabled, Draining, Failed];
    let legal = [
        (Disabled, Starting),
        (Starting, Enabled),
        (Starting, Failed),
        (Starting, Disabled),
        (Enabled, Draining),
        (Enabled, Failed),
        (Draining, Disabled),
        (Draining, Failed),
        (Failed, Starting),
        (Failed, Disabled),
    ];

    for from in states {
        for to in states {
            assert_eq!(
                from.can_transition_to(to),
                legal.contains(&(from, to)),
                "unexpected transition legality for {from:?} -> {to:?}",
            );
        }
    }
}

#[test]
fn audit_event_catalog_is_closed_and_exhaustive() {
    assert_eq!(ModuleEventType::ALL.len(), 7);
}

#[test]
fn complete_catalog_with_known_acyclic_dependencies_is_valid() {
    let mut specs = complete_fixture_catalog();
    specs[1].dependencies.insert(ModuleId::DeviceAuthorization);
    specs[2].dependencies.insert(ModuleId::TokenExchange);

    assert_eq!(specs.len(), ModuleId::ALL.len());
    assert!(validate_module_specs(&specs).is_ok());
}

#[test]
fn catalog_requires_exactly_one_spec_per_module() {
    let mut missing = complete_fixture_catalog();
    missing.pop();
    assert!(validate_module_specs(&missing).is_err());

    let mut duplicate = complete_fixture_catalog();
    duplicate.push(duplicate[0].clone());
    assert!(validate_module_specs(&duplicate).is_err());
}

#[test]
fn catalog_rejects_self_dependencies_and_cycles() {
    let mut self_dependent = complete_fixture_catalog();
    self_dependent[0]
        .dependencies
        .insert(ModuleId::DeviceAuthorization);
    assert!(validate_module_specs(&self_dependent).is_err());

    let mut cyclic = complete_fixture_catalog();
    cyclic[0].dependencies.insert(ModuleId::TokenExchange);
    cyclic[1].dependencies.insert(ModuleId::DeviceAuthorization);
    assert!(validate_module_specs(&cyclic).is_err());
}

#[test]
fn module_specs_retain_all_disable_policy_variants() {
    let policies = [
        DisablePolicy::Immediate,
        DisablePolicy::FinishExecutingRequests,
        DisablePolicy::DrainStoredTransactions {
            max_duration: Duration::from_secs(30),
        },
        DisablePolicy::NotRuntimeDisableable,
    ];

    for (spec, expected) in complete_fixture_catalog().into_iter().zip(policies) {
        let spec = ModuleSpec {
            disable_policy: expected,
            ..spec
        };
        assert_eq!(spec.disable_policy, expected);
    }
}

fn snapshot(revision: u64, accepting: impl IntoIterator<Item = ModuleId>) -> ActiveModuleSnapshot {
    ActiveModuleSnapshot {
        revision: ModuleRevision::new(revision),
        accepting: accepting.into_iter().collect(),
        draining: BTreeSet::new(),
    }
}

#[test]
fn revision_guards_and_snapshot_publication_reject_stale_transitions() {
    let latest = Arc::new(AtomicU64::new(7));
    let guard = TransitionGuard::bind(Arc::clone(&latest), ModuleRevision::new(7));
    let store = SnapshotStore::new(snapshot(7, [ModuleId::Scim]));

    assert_eq!(guard.revision().get(), 7);
    assert!(guard.ensure_current().is_ok());
    assert!(
        store
            .compare_and_publish(
                ModuleRevision::new(7),
                snapshot(8, [ModuleId::TokenExchange]),
            )
            .is_ok()
    );
    latest.store(8, Ordering::Release);

    assert_eq!(
        guard.ensure_current(),
        Err(StaleTransition::RevisionChanged {
            expected: ModuleRevision::new(7),
            current: ModuleRevision::new(8),
        })
    );
    assert_eq!(
        store.compare_and_publish(ModuleRevision::new(7), snapshot(9, [ModuleId::Ciba])),
        Err(StaleTransition::RevisionChanged {
            expected: ModuleRevision::new(7),
            current: ModuleRevision::new(8),
        })
    );
    assert_eq!(store.load().revision.get(), 8);
}

#[test]
fn request_lease_retains_the_old_snapshot_generation() {
    let store = SnapshotStore::new(snapshot(7, [ModuleId::Scim]));
    let request_lease = store.load();

    store
        .compare_and_publish(
            ModuleRevision::new(7),
            snapshot(8, [ModuleId::TokenExchange]),
        )
        .expect("revision 7 is current");

    assert_eq!(request_lease.revision.get(), 7);
    assert!(request_lease.accepting.contains(&ModuleId::Scim));
    let new_lease = store.load();
    assert_eq!(new_lease.revision.get(), 8);
    assert!(new_lease.accepting.contains(&ModuleId::TokenExchange));
}

#[test]
fn snapshot_publication_rejects_an_equal_revision() {
    let store = SnapshotStore::new(snapshot(7, [ModuleId::Scim]));

    let result = store.compare_and_publish(ModuleRevision::new(7), snapshot(7, [ModuleId::Ciba]));

    assert_eq!(
        result,
        Err(StaleTransition::NonMonotonicPublication {
            expected: ModuleRevision::new(7),
            attempted: ModuleRevision::new(7),
        })
    );
    let current = store.load();
    assert_eq!(current.revision.get(), 7);
    assert!(current.accepting.contains(&ModuleId::Scim));
    assert!(!current.accepting.contains(&ModuleId::Ciba));
}

#[test]
fn snapshot_publication_rejects_a_revision_rollback() {
    let store = SnapshotStore::new(snapshot(7, [ModuleId::Scim]));

    let result = store.compare_and_publish(ModuleRevision::new(7), snapshot(6, [ModuleId::Ciba]));

    assert_eq!(
        result,
        Err(StaleTransition::NonMonotonicPublication {
            expected: ModuleRevision::new(7),
            attempted: ModuleRevision::new(6),
        })
    );
    let current = store.load();
    assert_eq!(current.revision.get(), 7);
    assert!(current.accepting.contains(&ModuleId::Scim));
    assert!(!current.accepting.contains(&ModuleId::Ciba));
}

#[test]
fn two_same_base_callers_allow_only_the_strictly_advancing_publication() {
    let store = SnapshotStore::new(snapshot(7, [ModuleId::Scim]));

    let non_advancing =
        store.compare_and_publish(ModuleRevision::new(7), snapshot(7, [ModuleId::Ciba]));
    let advancing =
        store.compare_and_publish(ModuleRevision::new(7), snapshot(8, [ModuleId::Jarm]));

    assert_eq!(
        non_advancing,
        Err(StaleTransition::NonMonotonicPublication {
            expected: ModuleRevision::new(7),
            attempted: ModuleRevision::new(7),
        })
    );
    assert!(advancing.is_ok());
    let current = store.load();
    assert_eq!(current.revision.get(), 8);
    assert!(current.accepting.contains(&ModuleId::Jarm));
    assert!(!current.accepting.contains(&ModuleId::Ciba));
}

#[test]
fn only_one_concurrent_publisher_can_win_a_revision_compare_and_swap() {
    let store = Arc::new(SnapshotStore::new(snapshot(10, [])));
    let barrier = Arc::new(Barrier::new(3));
    let mut threads = Vec::new();

    for (next_revision, module) in [(11, ModuleId::Jarm), (12, ModuleId::Ciba)] {
        let store = Arc::clone(&store);
        let barrier = Arc::clone(&barrier);
        threads.push(std::thread::spawn(move || {
            barrier.wait();
            store.compare_and_publish(ModuleRevision::new(10), snapshot(next_revision, [module]))
        }));
    }

    barrier.wait();
    let results: Vec<_> = threads
        .into_iter()
        .map(|thread| thread.join().expect("publisher thread must not panic"))
        .collect();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(results.iter().filter(|result| result.is_err()).count(), 1);
    assert!(matches!(store.load().revision.get(), 11 | 12));
}

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

#[derive(Default)]
struct InMemoryState {
    desired: std::collections::BTreeMap<ModuleId, DesiredStateRecord>,
    instances: std::collections::BTreeMap<(String, ModuleId), InstanceStateRecord>,
    events: Vec<ModuleEventRecord>,
}

#[derive(Default)]
struct InMemoryRepository {
    state: Mutex<InMemoryState>,
}

impl InMemoryRepository {
    fn events(&self) -> Vec<ModuleEventRecord> {
        self.state
            .lock()
            .expect("state lock poisoned")
            .events
            .clone()
    }
}

impl ModuleStateRepository for InMemoryRepository {
    type Error = Infallible;

    async fn read_desired(
        &self,
        module_id: ModuleId,
    ) -> Result<Option<DesiredStateRecord>, Self::Error> {
        Ok(self
            .state
            .lock()
            .expect("state lock poisoned")
            .desired
            .get(&module_id)
            .cloned())
    }

    async fn read_all_desired(&self) -> Result<Vec<DesiredStateRecord>, Self::Error> {
        Ok(self
            .state
            .lock()
            .expect("state lock poisoned")
            .desired
            .values()
            .cloned()
            .collect())
    }

    async fn compare_and_set_desired(
        &self,
        change: DesiredStateChange,
    ) -> Result<CasOutcome<DesiredStateRecord>, Self::Error> {
        let mut state = self.state.lock().expect("state lock poisoned");
        let current = state.desired.get(&change.next.module_id).cloned();
        if current.as_ref().map(|record| record.revision) != change.expected_revision {
            return Ok(CasOutcome::Stale { current });
        }

        let event = ModuleEventRecord {
            event_id: format!("desired-{}", change.next.revision.get()),
            module_id: change.next.module_id,
            event_type: ModuleEventType::DesiredStateChanged,
            revision: change.next.revision,
            instance_id: None,
            actor_id: change.next.actor_id.clone(),
            reason: change.next.reason.clone(),
            before: current
                .as_ref()
                .map(|record| ModuleEventState::Desired(record.mode)),
            after: Some(ModuleEventState::Desired(change.next.mode)),
            outcome_code: None,
            occurred_at: change.next.updated_at,
        };
        state
            .desired
            .insert(change.next.module_id, change.next.clone());
        state.events.push(event);
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
        instance_id: &str,
        module_id: ModuleId,
    ) -> Result<Option<InstanceStateRecord>, Self::Error> {
        Ok(self
            .state
            .lock()
            .expect("state lock poisoned")
            .instances
            .get(&(instance_id.to_owned(), module_id))
            .cloned())
    }

    async fn read_all_instances(
        &self,
        instance_id: &str,
    ) -> Result<Vec<InstanceStateRecord>, Self::Error> {
        Ok(self
            .state
            .lock()
            .expect("state lock poisoned")
            .instances
            .iter()
            .filter(|((candidate, _), _)| candidate == instance_id)
            .map(|(_, record)| record.clone())
            .collect())
    }

    async fn page_events(&self, offset: i64, limit: i64) -> Result<ModuleEventPage, Self::Error> {
        let state = self.state.lock().expect("state lock poisoned");
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
        _required_desired_revision: ModuleRevision,
        mutation: InstanceStateMutation,
    ) -> Result<CasOutcome<InstanceStateRecord>, Self::Error> {
        let mut state = self.state.lock().expect("state lock poisoned");
        let change = mutation.change;
        let key = (change.next.instance_id.clone(), change.next.module_id);
        let current = state.instances.get(&key).cloned();
        if current.as_ref().map(|record| record.transition_revision) != change.expected_revision {
            state.events.push(mutation.stale_event);
            return Ok(CasOutcome::Stale { current });
        }
        state.instances.insert(key, change.next.clone());
        state.events.push(mutation.applied_event);
        Ok(CasOutcome::Applied(change.next))
    }

    async fn validate_revision(
        &self,
        module_id: ModuleId,
        expected: ModuleRevision,
    ) -> Result<bool, Self::Error> {
        Ok(self
            .state
            .lock()
            .expect("state lock poisoned")
            .desired
            .get(&module_id)
            .is_some_and(|record| record.revision == expected))
    }
}

fn desired_record(revision: u64, mode: DesiredMode) -> DesiredStateRecord {
    DesiredStateRecord {
        module_id: ModuleId::Scim,
        mode,
        revision: ModuleRevision::new(revision),
        actor_id: Some("admin-1".to_owned()),
        reason: Some("test change".to_owned()),
        updated_at: SystemTime::UNIX_EPOCH,
    }
}

fn instance_record(revision: u64, state: ModuleState) -> InstanceStateRecord {
    InstanceStateRecord {
        instance_id: "instance-1".to_owned(),
        module_id: ModuleId::Scim,
        state,
        transition_revision: ModuleRevision::new(revision),
        applied_revision: None,
        drain_deadline: None,
        error_code: None,
        updated_at: SystemTime::UNIX_EPOCH,
    }
}

fn instance_mutation(
    change: InstanceStateChange,
    event_type: ModuleEventType,
) -> InstanceStateMutation {
    let event = |event_type| ModuleEventRecord {
        event_id: format!("{event_type:?}-{}", change.next.transition_revision.get()),
        module_id: change.next.module_id,
        event_type,
        revision: change.next.transition_revision,
        instance_id: Some(change.next.instance_id.clone()),
        actor_id: None,
        reason: None,
        before: Some(ModuleEventState::Actual(ModuleState::Disabled)),
        after: Some(ModuleEventState::Actual(change.next.state)),
        outcome_code: None,
        occurred_at: change.next.updated_at,
    };
    InstanceStateMutation {
        applied_event: event(event_type),
        stale_event: event(ModuleEventType::StaleTransitionDiscarded),
        change,
    }
}

#[test]
fn desired_cas_distinguishes_absent_rows_and_atomically_appends_audit() {
    let repository = InMemoryRepository::default();
    let first = desired_record(1, DesiredMode::Enabled);

    let outcome = block_on(repository.compare_and_set_desired(DesiredStateChange {
        expected_revision: None,
        next: first.clone(),
    }))
    .expect("in-memory operation is infallible");
    assert_eq!(outcome, CasOutcome::Applied(first.clone()));
    assert_eq!(
        block_on(repository.read_desired(ModuleId::Scim)),
        Ok(Some(first))
    );
    let events = repository.events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event_type, ModuleEventType::DesiredStateChanged);
}

#[test]
fn stale_desired_cas_returns_current_without_mutation_or_event() {
    let repository = InMemoryRepository::default();
    let current = desired_record(1, DesiredMode::Enabled);
    block_on(repository.compare_and_set_desired(DesiredStateChange {
        expected_revision: None,
        next: current.clone(),
    }))
    .expect("in-memory operation is infallible");

    let outcome = block_on(repository.compare_and_set_desired(DesiredStateChange {
        expected_revision: None,
        next: desired_record(2, DesiredMode::Disabled),
    }))
    .expect("in-memory operation is infallible");
    assert_eq!(
        outcome,
        CasOutcome::Stale {
            current: Some(current.clone()),
        }
    );
    assert_eq!(
        block_on(repository.read_desired(ModuleId::Scim)),
        Ok(Some(current))
    );
    assert_eq!(repository.events().len(), 1);
}

#[test]
fn instance_cas_returns_current_on_revision_conflict() {
    let repository = InMemoryRepository::default();
    let starting = instance_record(3, ModuleState::Starting);
    assert_eq!(
        block_on(repository.compare_and_set_instance(
            ModuleRevision::new(3),
            instance_mutation(
                InstanceStateChange {
                    expected_revision: None,
                    next: starting.clone(),
                },
                ModuleEventType::TransitionStarted,
            )
        )),
        Ok(CasOutcome::Applied(starting.clone()))
    );

    let stale = block_on(repository.compare_and_set_instance(
        ModuleRevision::new(4),
        instance_mutation(
            InstanceStateChange {
                expected_revision: Some(ModuleRevision::new(2)),
                next: instance_record(4, ModuleState::Enabled),
            },
            ModuleEventType::TransitionCompleted,
        ),
    ));
    assert_eq!(
        stale,
        Ok(CasOutcome::Stale {
            current: Some(starting.clone()),
        })
    );
    assert_eq!(
        block_on(repository.read_instance("instance-1", ModuleId::Scim)),
        Ok(Some(starting))
    );
    assert_eq!(repository.events().len(), 2);
    assert_eq!(
        repository.events()[1].event_type,
        ModuleEventType::StaleTransitionDiscarded
    );
}

#[test]
fn durable_desired_revision_can_be_revalidated() {
    let repository = InMemoryRepository::default();
    block_on(repository.compare_and_set_desired(DesiredStateChange {
        expected_revision: None,
        next: desired_record(7, DesiredMode::Enabled),
    }))
    .expect("in-memory operation is infallible");

    assert_eq!(
        block_on(repository.validate_revision(ModuleId::Scim, ModuleRevision::new(7))),
        Ok(true)
    );
    assert_eq!(
        block_on(repository.validate_revision(ModuleId::Scim, ModuleRevision::new(8))),
        Ok(false)
    );
}
