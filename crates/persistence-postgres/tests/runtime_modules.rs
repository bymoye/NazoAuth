use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use diesel::{QueryableByName, sql_query, sql_types::BigInt};
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl};
use nazo_postgres::{RuntimeModuleRepository, create_pool};
use nazo_runtime_modules::{
    ActiveModuleSnapshot, CasOutcome, CatalogDurations, DesiredMode, DesiredRevisionGuard,
    DesiredStateChange, DesiredStateRecord, InstanceStateChange, InstanceStateMutation,
    InstanceStateRecord, ModuleCatalog, ModuleEventRecord, ModuleEventState, ModuleEventType,
    ModuleId, ModuleRevision, ModuleState, ModuleStateRepository, NoopModuleLifecycle,
    ReconcileOutcome, RuntimeModuleRegistry,
};
use uuid::Uuid;

fn database_url() -> Option<String> {
    let url = std::env::var("NAZO_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .ok();
    if url.is_none() && std::env::var_os("CI").is_some() {
        panic!("CI runtime repository tests require NAZO_TEST_DATABASE_URL or DATABASE_URL");
    }
    url
}

fn desired(module_id: ModuleId, mode: DesiredMode, revision: u64) -> DesiredStateRecord {
    DesiredStateRecord {
        module_id,
        mode,
        revision: ModuleRevision::new(revision),
        actor_id: None,
        reason: Some("runtime repository integration test".to_owned()),
        updated_at: SystemTime::now(),
    }
}

fn instance(
    instance_id: &str,
    module_id: ModuleId,
    state: ModuleState,
    revision: u64,
) -> InstanceStateRecord {
    InstanceStateRecord {
        instance_id: instance_id.to_owned(),
        module_id,
        state,
        transition_revision: ModuleRevision::new(revision),
        applied_revision: None,
        drain_deadline: None,
        error_code: None,
        updated_at: SystemTime::now(),
    }
}

fn instance_event(
    event_id: Uuid,
    instance: &InstanceStateRecord,
    event_type: ModuleEventType,
    before: Option<ModuleState>,
) -> ModuleEventRecord {
    ModuleEventRecord {
        event_id: event_id.to_string(),
        module_id: instance.module_id,
        event_type,
        revision: instance.transition_revision,
        instance_id: Some(instance.instance_id.clone()),
        actor_id: None,
        reason: Some("runtime repository integration test".to_owned()),
        before: before.map(ModuleEventState::Actual),
        after: Some(ModuleEventState::Actual(instance.state)),
        outcome_code: None,
        occurred_at: instance.updated_at,
    }
}

fn instance_mutation(
    change: InstanceStateChange,
    event_type: ModuleEventType,
    stale_event_id: Uuid,
) -> InstanceStateMutation {
    let before = change.expected_revision.map(|_| ModuleState::Starting);
    InstanceStateMutation {
        applied_event: instance_event(Uuid::now_v7(), &change.next, event_type, before),
        stale_event: instance_event(
            stale_event_id,
            &change.next,
            ModuleEventType::StaleTransitionDiscarded,
            before,
        ),
        change,
    }
}

#[derive(QueryableByName)]
struct EventCount {
    #[diesel(sql_type = BigInt)]
    count: i64,
}

async fn event_count(connection: &mut AsyncPgConnection, module_id: &str) -> i64 {
    sql_query("SELECT COUNT(*) AS count FROM runtime_module_state_events WHERE module_id = $1")
        .bind::<diesel::sql_types::Text, _>(module_id)
        .get_result::<EventCount>(connection)
        .await
        .expect("event count should load")
        .count
}

async fn event_type_count(
    connection: &mut AsyncPgConnection,
    module_id: &str,
    event_type: &str,
) -> i64 {
    sql_query(
        "SELECT COUNT(*) AS count FROM runtime_module_state_events WHERE module_id = $1 AND event_type = $2",
    )
    .bind::<diesel::sql_types::Text, _>(module_id)
    .bind::<diesel::sql_types::Text, _>(event_type)
    .get_result::<EventCount>(connection)
    .await
    .expect("event type count should load")
    .count
}

fn tagged_database_url(database_url: &str, application_name: &str) -> String {
    let separator = if database_url.contains('?') { '&' } else { '?' };
    format!("{database_url}{separator}application_name={application_name}")
}

async fn wait_for_lock_wait(connection: &mut AsyncPgConnection) -> bool {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while std::time::Instant::now() < deadline {
        let count = sql_query(
            "SELECT COUNT(*)::bigint AS count FROM pg_stat_activity WHERE wait_event_type = 'Lock' AND query ILIKE '%runtime_module_desired_states%'",
        )
        .get_result::<EventCount>(connection)
        .await
        .unwrap()
        .count;
        if count > 0 {
            return true;
        }
        tokio::task::yield_now().await;
    }
    false
}

async fn clear_module(database_url: &str, module_id: &str) {
    let mut connection = AsyncPgConnection::establish(database_url)
        .await
        .expect("test database should connect");
    for table in [
        "runtime_module_state_events",
        "runtime_module_instance_states",
        "runtime_module_desired_states",
    ] {
        sql_query(format!("DELETE FROM {table} WHERE module_id = $1"))
            .bind::<diesel::sql_types::Text, _>(module_id)
            .execute(&mut connection)
            .await
            .expect("runtime module fixture should clear");
    }
}

#[tokio::test]
async fn bulk_management_reads_return_domain_records_and_isolate_instances() {
    let Some(database_url) = database_url() else {
        return;
    };
    nazo_postgres::run_pending_migrations(&database_url)
        .await
        .expect("migrations should apply");
    let repository = RuntimeModuleRepository::new(create_pool(&database_url, 4).unwrap());
    let instance_id = format!("runtime-bulk-{}", Uuid::now_v7());
    let other_instance_id = format!("runtime-bulk-other-{}", Uuid::now_v7());
    let fixtures = [
        (ModuleId::RequestObjects, DesiredMode::Enabled),
        (ModuleId::Jarm, DesiredMode::Disabled),
    ];

    for (module_id, mode) in fixtures {
        let current = repository.read_desired(module_id).await.unwrap();
        let revision = current.as_ref().map_or(ModuleRevision::new(1), |record| {
            ModuleRevision::new(record.revision.get() + 1)
        });
        let applied = repository
            .compare_and_set_desired(DesiredStateChange {
                expected_revision: current.map(|record| record.revision),
                next: desired(module_id, mode, revision.get()),
            })
            .await
            .unwrap();
        let CasOutcome::Applied(applied) = applied else {
            panic!("single-threaded bulk fixture desired update must apply");
        };
        let revision = applied.revision;
        let state = instance(
            &instance_id,
            module_id,
            ModuleState::Enabled,
            revision.get(),
        );
        repository
            .compare_and_set_instance(
                revision,
                instance_mutation(
                    InstanceStateChange {
                        expected_revision: None,
                        next: state,
                    },
                    ModuleEventType::TransitionCompleted,
                    Uuid::now_v7(),
                ),
            )
            .await
            .unwrap();
    }

    let other_module = ModuleId::RequestObjects;
    let desired = repository
        .read_desired(other_module)
        .await
        .unwrap()
        .unwrap();
    repository
        .compare_and_set_instance(
            desired.revision,
            instance_mutation(
                InstanceStateChange {
                    expected_revision: None,
                    next: instance(
                        &other_instance_id,
                        other_module,
                        ModuleState::Enabled,
                        desired.revision.get(),
                    ),
                },
                ModuleEventType::TransitionCompleted,
                Uuid::now_v7(),
            ),
        )
        .await
        .unwrap();

    let desired_records = repository.read_all_desired().await.unwrap();
    for (module_id, mode) in fixtures {
        assert!(
            desired_records
                .iter()
                .any(|record| record.module_id == module_id && record.mode == mode)
        );
    }
    let instances = repository.read_all_instances(&instance_id).await.unwrap();
    assert_eq!(instances.len(), fixtures.len());
    assert!(
        instances
            .iter()
            .all(|record| record.instance_id == instance_id)
    );
}

#[tokio::test]
async fn guarded_desired_changes_are_serialized_across_database_connections() {
    let Some(database_url) = database_url() else {
        return;
    };
    nazo_postgres::run_pending_migrations(&database_url)
        .await
        .expect("migrations should apply");
    clear_module(&database_url, "http_message_signatures").await;
    clear_module(&database_url, "frontchannel_logout").await;
    let repository = Arc::new(RuntimeModuleRepository::new(
        create_pool(&database_url, 4).unwrap(),
    ));
    let first = ModuleId::HttpMessageSignatures;
    let second = ModuleId::FrontchannelLogout;
    for module_id in [first, second] {
        repository
            .compare_and_set_desired(DesiredStateChange {
                expected_revision: None,
                next: desired(module_id, DesiredMode::Enabled, 1),
            })
            .await
            .unwrap();
    }

    let first_change = repository.compare_and_set_desired_guarded(
        DesiredStateChange {
            expected_revision: Some(ModuleRevision::new(1)),
            next: desired(first, DesiredMode::Disabled, 2),
        },
        vec![DesiredRevisionGuard {
            module_id: second,
            expected_revision: Some(ModuleRevision::new(1)),
        }],
    );
    let second_change = repository.compare_and_set_desired_guarded(
        DesiredStateChange {
            expected_revision: Some(ModuleRevision::new(1)),
            next: desired(second, DesiredMode::Disabled, 2),
        },
        vec![DesiredRevisionGuard {
            module_id: first,
            expected_revision: Some(ModuleRevision::new(1)),
        }],
    );
    let (first_outcome, second_outcome) = tokio::join!(first_change, second_change);
    let outcomes = [first_outcome.unwrap(), second_outcome.unwrap()];
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, CasOutcome::Applied(_)))
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, CasOutcome::Stale { .. }))
            .count(),
        1
    );
    let revisions = [
        repository
            .read_desired(first)
            .await
            .unwrap()
            .unwrap()
            .revision,
        repository
            .read_desired(second)
            .await
            .unwrap()
            .unwrap()
            .revision,
    ];
    assert_eq!(
        revisions
            .iter()
            .filter(|revision| **revision == ModuleRevision::new(2))
            .count(),
        1
    );
}

#[tokio::test]
async fn registry_generated_transition_events_are_postgresql_compatible() {
    let Some(database_url) = database_url() else {
        return;
    };
    nazo_postgres::run_pending_migrations(&database_url)
        .await
        .expect("migrations should apply");
    clear_module(&database_url, "authorization_details").await;
    let pool = create_pool(&database_url, 4).expect("pool should build");
    let repository = Arc::new(RuntimeModuleRepository::new(pool));
    let module_id = ModuleId::AuthorizationDetails;
    repository
        .compare_and_set_desired(DesiredStateChange {
            expected_revision: None,
            next: desired(module_id, DesiredMode::Enabled, 1),
        })
        .await
        .expect("desired state should persist");
    let short = Duration::from_secs(1);
    let catalog = ModuleCatalog::fixed(
        CatalogDurations {
            device_authorization: short,
            ciba: short,
            authorization_code: short,
            refresh_token: short,
            session: short,
        },
        BTreeSet::new(),
    )
    .expect("fixed module catalog should be valid");
    let registry = RuntimeModuleRegistry::new(
        Arc::clone(&repository),
        Arc::new(NoopModuleLifecycle),
        catalog,
        "postgres-registry-test".to_owned(),
        ActiveModuleSnapshot {
            revision: ModuleRevision::new(0),
            accepting: BTreeSet::new(),
            draining: BTreeSet::new(),
        },
    );

    assert_eq!(
        registry.reconcile_once(module_id).await.unwrap(),
        ReconcileOutcome::Enabled,
    );
    assert!(registry.snapshot().admits(module_id));
    let actual = repository
        .read_instance("postgres-registry-test", module_id)
        .await
        .unwrap()
        .expect("actual state should persist");
    assert_eq!(actual.state, ModuleState::Enabled);
    assert_eq!(actual.applied_revision, Some(ModuleRevision::new(1)));

    let mut connection = AsyncPgConnection::establish(&database_url).await.unwrap();
    assert_eq!(
        event_type_count(
            &mut connection,
            "authorization_details",
            "transition_started",
        )
        .await,
        1,
    );
    assert_eq!(
        event_type_count(
            &mut connection,
            "authorization_details",
            "transition_completed",
        )
        .await,
        1,
    );
}

#[tokio::test]
async fn desired_state_cas_is_atomic_stale_safe_and_noop_audited() {
    let Some(database_url) = database_url() else {
        return;
    };
    nazo_postgres::run_pending_migrations(&database_url)
        .await
        .expect("migrations should apply");
    clear_module(&database_url, "ciba").await;
    let pool = create_pool(&database_url, 4).expect("pool should build");
    let repository = RuntimeModuleRepository::new(pool);
    let module_id = ModuleId::Ciba;

    let applied = repository
        .compare_and_set_desired(DesiredStateChange {
            expected_revision: None,
            next: desired(module_id, DesiredMode::Enabled, 1),
        })
        .await
        .expect("initial desired state should persist");
    assert!(
        matches!(applied, CasOutcome::Applied(record) if record.revision == ModuleRevision::new(1))
    );

    let stale = repository
        .compare_and_set_desired(DesiredStateChange {
            expected_revision: None,
            next: desired(module_id, DesiredMode::Disabled, 1),
        })
        .await
        .expect("stale desired CAS should be a typed outcome");
    assert!(
        matches!(stale, CasOutcome::Stale { current: Some(record) } if record.mode == DesiredMode::Enabled)
    );

    let noop = repository
        .compare_and_set_desired(DesiredStateChange {
            expected_revision: Some(ModuleRevision::new(1)),
            next: desired(module_id, DesiredMode::Enabled, 2),
        })
        .await
        .expect("same-mode desired CAS should be accepted");
    assert!(
        matches!(noop, CasOutcome::Applied(record) if record.revision == ModuleRevision::new(1))
    );
    assert_eq!(
        repository
            .read_desired(module_id)
            .await
            .expect("desired state should load")
            .expect("desired state should exist")
            .revision,
        ModuleRevision::new(1)
    );

    let mut connection = AsyncPgConnection::establish(&database_url)
        .await
        .expect("test database should connect");
    assert_eq!(event_count(&mut connection, "ciba").await, 2);
}

#[tokio::test]
async fn runtime_event_page_returns_typed_newest_first_records() {
    let Some(database_url) = database_url() else {
        return;
    };
    nazo_postgres::run_pending_migrations(&database_url)
        .await
        .expect("migrations should apply");
    clear_module(&database_url, "session_management").await;
    let repository = RuntimeModuleRepository::new(create_pool(&database_url, 4).unwrap());
    for (revision, mode) in [(1, DesiredMode::Enabled), (2, DesiredMode::Disabled)] {
        let expected_revision = (revision > 1).then(|| ModuleRevision::new(revision - 1));
        repository
            .compare_and_set_desired(DesiredStateChange {
                expected_revision,
                next: desired(ModuleId::SessionManagement, mode, revision),
            })
            .await
            .expect("desired event should persist");
    }

    let page = repository
        .page_events(0, 100)
        .await
        .expect("event page should load");
    let session_events: Vec<_> = page
        .events
        .iter()
        .filter(|event| event.module_id == ModuleId::SessionManagement)
        .collect();
    assert_eq!(session_events.len(), 2);
    assert_eq!(
        session_events[0].event_type,
        ModuleEventType::DesiredStateChanged
    );
    assert_eq!(
        session_events[0].after,
        Some(ModuleEventState::Desired(DesiredMode::Disabled))
    );
    assert_eq!(
        session_events[1].after,
        Some(ModuleEventState::Desired(DesiredMode::Enabled))
    );
    assert!(page.total >= 2);
}

#[tokio::test]
async fn instance_completion_cannot_overwrite_a_newer_transition_revision() {
    let Some(database_url) = database_url() else {
        return;
    };
    nazo_postgres::run_pending_migrations(&database_url)
        .await
        .expect("migrations should apply");
    clear_module(&database_url, "token_exchange").await;
    let repository = RuntimeModuleRepository::new(create_pool(&database_url, 4).unwrap());
    let instance_id = format!("runtime-test-{}", Uuid::now_v7());
    let module_id = ModuleId::TokenExchange;
    repository
        .compare_and_set_desired(DesiredStateChange {
            expected_revision: None,
            next: desired(module_id, DesiredMode::Enabled, 1),
        })
        .await
        .unwrap();
    repository
        .compare_and_set_desired(DesiredStateChange {
            expected_revision: Some(ModuleRevision::new(1)),
            next: desired(module_id, DesiredMode::Disabled, 2),
        })
        .await
        .unwrap();
    repository
        .compare_and_set_desired(DesiredStateChange {
            expected_revision: Some(ModuleRevision::new(2)),
            next: desired(module_id, DesiredMode::Enabled, 3),
        })
        .await
        .unwrap();
    repository
        .compare_and_set_desired(DesiredStateChange {
            expected_revision: Some(ModuleRevision::new(3)),
            next: desired(module_id, DesiredMode::Disabled, 4),
        })
        .await
        .unwrap();
    repository
        .compare_and_set_desired(DesiredStateChange {
            expected_revision: Some(ModuleRevision::new(4)),
            next: desired(module_id, DesiredMode::Enabled, 5),
        })
        .await
        .unwrap();
    repository
        .compare_and_set_desired(DesiredStateChange {
            expected_revision: Some(ModuleRevision::new(5)),
            next: desired(module_id, DesiredMode::Disabled, 6),
        })
        .await
        .unwrap();
    repository
        .compare_and_set_desired(DesiredStateChange {
            expected_revision: Some(ModuleRevision::new(6)),
            next: desired(module_id, DesiredMode::Enabled, 7),
        })
        .await
        .unwrap();

    repository
        .compare_and_set_instance(
            ModuleRevision::new(7),
            instance_mutation(
                InstanceStateChange {
                    expected_revision: None,
                    next: instance(&instance_id, module_id, ModuleState::Starting, 7),
                },
                ModuleEventType::TransitionStarted,
                Uuid::now_v7(),
            ),
        )
        .await
        .expect("initial instance state should persist");
    repository
        .compare_and_set_desired(DesiredStateChange {
            expected_revision: Some(ModuleRevision::new(7)),
            next: desired(module_id, DesiredMode::Disabled, 8),
        })
        .await
        .unwrap();
    repository
        .compare_and_set_instance(
            ModuleRevision::new(8),
            instance_mutation(
                InstanceStateChange {
                    expected_revision: Some(ModuleRevision::new(7)),
                    next: instance(&instance_id, module_id, ModuleState::Starting, 8),
                },
                ModuleEventType::TransitionStarted,
                Uuid::now_v7(),
            ),
        )
        .await
        .expect("newer transition should persist");

    let stale = repository
        .compare_and_set_instance(
            ModuleRevision::new(7),
            instance_mutation(
                InstanceStateChange {
                    expected_revision: Some(ModuleRevision::new(7)),
                    next: instance(&instance_id, module_id, ModuleState::Enabled, 7),
                },
                ModuleEventType::TransitionCompleted,
                Uuid::now_v7(),
            ),
        )
        .await
        .expect("stale completion should be a typed outcome");
    assert!(
        matches!(stale, CasOutcome::Stale { current: Some(record) } if record.transition_revision == ModuleRevision::new(8) && record.state == ModuleState::Starting)
    );
    let mut connection = AsyncPgConnection::establish(&database_url)
        .await
        .expect("test database should connect");
    assert_eq!(
        event_type_count(&mut connection, "token_exchange", "transition_completed").await,
        0,
        "stale completion must not be audited as completed"
    );
    assert_eq!(
        event_type_count(
            &mut connection,
            "token_exchange",
            "stale_transition_discarded",
        )
        .await,
        1
    );
}

#[tokio::test]
async fn desired_revision_change_commits_before_old_completion_and_forces_stale_audit() {
    let Some(database_url) = database_url() else {
        return;
    };
    nazo_postgres::run_pending_migrations(&database_url)
        .await
        .expect("migrations should apply");
    clear_module(&database_url, "native_sso").await;
    let module_id = ModuleId::NativeSso;
    let instance_id = format!("runtime-toctou-{}", Uuid::now_v7());
    let base_repository = RuntimeModuleRepository::new(create_pool(&database_url, 2).unwrap());
    base_repository
        .compare_and_set_desired(DesiredStateChange {
            expected_revision: None,
            next: desired(module_id, DesiredMode::Enabled, 1),
        })
        .await
        .unwrap();
    let mut desired_revision = 1;
    let mut desired_mode = DesiredMode::Enabled;
    while desired_revision < 7 {
        let next_revision = desired_revision + 1;
        desired_mode = match desired_mode {
            DesiredMode::Enabled => DesiredMode::Disabled,
            _ => DesiredMode::Enabled,
        };
        base_repository
            .compare_and_set_desired(DesiredStateChange {
                expected_revision: Some(ModuleRevision::new(desired_revision)),
                next: desired(module_id, desired_mode, next_revision),
            })
            .await
            .unwrap();
        desired_revision = next_revision;
    }
    base_repository
        .compare_and_set_instance(
            ModuleRevision::new(7),
            instance_mutation(
                InstanceStateChange {
                    expected_revision: None,
                    next: instance(&instance_id, module_id, ModuleState::Starting, 7),
                },
                ModuleEventType::TransitionStarted,
                Uuid::now_v7(),
            ),
        )
        .await
        .unwrap();

    let (desired_locked_tx, desired_locked_rx) = tokio::sync::oneshot::channel();
    let (commit_tx, commit_rx) = tokio::sync::oneshot::channel();
    let coordinator_url = database_url.clone();
    let coordinator = tokio::spawn(async move {
        let mut connection = AsyncPgConnection::establish(&coordinator_url)
            .await
            .unwrap();
        connection
            .transaction::<(), diesel::result::Error, _>(async |connection| {
                let updated = sql_query(
                    "UPDATE runtime_module_desired_states SET desired_mode = 'disabled', revision = 8, updated_at = CURRENT_TIMESTAMP WHERE module_id = 'native_sso'",
                )
                .execute(connection)
                .await?;
                assert_eq!(updated, 1);
                desired_locked_tx.send(()).unwrap();
                commit_rx
                    .await
                    .map_err(|_| diesel::result::Error::RollbackTransaction)?;
                Ok(())
            })
            .await
    });
    desired_locked_rx.await.unwrap();
    let mut observer = AsyncPgConnection::establish(&database_url).await.unwrap();

    let application_name = format!("runtime-old-completion-{}", Uuid::now_v7().simple());
    let old_repository = RuntimeModuleRepository::new(
        create_pool(tagged_database_url(&database_url, &application_name), 1).unwrap(),
    );
    let completion = instance_mutation(
        InstanceStateChange {
            expected_revision: Some(ModuleRevision::new(7)),
            next: instance(&instance_id, module_id, ModuleState::Enabled, 7),
        },
        ModuleEventType::TransitionCompleted,
        Uuid::now_v7(),
    );
    let old = tokio::spawn(async move {
        old_repository
            .compare_and_set_instance(ModuleRevision::new(7), completion)
            .await
    });
    if !wait_for_lock_wait(&mut observer).await {
        commit_tx.send(()).unwrap();
        coordinator.await.unwrap().unwrap();
        panic!("old completion did not block: {:?}", old.await);
    }
    commit_tx.send(()).unwrap();
    coordinator.await.unwrap().unwrap();

    assert!(matches!(
        old.await.unwrap().unwrap(),
        CasOutcome::Stale { current: Some(record) }
            if record.state == ModuleState::Starting
                && record.transition_revision == ModuleRevision::new(7)
    ));
    let stored = base_repository
        .read_instance(&instance_id, module_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.state, ModuleState::Starting);
    assert_eq!(
        event_type_count(&mut observer, "native_sso", "transition_completed").await,
        0
    );
    assert_eq!(
        event_type_count(&mut observer, "native_sso", "stale_transition_discarded",).await,
        1
    );
}

#[tokio::test]
async fn instance_event_insert_failure_rolls_back_state_mutation() {
    let Some(database_url) = database_url() else {
        return;
    };
    nazo_postgres::run_pending_migrations(&database_url)
        .await
        .expect("migrations should apply");
    clear_module(&database_url, "device_authorization").await;
    let repository = RuntimeModuleRepository::new(create_pool(&database_url, 4).unwrap());
    let instance_id = format!("runtime-test-{}", Uuid::now_v7());
    let module_id = ModuleId::DeviceAuthorization;
    repository
        .compare_and_set_desired(DesiredStateChange {
            expected_revision: None,
            next: desired(module_id, DesiredMode::Enabled, 1),
        })
        .await
        .unwrap();
    let duplicate_event_id = Uuid::now_v7();
    let initial = instance(&instance_id, module_id, ModuleState::Starting, 1);
    let mut initial_mutation = instance_mutation(
        InstanceStateChange {
            expected_revision: None,
            next: initial.clone(),
        },
        ModuleEventType::TransitionStarted,
        Uuid::now_v7(),
    );
    initial_mutation.applied_event.event_id = duplicate_event_id.to_string();
    repository
        .compare_and_set_instance(ModuleRevision::new(1), initial_mutation)
        .await
        .expect("initial transition should commit");

    let enabled = instance(&instance_id, module_id, ModuleState::Enabled, 1);
    let mut completion = instance_mutation(
        InstanceStateChange {
            expected_revision: Some(ModuleRevision::new(1)),
            next: enabled,
        },
        ModuleEventType::TransitionCompleted,
        Uuid::now_v7(),
    );
    completion.applied_event.event_id = duplicate_event_id.to_string();
    assert!(
        repository
            .compare_and_set_instance(ModuleRevision::new(1), completion)
            .await
            .is_err(),
        "duplicate audit event must fail the atomic mutation"
    );
    let stored = repository
        .read_instance(&instance_id, module_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.state, ModuleState::Starting);
}

#[tokio::test]
async fn audit_persistence_accepts_every_closed_event_kind() {
    let Some(database_url) = database_url() else {
        return;
    };
    nazo_postgres::run_pending_migrations(&database_url)
        .await
        .expect("migrations should apply");
    clear_module(&database_url, "jwt_bearer_grant").await;
    let repository = RuntimeModuleRepository::new(create_pool(&database_url, 4).unwrap());
    let module_id = ModuleId::JwtBearerGrant;
    repository
        .compare_and_set_desired(DesiredStateChange {
            expected_revision: None,
            next: desired(module_id, DesiredMode::Enabled, 1),
        })
        .await
        .expect("desired event should persist atomically");

    let instance_id = format!("runtime-audit-{}", Uuid::now_v7());
    let transitions = [
        (
            None,
            ModuleState::Starting,
            1,
            ModuleEventType::TransitionStarted,
        ),
        (
            Some(ModuleRevision::new(1)),
            ModuleState::Enabled,
            1,
            ModuleEventType::TransitionCompleted,
        ),
        (
            Some(ModuleRevision::new(1)),
            ModuleState::Draining,
            2,
            ModuleEventType::DrainStarted,
        ),
        (
            Some(ModuleRevision::new(2)),
            ModuleState::Disabled,
            2,
            ModuleEventType::DrainCompleted,
        ),
        (
            Some(ModuleRevision::new(2)),
            ModuleState::Starting,
            3,
            ModuleEventType::TransitionStarted,
        ),
        (
            Some(ModuleRevision::new(3)),
            ModuleState::Failed,
            3,
            ModuleEventType::TransitionFailed,
        ),
    ];
    let mut desired_revision = 1;
    let mut desired_mode = DesiredMode::Enabled;
    for (expected_revision, state, revision, event_type) in transitions {
        if revision != desired_revision {
            desired_mode = match desired_mode {
                DesiredMode::Enabled => DesiredMode::Disabled,
                _ => DesiredMode::Enabled,
            };
            repository
                .compare_and_set_desired(DesiredStateChange {
                    expected_revision: Some(ModuleRevision::new(desired_revision)),
                    next: desired(module_id, desired_mode, revision),
                })
                .await
                .unwrap();
            desired_revision = revision;
        }
        repository
            .compare_and_set_instance(
                ModuleRevision::new(revision),
                instance_mutation(
                    InstanceStateChange {
                        expected_revision,
                        next: instance(&instance_id, module_id, state, revision),
                    },
                    event_type,
                    Uuid::now_v7(),
                ),
            )
            .await
            .expect("transition event should persist atomically");
    }
    repository
        .compare_and_set_instance(
            ModuleRevision::new(2),
            instance_mutation(
                InstanceStateChange {
                    expected_revision: Some(ModuleRevision::new(2)),
                    next: instance(&instance_id, module_id, ModuleState::Enabled, 2),
                },
                ModuleEventType::TransitionCompleted,
                Uuid::now_v7(),
            ),
        )
        .await
        .expect("stale transition event should persist atomically");

    let mut connection = AsyncPgConnection::establish(&database_url)
        .await
        .expect("test database should connect");
    assert_eq!(event_count(&mut connection, "jwt_bearer_grant").await, 10);
}
