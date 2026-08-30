//! E03 unit coverage: accept-once durability, permanent id conflicts,
//! authorization snapshots, crash-boundary failpoints with zero duplicated
//! mutation, torn-publication recovery, and bounded retention for the
//! application operation journal (05 §4/§5).

use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
use std::sync::{Arc, Mutex};

use nazo_operator_protocol::{
    CONTROL_OPERATION_SCHEMA, CONTROL_RESULT_SCHEMA, ControlOperation, ControlOperationPayload,
    ControlOutcome, ControlResult, ControlResultData,
};

use super::*;

fn temporary_directory() -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "nazauth-control-journal-test-{}",
        rand::random::<u64>()
    ));
    fs::create_dir(&path).unwrap();
    path
}

const OPERATION_ID: &str = "019c8ca2-30a6-7000-8000-000000000005";
const OPERATION_ID_B: &str = "019c8ca2-30a6-7000-8000-000000000006";
/// D01 authoritative controller identity shape: canonical lowercase UUIDv7.
const CONTROLLER_ID: &str = "019c8ca2-30a6-7cc9-9f2a-4f5a6b7c8d90";

/// Checkpoint-only view over the accepted record for assertions that do not
/// care about the authorization snapshot.  Tests are allowed to read the
/// private storage helpers directly.
fn status(
    directory: &Path,
    operation_id: &str,
    request_hash: &str,
) -> Result<Option<JournalCheckpoint>, JournalFlowError> {
    ensure_file_safe_identifier(operation_id)?;
    ensure_request_hash_shape(request_hash)?;
    let path = record_path(&control_journal_directory(directory), operation_id);
    recover_temporary(&path)?;
    if !state_path_present(&path).map_err(transport)? {
        return Ok(None);
    }
    regular_state_file_present(&path, "control operation journal record").map_err(transport)?;
    let record = read_record(&path).map_err(transport)?;
    if record.request_hash != request_hash {
        return Err(JournalFlowError::OperationIdConflict);
    }
    Ok(Some(checkpoint(record)))
}

fn operation(operation_id: &str) -> ControlOperation {
    ControlOperation {
        schema: CONTROL_OPERATION_SCHEMA,
        operation_id: operation_id.to_owned(),
        kid: "kid-controller-test-key-0000000000000000000000000".to_owned(),
        deployment_id: "deployment-test".to_owned(),
        config_revision: "config-revision-1".to_owned(),
        operation: ControlOperationPayload::MigrateApply,
    }
}

fn snapshot() -> AuthorizationSnapshot {
    AuthorizationSnapshot {
        controller_id: CONTROLLER_ID.to_owned(),
        kid: "kid-controller-test-key-0000000000000000000000000".to_owned(),
        accepted_at: 1_000,
    }
}

fn hash(seed: char) -> String {
    std::iter::repeat_n(seed, 64).collect()
}

fn succeeded_result(operation_id: &str, request_hash: &str) -> ControlResult {
    ControlResult {
        schema: CONTROL_RESULT_SCHEMA,
        operation_id: operation_id.to_owned(),
        request_hash: request_hash.to_owned(),
        outcome: ControlOutcome::Succeeded,
        error: None,
        accepted_at: 1_000,
        completed_at: Some(1_005),
        result: None,
    }
}

/// Counting side effect with an owner ledger marker file, modelling an
/// operation class whose state owner deduplicates re-entry (migration
/// ledger semantics).  `invocations` counts attempts, `applications` counts
/// mutations that actually happened.
type LedgerSideEffect = Box<
    dyn FnOnce() -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Option<ControlResultData>, SideEffectError>>>,
    >,
>;

fn ledger_side_effect(directory: &Path) -> (Arc<AtomicUsize>, Arc<AtomicUsize>, LedgerSideEffect) {
    let invocations = Arc::new(AtomicUsize::new(0));
    let applications = Arc::new(AtomicUsize::new(0));
    let marker = directory.join("owner-ledger.marker");
    let invocations_clone = Arc::clone(&invocations);
    let applications_clone = Arc::clone(&applications);
    let effect = move || {
        invocations_clone.fetch_add(1, AtomicOrdering::SeqCst);
        let marker = marker.clone();
        let applications = Arc::clone(&applications_clone);
        Box::pin(async move {
            if state_path_present(&marker)? {
                return Ok(None);
            }
            fs::write(&marker, b"applied").map_err(anyhow::Error::from)?;
            applications.fetch_add(1, AtomicOrdering::SeqCst);
            Ok(None)
        })
            as std::pin::Pin<
                Box<
                    dyn std::future::Future<
                            Output = Result<Option<ControlResultData>, SideEffectError>,
                        >,
                >,
            >
    };
    (invocations, applications, Box::new(effect))
}

#[test]
fn accept_persists_the_authorization_snapshot_before_any_side_effect() {
    let directory = temporary_directory();
    let outcome = accept(
        &directory,
        &operation(OPERATION_ID),
        &hash('a'),
        &snapshot(),
    )
    .unwrap();
    assert_eq!(outcome, AcceptOutcome::Created);

    // The durable accepted record exists before any business step ran and
    // carries the full authorization snapshot.
    let path = control_journal_directory(&directory).join(format!("{OPERATION_ID}.journal.json"));
    let record: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    assert_eq!(record["phase"], "accepted");
    assert_eq!(record["controller_id"], CONTROLLER_ID);
    assert_eq!(record["kid"], snapshot().kid);
    assert_eq!(record["accepted_at"], 1_000);
    assert_eq!(record["request_hash"], hash('a'));
    assert_eq!(record["schema"], CONTROL_JOURNAL_SCHEMA);
    assert_eq!(record["result"], serde_json::Value::Null);

    // A second offer with the same id + hash resumes instead of re-accepting.
    let replay = accept(
        &directory,
        &operation(OPERATION_ID),
        &hash('a'),
        &snapshot(),
    )
    .unwrap();
    assert_eq!(replay, AcceptOutcome::Resumed(JournalCheckpoint::Accepted));
    assert_eq!(
        status(&directory, OPERATION_ID, &hash('a'))
            .unwrap()
            .unwrap(),
        JournalCheckpoint::Accepted
    );
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn same_id_with_a_different_request_hash_conflicts_permanently() {
    let directory = temporary_directory();
    accept(
        &directory,
        &operation(OPERATION_ID),
        &hash('a'),
        &snapshot(),
    )
    .unwrap();

    // Conflict while merely accepted...
    assert!(matches!(
        accept(
            &directory,
            &operation(OPERATION_ID),
            &hash('b'),
            &snapshot()
        ),
        Err(JournalFlowError::OperationIdConflict)
    ));
    assert!(matches!(
        status(&directory, OPERATION_ID, &hash('b')),
        Err(JournalFlowError::OperationIdConflict)
    ));

    // ...while executing...
    begin_execution(&directory, OPERATION_ID, &hash('a'), false).unwrap();
    assert!(matches!(
        accept(
            &directory,
            &operation(OPERATION_ID),
            &hash('b'),
            &snapshot()
        ),
        Err(JournalFlowError::OperationIdConflict)
    ));
    assert!(matches!(
        begin_execution(&directory, OPERATION_ID, &hash('b'), true),
        Err(JournalFlowError::OperationIdConflict)
    ));

    // ...and after the terminal result is durable.
    complete(&directory, &succeeded_result(OPERATION_ID, &hash('a'))).unwrap();
    assert!(matches!(
        accept(
            &directory,
            &operation(OPERATION_ID),
            &hash('b'),
            &snapshot()
        ),
        Err(JournalFlowError::OperationIdConflict)
    ));
    assert!(matches!(
        status(&directory, OPERATION_ID, &hash('b')),
        Err(JournalFlowError::OperationIdConflict)
    ));

    // The conflict is bound to the id, not the hash: a different operation
    // may reuse the same canonical request hash.
    accept(
        &directory,
        &operation(OPERATION_ID_B),
        &hash('a'),
        &snapshot(),
    )
    .unwrap();
    assert_eq!(
        status(&directory, OPERATION_ID_B, &hash('a'))
            .unwrap()
            .unwrap(),
        JournalCheckpoint::Accepted
    );
    fs::remove_dir_all(directory).unwrap();
}
#[tokio::test]
async fn happy_path_pauses_at_every_boundary_in_order_and_binds_the_result() {
    let directory = temporary_directory();
    let calls: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let recorder = calls.clone();
    let (invocations, applications, effect) = ledger_side_effect(&directory);
    let outcome = run_journaled_operation(
        &directory,
        &operation(OPERATION_ID),
        &hash('a'),
        &snapshot(),
        false,
        &move |name: &str| recorder.lock().unwrap().push(name.to_owned()),
        effect,
    )
    .await
    .unwrap();
    assert!(!outcome.recovered);
    // Bind every frozen field; completion time comes from the wall clock.
    let expected = succeeded_result(OPERATION_ID, &hash('a'));
    assert_eq!(outcome.result.schema, expected.schema);
    assert_eq!(outcome.result.operation_id, expected.operation_id);
    assert_eq!(outcome.result.request_hash, expected.request_hash);
    assert_eq!(outcome.result.outcome, expected.outcome);
    assert_eq!(outcome.result.error, None);
    assert_eq!(outcome.result.accepted_at, expected.accepted_at);
    assert!(
        outcome
            .result
            .completed_at
            .is_some_and(|at| at >= expected.accepted_at),
        "completion time must be ordered after acceptance"
    );
    assert_eq!(
        calls.lock().unwrap().as_slice(),
        [
            "control-journal-before-accept",
            "control-journal-after-accept",
            "control-journal-before-side-effect",
            "control-journal-after-side-effect",
            "control-journal-before-result",
            "control-journal-after-result",
        ]
    );
    assert_eq!(invocations.load(AtomicOrdering::SeqCst), 1);
    assert_eq!(applications.load(AtomicOrdering::SeqCst), 1);
    let durable = status(&directory, OPERATION_ID, &hash('a'))
        .unwrap()
        .unwrap();
    match durable {
        JournalCheckpoint::Completed(stored) => {
            assert_eq!(*stored, outcome.result);
            assert_eq!(stored.completed_at, outcome.result.completed_at);
        }
        other => panic!("expected completed checkpoint, got {other:?}"),
    }

    // Response-loss recovery: a fresh run returns the durable result
    // without touching the side effect and without re-running the flow.
    let recovered_calls: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let recorder = recovered_calls.clone();
    let (invocations, _applications, effect) = ledger_side_effect(&directory);
    let replay = run_journaled_operation(
        &directory,
        &operation(OPERATION_ID),
        &hash('a'),
        &snapshot(),
        true,
        &move |name: &str| recorder.lock().unwrap().push(name.to_owned()),
        effect,
    )
    .await
    .unwrap();
    assert!(replay.recovered);
    assert_eq!(replay.result, outcome.result);
    assert_eq!(
        recovered_calls.lock().unwrap().as_slice(),
        ["control-journal-before-accept"]
    );
    assert_eq!(invocations.load(AtomicOrdering::SeqCst), 0);
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn before_accept_crash_retries_cleanly_without_prior_mutation() {
    let directory = temporary_directory();
    // Kill before accept: nothing is on disk.
    assert_eq!(status(&directory, OPERATION_ID, &hash('a')).unwrap(), None);
    // Restart accepts and executes exactly once.
    let (invocations, applications, effect) = ledger_side_effect(&directory);
    let outcome = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(run_journaled_operation(
            &directory,
            &operation(OPERATION_ID),
            &hash('a'),
            &snapshot(),
            false,
            &|_| {},
            effect,
        ))
        .unwrap();
    assert!(!outcome.recovered);
    assert_eq!(applications.load(AtomicOrdering::SeqCst), 1);
    assert_eq!(invocations.load(AtomicOrdering::SeqCst), 1);
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn after_accept_crash_executes_the_side_effect_exactly_once() {
    let directory = temporary_directory();
    // First process dies right after the durable accept.
    accept(
        &directory,
        &operation(OPERATION_ID),
        &hash('a'),
        &snapshot(),
    )
    .unwrap();

    // Restart resumes from the accepted checkpoint and runs once.
    let (invocations, applications, effect) = ledger_side_effect(&directory);
    let outcome = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(run_journaled_operation(
            &directory,
            &operation(OPERATION_ID),
            &hash('a'),
            &snapshot(),
            false,
            &|_| {},
            effect,
        ))
        .unwrap();
    assert!(!outcome.recovered);
    assert_eq!(invocations.load(AtomicOrdering::SeqCst), 1);
    assert_eq!(applications.load(AtomicOrdering::SeqCst), 1);

    // And another restart observes the completed result only.
    let (_, _, effect) = ledger_side_effect(&directory);
    let replay = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(run_journaled_operation(
            &directory,
            &operation(OPERATION_ID),
            &hash('a'),
            &snapshot(),
            true,
            &|_| {},
            effect,
        ))
        .unwrap();
    assert!(replay.recovered);
    assert_eq!(invocations.load(AtomicOrdering::SeqCst), 1);
    fs::remove_dir_all(directory).unwrap();
}
#[test]
fn before_side_effect_crash_fails_closed_for_owners_without_idempotent_resume() {
    let directory = temporary_directory();
    accept(
        &directory,
        &operation(OPERATION_ID),
        &hash('a'),
        &snapshot(),
    )
    .unwrap();
    begin_execution(&directory, OPERATION_ID, &hash('a'), false).unwrap();

    // Restart without a proven-idempotent owner: refuse, never execute.
    let (invocations, _applications, effect) = ledger_side_effect(&directory);
    let error = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(run_journaled_operation(
            &directory,
            &operation(OPERATION_ID),
            &hash('a'),
            &snapshot(),
            false,
            &|_| {},
            effect,
        ))
        .unwrap_err();
    assert!(matches!(error, JournalFlowError::UnknownOutcome));
    assert_eq!(invocations.load(AtomicOrdering::SeqCst), 0);
    assert_eq!(
        status(&directory, OPERATION_ID, &hash('a'))
            .unwrap()
            .unwrap(),
        JournalCheckpoint::Executing
    );

    // The refusal is stable, not transient.
    let (_, _, effect) = ledger_side_effect(&directory);
    let again = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(run_journaled_operation(
            &directory,
            &operation(OPERATION_ID),
            &hash('a'),
            &snapshot(),
            false,
            &|_| {},
            effect,
        ))
        .unwrap_err();
    assert!(matches!(again, JournalFlowError::UnknownOutcome));
    assert_eq!(
        status(&directory, OPERATION_ID, &hash('a'))
            .unwrap()
            .unwrap(),
        JournalCheckpoint::Executing
    );
    fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
async fn executing_records_reenter_only_for_proven_idempotent_owners() {
    let directory = temporary_directory();
    accept(
        &directory,
        &operation(OPERATION_ID),
        &hash('a'),
        &snapshot(),
    )
    .unwrap();
    begin_execution(&directory, OPERATION_ID, &hash('a'), true).unwrap();

    // The owner's own ledger makes re-entry apply the mutation once even
    // though the business action is invoked twice across two processes.
    let (invocations, applications, effect) = ledger_side_effect(&directory);
    let outcome = run_journaled_operation(
        &directory,
        &operation(OPERATION_ID),
        &hash('a'),
        &snapshot(),
        true,
        &|_| {},
        effect,
    )
    .await
    .unwrap();
    assert!(!outcome.recovered);
    assert_eq!(invocations.load(AtomicOrdering::SeqCst), 1);
    assert_eq!(applications.load(AtomicOrdering::SeqCst), 1);

    // A second re-entry after completion is still refused for the raw
    // checkpoint transition: terminal records never re-execute.
    assert!(matches!(
        begin_execution(&directory, OPERATION_ID, &hash('a'), true),
        Err(JournalFlowError::UnknownOutcome)
    ));
    assert_eq!(applications.load(AtomicOrdering::SeqCst), 1);
    fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
async fn retryable_execution_keeps_a_resumable_record_without_a_false_failure_result() {
    let directory = temporary_directory();
    let error = run_journaled_operation(
        &directory,
        &operation(OPERATION_ID),
        &hash('a'),
        &snapshot(),
        true,
        &|_| {},
        || async {
            Err(SideEffectError::Retryable(anyhow::anyhow!(
                "database unavailable"
            )))
        },
    )
    .await
    .expect_err("a proven transient failure must not become a terminal result");
    assert!(matches!(error, JournalFlowError::RetryableExecution(_)));
    assert!(matches!(
        status(&directory, OPERATION_ID, &hash('a')).unwrap(),
        Some(JournalCheckpoint::Executing)
    ));
    let (_, applications, effect) = ledger_side_effect(&directory);
    let resumed = run_journaled_operation(
        &directory,
        &operation(OPERATION_ID),
        &hash('a'),
        &snapshot(),
        true,
        &|_| {},
        effect,
    )
    .await
    .expect("the same operation may resume only through its proven owner ledger");
    assert_eq!(resumed.result.outcome, ControlOutcome::Succeeded);
    assert_eq!(applications.load(AtomicOrdering::SeqCst), 1);
    fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
async fn after_side_effect_crash_never_duplicates_the_mutation_and_recovers_the_result() {
    let directory = temporary_directory();
    // Process one: side effect applied (durable in the owner's ledger),
    // crash before the journal result was persisted.
    accept(
        &directory,
        &operation(OPERATION_ID),
        &hash('a'),
        &snapshot(),
    )
    .unwrap();
    begin_execution(&directory, OPERATION_ID, &hash('a'), true).unwrap();
    {
        let (_invocations, applications, effect) = ledger_side_effect(&directory);
        let _ = effect().await.unwrap();
        assert_eq!(applications.load(AtomicOrdering::SeqCst), 1);
    }
    assert_eq!(
        status(&directory, OPERATION_ID, &hash('a'))
            .unwrap()
            .unwrap(),
        JournalCheckpoint::Executing
    );

    // Restart with an idempotent owner: re-invocation deduplicates and the
    // result finally becomes durable.  Applied mutations stay at one in
    // total: this process' invocation observed the ledger marker and
    // applied nothing itself.
    let (invocations, applications, effect) = ledger_side_effect(&directory);
    let outcome = run_journaled_operation(
        &directory,
        &operation(OPERATION_ID),
        &hash('a'),
        &snapshot(),
        true,
        &|_| {},
        effect,
    )
    .await
    .unwrap();
    assert!(!outcome.recovered);
    assert_eq!(invocations.load(AtomicOrdering::SeqCst), 1);
    assert_eq!(applications.load(AtomicOrdering::SeqCst), 0);
    let expected = succeeded_result(OPERATION_ID, &hash('a'));
    assert_eq!(outcome.result.schema, expected.schema);
    assert_eq!(outcome.result.operation_id, expected.operation_id);
    assert_eq!(outcome.result.request_hash, expected.request_hash);
    assert_eq!(outcome.result.outcome, expected.outcome);
    assert_eq!(outcome.result.error, None);
    assert_eq!(outcome.result.accepted_at, expected.accepted_at);
}

#[tokio::test]
async fn result_publication_is_durable_between_the_before_and_after_result_boundaries() {
    let directory = temporary_directory();
    accept(
        &directory,
        &operation(OPERATION_ID),
        &hash('a'),
        &snapshot(),
    )
    .unwrap();

    // At `before-result` the record must still be executing (the result is
    // not durable yet); at `after-result` it must be completed.  A crash in
    // this window therefore leaves the exact `executing` checkpoint covered
    // by the recovery tests above.
    let saw_executing = Arc::new(AtomicUsize::new(0));
    let saw_completed = Arc::new(AtomicUsize::new(0));
    let executing = Arc::clone(&saw_executing);
    let completed = Arc::clone(&saw_completed);
    let probe_directory = directory.clone();
    let (_invocations, _applications, effect) = ledger_side_effect(&directory);
    run_journaled_operation(
        &directory,
        &operation(OPERATION_ID),
        &hash('a'),
        &snapshot(),
        true,
        &move |name: &str| {
            let path = control_journal_directory(&probe_directory)
                .join(format!("{OPERATION_ID}.journal.json"));
            let record: serde_json::Value =
                serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
            let phase = record["phase"].clone();
            if name == "control-journal-before-result" {
                assert_eq!(phase, "executing");
                executing.fetch_add(1, AtomicOrdering::SeqCst);
            }
            if name == "control-journal-after-result" {
                assert_eq!(phase, "completed");
                completed.fetch_add(1, AtomicOrdering::SeqCst);
            }
        },
        effect,
    )
    .await
    .unwrap();
    assert_eq!(saw_executing.load(AtomicOrdering::SeqCst), 1);
    assert_eq!(saw_completed.load(AtomicOrdering::SeqCst), 1);
}

#[tokio::test]
async fn after_result_crash_returns_the_durable_result_without_reexecution() {
    let directory = temporary_directory();
    // Process one completes fully but dies before its stdout reached ctl:
    // accept -> executing -> applied once -> result persisted -> crash.
    accept(
        &directory,
        &operation(OPERATION_ID),
        &hash('a'),
        &snapshot(),
    )
    .unwrap();
    begin_execution(&directory, OPERATION_ID, &hash('a'), true).unwrap();
    let (_invocations, applications, effect) = ledger_side_effect(&directory);
    let _ = effect().await.unwrap();
    complete(&directory, &succeeded_result(OPERATION_ID, &hash('a'))).unwrap();
    assert_eq!(applications.load(AtomicOrdering::SeqCst), 1);

    // Restart: the stored result comes back verbatim and nothing runs.
    let calls: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let recorder = calls.clone();
    let (invocations, applications, effect) = ledger_side_effect(&directory);
    let outcome = run_journaled_operation(
        &directory,
        &operation(OPERATION_ID),
        &hash('a'),
        &snapshot(),
        true,
        &move |name: &str| recorder.lock().unwrap().push(name.to_owned()),
        effect,
    )
    .await
    .unwrap();
    assert!(outcome.recovered);
    assert_eq!(outcome.result, succeeded_result(OPERATION_ID, &hash('a')));
    assert_eq!(
        calls.lock().unwrap().as_slice(),
        ["control-journal-before-accept"]
    );
    assert_eq!(applications.load(AtomicOrdering::SeqCst), 0);
    assert_eq!(invocations.load(AtomicOrdering::SeqCst), 0);
}
#[test]
fn torn_publication_windows_recover_monotonically_or_fail_closed() {
    let directory = temporary_directory();
    let journal = control_journal_directory(&directory);
    fs::create_dir_all(&journal).unwrap();
    let path = journal.join(format!("{OPERATION_ID}.journal.json"));
    let temporary = path.with_extension("journal.json.tmp");
    let accepted = OperationJournalRecord {
        schema: CONTROL_JOURNAL_SCHEMA,
        operation_id: OPERATION_ID.to_owned(),
        request_hash: hash('a'),
        controller_id: CONTROLLER_ID.to_owned(),
        kid: snapshot().kid,
        accepted_at: 1_000,
        phase: "accepted".to_owned(),
        result: None,
    };

    // (a) Crash between the fsynced temporary and the hard-link publication:
    // the next accept finishes the publication and observes its own record.
    fs::write(&temporary, serde_json::to_vec(&accepted).unwrap()).unwrap();
    assert_eq!(
        accept(
            &directory,
            &operation(OPERATION_ID),
            &hash('a'),
            &snapshot()
        )
        .unwrap(),
        AcceptOutcome::Resumed(JournalCheckpoint::Accepted)
    );
    assert!(!temporary.exists());

    // (b) A fully written completed temporary ahead of a published
    // executing record is adopted: the side effect finished, only the
    // rename was lost.
    begin_execution(&directory, OPERATION_ID, &hash('a'), true).unwrap();
    let completed = OperationJournalRecord {
        phase: "completed".to_owned(),
        result: Some(succeeded_result(OPERATION_ID, &hash('a'))),
        ..accepted.clone()
    };
    fs::write(&temporary, serde_json::to_vec(&completed).unwrap()).unwrap();
    assert_eq!(
        status(&directory, OPERATION_ID, &hash('a'))
            .unwrap()
            .unwrap(),
        JournalCheckpoint::Completed(Box::new(succeeded_result(OPERATION_ID, &hash('a'))))
    );
    assert!(!temporary.exists());

    // (c) A stale temporary behind the published record fails closed.
    fs::write(&temporary, serde_json::to_vec(&accepted).unwrap()).unwrap();
    assert!(matches!(
        status(&directory, OPERATION_ID, &hash('a')),
        Err(JournalFlowError::Transport(_))
    ));
    assert!(
        temporary.exists(),
        "stale temporaries are never removed implicitly"
    );
    fs::remove_file(&temporary).unwrap();

    // (d) Garbage temporary bytes fail closed and stay untouched.
    fs::write(&temporary, b"partial").unwrap();
    assert!(matches!(
        status(&directory, OPERATION_ID, &hash('a')),
        Err(JournalFlowError::Transport(_))
    ));
    assert!(temporary.exists());
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn journal_records_fail_closed_on_unknown_fields_schema_drift_and_binding_mismatch() {
    let directory = temporary_directory();
    accept(
        &directory,
        &operation(OPERATION_ID),
        &hash('a'),
        &snapshot(),
    )
    .unwrap();
    complete(&directory, &succeeded_result(OPERATION_ID, &hash('a'))).unwrap();

    let corrupt = |mutate: fn(&mut OperationJournalRecord)| {
        let scratch = temporary_directory();
        let mut record = OperationJournalRecord {
            schema: CONTROL_JOURNAL_SCHEMA,
            operation_id: OPERATION_ID.to_owned(),
            request_hash: hash('a'),
            controller_id: CONTROLLER_ID.to_owned(),
            kid: snapshot().kid,
            accepted_at: 1_000,
            phase: "completed".to_owned(),
            result: Some(succeeded_result(OPERATION_ID, &hash('a'))),
        };
        mutate(&mut record);
        fs::create_dir_all(control_journal_directory(&scratch)).unwrap();
        fs::write(
            control_journal_directory(&scratch).join(format!("{OPERATION_ID}.journal.json")),
            serde_json::to_vec(&record).unwrap(),
        )
        .unwrap();
        let outcome = status(&scratch, OPERATION_ID, &hash('a'));
        fs::remove_dir_all(scratch).unwrap();
        outcome
    };

    assert!(corrupt(|record| record.schema = CONTROL_JOURNAL_SCHEMA + 1).is_err());
    assert!(corrupt(|record| record.phase = "cancelled".to_owned()).is_err());
    assert!(
        corrupt(|record| {
            record.result = None;
        })
        .is_err()
    );
    assert!(
        corrupt(|record| {
            if let Some(result) = record.result.as_mut() {
                result.request_hash = hash('f');
            }
        })
        .is_err()
    );

    // Unknown fields are denied on the storage record itself.
    let scratch = temporary_directory();
    let mut value: serde_json::Value = serde_json::json!({
        "schema": CONTROL_JOURNAL_SCHEMA,
        "operation_id": OPERATION_ID,
        "request_hash": hash('a'),
        "controller_id": CONTROLLER_ID,
        "kid": snapshot().kid,
        "accepted_at": 1_000,
        "phase": "accepted",
        "result": null,
        "evil": 1,
    });
    value["evil"] = serde_json::json!(1);
    fs::create_dir_all(control_journal_directory(&scratch)).unwrap();
    fs::write(
        control_journal_directory(&scratch).join(format!("{OPERATION_ID}.journal.json")),
        serde_json::to_vec(&value).unwrap(),
    )
    .unwrap();
    assert!(matches!(
        status(&scratch, OPERATION_ID, &hash('a')),
        Err(JournalFlowError::Transport(_))
    ));
    fs::remove_dir_all(scratch).unwrap();

    // Completed records whose embedded result is not bound to the accepted
    // snapshot are refused.
    let unbound = |mutate: fn(&mut ControlResult)| {
        let scratch = temporary_directory();
        let mut result = succeeded_result(OPERATION_ID, &hash('a'));
        mutate(&mut result);
        let record = OperationJournalRecord {
            schema: CONTROL_JOURNAL_SCHEMA,
            operation_id: OPERATION_ID.to_owned(),
            request_hash: hash('a'),
            controller_id: CONTROLLER_ID.to_owned(),
            kid: snapshot().kid,
            accepted_at: 1_000,
            phase: "completed".to_owned(),
            result: Some(result),
        };
        fs::create_dir_all(control_journal_directory(&scratch)).unwrap();
        fs::write(
            control_journal_directory(&scratch).join(format!("{OPERATION_ID}.journal.json")),
            serde_json::to_vec(&record).unwrap(),
        )
        .unwrap();
        let outcome = status(&scratch, OPERATION_ID, &hash('a'));
        fs::remove_dir_all(scratch).unwrap();
        outcome
    };
    assert!(unbound(|result| result.accepted_at = 2_000).is_err());
    assert!(unbound(|result| result.operation_id = OPERATION_ID_B.to_owned()).is_err());
}

#[test]
fn retention_deletes_only_terminal_records_past_the_cutoff() {
    let directory = temporary_directory();
    let journal = control_journal_directory(&directory);
    fs::create_dir_all(&journal).unwrap();
    let write_record = |id: &str, phase: &str, completed_at: Option<i64>| {
        let mut result = succeeded_result(id, &hash('a'));
        result.completed_at = completed_at;
        result.accepted_at = 900;
        let record = OperationJournalRecord {
            schema: CONTROL_JOURNAL_SCHEMA,
            operation_id: id.to_owned(),
            request_hash: hash('a'),
            controller_id: CONTROLLER_ID.to_owned(),
            kid: snapshot().kid,
            accepted_at: 900,
            phase: phase.to_owned(),
            result: if phase == "completed" {
                Some(result)
            } else {
                None
            },
        };
        let path = journal.join(format!("{id}.journal.json"));
        fs::write(&path, serde_json::to_vec(&record).unwrap()).unwrap();
        path
    };
    const CUTOFF: i64 = 50_000;
    let terminal_old = write_record(
        "019c8ca2-30a6-7000-8000-0000000000a1",
        "completed",
        Some(CUTOFF - 10),
    );
    let terminal_recent = write_record(
        "019c8ca2-30a6-7000-8000-0000000000a2",
        "completed",
        Some(CUTOFF + 10),
    );
    let executing = write_record("019c8ca2-30a6-7000-8000-0000000000a3", "executing", None);
    let accepted = write_record("019c8ca2-30a6-7000-8000-0000000000a4", "accepted", None);
    let garbage = journal.join("019c8ca2-30a6-7000-8000-0000000000a5.journal.json");
    fs::write(&garbage, b"not-json").unwrap();

    assert_eq!(cleanup_completed_before(&directory, CUTOFF).unwrap(), 1);
    assert!(!terminal_old.exists());
    assert!(terminal_recent.exists());
    assert!(executing.exists());
    assert!(accepted.exists());
    assert!(garbage.exists(), "unreadable records fail safe and stay");

    // Cleanup before any journal exists is a no-op.
    let empty = temporary_directory();
    assert_eq!(cleanup_completed_before(&empty, CUTOFF).unwrap(), 0);
    fs::remove_dir_all(empty).unwrap();
    fs::remove_dir_all(directory).unwrap();
}
#[test]
fn concurrent_offers_have_exactly_one_creator_and_conflicts_are_deterministic() {
    let directory = temporary_directory();
    let directory = Arc::new(directory);
    let creators = Arc::new(AtomicUsize::new(0));
    let threads = (0..16)
        .map(|_| {
            let directory = Arc::clone(&directory);
            let creators = Arc::clone(&creators);
            std::thread::spawn(move || {
                match accept(
                    &directory,
                    &operation(OPERATION_ID),
                    &hash('a'),
                    &snapshot(),
                ) {
                    Ok(AcceptOutcome::Created) => {
                        creators.fetch_add(1, AtomicOrdering::SeqCst);
                    }
                    Ok(AcceptOutcome::Resumed(_)) => {}
                    Err(error) => panic!("same id + same hash must never conflict: {error}"),
                }
            })
        })
        .collect::<Vec<_>>();
    for thread in threads {
        thread.join().unwrap();
    }
    assert_eq!(creators.load(AtomicOrdering::SeqCst), 1);

    // Once accepted, a different hash is deterministically rejected.
    assert!(matches!(
        accept(
            &directory,
            &operation(OPERATION_ID),
            &hash('b'),
            &snapshot()
        ),
        Err(JournalFlowError::OperationIdConflict)
    ));
    fs::remove_dir_all(directory.as_ref()).unwrap();
}

#[tokio::test]
async fn typed_result_data_is_attached_on_success_and_durable_for_recovery() {
    use nazo_operator_protocol::{
        TenantResourceIdentity, TenantResourceKind, canonical_tenant_resource_manifest_sha256,
    };

    let directory = temporary_directory();
    let resources = vec![TenantResourceIdentity {
        kind: TenantResourceKind::User,
        resource_id: "user-1".to_owned(),
        digest: "d".repeat(64),
    }];
    let data = ControlResultData::TenantResourceEnumerate {
        revision: 3,
        resource_manifest_sha256: canonical_tenant_resource_manifest_sha256(&resources).unwrap(),
        resources,
    };
    let outcome = run_journaled_operation(
        &directory,
        &operation(OPERATION_ID),
        &hash('a'),
        &snapshot(),
        true,
        &|_| {},
        || async { Ok(Some(data.clone())) },
    )
    .await
    .unwrap();
    assert_eq!(outcome.result.result, Some(data.clone()));
    match status(&directory, OPERATION_ID, &hash('a'))
        .unwrap()
        .unwrap()
    {
        JournalCheckpoint::Completed(stored) => assert_eq!(stored.result, Some(data)),
        other => panic!("expected completed checkpoint, got {other:?}"),
    }
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn storage_inputs_are_validated_before_touching_the_filesystem() {
    let directory = temporary_directory();

    // Path-traversal identifiers never reach the filesystem.
    let mut traversal = operation("..");
    traversal.operation_id = "..".to_owned();
    assert!(matches!(
        accept(&directory, &traversal, &hash('a'), &snapshot()),
        Err(JournalFlowError::Transport(_))
    ));
    assert!(!control_journal_directory(&directory).exists());

    // Request hashes must be lowercase sha256 hex.
    assert!(matches!(
        status(&directory, OPERATION_ID, "NOT-A-HASH"),
        Err(JournalFlowError::Transport(_))
    ));

    // Snapshot fields are bounded.
    let bad_snapshot = AuthorizationSnapshot {
        controller_id: String::new(),
        kid: snapshot().kid,
        accepted_at: 1_000,
    };
    assert!(matches!(
        accept(
            &directory,
            &operation(OPERATION_ID),
            &hash('a'),
            &bad_snapshot
        ),
        Err(JournalFlowError::Transport(_))
    ));

    // The snapshot controller identity must be the D01 canonical UUIDv7;
    // opaque legacy spellings are refused so journal records always join
    // against the controller registry.
    let legacy_snapshot = AuthorizationSnapshot {
        controller_id: "controller-test".to_owned(),
        kid: snapshot().kid,
        accepted_at: 1_000,
    };
    assert!(matches!(
        accept(
            &directory,
            &operation(OPERATION_ID),
            &hash('a'),
            &legacy_snapshot
        ),
        Err(JournalFlowError::Transport(_))
    ));

    // Acceptance times must be positive.
    let mut zero_time = snapshot();
    zero_time.accepted_at = 0;
    assert!(matches!(
        accept(&directory, &operation(OPERATION_ID), &hash('a'), &zero_time),
        Err(JournalFlowError::Transport(_))
    ));
    fs::remove_dir_all(directory).unwrap();
}
