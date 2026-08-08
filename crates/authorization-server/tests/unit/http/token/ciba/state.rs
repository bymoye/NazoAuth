use super::*;
use crate::test_support::valkey::valkey_atomic_snapshot;
use crate::test_support::valkey::valkey_eval_string;
use fred::interfaces::ClientLike;
use fred::prelude::{
    Builder as ValkeyBuilder, Client as ValkeyClient, Config as ValkeyConfig, ConnectionConfig,
    PerformanceConfig,
};
use nazo_auth::{
    CibaAtomicResult, CibaAuthenticationContext, CibaCreateFailure, CibaDecision,
    CibaDecisionEvaluation, CibaDecisionFailure, CibaPollCommit, CibaPollFailure,
    CibaPollTransition, CibaStateFuture, CibaStateStorePort, CibaStoredRequest,
    evaluate_ciba_decision, evaluate_ciba_decision_with_authentication_context, evaluate_ciba_poll,
};
use nazo_valkey::AtomicResult as ValkeyAtomicResult;
use nazo_valkey::test_support::ciba_request_storage_key;
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration as StdDuration;
use tokio::sync::Barrier;

fn pending_state(now: i64) -> CibaRequestState {
    CibaRequestState {
        client_id: "client-1".to_owned(),
        user_id: Uuid::now_v7(),
        scopes: vec!["openid".to_owned()],
        audiences: vec!["resource://default".to_owned()],
        acr: Some("1".to_owned()),
        authentication_context: None,
        binding_message: Some("Read the number".to_owned()),
        issued_at: now,
        status: CibaStatus::Pending,
        interval_seconds: 5,
        expires_at: now + 60,
        retention_expires_at: now + 180,
        last_poll_at: None,
        ping_notification: None,
    }
}

async fn live_valkey() -> Option<ValkeyClient> {
    let valkey_url = std::env::var("VALKEY_URL").ok()?;
    let mut builder =
        ValkeyBuilder::from_config(ValkeyConfig::from_url(&valkey_url).expect("VALKEY_URL"));
    builder.with_performance_config(|performance: &mut PerformanceConfig| {
        performance.default_command_timeout = StdDuration::from_secs(1);
    });
    builder.with_connection_config(|connection: &mut ConnectionConfig| {
        connection.connection_timeout = StdDuration::from_secs(1);
        connection.internal_command_timeout = StdDuration::from_secs(1);
        connection.max_command_attempts = 1;
    });
    let valkey = builder.build().expect("Valkey client should build");
    valkey.init().await.expect("Valkey should connect");
    Some(valkey)
}

async fn valkey_server_time(valkey: &ValkeyClient) -> i64 {
    valkey_eval_string(
        valkey,
        "return tostring(redis.call('TIME')[1])",
        Vec::new(),
        Vec::new(),
    )
    .await
    .expect("Valkey TIME should be readable")
    .parse()
    .expect("Valkey TIME should be an integer")
}

async fn stage_at_deadline(valkey: &ValkeyClient, key: &str, raw: &str, deadline: i64) {
    let reply = valkey_eval_string(
        valkey,
        "redis.call('SET', KEYS[1], ARGV[1]); redis.call('EXPIREAT', KEYS[1], ARGV[2]); return tostring(redis.call('EXPIRETIME', KEYS[1]))",
        vec![key.to_owned()],
        vec![raw.to_owned(), deadline.to_string()],
    )
    .await
    .expect("state should be staged");
    assert_eq!(reply.parse::<i64>().unwrap(), deadline);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CibaStoreCall {
    Create(Option<i64>),
    Replace(Option<i64>),
    Delete(Option<i64>),
}

#[derive(Clone)]
struct RecordedCibaRequest {
    state: CibaRequestState,
    version: u64,
}

/// A deterministic state-store double for protocol tests that must not depend
/// on a live Valkey server.  Its version check models the compare-and-set
/// linearization point, while the outcome queue can inject a lease expiry or
/// one stale-version conflict at that point.
#[derive(Clone)]
struct RecordingCibaStore {
    requests: Arc<Mutex<HashMap<String, RecordedCibaRequest>>>,
    calls: Arc<Mutex<Vec<CibaStoreCall>>>,
    outcomes: Arc<Mutex<VecDeque<CibaAtomicResult>>>,
    yield_before_load: bool,
    load_barrier: Option<Arc<Barrier>>,
    barrier_loads: Arc<AtomicUsize>,
}

impl RecordingCibaStore {
    fn new(yield_before_load: bool) -> Self {
        Self {
            requests: Arc::new(Mutex::new(HashMap::new())),
            calls: Arc::new(Mutex::new(Vec::new())),
            outcomes: Arc::new(Mutex::new(VecDeque::new())),
            yield_before_load,
            load_barrier: None,
            barrier_loads: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn with_load_barrier() -> Self {
        Self {
            load_barrier: Some(Arc::new(Barrier::new(2))),
            ..Self::new(false)
        }
    }

    fn seed(&self, auth_req_id: &str, state: CibaRequestState) {
        self.requests.lock().unwrap().insert(
            auth_req_id.to_owned(),
            RecordedCibaRequest { state, version: 0 },
        );
    }

    fn push_outcome(&self, outcome: CibaAtomicResult) {
        self.outcomes.lock().unwrap().push_back(outcome);
    }

    fn calls(&self) -> Vec<CibaStoreCall> {
        self.calls.lock().unwrap().clone()
    }
}

impl CibaStateStorePort for RecordingCibaStore {
    type Version = u64;

    fn load<'a>(
        &'a self,
        auth_req_id: &'a str,
    ) -> CibaStateFuture<'a, Option<CibaStoredRequest<Self::Version>>> {
        let requests = Arc::clone(&self.requests);
        let auth_req_id = auth_req_id.to_owned();
        let yield_before_load = self.yield_before_load;
        let load_barrier = self.load_barrier.clone();
        let barrier_loads = Arc::clone(&self.barrier_loads);
        Box::pin(async move {
            if yield_before_load {
                tokio::task::yield_now().await;
            }
            let participates_in_barrier =
                load_barrier.is_some() && barrier_loads.fetch_add(1, Ordering::SeqCst) < 2;
            if participates_in_barrier {
                let load_barrier = load_barrier.as_ref().expect("barrier is configured");
                load_barrier.wait().await;
            }
            let stored = requests
                .lock()
                .unwrap()
                .get(&auth_req_id)
                .map(|stored| CibaStoredRequest::new(stored.state.clone(), stored.version));
            if participates_in_barrier {
                let load_barrier = load_barrier.as_ref().expect("barrier is configured");
                load_barrier.wait().await;
            }
            Ok(stored)
        })
    }

    fn create<'a>(
        &'a self,
        auth_req_id: &'a str,
        state: &'a CibaRequestState,
    ) -> CibaStateFuture<'a, CibaAtomicResult> {
        self.create_with_lease_deadline(auth_req_id, state, None)
    }

    fn create_with_lease_deadline<'a>(
        &'a self,
        auth_req_id: &'a str,
        state: &'a CibaRequestState,
        lease_expires_at: Option<i64>,
    ) -> CibaStateFuture<'a, CibaAtomicResult> {
        let requests = Arc::clone(&self.requests);
        let calls = Arc::clone(&self.calls);
        let outcomes = Arc::clone(&self.outcomes);
        let auth_req_id = auth_req_id.to_owned();
        let state = state.clone();
        Box::pin(async move {
            calls
                .lock()
                .unwrap()
                .push(CibaStoreCall::Create(lease_expires_at));
            let outcome = outcomes
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(CibaAtomicResult::Applied);
            if outcome != CibaAtomicResult::Applied {
                return Ok(outcome);
            }
            let mut requests = requests.lock().unwrap();
            if requests.contains_key(&auth_req_id) {
                return Ok(CibaAtomicResult::Conflict);
            }
            requests.insert(auth_req_id, RecordedCibaRequest { state, version: 0 });
            Ok(CibaAtomicResult::Applied)
        })
    }

    fn replace<'a>(
        &'a self,
        auth_req_id: &'a str,
        version: &'a Self::Version,
        state: &'a CibaRequestState,
    ) -> CibaStateFuture<'a, CibaAtomicResult> {
        self.replace_with_lease_deadline(auth_req_id, version, state, None)
    }

    fn replace_with_lease_deadline<'a>(
        &'a self,
        auth_req_id: &'a str,
        version: &'a Self::Version,
        state: &'a CibaRequestState,
        lease_expires_at: Option<i64>,
    ) -> CibaStateFuture<'a, CibaAtomicResult> {
        let requests = Arc::clone(&self.requests);
        let calls = Arc::clone(&self.calls);
        let outcomes = Arc::clone(&self.outcomes);
        let auth_req_id = auth_req_id.to_owned();
        let expected_version = *version;
        let state = state.clone();
        Box::pin(async move {
            calls
                .lock()
                .unwrap()
                .push(CibaStoreCall::Replace(lease_expires_at));
            let mut requests = requests.lock().unwrap();
            let Some(stored) = requests.get_mut(&auth_req_id) else {
                return Ok(CibaAtomicResult::Conflict);
            };
            if stored.version != expected_version {
                return Ok(CibaAtomicResult::Conflict);
            }
            let outcome = outcomes
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(CibaAtomicResult::Applied);
            if outcome != CibaAtomicResult::Applied {
                return Ok(outcome);
            }
            stored.state = state;
            stored.version = stored.version.saturating_add(1);
            Ok(CibaAtomicResult::Applied)
        })
    }

    fn delete<'a>(
        &'a self,
        auth_req_id: &'a str,
        version: &'a Self::Version,
    ) -> CibaStateFuture<'a, CibaAtomicResult> {
        self.delete_with_lease_deadline(auth_req_id, version, None)
    }

    fn delete_with_lease_deadline<'a>(
        &'a self,
        auth_req_id: &'a str,
        version: &'a Self::Version,
        lease_expires_at: Option<i64>,
    ) -> CibaStateFuture<'a, CibaAtomicResult> {
        let requests = Arc::clone(&self.requests);
        let calls = Arc::clone(&self.calls);
        let outcomes = Arc::clone(&self.outcomes);
        let auth_req_id = auth_req_id.to_owned();
        let expected_version = *version;
        Box::pin(async move {
            calls
                .lock()
                .unwrap()
                .push(CibaStoreCall::Delete(lease_expires_at));
            let mut requests = requests.lock().unwrap();
            let Some(stored) = requests.get(&auth_req_id) else {
                return Ok(CibaAtomicResult::Conflict);
            };
            if stored.version != expected_version {
                return Ok(CibaAtomicResult::Conflict);
            }
            let outcome = outcomes
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(CibaAtomicResult::Applied);
            if outcome != CibaAtomicResult::Applied {
                return Ok(outcome);
            }
            requests.remove(&auth_req_id);
            Ok(CibaAtomicResult::Applied)
        })
    }
}

#[test]
fn ciba_poll_transition_preserves_absolute_deadlines() {
    let state = pending_state(1_000);
    let CibaPollTransition::AuthorizationPending(next) = evaluate_ciba_poll(&state, 1_001) else {
        panic!("first pending poll must commit authorization_pending")
    };

    assert_eq!(next.expires_at, state.expires_at);
    assert_eq!(next.retention_expires_at, state.retention_expires_at);
    assert_eq!(next.last_poll_at, Some(1_001));
}

#[test]
fn every_committed_premature_poll_adds_exactly_five_seconds() {
    let mut state = pending_state(1_000);
    state.last_poll_at = Some(1_000);

    for expected in [10, 15, 20] {
        let CibaPollTransition::SlowDown(next) = evaluate_ciba_poll(&state, 1_001) else {
            panic!("premature poll must commit slow_down")
        };
        assert_eq!(next.interval_seconds, expected);
        assert_eq!(next.expires_at, 1_060);
        assert_eq!(next.retention_expires_at, 1_180);
        state = next;
    }
}

#[test]
fn ciba_poll_selects_terminal_states_before_protocol_success() {
    let mut state = pending_state(1_000);
    assert!(matches!(
        evaluate_ciba_poll(&state, state.expires_at),
        CibaPollTransition::Expired
    ));

    state.status = CibaStatus::Approved;
    assert!(matches!(
        evaluate_ciba_poll(&state, 1_001),
        CibaPollTransition::Approved
    ));

    state.status = CibaStatus::Denied;
    assert!(matches!(
        evaluate_ciba_poll(&state, 1_001),
        CibaPollTransition::Denied
    ));
}

#[test]
fn ciba_decision_rejects_mismatch_terminal_and_expired_states() {
    let state = pending_state(1_000);
    assert!(matches!(
        evaluate_ciba_decision(&state, Some(Uuid::now_v7()), CibaDecision::Approve, 1_001),
        CibaDecisionEvaluation::UserMismatch
    ));

    let mut terminal = state.clone();
    terminal.status = CibaStatus::Approved;
    assert!(matches!(
        evaluate_ciba_decision(&terminal, Some(terminal.user_id), CibaDecision::Deny, 1_001),
        CibaDecisionEvaluation::AlreadyHandled
    ));

    assert!(matches!(
        evaluate_ciba_decision(
            &state,
            Some(state.user_id),
            CibaDecision::Approve,
            state.expires_at
        ),
        CibaDecisionEvaluation::Expired
    ));
}

#[test]
fn ciba_decision_changes_only_status() {
    let state = pending_state(1_000);
    let CibaDecisionEvaluation::Commit(next) =
        evaluate_ciba_decision(&state, Some(state.user_id), CibaDecision::Approve, 1_001)
    else {
        panic!("valid decision should produce a terminal replacement")
    };

    assert_eq!(next.status, CibaStatus::Approved);
    assert_eq!(next.expires_at, state.expires_at);
    assert_eq!(next.retention_expires_at, state.retention_expires_at);
    assert_eq!(next.interval_seconds, state.interval_seconds);
    assert_eq!(next.last_poll_at, state.last_poll_at);
}

#[test]
fn approved_ciba_state_preserves_the_authenticated_session_context() {
    let state = pending_state(1_000);
    let context = CibaAuthenticationContext {
        auth_time: 900,
        amr: vec!["pwd".to_owned(), "otp".to_owned()],
        oidc_sid: Some("sid-1".to_owned()),
    };
    let CibaDecisionEvaluation::Commit(next) = evaluate_ciba_decision_with_authentication_context(
        &state,
        Some(state.user_id),
        CibaDecision::Approve,
        Some(context.clone()),
        1_001,
    ) else {
        panic!("valid decision should produce a terminal replacement")
    };

    assert_eq!(next.authentication_context, Some(context));
}

#[actix_web::test]
async fn ciba_creation_passes_lease_deadline_to_atomic_store() {
    let store = RecordingCibaStore::new(false);
    store.push_outcome(CibaAtomicResult::DeadlineElapsed);
    let state = pending_state(1_000);
    let service = CibaService::new(store.clone());

    let result = service
        .create_unique_with_lease_deadline(&state, Some(900), || "lease-bound".to_owned())
        .await;

    assert_eq!(result, Err(CibaCreateFailure::DeadlineElapsed));
    assert_eq!(store.calls(), vec![CibaStoreCall::Create(Some(900))]);
    assert!(service.load("lease-bound").await.unwrap().is_none());
}

#[actix_web::test]
async fn ciba_decision_lease_expiry_blocks_cas_without_mutating_pending_state() {
    let store = RecordingCibaStore::new(false);
    let state = pending_state(1_000);
    let auth_req_id = "lease-decision-expired";
    store.seed(auth_req_id, state.clone());
    store.push_outcome(CibaAtomicResult::DeadlineElapsed);
    let service = CibaService::new(store.clone());

    let result = service
        .decide_with_authentication_context_and_lease_deadline(
            auth_req_id,
            CibaDecision::Approve,
            Some(state.user_id),
            None,
            Some(900),
            || 1_001,
        )
        .await;

    assert_eq!(result, Err(CibaDecisionFailure::Expired));
    assert_eq!(store.calls(), vec![CibaStoreCall::Replace(Some(900))]);
    assert_eq!(
        service.load(auth_req_id).await.unwrap().unwrap().state(),
        &state
    );
}

#[actix_web::test]
async fn expired_ciba_decision_uses_lease_guarded_cleanup_delete() {
    let store = RecordingCibaStore::new(false);
    let mut state = pending_state(1_000);
    state.expires_at = 1_000;
    state.retention_expires_at = 1_200;
    let auth_req_id = "lease-decision-cleanup";
    store.seed(auth_req_id, state.clone());
    store.push_outcome(CibaAtomicResult::DeadlineElapsed);
    let service = CibaService::new(store.clone());

    let result = service
        .decide_with_authentication_context_and_lease_deadline(
            auth_req_id,
            CibaDecision::Approve,
            Some(state.user_id),
            None,
            Some(900),
            || 1_001,
        )
        .await;

    assert_eq!(result, Err(CibaDecisionFailure::Expired));
    assert_eq!(store.calls(), vec![CibaStoreCall::Delete(Some(900))]);
    assert_eq!(
        service.load(auth_req_id).await.unwrap().unwrap().state(),
        &state
    );
}

#[actix_web::test]
async fn ciba_poll_lease_expiry_returns_expired_without_advancing_poll_state() {
    let store = RecordingCibaStore::new(false);
    let state = pending_state(1_000);
    let auth_req_id = "lease-poll-expired";
    store.seed(auth_req_id, state.clone());
    let initial = CibaService::new(store.clone())
        .load(auth_req_id)
        .await
        .unwrap()
        .unwrap();
    store.push_outcome(CibaAtomicResult::DeadlineElapsed);
    let service = CibaService::new(store.clone());

    let result = service
        .poll_with_lease_deadline(auth_req_id, &state.client_id, initial, Some(900), || 1_001)
        .await;

    assert_eq!(result, Ok(CibaPollCommit::Expired));
    assert_eq!(store.calls(), vec![CibaStoreCall::Replace(Some(900))]);
    assert_eq!(
        service.load(auth_req_id).await.unwrap().unwrap().state(),
        &state
    );
}

#[actix_web::test]
async fn approved_ciba_poll_lease_expiry_does_not_consume_terminal_state() {
    let store = RecordingCibaStore::new(false);
    let mut state = pending_state(1_000);
    state.status = CibaStatus::Approved;
    let auth_req_id = "lease-poll-terminal-expired";
    store.seed(auth_req_id, state.clone());
    let initial = CibaService::new(store.clone())
        .load(auth_req_id)
        .await
        .unwrap()
        .unwrap();
    store.push_outcome(CibaAtomicResult::DeadlineElapsed);
    let service = CibaService::new(store.clone());

    let result = service
        .poll_with_lease_deadline(auth_req_id, &state.client_id, initial, Some(900), || 1_001)
        .await;

    assert!(matches!(result, Ok(CibaPollCommit::Approved(_))));
    assert!(store.calls().is_empty());
    assert_eq!(
        service.load(auth_req_id).await.unwrap().unwrap().state(),
        &state
    );
}

#[actix_web::test]
async fn concurrent_ciba_decisions_retry_stale_cas_and_commit_one_terminal_state() {
    let store = RecordingCibaStore::with_load_barrier();
    let state = pending_state(1_000);
    let auth_req_id = "decision-lease-race";
    store.seed(auth_req_id, state.clone());
    let service = CibaService::new(store.clone());

    let (approve, deny) = tokio::join!(
        service.decide_with_authentication_context_and_lease_deadline(
            auth_req_id,
            CibaDecision::Approve,
            Some(state.user_id),
            None,
            Some(2_000),
            || 1_001,
        ),
        service.decide_with_authentication_context_and_lease_deadline(
            auth_req_id,
            CibaDecision::Deny,
            Some(state.user_id),
            None,
            Some(2_000),
            || 1_001,
        ),
    );

    assert_eq!(usize::from(approve.is_ok()) + usize::from(deny.is_ok()), 1);
    assert_eq!(
        [&approve, &deny]
            .into_iter()
            .filter(|result| matches!(result, Err(CibaDecisionFailure::AlreadyHandled)))
            .count(),
        1
    );
    let replace_calls = store
        .calls()
        .into_iter()
        .filter_map(|call| match call {
            CibaStoreCall::Replace(deadline) => Some(deadline),
            CibaStoreCall::Create(_) | CibaStoreCall::Delete(_) => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(replace_calls, vec![Some(2_000), Some(2_000)]);
    let stored = service.load(auth_req_id).await.unwrap().unwrap();
    assert!(matches!(
        stored.state().status,
        CibaStatus::Approved | CibaStatus::Denied
    ));
}

#[actix_web::test]
async fn ciba_poll_client_mismatch_rejects_before_lease_cas() {
    let store = RecordingCibaStore::new(false);
    let state = pending_state(1_000);
    let auth_req_id = "poll-client-mismatch";
    store.seed(auth_req_id, state.clone());
    let initial = CibaService::new(store.clone())
        .load(auth_req_id)
        .await
        .unwrap()
        .unwrap();
    let service = CibaService::new(store.clone());

    let result = service
        .poll_with_lease_deadline(
            auth_req_id,
            "different-client",
            initial,
            Some(2_000),
            || 1_001,
        )
        .await;

    assert_eq!(result, Err(CibaPollFailure::ClientMismatch));
    assert!(store.calls().is_empty());
    assert_eq!(
        service.load(auth_req_id).await.unwrap().unwrap().state(),
        &state
    );
}

#[actix_web::test]
async fn legacy_ciba_state_migrates_from_actual_expiretime() {
    let Some(valkey) = live_valkey().await else {
        return;
    };
    let connection = nazo_valkey::ValkeyConnection::from_existing_client(valkey.clone());
    let auth_req_id = format!("legacy-{}", Uuid::now_v7());
    let key = ciba_request_storage_key(&auth_req_id);
    let now = valkey_server_time(&valkey).await;
    let deadline = now + 180;
    let raw = serde_json::json!({
        "client_id": "client-1",
        "user_id": Uuid::now_v7(),
        "scopes": ["openid"],
        "audiences": ["resource://default"],
        "issued_at": now,
        "status": "pending",
        "interval_seconds": 5,
        "expires_at": now + 60,
        "last_poll_at": null
    })
    .to_string();
    stage_at_deadline(&valkey, &key, &raw, deadline).await;

    let stored = CibaStore::new(&connection)
        .load(&auth_req_id)
        .await
        .unwrap()
        .unwrap();

    assert_eq!(stored.value().retention_expires_at, deadline);
    let snapshot = valkey_atomic_snapshot(&valkey, &key)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(snapshot.raw, raw);
    assert!(!snapshot.raw.contains("retention_expires_at"));
}

#[actix_web::test]
async fn ciba_state_rejects_deadline_that_disagrees_with_expiretime() {
    let Some(valkey) = live_valkey().await else {
        return;
    };
    let connection = nazo_valkey::ValkeyConnection::from_existing_client(valkey.clone());
    let auth_req_id = format!("mismatch-{}", Uuid::now_v7());
    let key = ciba_request_storage_key(&auth_req_id);
    let now = valkey_server_time(&valkey).await;
    let deadline = now + 180;
    let mut state = pending_state(now);
    state.retention_expires_at = deadline - 1;
    stage_at_deadline(
        &valkey,
        &key,
        &serde_json::to_string(&state).unwrap(),
        deadline,
    )
    .await;

    let error = CibaService::new(CibaStore::new(&connection))
        .load(&auth_req_id)
        .await
        .expect_err("mismatched deadline must fail closed");

    assert_eq!(error, CibaStatePortError::CorruptData);
}

#[actix_web::test]
async fn ciba_compare_set_persists_legacy_deadline_without_refreshing_it() {
    let Some(valkey) = live_valkey().await else {
        return;
    };
    let connection = nazo_valkey::ValkeyConnection::from_existing_client(valkey.clone());
    let auth_req_id = format!("replace-{}", Uuid::now_v7());
    let key = ciba_request_storage_key(&auth_req_id);
    let now = valkey_server_time(&valkey).await;
    let state = pending_state(now);

    assert_eq!(
        CibaStore::new(&connection)
            .create(&auth_req_id, &state)
            .await
            .unwrap(),
        ValkeyAtomicResult::Applied
    );
    let stored = CibaStore::new(&connection)
        .load(&auth_req_id)
        .await
        .unwrap()
        .unwrap();
    let CibaPollTransition::AuthorizationPending(next) =
        evaluate_ciba_poll(stored.value(), now + 1)
    else {
        panic!("poll should remain pending")
    };

    assert_eq!(
        CibaStore::new(&connection)
            .replace(&auth_req_id, &stored, &next)
            .await
            .unwrap(),
        ValkeyAtomicResult::Applied
    );
    let snapshot = valkey_atomic_snapshot(&valkey, &key)
        .await
        .unwrap()
        .unwrap();
    let replaced: CibaRequestState = serde_json::from_str(&snapshot.raw).unwrap();
    assert_eq!(snapshot.expire_at, state.retention_expires_at);
    assert_eq!(replaced.expires_at, state.expires_at);
    assert_eq!(replaced.retention_expires_at, state.retention_expires_at);
}

#[actix_web::test]
async fn ciba_creation_retries_collision_without_overwriting_existing_state() {
    let Some(valkey) = live_valkey().await else {
        return;
    };
    let connection = nazo_valkey::ValkeyConnection::from_existing_client(valkey.clone());
    let now = valkey_server_time(&valkey).await;
    let state = pending_state(now);
    let occupied_id = format!("occupied-{}", Uuid::now_v7());
    let created_id = format!("created-{}", Uuid::now_v7());
    let mut occupied = state.clone();
    occupied.client_id = "existing-client".to_owned();
    assert_eq!(
        CibaStore::new(&connection)
            .create(&occupied_id, &occupied)
            .await
            .unwrap(),
        ValkeyAtomicResult::Applied
    );
    let occupied_raw = valkey_atomic_snapshot(&valkey, &ciba_request_storage_key(&occupied_id))
        .await
        .unwrap()
        .unwrap()
        .raw;
    let mut candidates = VecDeque::from([occupied_id.clone(), created_id.clone()]);

    let actual = CibaService::new(CibaStore::new(&connection))
        .create_unique(&state, || {
            candidates.pop_front().expect("candidate should exist")
        })
        .await
        .unwrap();

    assert_eq!(actual, created_id);
    assert_eq!(
        valkey_atomic_snapshot(&valkey, &ciba_request_storage_key(&occupied_id))
            .await
            .unwrap()
            .unwrap()
            .raw,
        occupied_raw
    );
    assert_eq!(
        CibaService::new(CibaStore::new(&connection))
            .load(&actual)
            .await
            .unwrap()
            .unwrap()
            .state(),
        &state
    );
}

#[actix_web::test]
async fn ciba_creation_stops_after_four_collisions() {
    let Some(valkey) = live_valkey().await else {
        return;
    };
    let connection = nazo_valkey::ValkeyConnection::from_existing_client(valkey.clone());
    let now = valkey_server_time(&valkey).await;
    let state = pending_state(now);
    let ids = (0..4)
        .map(|index| format!("collision-{index}-{}", Uuid::now_v7()))
        .collect::<Vec<_>>();
    for auth_req_id in &ids {
        assert_eq!(
            CibaStore::new(&connection)
                .create(auth_req_id, &state)
                .await
                .unwrap(),
            ValkeyAtomicResult::Applied
        );
    }
    let mut candidates = VecDeque::from(ids);

    let error = CibaService::new(CibaStore::new(&connection))
        .create_unique(&state, || {
            candidates.pop_front().expect("candidate should exist")
        })
        .await
        .expect_err("four collisions must fail closed");

    assert!(matches!(error, CibaCreateFailure::CollisionLimit));
}

#[actix_web::test]
async fn concurrent_ciba_decisions_commit_exactly_one_terminal_state() {
    let Some(valkey) = live_valkey().await else {
        return;
    };
    let connection = nazo_valkey::ValkeyConnection::from_existing_client(valkey.clone());
    let now = valkey_server_time(&valkey).await;
    let state = pending_state(now);
    let auth_req_id = format!("decision-race-{}", Uuid::now_v7());
    CibaStore::new(&connection)
        .create(&auth_req_id, &state)
        .await
        .unwrap();

    let service = CibaService::new(CibaStore::new(&connection));
    let (approve, deny) = tokio::join!(
        service.decide(
            &auth_req_id,
            CibaDecision::Approve,
            Some(state.user_id),
            || now
        ),
        service.decide(
            &auth_req_id,
            CibaDecision::Deny,
            Some(state.user_id),
            || now
        )
    );

    assert_eq!(usize::from(approve.is_ok()) + usize::from(deny.is_ok()), 1);
    assert!(matches!(
        approve.as_ref().err().or_else(|| deny.as_ref().err()),
        Some(CibaDecisionFailure::AlreadyHandled)
    ));
    let stored = service.load(&auth_req_id).await.unwrap().unwrap();
    assert!(matches!(
        stored.state().status,
        CibaStatus::Approved | CibaStatus::Denied
    ));
}

#[actix_web::test]
async fn ciba_decision_rejects_user_mismatch_without_mutation() {
    let Some(valkey) = live_valkey().await else {
        return;
    };
    let connection = nazo_valkey::ValkeyConnection::from_existing_client(valkey.clone());
    let now = valkey_server_time(&valkey).await;
    let state = pending_state(now);
    let auth_req_id = format!("decision-user-{}", Uuid::now_v7());
    CibaStore::new(&connection)
        .create(&auth_req_id, &state)
        .await
        .unwrap();

    let service = CibaService::new(CibaStore::new(&connection));
    let result = service
        .decide(
            &auth_req_id,
            CibaDecision::Approve,
            Some(Uuid::now_v7()),
            || now,
        )
        .await;

    assert!(matches!(result, Err(CibaDecisionFailure::UserMismatch)));
    assert_eq!(
        service.load(&auth_req_id).await.unwrap().unwrap().state(),
        &state
    );
}

#[actix_web::test]
async fn expired_ciba_decision_consumes_state_without_success_outcome() {
    let Some(valkey) = live_valkey().await else {
        return;
    };
    let connection = nazo_valkey::ValkeyConnection::from_existing_client(valkey.clone());
    let now = valkey_server_time(&valkey).await;
    let mut state = pending_state(now);
    state.expires_at = now - 1;
    state.retention_expires_at = now + 60;
    let auth_req_id = format!("decision-expired-{}", Uuid::now_v7());
    CibaStore::new(&connection)
        .create(&auth_req_id, &state)
        .await
        .unwrap();

    let service = CibaService::new(CibaStore::new(&connection));
    let result = service
        .decide(
            &auth_req_id,
            CibaDecision::Approve,
            Some(state.user_id),
            || now,
        )
        .await;

    assert!(matches!(result, Err(CibaDecisionFailure::Expired)));
    assert!(service.load(&auth_req_id).await.unwrap().is_none());
}

#[actix_web::test]
async fn three_concurrent_premature_polls_each_add_exactly_five_seconds() {
    let Some(valkey) = live_valkey().await else {
        return;
    };
    let connection = nazo_valkey::ValkeyConnection::from_existing_client(valkey.clone());
    let now = valkey_server_time(&valkey).await;
    let mut state = pending_state(now);
    state.last_poll_at = Some(now);
    let auth_req_id = format!("poll-slow-down-{}", Uuid::now_v7());
    CibaStore::new(&connection)
        .create(&auth_req_id, &state)
        .await
        .unwrap();
    let service = CibaService::new(CibaStore::new(&connection));
    let first = service.load(&auth_req_id).await.unwrap().unwrap();
    let second = service.load(&auth_req_id).await.unwrap().unwrap();
    let third = service.load(&auth_req_id).await.unwrap().unwrap();

    let (one, two, three) = tokio::join!(
        service.poll(&auth_req_id, &state.client_id, first, || now),
        service.poll(&auth_req_id, &state.client_id, second, || now),
        service.poll(&auth_req_id, &state.client_id, third, || now)
    );

    for result in [one, two, three] {
        assert!(matches!(result, Ok(CibaPollCommit::SlowDown)));
    }
    let stored = service.load(&auth_req_id).await.unwrap().unwrap();
    assert_eq!(stored.state().interval_seconds, state.interval_seconds + 15);
    assert_eq!(stored.state().expires_at, state.expires_at);
    assert_eq!(
        stored.state().retention_expires_at,
        state.retention_expires_at
    );
}

#[actix_web::test]
async fn concurrent_approved_polls_preserve_retryable_state() {
    let Some(valkey) = live_valkey().await else {
        return;
    };
    let connection = nazo_valkey::ValkeyConnection::from_existing_client(valkey.clone());
    let now = valkey_server_time(&valkey).await;
    let mut state = pending_state(now);
    state.status = CibaStatus::Approved;
    let auth_req_id = format!("poll-approved-{}", Uuid::now_v7());
    CibaStore::new(&connection)
        .create(&auth_req_id, &state)
        .await
        .unwrap();
    let service = CibaService::new(CibaStore::new(&connection));
    let first = service.load(&auth_req_id).await.unwrap().unwrap();
    let second = service.load(&auth_req_id).await.unwrap().unwrap();

    let (one, two) = tokio::join!(
        service.poll(&auth_req_id, &state.client_id, first, || now),
        service.poll(&auth_req_id, &state.client_id, second, || now)
    );

    let approved_count = [&one, &two]
        .into_iter()
        .filter(|result| matches!(result, Ok(CibaPollCommit::Approved(_))))
        .count();
    assert_eq!(approved_count, 2);
    assert!(service.load(&auth_req_id).await.unwrap().is_some());
}

#[actix_web::test]
async fn ciba_poll_conflict_retry_consumes_assertion_once() {
    let Some(valkey) = live_valkey().await else {
        return;
    };
    let connection = nazo_valkey::ValkeyConnection::from_existing_client(valkey.clone());
    let now = valkey_server_time(&valkey).await;
    let state = pending_state(now);
    let auth_req_id = format!("poll-assertion-{}", Uuid::now_v7());
    CibaStore::new(&connection)
        .create(&auth_req_id, &state)
        .await
        .unwrap();
    let service = CibaService::new(CibaStore::new(&connection));
    let initial = service.load(&auth_req_id).await.unwrap().unwrap();
    let assertion_calls = AtomicUsize::new(0);
    assertion_calls.fetch_add(1, Ordering::SeqCst);
    let winner_version = CibaStore::new(&connection)
        .load(&auth_req_id)
        .await
        .unwrap()
        .unwrap();
    let mut winner = winner_version.value().clone();
    winner.interval_seconds = 6;
    assert_eq!(
        CibaStore::new(&connection)
            .replace(&auth_req_id, &winner_version, &winner)
            .await
            .unwrap(),
        ValkeyAtomicResult::Applied
    );

    let result = service
        .poll(&auth_req_id, &state.client_id, initial, || now + 1)
        .await;

    assert!(matches!(result, Ok(CibaPollCommit::AuthorizationPending)));
    assert_eq!(assertion_calls.load(Ordering::SeqCst), 1);
}

#[actix_web::test]
async fn approved_state_survives_downstream_failure_for_retry() {
    let Some(valkey) = live_valkey().await else {
        return;
    };
    let connection = nazo_valkey::ValkeyConnection::from_existing_client(valkey.clone());
    let now = valkey_server_time(&valkey).await;
    let mut state = pending_state(now);
    state.status = CibaStatus::Approved;
    let auth_req_id = format!("poll-downstream-{}", Uuid::now_v7());
    CibaStore::new(&connection)
        .create(&auth_req_id, &state)
        .await
        .unwrap();
    let service = CibaService::new(CibaStore::new(&connection));
    let initial = service.load(&auth_req_id).await.unwrap().unwrap();

    let committed = service
        .poll(&auth_req_id, &state.client_id, initial, || now)
        .await
        .unwrap();
    assert!(matches!(committed, CibaPollCommit::Approved(_)));
    let downstream_result: Result<(), &str> = Err("deliberate issuance failure");
    assert!(downstream_result.is_err());
    assert_eq!(
        service.load(&auth_req_id).await.unwrap().unwrap().state(),
        &state
    );
}
