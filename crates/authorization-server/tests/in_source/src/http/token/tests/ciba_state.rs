use super::*;
use crate::test_support::valkey::valkey_atomic_snapshot;
use crate::test_support::valkey::valkey_eval_string;
use fred::interfaces::ClientLike;
use fred::prelude::{
    Builder as ValkeyBuilder, Client as ValkeyClient, Config as ValkeyConfig, ConnectionConfig,
    PerformanceConfig,
};
use nazo_auth::{
    CibaDecisionEvaluation, CibaPollTransition, evaluate_ciba_decision, evaluate_ciba_poll,
};
use nazo_valkey::AtomicResult as ValkeyAtomicResult;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration as StdDuration;

fn pending_state(now: i64) -> CibaRequestState {
    CibaRequestState {
        client_id: "client-1".to_owned(),
        user_id: Uuid::now_v7(),
        scopes: vec!["openid".to_owned()],
        audiences: vec!["resource://default".to_owned()],
        acr: Some("1".to_owned()),
        binding_message: Some("Read the number".to_owned()),
        issued_at: now,
        status: CibaStatus::Pending,
        interval_seconds: 5,
        expires_at: now + 60,
        retention_expires_at: now + 180,
        last_poll_at: None,
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

#[actix_web::test]
async fn legacy_ciba_state_migrates_from_actual_expiretime() {
    let Some(valkey) = live_valkey().await else {
        return;
    };
    let connection = nazo_valkey::ValkeyConnection::from_existing_client(valkey.clone());
    let auth_req_id = format!("legacy-{}", Uuid::now_v7());
    let key = ciba_request_key(&auth_req_id);
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
    let key = ciba_request_key(&auth_req_id);
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
    let key = ciba_request_key(&auth_req_id);
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
    let occupied_raw = valkey_atomic_snapshot(&valkey, &ciba_request_key(&occupied_id))
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
        valkey_atomic_snapshot(&valkey, &ciba_request_key(&occupied_id))
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
async fn concurrent_approved_consumers_produce_exactly_one_issuance_outcome() {
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
    let missing_count = [&one, &two]
        .into_iter()
        .filter(|result| matches!(result, Err(CibaPollFailure::Missing)))
        .count();
    assert_eq!(approved_count, 1);
    assert_eq!(missing_count, 1);
    assert!(service.load(&auth_req_id).await.unwrap().is_none());
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
async fn consumed_approved_state_is_not_restored_after_downstream_failure() {
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
    assert!(service.load(&auth_req_id).await.unwrap().is_none());
}
