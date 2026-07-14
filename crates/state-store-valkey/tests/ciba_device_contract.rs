use std::time::Duration;

use chrono::{TimeZone, Utc};
use fred::interfaces::{ClientLike, KeysInterface};
use fred::prelude::{Builder, Config};
use nazo_auth::{
    CibaPollCommit, CibaRequestState, CibaService, CibaStatus, DeviceAuthorizationApproval,
    DeviceAuthorizationPayload, DeviceAuthorizationState, DeviceDecisionFailure,
    DeviceGrantService, DevicePollCommit, DevicePollFailure,
};
use nazo_valkey::{AtomicResult, CibaStore, DeviceCreateResult, DeviceStore, ValkeyConnection};
use serde_json::json;

async fn setup() -> Option<(ValkeyConnection, fred::prelude::Client)> {
    let url = std::env::var("VALKEY_URL").ok()?;
    let connection = ValkeyConnection::connect(&url, Duration::from_secs(1))
        .await
        .unwrap();
    let inspector = Builder::from_config(Config::from_url(&url).unwrap())
        .build()
        .unwrap();
    inspector
        .init()
        .await
        .expect("explicit Valkey must be available");
    Some((connection, inspector))
}

async fn server_time(client: &fred::prelude::Client) -> i64 {
    use fred::interfaces::LuaInterface;
    client
        .eval::<String, _, _, _>(
            "return tostring(redis.call('TIME')[1])",
            Vec::<String>::new(),
            Vec::<String>::new(),
        )
        .await
        .unwrap()
        .parse()
        .unwrap()
}

#[tokio::test]
async fn ciba_cas_preserves_exact_key_payload_deadline_and_single_winner() {
    let Some((connection, inspector)) = setup().await else {
        return;
    };
    let store = CibaStore::new(&connection);
    let auth_req_id = format!("ciba-{}", uuid::Uuid::now_v7());
    let key = format!(
        "oauth:ciba:{}",
        blake3::hash(auth_req_id.as_bytes()).to_hex()
    );
    let now = server_time(&inspector).await;
    let mut state = CibaRequestState {
        client_id: "client-a".to_owned(),
        user_id: uuid::Uuid::from_u128(1),
        scopes: vec!["openid".to_owned()],
        audiences: vec!["resource".to_owned()],
        acr: None,
        binding_message: None,
        issued_at: now,
        status: CibaStatus::Pending,
        interval_seconds: 5,
        expires_at: now + 60,
        retention_expires_at: now + 180,
        last_poll_at: None,
    };
    assert_eq!(
        store.create(&auth_req_id, &state).await.unwrap(),
        AtomicResult::Applied
    );
    assert_eq!(
        inspector.expire_time::<i64, _>(&key).await.unwrap(),
        state.retention_expires_at
    );
    let stored = store.load(&auth_req_id).await.unwrap().unwrap();
    assert_eq!(stored.value(), &state);
    state.last_poll_at = Some(now + 1);
    let mut other = state.clone();
    other.interval_seconds = 10;
    let (first, second) = tokio::join!(
        store.replace(&auth_req_id, &stored, &state),
        store.replace(&auth_req_id, &stored, &other)
    );
    assert_eq!(
        [first.unwrap(), second.unwrap()]
            .iter()
            .filter(|r| **r == AtomicResult::Applied)
            .count(),
        1
    );
}

#[tokio::test]
async fn concurrent_approved_ciba_polls_have_exactly_one_token_issuance_winner() {
    let Some((connection, inspector)) = setup().await else {
        return;
    };
    let auth_req_id = format!("ciba-approved-{}", uuid::Uuid::now_v7());
    let now = server_time(&inspector).await;
    let state = CibaRequestState {
        client_id: "client-a".to_owned(),
        user_id: uuid::Uuid::from_u128(1),
        scopes: vec!["openid".to_owned()],
        audiences: vec!["resource".to_owned()],
        acr: None,
        binding_message: None,
        issued_at: now,
        status: CibaStatus::Approved,
        interval_seconds: 5,
        expires_at: now + 60,
        retention_expires_at: now + 180,
        last_poll_at: None,
    };
    let store = CibaStore::new(&connection);
    assert_eq!(
        store.create(&auth_req_id, &state).await.unwrap(),
        AtomicResult::Applied
    );
    let first = CibaService::new(store.clone());
    let second = CibaService::new(store);
    let first_stored = first.load(&auth_req_id).await.unwrap().unwrap();
    let second_stored = second.load(&auth_req_id).await.unwrap().unwrap();
    let (first_result, second_result) = tokio::join!(
        first.poll(&auth_req_id, "client-a", first_stored, || now),
        second.poll(&auth_req_id, "client-a", second_stored, || now)
    );
    assert_eq!(
        [first_result, second_result]
            .into_iter()
            .filter(|result| matches!(result, Ok(CibaPollCommit::Approved(_))))
            .count(),
        1,
        "approved auth_req_id must be consumed once even under concurrent polling"
    );
}

fn pending_device(now: chrono::DateTime<Utc>) -> DeviceAuthorizationState {
    DeviceAuthorizationState::Pending {
        payload: DeviceAuthorizationPayload {
            client_id: "client-a".to_owned(),
            client_name: "Client A".to_owned(),
            scopes: vec!["openid".to_owned()],
            resource_indicators: vec![],
            authorization_details: json!([]),
            interval_seconds: 5,
            issued_at: now,
            expires_at: now + chrono::Duration::seconds(60),
        },
        last_poll_at: None,
        slow_down_count: 0,
    }
}

#[tokio::test]
async fn device_creation_is_atomic_and_collision_leaves_no_orphan() {
    let Some((connection, inspector)) = setup().await else {
        return;
    };
    let store = DeviceStore::new(&connection);
    let suffix = uuid::Uuid::now_v7().to_string();
    let device_code = format!("device-{suffix}");
    let user_code = format!("USER-{suffix}");
    let device_hash = blake3::hash(device_code.as_bytes()).to_hex();
    let normalized = user_code
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .flat_map(char::to_uppercase)
        .collect::<String>();
    let user_key = format!(
        "oauth:device:user_code:{}",
        blake3::hash(normalized.as_bytes()).to_hex()
    );
    let device_key = format!("oauth:device:code:{device_hash}");
    let state = pending_device(Utc.timestamp_opt(1_000, 0).unwrap());
    inspector
        .set::<(), _, _>(&user_key, "occupied", None, None, false)
        .await
        .unwrap();

    assert_eq!(
        store
            .create(&device_code, &user_code, &state, 30)
            .await
            .unwrap(),
        DeviceCreateResult::UserCodeCollision
    );
    assert_eq!(
        inspector.exists::<i64, _>(&device_key).await.unwrap(),
        0,
        "collision must not expose an orphan device record"
    );
    let _: i64 = inspector.del(&user_key).await.unwrap();
    assert_eq!(
        store
            .create(&device_code, &user_code, &state, 30)
            .await
            .unwrap(),
        DeviceCreateResult::Applied
    );
    assert!(
        store
            .load_by_device_code(&device_code)
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(
        store
            .resolve_user_code(&user_code)
            .await
            .unwrap()
            .as_deref(),
        Some(device_hash.as_str())
    );
}

#[tokio::test]
async fn concurrent_device_polls_atomically_accumulate_slow_down() {
    let Some((connection, inspector)) = setup().await else {
        return;
    };
    let now = Utc.timestamp_opt(server_time(&inspector).await, 0).unwrap();
    let device_code = format!("device-poll-{}", uuid::Uuid::now_v7());
    let user_code = format!("POLL-{}", uuid::Uuid::now_v7());
    let mut state = pending_device(now);
    let DeviceAuthorizationState::Pending { last_poll_at, .. } = &mut state else {
        unreachable!()
    };
    *last_poll_at = Some(now);
    let store = DeviceStore::new(&connection);
    store
        .create(&device_code, &user_code, &state, 60)
        .await
        .unwrap();
    let service = DeviceGrantService::new(store);
    let poll_time = now + chrono::Duration::seconds(1);

    assert!(matches!(
        service
            .poll(&device_code, "other-client", || poll_time)
            .await,
        Err(DevicePollFailure::ClientMismatch)
    ));

    let (first, second) = tokio::join!(
        service.poll(&device_code, "client-a", || poll_time),
        service.poll(&device_code, "client-a", || poll_time)
    );

    assert!(matches!(first, Ok(DevicePollCommit::SlowDown)));
    assert!(matches!(second, Ok(DevicePollCommit::SlowDown)));
    let stored = DeviceStore::new(&connection)
        .load_by_device_code(&device_code)
        .await
        .unwrap()
        .unwrap();
    let DeviceAuthorizationState::Pending {
        slow_down_count, ..
    } = stored
    else {
        panic!("poll state must remain pending")
    };
    assert_eq!(slow_down_count, 2);
}

#[tokio::test]
async fn approved_device_code_has_exactly_one_consumer() {
    let Some((connection, inspector)) = setup().await else {
        return;
    };
    let now = Utc.timestamp_opt(server_time(&inspector).await, 0).unwrap();
    let device_code = format!("device-consume-{}", uuid::Uuid::now_v7());
    let user_code = format!("CONSUME-{}", uuid::Uuid::now_v7());
    let payload = match pending_device(now) {
        DeviceAuthorizationState::Pending { payload, .. } => payload,
        _ => unreachable!(),
    };
    let state = DeviceAuthorizationState::Approved {
        payload,
        approval: DeviceAuthorizationApproval {
            user_id: uuid::Uuid::from_u128(42),
            subject: "subject".to_owned(),
            auth_time: now.timestamp(),
            amr: vec!["pwd".to_owned()],
            oidc_sid: None,
        },
        approved_at: now,
    };
    let store = DeviceStore::new(&connection);
    store
        .create(&device_code, &user_code, &state, 60)
        .await
        .unwrap();
    let service = DeviceGrantService::new(store);

    let (first, second) = tokio::join!(
        service.poll(&device_code, "client-a", || now),
        service.poll(&device_code, "client-a", || now)
    );

    let approved = [&first, &second]
        .into_iter()
        .filter(|result| matches!(result, Ok(DevicePollCommit::Approved(_))))
        .count();
    let missing = [&first, &second]
        .into_iter()
        .filter(|result| matches!(result, Err(DevicePollFailure::Missing)))
        .count();
    assert_eq!(approved, 1);
    assert_eq!(missing, 1);
}

#[tokio::test]
async fn concurrent_device_denials_commit_one_terminal_result() {
    let Some((connection, inspector)) = setup().await else {
        return;
    };
    let now = Utc.timestamp_opt(server_time(&inspector).await, 0).unwrap();
    let device_code = format!("device-decision-{}", uuid::Uuid::now_v7());
    let user_code = format!("DECISION-{}", uuid::Uuid::now_v7());
    let state = pending_device(now);
    let store = DeviceStore::new(&connection);
    store
        .create(&device_code, &user_code, &state, 60)
        .await
        .unwrap();
    let service = DeviceGrantService::new(store);
    let (first, second) = tokio::join!(
        service.deny(&user_code, || now),
        service.deny(&user_code, || now)
    );

    assert_eq!(usize::from(first.is_ok()) + usize::from(second.is_ok()), 1);
    assert!(matches!(
        first.as_ref().err().or_else(|| second.as_ref().err()),
        Some(DeviceDecisionFailure::Missing | DeviceDecisionFailure::AlreadyHandled)
    ));
    assert!(
        DeviceStore::new(&connection)
            .resolve_user_code(&user_code)
            .await
            .unwrap()
            .is_none()
    );
}
