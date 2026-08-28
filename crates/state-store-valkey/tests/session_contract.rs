use std::time::Duration;

use fred::interfaces::{ClientLike, KeysInterface};
use fred::prelude::{Builder, Config};
use nazo_identity::{
    SessionId, SessionRotationOutcome, SessionUpdateOutcome, UserId, ports::SessionStorePort,
    session::SessionRecord,
};
use nazo_valkey::SessionStore;

async fn setup() -> Option<(SessionStore, fred::prelude::Client)> {
    let url = std::env::var("VALKEY_URL").ok()?;
    let connection = nazo_valkey::test_support::scoped_connect(&url, Duration::from_secs(1))
        .await
        .expect("an explicitly configured Valkey must be available");
    let inspector = Builder::from_config(Config::from_url(&url).unwrap())
        .build()
        .unwrap();
    inspector
        .init()
        .await
        .expect("an explicitly configured Valkey must be available");
    Some((SessionStore::new(&connection), inspector))
}

fn payload() -> SessionRecord {
    SessionRecord::new(
        UserId::new(uuid::Uuid::from_u128(1)).unwrap(),
        1_000,
        vec!["password".to_owned()],
        true,
        Some("oidc-sid".to_owned()),
    )
}

#[tokio::test]
async fn session_store_preserves_exact_key_payload_and_ttl() {
    let Some((store, inspector)) = setup().await else {
        return;
    };
    let sid = uuid::Uuid::now_v7().to_string();
    let key = nazo_valkey::test_support::state_storage_key(format!("oauth:session:{sid}"));
    let value = payload();

    store.store(&sid, &value, 30).await.unwrap();

    assert_eq!(
        inspector.get::<String, _>(&key).await.unwrap(),
        r#"{"user_id":"00000000-0000-0000-0000-000000000001","auth_time":1000,"amr":["password"],"pending_mfa":true,"oidc_sid":"oidc-sid"}"#
    );
    assert!((1..=30).contains(&inspector.ttl::<i64, _>(&key).await.unwrap()));
    assert_eq!(store.load(&sid).await.unwrap().unwrap().value(), &value);
}

#[tokio::test]
async fn session_load_rejects_a_record_without_current_mfa_state() {
    let Some((store, inspector)) = setup().await else {
        return;
    };
    let session_id = SessionId::new(format!("missing-mfa-state-{}", uuid::Uuid::now_v7()));
    let key = nazo_valkey::test_support::state_storage_key(format!(
        "oauth:session:{}",
        session_id.as_str()
    ));
    inspector
        .set::<(), _, _>(
            &key,
            r#"{"user_id":"00000000-0000-0000-0000-000000000001","auth_time":1000,"amr":["password"]}"#,
            None,
            None,
            false,
        )
        .await
        .unwrap();

    assert!(SessionStorePort::load(&store, &session_id).await.is_err());
}

#[tokio::test]
async fn session_compare_and_set_preserves_ttl_and_logged_in_rps() {
    let Some((store, inspector)) = setup().await else {
        return;
    };
    let sid = format!("bind-{}", uuid::Uuid::now_v7());
    let session_id = SessionId::new(sid.clone());
    let key = nazo_valkey::test_support::state_storage_key(format!("oauth:session:{sid}"));
    store.store(&sid, &payload(), 30).await.unwrap();
    let before_ttl = inspector.ttl::<i64, _>(&key).await.unwrap();
    let snapshot = SessionStorePort::load(&store, &session_id)
        .await
        .unwrap()
        .unwrap();
    let mut replacement = snapshot.record().clone();
    replacement.add_logged_in_client("rp-a");
    replacement.add_logged_in_client("rp-a");
    replacement.add_logged_in_client("rp-b");

    assert_eq!(
        SessionStorePort::compare_and_set(&store, &session_id, &snapshot, &replacement)
            .await
            .unwrap(),
        SessionUpdateOutcome::Applied
    );
    let after = SessionStorePort::load(&store, &session_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        after.record().logged_in_client_ids(),
        &["rp-a".to_owned(), "rp-b".to_owned()]
    );
    let after_ttl = inspector.ttl::<i64, _>(&key).await.unwrap();
    assert!(after_ttl > 0 && after_ttl <= before_ttl);
}

#[tokio::test]
async fn concurrent_session_rotation_has_exactly_one_winner_and_no_partial_state() {
    let Some((store, inspector)) = setup().await else {
        return;
    };
    let old_sid = format!("old-{}", uuid::Uuid::now_v7());
    let first_sid = format!("first-{}", uuid::Uuid::now_v7());
    let second_sid = format!("second-{}", uuid::Uuid::now_v7());
    let old_session_id = SessionId::new(old_sid.clone());
    let first_session_id = SessionId::new(first_sid.clone());
    let second_session_id = SessionId::new(second_sid.clone());
    let old = payload();
    let mut replacement = old.clone();
    replacement.set_pending_mfa(false);
    replacement.add_amr("mfa");
    store.store(&old_sid, &old, 30).await.unwrap();
    let stored = SessionStorePort::load(&store, &old_session_id)
        .await
        .unwrap()
        .unwrap();

    let (first, second) = tokio::join!(
        SessionStorePort::rotate(
            &store,
            &old_session_id,
            &stored,
            &first_session_id,
            &replacement,
            30
        ),
        SessionStorePort::rotate(
            &store,
            &old_session_id,
            &stored,
            &second_session_id,
            &replacement,
            30
        )
    );
    let results = [first.unwrap(), second.unwrap()];
    assert_eq!(
        results
            .iter()
            .filter(|r| **r == SessionRotationOutcome::Applied)
            .count(),
        1
    );
    assert_eq!(
        results
            .iter()
            .filter(|r| **r == SessionRotationOutcome::Conflict)
            .count(),
        1
    );
    assert!(
        SessionStorePort::load(&store, &old_session_id)
            .await
            .unwrap()
            .is_none()
    );
    let first_key =
        nazo_valkey::test_support::state_storage_key(format!("oauth:session:{first_sid}"));
    let second_key =
        nazo_valkey::test_support::state_storage_key(format!("oauth:session:{second_sid}"));
    let first_exists = inspector.exists::<i64, _>(first_key).await.unwrap();
    let second_exists = inspector.exists::<i64, _>(second_key).await.unwrap();
    assert_eq!(first_exists + second_exists, 1);
}
