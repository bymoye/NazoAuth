use std::time::Duration;

use fred::interfaces::{ClientLike, KeysInterface};
use fred::prelude::{Builder, Config};
use nazo_identity::UserId;
use nazo_valkey::{DeliveryConsume, DeliveryStore, ValkeyConnection};
use serde_json::json;

async fn setup() -> Option<(DeliveryStore, fred::prelude::Client)> {
    let url = std::env::var("VALKEY_URL").ok()?;
    let connection = ValkeyConnection::connect(&url, Duration::from_secs(1))
        .await
        .expect("an explicitly configured Valkey must be available");
    let inspector = Builder::from_config(Config::from_url(&url).unwrap())
        .build()
        .unwrap();
    inspector
        .init()
        .await
        .expect("an explicitly configured Valkey must be available");
    Some((DeliveryStore::new(&connection), inspector))
}

#[tokio::test]
async fn client_delivery_preserves_exact_key_semantic_payload_and_ttl() {
    let Some((store, inspector)) = setup().await else {
        return;
    };
    let user_id = UserId::new(uuid::Uuid::from_u128(7)).unwrap();
    let token = format!("token-{}", uuid::Uuid::now_v7());
    let key = format!("oauth:client_delivery:{}:{token}", user_id.as_uuid());
    let payload = json!({
        "delivery_state": "committed",
        "request_id": uuid::Uuid::from_u128(8),
        "user_id": user_id.as_uuid(),
        "client_id": "client-a",
        "client_secret": "secret"
    });

    store.store(user_id, &token, &payload, 30).await.unwrap();

    let raw = inspector.get::<String, _>(&key).await.unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&raw).unwrap(),
        payload
    );
    assert!((1..=30).contains(&inspector.ttl::<i64, _>(&key).await.unwrap()));
    assert_eq!(
        store.load(user_id, &token).await.unwrap().unwrap().value(),
        &payload
    );
}

#[tokio::test]
async fn concurrent_client_delivery_consume_has_exactly_one_winner() {
    let Some((store, _)) = setup().await else {
        return;
    };
    let user_id = UserId::new(uuid::Uuid::from_u128(9)).unwrap();
    let token = format!("token-{}", uuid::Uuid::now_v7());
    let payload = json!({"delivery_state":"committed", "client_id":"client-a"});
    store.store(user_id, &token, &payload, 30).await.unwrap();
    let first_snapshot = store.load(user_id, &token).await.unwrap().unwrap();
    let second_snapshot = first_snapshot.clone();

    let (first, second) = tokio::join!(
        store.consume(user_id, &token, &first_snapshot),
        store.consume(user_id, &token, &second_snapshot)
    );
    let winners = [first.unwrap(), second.unwrap()]
        .into_iter()
        .filter(|result| matches!(result, DeliveryConsume::Consumed(_)))
        .count();
    assert_eq!(winners, 1);
    assert!(store.load(user_id, &token).await.unwrap().is_none());
}
