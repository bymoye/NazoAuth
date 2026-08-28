use std::time::Duration;

use nazo_identity::TenantId;
use nazo_identity::{UserId, session::SessionRecord};
use nazo_valkey::test_support::KeysInterface;
use nazo_valkey::{ErrorKind, SessionStore, ValkeyConnection};
use url::Url;
use uuid::Uuid;

fn isolated_database_url(database: u8) -> Option<String> {
    let mut url = Url::parse(&std::env::var("VALKEY_URL").ok()?).ok()?;
    url.set_path(&format!("/{database}"));
    Some(url.into())
}

async fn connect(url: &str) -> Option<ValkeyConnection> {
    nazo_valkey::test_support::scoped_connect(url, Duration::from_secs(1))
        .await
        .ok()
}

async fn raw_client(url: &str) -> Option<nazo_valkey::test_support::Client> {
    nazo_valkey::test_support::connect(url, Duration::from_secs(1))
        .await
        .ok()
}

#[tokio::test]
async fn non_default_tenant_claims_empty_database_and_rejects_other_tenants() {
    let Some(url) = isolated_database_url(14) else {
        return;
    };
    let Some(connection) = connect(&url).await else {
        return;
    };
    let first = TenantId::new(Uuid::from_u128(0x100)).expect("tenant id");
    let other = TenantId::new(Uuid::from_u128(0x101)).expect("tenant id");
    let (first_result, other_result) = tokio::join!(
        connection.bind_tenant_owner(first),
        connection.bind_tenant_owner(other)
    );
    let (owner, rejected) = match (first_result, other_result) {
        (Ok(()), Err(error)) => (first, error),
        (Err(error), Ok(())) => (other, error),
        results => panic!("exactly one concurrent tenant must claim the database: {results:?}"),
    };
    assert_eq!(rejected.kind(), ErrorKind::UnexpectedResult);
    connection
        .bind_tenant_owner(owner)
        .await
        .expect("same tenant claim should be idempotent");
    let reconnected = connect(&url)
        .await
        .expect("new connection to disposable Valkey");
    reconnected
        .bind_tenant_owner(owner)
        .await
        .expect("owner marker must persist across connections");
    let non_owner = if owner == first { other } else { first };
    let error = reconnected
        .bind_tenant_owner(non_owner)
        .await
        .expect_err("another tenant must fail closed after reconnect");
    assert_eq!(error.kind(), ErrorKind::UnexpectedResult);
}

#[tokio::test]
async fn unmarked_nonempty_database_fails_closed_for_every_tenant() {
    use nazo_valkey::test_support::KeysInterface;

    let Some(url) = isolated_database_url(15) else {
        return;
    };
    let Some(connection) = connect(&url).await else {
        return;
    };
    let raw = raw_client(&url).await.expect("raw Valkey client");

    let first = TenantId::new(Uuid::from_u128(0x200)).expect("tenant id");
    let other = TenantId::new(Uuid::from_u128(0x201)).expect("tenant id");
    raw.set::<(), _, _>("legacy-state", "value", None, None, false)
        .await
        .expect("seed legacy state");
    let error = connection
        .bind_tenant_owner(first)
        .await
        .expect_err("an unmarked nonempty database must never be adopted");
    assert_eq!(error.kind(), ErrorKind::UnexpectedResult);
    let error = connection
        .bind_tenant_owner(other)
        .await
        .expect_err("every tenant must reject legacy unmarked state");
    assert_eq!(error.kind(), ErrorKind::UnexpectedResult);
    let _: i64 = raw
        .del("legacy-state")
        .await
        .expect("remove only this test fixture key");
}

#[tokio::test]
async fn raw_inspector_proves_deployment_and_epoch_are_physical_key_boundaries() {
    let Some(url) = isolated_database_url(15) else {
        return;
    };
    let epoch_a = Uuid::from_u128(0x301);
    let epoch_b = Uuid::from_u128(0x302);
    let connection_a =
        ValkeyConnection::connect(&url, Duration::from_secs(1), "deployment-a", epoch_a)
            .await
            .ok();
    let connection_b =
        ValkeyConnection::connect(&url, Duration::from_secs(1), "deployment-b", epoch_b)
            .await
            .ok();
    let (Some(connection_a), Some(connection_b)) = (connection_a, connection_b) else {
        return;
    };
    let raw = raw_client(&url).await.expect("raw Valkey client");
    let session_id = format!("namespace-{}", Uuid::now_v7());
    let record = SessionRecord::new(
        UserId::new(Uuid::from_u128(0x303)).expect("user id"),
        1_000,
        vec!["password".to_owned()],
        false,
        None,
    );
    SessionStore::new(&connection_a)
        .store(&session_id, &record, 30)
        .await
        .expect("store in first explicit namespace");
    assert!(
        SessionStore::new(&connection_b)
            .load(&session_id)
            .await
            .expect("load second namespace")
            .is_none()
    );
    let business_key = format!("oauth:session:{session_id}");
    let first_key = nazo_valkey::test_support::storage_key("deployment-a", epoch_a, &business_key)
        .expect("valid first physical key");
    let second_key = nazo_valkey::test_support::storage_key("deployment-b", epoch_b, &business_key)
        .expect("valid second physical key");
    assert_ne!(first_key, second_key);
    assert!(
        raw.get::<Option<String>, _>(&first_key)
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        raw.get::<Option<String>, _>(&second_key)
            .await
            .unwrap()
            .is_none()
    );
    let _: i64 = raw.del(&first_key).await.expect("remove only fixture key");
}
