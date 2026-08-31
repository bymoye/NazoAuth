use std::time::Duration;

use nazo_identity::{TenantId, UserId, session::SessionRecord};
use nazo_valkey::{SessionStore, ValkeyConnection};
use uuid::Uuid;

fn tenant(value: u128) -> TenantId {
    TenantId::new(Uuid::from_u128(value)).expect("test tenant must be non-nil")
}

#[test]
fn tenant_is_part_of_every_physical_state_key() {
    let epoch = Uuid::from_u128(0x301);
    let business_key = "oauth:session:same-session";
    let first =
        nazo_valkey::test_support::storage_key("deployment", epoch, tenant(0x100), business_key)
            .expect("valid first physical key");
    let second =
        nazo_valkey::test_support::storage_key("deployment", epoch, tenant(0x101), business_key)
            .expect("valid second physical key");

    assert_ne!(first, second);
    assert!(
        first.ends_with(":tenant:00000000-0000-0000-0000-000000000100:oauth:session:same-session")
    );
    assert!(
        second.ends_with(":tenant:00000000-0000-0000-0000-000000000101:oauth:session:same-session")
    );
}

#[tokio::test]
async fn two_tenants_can_store_the_same_logical_key_without_conflict() {
    let Ok(url) = std::env::var("VALKEY_URL") else {
        return;
    };
    let client = nazo_valkey::test_support::connect(&url, Duration::from_secs(1))
        .await
        .expect("an explicitly configured Valkey must be available");
    let first_connection =
        nazo_valkey::test_support::tenant_scoped_connection(client.clone(), tenant(0x200));
    let second_connection =
        nazo_valkey::test_support::tenant_scoped_connection(client, tenant(0x201));
    let first_store = SessionStore::new(&first_connection);
    let second_store = SessionStore::new(&second_connection);
    let session_id = format!("shared-{}", Uuid::now_v7());
    let first_record = SessionRecord::new(
        UserId::new(Uuid::from_u128(0x300)).expect("user id"),
        1_000,
        vec!["first".to_owned()],
        false,
        None,
    );
    let second_record = SessionRecord::new(
        UserId::new(Uuid::from_u128(0x301)).expect("user id"),
        2_000,
        vec!["second".to_owned()],
        false,
        None,
    );

    first_store
        .store(&session_id, &first_record, 30)
        .await
        .expect("store first tenant state");
    second_store
        .store(&session_id, &second_record, 30)
        .await
        .expect("store second tenant state");

    assert_eq!(
        first_store
            .load(&session_id)
            .await
            .expect("load first tenant state")
            .expect("first tenant state exists")
            .value(),
        &first_record
    );
    assert_eq!(
        second_store
            .load(&session_id)
            .await
            .expect("load second tenant state")
            .expect("second tenant state exists")
            .value(),
        &second_record
    );

    first_store
        .delete(&session_id)
        .await
        .expect("remove first fixture");
    second_store
        .delete(&session_id)
        .await
        .expect("remove second fixture");
}

#[tokio::test]
async fn deployment_and_epoch_remain_physical_key_boundaries() {
    let Ok(url) = std::env::var("VALKEY_URL") else {
        return;
    };
    let epoch_a = Uuid::from_u128(0x401);
    let epoch_b = Uuid::from_u128(0x402);
    let tenant_id = tenant(0x403);
    let connection_a = ValkeyConnection::connect(
        &url,
        Duration::from_secs(1),
        "deployment-a",
        epoch_a,
        tenant_id,
    )
    .await
    .expect("connect first namespace");
    let connection_b = ValkeyConnection::connect(
        &url,
        Duration::from_secs(1),
        "deployment-b",
        epoch_b,
        tenant_id,
    )
    .await
    .expect("connect second namespace");
    let session_id = format!("namespace-{}", Uuid::now_v7());
    let record = SessionRecord::new(
        UserId::new(Uuid::from_u128(0x404)).expect("user id"),
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
    SessionStore::new(&connection_a)
        .delete(&session_id)
        .await
        .expect("remove fixture");
}
