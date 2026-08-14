use std::time::Duration;

use nazo_identity::{DEFAULT_TENANT_ID, TenantId};
use nazo_valkey::{ErrorKind, ValkeyConnection};
use uuid::Uuid;

async fn connect(variable: &str) -> Option<ValkeyConnection> {
    let url = std::env::var(variable).ok()?;
    ValkeyConnection::connect(&url, Duration::from_secs(1))
        .await
        .ok()
}

async fn raw_client(variable: &str) -> Option<nazo_valkey::test_support::Client> {
    let url = std::env::var(variable).ok()?;
    nazo_valkey::test_support::connect(&url, Duration::from_secs(1))
        .await
        .ok()
}

#[tokio::test]
#[ignore = "requires an empty disposable VALKEY_URL logical database"]
async fn non_default_tenant_claims_empty_database_and_rejects_other_tenants() {
    let Some(connection) = connect("VALKEY_URL").await else {
        return;
    };
    let first = TenantId::new(Uuid::now_v7()).expect("tenant id");
    let other = TenantId::new(Uuid::now_v7()).expect("tenant id");
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
    let reconnected = connect("VALKEY_URL")
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
#[ignore = "requires an empty disposable VALKEY_LEGACY_URL logical database"]
async fn default_tenant_adopts_legacy_state_without_weakening_owner_binding() {
    use nazo_valkey::test_support::KeysInterface;

    let Some(connection) = connect("VALKEY_LEGACY_URL").await else {
        return;
    };
    let raw = raw_client("VALKEY_LEGACY_URL")
        .await
        .expect("raw Valkey client");

    let first = TenantId::new(Uuid::now_v7()).expect("tenant id");
    let other = TenantId::new(Uuid::now_v7()).expect("tenant id");
    raw.set::<(), _, _>("legacy-state", "value", None, None, false)
        .await
        .expect("seed legacy state");
    let error = connection
        .bind_tenant_owner(first)
        .await
        .expect_err("non-default tenant must not adopt unmarked state");
    assert_eq!(error.kind(), ErrorKind::UnexpectedResult);

    let legacy = TenantId::new(DEFAULT_TENANT_ID).expect("default tenant id");
    connection
        .bind_tenant_owner(legacy)
        .await
        .expect("default tenant may adopt legacy state during upgrade");
    connection
        .bind_tenant_owner(legacy)
        .await
        .expect("same tenant claim should be idempotent");
    connection
        .bind_tenant_owner(other)
        .await
        .expect_err("legacy adoption must still bind the database");
}
