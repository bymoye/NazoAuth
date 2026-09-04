use std::time::Duration;

use fred::prelude::KeysInterface;
use nazo_identity::{
    OrganizationId, RealmId, TenantContext, TenantDirectoryBinding, TenantDirectorySnapshot,
    TenantId,
};
use nazo_valkey::{ErrorKind, TenantDirectoryCache, ValkeyClient};
use uuid::Uuid;

fn snapshot(revision: u64) -> TenantDirectorySnapshot {
    TenantDirectorySnapshot {
        revision,
        tenants: vec![TenantDirectoryBinding {
            tenant: TenantContext {
                tenant_id: TenantId::new(Uuid::from_u128(1)).unwrap(),
                realm_id: RealmId::new(Uuid::from_u128(2)).unwrap(),
                organization_id: OrganizationId::new(Uuid::from_u128(3)).unwrap(),
            },
            runtime_revision: 1,
            issuer: "https://tenant.example.com".to_owned(),
            external_host: "tenant.example.com".to_owned(),
        }],
    }
}

#[tokio::test]
async fn cache_is_monotonic_and_authoritative_snapshot_repairs_corruption() {
    let Ok(url) = std::env::var("VALKEY_URL") else {
        return;
    };
    let raw = nazo_valkey::test_support::connect(&url, Duration::from_secs(1))
        .await
        .expect("VALKEY_URL should identify a reachable test server");
    let epoch = Uuid::now_v7();
    let deployment_id = format!("tenant-directory-contract-{epoch}");
    let client = ValkeyClient::from_existing_client(raw.clone(), &deployment_id, epoch).unwrap();
    let cache = TenantDirectoryCache::new(&client);
    let physical_key = nazo_valkey::test_support::deployment_storage_key(
        &deployment_id,
        epoch,
        "tenant-directory:snapshot",
    )
    .unwrap();

    assert!(!physical_key.contains(":tenant:"));
    assert_eq!(cache.load().await.unwrap(), None);
    assert!(cache.publish_authoritative(&snapshot(2)).await.unwrap());
    assert_eq!(cache.load().await.unwrap(), Some(snapshot(2)));
    assert!(!cache.publish_authoritative(&snapshot(2)).await.unwrap());
    assert!(!cache.publish_authoritative(&snapshot(1)).await.unwrap());

    let repaired = TenantDirectorySnapshot {
        revision: 2,
        tenants: Vec::new(),
    };
    assert!(cache.publish_authoritative(&repaired).await.unwrap());
    assert_eq!(cache.load().await.unwrap(), Some(repaired));

    raw.set::<(), _, _>(&physical_key, "not-json", None, None, false)
        .await
        .unwrap();
    assert_eq!(
        cache.load().await.unwrap_err().kind(),
        ErrorKind::CorruptData
    );
    assert!(cache.publish_authoritative(&snapshot(2)).await.unwrap());
    assert_eq!(cache.load().await.unwrap(), Some(snapshot(2)));

    assert!(cache.publish_authoritative(&snapshot(3)).await.unwrap());
    assert_eq!(cache.load().await.unwrap(), Some(snapshot(3)));

    raw.set::<(), _, _>(
        &physical_key,
        r#"{"schema_version":2,"integrity":"nazo-tenant-directory-cache-v2","revision":"99","tenants":[{"tenant_id":"00000000-0000-0000-0000-000000000001","realm_id":"00000000-0000-0000-0000-000000000002","organization_id":"00000000-0000-0000-0000-000000000003","runtime_revision":"0","issuer":"https://tenant.example.com","external_host":"tenant.example.com"}]}"#,
        None,
        None,
        false,
    )
    .await
    .unwrap();
    assert!(cache.publish_authoritative(&snapshot(3)).await.unwrap());
    assert_eq!(cache.load().await.unwrap(), Some(snapshot(3)));

    raw.set::<(), _, _>(
        &physical_key,
        r#"{"schema_version":1,"integrity":"nazo-tenant-directory-cache-v1","revision":"99","tenants":[{"tenant_id":false}]}"#,
        None,
        None,
        false,
    )
    .await
    .unwrap();
    assert!(cache.publish_authoritative(&snapshot(3)).await.unwrap());
    assert_eq!(cache.load().await.unwrap(), Some(snapshot(3)));

    assert_eq!(raw.del::<i64, _>(&physical_key).await.unwrap(), 1);
}
