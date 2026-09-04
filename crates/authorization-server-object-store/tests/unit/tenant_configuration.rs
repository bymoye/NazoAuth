use super::*;
use serde_json::json;
use uuid::Uuid;

fn tenant(value: u128) -> TenantId {
    TenantId::new(Uuid::from_u128(value)).unwrap()
}

fn global_s3() -> Option<Arc<dyn ServerAvatarObjectStoreProvider>> {
    Some(Arc::new(
        S3AvatarObjectStoreProvider::new(S3AvatarObjectStoreConfig {
            endpoint: "https://global.example.test".into(),
            region: "global-region".into(),
            bucket: "global-bucket".into(),
            access_key: "global-access".into(),
            secret_key: "global-secret".into(),
            path_style: true,
        })
        .unwrap(),
    ))
}

async fn target(provider: &dyn ServerAvatarObjectStoreProvider, id: TenantId) -> String {
    let ServerAvatarStorageCapability::Direct(store) = provider.for_tenant(id) else {
        panic!("expected direct upload");
    };
    store
        .authorize_upload(
            "same-object",
            100,
            Utc::now() + chrono::Duration::minutes(5),
        )
        .await
        .unwrap()
        .url
}

#[tokio::test]
async fn complete_tenant_configuration_replaces_global_s3_without_field_inheritance() {
    let overrides = json!({tenant(1).as_uuid().to_string(): {
        "type": "s3", "endpoint": "https://tenant.example.test", "region": "tenant-region",
        "bucket": "tenant-bucket", "access_key": "tenant-access", "secret_key": "tenant-secret"
    }});
    let provider =
        TenantAvatarObjectStoreProvider::new(global_s3(), &overrides.to_string()).unwrap();
    let overridden = target(&provider, tenant(1)).await;
    assert!(overridden.starts_with("https://tenant.example.test/tenant-bucket/"));
    assert!(overridden.contains("tenant-access"));
    assert!(overridden.contains("tenant-region"));
    assert!(!overridden.contains("global-"));
    let inherited = target(&provider, tenant(2)).await;
    assert!(inherited.starts_with("https://global.example.test/global-bucket/"));
    assert!(inherited.contains("global-access"));
}

#[test]
fn local_overrides_replace_s3_and_namespace_even_a_shared_directory() {
    let root = std::env::temp_dir().join("tenant-avatar-configuration");
    let overrides = json!({
        tenant(1).as_uuid().to_string(): {"type": "local", "directory": root},
        tenant(2).as_uuid().to_string(): {"type": "local", "directory": root}
    });
    let provider =
        TenantAvatarObjectStoreProvider::new(global_s3(), &overrides.to_string()).unwrap();
    for id in [tenant(1), tenant(2)] {
        let ServerAvatarStorageCapability::Local { directory } = provider.for_tenant(id) else {
            panic!("tenant local override must replace global S3");
        };
        assert_eq!(directory, Some(root.join(id.as_uuid().to_string())));
    }
}

#[tokio::test]
async fn tenant_s3_can_override_global_local_and_absent_tenants_still_inherit() {
    let overrides = json!({tenant(1).as_uuid().to_string(): {
        "type": "s3", "endpoint": "https://tenant.example.test", "region": "auto",
        "bucket": "tenant-bucket", "access_key": "access", "secret_key": "secret", "path_style": true
    }});
    let provider = TenantAvatarObjectStoreProvider::new(
        Some(Arc::new(crate::LocalAvatarObjectStoreProvider)),
        &overrides.to_string(),
    )
    .unwrap();
    assert!(
        target(&provider, tenant(1))
            .await
            .starts_with("https://tenant.example.test/tenant-bucket/")
    );
    assert!(matches!(
        provider.for_tenant(tenant(2)),
        ServerAvatarStorageCapability::Local { directory: None }
    ));
}

#[test]
fn missing_global_and_tenant_storage_disables_avatars_without_blocking_configuration() {
    let provider = TenantAvatarObjectStoreProvider::from_config(&ConfigSource::default()).unwrap();
    for id in [tenant(1), tenant(2)] {
        assert!(matches!(
            provider.for_tenant(id),
            ServerAvatarStorageCapability::Disabled
        ));
    }
}

#[tokio::test]
async fn absent_global_storage_makes_tenant_configuration_the_allowlist() {
    let root = std::env::temp_dir().join("avatar-allowlist");
    let overrides = json!({
        tenant(1).as_uuid().to_string(): {
            "type": "s3", "endpoint": "https://tenant.example.test", "region": "auto",
            "bucket": "allowed-bucket", "access_key": "access", "secret_key": "secret"
        },
        tenant(2).as_uuid().to_string(): {"type": "local", "directory": root}
    });
    let provider = TenantAvatarObjectStoreProvider::new(None, &overrides.to_string()).unwrap();
    assert!(
        target(&provider, tenant(1))
            .await
            .starts_with("https://tenant.example.test/allowed-bucket/")
    );
    let ServerAvatarStorageCapability::Local { directory } = provider.for_tenant(tenant(2)) else {
        panic!("explicit local tenant remains enabled");
    };
    assert_eq!(directory, Some(root.join(tenant(2).as_uuid().to_string())));
    assert!(matches!(
        provider.for_tenant(tenant(3)),
        ServerAvatarStorageCapability::Disabled
    ));
}

#[tokio::test]
async fn unavailable_tenant_s3_returns_the_storage_error_instead_of_global_local() {
    let overrides = json!({tenant(1).as_uuid().to_string(): {
        "type": "s3", "endpoint": "http://127.0.0.1:1", "region": "auto",
        "bucket": "unavailable", "access_key": "access", "secret_key": "secret"
    }});
    let provider = TenantAvatarObjectStoreProvider::new(
        Some(Arc::new(crate::LocalAvatarObjectStoreProvider)),
        &overrides.to_string(),
    )
    .unwrap();
    let ServerAvatarStorageCapability::Direct(store) = provider.for_tenant(tenant(1)) else {
        panic!("configured S3 must not become local");
    };
    assert!(matches!(
        store.read_final("existing-avatar").await,
        Err(AvatarStorageError::Unavailable(_))
    ));
    assert!(matches!(
        provider.for_tenant(tenant(1)),
        ServerAvatarStorageCapability::Direct(_)
    ));
}

#[test]
fn invalid_or_partial_overrides_fail_before_tenants_are_served() {
    let key = tenant(1).as_uuid().to_string();
    for invalid in [
        json!({"not-a-uuid": {"type": "local", "directory": "/tmp/avatar"}}),
        json!({Uuid::nil().to_string(): {"type": "local", "directory": "/tmp/avatar"}}),
        json!({key.clone(): {"type": "s3", "bucket": "only-a-bucket"}}),
        json!({key.clone(): {"type": "local", "directory": "relative/path"}}),
        json!({key.clone(): {"type": "unknown"}}),
        json!({key.clone(): null}),
        json!({key: {"type": "s3", "endpoint": "https://example.test", "region": "auto", "bucket": "bucket", "access_key": "", "secret_key": "secret"}}),
    ] {
        assert!(TenantAvatarObjectStoreProvider::new(global_s3(), &invalid.to_string()).is_err());
    }
}
