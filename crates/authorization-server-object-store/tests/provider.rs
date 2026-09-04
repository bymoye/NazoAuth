use nazo_identity::TenantId;
use nazo_oauth_server::bootstrap::{
    ServerAvatarObjectStoreProvider, ServerAvatarStorageCapability,
};
use nazo_oauth_server_object_store::{S3AvatarObjectStoreConfig, S3AvatarObjectStoreProvider};
use uuid::Uuid;

#[tokio::test]
async fn provider_derives_disjoint_opaque_tenant_object_namespaces() {
    let provider = S3AvatarObjectStoreProvider::new(S3AvatarObjectStoreConfig {
        endpoint: "https://objects.example.test".to_owned(),
        region: "us-east-1".to_owned(),
        bucket: "avatars".to_owned(),
        access_key: "access".to_owned(),
        secret_key: "secret".to_owned(),
        path_style: true,
    })
    .expect("valid S3 configuration");
    let first = TenantId::new(Uuid::from_u128(1)).unwrap();
    let second = TenantId::new(Uuid::from_u128(2)).unwrap();

    let ServerAvatarStorageCapability::Direct(first_store) = provider.for_tenant(first) else {
        panic!("S3 provider supports direct upload");
    };
    let ServerAvatarStorageCapability::Direct(second_store) = provider.for_tenant(second) else {
        panic!("S3 provider supports direct upload");
    };
    let expiry = chrono::Utc::now() + chrono::Duration::minutes(5);
    let first_key = first_store
        .authorize_upload("upload-a", 1024, expiry)
        .await
        .unwrap()
        .url;
    let second_key = second_store
        .authorize_upload("upload-a", 1024, expiry)
        .await
        .unwrap()
        .url;

    let first_key = first_key.split('?').next().unwrap();
    let second_key = second_key.split('?').next().unwrap();

    assert_ne!(first_key, second_key);
    assert!(!first_key.contains(&first.as_uuid().to_string()));
    assert!(!second_key.contains(&second.as_uuid().to_string()));
    assert!(first_key.contains("/avatars/staging/"));
}
