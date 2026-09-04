use std::collections::BTreeMap;

use nazo_identity::{TenantContext, ports::AvatarDirectUploadPort};
use nazo_oauth_server_object_store::{S3AvatarObjectStore, S3AvatarObjectStoreConfig};

#[tokio::test]
async fn s3_direct_target_fixes_the_staging_key_and_exact_length() {
    let store = S3AvatarObjectStore::new(
        S3AvatarObjectStoreConfig {
            endpoint: "https://objects.example.test".to_owned(),
            region: "us-east-1".to_owned(),
            bucket: "avatars".to_owned(),
            access_key: "access".to_owned(),
            secret_key: "secret".to_owned(),
            path_style: true,
        },
        TenantContext::default_system().tenant_id,
    )
    .expect("valid S3 configuration");

    let target = store
        .authorize_upload(
            "staging-a",
            1234,
            chrono::Utc::now() + chrono::Duration::minutes(5),
        )
        .await
        .expect("presigned PUT");

    assert_eq!(target.method, "PUT");
    let key = target.url.split('?').next().expect("signed target URL");
    assert!(key.contains("/avatars/staging/"));
    assert!(key.ends_with("/staging-a"));
    assert_eq!(target.headers, BTreeMap::new());
    assert!(
        target
            .url
            .contains("X-Amz-SignedHeaders=content-length%3Bhost")
    );
}
