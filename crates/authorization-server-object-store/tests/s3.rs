use std::collections::BTreeMap;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use nazo_identity::{TenantContext, ports::AvatarDirectUploadPort};
use nazo_oauth_server_object_store::{S3AvatarObjectStore, S3AvatarObjectStoreConfig};

#[tokio::test]
async fn s3_direct_target_fixes_the_staging_key_and_byte_range() {
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
        .expect("presigned post");

    assert_eq!(target.method, "POST");
    let key = target.fields.get("key").expect("fixed S3 key");
    assert!(key.starts_with("avatars/"));
    assert!(key.ends_with("/staging/staging-a"));
    assert_eq!(target.headers, BTreeMap::new());
    let policy = target.fields.get("Policy").expect("S3 policy field");
    let policy: serde_json::Value =
        serde_json::from_slice(&STANDARD.decode(policy).unwrap()).unwrap();
    assert!(
        policy["conditions"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!({"key": key}))
    );
    assert!(
        policy["conditions"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!(["content-length-range", 0, 1234]))
    );
}
