use super::*;

fn store(endpoint: &str, path_style: bool) -> S3AvatarObjectStore {
    S3AvatarObjectStore::new(
        S3AvatarObjectStoreConfig {
            endpoint: endpoint.to_owned(),
            region: "us-east-1".to_owned(),
            bucket: "avatar.bucket".to_owned(),
            access_key: "access".to_owned(),
            secret_key: "secret".to_owned(),
            path_style,
        },
        TenantId::new(uuid::Uuid::now_v7()).expect("tenant"),
    )
    .expect("valid config")
}

#[test]
fn path_style_preserves_endpoint_prefix_without_double_slash() {
    let url = store("https://objects.example.test/prefix/", true)
        .object_url("avatars/staging/object-id")
        .expect("object URL");
    assert_eq!(
        url.as_str(),
        "https://objects.example.test/prefix/avatar.bucket/avatars/staging/object-id"
    );
}

#[test]
fn virtual_host_style_moves_bucket_into_host() {
    let url = store("https://objects.example.test/", false)
        .object_url("avatars/final/object-id")
        .expect("object URL");
    assert_eq!(
        url.as_str(),
        "https://avatar.bucket.objects.example.test/avatars/final/object-id"
    );
}
