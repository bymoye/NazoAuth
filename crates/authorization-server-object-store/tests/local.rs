use nazo_identity::{AvatarContentType, ports::AvatarDirectUploadPort};
use nazo_oauth_server_object_store::LocalAvatarObjectStore;

#[tokio::test]
async fn local_store_keeps_a_published_final_immutable() {
    let temporary = tempfile::tempdir().expect("temporary root");
    let store = LocalAvatarObjectStore::new(temporary.path().to_owned());

    std::fs::create_dir_all(temporary.path().join("staging")).expect("staging directory");
    std::fs::write(temporary.path().join("staging/upload-a"), b"image bytes")
        .expect("staged bytes");

    let staged = store
        .read_staged("upload-a", 1024)
        .await
        .expect("staged bytes are readable");
    store
        .publish_staged(
            "upload-a",
            &staged.version,
            "final-a",
            AvatarContentType::Png,
        )
        .await
        .expect("candidate is published");

    let final_object = store.read_final("final-a").await.expect("final object");
    assert_eq!(final_object.bytes, b"image bytes");
    assert_eq!(final_object.content_type, AvatarContentType::Png);
    store
        .delete_final("final-a")
        .await
        .expect("unreferenced final is deleted");
    assert!(store.read_final("final-a").await.is_err());
    assert!(
        store
            .authorize_upload("upload-b", 1024, chrono::Utc::now())
            .await
            .is_err()
    );
}
