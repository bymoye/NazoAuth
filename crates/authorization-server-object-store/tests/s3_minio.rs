use std::env;

use nazo_identity::{
    AvatarContentType, TenantId,
    ports::{AvatarDirectUploadPort, AvatarStorageError, AvatarUploadTarget},
};
use nazo_oauth_server_object_store::{S3AvatarObjectStore, S3AvatarObjectStoreConfig};
use uuid::Uuid;

const ENDPOINT: &str = "NAZO_TEST_S3_ENDPOINT";
const BUCKET: &str = "NAZO_TEST_S3_BUCKET";
const ACCESS_KEY: &str = "NAZO_TEST_S3_ACCESS_KEY";
const SECRET_KEY: &str = "NAZO_TEST_S3_SECRET_KEY";
const REGION: &str = "NAZO_TEST_S3_REGION";
const MAX_BYTES: usize = 1_024;

#[tokio::test]
async fn minio_presigned_post_publishes_an_immutable_candidate() {
    let Some(config) = minio_config() else {
        return;
    };
    let tenant_id = TenantId::new(Uuid::now_v7()).expect("non-nil tenant");
    let store = S3AvatarObjectStore::new(config, tenant_id).expect("S3 adapter configuration");
    let upload_id = Uuid::now_v7().to_string();
    let final_id = format!("final-{upload_id}");
    let conflicting_final_id = format!("conflict-{upload_id}");
    let original = b"accepted staged image bytes";
    let replay = b"replayed staged image bytes";

    let target = store
        .authorize_upload(
            &upload_id,
            MAX_BYTES,
            chrono::Utc::now() + chrono::Duration::minutes(5),
        )
        .await
        .expect("presigned POST");
    post(&target, original)
        .await
        .expect("original POST is accepted");
    let staged = store
        .read_staged(&upload_id, MAX_BYTES)
        .await
        .expect("staged object is readable");
    assert_eq!(staged.bytes, original);
    store
        .publish_staged(
            &upload_id,
            &staged.version,
            &final_id,
            AvatarContentType::Png,
        )
        .await
        .expect("source-version conditional publish");
    assert_eq!(
        store
            .read_final(&final_id)
            .await
            .expect("final object")
            .bytes,
        original
    );

    post(&target, replay)
        .await
        .expect("staging replay is accepted");
    assert!(matches!(
        store
            .publish_staged(
                &upload_id,
                &staged.version,
                &conflicting_final_id,
                AvatarContentType::Png,
            )
            .await,
        Err(AvatarStorageError::Conflict)
    ));
    assert_eq!(
        store
            .read_final(&final_id)
            .await
            .expect("immutable final")
            .bytes,
        original
    );

    let oversized_target = store
        .authorize_upload(
            &format!("oversized-{upload_id}"),
            MAX_BYTES,
            chrono::Utc::now() + chrono::Duration::minutes(5),
        )
        .await
        .expect("oversized policy target");
    assert!(
        post(&oversized_target, &vec![0; MAX_BYTES + 1])
            .await
            .is_err()
    );

    store
        .delete_staging(&upload_id)
        .await
        .expect("staging cleanup");
    store.delete_final(&final_id).await.expect("final cleanup");
}

fn minio_config() -> Option<S3AvatarObjectStoreConfig> {
    let values = [ENDPOINT, BUCKET, ACCESS_KEY, SECRET_KEY, REGION]
        .into_iter()
        .map(|key| (key, env::var(key).ok()))
        .collect::<Vec<_>>();
    if values.iter().all(|(_, value)| value.is_none()) {
        return None;
    }
    let value = |key| {
        values
            .iter()
            .find(|(candidate, _)| *candidate == key)
            .and_then(|(_, value)| value.clone())
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| panic!("{key} must be set when any MinIO test variable is set"))
    };
    Some(S3AvatarObjectStoreConfig {
        endpoint: value(ENDPOINT),
        region: value(REGION),
        bucket: value(BUCKET),
        access_key: value(ACCESS_KEY),
        secret_key: value(SECRET_KEY),
        path_style: true,
    })
}

async fn post(target: &AvatarUploadTarget, bytes: &[u8]) -> Result<(), String> {
    if target.method != "POST" || !target.headers.is_empty() {
        return Err("direct target is not a headerless POST".to_owned());
    }
    let mut form = reqwest::multipart::Form::new();
    for (name, value) in &target.fields {
        form = form.text(name.clone(), value.clone());
    }
    let file = reqwest::multipart::Part::bytes(bytes.to_vec())
        .file_name("avatar.png")
        .mime_str("image/png")
        .map_err(|error| error.to_string())?;
    let response = reqwest::Client::new()
        .post(&target.url)
        .multipart(form.part("file", file))
        .send()
        .await
        .map_err(|error| error.to_string())?;
    if response.status().is_success() {
        Ok(())
    } else {
        Err(format!("object store returned HTTP {}", response.status()))
    }
}
