use std::env;

use base64::{Engine as _, engine::general_purpose::STANDARD};
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
#[tokio::test]
async fn minio_presigned_put_publishes_an_immutable_candidate() {
    let Some(config) = minio_config() else {
        return;
    };
    let tenant_id = TenantId::new(Uuid::now_v7()).expect("non-nil tenant");
    let store = S3AvatarObjectStore::new(config, tenant_id).expect("S3 adapter configuration");
    let upload_id = Uuid::now_v7().to_string();
    let final_id = format!("final-{upload_id}");
    let conflicting_final_id = format!("conflict-{upload_id}");
    let original = STANDARD
        .decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR4nGP4z8DwHwAFAAH/iZk9HQAAAABJRU5ErkJggg==")
        .expect("valid PNG fixture");
    let mut replay = original.clone();
    replay[0] ^= 1;

    let target = store
        .authorize_upload(
            &upload_id,
            original.len(),
            chrono::Utc::now() + chrono::Duration::minutes(5),
        )
        .await
        .expect("presigned PUT");
    put(&target, &original)
        .await
        .expect("original PUT is accepted");
    let staged = store
        .read_staged(&upload_id, original.len())
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

    put(&target, &replay)
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

    let mismatched_size_target = store
        .authorize_upload(
            &format!("mismatched-size-{upload_id}"),
            original.len(),
            chrono::Utc::now() + chrono::Duration::minutes(5),
        )
        .await
        .expect("exact-length target");
    assert!(
        put(&mismatched_size_target, &vec![0; original.len() + 1])
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

async fn put(target: &AvatarUploadTarget, bytes: &[u8]) -> Result<(), String> {
    if target.method != "PUT" || !target.headers.is_empty() {
        return Err("direct target is not a headerless PUT".to_owned());
    }
    let response = reqwest::Client::new()
        .put(&target.url)
        .body(bytes.to_vec())
        .send()
        .await
        .map_err(|error| error.to_string())?;
    if response.status().is_success() {
        Ok(())
    } else {
        let status = response.status();
        let body = response.text().await.map_err(|error| error.to_string())?;
        let code = xml_error_field(&body, "Code").unwrap_or("unknown");
        let message = xml_error_field(&body, "Message").unwrap_or("unknown");
        Err(format!(
            "object store returned HTTP {status}: {code}: {message}"
        ))
    }
}

fn xml_error_field<'a>(body: &'a str, field: &str) -> Option<&'a str> {
    let opening = format!("<{field}>");
    let closing = format!("</{field}>");
    let value = body.split_once(&opening)?.1;
    Some(value.split_once(&closing)?.0)
}
