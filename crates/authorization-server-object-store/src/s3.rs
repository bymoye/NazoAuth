use std::{borrow::Cow, collections::BTreeMap, sync::Arc};

use chrono::{DateTime, Utc};
use futures_util::StreamExt as _;
use nazo_identity::{
    AvatarContentType, AvatarObject, TenantId,
    ports::{
        AvatarDirectUploadPort, AvatarStagedObject, AvatarStorageError, AvatarStorageFuture,
        AvatarUploadTarget,
    },
};
use nazo_oauth_server::{
    bootstrap::{
        ServerAvatarObjectStoreBindings, ServerAvatarObjectStoreProvider,
        ServerAvatarStorageCapability,
    },
    cli::{AvatarObjectStoreLauncher as ServerAvatarObjectStoreLauncher, LauncherFuture},
    config::{ConfigSource, ServerConfigExtension},
};
use s3::{
    Bucket, Region,
    creds::Credentials,
    post_policy::{PostPolicy, PostPolicyField, PostPolicyValue},
};

const STAGING_DIRECTORY: &str = "staging";
const FINAL_DIRECTORY: &str = "final";
const TENANT_PREFIX: &str = "avatars";

/// All S3-compatible object-store connection details.  This concrete adapter
/// deliberately does not leak S3 SDK values through the server or domain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct S3AvatarObjectStoreConfig {
    pub endpoint: String,
    pub region: String,
    pub bucket: String,
    pub access_key: String,
    pub secret_key: String,
    pub path_style: bool,
}

#[derive(Clone)]
pub struct S3AvatarObjectStore {
    bucket: Arc<Bucket>,
    prefix: Arc<str>,
}

impl S3AvatarObjectStore {
    pub fn new(
        config: S3AvatarObjectStoreConfig,
        tenant_id: TenantId,
    ) -> Result<Self, AvatarStorageError> {
        validate_config(&config)?;
        let credentials = Credentials::new(
            Some(&config.access_key),
            Some(&config.secret_key),
            None,
            None,
            None,
        )
        .map_err(unavailable)?;
        let region = Region::Custom {
            region: config.region,
            endpoint: config.endpoint,
        };
        let bucket = Bucket::new(&config.bucket, region, credentials).map_err(s3_unavailable)?;
        let bucket = if config.path_style {
            *bucket.with_path_style()
        } else {
            *bucket
        };
        Ok(Self {
            bucket: Arc::new(bucket),
            prefix: Arc::from(tenant_namespace(tenant_id)),
        })
    }

    fn staging_key(&self, object_id: &str) -> Result<String, AvatarStorageError> {
        safe_object_id(object_id)?;
        Ok(format!("{}/{STAGING_DIRECTORY}/{object_id}", self.prefix))
    }

    fn final_key(&self, object_id: &str) -> Result<String, AvatarStorageError> {
        safe_object_id(object_id)?;
        Ok(format!("{}/{FINAL_DIRECTORY}/{object_id}", self.prefix))
    }
}

/// Binds one S3 bucket configuration to disjoint tenant object namespaces.
#[derive(Clone)]
pub struct S3AvatarObjectStoreProvider {
    config: S3AvatarObjectStoreConfig,
}

impl S3AvatarObjectStoreProvider {
    pub fn new(config: S3AvatarObjectStoreConfig) -> Result<Self, AvatarStorageError> {
        validate_config(&config)?;
        Ok(Self { config })
    }
}

impl ServerAvatarObjectStoreProvider for S3AvatarObjectStoreProvider {
    fn for_tenant(&self, tenant_id: TenantId) -> ServerAvatarStorageCapability {
        let store = S3AvatarObjectStore::new(self.config.clone(), tenant_id)
            .expect("provider configuration was validated before tenant binding");
        ServerAvatarStorageCapability::Direct(Arc::new(store))
    }
}

/// Concrete object-store launcher. S3 settings are parsed only in this crate;
/// the authorization server receives a tenant-bound generic capability.
#[derive(Clone, Copy, Debug, Default)]
pub struct AvatarObjectStoreLauncher;

impl ServerAvatarObjectStoreLauncher for AvatarObjectStoreLauncher {
    fn server_config_extension(&self) -> ServerConfigExtension {
        ServerConfigExtension::configuration_only(
            "AVATAR_OBJECT_STORE: \"local\"\n".to_owned(),
            vec![
                "AVATAR_OBJECT_STORE",
                "AVATAR_S3_ACCESS_KEY",
                "AVATAR_S3_BUCKET",
                "AVATAR_S3_ENDPOINT",
                "AVATAR_S3_PATH_STYLE",
                "AVATAR_S3_REGION",
                "AVATAR_S3_SECRET_KEY",
            ],
        )
    }

    fn server_bindings<'a>(
        &'a self,
        source: &'a ConfigSource,
        _deployment_id: &'a str,
    ) -> LauncherFuture<'a, ServerAvatarObjectStoreBindings> {
        Box::pin(async move {
            let provider: Arc<dyn ServerAvatarObjectStoreProvider> =
                match source.string("AVATAR_OBJECT_STORE", "local").trim() {
                    "local" => Arc::new(crate::LocalAvatarObjectStoreProvider),
                    "s3" => Arc::new(S3AvatarObjectStoreProvider::new(
                        S3AvatarObjectStoreConfig {
                            endpoint: source.required_string("AVATAR_S3_ENDPOINT")?,
                            region: source.required_string("AVATAR_S3_REGION")?,
                            bucket: source.required_string("AVATAR_S3_BUCKET")?,
                            access_key: source.required_string("AVATAR_S3_ACCESS_KEY")?,
                            secret_key: source.required_string("AVATAR_S3_SECRET_KEY")?,
                            path_style: source.bool("AVATAR_S3_PATH_STYLE", true)?,
                        },
                    )?),
                    _ => anyhow::bail!("AVATAR_OBJECT_STORE must be local or s3"),
                };
            Ok(ServerAvatarObjectStoreBindings::new(provider))
        })
    }
}

impl AvatarDirectUploadPort for S3AvatarObjectStore {
    fn authorize_upload<'a>(
        &'a self,
        staging_object_id: &'a str,
        max_bytes: usize,
        expires_at: DateTime<Utc>,
    ) -> AvatarStorageFuture<'a, AvatarUploadTarget> {
        Box::pin(async move {
            let object_key = self.staging_key(staging_object_id)?;
            let expiry_seconds = expiry_seconds(expires_at)?;
            let max_bytes: u32 = max_bytes
                .try_into()
                .map_err(|_| AvatarStorageError::InvalidState)?;
            let policy = PostPolicy::new(expiry_seconds)
                .condition(
                    PostPolicyField::Key,
                    PostPolicyValue::Exact(Cow::Owned(object_key)),
                )
                .map_err(s3_unavailable)?
                .condition(
                    PostPolicyField::ContentLengthRange,
                    PostPolicyValue::Range(0, max_bytes),
                )
                .map_err(s3_unavailable)?;
            let signed = self
                .bucket
                .presign_post(policy)
                .await
                .map_err(s3_unavailable)?;
            Ok(AvatarUploadTarget {
                url: signed.url,
                method: "POST".to_owned(),
                fields: signed.fields.into_iter().collect::<BTreeMap<_, _>>(),
                headers: BTreeMap::new(),
            })
        })
    }

    fn read_staged<'a>(
        &'a self,
        staging_object_id: &'a str,
        max_bytes: usize,
    ) -> AvatarStorageFuture<'a, AvatarStagedObject> {
        Box::pin(async move {
            let object_key = self.staging_key(staging_object_id)?;
            let (head, status) = self
                .bucket
                .head_object(&object_key)
                .await
                .map_err(s3_unavailable)?;
            ensure_status(status)?;
            let content_length = head
                .content_length
                .ok_or(AvatarStorageError::InvalidState)?;
            if content_length < 0 || content_length as u64 > max_bytes as u64 {
                return Err(AvatarStorageError::InvalidState);
            }
            let version = head.e_tag.ok_or(AvatarStorageError::InvalidState)?;
            let mut response = self
                .bucket
                .get_object_stream(&object_key)
                .await
                .map_err(s3_unavailable)?;
            ensure_status(response.status_code)?;
            let mut bytes = Vec::with_capacity(content_length as usize);
            while let Some(chunk) = response.bytes().next().await {
                let chunk = chunk.map_err(s3_unavailable)?;
                if bytes.len().saturating_add(chunk.len()) > max_bytes {
                    return Err(AvatarStorageError::InvalidState);
                }
                bytes.extend_from_slice(&chunk);
            }
            Ok(AvatarStagedObject { bytes, version })
        })
    }

    fn publish_staged<'a>(
        &'a self,
        staging_object_id: &'a str,
        expected_version: &'a str,
        final_object_id: &'a str,
        content_type: AvatarContentType,
    ) -> AvatarStorageFuture<'a, ()> {
        Box::pin(async move {
            let source = self.staging_key(staging_object_id)?;
            let destination = self.final_key(final_object_id)?;
            let (existing, status) = self
                .bucket
                .head_object(&destination)
                .await
                .map_err(s3_unavailable)?;
            if (200..300).contains(&status) {
                return existing_candidate_matches(&existing, expected_version, content_type);
            }
            if status != 404 {
                return ensure_status(status);
            }

            let mut headers = self.bucket.extra_headers().clone();
            headers.insert(
                "x-amz-copy-source-if-match",
                expected_version
                    .parse()
                    .map_err(|_| AvatarStorageError::InvalidState)?,
            );
            headers.insert(
                "x-amz-metadata-directive",
                "REPLACE".parse().expect("static header is valid"),
            );
            headers.insert(
                "content-type",
                content_type
                    .as_str()
                    .parse()
                    .expect("static content type is valid"),
            );
            let bucket = self
                .bucket
                .with_extra_headers(headers)
                .map_err(s3_unavailable)?;
            let status = bucket
                .copy_object_internal(&source, &destination)
                .await
                .map_err(s3_unavailable)?;
            if (200..300).contains(&status) {
                return Ok(());
            }
            if status == 412 {
                return Err(AvatarStorageError::Conflict);
            }
            ensure_status(status)
        })
    }

    fn read_final<'a>(&'a self, final_object_id: &'a str) -> AvatarStorageFuture<'a, AvatarObject> {
        Box::pin(async move {
            let object_key = self.final_key(final_object_id)?;
            let (head, status) = self
                .bucket
                .head_object(&object_key)
                .await
                .map_err(s3_unavailable)?;
            ensure_status(status)?;
            let content_type = head
                .content_type
                .as_deref()
                .and_then(AvatarContentType::parse)
                .ok_or(AvatarStorageError::InvalidState)?;
            let response = self
                .bucket
                .get_object(&object_key)
                .await
                .map_err(s3_unavailable)?;
            ensure_status(response.status_code())?;
            Ok(AvatarObject {
                bytes: response.to_vec(),
                content_type,
                version: final_object_id.to_owned(),
            })
        })
    }

    fn delete_staging<'a>(&'a self, staging_object_id: &'a str) -> AvatarStorageFuture<'a, ()> {
        Box::pin(async move {
            let object_key = self.staging_key(staging_object_id)?;
            let response = self
                .bucket
                .delete_object(object_key)
                .await
                .map_err(s3_unavailable)?;
            ensure_status(response.status_code())
        })
    }

    fn delete_final<'a>(&'a self, final_object_id: &'a str) -> AvatarStorageFuture<'a, ()> {
        Box::pin(async move {
            let object_key = self.final_key(final_object_id)?;
            let response = self
                .bucket
                .delete_object(object_key)
                .await
                .map_err(s3_unavailable)?;
            ensure_status(response.status_code())
        })
    }
}

fn validate_config(config: &S3AvatarObjectStoreConfig) -> Result<(), AvatarStorageError> {
    if !matches!(config.endpoint.strip_prefix("http://").or_else(|| config.endpoint.strip_prefix("https://")), Some(value) if !value.is_empty())
        || config.region.trim().is_empty()
        || config.bucket.trim().is_empty()
        || config.access_key.trim().is_empty()
        || config.secret_key.trim().is_empty()
    {
        return Err(AvatarStorageError::InvalidState);
    }
    Ok(())
}

fn safe_object_id(object_id: &str) -> Result<(), AvatarStorageError> {
    if object_id.is_empty()
        || !object_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(AvatarStorageError::InvalidState);
    }
    Ok(())
}

fn tenant_namespace(tenant_id: TenantId) -> String {
    use sha2::{Digest as _, Sha256};

    let digest = Sha256::digest(tenant_id.as_uuid().as_bytes());
    let encoded = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("{TENANT_PREFIX}/{encoded}")
}

fn expiry_seconds(expires_at: DateTime<Utc>) -> Result<u32, AvatarStorageError> {
    let remaining = expires_at.signed_duration_since(Utc::now());
    let seconds = remaining.num_seconds();
    if seconds <= 0 || seconds > 604_800 {
        return Err(AvatarStorageError::InvalidState);
    }
    seconds
        .try_into()
        .map_err(|_| AvatarStorageError::InvalidState)
}

fn existing_candidate_matches(
    existing: &s3::serde_types::HeadObjectResult,
    expected_version: &str,
    expected_content_type: AvatarContentType,
) -> Result<(), AvatarStorageError> {
    if existing
        .e_tag
        .as_deref()
        .is_some_and(|etag| normalize_etag(etag) == normalize_etag(expected_version))
        && existing.content_type.as_deref() == Some(expected_content_type.as_str())
    {
        Ok(())
    } else {
        Err(AvatarStorageError::Conflict)
    }
}

fn normalize_etag(value: &str) -> &str {
    value.trim().trim_matches('"')
}

fn ensure_status(status: u16) -> Result<(), AvatarStorageError> {
    match status {
        200..=299 => Ok(()),
        404 => Err(AvatarStorageError::Missing),
        409 | 412 => Err(AvatarStorageError::Conflict),
        _ => Err(AvatarStorageError::Unavailable(format!(
            "S3 returned HTTP {status}"
        ))),
    }
}

fn s3_unavailable(error: s3::error::S3Error) -> AvatarStorageError {
    unavailable(error)
}

fn unavailable(error: impl std::fmt::Display) -> AvatarStorageError {
    AvatarStorageError::Unavailable(error.to_string())
}
