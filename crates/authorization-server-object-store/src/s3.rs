use std::{
    collections::{BTreeMap, HashMap},
    path::PathBuf,
    sync::Arc,
    time::SystemTime,
};

use aws_credential_types::Credentials as AwsCredentials;
use aws_sigv4::{
    http_request::{PayloadChecksumKind, SignableBody, SignableRequest, SigningSettings, sign},
    sign::v4,
};
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
use s3::{Bucket, Region, creds::Credentials};
use serde::Deserialize;

const STAGING_DIRECTORY: &str = "staging";
const FINAL_DIRECTORY: &str = "final";
const TENANT_PREFIX: &str = "avatars";

/// All S3-compatible object-store connection details.  This concrete adapter
/// deliberately does not leak S3 SDK values through the server or domain.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct S3AvatarObjectStoreConfig {
    pub endpoint: String,
    pub region: String,
    pub bucket: String,
    pub access_key: String,
    pub secret_key: String,
    #[serde(default = "default_path_style")]
    pub path_style: bool,
}

fn default_path_style() -> bool {
    true
}

#[derive(Clone)]
pub struct S3AvatarObjectStore {
    bucket: Arc<Bucket>,
    client: reqwest::Client,
    credentials: AwsCredentials,
    region: Arc<str>,
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
            region: config.region.clone(),
            endpoint: config.endpoint.clone(),
        };
        let bucket = Bucket::new(&config.bucket, region, credentials).map_err(s3_unavailable)?;
        let bucket = if config.path_style {
            *bucket.with_path_style()
        } else {
            *bucket
        };
        let client = reqwest::Client::builder().build().map_err(unavailable)?;
        let credentials = AwsCredentials::new(
            config.access_key,
            config.secret_key,
            None,
            None,
            "nazo-avatar-object-store",
        );
        Ok(Self {
            bucket: Arc::new(bucket),
            client,
            credentials,
            region: Arc::from(config.region),
            prefix: Arc::from(tenant_namespace(tenant_id)),
        })
    }

    fn staging_key(&self, object_id: &str) -> Result<String, AvatarStorageError> {
        safe_object_id(object_id)?;
        Ok(format!(
            "{TENANT_PREFIX}/{STAGING_DIRECTORY}/{}/{object_id}",
            self.prefix
        ))
    }

    fn final_key(&self, object_id: &str) -> Result<String, AvatarStorageError> {
        safe_object_id(object_id)?;
        Ok(format!(
            "{TENANT_PREFIX}/{FINAL_DIRECTORY}/{}/{object_id}",
            self.prefix
        ))
    }

    async fn copy_staged_object(
        &self,
        source: &str,
        destination: &str,
        expected_version: &str,
        content_type: AvatarContentType,
    ) -> Result<u16, AvatarStorageError> {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            "x-amz-copy-source",
            format!("{}/{}", self.bucket.name(), source)
                .parse()
                .map_err(unavailable)?,
        );
        headers.insert(
            "x-amz-copy-source-if-match",
            expected_version.parse().map_err(unavailable)?,
        );
        headers.insert(
            "x-amz-metadata-directive",
            "REPLACE".parse().expect("static header is valid"),
        );
        headers.insert(
            http::header::CONTENT_TYPE,
            content_type
                .as_str()
                .parse()
                .expect("static content type is valid"),
        );
        self.signed_empty_object_request(http::Method::PUT, destination, headers)
            .await
    }

    async fn signed_empty_object_request(
        &self,
        method: http::Method,
        object_key: &str,
        mut headers: http::HeaderMap,
    ) -> Result<u16, AvatarStorageError> {
        let uri: http::Uri = format!("{}/{object_key}", self.bucket.url())
            .parse()
            .map_err(unavailable)?;
        let host = uri
            .authority()
            .ok_or(AvatarStorageError::InvalidState)?
            .as_str()
            .to_owned();
        headers.insert(http::header::HOST, host.parse().map_err(unavailable)?);
        let mut request = http::Request::builder()
            .method(method)
            .uri(uri)
            .body(Vec::new())
            .map_err(unavailable)?;
        *request.headers_mut() = headers;
        let headers = request
            .headers()
            .iter()
            .map(|(name, value)| {
                value
                    .to_str()
                    .map(|value| (name.as_str(), value))
                    .map_err(unavailable)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let signable = SignableRequest::new(
            request.method().as_str(),
            request.uri().to_string(),
            headers.into_iter(),
            SignableBody::Bytes(&[]),
        )
        .map_err(unavailable)?;
        let identity = self.credentials.clone().into();
        let mut signing_settings = SigningSettings::default();
        signing_settings.payload_checksum_kind = PayloadChecksumKind::XAmzSha256;
        let signing_params = v4::SigningParams::builder()
            .identity(&identity)
            .region(self.region.as_ref())
            .name("s3")
            .time(SystemTime::now())
            .settings(signing_settings)
            .build()
            .map_err(unavailable)?
            .into();
        let (instructions, _) = sign(signable, &signing_params)
            .map_err(unavailable)?
            .into_parts();
        instructions.apply_to_request_http1x(&mut request);
        let request = reqwest::Request::try_from(request).map_err(unavailable)?;
        let response = self.client.execute(request).await.map_err(unavailable)?;
        let status = response.status().as_u16();
        response.bytes().await.map_err(unavailable)?;
        Ok(status)
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

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
enum TenantStorageConfig {
    Local { directory: PathBuf },
    S3(S3AvatarObjectStoreConfig),
}

struct TenantAvatarObjectStoreProvider {
    default: Option<Arc<dyn ServerAvatarObjectStoreProvider>>,
    overrides: HashMap<TenantId, ServerAvatarStorageCapability>,
}

impl TenantAvatarObjectStoreProvider {
    fn new(
        default: Option<Arc<dyn ServerAvatarObjectStoreProvider>>,
        overrides_json: &str,
    ) -> anyhow::Result<Self> {
        let configurations: HashMap<TenantId, TenantStorageConfig> =
            serde_json::from_str(overrides_json)
                .map_err(|_| anyhow::anyhow!("AVATAR_TENANT_STORAGE_JSON must map tenant UUIDs to complete local or s3 configurations"))?;
        let mut overrides = HashMap::new();
        for (tenant_id, configuration) in configurations {
            let capability = match configuration {
                TenantStorageConfig::Local { directory } => {
                    anyhow::ensure!(
                        directory.is_absolute(),
                        "tenant avatar storage directory must be absolute"
                    );
                    ServerAvatarStorageCapability::Local {
                        directory: Some(directory.join(tenant_id.as_uuid().to_string())),
                    }
                }
                TenantStorageConfig::S3(config) => ServerAvatarStorageCapability::Direct(Arc::new(
                    S3AvatarObjectStore::new(config, tenant_id)?,
                )),
            };
            overrides.insert(tenant_id, capability);
        }
        Ok(Self { default, overrides })
    }

    fn from_config(source: &ConfigSource) -> anyhow::Result<Self> {
        let default: Option<Arc<dyn ServerAvatarObjectStoreProvider>> =
            match source.optional_string("AVATAR_OBJECT_STORE").as_deref() {
                None => None,
                Some("local") => Some(Arc::new(crate::LocalAvatarObjectStoreProvider)),
                Some("s3") => Some(Arc::new(S3AvatarObjectStoreProvider::new(
                    S3AvatarObjectStoreConfig {
                        endpoint: source.required_string("AVATAR_S3_ENDPOINT")?,
                        region: source.required_string("AVATAR_S3_REGION")?,
                        bucket: source.required_string("AVATAR_S3_BUCKET")?,
                        access_key: source.required_string("AVATAR_S3_ACCESS_KEY")?,
                        secret_key: source.required_string("AVATAR_S3_SECRET_KEY")?,
                        path_style: source.bool("AVATAR_S3_PATH_STYLE", true)?,
                    },
                )?)),
                Some(_) => anyhow::bail!("AVATAR_OBJECT_STORE must be local or s3 when configured"),
            };
        Self::new(default, &source.string("AVATAR_TENANT_STORAGE_JSON", "{}"))
    }
}

impl ServerAvatarObjectStoreProvider for TenantAvatarObjectStoreProvider {
    fn for_tenant(&self, tenant_id: TenantId) -> ServerAvatarStorageCapability {
        self.overrides.get(&tenant_id).cloned().unwrap_or_else(|| {
            self.default
                .as_ref()
                .map_or(ServerAvatarStorageCapability::Disabled, |provider| {
                    provider.for_tenant(tenant_id)
                })
        })
    }
}

/// Concrete object-store launcher. S3 settings are parsed only in this crate;
/// the authorization server receives a tenant-bound generic capability.
#[derive(Clone, Copy, Debug, Default)]
pub struct AvatarObjectStoreLauncher;

impl ServerAvatarObjectStoreLauncher for AvatarObjectStoreLauncher {
    fn server_config_extension(&self) -> ServerConfigExtension {
        ServerConfigExtension::configuration_only(
            "# Optional shared avatar storage; omit to require tenant-specific storage.\n# AVATAR_OBJECT_STORE: \"local\"\n".to_owned(),
            vec![
                "AVATAR_OBJECT_STORE",
                "AVATAR_S3_ACCESS_KEY",
                "AVATAR_S3_BUCKET",
                "AVATAR_S3_ENDPOINT",
                "AVATAR_S3_PATH_STYLE",
                "AVATAR_S3_REGION",
                "AVATAR_S3_SECRET_KEY",
                "AVATAR_TENANT_STORAGE_JSON",
            ],
        )
    }

    fn server_bindings<'a>(
        &'a self,
        source: &'a ConfigSource,
        _deployment_id: &'a str,
    ) -> LauncherFuture<'a, ServerAvatarObjectStoreBindings> {
        Box::pin(async move {
            Ok(ServerAvatarObjectStoreBindings::new(Arc::new(
                TenantAvatarObjectStoreProvider::from_config(source)?,
            )))
        })
    }
}

impl AvatarDirectUploadPort for S3AvatarObjectStore {
    fn authorize_upload<'a>(
        &'a self,
        staging_object_id: &'a str,
        content_length: usize,
        expires_at: DateTime<Utc>,
    ) -> AvatarStorageFuture<'a, AvatarUploadTarget> {
        Box::pin(async move {
            let object_key = self.staging_key(staging_object_id)?;
            let expiry_seconds = expiry_seconds(expires_at)?;
            let content_length: u64 = content_length
                .try_into()
                .map_err(|_| AvatarStorageError::InvalidState)?;
            let mut signed_headers = http::HeaderMap::new();
            signed_headers.insert(
                http::header::CONTENT_LENGTH,
                content_length
                    .to_string()
                    .parse()
                    .expect("content length is a valid HTTP header"),
            );
            let url = self
                .bucket
                .presign_put(&object_key, expiry_seconds, Some(signed_headers), None)
                .await
                .map_err(s3_unavailable)?;
            Ok(AvatarUploadTarget {
                url,
                method: "PUT".to_owned(),
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
            // Bind the bytes handed to the image decoder to the same object
            // version later supplied to CopyObject. Without this conditional
            // GET, a client could replace staging between HEAD and GET, then
            // restore the old ETag before copy and publish unvalidated bytes.
            let mut headers = self.bucket.extra_headers().clone();
            headers.insert(
                "if-match",
                version
                    .parse()
                    .map_err(|_| AvatarStorageError::InvalidState)?,
            );
            let bucket = self
                .bucket
                .with_extra_headers(headers)
                .map_err(s3_unavailable)?;
            let mut response = bucket
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

            let status = self
                .copy_staged_object(&source, &destination, expected_version, content_type)
                .await?;
            if (200..300).contains(&status) {
                let (published, status) = self
                    .bucket
                    .head_object(&destination)
                    .await
                    .map_err(s3_unavailable)?;
                ensure_status(status)?;
                return existing_candidate_matches(&published, expected_version, content_type);
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
            ensure_status(
                self.signed_empty_object_request(
                    http::Method::DELETE,
                    &object_key,
                    http::HeaderMap::new(),
                )
                .await?,
            )
        })
    }

    fn delete_final<'a>(&'a self, final_object_id: &'a str) -> AvatarStorageFuture<'a, ()> {
        Box::pin(async move {
            let object_key = self.final_key(final_object_id)?;
            ensure_status(
                self.signed_empty_object_request(
                    http::Method::DELETE,
                    &object_key,
                    http::HeaderMap::new(),
                )
                .await?,
            )
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
    digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
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

#[cfg(test)]
#[path = "../tests/unit/tenant_configuration.rs"]
mod tenant_configuration_tests;
