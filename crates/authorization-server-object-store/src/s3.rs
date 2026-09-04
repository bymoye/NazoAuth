use std::{
    collections::{BTreeMap, HashMap},
    path::PathBuf,
    sync::Arc,
    time::SystemTime,
};

use aws_credential_types::Credentials as AwsCredentials;
use aws_sigv4::{
    http_request::{
        PayloadChecksumKind, PercentEncodingMode, SignableBody, SignableRequest, SignatureLocation,
        SigningSettings, UriPathNormalizationMode, sign,
    },
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
use reqwest::Url;
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
    endpoint: Url,
    bucket: Arc<str>,
    path_style: bool,
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
        let endpoint = Url::parse(&config.endpoint).map_err(unavailable)?;
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(unavailable)?;
        let credentials = AwsCredentials::new(
            config.access_key,
            config.secret_key,
            None,
            None,
            "nazo-avatar-object-store",
        );
        Ok(Self {
            endpoint,
            bucket: Arc::from(config.bucket),
            path_style: config.path_style,
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

    fn object_url(&self, object_key: &str) -> Result<Url, AvatarStorageError> {
        let mut url = self.endpoint.clone();
        if !self.path_style {
            let host = url.host_str().ok_or(AvatarStorageError::InvalidState)?;
            let virtual_host = format!("{}.{}", self.bucket, host);
            url.set_host(Some(&virtual_host)).map_err(unavailable)?;
        }
        {
            let mut segments = url
                .path_segments_mut()
                .map_err(|_| AvatarStorageError::InvalidState)?;
            segments.pop_if_empty();
            if self.path_style {
                segments.push(self.bucket.as_ref());
            }
            for segment in object_key.split('/') {
                segments.push(segment);
            }
        }
        Ok(url)
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
            format!("/{}/{}", self.bucket, source)
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
        let response = self
            .signed_request(http::Method::PUT, destination, headers, Vec::new())
            .await?;
        let status = response.status().as_u16();
        // S3 can finish a CopyObject response after sending the status line.
        // Drain it before verifying the destination and publishing its reference.
        response.bytes().await.map_err(unavailable)?;
        Ok(status)
    }

    async fn signed_request(
        &self,
        method: http::Method,
        object_key: &str,
        mut headers: http::HeaderMap,
        body: Vec<u8>,
    ) -> Result<reqwest::Response, AvatarStorageError> {
        let uri: http::Uri = self
            .object_url(object_key)?
            .as_str()
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
            .body(body)
            .map_err(unavailable)?;
        *request.headers_mut() = headers;
        let header_values = request
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
            header_values.into_iter(),
            SignableBody::Bytes(request.body()),
        )
        .map_err(unavailable)?;
        let identity = self.credentials.clone().into();
        let mut signing_settings = SigningSettings::default();
        signing_settings.payload_checksum_kind = PayloadChecksumKind::XAmzSha256;
        signing_settings.percent_encoding_mode = PercentEncodingMode::Single;
        signing_settings.uri_path_normalization_mode = UriPathNormalizationMode::Disabled;
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
        self.client
            .execute(reqwest::Request::try_from(request).map_err(unavailable)?)
            .await
            .map_err(unavailable)
    }

    async fn presigned_put(
        &self,
        object_key: &str,
        content_length: u64,
        expires: u32,
    ) -> Result<String, AvatarStorageError> {
        let uri: http::Uri = self
            .object_url(object_key)?
            .as_str()
            .parse()
            .map_err(unavailable)?;
        let host = uri
            .authority()
            .ok_or(AvatarStorageError::InvalidState)?
            .as_str()
            .to_owned();
        let mut request = http::Request::builder()
            .method(http::Method::PUT)
            .uri(uri)
            .body(Vec::<u8>::new())
            .map_err(unavailable)?;
        request
            .headers_mut()
            .insert(http::header::HOST, host.parse().map_err(unavailable)?);
        request.headers_mut().insert(
            http::header::CONTENT_LENGTH,
            content_length.to_string().parse().map_err(unavailable)?,
        );
        let values = request
            .headers()
            .iter()
            .map(|(n, v)| v.to_str().map(|v| (n.as_str(), v)).map_err(unavailable))
            .collect::<Result<Vec<_>, _>>()?;
        let signable = SignableRequest::new(
            "PUT",
            request.uri().to_string(),
            values.into_iter(),
            SignableBody::UnsignedPayload,
        )
        .map_err(unavailable)?;
        let identity = self.credentials.clone().into();
        let mut settings = SigningSettings::default();
        settings.signature_location = SignatureLocation::QueryParams;
        settings.expires_in = Some(std::time::Duration::from_secs(expires.into()));
        settings.payload_checksum_kind = PayloadChecksumKind::NoHeader;
        settings.percent_encoding_mode = PercentEncodingMode::Single;
        settings.uri_path_normalization_mode = UriPathNormalizationMode::Disabled;
        let params = v4::SigningParams::builder()
            .identity(&identity)
            .region(self.region.as_ref())
            .name("s3")
            .time(SystemTime::now())
            .settings(settings)
            .build()
            .map_err(unavailable)?
            .into();
        let (instructions, _) = sign(signable, &params).map_err(unavailable)?.into_parts();
        instructions.apply_to_request_http1x(&mut request);
        Ok(request.uri().to_string())
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
            let url = self
                .presigned_put(&object_key, content_length, expiry_seconds)
                .await?;
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
            let response = self
                .signed_request(
                    http::Method::HEAD,
                    &object_key,
                    http::HeaderMap::new(),
                    Vec::new(),
                )
                .await?;
            ensure_status(response.status().as_u16())?;
            let content_length = response
                .headers()
                .get(http::header::CONTENT_LENGTH)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse::<u64>().ok())
                .ok_or(AvatarStorageError::InvalidState)?;
            if content_length > max_bytes as u64 {
                return Err(AvatarStorageError::InvalidState);
            }
            let version = response
                .headers()
                .get("etag")
                .and_then(|v| v.to_str().ok())
                .ok_or(AvatarStorageError::InvalidState)?
                .to_owned();
            // Bind the bytes handed to the image decoder to the same object
            // version later supplied to CopyObject. Without this conditional
            // GET, a client could replace staging between HEAD and GET, then
            // restore the old ETag before copy and publish unvalidated bytes.
            let mut headers = http::HeaderMap::new();
            headers.insert(
                "if-match",
                version
                    .parse()
                    .map_err(|_| AvatarStorageError::InvalidState)?,
            );
            let response = self
                .signed_request(http::Method::GET, &object_key, headers, Vec::new())
                .await?;
            ensure_status(response.status().as_u16())?;
            let mut bytes = Vec::with_capacity(content_length as usize);
            let mut stream = response.bytes_stream();
            while let Some(chunk) = stream.next().await {
                let chunk = chunk.map_err(unavailable)?;
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
            let response = self
                .signed_request(
                    http::Method::HEAD,
                    &destination,
                    http::HeaderMap::new(),
                    Vec::new(),
                )
                .await?;
            let status = response.status().as_u16();
            if (200..300).contains(&status) {
                return existing_candidate_matches(
                    response.headers(),
                    expected_version,
                    content_type,
                );
            }
            if status != 404 {
                return ensure_status(status);
            }

            let status = self
                .copy_staged_object(&source, &destination, expected_version, content_type)
                .await?;
            if (200..300).contains(&status) {
                let response = self
                    .signed_request(
                        http::Method::HEAD,
                        &destination,
                        http::HeaderMap::new(),
                        Vec::new(),
                    )
                    .await?;
                ensure_status(response.status().as_u16())?;
                return existing_candidate_matches(
                    response.headers(),
                    expected_version,
                    content_type,
                );
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
            let response = self
                .signed_request(
                    http::Method::HEAD,
                    &object_key,
                    http::HeaderMap::new(),
                    Vec::new(),
                )
                .await?;
            ensure_status(response.status().as_u16())?;
            let content_type = response
                .headers()
                .get(http::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .and_then(AvatarContentType::parse)
                .ok_or(AvatarStorageError::InvalidState)?;
            let response = self
                .signed_request(
                    http::Method::GET,
                    &object_key,
                    http::HeaderMap::new(),
                    Vec::new(),
                )
                .await?;
            ensure_status(response.status().as_u16())?;
            Ok(AvatarObject {
                bytes: response.bytes().await.map_err(unavailable)?.to_vec(),
                content_type,
                version: final_object_id.to_owned(),
            })
        })
    }

    fn delete_staging<'a>(&'a self, staging_object_id: &'a str) -> AvatarStorageFuture<'a, ()> {
        Box::pin(async move {
            let object_key = self.staging_key(staging_object_id)?;
            ensure_status(
                self.signed_request(
                    http::Method::DELETE,
                    &object_key,
                    http::HeaderMap::new(),
                    Vec::new(),
                )
                .await?
                .status()
                .as_u16(),
            )
        })
    }

    fn delete_final<'a>(&'a self, final_object_id: &'a str) -> AvatarStorageFuture<'a, ()> {
        Box::pin(async move {
            let object_key = self.final_key(final_object_id)?;
            ensure_status(
                self.signed_request(
                    http::Method::DELETE,
                    &object_key,
                    http::HeaderMap::new(),
                    Vec::new(),
                )
                .await?
                .status()
                .as_u16(),
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
    headers: &http::HeaderMap,
    expected_version: &str,
    expected_content_type: AvatarContentType,
) -> Result<(), AvatarStorageError> {
    if headers
        .get("etag")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|etag| normalize_etag(etag) == normalize_etag(expected_version))
        && headers
            .get(http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            == Some(expected_content_type.as_str())
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

fn unavailable(error: impl std::fmt::Display) -> AvatarStorageError {
    AvatarStorageError::Unavailable(error.to_string())
}

#[cfg(test)]
#[path = "../tests/unit/tenant_configuration.rs"]
mod tenant_configuration_tests;

#[cfg(test)]
#[path = "../tests/unit/urls.rs"]
mod url_tests;
