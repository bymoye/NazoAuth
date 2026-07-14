use std::{future::Future, pin::Pin};

use nazo_identity::TenantContext;
use serde::Deserialize;
use serde_json::Value;
use uuid::Uuid;

use crate::{OAuthClient, ValidatedClientRegistration};

mod validation;

use validation::{ClientMetadata, default_true, validate_client_metadata};

pub type AdminClientFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, AdminClientPortError>> + Send + 'a>>;
pub type SectorIdentifierFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Vec<String>, String>> + Send + 'a>>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdminClientPortError {
    Unavailable,
    Conflict,
    CorruptData,
    Unexpected,
}

impl std::fmt::Display for AdminClientPortError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Unavailable => "admin client repository unavailable",
            Self::Conflict => "admin client repository conflict",
            Self::CorruptData => "admin client repository returned corrupt data",
            Self::Unexpected => "unexpected admin client repository failure",
        })
    }
}

impl std::error::Error for AdminClientPortError {}

pub trait AdminClientRepositoryPort: Send + Sync {
    fn page(&self, offset: i64, limit: i64) -> AdminClientFuture<'_, (Vec<OAuthClient>, i64)>;

    fn by_client_id<'a>(
        &'a self,
        tenant_id: Uuid,
        client_id: &'a str,
    ) -> AdminClientFuture<'a, Option<OAuthClient>>;

    fn insert<'a>(
        &'a self,
        client: &'a OAuthClient,
        client_secret_hash: Option<&'a str>,
        registration_access_token_blake3: Option<&'a str>,
    ) -> AdminClientFuture<'a, OAuthClient>;

    fn update<'a>(&'a self, client: &'a OAuthClient) -> AdminClientFuture<'a, OAuthClient>;
}

pub trait SectorIdentifierResolverPort: Send + Sync {
    fn resolve<'a>(&'a self, uri: &'a str) -> SectorIdentifierFuture<'a>;
}

/// Cryptographic operations are isolated from protocol validation and use-case policy.
pub trait AdminClientCryptoPort: Send + Sync {
    fn response_signing_algorithms(&self) -> Vec<String>;
    fn issue_client_secret(&self, pepper: &str) -> (String, String);
    fn validate_jwks(&self, jwks: &Value, allow_missing_kid: bool) -> Result<(), String>;
    fn matching_encryption_key_count(&self, jwks: &Value, algorithm: &str) -> usize;
    fn contains_signing_key(&self, jwks: &Value) -> bool;
    fn valid_self_signed_mtls_jwks(&self, jwks: &Value) -> bool;
}

#[derive(Clone)]
pub struct AdminClientPolicy {
    pub tenant: TenantContext,
    pub pairwise_subject_secret: Option<String>,
    pub client_secret_pepper: String,
}

impl std::fmt::Debug for AdminClientPolicy {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AdminClientPolicy")
            .field("tenant", &self.tenant)
            .field(
                "pairwise_subject_secret",
                &self.pairwise_subject_secret.as_ref().map(|_| "[REDACTED]"),
            )
            .field("client_secret_pepper", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug)]
pub enum AdminClientError {
    InvalidRequest(String),
    NotFound,
    Repository(AdminClientPortError),
    Lookup(AdminClientPortError),
    Write(AdminClientPortError),
    Consistency(String),
}

impl std::fmt::Display for AdminClientError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidRequest(message) | Self::Consistency(message) => {
                formatter.write_str(message)
            }
            Self::NotFound => formatter.write_str("admin client not found"),
            Self::Repository(error) | Self::Lookup(error) | Self::Write(error) => {
                error.fmt(formatter)
            }
        }
    }
}

impl std::error::Error for AdminClientError {}

#[derive(Clone, Debug, Deserialize)]
pub struct CreateClientRequest {
    pub client_name: String,
    pub client_type: String,
    pub redirect_uris: Vec<String>,
    #[serde(default)]
    pub post_logout_redirect_uris: Vec<String>,
    pub scopes: Vec<String>,
    pub allowed_audiences: Vec<String>,
    pub grant_types: Vec<String>,
    pub token_endpoint_auth_method: String,
    #[serde(default)]
    pub subject_type: Option<String>,
    #[serde(default)]
    pub sector_identifier_uri: Option<String>,
    #[serde(default)]
    pub require_dpop_bound_tokens: bool,
    #[serde(default)]
    pub allow_client_assertion_audience_array: bool,
    #[serde(default)]
    pub allow_client_assertion_endpoint_audience: bool,
    #[serde(default)]
    pub require_par_request_object: bool,
    #[serde(default)]
    pub allow_authorization_code_without_pkce: bool,
    #[serde(default)]
    pub backchannel_logout_uri: Option<String>,
    #[serde(default = "default_true")]
    pub backchannel_logout_session_required: bool,
    #[serde(default)]
    pub frontchannel_logout_uri: Option<String>,
    #[serde(default = "default_true")]
    pub frontchannel_logout_session_required: bool,
    #[serde(default)]
    pub tls_client_auth_subject_dn: Option<String>,
    #[serde(default)]
    pub tls_client_auth_cert_sha256: Option<String>,
    #[serde(default)]
    pub tls_client_auth_san_dns: Vec<String>,
    #[serde(default)]
    pub tls_client_auth_san_uri: Vec<String>,
    #[serde(default)]
    pub tls_client_auth_san_ip: Vec<String>,
    #[serde(default)]
    pub tls_client_auth_san_email: Vec<String>,
    pub jwks: Option<Value>,
    #[serde(default)]
    pub introspection_encrypted_response_alg: Option<String>,
    #[serde(default)]
    pub introspection_encrypted_response_enc: Option<String>,
    #[serde(default)]
    pub userinfo_signed_response_alg: Option<String>,
    #[serde(default)]
    pub userinfo_encrypted_response_alg: Option<String>,
    #[serde(default)]
    pub userinfo_encrypted_response_enc: Option<String>,
    #[serde(default)]
    pub authorization_signed_response_alg: Option<String>,
    #[serde(default)]
    pub authorization_encrypted_response_alg: Option<String>,
    #[serde(default)]
    pub authorization_encrypted_response_enc: Option<String>,
    #[serde(default, skip_deserializing)]
    pub allow_jwks_without_kid: bool,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct PatchClientRequest {
    pub client_name: Option<String>,
    pub redirect_uris: Option<Vec<String>>,
    pub post_logout_redirect_uris: Option<Vec<String>>,
    pub scopes: Option<Vec<String>>,
    pub allowed_audiences: Option<Vec<String>>,
    pub grant_types: Option<Vec<String>>,
    pub require_dpop_bound_tokens: Option<bool>,
    pub allow_client_assertion_audience_array: Option<bool>,
    pub allow_client_assertion_endpoint_audience: Option<bool>,
    pub require_par_request_object: Option<bool>,
    pub allow_authorization_code_without_pkce: Option<bool>,
    pub subject_type: Option<String>,
    pub sector_identifier_uri: Option<String>,
    pub backchannel_logout_uri: Option<String>,
    pub backchannel_logout_session_required: Option<bool>,
    pub frontchannel_logout_uri: Option<String>,
    pub frontchannel_logout_session_required: Option<bool>,
    pub tls_client_auth_subject_dn: Option<String>,
    pub tls_client_auth_cert_sha256: Option<String>,
    pub tls_client_auth_san_dns: Option<Vec<String>>,
    pub tls_client_auth_san_uri: Option<Vec<String>>,
    pub tls_client_auth_san_ip: Option<Vec<String>>,
    pub tls_client_auth_san_email: Option<Vec<String>>,
    pub jwks: Option<Value>,
    pub introspection_encrypted_response_alg: Option<String>,
    pub introspection_encrypted_response_enc: Option<String>,
    pub userinfo_signed_response_alg: Option<String>,
    pub userinfo_encrypted_response_alg: Option<String>,
    pub userinfo_encrypted_response_enc: Option<String>,
    pub authorization_signed_response_alg: Option<String>,
    pub authorization_encrypted_response_alg: Option<String>,
    pub authorization_encrypted_response_enc: Option<String>,
    pub is_active: Option<bool>,
}

#[derive(Clone)]
pub struct PreparedClientRegistration {
    pub tenant: TenantContext,
    pub registration: ValidatedClientRegistration,
    pub issued_secret: Option<String>,
    pub client_secret_hash: Option<String>,
    pub registration_access_token_blake3: Option<String>,
}

impl std::fmt::Debug for PreparedClientRegistration {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PreparedClientRegistration")
            .field("tenant", &self.tenant)
            .field("registration", &self.registration)
            .field(
                "issued_secret",
                &self.issued_secret.as_ref().map(|_| "[REDACTED]"),
            )
            .field(
                "client_secret_hash",
                &self.client_secret_hash.as_ref().map(|_| "[REDACTED]"),
            )
            .field(
                "registration_access_token_blake3",
                &self
                    .registration_access_token_blake3
                    .as_ref()
                    .map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

impl std::ops::Deref for PreparedClientRegistration {
    type Target = ValidatedClientRegistration;

    fn deref(&self) -> &Self::Target {
        &self.registration
    }
}

impl std::ops::DerefMut for PreparedClientRegistration {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.registration
    }
}

#[derive(Clone)]
pub struct CreatedClient {
    pub client: OAuthClient,
    pub issued_secret: Option<String>,
}

impl std::fmt::Debug for CreatedClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CreatedClient")
            .field("client", &self.client)
            .field(
                "issued_secret",
                &self.issued_secret.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

pub struct AdminClientService<R, S, C> {
    repository: R,
    sector_identifiers: S,
    crypto: C,
    policy: AdminClientPolicy,
}

impl<R, S, C> AdminClientService<R, S, C>
where
    R: AdminClientRepositoryPort,
    S: SectorIdentifierResolverPort,
    C: AdminClientCryptoPort,
{
    pub const fn new(
        repository: R,
        sector_identifiers: S,
        crypto: C,
        policy: AdminClientPolicy,
    ) -> Self {
        Self {
            repository,
            sector_identifiers,
            crypto,
            policy,
        }
    }

    pub async fn page(
        &self,
        offset: i64,
        limit: i64,
    ) -> Result<(Vec<OAuthClient>, i64), AdminClientError> {
        self.repository
            .page(offset, limit)
            .await
            .map_err(AdminClientError::Repository)
    }

    pub async fn detail(&self, client_id: &str) -> Result<OAuthClient, AdminClientError> {
        self.repository
            .by_client_id(self.policy.tenant.tenant_id.as_uuid(), client_id)
            .await
            .map_err(AdminClientError::Lookup)?
            .ok_or(AdminClientError::NotFound)
    }

    pub async fn create(
        &self,
        request: CreateClientRequest,
    ) -> Result<CreatedClient, AdminClientError> {
        let prepared = self.prepare_registration(request).await?;
        let issued_secret = prepared.issued_secret.clone();
        let client = insert_prepared_client(&self.repository, &prepared).await?;
        Ok(CreatedClient {
            client,
            issued_secret,
        })
    }

    /// Validate and prepare a registration for a caller that owns a wider transaction boundary.
    ///
    /// Access-request approval uses this path so the client row and approval state can still be
    /// committed by the PostgreSQL adapter in one transaction.
    pub async fn prepare_registration(
        &self,
        request: CreateClientRequest,
    ) -> Result<PreparedClientRegistration, AdminClientError> {
        prepare_client_registration(
            request,
            &self.policy,
            &self.sector_identifiers,
            &self.crypto,
        )
        .await
    }

    pub async fn update(
        &self,
        client_id: &str,
        request: PatchClientRequest,
    ) -> Result<OAuthClient, AdminClientError> {
        let current = self.detail(client_id).await?;
        let updated = prepare_client_patch(
            current,
            request,
            &self.policy,
            &self.sector_identifiers,
            &self.crypto,
        )
        .await?;
        self.repository
            .update(&updated)
            .await
            .map_err(AdminClientError::Write)
    }
}

pub async fn insert_prepared_client<R: AdminClientRepositoryPort>(
    repository: &R,
    prepared: &PreparedClientRegistration,
) -> Result<OAuthClient, AdminClientError> {
    let client = OAuthClient {
        id: Uuid::now_v7(),
        tenant_id: prepared.tenant.tenant_id.as_uuid(),
        realm_id: prepared.tenant.realm_id.as_uuid(),
        organization_id: prepared.tenant.organization_id.as_uuid(),
        registration: prepared.registration.clone(),
        require_mtls_bound_tokens: false,
        is_active: true,
    };
    let inserted = repository
        .insert(
            &client,
            prepared.client_secret_hash.as_deref(),
            prepared.registration_access_token_blake3.as_deref(),
        )
        .await
        .map_err(AdminClientError::Write)?;
    if inserted.tenant_id != client.tenant_id
        || inserted.realm_id != client.realm_id
        || inserted.organization_id != client.organization_id
    {
        return Err(AdminClientError::Consistency(
            "客户端写入后租户边界不匹配".to_owned(),
        ));
    }
    Ok(inserted)
}

pub async fn prepare_client_registration<S, C>(
    request: CreateClientRequest,
    policy: &AdminClientPolicy,
    sector_identifiers: &S,
    crypto: &C,
) -> Result<PreparedClientRegistration, AdminClientError>
where
    S: SectorIdentifierResolverPort + ?Sized,
    C: AdminClientCryptoPort + ?Sized,
{
    validate_pkce_compatibility_policy(
        request.allow_authorization_code_without_pkce,
        &request.client_type,
        request.require_dpop_bound_tokens,
    )?;
    validate_client_metadata(
        ClientMetadata::from_create(&request),
        &crypto.response_signing_algorithms(),
        crypto,
    )?;
    let (issued_secret, client_secret_hash) = if request.client_type == "confidential"
        && matches!(
            request.token_endpoint_auth_method.as_str(),
            "client_secret_basic" | "client_secret_post"
        ) {
        let (secret, digest) = crypto.issue_client_secret(&policy.client_secret_pepper);
        (Some(secret), Some(digest))
    } else {
        (None, None)
    };
    let subject_type = request.subject_type.unwrap_or_else(|| "public".to_owned());
    let redirect_uris = request.redirect_uris;
    let (sector_identifier_uri, sector_identifier_host) = pairwise_subject(
        &subject_type,
        request.sector_identifier_uri,
        &redirect_uris,
        policy.pairwise_subject_secret.as_deref(),
        sector_identifiers,
    )
    .await?;
    Ok(PreparedClientRegistration {
        tenant: policy.tenant,
        registration: ValidatedClientRegistration {
            client_id: format!("client-{}", Uuid::now_v7()),
            client_name: request.client_name,
            client_type: request.client_type,
            redirect_uris,
            post_logout_redirect_uris: trim_string_vec(request.post_logout_redirect_uris),
            scopes: request.scopes,
            allowed_audiences: request.allowed_audiences,
            grant_types: request.grant_types,
            token_endpoint_auth_method: request.token_endpoint_auth_method,
            subject_type,
            sector_identifier_uri,
            sector_identifier_host,
            require_dpop_bound_tokens: request.require_dpop_bound_tokens,
            allow_client_assertion_audience_array: request.allow_client_assertion_audience_array,
            allow_client_assertion_endpoint_audience: request
                .allow_client_assertion_endpoint_audience,
            require_par_request_object: request.require_par_request_object,
            allow_authorization_code_without_pkce: request.allow_authorization_code_without_pkce,
            backchannel_logout_uri: trim_optional_string(request.backchannel_logout_uri),
            backchannel_logout_session_required: request.backchannel_logout_session_required,
            frontchannel_logout_uri: trim_optional_string(request.frontchannel_logout_uri),
            frontchannel_logout_session_required: request.frontchannel_logout_session_required,
            tls_client_auth_subject_dn: trim_optional_string(request.tls_client_auth_subject_dn),
            tls_client_auth_cert_sha256: trim_optional_string(request.tls_client_auth_cert_sha256),
            tls_client_auth_san_dns: trim_string_vec(request.tls_client_auth_san_dns),
            tls_client_auth_san_uri: trim_string_vec(request.tls_client_auth_san_uri),
            tls_client_auth_san_ip: trim_string_vec(request.tls_client_auth_san_ip),
            tls_client_auth_san_email: trim_string_vec(request.tls_client_auth_san_email),
            jwks: request.jwks,
            introspection_encrypted_response_alg: trim_optional_string(
                request.introspection_encrypted_response_alg,
            ),
            introspection_encrypted_response_enc: trim_optional_string(
                request.introspection_encrypted_response_enc,
            ),
            userinfo_signed_response_alg: trim_optional_string(
                request.userinfo_signed_response_alg,
            ),
            userinfo_encrypted_response_alg: trim_optional_string(
                request.userinfo_encrypted_response_alg,
            ),
            userinfo_encrypted_response_enc: trim_optional_string(
                request.userinfo_encrypted_response_enc,
            ),
            authorization_signed_response_alg: trim_optional_string(
                request.authorization_signed_response_alg,
            ),
            authorization_encrypted_response_alg: trim_optional_string(
                request.authorization_encrypted_response_alg,
            ),
            authorization_encrypted_response_enc: trim_optional_string(
                request.authorization_encrypted_response_enc,
            ),
        },
        issued_secret,
        client_secret_hash,
        registration_access_token_blake3: None,
    })
}

pub async fn prepare_client_patch<S, C>(
    mut client: OAuthClient,
    request: PatchClientRequest,
    policy: &AdminClientPolicy,
    sector_identifiers: &S,
    crypto: &C,
) -> Result<OAuthClient, AdminClientError>
where
    S: SectorIdentifierResolverPort + ?Sized,
    C: AdminClientCryptoPort + ?Sized,
{
    let redirect_uris_changed = request.redirect_uris.is_some();
    if let Some(value) = request.client_name {
        client.client_name = value;
    }
    if let Some(value) = request.redirect_uris {
        client.redirect_uris = value;
    }
    if let Some(value) = request.post_logout_redirect_uris {
        client.post_logout_redirect_uris = value;
    }
    if let Some(value) = request.scopes {
        client.scopes = value;
    }
    if let Some(value) = request.allowed_audiences {
        client.allowed_audiences = value;
    }
    if let Some(value) = request.grant_types {
        client.grant_types = value;
    }
    if let Some(value) = request.require_dpop_bound_tokens {
        client.require_dpop_bound_tokens = value;
    }
    if let Some(value) = request.allow_client_assertion_audience_array {
        client.allow_client_assertion_audience_array = value;
    }
    if let Some(value) = request.allow_client_assertion_endpoint_audience {
        client.allow_client_assertion_endpoint_audience = value;
    }
    if let Some(value) = request.require_par_request_object {
        client.require_par_request_object = value;
    }
    if let Some(value) = request.allow_authorization_code_without_pkce {
        client.allow_authorization_code_without_pkce = value;
    }
    if let Some(value) = request.backchannel_logout_uri {
        client.backchannel_logout_uri = trim_optional_string(Some(value));
    }
    if let Some(value) = request.backchannel_logout_session_required {
        client.backchannel_logout_session_required = value;
    }
    if let Some(value) = request.frontchannel_logout_uri {
        client.frontchannel_logout_uri = trim_optional_string(Some(value));
    }
    if let Some(value) = request.frontchannel_logout_session_required {
        client.frontchannel_logout_session_required = value;
    }
    if let Some(value) = request.tls_client_auth_subject_dn {
        client.tls_client_auth_subject_dn = trim_optional_string(Some(value));
    }
    if let Some(value) = request.tls_client_auth_cert_sha256 {
        client.tls_client_auth_cert_sha256 = trim_optional_string(Some(value));
    }
    if let Some(value) = request.tls_client_auth_san_dns {
        client.tls_client_auth_san_dns = value;
    }
    if let Some(value) = request.tls_client_auth_san_uri {
        client.tls_client_auth_san_uri = value;
    }
    if let Some(value) = request.tls_client_auth_san_ip {
        client.tls_client_auth_san_ip = value;
    }
    if let Some(value) = request.tls_client_auth_san_email {
        client.tls_client_auth_san_email = value;
    }
    if let Some(value) = request.jwks {
        client.jwks = Some(value);
    }
    if let Some(value) = request.introspection_encrypted_response_alg {
        client.introspection_encrypted_response_alg = trim_optional_string(Some(value));
    }
    if let Some(value) = request.introspection_encrypted_response_enc {
        client.introspection_encrypted_response_enc = trim_optional_string(Some(value));
    }
    if let Some(value) = request.userinfo_signed_response_alg {
        client.userinfo_signed_response_alg = trim_optional_string(Some(value));
    }
    if let Some(value) = request.userinfo_encrypted_response_alg {
        client.userinfo_encrypted_response_alg = trim_optional_string(Some(value));
    }
    if let Some(value) = request.userinfo_encrypted_response_enc {
        client.userinfo_encrypted_response_enc = trim_optional_string(Some(value));
    }
    if let Some(value) = request.authorization_signed_response_alg {
        client.authorization_signed_response_alg = trim_optional_string(Some(value));
    }
    if let Some(value) = request.authorization_encrypted_response_alg {
        client.authorization_encrypted_response_alg = trim_optional_string(Some(value));
    }
    if let Some(value) = request.authorization_encrypted_response_enc {
        client.authorization_encrypted_response_enc = trim_optional_string(Some(value));
    }
    if let Some(value) = request.is_active {
        client.is_active = value;
    }

    let new_subject_type = request
        .subject_type
        .unwrap_or_else(|| client.subject_type.clone());
    let requested_sector_identifier_uri = match request.sector_identifier_uri {
        Some(_) if client.sector_identifier_uri.is_some() => {
            return Err(AdminClientError::InvalidRequest(
                "已配置 pairwise 客户端的 sector_identifier_uri 不可修改".to_owned(),
            ));
        }
        Some(uri) => Some(uri),
        None => client.sector_identifier_uri.clone(),
    };
    if new_subject_type != "pairwise" {
        client.sector_identifier_uri = None;
        client.sector_identifier_host = None;
    } else {
        if policy.pairwise_subject_secret.is_none() {
            return Err(AdminClientError::InvalidRequest(
                "pairwise 主题类型需要配置 PAIRWISE_SUBJECT_SECRET".to_owned(),
            ));
        }
        let host = match &requested_sector_identifier_uri {
            Some(uri)
                if !redirect_uris_changed
                    && client.sector_identifier_uri.as_deref() == Some(uri.as_str())
                    && client.sector_identifier_host.is_some() =>
            {
                client.sector_identifier_host.clone().ok_or_else(|| {
                    AdminClientError::Consistency(
                        "pairwise 客户端缺少 sector_identifier_host".to_owned(),
                    )
                })?
            }
            Some(uri) => {
                let uris = sector_identifiers.resolve(uri).await.map_err(|error| {
                    AdminClientError::InvalidRequest(format!(
                        "sector_identifier_uri 获取失败: {error}"
                    ))
                })?;
                sector_identifier_host_for_redirects(uri, &client.redirect_uris, &uris)?
            }
            None => client
                .sector_identifier_host
                .clone()
                .or_else(|| all_same_host(&client.redirect_uris))
                .ok_or_else(|| {
                    AdminClientError::InvalidRequest(
                        "pairwise 主题需要 sector_identifier_uri 或所有 redirect_uri 使用同一 host"
                            .to_owned(),
                    )
                })?,
        };
        client.sector_identifier_uri = requested_sector_identifier_uri;
        client.sector_identifier_host = Some(host);
    }
    client.subject_type = new_subject_type;

    validate_pkce_compatibility_policy(
        client.allow_authorization_code_without_pkce,
        &client.client_type,
        client.require_dpop_bound_tokens,
    )?;
    validate_client_metadata(
        ClientMetadata::from_client(&client),
        &crypto.response_signing_algorithms(),
        crypto,
    )?;
    Ok(client)
}

async fn pairwise_subject<S: SectorIdentifierResolverPort + ?Sized>(
    subject_type: &str,
    sector_identifier_uri: Option<String>,
    redirect_uris: &[String],
    pairwise_subject_secret: Option<&str>,
    resolver: &S,
) -> Result<(Option<String>, Option<String>), AdminClientError> {
    if subject_type != "pairwise" {
        return Ok((None, None));
    }
    if pairwise_subject_secret.is_none() {
        return Err(AdminClientError::InvalidRequest(
            "pairwise 主题类型需要配置 PAIRWISE_SUBJECT_SECRET".to_owned(),
        ));
    }
    let host = match sector_identifier_uri.as_deref() {
        Some(uri) => {
            let uris = resolver.resolve(uri).await.map_err(|error| {
                AdminClientError::InvalidRequest(format!("sector_identifier_uri 获取失败: {error}"))
            })?;
            sector_identifier_host_for_redirects(uri, redirect_uris, &uris)?
        }
        None => all_same_host(redirect_uris).ok_or_else(|| {
            AdminClientError::InvalidRequest(
                "pairwise 主题需要 sector_identifier_uri 或所有 redirect_uri 使用同一 host"
                    .to_owned(),
            )
        })?,
    };
    Ok((sector_identifier_uri, Some(host)))
}

fn trim_optional_string(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn trim_string_vec(values: Vec<String>) -> Vec<String> {
    values
        .into_iter()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .collect()
}

fn all_same_host(uris: &[String]) -> Option<String> {
    let mut hosts = uris
        .iter()
        .filter_map(|uri| url::Url::parse(uri).ok()?.host_str().map(ToOwned::to_owned));
    let first = hosts.next()?;
    hosts.all(|host| host == first).then_some(first)
}

fn sector_identifier_host_for_redirects(
    uri: &str,
    redirect_uris: &[String],
    sector_uris: &[String],
) -> Result<String, AdminClientError> {
    for redirect_uri in redirect_uris {
        if !sector_uris.contains(redirect_uri) {
            return Err(AdminClientError::InvalidRequest(format!(
                "redirect_uri {redirect_uri} 不在 sector_identifier_uri 返回列表中"
            )));
        }
    }
    url::Url::parse(uri)
        .ok()
        .and_then(|url| url.host_str().map(ToOwned::to_owned))
        .ok_or_else(|| {
            AdminClientError::InvalidRequest(
                "sector_identifier_uri host 解析失败: InvalidUri".to_owned(),
            )
        })
}

fn validate_pkce_compatibility_policy(
    allow_without_pkce: bool,
    client_type: &str,
    require_dpop: bool,
) -> Result<(), AdminClientError> {
    if !allow_without_pkce {
        return Ok(());
    }
    if client_type != "confidential" {
        return Err(AdminClientError::InvalidRequest(
            "PKCE compatibility exceptions are limited to confidential clients".to_owned(),
        ));
    }
    if require_dpop {
        return Err(AdminClientError::InvalidRequest(
            "DPoP-bound clients must use PKCE".to_owned(),
        ));
    }
    Ok(())
}
