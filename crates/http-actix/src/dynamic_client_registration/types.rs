use std::{future::Future, pin::Pin, sync::Arc};

use nazo_auth::{
    AdminClientCryptoPort, ClientSecretDigesterPort, DynamicRegistrationClientStore,
    DynamicRegistrationFuture, DynamicRegistrationSecretPort, OAuthClient,
    SectorIdentifierResolverPort,
};
use serde_json::Value;
use uuid::Uuid;

use super::ip::{ClientIpConfig, ClientIpHeaderMode, IpCidr};

pub type RemoteJwksFuture<'a> = Pin<Box<dyn Future<Output = Result<Value, String>> + Send + 'a>>;

/// Resolves a remote JWKS under the embedding server's outbound-document policy.
pub trait RemoteJwksResolverPort: Send + Sync {
    fn resolve<'a>(&'a self, uri: &'a str) -> RemoteJwksFuture<'a>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DynamicRegistrationRateLimitError {
    Limited { retry_after_seconds: u64 },
    Unavailable,
}

pub trait DynamicRegistrationRequestGuard: Send + Sync {
    fn accepts_new_requests(&self) -> bool;

    fn enforce_rate_limit<'a>(
        &'a self,
        source_ip: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(), DynamicRegistrationRateLimitError>> + Send + 'a>>;

    /// Resolves a non-configured initial access token to one effective
    /// conformance lease. Implementations must derive and compare a
    /// non-reversible digest rather than persist or log the bearer token.
    fn conformance_lease_for_initial_access_token<'a>(
        &'a self,
        token: &'a str,
    ) -> DynamicRegistrationFuture<'a, Option<Uuid>>;

    fn audit(&self, event: &'static str, client: &OAuthClient, source_ip: &str);
}

#[derive(Clone)]
pub struct DynamicRegistrationEndpointConfig {
    pub issuer: String,
    pub default_audience: String,
    pub pairwise_subject_secret: Option<String>,
    pub client_secret_pepper: String,
    pub initial_access_token: Option<String>,
    pub client_ip_header_mode: ClientIpHeaderMode,
    pub trusted_proxy_cidrs: Vec<IpCidr>,
    pub id_token_signing_algs: Vec<&'static str>,
    pub response_signing_algs: Vec<&'static str>,
    pub request_object_encryption_algs: Vec<&'static str>,
    pub request_object_encryption_encs: Vec<&'static str>,
}

#[derive(Clone)]
pub struct DynamicRegistrationSecurityServices {
    pub(super) remote_jwks: Arc<dyn RemoteJwksResolverPort>,
    pub(super) crypto: Arc<dyn AdminClientCryptoPort>,
    pub(super) secret_digester: Arc<dyn ClientSecretDigesterPort>,
    pub(super) registration_tokens: Arc<dyn DynamicRegistrationSecretPort>,
}

impl DynamicRegistrationSecurityServices {
    pub fn new(
        remote_jwks: Arc<dyn RemoteJwksResolverPort>,
        crypto: Arc<dyn AdminClientCryptoPort>,
        secret_digester: Arc<dyn ClientSecretDigesterPort>,
        registration_tokens: Arc<dyn DynamicRegistrationSecretPort>,
    ) -> Self {
        Self {
            remote_jwks,
            crypto,
            secret_digester,
            registration_tokens,
        }
    }
}

#[derive(Clone)]
pub struct DynamicRegistrationEndpoint {
    pub(super) config: DynamicRegistrationEndpointConfig,
    pub(super) clients: Arc<dyn DynamicRegistrationClientStore>,
    pub(super) sector_identifiers: Arc<dyn SectorIdentifierResolverPort>,
    pub(super) security: DynamicRegistrationSecurityServices,
    pub(super) request_guard: Arc<dyn DynamicRegistrationRequestGuard>,
    pub(super) client_ip: ClientIpConfig,
}

impl DynamicRegistrationEndpoint {
    pub fn new(
        config: DynamicRegistrationEndpointConfig,
        clients: Arc<dyn DynamicRegistrationClientStore>,
        sector_identifiers: Arc<dyn SectorIdentifierResolverPort>,
        security: DynamicRegistrationSecurityServices,
        request_guard: Arc<dyn DynamicRegistrationRequestGuard>,
    ) -> Self {
        let client_ip =
            ClientIpConfig::new(&config.trusted_proxy_cidrs, config.client_ip_header_mode);
        Self {
            config,
            clients,
            sector_identifiers,
            security,
            request_guard,
            client_ip,
        }
    }
}
