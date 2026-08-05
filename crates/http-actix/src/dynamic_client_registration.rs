use std::{
    error::Error,
    fmt,
    future::Future,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    pin::Pin,
    sync::Arc,
};

use actix_web::{
    FromRequest, HttpRequest, HttpResponse,
    http::{StatusCode, header},
    web::{Data, Json, Path, Payload},
};
use chrono::Utc;
use nazo_auth::{
    AdminClientCryptoPort, AdminClientError, AdminClientPolicy, ClientSecretDigesterPort,
    DynamicClientRegistrationRequest, DynamicRegistrationError, DynamicRegistrationPolicy,
    DynamicRegistrationSecretPort, OAuthClient, PreparedClientRegistration,
    SectorIdentifierResolverPort, parse_client_configuration_update,
    prepare_dynamic_client_registration, response_types_from_client,
};
use nazo_identity::TenantContext;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::{
    authorization_error_response, empty_response, empty_response_no_store, json_response_no_store,
    json_response_status_no_store, oauth_bearer_error, oauth_error,
};

pub use nazo_auth::{
    DynamicRegistrationClientStore, DynamicRegistrationDependencyError, DynamicRegistrationFuture,
};

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
    remote_jwks: Arc<dyn RemoteJwksResolverPort>,
    crypto: Arc<dyn AdminClientCryptoPort>,
    secret_digester: Arc<dyn ClientSecretDigesterPort>,
    registration_tokens: Arc<dyn DynamicRegistrationSecretPort>,
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
    config: DynamicRegistrationEndpointConfig,
    clients: Arc<dyn DynamicRegistrationClientStore>,
    sector_identifiers: Arc<dyn SectorIdentifierResolverPort>,
    security: DynamicRegistrationSecurityServices,
    request_guard: Arc<dyn DynamicRegistrationRequestGuard>,
    client_ip: ClientIpConfig,
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

#[derive(Clone)]
pub struct ClientIpConfig {
    trusted_proxy_cidrs: Box<[IpCidr]>,
    header_mode: ClientIpHeaderMode,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientIpHeaderMode {
    None,
    Forwarded,
    XForwardedFor,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IpCidr {
    addr: IpAddr,
    prefix: u8,
}

impl ClientIpConfig {
    #[must_use]
    pub fn new(trusted_proxy_cidrs: &[IpCidr], header_mode: ClientIpHeaderMode) -> Self {
        Self {
            trusted_proxy_cidrs: trusted_proxy_cidrs.into(),
            header_mode,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientIpParseError(String);

impl fmt::Display for ClientIpParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Error for ClientIpParseError {}

impl ClientIpHeaderMode {
    pub fn parse(value: &str) -> Result<Self, ClientIpParseError> {
        match value.trim().to_ascii_lowercase().as_str() {
            "none" => Ok(Self::None),
            "forwarded" => Ok(Self::Forwarded),
            "x-forwarded-for" => Ok(Self::XForwardedFor),
            value => Err(ClientIpParseError(format!(
                "CLIENT_IP_HEADER_MODE must be none, forwarded, or x-forwarded-for, got {value}"
            ))),
        }
    }
}

impl IpCidr {
    pub fn parse(value: &str) -> Result<Self, ClientIpParseError> {
        let (addr, prefix) = value.trim().split_once('/').ok_or_else(|| {
            ClientIpParseError("trusted proxy CIDR must include prefix length".to_owned())
        })?;
        let addr = addr
            .parse::<IpAddr>()
            .map_err(|_| ClientIpParseError("trusted proxy CIDR address is invalid".to_owned()))?;
        let prefix = prefix
            .parse::<u8>()
            .map_err(|_| ClientIpParseError("trusted proxy CIDR prefix is invalid".to_owned()))?;
        let max_prefix = match addr {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if prefix > max_prefix {
            return Err(ClientIpParseError(
                "trusted proxy CIDR prefix is out of range".to_owned(),
            ));
        }
        Ok(Self { addr, prefix })
    }

    #[must_use]
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(network), IpAddr::V4(ip)) => {
                ipv4_prefix_value(network, self.prefix) == ipv4_prefix_value(ip, self.prefix)
            }
            (IpAddr::V6(network), IpAddr::V6(ip)) => {
                ipv6_prefix_value(network, self.prefix) == ipv6_prefix_value(ip, self.prefix)
            }
            _ => false,
        }
    }
}

pub fn parse_trusted_proxy_cidrs(raw: Option<String>) -> Result<Vec<IpCidr>, ClientIpParseError> {
    raw.unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(IpCidr::parse)
        .collect()
}

pub async fn dynamic_client_registration(
    endpoint: Data<DynamicRegistrationEndpoint>,
    request: HttpRequest,
    body: Payload,
) -> HttpResponse {
    if !endpoint.request_guard.accepts_new_requests() {
        return empty_response(StatusCode::NOT_FOUND);
    }
    let mut body = body.into_inner();
    let Json(payload) =
        match Json::<DynamicClientRegistrationRequest>::from_request(&request, &mut body).await {
            Ok(payload) => payload,
            Err(error) => return error.error_response(),
        };
    let source_ip = match enforce_rate_limit(&endpoint, &request).await {
        Ok(source_ip) => source_ip,
        Err(response) => return response,
    };
    let initial_access = match authorize_initial_access(&endpoint, &request).await {
        Ok(grant) => grant,
        Err(response) => return response,
    };

    let prepared = match prepare_dynamic_client_registration(
        payload,
        DynamicRegistrationPolicy {
            default_audience: &endpoint.config.default_audience,
            pairwise_subject_supported: endpoint.config.pairwise_subject_secret.is_some(),
            id_token_signing_algs: &endpoint.config.id_token_signing_algs,
            response_signing_algs: &endpoint.config.response_signing_algs,
            request_object_encryption_algs: &endpoint.config.request_object_encryption_algs,
            request_object_encryption_encs: &endpoint.config.request_object_encryption_encs,
        },
    ) {
        Ok(prepared) => prepared,
        Err(error) => return dynamic_registration_error_response(error),
    };
    let response_types = prepared.response_types.clone();
    let registration_access_token = endpoint.security.registration_tokens.random_token();
    let prepared_insert = match prepare_insert(
        &endpoint,
        prepared,
        &registration_access_token,
        initial_access.conformance_lease_id(),
        None,
    )
    .await
    {
        Ok(prepared) => prepared,
        Err(AdminClientError::InvalidRequest(message)) => {
            return dynamic_registration_error_response(map_insert_error(message));
        }
        Err(_error) => {
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "Dynamic client registration failed.",
            );
        }
    };
    let issued_secret = prepared_insert.issued_secret.clone();
    match endpoint.clients.insert(&prepared_insert).await {
        Ok(client) => {
            endpoint
                .request_guard
                .audit("dynamic_client_registered", &client, &source_ip);
            dynamic_registration_created_response(
                &client,
                &response_types,
                issued_secret,
                &endpoint.config.issuer,
                &registration_access_token,
            )
        }
        Err(_error) => oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "Dynamic client registration failed.",
        ),
    }
}

pub async fn client_configuration_get(
    endpoint: Data<DynamicRegistrationEndpoint>,
    request: HttpRequest,
    path: Path<String>,
) -> HttpResponse {
    if !endpoint.request_guard.accepts_new_requests() {
        return empty_response(StatusCode::NOT_FOUND);
    }
    let source_ip = match enforce_rate_limit(&endpoint, &request).await {
        Ok(source_ip) => source_ip,
        Err(response) => return response,
    };
    let (current, _authenticated_token_hash, registration_access_token) =
        match authenticate_registration_client(&endpoint, &request, &path).await {
            Ok(authenticated) => authenticated,
            Err(response) => return response,
        };
    let response_types = response_types_from_client(&current);
    endpoint
        .request_guard
        .audit("dynamic_client_configuration_read", &current, &source_ip);
    json_response_no_store(dynamic_registration_response(
        &current,
        &response_types,
        None,
        &endpoint.config.issuer,
        &registration_access_token,
    ))
}

pub async fn client_configuration_put(
    endpoint: Data<DynamicRegistrationEndpoint>,
    request: HttpRequest,
    path: Path<String>,
    body: Payload,
) -> HttpResponse {
    if !endpoint.request_guard.accepts_new_requests() {
        return empty_response(StatusCode::NOT_FOUND);
    }
    let mut body = body.into_inner();
    let Json(payload) = match Json::<Value>::from_request(&request, &mut body).await {
        Ok(payload) => payload,
        Err(error) => return error.error_response(),
    };
    let source_ip = match enforce_rate_limit(&endpoint, &request).await {
        Ok(source_ip) => source_ip,
        Err(response) => return response,
    };
    let (current, authenticated_token_hash, _) =
        match authenticate_registration_client(&endpoint, &request, &path).await {
            Ok(authenticated) => authenticated,
            Err(response) => return response,
        };
    let has_secret = match endpoint.clients.has_client_secret(current.id).await {
        Ok(has_secret) => has_secret,
        Err(_error) => {
            return lookup_failed();
        }
    };
    let secret_matches = match submitted_secret_matches(&endpoint, &current, &payload).await {
        Ok(matches) => matches,
        Err(_error) => {
            return lookup_failed();
        }
    };
    let payload =
        match parse_client_configuration_update(payload, &current, has_secret, secret_matches) {
            Ok(payload) => payload,
            Err(error) => return dynamic_registration_error_response(error),
        };
    let registration = match prepare_dynamic_client_registration(
        payload,
        DynamicRegistrationPolicy {
            default_audience: &endpoint.config.default_audience,
            pairwise_subject_supported: endpoint.config.pairwise_subject_secret.is_some(),
            id_token_signing_algs: &endpoint.config.id_token_signing_algs,
            response_signing_algs: &endpoint.config.response_signing_algs,
            request_object_encryption_algs: &endpoint.config.request_object_encryption_algs,
            request_object_encryption_encs: &endpoint.config.request_object_encryption_encs,
        },
    ) {
        Ok(registration) => registration,
        Err(error) => return dynamic_registration_error_response(error),
    };
    let response_types = registration.response_types.clone();
    let registration_access_token = endpoint.security.registration_tokens.random_token();
    let prepared = match prepare_insert(
        &endpoint,
        registration,
        &registration_access_token,
        None,
        current.security_policy.as_ref(),
    )
    .await
    {
        Ok(prepared) => prepared,
        Err(AdminClientError::InvalidRequest(message)) => {
            return dynamic_registration_error_response(map_insert_error(message));
        }
        Err(_error) => {
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "Client configuration update failed.",
            );
        }
    };
    let issued_secret = prepared.issued_secret.clone();
    let mut registration = prepared.registration.clone();
    registration.security_policy = current.security_policy.clone();
    let updated = OAuthClient {
        id: current.id,
        tenant_id: current.tenant_id,
        realm_id: current.realm_id,
        organization_id: current.organization_id,
        registration,
        require_mtls_bound_tokens: prepared.require_mtls_bound_tokens,
        is_active: current.is_active,
    };
    let client = match endpoint
        .clients
        .replace_registration(
            &updated,
            prepared.client_secret_hash.as_deref(),
            &authenticated_token_hash,
            prepared.registration_access_token_blake3.as_deref(),
        )
        .await
    {
        Ok(client) => client,
        Err(DynamicRegistrationDependencyError::StaleCredentials) => {
            return registration_access_denied();
        }
        Err(DynamicRegistrationDependencyError::Unavailable) => {
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "Client configuration update failed.",
            );
        }
    };
    endpoint
        .request_guard
        .audit("dynamic_client_configuration_updated", &client, &source_ip);
    json_response_no_store(dynamic_registration_response(
        &client,
        &response_types,
        issued_secret,
        &endpoint.config.issuer,
        &registration_access_token,
    ))
}

pub async fn client_configuration_delete(
    endpoint: Data<DynamicRegistrationEndpoint>,
    request: HttpRequest,
    path: Path<String>,
) -> HttpResponse {
    if !endpoint.request_guard.accepts_new_requests() {
        return empty_response(StatusCode::NOT_FOUND);
    }
    let source_ip = match enforce_rate_limit(&endpoint, &request).await {
        Ok(source_ip) => source_ip,
        Err(response) => return response,
    };
    let (current, authenticated_token_hash, _) =
        match authenticate_registration_client(&endpoint, &request, &path).await {
            Ok(authenticated) => authenticated,
            Err(response) => return response,
        };
    match endpoint
        .clients
        .deactivate(current.tenant_id, current.id, &authenticated_token_hash)
        .await
    {
        Ok(true) => {}
        Err(DynamicRegistrationDependencyError::StaleCredentials) => {
            return registration_access_denied();
        }
        Ok(false) | Err(DynamicRegistrationDependencyError::Unavailable) => {
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "Client deletion failed.",
            );
        }
    }
    endpoint
        .request_guard
        .audit("dynamic_client_deleted", &current, &source_ip);
    empty_response_no_store(StatusCode::NO_CONTENT)
}

async fn prepare_insert(
    endpoint: &DynamicRegistrationEndpoint,
    mut registration: nazo_auth::PreparedDynamicClientRegistration,
    registration_access_token: &str,
    conformance_lease_id: Option<Uuid>,
    security_policy_override: Option<&nazo_auth::ClientSecurityPolicy>,
) -> Result<PreparedClientRegistration, AdminClientError> {
    if let Some(uri) = registration.jwks_uri.as_deref() {
        registration.jwks = Some(endpoint.security.remote_jwks.resolve(uri).await.map_err(
            |error| {
                AdminClientError::InvalidRequest(format!("jwks_uri could not be resolved: {error}"))
            },
        )?);
    }
    let mut request = registration.into_create_client_request();
    request.conformance_lease_id = conformance_lease_id;
    if let Some(security_policy) = security_policy_override {
        request.security_policy = security_policy.clone();
    }
    if conformance_lease_id.is_some() && request.client_type == "confidential" {
        request.security_policy.allow_confidential_oidc_without_pkce = true;
    }
    let policy = AdminClientPolicy {
        tenant: TenantContext::default_system(),
        pairwise_subject_secret: endpoint.config.pairwise_subject_secret.clone(),
        client_secret_pepper: endpoint.config.client_secret_pepper.clone(),
    };
    let mut prepared = nazo_auth::prepare_client_registration(
        request,
        &policy,
        endpoint.sector_identifiers.as_ref(),
        endpoint.security.crypto.as_ref(),
    )
    .await?;
    prepared.registration_access_token_blake3 = Some(
        endpoint
            .security
            .registration_tokens
            .token_hash(registration_access_token),
    );
    Ok(prepared)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DynamicRegistrationInitialAccessGrant {
    Configured,
    ConformanceLease(Uuid),
}

impl DynamicRegistrationInitialAccessGrant {
    fn conformance_lease_id(self) -> Option<Uuid> {
        match self {
            Self::Configured => None,
            Self::ConformanceLease(lease_id) => Some(lease_id),
        }
    }
}

async fn authorize_initial_access(
    endpoint: &DynamicRegistrationEndpoint,
    request: &HttpRequest,
) -> Result<DynamicRegistrationInitialAccessGrant, HttpResponse> {
    let authorization_header = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok());
    if initial_access_token_authorized(
        endpoint.security.registration_tokens.as_ref(),
        authorization_header,
        endpoint.config.initial_access_token.as_deref(),
    ) {
        return Ok(DynamicRegistrationInitialAccessGrant::Configured);
    }
    let Some(actual) = bearer_token(request) else {
        return Err(initial_access_denied());
    };
    match endpoint
        .request_guard
        .conformance_lease_for_initial_access_token(actual)
        .await
    {
        Ok(Some(lease_id)) => Ok(DynamicRegistrationInitialAccessGrant::ConformanceLease(
            lease_id,
        )),
        Ok(None) => Err(initial_access_denied()),
        Err(_) => Err(oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "Dynamic client registration authentication failed.",
        )),
    }
}

async fn authenticate_registration_client(
    endpoint: &DynamicRegistrationEndpoint,
    request: &HttpRequest,
    client_id: &str,
) -> Result<(OAuthClient, String, String), HttpResponse> {
    let Some(token) = bearer_token(request) else {
        return Err(registration_access_denied());
    };
    let token_hash = endpoint.security.registration_tokens.token_hash(token);
    match endpoint
        .clients
        .by_registration_access_token(
            TenantContext::default_system().tenant_id.as_uuid(),
            client_id,
            &token_hash,
        )
        .await
    {
        Ok(Some(client)) => Ok((client, token_hash, token.to_owned())),
        Ok(None) => Err(registration_access_denied()),
        Err(_error) => Err(lookup_failed()),
    }
}

async fn submitted_secret_matches(
    endpoint: &DynamicRegistrationEndpoint,
    current: &OAuthClient,
    payload: &Value,
) -> Result<bool, DynamicRegistrationDependencyError> {
    let Some(secret) = payload.get("client_secret").and_then(Value::as_str) else {
        return Ok(false);
    };
    let Some(salt) = endpoint.clients.client_secret_salt(current.id).await? else {
        return Ok(false);
    };
    let candidate = endpoint.security.secret_digester.client_secret_digest(
        secret,
        &endpoint.config.client_secret_pepper,
        &salt,
    );
    endpoint
        .clients
        .client_secret_digest_matches(current.id, &candidate)
        .await
}

async fn enforce_rate_limit(
    endpoint: &DynamicRegistrationEndpoint,
    request: &HttpRequest,
) -> Result<String, HttpResponse> {
    let source_ip = client_ip_with_config(request, &endpoint.client_ip);
    match endpoint.request_guard.enforce_rate_limit(&source_ip).await {
        Ok(()) => Ok(source_ip),
        Err(DynamicRegistrationRateLimitError::Unavailable) => Err(oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "请求频率校验失败.",
        )),
        Err(DynamicRegistrationRateLimitError::Limited {
            retry_after_seconds,
        }) => {
            let mut response = authorization_error_response(
                StatusCode::TOO_MANY_REQUESTS,
                "temporarily_unavailable",
                "请求过于频繁，请稍后重试.",
            );
            if let Ok(value) = header::HeaderValue::from_str(&retry_after_seconds.to_string()) {
                response.headers_mut().insert(header::RETRY_AFTER, value);
            }
            Err(response)
        }
    }
}

#[must_use]
pub fn client_ip_with_config(request: &HttpRequest, config: &ClientIpConfig) -> String {
    client_ip_with_context(request, config.header_mode, &config.trusted_proxy_cidrs)
}

#[must_use]
pub fn client_ip_with_context(
    request: &HttpRequest,
    header_mode: ClientIpHeaderMode,
    trusted_proxy_cidrs: &[IpCidr],
) -> String {
    let Some(peer_ip) = request.peer_addr().map(|address| address.ip()) else {
        return "unknown".to_owned();
    };
    if header_mode == ClientIpHeaderMode::None
        || !trusted_proxy_peer_ip(peer_ip, trusted_proxy_cidrs)
    {
        return peer_ip.to_string();
    }
    let parsed = match header_mode {
        ClientIpHeaderMode::None => None,
        ClientIpHeaderMode::Forwarded => forwarded_ip_chain(request)
            .and_then(|chain| nearest_untrusted_hop(chain, peer_ip, trusted_proxy_cidrs)),
        ClientIpHeaderMode::XForwardedFor => x_forwarded_for_ip_chain(request)
            .and_then(|chain| nearest_untrusted_hop(chain, peer_ip, trusted_proxy_cidrs)),
    };
    parsed.unwrap_or(peer_ip).to_string()
}

#[must_use]
pub fn request_from_trusted_proxy_cidrs(
    request: &HttpRequest,
    trusted_proxy_cidrs: &[IpCidr],
) -> bool {
    request
        .peer_addr()
        .is_some_and(|address| trusted_proxy_peer_ip(address.ip(), trusted_proxy_cidrs))
}

fn trusted_proxy_peer_ip(peer_ip: IpAddr, trusted_proxy_cidrs: &[IpCidr]) -> bool {
    trusted_proxy_cidrs
        .iter()
        .any(|cidr| cidr.contains(peer_ip))
}

fn forwarded_ip_chain(request: &HttpRequest) -> Option<Vec<IpAddr>> {
    let mut values = request.headers().get_all("forwarded");
    let raw = values.next()?.to_str().ok()?;
    if values.next().is_some() {
        return None;
    }
    let mut chain = Vec::new();
    for element in raw.split(',') {
        if element.trim().is_empty() {
            return None;
        }
        let mut forwarded_for = None;
        for parameter in element.split(';') {
            let (name, value) = parameter.trim().split_once('=')?;
            if name.trim().eq_ignore_ascii_case("for") {
                if forwarded_for.is_some() {
                    return None;
                }
                forwarded_for = Some(parse_forwarded_for_value(value.trim())?);
            }
        }
        chain.push(forwarded_for?);
    }
    (!chain.is_empty()).then_some(chain)
}

#[must_use]
pub fn parse_forwarded_for_value(value: &str) -> Option<IpAddr> {
    let value = match (value.strip_prefix('"'), value.strip_suffix('"')) {
        (Some(without_prefix), Some(_)) => without_prefix.strip_suffix('"')?,
        (None, None) => value,
        _ => return None,
    };
    if let Some(ip) = value
        .strip_prefix('[')
        .and_then(|rest| rest.split_once(']').map(|(ip, _)| ip))
    {
        return ip.parse().ok();
    }
    let host = value.rsplit_once(':').and_then(|(host, port)| {
        port.parse::<u16>().ok()?;
        Some(host)
    });
    host.unwrap_or(value).parse().ok()
}

fn x_forwarded_for_ip_chain(request: &HttpRequest) -> Option<Vec<IpAddr>> {
    let mut values = request.headers().get_all("x-forwarded-for");
    let raw = values.next()?.to_str().ok()?;
    if values.next().is_some() {
        return None;
    }
    let chain = raw
        .split(',')
        .map(str::trim)
        .map(str::parse::<IpAddr>)
        .collect::<Result<Vec<_>, _>>()
        .ok()?;
    (!chain.is_empty()).then_some(chain)
}

fn nearest_untrusted_hop(
    chain: Vec<IpAddr>,
    peer_ip: IpAddr,
    trusted_proxy_cidrs: &[IpCidr],
) -> Option<IpAddr> {
    chain
        .into_iter()
        .chain(std::iter::once(peer_ip))
        .rev()
        .find(|ip| !trusted_proxy_peer_ip(*ip, trusted_proxy_cidrs))
}

fn ipv4_prefix_value(ip: Ipv4Addr, prefix: u8) -> u32 {
    if prefix == 0 {
        return 0;
    }
    u32::from(ip) >> (32 - prefix)
}

fn ipv6_prefix_value(ip: Ipv6Addr, prefix: u8) -> u128 {
    if prefix == 0 {
        return 0;
    }
    u128::from(ip) >> (128 - prefix)
}

fn initial_access_token_authorized(
    secrets: &dyn DynamicRegistrationSecretPort,
    authorization_header: Option<&str>,
    expected_token: Option<&str>,
) -> bool {
    let Some(expected_token) = expected_token else {
        return false;
    };
    let Some(actual) = authorization_header.and_then(parse_bearer) else {
        return false;
    };
    secrets.constant_time_eq(actual.as_bytes(), expected_token.as_bytes())
}

fn bearer_token(request: &HttpRequest) -> Option<&str> {
    request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(parse_bearer)
}

fn parse_bearer(value: &str) -> Option<&str> {
    let mut parts = value.trim().splitn(2, char::is_whitespace);
    let scheme = parts.next()?.trim();
    let token = parts.next()?.trim();
    (scheme.eq_ignore_ascii_case("Bearer")
        && !token.is_empty()
        && token.split_whitespace().count() == 1)
        .then_some(token)
}

fn initial_access_denied() -> HttpResponse {
    oauth_bearer_error(
        StatusCode::UNAUTHORIZED,
        "invalid_token",
        "Initial access token is missing or invalid.",
    )
}

fn registration_access_denied() -> HttpResponse {
    oauth_bearer_error(
        StatusCode::UNAUTHORIZED,
        "invalid_token",
        "Registration access token is missing or invalid.",
    )
}

fn lookup_failed() -> HttpResponse {
    oauth_error(
        StatusCode::SERVICE_UNAVAILABLE,
        "server_error",
        "Client configuration lookup failed.",
    )
}

fn map_insert_error(message: String) -> DynamicRegistrationError {
    let error = if message.contains("redirect_uri") {
        "invalid_redirect_uri"
    } else {
        "invalid_client_metadata"
    };
    DynamicRegistrationError::new(error, message)
}

fn dynamic_registration_error_response(error: DynamicRegistrationError) -> HttpResponse {
    oauth_error(StatusCode::BAD_REQUEST, error.error, &error.description)
}

fn dynamic_registration_created_response(
    client: &OAuthClient,
    response_types: &[String],
    issued_secret: Option<String>,
    issuer: &str,
    registration_access_token: &str,
) -> HttpResponse {
    let mut body = dynamic_registration_response(
        client,
        response_types,
        issued_secret,
        issuer,
        registration_access_token,
    );
    body["client_id_issued_at"] = json!(Utc::now().timestamp());
    json_response_status_no_store(StatusCode::CREATED, body)
}

fn dynamic_registration_response(
    client: &OAuthClient,
    response_types: &[String],
    issued_secret: Option<String>,
    issuer: &str,
    registration_access_token: &str,
) -> Value {
    let mut body = json!({
        "client_id": client.client_id,
        "client_name": client.client_name,
        "registration_access_token": registration_access_token,
        "registration_client_uri": format!("{issuer}/register/{}", encode_path_segment(&client.client_id)),
        "redirect_uris": client.redirect_uris,
        "grant_types": client.grant_types,
        "response_types": response_types,
        "scope": client.scopes.join(" "),
        "token_endpoint_auth_method": client.token_endpoint_auth_method,
        "dpop_bound_access_tokens": client.require_dpop_bound_tokens,
        "tls_client_certificate_bound_access_tokens": client.require_mtls_bound_tokens,
        "subject_type": client.subject_type,
        "post_logout_redirect_uris": client.post_logout_redirect_uris,
        "backchannel_logout_session_required": client.backchannel_logout_session_required,
        "backchannel_token_delivery_mode": client.backchannel_token_delivery_mode,
        "backchannel_user_code_parameter": client.backchannel_user_code_parameter,
        "frontchannel_logout_session_required": client.frontchannel_logout_session_required,
    });
    if let Some(uri) = &client.backchannel_logout_uri {
        body["backchannel_logout_uri"] = json!(uri);
    }
    if let Some(uri) = &client.backchannel_client_notification_endpoint {
        body["backchannel_client_notification_endpoint"] = json!(uri);
    }
    if let Some(alg) = &client.backchannel_authentication_request_signing_alg {
        body["backchannel_authentication_request_signing_alg"] = json!(alg);
    }
    if let Some(uri) = &client.frontchannel_logout_uri {
        body["frontchannel_logout_uri"] = json!(uri);
    }
    if let Some(subject_dn) = &client.tls_client_auth_subject_dn {
        body["tls_client_auth_subject_dn"] = json!(subject_dn);
    }
    for (field, values) in [
        ("tls_client_auth_san_dns", &client.tls_client_auth_san_dns),
        ("tls_client_auth_san_uri", &client.tls_client_auth_san_uri),
        ("tls_client_auth_san_ip", &client.tls_client_auth_san_ip),
        (
            "tls_client_auth_san_email",
            &client.tls_client_auth_san_email,
        ),
    ] {
        if let [value] = values.as_slice() {
            body[field] = json!(value);
        }
    }
    if let Some(jwks_uri) = &client.jwks_uri {
        body["jwks_uri"] = json!(jwks_uri);
    } else if let Some(jwks) = &client.jwks {
        body["jwks"] = jwks.clone();
    }
    if !client.request_uris.is_empty() {
        body["request_uris"] = json!(client.request_uris);
    }
    if let Some(initiate_login_uri) = &client.initiate_login_uri {
        body["initiate_login_uri"] = json!(initiate_login_uri);
    }
    if let Some(logo_uri) = &client.presentation.logo_uri {
        body["logo_uri"] = json!(logo_uri);
    }
    if let Some(policy_uri) = &client.presentation.policy_uri {
        body["policy_uri"] = json!(policy_uri);
    }
    if let Some(tos_uri) = &client.presentation.tos_uri {
        body["tos_uri"] = json!(tos_uri);
    }
    for (field, value) in [
        (
            "id_token_signed_response_alg",
            client.id_token_signed_response_alg.as_ref(),
        ),
        (
            "id_token_encrypted_response_alg",
            client.id_token_encrypted_response_alg.as_ref(),
        ),
        (
            "id_token_encrypted_response_enc",
            client.id_token_encrypted_response_enc.as_ref(),
        ),
        (
            "request_object_signing_alg",
            client.request_object_signing_alg.as_ref(),
        ),
        (
            "request_object_encryption_alg",
            client.request_object_encryption_alg.as_ref(),
        ),
        (
            "request_object_encryption_enc",
            client.request_object_encryption_enc.as_ref(),
        ),
        (
            "token_endpoint_auth_signing_alg",
            client.token_endpoint_auth_signing_alg.as_ref(),
        ),
        (
            "introspection_signed_response_alg",
            client.introspection_signed_response_alg.as_ref(),
        ),
        (
            "introspection_encrypted_response_alg",
            client.introspection_encrypted_response_alg.as_ref(),
        ),
        (
            "introspection_encrypted_response_enc",
            client.introspection_encrypted_response_enc.as_ref(),
        ),
        (
            "userinfo_signed_response_alg",
            client.userinfo_signed_response_alg.as_ref(),
        ),
        (
            "userinfo_encrypted_response_alg",
            client.userinfo_encrypted_response_alg.as_ref(),
        ),
        (
            "userinfo_encrypted_response_enc",
            client.userinfo_encrypted_response_enc.as_ref(),
        ),
        (
            "authorization_signed_response_alg",
            client.authorization_signed_response_alg.as_ref(),
        ),
        (
            "authorization_encrypted_response_alg",
            client.authorization_encrypted_response_alg.as_ref(),
        ),
        (
            "authorization_encrypted_response_enc",
            client.authorization_encrypted_response_enc.as_ref(),
        ),
    ] {
        if let Some(value) = value {
            body[field] = json!(value);
        }
    }
    if let Some(secret) = issued_secret {
        body["client_secret"] = json!(secret);
        body["client_secret_expires_at"] = json!(0);
    }
    body
}

fn encode_path_segment(value: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
    }
    encoded
}

#[cfg(test)]
#[path = "../tests/unit/dynamic_client_registration.rs"]
mod tests;
