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

use crate::{
    authorization_error_response, empty_response, empty_response_no_store, json_response_no_store,
    json_response_status_no_store, oauth_bearer_error, oauth_error,
};

pub use nazo_auth::DynamicRegistrationSecretPort as DynamicRegistrationSecurity;
pub use nazo_auth::{
    DynamicRegistrationClientStore, DynamicRegistrationDependencyError, DynamicRegistrationFuture,
};

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
}

#[derive(Clone)]
pub struct DynamicRegistrationEndpoint {
    config: DynamicRegistrationEndpointConfig,
    clients: Arc<dyn DynamicRegistrationClientStore>,
    sector_identifiers: Arc<dyn SectorIdentifierResolverPort>,
    crypto: Arc<dyn AdminClientCryptoPort>,
    secret_digester: Arc<dyn ClientSecretDigesterPort>,
    secrets: Arc<dyn DynamicRegistrationSecretPort>,
    request_guard: Arc<dyn DynamicRegistrationRequestGuard>,
    client_ip: ClientIpConfig,
}

impl DynamicRegistrationEndpoint {
    pub fn new(
        config: DynamicRegistrationEndpointConfig,
        clients: Arc<dyn DynamicRegistrationClientStore>,
        sector_identifiers: Arc<dyn SectorIdentifierResolverPort>,
        crypto: Arc<dyn AdminClientCryptoPort>,
        secret_digester: Arc<dyn ClientSecretDigesterPort>,
        secrets: Arc<dyn DynamicRegistrationSecretPort>,
        request_guard: Arc<dyn DynamicRegistrationRequestGuard>,
    ) -> Self {
        let client_ip =
            ClientIpConfig::new(&config.trusted_proxy_cidrs, config.client_ip_header_mode);
        Self {
            config,
            clients,
            sector_identifiers,
            crypto,
            secret_digester,
            secrets,
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
    if !initial_access_token_authorized(
        endpoint.secrets.as_ref(),
        request
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok()),
        endpoint.config.initial_access_token.as_deref(),
    ) {
        return oauth_bearer_error(
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            "Initial access token is missing or invalid.",
        );
    }

    let prepared = match prepare_dynamic_client_registration(
        payload,
        DynamicRegistrationPolicy {
            default_audience: &endpoint.config.default_audience,
        },
    ) {
        Ok(prepared) => prepared,
        Err(error) => return dynamic_registration_error_response(error),
    };
    let response_types = prepared.response_types.clone();
    let registration_access_token = endpoint.secrets.random_token();
    let prepared_insert =
        match prepare_insert(&endpoint, prepared, &registration_access_token).await {
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
    let current = match authenticate_registration_client(&endpoint, &request, &path).await {
        Ok(client) => client,
        Err(response) => return response,
    };
    let response_types = response_types_from_client(&current);
    let registration_access_token = endpoint.secrets.random_token();
    let (issued_secret, client_secret_hash) = issue_client_secret(&endpoint, &current);
    let client = match endpoint
        .clients
        .rotate_credentials(
            current.tenant_id,
            current.id,
            client_secret_hash.as_deref(),
            &endpoint.secrets.token_hash(&registration_access_token),
        )
        .await
    {
        Ok(client) => client,
        Err(_error) => {
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "Client configuration update failed.",
            );
        }
    };
    endpoint
        .request_guard
        .audit("dynamic_client_configuration_read", &client, &source_ip);
    json_response_no_store(dynamic_registration_response(
        &client,
        &response_types,
        issued_secret,
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
    let current = match authenticate_registration_client(&endpoint, &request, &path).await {
        Ok(client) => client,
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
        },
    ) {
        Ok(registration) => registration,
        Err(error) => return dynamic_registration_error_response(error),
    };
    let response_types = registration.response_types.clone();
    let registration_access_token = endpoint.secrets.random_token();
    let prepared = match prepare_insert(&endpoint, registration, &registration_access_token).await {
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
    let updated = OAuthClient {
        id: current.id,
        tenant_id: current.tenant_id,
        realm_id: current.realm_id,
        organization_id: current.organization_id,
        registration: prepared.registration.clone(),
        require_mtls_bound_tokens: current.require_mtls_bound_tokens,
        is_active: current.is_active,
    };
    let client = match endpoint
        .clients
        .replace_registration(
            &updated,
            prepared.client_secret_hash.as_deref(),
            prepared.registration_access_token_blake3.as_deref(),
        )
        .await
    {
        Ok(client) => client,
        Err(_error) => {
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
    let current = match authenticate_registration_client(&endpoint, &request, &path).await {
        Ok(client) => client,
        Err(response) => return response,
    };
    match endpoint
        .clients
        .deactivate(current.tenant_id, current.id)
        .await
    {
        Ok(true) => {}
        Ok(false) | Err(_) => {
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
    registration: nazo_auth::PreparedDynamicClientRegistration,
    registration_access_token: &str,
) -> Result<PreparedClientRegistration, AdminClientError> {
    let policy = AdminClientPolicy {
        tenant: TenantContext::default_system(),
        pairwise_subject_secret: endpoint.config.pairwise_subject_secret.clone(),
        client_secret_pepper: endpoint.config.client_secret_pepper.clone(),
    };
    let mut prepared = nazo_auth::prepare_client_registration(
        registration.into_create_client_request(),
        &policy,
        endpoint.sector_identifiers.as_ref(),
        endpoint.crypto.as_ref(),
    )
    .await?;
    prepared.registration_access_token_blake3 =
        Some(endpoint.secrets.token_hash(registration_access_token));
    Ok(prepared)
}

async fn authenticate_registration_client(
    endpoint: &DynamicRegistrationEndpoint,
    request: &HttpRequest,
    client_id: &str,
) -> Result<OAuthClient, HttpResponse> {
    let Some(token) = bearer_token(request) else {
        return Err(registration_access_denied());
    };
    match endpoint
        .clients
        .by_registration_access_token(
            TenantContext::default_system().tenant_id.as_uuid(),
            client_id,
            &endpoint.secrets.token_hash(token),
        )
        .await
    {
        Ok(Some(client)) => Ok(client),
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
    let candidate = endpoint.secret_digester.client_secret_digest(
        secret,
        &endpoint.config.client_secret_pepper,
        &salt,
    );
    endpoint
        .clients
        .client_secret_digest_matches(current.id, &candidate)
        .await
}

fn issue_client_secret(
    endpoint: &DynamicRegistrationEndpoint,
    client: &OAuthClient,
) -> (Option<String>, Option<String>) {
    if client.client_type != "confidential"
        || !matches!(
            client.token_endpoint_auth_method.as_str(),
            "client_secret_basic" | "client_secret_post"
        )
    {
        return (None, None);
    }
    let (secret, digest) = endpoint
        .crypto
        .issue_client_secret(&endpoint.config.client_secret_pepper);
    (Some(secret), Some(digest))
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
    value
        .trim()
        .strip_prefix("Bearer ")
        .map(str::trim)
        .filter(|value| !value.is_empty())
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
        "subject_type": client.subject_type,
        "post_logout_redirect_uris": client.post_logout_redirect_uris,
        "backchannel_logout_session_required": client.backchannel_logout_session_required,
        "frontchannel_logout_session_required": client.frontchannel_logout_session_required,
    });
    if let Some(uri) = &client.backchannel_logout_uri {
        body["backchannel_logout_uri"] = json!(uri);
    }
    if let Some(uri) = &client.frontchannel_logout_uri {
        body["frontchannel_logout_uri"] = json!(uri);
    }
    if let Some(jwks) = &client.jwks {
        body["jwks"] = jwks.clone();
    }
    for (field, value) in [
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
mod tests {
    use std::sync::{Arc, Mutex};

    use actix_web::{App, http::header, test, web};
    use nazo_auth::{
        AdminClientCryptoPort, SectorIdentifierFuture, SectorIdentifierResolverPort,
        ValidatedClientRegistration,
    };
    use serde_json::{Value, json};
    use uuid::Uuid;

    use super::*;

    #[derive(Clone)]
    struct FakeStore {
        client: Arc<Mutex<Option<OAuthClient>>>,
    }

    impl FakeStore {
        fn new() -> Self {
            Self {
                client: Arc::new(Mutex::new(Some(client()))),
            }
        }
    }

    impl DynamicRegistrationClientStore for FakeStore {
        fn insert<'a>(
            &'a self,
            prepared: &'a PreparedClientRegistration,
        ) -> DynamicRegistrationFuture<'a, OAuthClient> {
            let inserted = OAuthClient {
                id: Uuid::now_v7(),
                tenant_id: prepared.tenant.tenant_id.as_uuid(),
                realm_id: prepared.tenant.realm_id.as_uuid(),
                organization_id: prepared.tenant.organization_id.as_uuid(),
                registration: prepared.registration.clone(),
                require_mtls_bound_tokens: false,
                is_active: true,
            };
            *self.client.lock().expect("client lock") = Some(inserted.clone());
            Box::pin(async move { Ok(inserted) })
        }

        fn by_registration_access_token<'a>(
            &'a self,
            _tenant_id: Uuid,
            client_id: &'a str,
            _token_hash: &'a str,
        ) -> DynamicRegistrationFuture<'a, Option<OAuthClient>> {
            let found = self
                .client
                .lock()
                .expect("client lock")
                .clone()
                .filter(|client| client.client_id == client_id);
            Box::pin(async move { Ok(found) })
        }

        fn has_client_secret(&self, _client_id: Uuid) -> DynamicRegistrationFuture<'_, bool> {
            Box::pin(async { Ok(true) })
        }

        fn client_secret_salt(
            &self,
            _client_id: Uuid,
        ) -> DynamicRegistrationFuture<'_, Option<String>> {
            Box::pin(async { Ok(Some("salt".to_owned())) })
        }

        fn client_secret_digest_matches<'a>(
            &'a self,
            _client_id: Uuid,
            candidate_digest: &'a str,
        ) -> DynamicRegistrationFuture<'a, bool> {
            let matches = candidate_digest == "digest:current-secret:pepper:salt";
            Box::pin(async move { Ok(matches) })
        }

        fn rotate_credentials<'a>(
            &'a self,
            _tenant_id: Uuid,
            _client_id: Uuid,
            _client_secret_hash: Option<&'a str>,
            _registration_access_token_hash: &'a str,
        ) -> DynamicRegistrationFuture<'a, OAuthClient> {
            let client = self.client.lock().expect("client lock").clone();
            Box::pin(async move { client.ok_or(DynamicRegistrationDependencyError::Unavailable) })
        }

        fn replace_registration<'a>(
            &'a self,
            client: &'a OAuthClient,
            _client_secret_hash: Option<&'a str>,
            _registration_access_token_hash: Option<&'a str>,
        ) -> DynamicRegistrationFuture<'a, OAuthClient> {
            *self.client.lock().expect("client lock") = Some(client.clone());
            Box::pin(async move { Ok(client.clone()) })
        }

        fn deactivate(
            &self,
            _tenant_id: Uuid,
            _client_id: Uuid,
        ) -> DynamicRegistrationFuture<'_, bool> {
            *self.client.lock().expect("client lock") = None;
            Box::pin(async { Ok(true) })
        }
    }

    #[derive(Clone, Copy)]
    struct FakeSecurity;

    impl SectorIdentifierResolverPort for FakeSecurity {
        fn resolve<'a>(&'a self, _uri: &'a str) -> SectorIdentifierFuture<'a> {
            Box::pin(async { Ok(Vec::new()) })
        }
    }

    impl AdminClientCryptoPort for FakeSecurity {
        fn response_signing_algorithms(&self) -> Vec<String> {
            vec!["RS256".to_owned(), "PS256".to_owned()]
        }

        fn issue_client_secret(&self, _pepper: &str) -> (String, String) {
            ("issued-secret".to_owned(), "stored-secret-hash".to_owned())
        }

        fn validate_jwks(&self, _jwks: &Value, _allow_missing_kid: bool) -> Result<(), String> {
            Ok(())
        }

        fn matching_encryption_key_count(&self, _jwks: &Value, _algorithm: &str) -> usize {
            1
        }

        fn contains_signing_key(&self, _jwks: &Value) -> bool {
            true
        }

        fn valid_self_signed_mtls_jwks(&self, _jwks: &Value) -> bool {
            true
        }
    }

    impl DynamicRegistrationSecurity for FakeSecurity {
        fn random_token(&self) -> String {
            "registration-token".to_owned()
        }

        fn token_hash(&self, token: &str) -> String {
            format!("token-hash:{token}")
        }

        fn constant_time_eq(&self, left: &[u8], right: &[u8]) -> bool {
            left == right
        }
    }

    impl ClientSecretDigesterPort for FakeSecurity {
        fn client_secret_digest(&self, secret: &str, pepper: &str, salt: &str) -> String {
            format!("digest:{secret}:{pepper}:{salt}")
        }
    }

    #[derive(Clone)]
    struct FakeGuard {
        enabled: bool,
        rate_limit: Option<DynamicRegistrationRateLimitError>,
    }

    impl DynamicRegistrationRequestGuard for FakeGuard {
        fn accepts_new_requests(&self) -> bool {
            self.enabled
        }

        fn enforce_rate_limit<'a>(
            &'a self,
            _source_ip: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<(), DynamicRegistrationRateLimitError>> + Send + 'a>>
        {
            let result = self.rate_limit.map_or(Ok(()), Err);
            Box::pin(async move { result })
        }

        fn audit(&self, _event: &'static str, _client: &OAuthClient, _source_ip: &str) {}
    }

    fn endpoint(enabled: bool) -> DynamicRegistrationEndpoint {
        DynamicRegistrationEndpoint::new(
            DynamicRegistrationEndpointConfig {
                issuer: "https://issuer.example".to_owned(),
                default_audience: "https://api.example".to_owned(),
                pairwise_subject_secret: None,
                client_secret_pepper: "pepper".to_owned(),
                initial_access_token: Some("initial-token".to_owned()),
                client_ip_header_mode: ClientIpHeaderMode::None,
                trusted_proxy_cidrs: Vec::new(),
            },
            Arc::new(FakeStore::new()),
            Arc::new(FakeSecurity),
            Arc::new(FakeSecurity),
            Arc::new(FakeSecurity),
            Arc::new(FakeSecurity),
            Arc::new(FakeGuard {
                enabled,
                rate_limit: None,
            }),
        )
    }

    fn configure(config: &mut web::ServiceConfig) {
        config.route("/register", web::post().to(dynamic_client_registration));
        config.service(
            web::resource("/register/{client_id}")
                .route(web::get().to(client_configuration_get))
                .route(web::put().to(client_configuration_put))
                .route(web::delete().to(client_configuration_delete)),
        );
    }

    #[actix_web::test]
    async fn untrusted_peer_cannot_spoof_forwarded_source_ip() {
        let config = ClientIpConfig::new(
            &[IpCidr::parse("192.0.2.0/24").expect("network")],
            ClientIpHeaderMode::XForwardedFor,
        );
        let request = test::TestRequest::default()
            .peer_addr("198.51.100.10:443".parse().expect("peer"))
            .insert_header(("x-forwarded-for", "203.0.113.9"))
            .to_http_request();

        assert_eq!(client_ip_with_config(&request, &config), "198.51.100.10");
    }

    #[actix_web::test]
    async fn trusted_proxy_chain_selects_nearest_untrusted_hop() {
        let config = ClientIpConfig::new(
            &[IpCidr::parse("192.0.2.0/24").expect("network")],
            ClientIpHeaderMode::XForwardedFor,
        );
        let request = test::TestRequest::default()
            .peer_addr("192.0.2.10:443".parse().expect("peer"))
            .insert_header(("x-forwarded-for", "203.0.113.9, 192.0.2.20"))
            .to_http_request();

        assert_eq!(client_ip_with_config(&request, &config), "203.0.113.9");
    }

    #[actix_web::test]
    async fn disabled_module_rejects_every_method_before_body_or_credentials() {
        let service = test::init_service(
            App::new()
                .app_data(Data::new(endpoint(false)))
                .configure(configure),
        )
        .await;
        for request in [
            test::TestRequest::post()
                .uri("/register")
                .set_payload("not-json")
                .to_request(),
            test::TestRequest::get()
                .uri("/register/client-test")
                .to_request(),
            test::TestRequest::put()
                .uri("/register/client-test")
                .set_payload("not-json")
                .to_request(),
            test::TestRequest::delete()
                .uri("/register/client-test")
                .to_request(),
        ] {
            let response = test::call_service(&service, request).await;
            assert_eq!(response.status(), StatusCode::NOT_FOUND);
        }
    }

    #[actix_web::test]
    async fn registration_authentication_error_keeps_bearer_and_no_store_contract() {
        let service = test::init_service(
            App::new()
                .app_data(Data::new(endpoint(true)))
                .configure(configure),
        )
        .await;
        let response = test::call_service(
            &service,
            test::TestRequest::post()
                .uri("/register")
                .set_json(json!({}))
                .to_request(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE),
            Some(&header::HeaderValue::from_static("application/json"))
        );
        assert_eq!(
            response.headers().get(header::WWW_AUTHENTICATE),
            Some(&header::HeaderValue::from_static(
                "Bearer error=\"invalid_token\", error_description=\"Initial access token is missing or invalid.\""
            ))
        );
        let body: Value = test::read_body_json(response).await;
        assert_eq!(body["error"], "invalid_token");
    }

    #[actix_web::test]
    async fn registration_and_management_methods_keep_wire_contracts() {
        let endpoint = endpoint(true);
        let service = test::init_service(
            App::new()
                .app_data(Data::new(endpoint))
                .configure(configure),
        )
        .await;
        let created = test::call_service(
            &service,
            test::TestRequest::post()
                .uri("/register")
                .insert_header((header::AUTHORIZATION, "Bearer initial-token"))
                .set_json(json!({
                    "client_name": "Registered Client",
                    "redirect_uris": ["https://client.example/callback"]
                }))
                .to_request(),
        )
        .await;
        assert_eq!(created.status(), StatusCode::CREATED);
        assert_eq!(
            created.headers().get(header::CACHE_CONTROL),
            Some(&header::HeaderValue::from_static("no-store"))
        );
        let created: Value = test::read_body_json(created).await;
        let client_id = created["client_id"].as_str().expect("client id");
        assert_eq!(created["registration_access_token"], "registration-token");
        assert_eq!(created["client_secret"], "issued-secret");
        assert!(created["client_id_issued_at"].is_i64());
        assert_eq!(
            created["registration_client_uri"],
            format!("https://issuer.example/register/{client_id}")
        );

        let read = test::call_service(
            &service,
            test::TestRequest::get()
                .uri(&format!("/register/{client_id}"))
                .insert_header((header::AUTHORIZATION, "Bearer registration-token"))
                .to_request(),
        )
        .await;
        assert_eq!(read.status(), StatusCode::OK);
        assert_eq!(
            read.headers().get(header::CACHE_CONTROL),
            Some(&header::HeaderValue::from_static("no-store"))
        );

        let update = test::call_service(
            &service,
            test::TestRequest::put()
                .uri(&format!("/register/{client_id}"))
                .insert_header((header::AUTHORIZATION, "Bearer registration-token"))
                .set_json(json!({
                    "client_id": client_id,
                    "client_secret": "current-secret",
                    "client_name": "Updated Client",
                    "redirect_uris": ["https://client.example/callback"]
                }))
                .to_request(),
        )
        .await;
        assert_eq!(update.status(), StatusCode::OK);
        let updated: Value = test::read_body_json(update).await;
        assert_eq!(updated["client_name"], "Updated Client");
        let updated_client_id = updated["client_id"].as_str().expect("updated client id");

        let deleted = test::call_service(
            &service,
            test::TestRequest::delete()
                .uri(&format!("/register/{updated_client_id}"))
                .insert_header((header::AUTHORIZATION, "Bearer registration-token"))
                .to_request(),
        )
        .await;
        assert_eq!(deleted.status(), StatusCode::NO_CONTENT);
        assert_eq!(
            deleted.headers().get(header::CACHE_CONTROL),
            Some(&header::HeaderValue::from_static("no-store"))
        );
    }

    #[actix_web::test]
    async fn rate_limit_error_keeps_oauth_code_and_retry_after() {
        let mut endpoint = endpoint(true);
        endpoint.request_guard = Arc::new(FakeGuard {
            enabled: true,
            rate_limit: Some(DynamicRegistrationRateLimitError::Limited {
                retry_after_seconds: 30,
            }),
        });
        let service = test::init_service(
            App::new()
                .app_data(Data::new(endpoint))
                .configure(configure),
        )
        .await;
        let response = test::call_service(
            &service,
            test::TestRequest::post()
                .uri("/register")
                .insert_header((header::AUTHORIZATION, "Bearer initial-token"))
                .set_json(json!({}))
                .to_request(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response.headers().get(header::RETRY_AFTER).unwrap(), "30");
        let body: Value = test::read_body_json(response).await;
        assert_eq!(body["error"], "temporarily_unavailable");
    }

    fn client() -> OAuthClient {
        OAuthClient {
            id: Uuid::now_v7(),
            tenant_id: Uuid::nil(),
            realm_id: Uuid::nil(),
            organization_id: Uuid::nil(),
            registration: ValidatedClientRegistration {
                client_id: "client-test".to_owned(),
                client_name: "Client".to_owned(),
                client_type: "confidential".to_owned(),
                redirect_uris: vec!["https://client.example/callback".to_owned()],
                post_logout_redirect_uris: Vec::new(),
                scopes: vec!["openid".to_owned()],
                allowed_audiences: vec!["https://api.example".to_owned()],
                grant_types: vec!["authorization_code".to_owned()],
                token_endpoint_auth_method: "client_secret_basic".to_owned(),
                subject_type: "public".to_owned(),
                sector_identifier_uri: None,
                sector_identifier_host: None,
                require_dpop_bound_tokens: false,
                allow_client_assertion_audience_array: false,
                allow_client_assertion_endpoint_audience: false,
                require_par_request_object: false,
                allow_authorization_code_without_pkce: true,
                backchannel_logout_uri: None,
                backchannel_logout_session_required: false,
                frontchannel_logout_uri: None,
                frontchannel_logout_session_required: false,
                tls_client_auth_subject_dn: None,
                tls_client_auth_cert_sha256: None,
                tls_client_auth_san_dns: Vec::new(),
                tls_client_auth_san_uri: Vec::new(),
                tls_client_auth_san_ip: Vec::new(),
                tls_client_auth_san_email: Vec::new(),
                jwks: None,
                introspection_encrypted_response_alg: None,
                introspection_encrypted_response_enc: None,
                userinfo_signed_response_alg: None,
                userinfo_encrypted_response_alg: None,
                userinfo_encrypted_response_enc: None,
                authorization_signed_response_alg: None,
                authorization_encrypted_response_alg: None,
                authorization_encrypted_response_enc: None,
            },
            require_mtls_bound_tokens: false,
            is_active: true,
        }
    }
}
