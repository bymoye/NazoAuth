use actix_web::{
    HttpRequest, HttpResponse,
    http::{StatusCode, header},
};
use nazo_auth::{DynamicRegistrationDependencyError, DynamicRegistrationSecretPort, OAuthClient};
use nazo_identity::TenantContext;
use serde_json::Value;
use uuid::Uuid;

use super::{
    ip::client_ip_with_config,
    response::{initial_access_denied, lookup_failed, registration_access_denied},
    types::{DynamicRegistrationEndpoint, DynamicRegistrationRateLimitError},
};
use crate::{authorization_error_response, oauth_error};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum DynamicRegistrationInitialAccessGrant {
    Configured,
    ConformanceLease(Uuid),
}

impl DynamicRegistrationInitialAccessGrant {
    pub(super) fn conformance_lease_id(self) -> Option<Uuid> {
        match self {
            Self::Configured => None,
            Self::ConformanceLease(lease_id) => Some(lease_id),
        }
    }
}

pub(super) async fn authorize_initial_access(
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

pub(super) async fn authenticate_registration_client(
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

pub(super) async fn submitted_secret_matches(
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

pub(super) async fn enforce_rate_limit(
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

pub(super) fn initial_access_token_authorized(
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

pub(super) fn bearer_token(request: &HttpRequest) -> Option<&str> {
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
