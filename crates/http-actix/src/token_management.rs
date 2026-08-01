use std::{future::Future, pin::Pin, sync::Arc};

use actix_web::{
    HttpRequest, HttpResponse,
    http::{StatusCode, header},
    web::{Bytes, Data},
};
use nazo_auth::TokenInspection;

use crate::{
    ClientCertificateFacts, TokenClientAuthForm, TokenClientAuthTransportFacts, TokenOnlyForm,
    authorization_error_response, empty_response_no_store, json_response_no_store,
    oauth_token_error, parse_token_management_form, token_client_auth_transport_facts,
    token_management_form_error, token_management_has_conflicting_client_auth,
    token_management_oauth_error,
};

pub const TOKEN_INTROSPECTION_JWT_MEDIA_TYPE: &str = "application/token-introspection+jwt";

pub type TokenManagementFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, TokenManagementError>> + 'a>>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TokenManagementRateLimitError {
    Limited { retry_after_seconds: u64 },
    Unavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TokenManagementError {
    InvalidClient { basic_challenge: bool },
    AuthenticationStoreUnavailable,
    ClientLookupUnavailable,
    InspectionUnavailable,
    RevocationUnavailable,
    ResponseProtectionFailed,
}

#[derive(Clone, Debug, PartialEq)]
pub enum TokenIntrospectionRepresentation {
    Inspection(TokenInspection),
    Jwt(String),
}

/// Deployment-derived request facts shared by rate limiting and token-management operations.
///
/// Protocol/application implementations never receive the Actix request or its headers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TokenManagementRequestFacts {
    pub source_ip: String,
    pub endpoint_path: String,
    pub client_certificate: Option<ClientCertificateFacts>,
}

pub trait TokenManagementRequestFactsExtractor: Send + Sync {
    /// Extracts only cheap facts needed before rate limiting.
    fn extract(&self, request: &HttpRequest) -> TokenManagementRequestFacts;

    /// Resolves a verified certificate after rate limiting and form/auth-source validation.
    /// Implementations must only return a certificate for a trusted forwarding peer.
    fn extract_client_certificate(&self, _request: &HttpRequest) -> Option<ClientCertificateFacts> {
        None
    }
}

pub trait TokenManagementRequestGuard: Send + Sync {
    fn enforce<'a>(
        &'a self,
        request: &'a TokenManagementRequestFacts,
    ) -> Pin<Box<dyn Future<Output = Result<(), TokenManagementRateLimitError>> + Send + 'a>>;
}

pub trait TokenManagementOperations: Send + Sync {
    fn introspect<'a>(
        &'a self,
        request: TokenManagementRequestFacts,
        client_auth: TokenClientAuthTransportFacts,
        form: TokenOnlyForm,
        signed_response_requested: bool,
    ) -> TokenManagementFuture<'a, TokenIntrospectionRepresentation>;

    fn revoke<'a>(
        &'a self,
        request: TokenManagementRequestFacts,
        client_auth: TokenClientAuthTransportFacts,
        form: TokenOnlyForm,
    ) -> TokenManagementFuture<'a, ()>;
}

#[derive(Clone)]
pub struct TokenManagementEndpoint {
    request_facts: Arc<dyn TokenManagementRequestFactsExtractor>,
    guard: Arc<dyn TokenManagementRequestGuard>,
    operations: Arc<dyn TokenManagementOperations>,
}

impl TokenManagementEndpoint {
    pub fn new(
        request_facts: Arc<dyn TokenManagementRequestFactsExtractor>,
        guard: Arc<dyn TokenManagementRequestGuard>,
        operations: Arc<dyn TokenManagementOperations>,
    ) -> Self {
        Self {
            request_facts,
            guard,
            operations,
        }
    }
}

pub async fn introspect(
    endpoint: Data<TokenManagementEndpoint>,
    request: HttpRequest,
    body: Bytes,
) -> HttpResponse {
    let mut request_facts = endpoint.request_facts.extract(&request);
    if let Err(response) = enforce_rate_limit(&endpoint, &request_facts).await {
        return response;
    }
    let form = match parse_token_management_form(&request, &body) {
        Ok(form) => form,
        Err(error) => return token_management_form_error(error),
    };
    let client_auth = token_client_auth_transport_facts(
        &request,
        TokenClientAuthForm {
            client_id: form.client_id.as_deref(),
            client_secret: form.client_secret.as_deref(),
            client_assertion_type: form.client_assertion_type.as_deref(),
            client_assertion: form.client_assertion.as_deref(),
        },
    );
    let has_basic = client_auth.basic_challenge();
    if token_management_has_conflicting_client_auth(has_basic, &form) {
        return token_management_oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "同一请求不能同时使用多种客户端认证方式.",
        );
    }
    request_facts.client_certificate = endpoint.request_facts.extract_client_certificate(&request);
    let signed_response_requested = signed_introspection_requested(&request);
    match endpoint
        .operations
        .introspect(request_facts, client_auth, form, signed_response_requested)
        .await
    {
        Ok(TokenIntrospectionRepresentation::Inspection(inspection)) => {
            json_response_no_store(inspection.into_document())
        }
        Ok(TokenIntrospectionRepresentation::Jwt(token)) => HttpResponse::Ok()
            .insert_header((
                header::CONTENT_TYPE,
                header::HeaderValue::from_static(TOKEN_INTROSPECTION_JWT_MEDIA_TYPE),
            ))
            .insert_header((
                header::CACHE_CONTROL,
                header::HeaderValue::from_static("no-store"),
            ))
            .insert_header((header::PRAGMA, header::HeaderValue::from_static("no-cache")))
            .body(token),
        Err(error) => token_management_error_response(error),
    }
}

pub async fn revoke(
    endpoint: Data<TokenManagementEndpoint>,
    request: HttpRequest,
    body: Bytes,
) -> HttpResponse {
    let mut request_facts = endpoint.request_facts.extract(&request);
    if let Err(response) = enforce_rate_limit(&endpoint, &request_facts).await {
        return response;
    }
    let form = match parse_token_management_form(&request, &body) {
        Ok(form) => form,
        Err(error) => return token_management_form_error(error),
    };
    let client_auth = token_client_auth_transport_facts(
        &request,
        TokenClientAuthForm {
            client_id: form.client_id.as_deref(),
            client_secret: form.client_secret.as_deref(),
            client_assertion_type: form.client_assertion_type.as_deref(),
            client_assertion: form.client_assertion.as_deref(),
        },
    );
    let has_basic = client_auth.basic_challenge();
    if token_management_has_conflicting_client_auth(has_basic, &form) {
        return token_management_oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "同一请求不能同时使用多种客户端认证方式.",
        );
    }
    request_facts.client_certificate = endpoint.request_facts.extract_client_certificate(&request);
    match endpoint
        .operations
        .revoke(request_facts, client_auth, form)
        .await
    {
        Ok(()) => empty_response_no_store(StatusCode::OK),
        Err(error) => token_management_error_response(error),
    }
}

fn signed_introspection_requested(request: &HttpRequest) -> bool {
    request
        .headers()
        .get(header::ACCEPT)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value.split(',').any(|part| {
                part.split(';').next().is_some_and(|media_type| {
                    media_type.trim() == TOKEN_INTROSPECTION_JWT_MEDIA_TYPE
                })
            })
        })
}

async fn enforce_rate_limit(
    endpoint: &TokenManagementEndpoint,
    request: &TokenManagementRequestFacts,
) -> Result<(), HttpResponse> {
    match endpoint.guard.enforce(request).await {
        Ok(()) => Ok(()),
        Err(TokenManagementRateLimitError::Unavailable) => Err(token_management_oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "请求频率校验失败.",
        )),
        Err(TokenManagementRateLimitError::Limited {
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

fn token_management_error_response(error: TokenManagementError) -> HttpResponse {
    match error {
        TokenManagementError::InvalidClient { basic_challenge } => oauth_token_error(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "客户端认证失败.",
            basic_challenge,
        ),
        TokenManagementError::AuthenticationStoreUnavailable => oauth_token_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "客户端认证状态存储不可用.",
            false,
        ),
        TokenManagementError::ClientLookupUnavailable => token_management_oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "客户端查询失败.",
        ),
        TokenManagementError::InspectionUnavailable => token_management_oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "token 状态查询失败.",
        ),
        TokenManagementError::RevocationUnavailable => token_management_oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "token 撤销失败.",
        ),
        TokenManagementError::ResponseProtectionFailed => token_management_oauth_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "token introspection JWT response build failed.",
        ),
    }
}

#[cfg(test)]
#[path = "../tests/unit/token_management.rs"]
mod tests;
