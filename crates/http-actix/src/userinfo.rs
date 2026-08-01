use std::{future::Future, pin::Pin, sync::Arc};

use actix_web::{
    HttpRequest, HttpResponse,
    http::{StatusCode, header},
    web::{Bytes, Data},
};
use serde_json::Value;

use crate::{
    AccessTokenAuthScheme, ResourceAccessToken, json_response_no_store, oauth_bearer_error,
    oauth_error, resource_access_token,
};

pub type UserinfoFuture<'a> =
    Pin<Box<dyn Future<Output = Result<UserinfoSuccess, UserinfoError>> + 'a>>;

#[derive(Clone, Debug, PartialEq)]
pub enum UserinfoRepresentation {
    Claims(Value),
    Jwt(String),
}

#[derive(Clone, Debug, PartialEq)]
pub struct UserinfoSuccess {
    pub representation: UserinfoRepresentation,
    pub dpop_nonce: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UserinfoDpopError {
    MissingProof,
    MalformedProof,
    InvalidProof,
    ReplayDetected,
    BindingMismatch,
    TokenNotBound,
    UseNonce(String),
    NonceStoreUnavailable,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UserinfoError {
    InvalidAccessToken,
    InvalidAudience,
    InvalidTenantBoundary,
    RevokedAccessToken,
    Dpop(UserinfoDpopError),
    MissingMtlsCertificate,
    MtlsCertificateMismatch,
    InsufficientScope,
    InvalidSubject,
    InactiveSubject,
    ClientUnavailable,
    QueryUnavailable,
    ResponseProtectionFailed,
}

pub trait UserinfoOperations: Send + Sync {
    fn userinfo<'a>(
        &'a self,
        request: &'a HttpRequest,
        scheme: AccessTokenAuthScheme,
        token: String,
    ) -> UserinfoFuture<'a>;
}

#[derive(Clone)]
pub struct UserinfoEndpoint {
    operations: Arc<dyn UserinfoOperations>,
}

impl UserinfoEndpoint {
    pub fn new(operations: Arc<dyn UserinfoOperations>) -> Self {
        Self { operations }
    }
}

pub async fn userinfo(
    endpoint: Data<UserinfoEndpoint>,
    request: HttpRequest,
    body: Bytes,
) -> HttpResponse {
    let (scheme, token) = match resource_access_token(&request, &body, false) {
        ResourceAccessToken::Present(scheme, token) => (scheme, token),
        ResourceAccessToken::Missing => {
            return oauth_bearer_error(StatusCode::UNAUTHORIZED, "invalid_token", "缺少访问令牌.");
        }
        ResourceAccessToken::InvalidRequest => {
            return oauth_bearer_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Only one access token transport method may be used.",
            );
        }
    };

    match endpoint.operations.userinfo(&request, scheme, token).await {
        Ok(success) => userinfo_success_response(success),
        Err(error) => userinfo_error_response(error),
    }
}

fn userinfo_success_response(success: UserinfoSuccess) -> HttpResponse {
    let mut response = match success.representation {
        UserinfoRepresentation::Claims(claims) => json_response_no_store(claims),
        UserinfoRepresentation::Jwt(jwt) => HttpResponse::Ok()
            .insert_header((
                header::CONTENT_TYPE,
                header::HeaderValue::from_static("application/jwt"),
            ))
            .insert_header((
                header::CACHE_CONTROL,
                header::HeaderValue::from_static("no-store"),
            ))
            .insert_header((header::PRAGMA, header::HeaderValue::from_static("no-cache")))
            .body(jwt),
    };
    if let Some(nonce) = success.dpop_nonce
        && let Ok(value) = header::HeaderValue::from_str(&nonce)
    {
        response
            .headers_mut()
            .insert(header::HeaderName::from_static("dpop-nonce"), value);
    }
    response
}

fn userinfo_error_response(error: UserinfoError) -> HttpResponse {
    match error {
        UserinfoError::InvalidAccessToken => oauth_bearer_error(
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            "访问令牌无效或已过期.",
        ),
        UserinfoError::InvalidAudience => oauth_bearer_error(
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            "访问令牌 audience 不适用于 userinfo.",
        ),
        UserinfoError::InvalidTenantBoundary => oauth_bearer_error(
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            "访问令牌租户边界无效.",
        ),
        UserinfoError::RevokedAccessToken => {
            oauth_bearer_error(StatusCode::UNAUTHORIZED, "invalid_token", "访问令牌已撤销.")
        }
        UserinfoError::Dpop(error) => userinfo_dpop_error_response(error),
        UserinfoError::MissingMtlsCertificate => oauth_bearer_error(
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            "mTLS-bound access token requires a verified client certificate.",
        ),
        UserinfoError::MtlsCertificateMismatch => oauth_bearer_error(
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            "mTLS-bound access token certificate mismatch.",
        ),
        UserinfoError::InsufficientScope => oauth_bearer_error(
            StatusCode::FORBIDDEN,
            "insufficient_scope",
            "userinfo 需要 openid scope.",
        ),
        UserinfoError::InvalidSubject => oauth_bearer_error(
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            "访问令牌主体无效.",
        ),
        UserinfoError::InactiveSubject => oauth_bearer_error(
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            "访问令牌主体不存在或已停用.",
        ),
        UserinfoError::ClientUnavailable => oauth_bearer_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "userinfo 客户端状态不可用.",
        ),
        UserinfoError::QueryUnavailable => oauth_bearer_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "userinfo 查询失败.",
        ),
        UserinfoError::ResponseProtectionFailed => oauth_bearer_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "userinfo 响应生成失败.",
        ),
    }
}

fn userinfo_dpop_error_response(error: UserinfoDpopError) -> HttpResponse {
    let description = match &error {
        UserinfoDpopError::MissingProof => "DPoP proof is required.",
        UserinfoDpopError::MalformedProof => "DPoP proof is malformed.",
        UserinfoDpopError::InvalidProof => "DPoP proof validation failed.",
        UserinfoDpopError::ReplayDetected => "DPoP proof jti has already been used.",
        UserinfoDpopError::BindingMismatch => "DPoP binding mismatch.",
        UserinfoDpopError::TokenNotBound => "Token is not DPoP-bound.",
        UserinfoDpopError::UseNonce(_) => "Authorization server requires nonce in DPoP proof.",
        UserinfoDpopError::NonceStoreUnavailable => "DPoP nonce validation is unavailable.",
    };
    let status = match &error {
        UserinfoDpopError::MissingProof | UserinfoDpopError::UseNonce(_) => {
            StatusCode::UNAUTHORIZED
        }
        UserinfoDpopError::NonceStoreUnavailable => StatusCode::SERVICE_UNAVAILABLE,
        _ => StatusCode::BAD_REQUEST,
    };
    let error_code = match &error {
        UserinfoDpopError::UseNonce(_) => "use_dpop_nonce",
        UserinfoDpopError::NonceStoreUnavailable => "server_error",
        _ => "invalid_dpop_proof",
    };
    let mut response = oauth_error(status, error_code, description);
    if let UserinfoDpopError::UseNonce(nonce) = error
        && let Ok(value) = header::HeaderValue::from_str(&nonce)
    {
        response
            .headers_mut()
            .insert(header::HeaderName::from_static("dpop-nonce"), value);
    }
    response.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        header::HeaderValue::from_str(&format!("DPoP error=\"{error_code}\""))
            .unwrap_or_else(|_| header::HeaderValue::from_static("DPoP")),
    );
    response
}

#[cfg(test)]
#[path = "../tests/unit/userinfo.rs"]
mod tests;
