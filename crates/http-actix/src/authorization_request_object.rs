use actix_web::{HttpResponse, http::StatusCode};
use nazo_auth::{AuthorizationRequestError, RequestObjectVerificationError};

use crate::oauth_error;

#[must_use]
pub fn request_object_verification_error(error: RequestObjectVerificationError) -> HttpResponse {
    let description = match error {
        RequestObjectVerificationError::InvalidCompact => "request object 无效.",
        RequestObjectVerificationError::InvalidHeader => "request object header 无效.",
        RequestObjectVerificationError::InvalidClaims => "request object claims 无效.",
        RequestObjectVerificationError::InvalidAlgorithm => "request object 签名算法无效.",
        RequestObjectVerificationError::MissingKeyId => "request object 缺少 kid.",
        RequestObjectVerificationError::InvalidKey => "request object 签名密钥无效.",
        RequestObjectVerificationError::InvalidSignature => "request object 验签失败.",
    };
    oauth_error(
        StatusCode::BAD_REQUEST,
        "invalid_request_object",
        description,
    )
}

#[must_use]
pub fn request_object_policy_error(error: AuthorizationRequestError) -> HttpResponse {
    let (status, description) = match error {
        AuthorizationRequestError::InvalidRequestObject
        | AuthorizationRequestError::RequestObjectClaims => {
            (StatusCode::BAD_REQUEST, "request object claims 无效.")
        }
        AuthorizationRequestError::RequestObjectContainsRequestUri => (
            StatusCode::BAD_REQUEST,
            "request object 不能包含 request_uri.",
        ),
        AuthorizationRequestError::RequestObjectParameterType => {
            (StatusCode::BAD_REQUEST, "request object 参数类型无效.")
        }
        AuthorizationRequestError::InvalidRequest
        | AuthorizationRequestError::OuterClientIdConflict => (
            StatusCode::BAD_REQUEST,
            "request object 与外层 client_id 冲突.",
        ),
        AuthorizationRequestError::SignedRequestObjectMissingRedirectUri => (
            StatusCode::BAD_REQUEST,
            "signed request object 缺少 redirect_uri.",
        ),
        AuthorizationRequestError::OuterAuthorizationParametersConflict => (
            StatusCode::BAD_REQUEST,
            "request object 与外层授权参数冲突.",
        ),
        AuthorizationRequestError::InvalidRequestObjectReplay => {
            (StatusCode::BAD_REQUEST, "request object jti 已使用.")
        }
        AuthorizationRequestError::Dependency(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            "request object 防重放状态不可用.",
        ),
        AuthorizationRequestError::InvalidTarget
        | AuthorizationRequestError::UnsupportedResponseType
        | AuthorizationRequestError::UnauthorizedClient
        | AuthorizationRequestError::InvalidClient => {
            (StatusCode::BAD_REQUEST, "request object claims 无效.")
        }
    };
    oauth_error(status, error.oauth_error(), description)
}

#[cfg(test)]
#[path = "../tests/unit/authorization_request_object.rs"]
mod tests;
