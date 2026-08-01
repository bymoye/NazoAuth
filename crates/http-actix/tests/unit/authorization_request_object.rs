use actix_web::body::to_bytes;
use nazo_auth::{AuthorizationPortError, AuthorizationRequestError};
use serde_json::Value;

use super::*;
use crate::{OAuthJsonErrorFields, oauth_error_description};

async fn assert_error(response: HttpResponse, status: StatusCode, code: &str, description: &str) {
    assert_eq!(response.status(), status);
    assert_eq!(
        response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok()),
        Some("application/json")
    );
    let fields = response
        .extensions()
        .get::<OAuthJsonErrorFields>()
        .cloned()
        .expect("OAuth fields extension");
    assert_eq!(fields.error, code);
    let body: Value = serde_json::from_slice(&to_bytes(response.into_body()).await.unwrap())
        .expect("JSON error body");
    assert_eq!(body["error"], code);
    assert_eq!(
        body["error_description"],
        oauth_error_description(description).as_ref()
    );
}

#[actix_web::test]
async fn verification_errors_preserve_existing_oauth_contract() {
    for (error, description) in [
        (
            RequestObjectVerificationError::InvalidCompact,
            "request object 无效.",
        ),
        (
            RequestObjectVerificationError::InvalidHeader,
            "request object header 无效.",
        ),
        (
            RequestObjectVerificationError::InvalidClaims,
            "request object claims 无效.",
        ),
        (
            RequestObjectVerificationError::InvalidAlgorithm,
            "request object 签名算法无效.",
        ),
        (
            RequestObjectVerificationError::MissingKeyId,
            "request object 缺少 kid.",
        ),
        (
            RequestObjectVerificationError::InvalidKey,
            "request object 签名密钥无效.",
        ),
        (
            RequestObjectVerificationError::InvalidSignature,
            "request object 验签失败.",
        ),
    ] {
        assert_error(
            request_object_verification_error(error),
            StatusCode::BAD_REQUEST,
            "invalid_request_object",
            description,
        )
        .await;
    }
}

#[actix_web::test]
async fn policy_and_replay_errors_preserve_status_code_and_body() {
    for (error, status, code, description) in [
        (
            AuthorizationRequestError::OuterClientIdConflict,
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "request object 与外层 client_id 冲突.",
        ),
        (
            AuthorizationRequestError::InvalidRequestObjectReplay,
            StatusCode::BAD_REQUEST,
            "invalid_request_object",
            "request object jti 已使用.",
        ),
        (
            AuthorizationRequestError::Dependency(AuthorizationPortError::Unavailable),
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "request object 防重放状态不可用.",
        ),
    ] {
        assert_error(
            request_object_policy_error(error),
            status,
            code,
            description,
        )
        .await;
    }
}
