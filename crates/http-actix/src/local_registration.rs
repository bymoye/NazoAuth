use std::{future::Future, pin::Pin, sync::Arc};

use actix_web::{
    HttpRequest, HttpResponse,
    http::{StatusCode, header},
    web::{Data, Json},
};
use nazo_identity::{
    RegisterLocalAccountError, RegisterLocalAccountInput, SendVerificationCodeError,
    SendVerificationCodeOutcome, email::normalize_email_address, registration::RegisteredAccount,
};
use serde::Deserialize;
use serde_json::json;

use crate::{
    ClientIpConfig, authorization_error_response, client_ip_with_config, json_response,
    json_response_status, oauth_error,
};

pub type LocalRegistrationFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

pub trait LocalRegistrationOperations: Send + Sync {
    fn send_verification_code<'a>(
        &'a self,
        normalized_email: &'a str,
        peer_subject: &'a str,
    ) -> LocalRegistrationFuture<'a, Result<SendVerificationCodeOutcome, SendVerificationCodeError>>;

    fn register_local_account(
        &self,
        input: RegisterLocalAccountInput,
    ) -> LocalRegistrationFuture<'_, Result<RegisteredAccount, RegisterLocalAccountError>>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthenticationRateLimitError {
    Limited { retry_after_seconds: u64 },
    Unavailable,
}

pub trait AuthenticationRateLimit: Send + Sync {
    fn enforce<'a>(
        &'a self,
        subject: &'a str,
    ) -> LocalRegistrationFuture<'a, Result<(), AuthenticationRateLimitError>>;
}

#[derive(Clone)]
pub struct LocalRegistrationEndpoint {
    operations: Arc<dyn LocalRegistrationOperations>,
    rate_limit: Arc<dyn AuthenticationRateLimit>,
    client_ip: ClientIpConfig,
    dev_response_enabled: bool,
}

impl LocalRegistrationEndpoint {
    #[must_use]
    pub fn new(
        operations: Arc<dyn LocalRegistrationOperations>,
        rate_limit: Arc<dyn AuthenticationRateLimit>,
        client_ip: ClientIpConfig,
        dev_response_enabled: bool,
    ) -> Self {
        Self {
            operations,
            rate_limit,
            client_ip,
            dev_response_enabled,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct SendCodeRequest {
    email: String,
}

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    email: String,
    verification_code: String,
    password: String,
}

/// Sends a registration verification code without exposing account existence.
pub async fn send_code(
    endpoint: Data<LocalRegistrationEndpoint>,
    request: HttpRequest,
    Json(payload): Json<SendCodeRequest>,
) -> HttpResponse {
    if let Err(error) = endpoint
        .rate_limit
        .enforce(&client_ip_with_config(&request, &endpoint.client_ip))
        .await
    {
        return authentication_rate_limit_error_response(error);
    }

    let Ok(email) = normalize_email_address(&payload.email) else {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_request", "邮箱格式无效.");
    };
    let peer_subject = request
        .peer_addr()
        .map(|address| address.ip().to_string())
        .unwrap_or_else(|| "unknown".to_owned());
    match endpoint
        .operations
        .send_verification_code(&email, &peer_subject)
        .await
    {
        Ok(SendVerificationCodeOutcome::Suppressed) => {
            send_code_success_response(endpoint.dev_response_enabled, None)
        }
        Ok(SendVerificationCodeOutcome::Sent { code }) => {
            send_code_success_response(endpoint.dev_response_enabled, Some(&code))
        }
        Err(SendVerificationCodeError::DeliveryNotConfigured) => oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "邮件发送未配置.",
        ),
        Err(SendVerificationCodeError::AccountLookup(_)) => oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "数据库连接失败.",
        ),
        Err(
            SendVerificationCodeError::Reservation(_) | SendVerificationCodeError::CodeStore(_),
        ) => oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "验证码生成失败.",
        ),
        Err(SendVerificationCodeError::CodeHash(_)) => oauth_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "验证码生成失败.",
        ),
        Err(SendVerificationCodeError::Delivery(_)) => oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "验证码发送失败.",
        ),
    }
}

/// Creates a verified local account from a one-time email code.
pub async fn register(
    endpoint: Data<LocalRegistrationEndpoint>,
    request: HttpRequest,
    Json(payload): Json<RegisterRequest>,
) -> HttpResponse {
    if let Err(error) = endpoint
        .rate_limit
        .enforce(&client_ip_with_config(&request, &endpoint.client_ip))
        .await
    {
        return authentication_rate_limit_error_response(error);
    }

    let Ok(email) = normalize_email_address(&payload.email) else {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_request", "邮箱格式无效.");
    };
    let input = RegisterLocalAccountInput {
        email,
        verification_code: payload.verification_code.trim().to_owned(),
        password: payload.password,
    };
    match endpoint.operations.register_local_account(input).await {
        Ok(account) => json_response_status(
            StatusCode::CREATED,
            json!({"id": account.id, "email": account.email}),
        ),
        Err(RegisterLocalAccountError::InvalidVerificationCode) => oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "验证码错误或已过期.",
        ),
        Err(RegisterLocalAccountError::VerificationUnavailable(_)) => oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "验证码校验失败.",
        ),
        Err(RegisterLocalAccountError::AccountLookup(_)) => oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "数据库连接失败.",
        ),
        Err(RegisterLocalAccountError::Conflict) => {
            oauth_error(StatusCode::CONFLICT, "invalid_request", "该邮箱已注册.")
        }
        Err(RegisterLocalAccountError::PasswordHash(_)) => oauth_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "密码哈希失败.",
        ),
        Err(RegisterLocalAccountError::Create(_)) => oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "用户创建失败.",
        ),
        Err(RegisterLocalAccountError::Consistency) => oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "用户创建失败.",
        ),
    }
}

fn authentication_rate_limit_error_response(error: AuthenticationRateLimitError) -> HttpResponse {
    match error {
        AuthenticationRateLimitError::Limited {
            retry_after_seconds,
        } => {
            let mut response = authorization_error_response(
                StatusCode::TOO_MANY_REQUESTS,
                "temporarily_unavailable",
                "请求过于频繁，请稍后重试.",
            );
            if let Ok(value) = header::HeaderValue::from_str(&retry_after_seconds.to_string()) {
                response.headers_mut().insert(header::RETRY_AFTER, value);
            }
            response
        }
        AuthenticationRateLimitError::Unavailable => oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "请求频率校验失败.",
        ),
    }
}

fn send_code_success_response(dev_response_enabled: bool, code: Option<&str>) -> HttpResponse {
    let mut body = json!({"success": true, "message": "如果邮箱尚未注册，验证码将会发送。"});
    if cfg!(debug_assertions)
        && dev_response_enabled
        && let Some(code) = code
    {
        body["verification_code"] = json!(code);
    }
    json_response(body)
}

#[cfg(test)]
#[path = "../tests/unit/local_registration.rs"]
mod tests;
