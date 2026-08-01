//! 基于 Valkey 的固定窗口限流。
//! 限流主体默认取连接来源地址，不信任可伪造的转发头。
use nazo_http_actix::{authorization_error_response, oauth_error};

use actix_web::http::StatusCode;
use actix_web::http::header;
use actix_web::http::header::HeaderValue;
use actix_web::{HttpRequest, HttpResponse};
use nazo_http_actix::{ClientIpConfig, client_ip_with_config};

#[derive(Clone, Copy)]
pub(crate) struct AuthRateLimitConfig {
    window_seconds: u64,
    max_requests: u64,
}

/// Focused HTTP security dependency for authentication endpoint rate limits.
///
/// It owns the storage adapter, threshold policy, and trusted-proxy client IP
/// derivation so handlers cannot issue Valkey commands or reconstruct policy.
#[derive(Clone)]
pub(crate) struct AuthRequestLimiter {
    store: nazo_valkey::RateLimitStore,
    config: AuthRateLimitConfig,
    client_ip: ClientIpConfig,
}

/// Focused rate-limit adapter for token-management endpoints.
#[derive(Clone)]
pub(crate) struct TokenManagementRequestLimiter {
    store: nazo_valkey::RateLimitStore,
    window_seconds: u64,
    max_requests: u64,
    client_ip: ClientIpConfig,
}

impl TokenManagementRequestLimiter {
    pub(crate) fn new(
        store: nazo_valkey::RateLimitStore,
        window_seconds: u64,
        max_requests: u64,
        client_ip: ClientIpConfig,
    ) -> Self {
        Self {
            store,
            window_seconds,
            max_requests,
            client_ip,
        }
    }

    pub(crate) async fn enforce(&self, req: &HttpRequest) -> Result<(), HttpResponse> {
        let count = self
            .store
            .increment(
                nazo_valkey::RateDimension::TokenManagement,
                &client_ip_with_config(req, &self.client_ip),
                self.window_seconds,
            )
            .await
            .map_err(|error| {
                tracing::warn!(%error, "rate limit increment failed");
                oauth_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "server_error",
                    "请求频率校验失败.",
                )
            })?;
        if count > self.max_requests {
            return Err(rate_limited_response(self.window_seconds));
        }
        Ok(())
    }
}

impl AuthRequestLimiter {
    pub(crate) fn new(
        store: nazo_valkey::RateLimitStore,
        window_seconds: u64,
        max_requests: u64,
        client_ip: ClientIpConfig,
    ) -> Self {
        Self {
            store,
            config: AuthRateLimitConfig::new(window_seconds, max_requests),
            client_ip,
        }
    }

    pub(crate) async fn enforce(&self, req: &HttpRequest) -> Result<(), HttpResponse> {
        enforce_auth_rate_limit(&self.store, req, self.config, &self.client_ip).await
    }
}

impl AuthRateLimitConfig {
    pub(crate) fn new(window_seconds: u64, max_requests: u64) -> Self {
        Self {
            window_seconds,
            max_requests,
        }
    }
}

pub(crate) async fn enforce_auth_rate_limit(
    store: &nazo_valkey::RateLimitStore,
    req: &HttpRequest,
    config: AuthRateLimitConfig,
    client_ip: &ClientIpConfig,
) -> Result<(), HttpResponse> {
    let count = store
        .increment(
            nazo_valkey::RateDimension::Auth,
            &client_ip_with_config(req, client_ip),
            config.window_seconds,
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "rate limit increment failed");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "请求频率校验失败.",
            )
        })?;
    if count > config.max_requests {
        return Err(rate_limited_response(config.window_seconds));
    }
    Ok(())
}

pub(crate) fn rate_limited_response(retry_after_seconds: u64) -> HttpResponse {
    let mut response = authorization_error_response(
        StatusCode::TOO_MANY_REQUESTS,
        "temporarily_unavailable",
        "请求过于频繁，请稍后重试.",
    );
    if let Ok(value) = HeaderValue::from_str(&retry_after_seconds.to_string()) {
        response.headers_mut().insert(header::RETRY_AFTER, value);
    }
    response
}

#[cfg(test)]
#[path = "../../tests/unit/http/rate_limit.rs"]
mod tests;
