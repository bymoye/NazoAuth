use super::super::issue::TokenIssuanceConfig;
use crate::http::authorization::ServerAuthorizationService;
use crate::http::rate_limit::rate_limited_response;
use actix_web::http::StatusCode;
use actix_web::{HttpRequest, HttpResponse};
use nazo_http_actix::{client_ip_with_context, oauth_token_error};

pub(super) async fn enforce_token_rate_limit(
    service: &ServerAuthorizationService,
    config: &TokenIssuanceConfig,
    req: &HttpRequest,
) -> Result<(), HttpResponse> {
    let subject = client_ip_with_context(
        req,
        config.client_ip_header_mode(),
        config.trusted_proxy_cidrs(),
    );
    let count = service
        .increment_token_rate(&subject, config.rate_limit_window_seconds())
        .await
        .map_err(|error| {
            tracing::warn!(%error, "token rate limit increment failed");
            oauth_token_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "请求频率校验失败.",
                false,
            )
        })?;
    if count > config.token_rate_limit_max_requests() {
        return Err(rate_limited_response(config.rate_limit_window_seconds()));
    }
    Ok(())
}
