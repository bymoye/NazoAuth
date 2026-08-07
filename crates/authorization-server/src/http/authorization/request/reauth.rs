use crate::adapters::security::random_urlsafe_token;
use actix_web::HttpResponse;
use actix_web::http::StatusCode;
use chrono::Utc;
use nazo_http_actix::oauth_error;
use std::collections::HashMap;

use super::{
    AuthorizationRequestContext, authorization_login_url_for_frontend, reauth_nonce_parameter,
};

const REAUTH_NONCE_TTL_SECONDS: u64 = 600;

pub(super) async fn consume_reauth_nonce_with_context(
    context: &AuthorizationRequestContext<'_>,
    q: &mut HashMap<String, String>,
) -> Option<i64> {
    let nonce = q.remove(reauth_nonce_parameter())?;
    match context.service.take_reauth_nonce(&nonce).await {
        Ok(Some(started_at)) => (started_at > 0).then_some(started_at),
        Ok(None) => None,
        Err(error) => {
            tracing::warn!(%error, "failed to consume reauthentication nonce");
            None
        }
    }
}

pub(super) async fn authorization_login_url_with_context(
    context: &AuthorizationRequestContext<'_>,
    q: &HashMap<String, String>,
    reauthentication_required: bool,
) -> Result<String, HttpResponse> {
    let reauth_nonce = if reauthentication_required {
        Some(issue_reauth_nonce(context).await?)
    } else {
        None
    };
    Ok(authorization_login_url_for_frontend(
        context.config.frontend_base_url.as_ref(),
        q,
        reauth_nonce.as_deref(),
    ))
}

async fn issue_reauth_nonce(
    context: &AuthorizationRequestContext<'_>,
) -> Result<String, HttpResponse> {
    let nonce = random_urlsafe_token();
    let started_at = Utc::now().timestamp();
    context
        .service
        .store_reauth_nonce(&nonce, started_at, REAUTH_NONCE_TTL_SECONDS)
        .await
        .map_err(|error| {
            tracing::warn!(%error, "failed to store reauthentication nonce");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "重新认证状态写入失败.",
            )
        })?;
    Ok(nonce)
}
