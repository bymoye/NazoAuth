use actix_web::HttpResponse;
use std::collections::HashMap;

use super::{
    AuthorizationRequestContext, AuthorizationResponseRedirect,
    authorization_response_redirect_with_context,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PushedAuthorizationRequestConsumeError {
    Missing,
    ReadFailed,
    Malformed,
}

pub(crate) async fn consume_pushed_authorization_request_with_context(
    context: &AuthorizationRequestContext<'_>,
    request_uri: &str,
) -> Result<(), PushedAuthorizationRequestConsumeError> {
    match context.service.take_par(request_uri).await {
        Ok(Some(_)) => Ok(()),
        Ok(None) => Err(PushedAuthorizationRequestConsumeError::Missing),
        Err(nazo_auth::AuthorizationPortError::CorruptData) => {
            tracing::warn!("PAR payload is malformed");
            Err(PushedAuthorizationRequestConsumeError::Malformed)
        }
        Err(error) => {
            tracing::warn!(%error, "failed to consume PAR request_uri");
            Err(PushedAuthorizationRequestConsumeError::ReadFailed)
        }
    }
}

pub(crate) async fn authorization_oauth_error_redirect(
    context: &AuthorizationRequestContext<'_>,
    redirect_uri: &str,
    error: &str,
    q: &HashMap<String, String>,
) -> HttpResponse {
    authorization_response_redirect_with_context(
        context,
        AuthorizationResponseRedirect {
            redirect_uri,
            client_id: q.get("client_id").map(String::as_str).unwrap_or(""),
            response_mode: q.get("response_mode").map(String::as_str),
            code: None,
            error: Some(error),
            state: q.get("state").map(String::as_str),
            oidc_sid: None,
            client_policy: None,
        },
    )
    .await
}
