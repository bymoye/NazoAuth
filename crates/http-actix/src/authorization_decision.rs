use std::{future::Future, pin::Pin, sync::Arc};

use actix_web::{
    HttpRequest, HttpResponse,
    http::StatusCode,
    web::{Data, Form},
};
use nazo_auth::UserAuthorizationDecision;
use nazo_identity::SessionId;
use serde::Deserialize;

use crate::{
    ClientIpConfig, SessionCookieConfig, client_ip_with_config, csrf_error,
    login_required_response, oauth_error, redirect_found,
};

pub type AuthorizationDecisionFuture<'a> = Pin<
    Box<
        dyn Future<Output = Result<AuthorizationDecisionRedirect, AuthorizationDecisionError>>
            + Send
            + 'a,
    >,
>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizationDecisionCommand {
    pub request_id: String,
    pub decision: UserAuthorizationDecision,
    pub session_id: SessionId,
    pub source_ip: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizationDecisionRedirect {
    pub location: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorizationDecisionError {
    LoginRequired,
    SessionLookupUnavailable,
    ConsentInvalid,
    ConsentReadUnavailable,
    UserMismatch,
    ApprovalUnavailable,
    UnsupportedResponseMode,
    ResponseProtectionUnavailable,
    ResponseSigningUnavailable,
}

pub trait AuthorizationDecisionOperations: Send + Sync {
    fn decide(&self, command: AuthorizationDecisionCommand) -> AuthorizationDecisionFuture<'_>;
}

#[derive(Clone)]
pub struct AuthorizationDecisionEndpoint {
    operations: Arc<dyn AuthorizationDecisionOperations>,
    cookies: SessionCookieConfig,
    client_ip: ClientIpConfig,
}

impl AuthorizationDecisionEndpoint {
    #[must_use]
    pub fn new(
        operations: Arc<dyn AuthorizationDecisionOperations>,
        cookies: SessionCookieConfig,
        client_ip: ClientIpConfig,
    ) -> Self {
        Self {
            operations,
            cookies,
            client_ip,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct AuthorizationDecisionForm {
    pub request_id: String,
    pub decision: String,
    pub csrf_token: Option<String>,
}

pub async fn authorize_decision(
    endpoint: Data<AuthorizationDecisionEndpoint>,
    request: HttpRequest,
    Form(form): Form<AuthorizationDecisionForm>,
) -> HttpResponse {
    if !endpoint
        .cookies
        .has_valid_csrf_token(&request, form.csrf_token.as_deref())
    {
        return csrf_error();
    }
    let Some(decision) = nazo_auth::parse_user_authorization_decision(&form.decision) else {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_request", "授权决策无效.");
    };
    let Some(session_id) = endpoint.cookies.session_id(&request) else {
        return login_required_response(&endpoint.cookies);
    };
    let command = AuthorizationDecisionCommand {
        request_id: form.request_id,
        decision,
        session_id,
        source_ip: client_ip_with_config(&request, &endpoint.client_ip),
    };
    match endpoint.operations.decide(command).await {
        Ok(redirect) => redirect_found(redirect.location),
        Err(error) => authorization_decision_error_response(error, &endpoint.cookies),
    }
}

fn authorization_decision_error_response(
    error: AuthorizationDecisionError,
    cookies: &SessionCookieConfig,
) -> HttpResponse {
    match error {
        AuthorizationDecisionError::LoginRequired => login_required_response(cookies),
        AuthorizationDecisionError::SessionLookupUnavailable => oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "会话查询失败.",
        ),
        AuthorizationDecisionError::ConsentInvalid => oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "授权请求不存在或已过期,请重新发起授权.",
        ),
        AuthorizationDecisionError::ConsentReadUnavailable => oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "授权请求读取失败.",
        ),
        AuthorizationDecisionError::UserMismatch => oauth_error(
            StatusCode::FORBIDDEN,
            "access_denied",
            "当前会话与授权请求不匹配.",
        ),
        AuthorizationDecisionError::ApprovalUnavailable => oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "授权记录写入失败.",
        ),
        AuthorizationDecisionError::UnsupportedResponseMode => oauth_error(
            StatusCode::BAD_REQUEST,
            "unsupported_response_mode",
            "JWT-secured authorization responses are disabled.",
        ),
        AuthorizationDecisionError::ResponseProtectionUnavailable => oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "authorization response protection failed.",
        ),
        AuthorizationDecisionError::ResponseSigningUnavailable => oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "authorization response signing failed.",
        ),
    }
}
