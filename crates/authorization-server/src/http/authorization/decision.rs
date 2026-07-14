//! 授权确认提交端点。
use crate::adapters::audit::audit_event;
use crate::adapters::audit::audit_fields;
use crate::adapters::security::blake3_hex;
use crate::adapters::security::random_urlsafe_token;
use crate::domain::ConsentPayload;
#[cfg(test)]
use crate::domain::DatabaseUserFixture;
#[cfg(test)]
use crate::domain::TestAppState;
#[cfg(test)]
use crate::domain::tenancy::DEFAULT_ORGANIZATION_ID;
use crate::domain::tenancy::DEFAULT_REALM_ID;
use crate::domain::tenancy::DEFAULT_TENANT_ID;
use crate::domain::tenancy::default_tenant_context;
use crate::http::authorization::{AuthorizationEndpoint, AuthorizationRequestContext};
use crate::http::client_ip::client_ip_with_config;
#[cfg(test)]
use crate::settings::Settings;
#[cfg(test)]
use crate::test_support::valkey::valkey_set_ex;
use actix_web::http::StatusCode;
#[cfg(test)]
use actix_web::http::header;
use actix_web::web::{Data, Form};
use actix_web::{HttpRequest, HttpResponse};
#[cfg(test)]
use chrono::Duration;
use chrono::Utc;
use nazo_auth::{
    AuthorizationDecisionAdmissionError, UserAuthorizationDecision as AuthorizationDecision,
    parse_user_authorization_decision as parse_authorization_decision,
};
use nazo_http_actix::{csrf_error, has_valid_csrf_token_for_cookies, oauth_error};
use serde::Deserialize;
#[cfg(test)]
use serde_json::Value;
use serde_json::json;
use uuid::Uuid;
// 同意时签发一次性授权码；拒绝时按 OAuth 规范把错误回传 redirect_uri。
#[cfg(test)]
use super::authorization_response_redirect;
use super::{AuthorizationResponseRedirect, authorization_response_redirect_with_context};

#[derive(Deserialize)]
pub(crate) struct DecisionForm {
    request_id: String,
    decision: String,
    csrf_token: Option<String>,
}

#[cfg(test)]
fn parse_consent_payload(raw: Option<String>) -> Option<ConsentPayload> {
    raw.and_then(|value| serde_json::from_str::<ConsentPayload>(&value).ok())
}

async fn authorization_error_redirect_with_context(
    context: &AuthorizationRequestContext<'_>,
    payload: &ConsentPayload,
    error: &str,
) -> HttpResponse {
    authorization_response_redirect_with_context(
        context,
        AuthorizationResponseRedirect {
            redirect_uri: &payload.redirect_uri,
            client_id: &payload.client_id,
            response_mode: payload.response_mode.as_deref(),
            code: None,
            error: Some(error),
            state: payload.state.as_deref(),
            oidc_sid: None,
        },
    )
    .await
}

#[cfg(test)]
async fn authorization_error_redirect(
    state: &TestAppState,
    payload: &ConsentPayload,
    error: &str,
) -> HttpResponse {
    let dependencies = super::TestAuthorizationDependencies::new(state);
    authorization_error_redirect_with_context(&dependencies.context(), payload, error).await
}

/// 处理用户对授权请求的同意或拒绝。
pub(crate) async fn authorize_decision(
    endpoint: Data<AuthorizationEndpoint>,
    req: HttpRequest,
    Form(form): Form<DecisionForm>,
) -> HttpResponse {
    let context = endpoint.context();
    authorize_decision_with_context(&context, req, form).await
}

async fn authorize_decision_with_context(
    context: &AuthorizationRequestContext<'_>,
    req: HttpRequest,
    form: DecisionForm,
) -> HttpResponse {
    if !has_valid_csrf_token_for_cookies(
        &req,
        form.csrf_token.as_deref(),
        context.sessions.http_config().session_cookie_name(),
        context.sessions.http_config().csrf_cookie_name(),
    ) {
        return csrf_error();
    }
    let Some(decision) = parse_authorization_decision(&form.decision) else {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_request", "授权决策无效.");
    };
    let user = match context.sessions.current_user_or_login_required(&req).await {
        Ok(user) => user,
        Err(response) => return response,
    };

    let payload = match context
        .service
        .admit_user_decision(&form.request_id, user.id())
        .await
    {
        Ok(payload) => payload,
        Err(
            AuthorizationDecisionAdmissionError::ConsentMissing
            | AuthorizationDecisionAdmissionError::ConsentMalformed,
        ) => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "授权请求不存在或已过期,请重新发起授权.",
            );
        }
        Err(AuthorizationDecisionAdmissionError::ConsentReadFailed(error)) => {
            tracing::warn!(%error, "failed to claim authorization consent state");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "授权请求读取失败.",
            );
        }
        Err(AuthorizationDecisionAdmissionError::UserMismatch) => {
            return oauth_error(
                StatusCode::FORBIDDEN,
                "access_denied",
                "当前会话与授权请求不匹配.",
            );
        }
        Err(AuthorizationDecisionAdmissionError::PushedRequestMissing(payload)) => {
            return authorization_error_redirect_with_context(
                context,
                &payload,
                "invalid_request_uri",
            )
            .await;
        }
        Err(AuthorizationDecisionAdmissionError::PushedRequestMalformed(payload)) => {
            tracing::warn!("PAR payload is malformed while claiming authorization consent");
            return authorization_error_redirect_with_context(context, &payload, "server_error")
                .await;
        }
        Err(AuthorizationDecisionAdmissionError::PushedRequestReadFailed { consent, source }) => {
            tracing::warn!(%source, "failed to claim consent-bound PAR state");
            return authorization_error_redirect_with_context(context, &consent, "server_error")
                .await;
        }
    };

    match decision {
        AuthorizationDecision::Deny => {
            audit_event(
                "authorization_denied",
                audit_fields(&[
                    ("user_id", json!(payload.user_id)),
                    ("client_id", json!(payload.client_id)),
                    ("scope", json!(payload.scopes.join(" "))),
                    (
                        "source_ip_hash",
                        json!(blake3_hex(&client_ip_with_config(
                            &req,
                            &context.config.client_ip,
                        ))),
                    ),
                ]),
            );
            return authorization_error_redirect_with_context(context, &payload, "access_denied")
                .await;
        }
        AuthorizationDecision::Approve => {}
    }

    let now = Utc::now();
    let code = random_urlsafe_token();
    let code_id = Uuid::now_v7().to_string();
    let oidc_sid = payload.oidc_sid.clone();
    let code_hash = blake3_hex(&code);
    if let Err(error) = context
        .service
        .approve_consent(nazo_auth::AuthorizationApprovalInput {
            consent: &payload,
            code_hash: &code_hash,
            code_id: &code_id,
            issued_at: now,
            code_ttl_seconds: context.config.auth_code_ttl_seconds,
            tenant_id: default_tenant_context().tenant_id,
        })
        .await
    {
        tracing::warn!(%error, "failed to persist user client grant");
        return oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "授权记录写入失败.",
        );
    }

    audit_event(
        "authorization_approved",
        audit_fields(&[
            ("user_id", json!(payload.user_id)),
            ("client_id", json!(payload.client_id)),
            ("scope", json!(payload.scopes.join(" "))),
            (
                "source_ip_hash",
                json!(blake3_hex(&client_ip_with_config(
                    &req,
                    &context.config.client_ip,
                ))),
            ),
        ]),
    );

    authorization_response_redirect_with_context(
        context,
        AuthorizationResponseRedirect {
            redirect_uri: &payload.redirect_uri,
            client_id: &payload.client_id,
            response_mode: payload.response_mode.as_deref(),
            code: Some(&code),
            error: None,
            state: payload.state.as_deref(),
            oidc_sid: oidc_sid.as_deref(),
        },
    )
    .await
}

#[cfg(test)]
#[path = "../../../tests/in_source/src/http/authorization/tests/decision.rs"]
mod tests;
