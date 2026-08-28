use crate::adapters::audit::audit_event;
use crate::adapters::audit::audit_fields;
use crate::adapters::security::blake3_hex;
use crate::adapters::security::random_urlsafe_token;
use crate::domain::{AuthorizationCodeState, CodePayload, ConsentPayload};
use crate::http::authorization::AuthorizationRequestContext;
use crate::http::authorization::request::{
    AuthorizationResponseClientPolicy, AuthorizationResponseRedirect,
    PushedAuthorizationRequestConsumeError, authorization_response_redirect_with_context,
    consume_pushed_authorization_request_with_context,
};
use actix_web::http::StatusCode;
use actix_web::{HttpRequest, HttpResponse};
use chrono::{Duration, Utc};
use nazo_http_actix::client_ip_with_config;
use nazo_http_actix::oauth_error;
use serde_json::{Value, json};
use uuid::Uuid;

pub(super) async fn user_grant_covers_requested_scopes_with_context(
    context: &AuthorizationRequestContext<'_>,
    user_id: Uuid,
    client_id: Uuid,
    requested_scopes: &[String],
    requested_resource_indicators: &[String],
    requested_authorization_details: &Value,
) -> Result<bool, HttpResponse> {
    match context
        .service
        .grant_covers(
            user_id,
            client_id,
            requested_scopes,
            requested_resource_indicators,
            requested_authorization_details,
        )
        .await
    {
        Ok(value) => Ok(value),
        Err(error) => {
            tracing::warn!(%error, "failed to query authorization grant");
            Err(oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "授权记录查询失败.",
            ))
        }
    }
}

pub(super) async fn issue_authorization_code_without_interaction_with_context(
    context: &AuthorizationRequestContext<'_>,
    req: &HttpRequest,
    payload: ConsentPayload,
) -> HttpResponse {
    let (Some(signed_response_required), Some(session_management_allowed), Some(ttl_seconds)) = (
        payload.signed_authorization_response_required,
        payload.session_management_allowed,
        payload.authorization_code_ttl_seconds,
    ) else {
        return oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "authorization request has no current client security policy.",
        );
    };
    let response_policy = AuthorizationResponseClientPolicy {
        signed_response_required,
        session_management_allowed,
        ttl_seconds,
    };
    if let Some(request_uri) = payload.pushed_request_uri.as_deref() {
        match consume_pushed_authorization_request_with_context(context, request_uri).await {
            Ok(()) => {}
            Err(PushedAuthorizationRequestConsumeError::Missing) => {
                return authorization_response_redirect_with_context(
                    context,
                    AuthorizationResponseRedirect {
                        redirect_uri: &payload.redirect_uri,
                        client_id: &payload.client_id,
                        response_mode: payload.response_mode.as_deref(),
                        code: None,
                        error: Some("invalid_request_uri"),
                        state: payload.state.as_deref(),
                        oidc_sid: None,
                        client_policy: Some(response_policy),
                    },
                )
                .await;
            }
            Err(PushedAuthorizationRequestConsumeError::ReadFailed)
            | Err(PushedAuthorizationRequestConsumeError::Malformed) => {
                return authorization_response_redirect_with_context(
                    context,
                    AuthorizationResponseRedirect {
                        redirect_uri: &payload.redirect_uri,
                        client_id: &payload.client_id,
                        response_mode: payload.response_mode.as_deref(),
                        code: None,
                        error: Some("server_error"),
                        state: payload.state.as_deref(),
                        oidc_sid: None,
                        client_policy: Some(response_policy),
                    },
                )
                .await;
            }
        }
    }

    let now = Utc::now();
    let code = random_urlsafe_token();
    let oidc_sid = payload.oidc_sid.clone();
    let code_payload = CodePayload {
        code_id: Uuid::now_v7().to_string(),
        user_id: payload.user_id,
        client_id: payload.client_id.clone(),
        redirect_uri: payload.redirect_uri.clone(),
        redirect_uri_was_supplied: payload.redirect_uri_was_supplied,
        scopes: payload.scopes.clone(),
        resource_indicators: payload.resource_indicators,
        authorization_details: payload.authorization_details,
        nonce: payload.nonce,
        auth_time: payload.auth_time,
        amr: payload.amr,
        oidc_sid: payload.oidc_sid,
        acr: payload.acr,
        userinfo_claims: payload.userinfo_claims,
        userinfo_claim_requests: payload.userinfo_claim_requests,
        id_token_claims: payload.id_token_claims,
        id_token_claim_requests: payload.id_token_claim_requests,
        code_challenge: payload.code_challenge,
        code_challenge_method: payload.code_challenge_method,
        dpop_jkt: payload.dpop_jkt,
        mtls_x5t_s256: payload.mtls_x5t_s256,
        issued_at: now,
        expires_at: now + Duration::seconds(response_policy.ttl_seconds as i64),
    };
    if let Err(error) = context
        .service
        .store_authorization_code(
            &blake3_hex(&code),
            &AuthorizationCodeState::Pending {
                payload: code_payload,
            },
            response_policy.ttl_seconds,
        )
        .await
    {
        tracing::warn!(%error, "failed to persist prompt=none authorization code");
        return oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "授权码创建失败.",
        );
    }
    audit_event(
        "authorization_prompt_none_approved",
        audit_fields(&[
            ("user_id", json!(payload.user_id)),
            ("client_id", json!(payload.client_id)),
            ("scope", json!(payload.scopes.join(" "))),
            (
                "source_ip_hash",
                json!(blake3_hex(&client_ip_with_config(
                    req,
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
            client_policy: Some(response_policy),
        },
    )
    .await
}
