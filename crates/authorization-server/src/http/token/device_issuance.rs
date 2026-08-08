//! Device grant handoff into the shared typed token-issuance pipeline.
//!
//! Device state admission, polling, client binding, and one-time consumption live
//! behind [`super::device::ServerDeviceGrantService`], while token minting uses
//! [`TokenIssuanceContext`] and [`ServerTokenService`]. Sender constraints and
//! client-assertion consumption use the focused authorization service carried by
//! the issuance context.
use crate::adapters::security::ValidatedClientAssertion;
use crate::adapters::security::blake3_hex;
use crate::domain::{ClientRow, RefreshTokenPolicy, TokenIssue};
use crate::http::dpop::DpopErrorContext;
use crate::http::dpop::dpop_error_response;
use actix_web::{HttpRequest, HttpResponse, http::StatusCode};
use chrono::Utc;
use nazo_auth::{DevicePollCommit, DevicePollFailure};
use nazo_http_actix::oauth_token_error;

use super::client_auth::consume_token_client_assertion_with_authorization_service;
use super::{
    SenderConstraintValidationError, ServerTokenService, TokenForm,
    device::ServerDeviceGrantService,
    issue::{TokenIssuanceContext, issue_token_response_with_service_and_grant},
    sender_constraint_multiple_error, validate_token_sender_constraints,
};

pub(super) fn device_grant_key(
    device_code: &str,
    dpop_jkt: Option<&str>,
    mtls_x5t_s256: Option<&str>,
) -> String {
    format!(
        "device_code:{}:{}:{}",
        blake3_hex(device_code),
        dpop_jkt.map(blake3_hex).unwrap_or_default(),
        mtls_x5t_s256.map(blake3_hex).unwrap_or_default(),
    )
}

pub(crate) async fn token_device_code_with_service(
    token_service: &ServerTokenService,
    issuance: &TokenIssuanceContext<'_>,
    device_service: &ServerDeviceGrantService,
    req: &HttpRequest,
    client: &ClientRow,
    form: &TokenForm,
    client_assertion: Option<&ValidatedClientAssertion>,
) -> HttpResponse {
    if !issuance.permits(nazo_runtime_modules::ModuleId::DeviceAuthorization) {
        return oauth_token_error(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            "Device Authorization Grant is not enabled.",
            false,
        );
    }
    if !issuance
        .config
        .authorization_server_profile()
        .effective_client_policy(client)
        .allow_cross_device_flows
    {
        return oauth_token_error(
            StatusCode::BAD_REQUEST,
            "unauthorized_client",
            "This client is not authorized for cross-device flows.",
            false,
        );
    }
    let device_code = match required_device_code(form) {
        Ok(device_code) => device_code,
        Err(response) => return response,
    };
    let sender =
        match validate_token_sender_constraints(issuance, req, client, None, None, None).await {
            Ok(value) => value,
            Err(SenderConstraintValidationError::Dpop(error)) => {
                return dpop_error_response(error, DpopErrorContext::TokenEndpoint);
            }
            Err(SenderConstraintValidationError::MissingMtls) => {
                return oauth_token_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "device_code requires mTLS sender constraint.",
                    false,
                );
            }
            Err(SenderConstraintValidationError::Multiple) => {
                return sender_constraint_multiple_error();
            }
        };
    let device_grant_key = device_grant_key(
        device_code,
        sender.dpop_jkt.as_deref(),
        sender.mtls_x5t_s256.as_deref(),
    );
    if let Err(error) = consume_token_client_assertion_with_authorization_service(
        issuance.authorization,
        client,
        client_assertion,
    )
    .await
    {
        return super::token_client_assertion_error(error);
    }

    match device_service
        .poll(device_code, &client.client_id, Utc::now)
        .await
    {
        Ok(DevicePollCommit::AuthorizationPending) => oauth_token_error(
            StatusCode::BAD_REQUEST,
            "authorization_pending",
            "授权仍在等待用户确认.",
            false,
        ),
        Ok(DevicePollCommit::SlowDown) => {
            oauth_token_error(StatusCode::BAD_REQUEST, "slow_down", "设备轮询过快.", false)
        }
        Ok(DevicePollCommit::AccessDenied) => oauth_token_error(
            StatusCode::BAD_REQUEST,
            "access_denied",
            "用户拒绝设备授权.",
            false,
        ),
        Ok(DevicePollCommit::Expired) => oauth_token_error(
            StatusCode::BAD_REQUEST,
            "expired_token",
            "device_code 已过期.",
            false,
        ),
        Ok(DevicePollCommit::Consumed) => oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "device_code 已使用.",
            false,
        ),
        Ok(DevicePollCommit::Approved(approved)) => {
            let nazo_auth::ApprovedDeviceAuthorization { payload, approval } = *approved;
            issue_token_response_with_service_and_grant(
                issuance,
                token_service,
                client,
                Some(&device_grant_key),
                TokenIssue {
                    user_id: Some(approval.user_id),
                    subject: approval.subject,
                    scopes: payload.scopes,
                    authorization_details: payload.authorization_details,
                    audiences: payload.resource_indicators,
                    nonce: None,
                    auth_time: Some(approval.auth_time),
                    amr: approval.amr,
                    oidc_sid: approval.oidc_sid,
                    acr: None,
                    userinfo_claims: Vec::new(),
                    userinfo_claim_requests: Vec::new(),
                    id_token_claims: Vec::new(),
                    id_token_claim_requests: Vec::new(),
                    refresh_id_token_sid: None,
                    include_refresh: true,
                    refresh_token_policy: RefreshTokenPolicy::IssueNew,
                    refresh_token_dpop_jkt: sender.dpop_jkt.clone(),
                    dpop_jkt: sender.dpop_jkt,
                    mtls_x5t_s256: sender.mtls_x5t_s256.clone(),
                    refresh_token_mtls_x5t_s256: sender.mtls_x5t_s256,
                    refresh_token_client_attestation_jkt: None,
                    refresh_token_scopes: None,
                    authorization_code_hash: None,
                    actor: None,
                    issued_token_type: None,
                    native_sso: None,
                },
            )
            .await
        }
        Err(DevicePollFailure::Missing) => oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "device_code 无效或已过期.",
            false,
        ),
        Err(DevicePollFailure::ClientMismatch) => oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "device_code 未签发给该客户端.",
            false,
        ),
        Err(DevicePollFailure::Storage(error)) => {
            tracing::warn!(%error, "failed to update device authorization state");
            oauth_token_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "设备授权状态读取失败.",
                false,
            )
        }
        Err(DevicePollFailure::Contended) => oauth_token_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "设备授权状态正忙.",
            false,
        ),
    }
}

pub(super) fn required_device_code(form: &TokenForm) -> Result<&str, HttpResponse> {
    form.device_code
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "缺少 device_code.",
                false,
            )
        })
}

#[cfg(test)]
#[path = "../../../tests/unit/http/token/device_issuance.rs"]
mod tests;
