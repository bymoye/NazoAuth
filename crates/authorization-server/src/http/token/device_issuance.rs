//! Device grant handoff into the shared typed token-issuance pipeline.
//!
//! Device state admission, polling, client binding, and one-time consumption live
//! behind [`super::device::ServerDeviceGrantService`], while token minting uses
//! [`TokenIssuanceContext`] and [`ServerTokenService`]. Sender constraints and
//! client-assertion consumption use the focused authorization service carried by
//! the issuance context.
use crate::adapters::security::ValidatedClientAssertion;
use crate::domain::{ClientRow, RefreshTokenPolicy, TokenIssue};
use crate::http::dpop::DpopError;
use crate::http::dpop::DpopErrorContext;
use crate::http::dpop::dpop_error_response;
use crate::http::dpop::validate_dpop_proof_with_authorization_service;
use crate::http::mtls::request_mtls_thumbprint_from_trusted_proxy;
use actix_web::{HttpRequest, HttpResponse, http::StatusCode};
use chrono::Utc;
use nazo_auth::{DevicePollCommit, DevicePollFailure};
use nazo_http_actix::oauth_token_error;

use super::client_auth::consume_token_client_assertion_with_authorization_service;
use super::{
    ServerTokenService, TokenForm,
    device::ServerDeviceGrantService,
    issue::{TokenIssuanceContext, issue_token_response_with_service},
};

pub(crate) async fn token_device_code_with_service(
    token_service: &ServerTokenService,
    issuance: &TokenIssuanceContext<'_>,
    device_service: &ServerDeviceGrantService,
    req: &HttpRequest,
    client: &ClientRow,
    form: &TokenForm,
    client_assertion: Option<&ValidatedClientAssertion>,
) -> HttpResponse {
    if !issuance.accepts(nazo_runtime_modules::ModuleId::DeviceAuthorization) {
        return oauth_token_error(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            "Device Authorization Grant is not enabled.",
            false,
        );
    }
    let device_code = match required_device_code(form) {
        Ok(device_code) => device_code,
        Err(response) => return response,
    };
    let dpop_jkt = match validate_dpop_proof_with_authorization_service(
        issuance.authorization,
        issuance.config.issuer(),
        issuance.config.mtls_endpoint_base_url(),
        issuance.config.dpop_nonce_policy(),
        req,
        None,
        None,
    )
    .await
    {
        Ok(value) => value,
        Err(error) => return dpop_error_response(error, DpopErrorContext::TokenEndpoint),
    };
    if client.require_dpop_bound_tokens && dpop_jkt.is_none() {
        return dpop_error_response(DpopError::MissingProof, DpopErrorContext::TokenEndpoint);
    }
    let mtls_x5t_s256 = if client.require_mtls_bound_tokens {
        match request_mtls_thumbprint_from_trusted_proxy(req, issuance.config.trusted_proxy_cidrs())
        {
            Some(value) => Some(value),
            None => {
                return oauth_token_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "device_code requires mTLS sender constraint.",
                    false,
                );
            }
        }
    } else {
        None
    };
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
            issue_token_response_with_service(
                issuance,
                token_service,
                client,
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
                    include_refresh: true,
                    refresh_token_policy: RefreshTokenPolicy::IssueNew,
                    refresh_token_dpop_jkt: dpop_jkt.clone(),
                    dpop_jkt,
                    mtls_x5t_s256: mtls_x5t_s256.clone(),
                    refresh_token_mtls_x5t_s256: mtls_x5t_s256,
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
    form.device_code.as_deref().ok_or_else(|| {
        oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "缺少 device_code.",
            false,
        )
    })
}
