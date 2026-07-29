//! refresh_token grant 处理。
use crate::adapters::audit::audit_event;
use crate::adapters::audit::audit_fields;
use crate::adapters::security::ValidatedClientAssertion;
use crate::adapters::security::blake3_hex;
use crate::adapters::security::constant_time_eq;

use crate::domain::client_policy::audiences_allowed;
use crate::domain::client_policy::is_subset;
use crate::domain::client_policy::json_array_to_strings;
use crate::domain::client_policy::parse_scope;

use crate::domain::{ClientRow, RefreshTokenPolicy, TokenIssue, TokenRow};
use crate::http::dpop::DpopErrorContext;
use crate::http::dpop::dpop_error_response;
use crate::http::dpop::dpop_proof_present;
use crate::http::dpop::validate_dpop_proof_with_authorization_service;
use crate::http::mtls::request_mtls_thumbprint_from_trusted_proxy;

use actix_web::http::StatusCode;

use actix_web::{HttpRequest, HttpResponse};

use chrono::{DateTime, Utc};
use nazo_http_actix::client_ip_with_context;
use nazo_http_actix::oauth_token_error;

use serde_json::json;
use uuid::Uuid;
// 只处理 refresh token 校验、复用检测和轮换前置约束。

use super::{
    ServerTokenService, TokenForm, consume_token_client_assertion_with_authorization_service,
    issue::{TokenIssuanceContext, issue_token_response_with_service},
    should_issue_refresh_token,
};
use crate::settings::AuthorizationServerProfile;

fn refresh_token_policy_for_authorization_server_profile(
    profile: AuthorizationServerProfile,
    client: &ClientRow,
    token: &TokenRow,
) -> RefreshTokenPolicy {
    let sender_constrained_confidential_client = client.client_type == "confidential"
        && (client.require_dpop_bound_tokens || client.require_mtls_bound_tokens);
    if sender_constrained_confidential_client
        || (profile
            .effective_client_policy(client)
            .requires_fapi2_security()
            && refresh_token_has_stable_sender_constraint(token))
    {
        RefreshTokenPolicy::PreserveExisting
    } else {
        RefreshTokenPolicy::Rotate {
            family_id: token.token_family_id,
            rotated_from_id: token.id,
        }
    }
}

fn refresh_token_has_stable_sender_constraint(token: &TokenRow) -> bool {
    token.dpop_jkt.is_some() || token.mtls_x5t_s256.is_some()
}

fn refresh_token_policy_for_profile_value(
    profile: AuthorizationServerProfile,
    client: &ClientRow,
    token: &TokenRow,
) -> RefreshTokenPolicy {
    refresh_token_policy_for_authorization_server_profile(profile, client, token)
}

fn refresh_token_scopes(
    original_scopes: &[String],
    requested_scope: Option<&str>,
) -> Result<Vec<String>, ()> {
    let Some(requested) = requested_scope.map(parse_scope) else {
        return Ok(original_scopes.to_vec());
    };
    if requested.is_empty() {
        return Ok(original_scopes.to_vec());
    }
    if is_subset(&requested, original_scopes) {
        Ok(requested)
    } else {
        Err(())
    }
}

fn client_attestation_refresh_binding_matches(
    token_endpoint_auth_method: &str,
    expected: Option<&str>,
    presented: Option<&str>,
) -> bool {
    // Attestation-Based Client Authentication draft-07 section 10.3 binds a
    // refresh token to the Client Instance and the public key in cnf.jwk.
    if token_endpoint_auth_method != "attest_jwt_client_auth" {
        return expected.is_none() && presented.is_none();
    }
    matches!(
        (expected, presented),
        (Some(expected), Some(presented))
            if constant_time_eq(expected.as_bytes(), presented.as_bytes())
    )
}

fn refresh_token_audiences_with_default(
    default_audience: &str,
    token: &TokenRow,
    form: &TokenForm,
) -> Result<Vec<String>, ()> {
    let original_audiences = json_array_to_strings(&token.audience);
    let original_audiences = if original_audiences.is_empty() {
        vec![default_audience.to_owned()]
    } else {
        original_audiences
    };
    if form.audiences.is_empty() {
        return Ok(original_audiences);
    }
    is_subset(&form.audiences, &original_audiences)
        .then(|| form.audiences.clone())
        .ok_or(())
}

async fn lost_response_successor_or_mark_reuse(
    service: &ServerTokenService,
    token: &TokenRow,
    client_id: Uuid,
    retry_started_at: DateTime<Utc>,
) -> anyhow::Result<Option<TokenRow>> {
    service
        .recover_lost_refresh_response(token, client_id, retry_started_at)
        .await
        .map_err(|error| anyhow::anyhow!("failed to inspect refresh family: {error:?}"))
}

pub(crate) async fn token_refresh_with_service(
    token_service: &ServerTokenService,
    issuance: &TokenIssuanceContext<'_>,
    req: &HttpRequest,
    client: &ClientRow,
    form: &TokenForm,
    client_assertion: Option<&ValidatedClientAssertion>,
    client_attestation_jkt: Option<&str>,
) -> HttpResponse {
    let request_started_at = Utc::now();
    let Some(refresh_token) = &form.refresh_token else {
        return oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "缺少 refresh_token.",
            false,
        );
    };
    let token = match token_service
        .refresh_token(client.tenant_id, refresh_token)
        .await
    {
        Ok(value) => value,
        Err(error) => {
            tracing::warn!(?error, "failed to load refresh token");
            return oauth_token_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "refresh_token 校验失败.",
                false,
            );
        }
    };
    let Some(mut token) = token else {
        return oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "refresh_token 无效.",
            false,
        );
    };
    if token.client_id != client.id || token.expires_at <= Utc::now() {
        return oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "refresh_token 无效或已撤销.",
            false,
        );
    }
    if !client_attestation_refresh_binding_matches(
        &client.token_endpoint_auth_method,
        token.client_attestation_jkt.as_deref(),
        client_attestation_jkt,
    ) {
        return oauth_token_error(
            StatusCode::UNAUTHORIZED,
            "invalid_client_attestation",
            "Refresh token is not bound to this client instance key.",
            false,
        );
    }
    let mut lost_response_original_id = None;
    if token.revoked_at.is_some() {
        let successor = lost_response_successor_or_mark_reuse(
            token_service,
            &token,
            client.id,
            request_started_at,
        )
        .await;
        match successor {
            Ok(Some(successor)) => {
                lost_response_original_id = Some(token.id);
                token = successor;
            }
            Ok(None) => {
                audit_event(
                    "refresh_reuse_detected",
                    audit_fields(&[
                        ("client_id", json!(client.client_id)),
                        ("token_family_id", json!(token.token_family_id)),
                        (
                            "source_ip_hash",
                            json!(blake3_hex(&client_ip_with_context(
                                req,
                                issuance.config.client_ip_header_mode(),
                                issuance.config.trusted_proxy_cidrs(),
                            ))),
                        ),
                    ]),
                );
                return oauth_token_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "refresh_token 无效或已撤销.",
                    false,
                );
            }
            Err(error) => {
                tracing::warn!(%error, "failed to inspect or mark rotated refresh token family");
                return oauth_token_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "server_error",
                    "refresh_token 复用处理失败.",
                    false,
                );
            }
        }
    }
    let original_scopes = json_array_to_strings(&token.scopes);
    if let Some(user_id) = token.user_id {
        match token_service
            .active_subject_claims(token.tenant_id, user_id)
            .await
        {
            Ok(Some(_)) => {}
            Ok(None) => {
                return oauth_token_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "授权用户不存在或已停用.",
                    false,
                );
            }
            Err(error) => {
                tracing::warn!(?error, "failed to load refresh token user");
                return oauth_token_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "server_error",
                    "refresh_token 用户校验失败.",
                    false,
                );
            }
        }
    }
    let dpop_jkt = if dpop_proof_present(req) {
        match validate_dpop_proof_with_authorization_service(
            issuance.authorization,
            issuance.config.issuer(),
            issuance.config.mtls_endpoint_base_url(),
            issuance.config.dpop_nonce_policy(),
            req,
            None,
            token.dpop_jkt.as_deref(),
        )
        .await
        {
            Ok(value) => value.or(token.dpop_jkt.clone()),
            Err(error) => return dpop_error_response(error, DpopErrorContext::TokenEndpoint),
        }
    } else if token.dpop_jkt.is_some() {
        return oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "refresh_token requires proof of possession.",
            false,
        );
    } else {
        None
    };
    if client.client_type == "public"
        && client.require_dpop_bound_tokens
        && token.dpop_jkt.is_none()
    {
        return oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "refresh_token is not DPoP-bound.",
            false,
        );
    }
    if client.require_dpop_bound_tokens && dpop_jkt.is_none() {
        return oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "refresh_token requires proof of possession.",
            false,
        );
    }
    let mtls_x5t_s256 = if let Some(expected) = token.mtls_x5t_s256.clone() {
        match request_mtls_thumbprint_from_trusted_proxy(req, issuance.config.trusted_proxy_cidrs())
        {
            Some(actual) if constant_time_eq(expected.as_bytes(), actual.as_bytes()) => {
                Some(expected)
            }
            _ => {
                return oauth_token_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "refresh_token requires mTLS proof of possession.",
                    false,
                );
            }
        }
    } else if client.require_mtls_bound_tokens {
        match request_mtls_thumbprint_from_trusted_proxy(req, issuance.config.trusted_proxy_cidrs())
        {
            Some(actual) => Some(actual),
            None => {
                return oauth_token_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "refresh_token requires mTLS proof of possession.",
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
    let openid4vci_credential_authorization = issuance
        .config
        .openid4vci_audience(&original_scopes, &token.authorization_details)
        .is_some();
    if !should_issue_refresh_token(
        client,
        &original_scopes,
        openid4vci_credential_authorization,
    ) {
        return oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "refresh_token 不具备可续期授权.",
            false,
        );
    }
    let scopes = match refresh_token_scopes(&original_scopes, form.scope.as_deref()) {
        Ok(scopes) => scopes,
        Err(()) => {
            return oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_scope",
                "请求的作用域超出 refresh_token 原始授权范围.",
                false,
            );
        }
    };
    let audiences = match refresh_token_audiences_with_default(
        issuance.config.default_audience(),
        &token,
        form,
    ) {
        Ok(audiences) => audiences,
        Err(()) => {
            return oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_target",
                "请求的 resource 超出 refresh_token 原始授权范围.",
                false,
            );
        }
    };
    if !audiences_allowed(client, &audiences) {
        return oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_target",
            "请求的 audience 不在客户端允许范围内.",
            false,
        );
    }
    let refresh_token_policy = match lost_response_original_id {
        Some(original_id) => RefreshTokenPolicy::RotateLostResponse {
            family_id: token.token_family_id,
            original_id,
            successor_id: token.id,
            retry_started_at: request_started_at,
        },
        None => refresh_token_policy_for_profile_value(
            issuance.config.authorization_server_profile(),
            client,
            &token,
        ),
    };
    issue_token_response_with_service(
        issuance,
        token_service,
        client,
        TokenIssue {
            user_id: token.user_id,
            subject: token.subject,
            scopes,
            authorization_details: token.authorization_details,
            audiences,
            nonce: None,
            auth_time: None,
            amr: Vec::new(),
            oidc_sid: None,
            acr: None,
            userinfo_claims: Vec::new(),
            userinfo_claim_requests: Vec::new(),
            id_token_claims: Vec::new(),
            id_token_claim_requests: Vec::new(),
            include_refresh: true,
            refresh_token_policy,
            dpop_jkt: dpop_jkt.clone(),
            refresh_token_dpop_jkt: token.dpop_jkt,
            mtls_x5t_s256: mtls_x5t_s256.clone(),
            refresh_token_mtls_x5t_s256: mtls_x5t_s256,
            refresh_token_client_attestation_jkt: token.client_attestation_jkt,
            refresh_token_scopes: Some(original_scopes),
            authorization_code_hash: None,
            actor: None,
            issued_token_type: None,
            native_sso: None,
        },
    )
    .await
}

#[cfg(test)]
#[path = "../../../tests/unit/http/token/refresh.rs"]
mod tests;
