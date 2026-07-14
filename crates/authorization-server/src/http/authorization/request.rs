//! 授权请求入口端点。
use crate::adapters::security::blake3_hex;
#[cfg(test)]
use crate::adapters::security::pkce_s256;
use crate::adapters::security::random_urlsafe_token;
#[cfg(test)]
use crate::domain::TestAppState;
use crate::domain::client_jwe::JwePayloadKind;
use crate::domain::client_jwe::client_jwe_key;
use crate::domain::client_jwe::encrypt_compact_jwe;
use crate::domain::client_policy::RedirectUriError;
#[cfg(test)]
use crate::domain::client_policy::authorization_code_key;
use crate::domain::client_policy::client_supports_grant;
use crate::domain::client_policy::registered_redirect_uri;
#[cfg(test)]
use crate::domain::tenancy::DEFAULT_ORGANIZATION_ID;
#[cfg(test)]
use crate::domain::tenancy::DEFAULT_REALM_ID;
#[cfg(test)]
use crate::domain::tenancy::DEFAULT_TENANT_ID;
#[cfg(test)]
use crate::domain::{AuthorizationCodeState, DatabaseUserFixture, PushedAuthorizationRequest};
use crate::domain::{ClientRow, ConsentPayload};
#[cfg(test)]
use crate::http::sessions::SessionPayload;
use crate::http::views::append_query;
#[cfg(test)]
use crate::settings::Settings;
#[cfg(test)]
use crate::test_support::valkey::valkey_get;
#[cfg(test)]
use crate::test_support::valkey::valkey_set_ex;
use actix_web::http::StatusCode;
#[cfg(test)]
use actix_web::http::header;
use actix_web::web::{Bytes, Data};
use actix_web::{HttpRequest, HttpResponse};
use chrono::{Duration, Utc};
#[cfg(test)]
use nazo_auth::OidcClaimRequest;
use nazo_auth::{
    AuthorizationCapabilityPolicy, AuthorizationClientPolicy, AuthorizationProfilePolicy,
    AuthorizationResponsePlan, AuthorizationResponsePolicyError, AuthorizationResponsePolicyInput,
    AuthorizationSession, AuthorizationSessionDecision, is_valid_dpop_jkt,
    normalize_authorization_request, parse_scope, plan_authorization_response,
};
use nazo_http_actix::{
    OAuthJsonErrorFields, authorization_error_response, oauth_error, redirect_found,
};
use serde_json::Value;
#[cfg(test)]
use serde_json::json;
use std::collections::HashMap;
use uuid::Uuid;
// 该端点只创建 consent 临时状态，不签发授权码。
use super::{
    AuthorizationEndpoint, AuthorizationRequestContext, apply_request_object_with_context,
    is_pushed_authorization_request_uri, unverified_signed_request_object_client_id,
};
use nazo_auth::issue_oidc_session_state;

mod form;
mod parameters;
mod prompt_none;

use form::*;
use parameters::*;
use prompt_none::*;

const REAUTH_NONCE_TTL_SECONDS: u64 = 600;

/// 校验 OAuth authorize 参数并创建待确认授权请求。
pub(crate) async fn authorize_get(
    endpoint: Data<AuthorizationEndpoint>,
    req: HttpRequest,
) -> HttpResponse {
    let query_parameters = authorization_duplicate_parameters();
    let mut q = match parse_authorization_query(req.query_string(), &query_parameters) {
        Ok(q) => q,
        Err(response) => return response,
    };
    let context = endpoint.context();
    authorize_request_with_context(&context, req, &mut q).await
}

pub(crate) async fn authorize_post(
    endpoint: Data<AuthorizationEndpoint>,
    req: HttpRequest,
    body: Bytes,
) -> HttpResponse {
    let query_parameters = authorization_duplicate_parameters();
    let mut q = match parse_authorization_post_form(&req, &body, &query_parameters) {
        Ok(q) => q,
        Err(response) => return response,
    };
    let context = endpoint.context();
    authorize_request_with_context(&context, req, &mut q).await
}

async fn authorize_request_with_context(
    context: &AuthorizationRequestContext<'_>,
    req: HttpRequest,
    q: &mut HashMap<String, String>,
) -> HttpResponse {
    if let Some(response) = runtime_authorization_capability_error(context, q) {
        return response;
    }

    let original_authorization_query = q.clone();
    let reauth_started_at = consume_reauth_nonce_with_context(context, q).await;
    let mut pushed_dpop_jkt = None;
    let mut pushed_mtls_x5t_s256 = None;
    let mut consumed_request_uri_error: Option<&'static str> = None;
    let mut used_pushed_authorization_request = false;
    let mut pending_pushed_request_uri = None;
    let mut pending_pushed_request_digest = None;
    if let Some(request_uri) = q.get("request_uri").cloned() {
        if !is_pushed_authorization_request_uri(&request_uri) {
            consumed_request_uri_error = Some("request_uri_not_supported");
        } else {
            let pushed = match context.service.load_par(&request_uri).await {
                Ok(Some(pushed)) => Some(pushed),
                Ok(None) => {
                    consumed_request_uri_error = Some("invalid_request_uri");
                    None
                }
                Err(error) => {
                    tracing::warn!(%error, "failed to read PAR request_uri");
                    return oauth_error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "server_error",
                        "request_uri 读取失败.",
                    );
                }
            };
            if let Some(pushed) = pushed {
                if q.get("client_id")
                    .is_some_and(|client_id| client_id != &pushed.client_id)
                {
                    consumed_request_uri_error = Some("invalid_request_uri");
                } else {
                    let outer_parameters_are_fapi_invalid =
                        context.config.profile.requires_fapi2_security()
                            && !outer_request_uri_parameters_are_fapi_compliant(q);
                    let outer_parameters_mismatch =
                        !outer_request_uri_parameters_match_pushed(q, &pushed.params);
                    if outer_parameters_are_fapi_invalid || outer_parameters_mismatch {
                        consumed_request_uri_error = Some("invalid_request");
                        *q = pushed.params;
                    } else {
                        let digest = match nazo_auth::pushed_authorization_request_digest(&pushed) {
                            Ok(digest) => digest,
                            Err(error) => {
                                tracing::warn!(%error, "failed to bind PAR transaction state");
                                return oauth_error(
                                    StatusCode::SERVICE_UNAVAILABLE,
                                    "server_error",
                                    "request_uri 读取失败.",
                                );
                            }
                        };
                        pushed_dpop_jkt = pushed.dpop_jkt;
                        pushed_mtls_x5t_s256 = pushed.mtls_x5t_s256;
                        used_pushed_authorization_request = true;
                        pending_pushed_request_uri = Some(request_uri);
                        pending_pushed_request_digest = Some(digest);
                        *q = pushed.params;
                    }
                }
            }
        }
    } else if context.config.require_pushed_authorization_requests {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "该服务要求使用 pushed authorization request.",
        );
    }

    if let Some(response) = runtime_authorization_capability_error(context, q) {
        return response;
    }

    if !q.contains_key("client_id")
        && let Some(request_object) = q.get("request")
        && let Some(client_id) = unverified_signed_request_object_client_id(request_object)
    {
        q.insert("client_id".to_owned(), client_id);
    }

    let Some(client_id) = q.get("client_id") else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "缺少 client_id.",
        );
    };

    let client = match context.service.client_by_id(client_id).await {
        Ok(Some(client)) => client,
        Ok(None) => {
            return oauth_error(
                StatusCode::UNAUTHORIZED,
                "unauthorized_client",
                "客户端不存在或已停用.",
            );
        }
        Err(error) => {
            tracing::warn!(%error, "failed to query oauth client");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "客户端查询失败.",
            );
        }
    };
    if !client.is_active {
        return oauth_error(
            StatusCode::UNAUTHORIZED,
            "unauthorized_client",
            "客户端不存在或已停用.",
        );
    }
    if !client_supports_grant(&client, "authorization_code") {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "unauthorized_client",
            "该客户端未启用 authorization_code 授权类型.",
        );
    }
    let request_object_error = apply_request_object_with_context(context, q, &client)
        .await
        .err();
    if let Some(response) = runtime_authorization_capability_error(context, q) {
        return response;
    }
    let request_dpop_jkt = match q.get("dpop_jkt") {
        Some(value) if is_valid_dpop_jkt(value) => Some(value.clone()),
        Some(_) => {
            return oauth_error(StatusCode::BAD_REQUEST, "invalid_request", "dpop_jkt 无效.");
        }
        None => None,
    };
    let dpop_jkt = match (pushed_dpop_jkt, request_dpop_jkt) {
        (Some(pushed), Some(requested)) if pushed != requested => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "dpop_jkt 与 PAR 绑定不匹配.",
            );
        }
        (Some(pushed), _) => Some(pushed),
        (None, requested) => requested,
    };
    preserve_verified_dpop_binding(q, dpop_jkt.as_deref());
    let mtls_x5t_s256 = pushed_mtls_x5t_s256;
    let redirect_uri =
        match registered_redirect_uri(&client, q.get("redirect_uri").map(String::as_str)) {
            Ok(value) => value,
            Err(RedirectUriError::Missing) => {
                return authorization_error_response(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "redirect_uri is required for this authorization request.",
                );
            }
            Err(RedirectUriError::Invalid) => {
                return authorization_error_response(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "redirect_uri is not registered for this client.",
                );
            }
        };

    if let Some(error) = consumed_request_uri_error {
        return authorization_oauth_error_redirect(context, &redirect_uri, error, q).await;
    }
    if let Some(error_response) = request_object_error {
        if let Some(error) = oauth_json_error(&error_response) {
            return authorization_oauth_error_redirect(context, &redirect_uri, &error, q).await;
        }
        return error_response;
    }
    let normalized = match normalize_authorization_request(
        q,
        AuthorizationClientPolicy {
            client_type: &client.client_type,
            allowed_scopes: &client.scopes,
            allowed_audiences: &client.allowed_audiences,
            require_dpop_bound_tokens: client.require_dpop_bound_tokens,
            require_mtls_bound_tokens: client.require_mtls_bound_tokens,
            allow_authorization_code_without_pkce: client.allow_authorization_code_without_pkce,
        },
        AuthorizationCapabilityPolicy {
            authorization_details: crate::http::authorization::accepts_module(
                context,
                nazo_runtime_modules::ModuleId::AuthorizationDetails,
            ),
            jarm: crate::http::authorization::accepts_module(
                context,
                nazo_runtime_modules::ModuleId::Jarm,
            ),
            native_sso: crate::http::authorization::accepts_module(
                context,
                nazo_runtime_modules::ModuleId::NativeSso,
            ),
        },
        AuthorizationProfilePolicy {
            signed_authorization_response_required: context
                .config
                .profile
                .requires_signed_authorization_response(),
        },
        used_pushed_authorization_request,
    ) {
        Ok(normalized) => normalized,
        Err(error) => {
            return authorization_oauth_error_redirect(
                context,
                &redirect_uri,
                error.oauth_error(),
                q,
            )
            .await;
        }
    };

    let session = match context.sessions.current_session(&req).await {
        Ok(session) => session,
        Err(error) => {
            tracing::warn!(%error, "failed to resolve authorization request user");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "会话查询失败.",
            );
        }
    };
    match nazo_auth::authorization_session_decision(
        session.as_ref().map(|session| AuthorizationSession {
            auth_time: session.auth_time,
        }),
        normalized.prompt,
        normalized.max_age,
        reauth_started_at,
        Utc::now().timestamp(),
    ) {
        AuthorizationSessionDecision::LoginRequired => {
            return authorization_response_redirect_with_context(
                context,
                AuthorizationResponseRedirect {
                    redirect_uri: &redirect_uri,
                    client_id: q.get("client_id").map(String::as_str).unwrap_or(""),
                    response_mode: q.get("response_mode").map(String::as_str),
                    code: None,
                    error: Some("login_required"),
                    state: q.get("state").map(String::as_str),
                    oidc_sid: None,
                },
            )
            .await;
        }
        AuthorizationSessionDecision::Login {
            fresh_authentication,
        } => {
            return match authorization_login_url_with_context(
                context,
                &authorization_login_query(
                    q,
                    &original_authorization_query,
                    pending_pushed_request_uri.as_ref(),
                ),
                fresh_authentication,
            )
            .await
            {
                Ok(location) => redirect_found(location),
                Err(response) => response,
            };
        }
        AuthorizationSessionDecision::Continue => {}
    }
    let session = session.expect("authorization session policy allowed continuation");
    let now = Utc::now();
    let request_id = Uuid::now_v7().to_string();
    let payload = ConsentPayload {
        request_id: request_id.clone(),
        user_id: session.user.id(),
        client_id: client.client_id.clone(),
        client_name: client.client_name.clone(),
        redirect_uri: redirect_uri.clone(),
        redirect_uri_was_supplied: q.contains_key("redirect_uri"),
        scopes: normalized.scopes,
        resource_indicators: normalized.resources,
        authorization_details: normalized.authorization_details,
        state: q.get("state").cloned(),
        response_mode: normalized.response_mode,
        nonce: q.get("nonce").cloned(),
        auth_time: session.auth_time,
        amr: session.amr,
        oidc_sid: Some(session.oidc_sid),
        acr: normalized.acr,
        userinfo_claims: claim_request_names(&normalized.requested_claims.userinfo),
        userinfo_claim_requests: normalized.requested_claims.userinfo,
        id_token_claims: claim_request_names(&normalized.requested_claims.id_token),
        id_token_claim_requests: normalized.requested_claims.id_token,
        code_challenge: normalized.code_challenge,
        code_challenge_method: normalized.code_challenge_method,
        dpop_jkt,
        mtls_x5t_s256,
        pushed_request_uri: pending_pushed_request_uri,
        pushed_request_digest: pending_pushed_request_digest,
        issued_at: now,
        expires_at: now + Duration::seconds(context.config.auth_code_ttl_seconds as i64),
    };
    if normalized.prompt.none {
        match user_grant_covers_requested_scopes_with_context(
            context,
            payload.user_id,
            client.id,
            &payload.scopes,
            &payload.resource_indicators,
            &payload.authorization_details,
        )
        .await
        {
            Ok(true) => {
                return issue_authorization_code_without_interaction_with_context(
                    context, &req, payload,
                )
                .await;
            }
            Ok(false) => {
                return authorization_oauth_error_redirect(
                    context,
                    &redirect_uri,
                    "consent_required",
                    q,
                )
                .await;
            }
            Err(response) => return response,
        }
    }
    if let Err(error) = context
        .service
        .store_consent(&request_id, &payload, context.config.auth_code_ttl_seconds)
        .await
    {
        tracing::warn!(%error, "failed to persist consent request");
        return oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "授权请求创建失败.",
        );
    }

    redirect_found(format!(
        "{}/consent?request_id={request_id}",
        context.config.frontend_base_url.trim_end_matches('/')
    ))
}

fn runtime_authorization_capability_error(
    context: &AuthorizationRequestContext<'_>,
    parameters: &HashMap<String, String>,
) -> Option<HttpResponse> {
    if !crate::http::authorization::accepts_module(
        context,
        nazo_runtime_modules::ModuleId::RequestObjects,
    ) && parameters.contains_key("request")
    {
        return Some(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "request 参数未启用.",
        ));
    }
    if !crate::http::authorization::accepts_module(
        context,
        nazo_runtime_modules::ModuleId::AuthorizationDetails,
    ) && parameters.contains_key("authorization_details")
    {
        return Some(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "authorization_details 参数未启用.",
        ));
    }
    if parameters
        .get("response_mode")
        .is_some_and(|mode| mode == "jwt")
        && !crate::http::authorization::accepts_module(
            context,
            nazo_runtime_modules::ModuleId::Jarm,
        )
    {
        return Some(oauth_error(
            StatusCode::BAD_REQUEST,
            "unsupported_response_mode",
            "JWT-secured authorization responses are disabled.",
        ));
    }
    if parameters
        .get("scope")
        .is_some_and(|scope| parse_scope(scope).iter().any(|value| value == "device_sso"))
        && !crate::http::authorization::accepts_module(
            context,
            nazo_runtime_modules::ModuleId::NativeSso,
        )
    {
        return Some(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_scope",
            "Native SSO is disabled.",
        ));
    }
    None
}

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

#[cfg(test)]
pub(crate) async fn consume_pushed_authorization_request(
    state: &TestAppState,
    request_uri: &str,
) -> Result<(), PushedAuthorizationRequestConsumeError> {
    let dependencies = super::TestAuthorizationDependencies::new(state);
    consume_pushed_authorization_request_with_context(&dependencies.context(), request_uri).await
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
        },
    )
    .await
}

pub(crate) struct AuthorizationResponseRedirect<'a> {
    pub(crate) redirect_uri: &'a str,
    pub(crate) client_id: &'a str,
    pub(crate) response_mode: Option<&'a str>,
    pub(crate) code: Option<&'a str>,
    pub(crate) error: Option<&'a str>,
    pub(crate) state: Option<&'a str>,
    pub(crate) oidc_sid: Option<&'a str>,
}

pub(crate) async fn authorization_response_redirect_with_context(
    context: &AuthorizationRequestContext<'_>,
    input: AuthorizationResponseRedirect<'_>,
) -> HttpResponse {
    let signed_response_required = context
        .config
        .profile
        .requires_signed_authorization_response();
    let jarm_available = crate::http::authorization::permits_existing_module_transaction(
        context,
        nazo_runtime_modules::ModuleId::Jarm,
    );
    let session_management_available = crate::http::authorization::accepts_module(
        context,
        nazo_runtime_modules::ModuleId::SessionManagement,
    );
    let plan = match plan_authorization_response(AuthorizationResponsePolicyInput {
        issuer: context.config.issuer.as_ref(),
        redirect_uri: input.redirect_uri,
        client_id: input.client_id,
        response_mode: input.response_mode,
        code: input.code,
        error: input.error,
        state: input.state,
        ttl_seconds: context.config.auth_code_ttl_seconds as i64,
        signed_response_required,
        jarm_available,
        session_management_available,
    }) {
        Ok(plan) => plan,
        Err(AuthorizationResponsePolicyError::UnsupportedResponseMode) => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "unsupported_response_mode",
                "JWT-secured authorization responses are disabled.",
            );
        }
        Err(AuthorizationResponsePolicyError::MissingClientId) => {
            tracing::warn!("cannot build signed authorization response without client_id");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "authorization response signing failed.",
            );
        }
        Err(AuthorizationResponsePolicyError::Dependency(error)) => {
            tracing::warn!(?error, "authorization response policy dependency failed");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "authorization response protection failed.",
            );
        }
    };
    if matches!(plan, AuthorizationResponsePlan::Jarm(_)) {
        debug_assert!(jarm_available);
        let client = match context.service.client_by_id(input.client_id).await {
            Ok(Some(client)) if client.is_active => client,
            Ok(_) => {
                tracing::warn!(client_id_hash = %blake3_hex(input.client_id), "JARM client is missing or inactive");
                return oauth_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "server_error",
                    "authorization response protection failed.",
                );
            }
            Err(error) => {
                tracing::warn!(%error, client_id_hash = %blake3_hex(input.client_id), "failed to load JARM client response policy");
                return oauth_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "server_error",
                    "authorization response protection failed.",
                );
            }
        };
        let protection = AuthorizationResponseProtection::from(&client);
        return authorization_response_redirect_with_protection_context(context, input, protection)
            .await;
    }
    let AuthorizationResponsePlan::Plain(plain) = plan else {
        unreachable!("JARM response returned above")
    };
    let session_state = if plain.issue_session_state {
        input
            .oidc_sid
            .and_then(|sid| issue_oidc_session_state(input.client_id, input.redirect_uri, sid))
    } else {
        None
    };
    redirect_found(append_authorization_response_query(
        input.redirect_uri,
        context.config.issuer.as_ref(),
        input.code,
        input.error,
        input.state,
        session_state.as_deref(),
    ))
}

#[cfg(test)]
pub(crate) async fn authorization_response_redirect(
    state: &TestAppState,
    input: AuthorizationResponseRedirect<'_>,
) -> HttpResponse {
    let dependencies = super::TestAuthorizationDependencies::new(state);
    authorization_response_redirect_with_context(&dependencies.context(), input).await
}

#[derive(Clone, Copy, Default)]
struct AuthorizationResponseProtection<'a> {
    signing_alg: Option<&'a str>,
    encryption_alg: Option<&'a str>,
    encryption_enc: Option<&'a str>,
    jwks: Option<&'a Value>,
}

impl<'a> From<&'a ClientRow> for AuthorizationResponseProtection<'a> {
    fn from(client: &'a ClientRow) -> Self {
        Self {
            signing_alg: client.authorization_signed_response_alg.as_deref(),
            encryption_alg: client.authorization_encrypted_response_alg.as_deref(),
            encryption_enc: client.authorization_encrypted_response_enc.as_deref(),
            jwks: client.jwks.as_ref(),
        }
    }
}

async fn authorization_response_redirect_with_protection_context(
    context: &AuthorizationRequestContext<'_>,
    input: AuthorizationResponseRedirect<'_>,
    protection: AuthorizationResponseProtection<'_>,
) -> HttpResponse {
    let result = protected_authorization_response_jwt(context, &input, protection).await;
    authorization_response_jwt_result(input.redirect_uri, result)
}

#[cfg(test)]
async fn authorization_response_redirect_with_protection(
    state: &TestAppState,
    input: AuthorizationResponseRedirect<'_>,
    protection: AuthorizationResponseProtection<'_>,
) -> HttpResponse {
    let dependencies = super::TestAuthorizationDependencies::new(state);
    authorization_response_redirect_with_protection_context(
        &dependencies.context(),
        input,
        protection,
    )
    .await
}

async fn protected_authorization_response_jwt(
    context: &AuthorizationRequestContext<'_>,
    input: &AuthorizationResponseRedirect<'_>,
    protection: AuthorizationResponseProtection<'_>,
) -> anyhow::Result<String> {
    let signed = context
        .service
        .sign_authorization_response(nazo_auth::AuthorizationResponseSignInput {
            issuer: context.config.issuer.as_ref(),
            client_id: input.client_id,
            code: input.code,
            error: input.error,
            state: input.state,
            ttl: context.config.auth_code_ttl_seconds as i64,
            signing_algorithm: protection.signing_alg,
        })
        .await
        .map_err(|error| anyhow::anyhow!("authorization response signing failed: {error:?}"))?;
    match client_jwe_key(
        protection.jwks,
        protection.encryption_alg,
        protection.encryption_enc,
        "authorization response",
    )? {
        Some(key) => Ok(encrypt_compact_jwe(
            &key,
            signed.as_bytes(),
            JwePayloadKind::NestedJwt,
        )?),
        None => Ok(signed),
    }
}

fn authorization_response_jwt_result(
    redirect_uri: &str,
    result: anyhow::Result<String>,
) -> HttpResponse {
    match result {
        Ok(response) => authorization_response_jwt_redirect(redirect_uri, &response),
        Err(error) => {
            tracing::warn!(%error, "failed to protect JARM authorization response");
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "authorization response signing failed.",
            )
        }
    }
}

fn authorization_response_jwt_redirect(redirect_uri: &str, response: &str) -> HttpResponse {
    redirect_found(append_query(redirect_uri, &[("response", response)]))
}

fn oauth_json_error(response: &HttpResponse) -> Option<String> {
    let extensions = response.extensions();
    extensions
        .get::<OAuthJsonErrorFields>()
        .map(|fields| fields.error.clone())
}

async fn consume_reauth_nonce_with_context(
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

#[cfg(test)]
async fn consume_reauth_nonce(
    state: &TestAppState,
    q: &mut HashMap<String, String>,
) -> Option<i64> {
    let dependencies = super::TestAuthorizationDependencies::new(state);
    consume_reauth_nonce_with_context(&dependencies.context(), q).await
}

async fn authorization_login_url_with_context(
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

#[cfg(test)]
async fn authorization_login_url(
    state: &TestAppState,
    q: &HashMap<String, String>,
    reauthentication_required: bool,
) -> Result<String, HttpResponse> {
    let dependencies = super::TestAuthorizationDependencies::new(state);
    authorization_login_url_with_context(&dependencies.context(), q, reauthentication_required)
        .await
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

#[cfg(test)]
#[path = "../../../tests/in_source/src/http/authorization/tests/request.rs"]
mod tests;
