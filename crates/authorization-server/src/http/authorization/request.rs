//! 授权请求入口端点。
use crate::adapters::security::blake3_hex;
use crate::adapters::security::random_urlsafe_token;

use crate::domain::client_jwe::JwePayloadKind;
use crate::domain::client_jwe::client_jwe_key;
use crate::domain::client_jwe::encrypt_compact_jwe;
use crate::domain::client_policy::RedirectUriError;

use crate::domain::client_policy::client_supports_grant;
use crate::domain::client_policy::registered_redirect_uri;

use crate::domain::{ClientRow, ConsentPayload};

use crate::http::views::append_query;

use actix_web::http::StatusCode;

use actix_web::web::{Bytes, Data};
use actix_web::{HttpRequest, HttpResponse};
use chrono::{Duration, Utc};

use nazo_auth::{
    AuthorizationCapabilityPolicy, AuthorizationClientPolicy, AuthorizationProfilePolicy,
    AuthorizationResponsePlan, AuthorizationResponsePolicyError, AuthorizationResponsePolicyInput,
    AuthorizationSession, AuthorizationSessionDecision, is_valid_dpop_jkt,
    normalize_authorization_request, parse_scope, plan_authorization_response,
};
use nazo_http_actix::{
    OAuthJsonErrorFields, authorization_error_response, form_post_authorization_response,
    oauth_error, redirect_found,
};
use serde_json::Value;

use std::collections::HashMap;
use uuid::Uuid;
// 该端点只创建 consent 临时状态，不签发授权码。
use super::{
    AuthorizationEndpoint, AuthorizationRequestContext, apply_request_object_with_context,
    is_pushed_authorization_request_uri,
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
    let mut pending_external_request_uri = None;
    if let Some(request_uri) = q.get("request_uri").cloned() {
        if !is_pushed_authorization_request_uri(&request_uri) {
            if !crate::http::authorization::accepts_module(
                context,
                nazo_runtime_modules::ModuleId::RequestObjects,
            ) {
                consumed_request_uri_error = Some("request_uri_not_supported");
            } else {
                pending_external_request_uri = Some(request_uri);
            }
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
                    let outer_parameters_mismatch =
                        !outer_request_uri_parameters_match_pushed(q, &pushed.params);
                    if outer_parameters_mismatch {
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
        && let Some(client_id) =
            super::unverified_request_object_client_id(context.request_object_keys, request_object)
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
    let client_policy = context.config.profile.effective_client_policy(&client);
    if client_policy.requires_fapi2_security()
        && used_pushed_authorization_request
        && !outer_request_uri_parameters_are_fapi_compliant(&original_authorization_query)
    {
        consumed_request_uri_error = Some("invalid_request");
    }
    if client_policy.requires_fapi2_security() && pending_external_request_uri.is_some() {
        consumed_request_uri_error = Some("request_uri_not_supported");
        pending_external_request_uri = None;
    }
    if let Some(request_uri) = pending_external_request_uri.as_deref() {
        if q.contains_key("request") || !client.request_uris.iter().any(|uri| uri == request_uri) {
            consumed_request_uri_error = Some("invalid_request_uri");
        } else if let Some(resolver) = context.remote_client_documents {
            match resolver.request_object(request_uri).await {
                Ok(request_object) => {
                    q.remove("request_uri");
                    q.insert("request".to_owned(), request_object);
                }
                Err(error) => {
                    tracing::warn!(%error, "registered request_uri could not be resolved");
                    consumed_request_uri_error = Some("invalid_request_uri");
                }
            }
        } else {
            consumed_request_uri_error = Some("request_uri_not_supported");
        }
    }
    let direct_request_object_present = q.contains_key("request");
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
    if client_policy.requires_fapi2_security() && !used_pushed_authorization_request {
        return authorization_oauth_error_redirect(context, &redirect_uri, "invalid_request", q)
            .await;
    }
    if client_policy.require_signed_authorization_request
        && !used_pushed_authorization_request
        && !direct_request_object_present
    {
        return authorization_oauth_error_redirect(context, &redirect_uri, "invalid_request", q)
            .await;
    }
    if let Some(error_response) = request_object_error {
        if let Some(error) = oauth_json_error(&error_response) {
            return authorization_oauth_error_redirect(context, &redirect_uri, &error, q).await;
        }
        return error_response;
    }
    let mut normalized = match normalize_authorization_request(
        q,
        AuthorizationClientPolicy {
            client_type: &client.client_type,
            allowed_scopes: &client.scopes,
            allowed_audiences: &client.allowed_audiences,
            require_dpop_bound_tokens: client.require_dpop_bound_tokens,
            require_mtls_bound_tokens: client.require_mtls_bound_tokens,
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
            form_post: !client_policy.requires_fapi2_security(),
        },
        AuthorizationProfilePolicy {
            signed_authorization_response_required: client_policy
                .require_signed_authorization_response,
            pkce_required: !client_policy.allow_confidential_oidc_without_pkce
                || client_policy.requires_fapi2_security()
                || client.require_dpop_bound_tokens
                || client.require_mtls_bound_tokens
                || dpop_jkt.is_some()
                || mtls_x5t_s256.is_some(),
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
                    client_policy: Some(AuthorizationResponseClientPolicy {
                        signed_response_required: client_policy
                            .require_signed_authorization_response,
                        session_management_allowed: client_policy.session_management,
                        ttl_seconds: if client_policy.requires_fapi2_security() {
                            context.config.auth_code_ttl_seconds.min(60)
                        } else {
                            context.config.auth_code_ttl_seconds
                        },
                    }),
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
    if let Some(issuer_state) = q.get("issuer_state") {
        if !crate::http::authorization::accepts_module(
            context,
            nazo_runtime_modules::ModuleId::Openid4vciIssuer,
        ) {
            return authorization_oauth_error_redirect(
                context,
                &redirect_uri,
                "invalid_request",
                q,
            )
            .await;
        }
        let Some(offers) = context.credential_authorization_offers else {
            return authorization_oauth_error_redirect(
                context,
                &redirect_uri,
                "temporarily_unavailable",
                q,
            )
            .await;
        };
        let authorization = match offers
            .resolve_authorization_offer(
                &blake3_hex(issuer_state),
                session.user.id(),
                &client.client_id,
                Utc::now(),
            )
            .await
        {
            Ok(Some(authorization)) => authorization,
            Ok(None) => {
                return authorization_oauth_error_redirect(
                    context,
                    &redirect_uri,
                    "invalid_request",
                    q,
                )
                .await;
            }
            Err(error) => {
                tracing::warn!(%error, "failed to resolve OpenID4VCI issuer_state");
                return authorization_oauth_error_redirect(
                    context,
                    &redirect_uri,
                    "temporarily_unavailable",
                    q,
                )
                .await;
            }
        };
        let requested = credential_configuration_ids(&normalized.authorization_details);
        if requested.iter().any(|id| {
            !authorization
                .configuration_ids
                .iter()
                .any(|allowed| allowed == id)
        }) {
            return authorization_oauth_error_redirect(
                context,
                &redirect_uri,
                "invalid_request",
                q,
            )
            .await;
        }
        let selected = if requested.is_empty() {
            authorization.configuration_ids
        } else {
            requested
        };
        normalized.authorization_details = Value::Array(
            selected
                .into_iter()
                .map(|credential_configuration_id| {
                    crate::domain::openid4vci_authorization_detail(
                        context.config.issuer.as_ref(),
                        &credential_configuration_id,
                    )
                })
                .collect(),
        );
    }
    let now = Utc::now();
    let request_id = Uuid::now_v7().to_string();
    let authorization_code_ttl_seconds = if client_policy.requires_fapi2_security() {
        context.config.auth_code_ttl_seconds.min(60)
    } else {
        context.config.auth_code_ttl_seconds
    };
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
        signed_authorization_response_required: Some(
            client_policy.require_signed_authorization_response,
        ),
        session_management_allowed: Some(client_policy.session_management),
        authorization_code_ttl_seconds: Some(authorization_code_ttl_seconds),
        issued_at: now,
        expires_at: now + Duration::seconds(authorization_code_ttl_seconds as i64),
    };
    if normalized.prompt.none {
        if !crate::domain::oidc_claims::user_claims_are_covered_by_scopes(
            &payload.scopes,
            &payload.userinfo_claims,
        ) || !crate::domain::oidc_claims::user_claims_are_covered_by_scopes(
            &payload.scopes,
            &payload.id_token_claims,
        ) {
            return authorization_oauth_error_redirect(
                context,
                &redirect_uri,
                "consent_required",
                q,
            )
            .await;
        }
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
        .store_consent(&request_id, &payload, authorization_code_ttl_seconds)
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

fn credential_configuration_ids(authorization_details: &Value) -> Vec<String> {
    authorization_details
        .as_array()
        .into_iter()
        .flatten()
        .filter(|detail| detail.get("type").and_then(Value::as_str) == Some("openid_credential"))
        .filter_map(|detail| {
            detail
                .get("credential_configuration_id")
                .and_then(Value::as_str)
        })
        .map(ToOwned::to_owned)
        .collect()
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

pub(crate) struct AuthorizationResponseRedirect<'a> {
    pub(crate) redirect_uri: &'a str,
    pub(crate) client_id: &'a str,
    pub(crate) response_mode: Option<&'a str>,
    pub(crate) code: Option<&'a str>,
    pub(crate) error: Option<&'a str>,
    pub(crate) state: Option<&'a str>,
    pub(crate) oidc_sid: Option<&'a str>,
    pub(crate) client_policy: Option<AuthorizationResponseClientPolicy>,
}

#[derive(Clone, Copy)]
pub(crate) struct AuthorizationResponseClientPolicy {
    pub(crate) signed_response_required: bool,
    pub(crate) session_management_allowed: bool,
    pub(crate) ttl_seconds: u64,
}

pub(crate) async fn authorization_response_redirect_with_context(
    context: &AuthorizationRequestContext<'_>,
    input: AuthorizationResponseRedirect<'_>,
) -> HttpResponse {
    let mut client = None;
    let response_policy = if let Some(policy) = input.client_policy {
        policy
    } else {
        client = if input.client_id.is_empty() {
            None
        } else {
            match context.service.client_by_id(input.client_id).await {
                Ok(Some(client)) if client.is_active => Some(client),
                Ok(_) => None,
                Err(error) => {
                    tracing::warn!(%error, client_id_hash = %blake3_hex(input.client_id), "failed to load authorization response client policy");
                    return oauth_error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "server_error",
                        "authorization response policy is unavailable.",
                    );
                }
            }
        };
        let client_policy = client.as_ref().map_or_else(
            || context.config.profile.legacy_client_policy(),
            |client| context.config.profile.effective_client_policy(client),
        );
        AuthorizationResponseClientPolicy {
            signed_response_required: client_policy.require_signed_authorization_response,
            session_management_allowed: client_policy.session_management,
            ttl_seconds: if client_policy.requires_fapi2_security() {
                context.config.auth_code_ttl_seconds.min(60)
            } else {
                context.config.auth_code_ttl_seconds
            },
        }
    };
    let jarm_available = crate::http::authorization::permits_existing_module_transaction(
        context,
        nazo_runtime_modules::ModuleId::Jarm,
    );
    let session_management_available = response_policy.session_management_allowed
        && crate::http::authorization::accepts_module(
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
        ttl_seconds: response_policy.ttl_seconds as i64,
        signed_response_required: response_policy.signed_response_required,
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
        let client = match client {
            Some(client) => Some(client),
            None if input.client_id.is_empty() => None,
            None => match context.service.client_by_id(input.client_id).await {
                Ok(Some(client)) if client.is_active => Some(client),
                Ok(_) => None,
                Err(error) => {
                    tracing::warn!(%error, client_id_hash = %blake3_hex(input.client_id), "failed to load JARM client");
                    return oauth_error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "server_error",
                        "authorization response protection failed.",
                    );
                }
            },
        };
        let Some(client) = client else {
            tracing::warn!(client_id_hash = %blake3_hex(input.client_id), "JARM client is missing or inactive");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "authorization response protection failed.",
            );
        };
        let protection = AuthorizationResponseProtection::from(&client);
        return authorization_response_redirect_with_protection_context(
            context,
            input,
            protection,
            response_policy.ttl_seconds as i64,
        )
        .await;
    }
    let (plain, form_post) = match plan {
        AuthorizationResponsePlan::Plain(plain) => (plain, false),
        AuthorizationResponsePlan::FormPost(plain) => (plain, true),
        AuthorizationResponsePlan::Jarm(_) => unreachable!("JARM response returned above"),
    };
    let session_state = if plain.issue_session_state {
        input
            .oidc_sid
            .and_then(|sid| issue_oidc_session_state(input.client_id, input.redirect_uri, sid))
    } else {
        None
    };
    if form_post {
        return form_post_authorization_response(
            &plain.redirect_uri,
            &plain.parameters,
            session_state.as_deref(),
            &random_urlsafe_token(),
        );
    }
    redirect_found(nazo_auth::plain_authorization_response_uri(
        &plain,
        session_state.as_deref(),
    ))
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
    ttl_seconds: i64,
) -> HttpResponse {
    let result =
        protected_authorization_response_jwt(context, &input, protection, ttl_seconds).await;
    authorization_response_jwt_result(input.redirect_uri, result)
}

async fn protected_authorization_response_jwt(
    context: &AuthorizationRequestContext<'_>,
    input: &AuthorizationResponseRedirect<'_>,
    protection: AuthorizationResponseProtection<'_>,
    ttl_seconds: i64,
) -> anyhow::Result<String> {
    let signed = context
        .service
        .sign_authorization_response(nazo_auth::AuthorizationResponseSignInput {
            issuer: context.config.issuer.as_ref(),
            client_id: input.client_id,
            code: input.code,
            error: input.error,
            state: input.state,
            ttl: ttl_seconds,
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
#[path = "../../../tests/unit/http/authorization/request.rs"]
mod tests;
