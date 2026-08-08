use crate::adapters::security::blake3_hex;
use crate::domain::ConsentPayload;
use crate::domain::client_policy::{
    RedirectUriError, client_supports_grant, registered_redirect_uri,
};
use actix_web::http::StatusCode;
use actix_web::web::{Bytes, Data};
use actix_web::{HttpRequest, HttpResponse};
use chrono::{Duration, Utc};
use nazo_auth::{
    AuthorizationCapabilityPolicy, AuthorizationClientPolicy, AuthorizationProfilePolicy,
    AuthorizationSession, AuthorizationSessionDecision, is_valid_dpop_jkt,
    normalize_authorization_request,
};
use nazo_http_actix::{authorization_error_response, oauth_error, redirect_found};
use serde_json::Value;
use std::collections::HashMap;
use uuid::Uuid;

use super::{
    AuthorizationEndpoint, AuthorizationRequestContext, AuthorizationResponseClientPolicy,
    AuthorizationResponseRedirect, apply_request_object_with_context,
    authorization_duplicate_parameters, authorization_login_query,
    authorization_login_url_with_context, authorization_oauth_error_redirect,
    authorization_response_redirect_with_context, claim_request_names,
    consume_reauth_nonce_with_context, credential_configuration_ids,
    is_pushed_authorization_request_uri, issue_authorization_code_without_interaction_with_context,
    oauth_json_error, outer_request_uri_parameters_match_pushed, parse_authorization_post_form,
    parse_authorization_query, preserve_verified_dpop_binding,
    runtime_authorization_capability_error, user_grant_covers_requested_scopes_with_context,
};

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

pub(super) async fn authorize_request_with_context(
    context: &AuthorizationRequestContext<'_>,
    req: HttpRequest,
    q: &mut HashMap<String, String>,
) -> HttpResponse {
    if let Some(response) = runtime_authorization_capability_error(context, q) {
        return response;
    }

    let original_authorization_query = q.get("request_uri").is_some().then(|| q.clone());
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
                    original_authorization_query.as_ref(),
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
                context.tenant_id,
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
