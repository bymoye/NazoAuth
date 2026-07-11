//! 授权请求入口端点。
// 该端点只创建 consent 临时状态，不签发授权码。
use super::{
    apply_request_object, is_pushed_authorization_request_uri, pushed_authorization_request_key,
    unverified_signed_request_object_client_id,
};
use crate::http::prelude::*;
use crate::http::profile::issue_oidc_session_state;

mod form;
mod parameters;
mod prompt_none;

use form::*;
pub(crate) use parameters::AUTHORIZED_REQUEST_PARAMETERS;
use parameters::*;
use prompt_none::*;

const REAUTH_NONCE_TTL_SECONDS: u64 = 600;

/// 校验 OAuth authorize 参数并创建待确认授权请求。
pub(crate) async fn authorize_get(state: Data<AppState>, req: HttpRequest) -> HttpResponse {
    let query_parameters = authorization_duplicate_parameters();
    let mut q = match parse_authorization_query(req.query_string(), &query_parameters) {
        Ok(q) => q,
        Err(response) => return response,
    };
    authorize_request(state, req, &mut q).await
}

pub(crate) async fn authorize_post(
    state: Data<AppState>,
    req: HttpRequest,
    body: Bytes,
) -> HttpResponse {
    let query_parameters = authorization_duplicate_parameters();
    let mut q = match parse_authorization_post_form(&req, &body, &query_parameters) {
        Ok(q) => q,
        Err(response) => return response,
    };
    authorize_request(state, req, &mut q).await
}

async fn authorize_request(
    state: Data<AppState>,
    req: HttpRequest,
    q: &mut HashMap<String, String>,
) -> HttpResponse {
    if !state.settings.enable_request_object && q.contains_key("request") {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "request 参数未启用.",
        );
    }
    if !state.settings.enable_authorization_details && q.contains_key("authorization_details") {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "authorization_details 参数未启用.",
        );
    }

    let original_authorization_query = q.clone();
    let reauth_started_at = consume_reauth_nonce(&state, q).await;
    let mut pushed_dpop_jkt = None;
    let mut pushed_mtls_x5t_s256 = None;
    let mut consumed_request_uri_error: Option<&'static str> = None;
    let mut used_pushed_authorization_request = false;
    let mut pending_pushed_request_uri = None;
    if let Some(request_uri) = q.get("request_uri").cloned() {
        if !is_pushed_authorization_request_uri(&request_uri) {
            consumed_request_uri_error = Some("request_uri_not_supported");
        } else {
            let raw = match valkey_get(
                &state.valkey,
                pushed_authorization_request_key(&request_uri),
            )
            .await
            {
                Ok(Some(raw)) => raw,
                Ok(None) => {
                    consumed_request_uri_error = Some("invalid_request_uri");
                    String::new()
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
            if consumed_request_uri_error.is_none() {
                let pushed = match serde_json::from_str::<PushedAuthorizationRequest>(&raw) {
                    Ok(pushed) => pushed,
                    Err(error) => {
                        tracing::warn!(%error, "PAR payload is malformed");
                        return oauth_error(
                            StatusCode::SERVICE_UNAVAILABLE,
                            "server_error",
                            "request_uri 状态无效.",
                        );
                    }
                };
                if q.get("client_id")
                    .is_some_and(|client_id| client_id != &pushed.client_id)
                {
                    consumed_request_uri_error = Some("invalid_request_uri");
                } else {
                    let outer_parameters_are_fapi_invalid = state
                        .settings
                        .authorization_server_profile
                        .requires_fapi2_security()
                        && !outer_request_uri_parameters_are_fapi_compliant(q);
                    let outer_parameters_mismatch =
                        !outer_request_uri_parameters_match_pushed(q, &pushed.params);
                    if outer_parameters_are_fapi_invalid || outer_parameters_mismatch {
                        consumed_request_uri_error = Some("invalid_request");
                        *q = pushed.params;
                    } else {
                        pushed_dpop_jkt = pushed.dpop_jkt;
                        pushed_mtls_x5t_s256 = pushed.mtls_x5t_s256;
                        used_pushed_authorization_request = true;
                        pending_pushed_request_uri = Some(request_uri);
                        *q = pushed.params;
                    }
                }
            }
        }
    } else if state.settings.require_pushed_authorization_requests {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "该服务要求使用 pushed authorization request.",
        );
    }

    if !state.settings.enable_authorization_details && q.contains_key("authorization_details") {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "authorization_details 参数未启用.",
        );
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

    let client = match find_client(&state.diesel_db, client_id).await {
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
    let request_object_error = apply_request_object(&state, q, &client).await.err();
    if !state.settings.enable_authorization_details && q.contains_key("authorization_details") {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "authorization_details 参数未启用.",
        );
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
        return authorization_oauth_error_redirect(&state, &redirect_uri, error, q).await;
    }
    if let Some(error_response) = request_object_error {
        if let Some(error) = oauth_json_error(&error_response) {
            return authorization_oauth_error_redirect(&state, &redirect_uri, &error, q).await;
        }
        return error_response;
    }
    if (client.require_dpop_bound_tokens || client.require_mtls_bound_tokens)
        && !used_pushed_authorization_request
        && !q.contains_key("request")
    {
        return authorization_oauth_error_redirect(&state, &redirect_uri, "invalid_request", q)
            .await;
    }
    if authorization_nonce_too_long(q) {
        return authorization_oauth_error_redirect(&state, &redirect_uri, "invalid_request", q)
            .await;
    }

    if q.get("response_type").map(String::as_str) != Some("code") {
        return authorization_oauth_error_redirect(
            &state,
            &redirect_uri,
            "unsupported_response_type",
            q,
        )
        .await;
    }
    let response_mode = match authorization_response_mode(q) {
        Ok(value) => value,
        Err(()) => {
            return authorization_oauth_error_redirect(&state, &redirect_uri, "invalid_request", q)
                .await;
        }
    };
    let (code_challenge, code_challenge_method) = match authorization_pkce(q) {
        Ok(value) => value,
        Err(()) => {
            return authorization_oauth_error_redirect(&state, &redirect_uri, "invalid_request", q)
                .await;
        }
    };
    if code_challenge.is_none() && authorization_request_requires_pkce(&client) {
        return authorization_oauth_error_redirect(&state, &redirect_uri, "invalid_request", q)
            .await;
    }

    let prompt = match requested_prompt(q) {
        Ok(prompt) => prompt,
        Err(()) => {
            return authorization_oauth_error_redirect(&state, &redirect_uri, "invalid_request", q)
                .await;
        }
    };
    let max_age = match q.get("max_age") {
        Some(value) => match value.parse::<i64>() {
            Ok(value) if value >= 0 => Some(value),
            _ => {
                return authorization_oauth_error_redirect(
                    &state,
                    &redirect_uri,
                    "invalid_request",
                    q,
                )
                .await;
            }
        },
        None => None,
    };
    let requested_claims = match requested_claims(q) {
        Ok(value) => value,
        Err(()) => {
            return authorization_oauth_error_redirect(&state, &redirect_uri, "invalid_request", q)
                .await;
        }
    };
    let acr = match requested_acr(q, requested_claims.acr.as_ref()) {
        Ok(acr) => acr,
        Err(()) => {
            return authorization_oauth_error_redirect(&state, &redirect_uri, "invalid_request", q)
                .await;
        }
    };

    let session = match current_session(&state, &req).await {
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
    let Some(session) = session else {
        if prompt.none {
            return authorization_response_redirect(
                &state,
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
        return match authorization_login_url(
            &state,
            &authorization_login_query(
                q,
                &original_authorization_query,
                pending_pushed_request_uri.as_ref(),
            ),
            prompt.login || prompt.select_account,
        )
        .await
        {
            Ok(location) => redirect_found(location),
            Err(response) => response,
        };
    };
    if session_requires_reauthentication(
        prompt,
        max_age,
        session.auth_time,
        reauth_started_at,
        Utc::now().timestamp(),
    ) {
        if prompt.none {
            return authorization_response_redirect(
                &state,
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
        return match authorization_login_url(
            &state,
            &authorization_login_query(
                q,
                &original_authorization_query,
                pending_pushed_request_uri.as_ref(),
            ),
            prompt.login || prompt.select_account,
        )
        .await
        {
            Ok(location) => redirect_found(location),
            Err(response) => response,
        };
    }

    let requested_scopes = parse_scope(q.get("scope").map(String::as_str).unwrap_or(""));
    if !is_subset(&requested_scopes, &json_array_to_strings(&client.scopes)) {
        return authorization_oauth_error_redirect(&state, &redirect_uri, "invalid_scope", q).await;
    }
    let resource_indicators =
        match resource_indicators_from_parameter_value(q.get("resource").map(String::as_str)) {
            Ok(resources) => resources,
            Err(_) => {
                return authorization_oauth_error_redirect(
                    &state,
                    &redirect_uri,
                    "invalid_target",
                    q,
                )
                .await;
            }
        };
    if !resource_indicators.is_empty() && !audiences_allowed(&client, &resource_indicators) {
        return authorization_oauth_error_redirect(&state, &redirect_uri, "invalid_target", q)
            .await;
    }
    let authorization_details =
        match parse_authorization_details(q.get("authorization_details").map(String::as_str)) {
            Ok(value) => value,
            Err(()) => {
                return authorization_oauth_error_redirect(
                    &state,
                    &redirect_uri,
                    "invalid_request",
                    q,
                )
                .await;
            }
        };
    let now = Utc::now();
    let request_id = Uuid::now_v7().to_string();
    let payload = ConsentPayload {
        request_id: request_id.clone(),
        user_id: session.user.id,
        client_id: client.client_id,
        client_name: client.client_name,
        redirect_uri: redirect_uri.clone(),
        redirect_uri_was_supplied: q.contains_key("redirect_uri"),
        scopes: requested_scopes,
        resource_indicators,
        authorization_details,
        state: q.get("state").cloned(),
        response_mode,
        nonce: q.get("nonce").cloned(),
        auth_time: session.auth_time,
        amr: session.amr,
        oidc_sid: Some(session.oidc_sid),
        acr,
        userinfo_claims: claim_request_names(&requested_claims.userinfo),
        userinfo_claim_requests: requested_claims.userinfo,
        id_token_claims: claim_request_names(&requested_claims.id_token),
        id_token_claim_requests: requested_claims.id_token,
        code_challenge,
        code_challenge_method,
        dpop_jkt,
        mtls_x5t_s256,
        pushed_request_uri: pending_pushed_request_uri,
        issued_at: now,
        expires_at: now + Duration::seconds(state.settings.auth_code_ttl_seconds as i64),
    };
    if prompt.none {
        match user_grant_covers_requested_scopes(
            &state,
            payload.user_id,
            client.id,
            &payload.scopes,
            &payload.resource_indicators,
            &payload.authorization_details,
        )
        .await
        {
            Ok(true) => {
                return issue_authorization_code_without_interaction(&state, &req, payload).await;
            }
            Ok(false) => {
                return authorization_oauth_error_redirect(
                    &state,
                    &redirect_uri,
                    "consent_required",
                    q,
                )
                .await;
            }
            Err(response) => return response,
        }
    }
    let key = format!("oauth:consent:{request_id}");
    let body =
        serde_json::to_string(&payload).expect("consent payload serialization must be infallible");
    if let Err(error) = valkey_set_ex(
        &state.valkey,
        key,
        body,
        state.settings.auth_code_ttl_seconds,
    )
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
        state.settings.frontend_base_url.trim_end_matches('/')
    ))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PushedAuthorizationRequestConsumeError {
    Missing,
    ReadFailed,
    Malformed,
}

pub(crate) async fn consume_pushed_authorization_request(
    state: &AppState,
    request_uri: &str,
) -> Result<(), PushedAuthorizationRequestConsumeError> {
    let raw =
        match valkey_getdel(&state.valkey, pushed_authorization_request_key(request_uri)).await {
            Ok(Some(raw)) => raw,
            Ok(None) => {
                return Err(PushedAuthorizationRequestConsumeError::Missing);
            }
            Err(error) => {
                tracing::warn!(%error, "failed to consume PAR request_uri");
                return Err(PushedAuthorizationRequestConsumeError::ReadFailed);
            }
        };
    if let Err(error) = serde_json::from_str::<PushedAuthorizationRequest>(&raw) {
        tracing::warn!(%error, "PAR payload is malformed");
        return Err(PushedAuthorizationRequestConsumeError::Malformed);
    }
    Ok(())
}

pub(crate) async fn authorization_oauth_error_redirect(
    state: &AppState,
    redirect_uri: &str,
    error: &str,
    q: &HashMap<String, String>,
) -> HttpResponse {
    authorization_response_redirect(
        state,
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

pub(crate) async fn authorization_response_redirect(
    state: &AppState,
    input: AuthorizationResponseRedirect<'_>,
) -> HttpResponse {
    let signed_response_required = state
        .settings
        .authorization_server_profile
        .requires_signed_authorization_response();
    if input.response_mode == Some("jwt") || signed_response_required {
        if input.client_id.trim().is_empty() {
            tracing::warn!("cannot build signed authorization response without client_id");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "authorization response signing failed.",
            );
        }
        let client = match find_client(&state.diesel_db, input.client_id).await {
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
        return authorization_response_redirect_with_protection(state, input, protection).await;
    }
    let session_state = if state.settings.enable_session_management
        && input.code.is_some()
        && input.error.is_none()
    {
        input
            .oidc_sid
            .and_then(|sid| issue_oidc_session_state(input.client_id, input.redirect_uri, sid))
    } else {
        None
    };
    redirect_found(append_authorization_response_query(
        input.redirect_uri,
        state.settings.issuer.as_str(),
        input.code,
        input.error,
        input.state,
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

async fn authorization_response_redirect_with_protection(
    state: &AppState,
    input: AuthorizationResponseRedirect<'_>,
    protection: AuthorizationResponseProtection<'_>,
) -> HttpResponse {
    let result = protected_authorization_response_jwt(state, &input, protection).await;
    authorization_response_jwt_result(input.redirect_uri, result)
}

async fn protected_authorization_response_jwt(
    state: &AppState,
    input: &AuthorizationResponseRedirect<'_>,
    protection: AuthorizationResponseProtection<'_>,
) -> anyhow::Result<String> {
    let signing_alg = protection
        .signing_alg
        .map(|value| {
            signing_algorithm_from_name(value)
                .ok_or_else(|| anyhow::anyhow!("unsupported JARM signing algorithm"))
        })
        .transpose()?;
    let signed = make_authorization_response_jwt(
        state,
        AuthorizationResponseJwtInput {
            client_id: input.client_id,
            code: input.code,
            error: input.error,
            state: input.state,
            ttl: state.settings.auth_code_ttl_seconds as i64,
        },
        signing_alg,
    )
    .await?;
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

async fn consume_reauth_nonce(state: &AppState, q: &mut HashMap<String, String>) -> Option<i64> {
    let nonce = q.remove(reauth_nonce_parameter())?;
    let raw = match valkey_getdel(&state.valkey, reauth_nonce_key(&nonce)).await {
        Ok(Some(raw)) => raw,
        Ok(None) => return None,
        Err(error) => {
            tracing::warn!(%error, "failed to consume reauthentication nonce");
            return None;
        }
    };
    raw.parse::<i64>().ok().filter(|value| *value > 0)
}

async fn authorization_login_url(
    state: &AppState,
    q: &HashMap<String, String>,
    reauthentication_required: bool,
) -> Result<String, HttpResponse> {
    let reauth_nonce = if reauthentication_required {
        Some(issue_reauth_nonce(state).await?)
    } else {
        None
    };
    Ok(authorization_login_url_for_frontend(
        &state.settings.frontend_base_url,
        q,
        reauth_nonce.as_deref(),
    ))
}

async fn issue_reauth_nonce(state: &AppState) -> Result<String, HttpResponse> {
    let nonce = random_urlsafe_token();
    let started_at = Utc::now().timestamp().to_string();
    valkey_set_ex(
        &state.valkey,
        reauth_nonce_key(&nonce),
        started_at,
        REAUTH_NONCE_TTL_SECONDS,
    )
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

fn reauth_nonce_key(nonce: &str) -> String {
    format!("oauth:authorization:reauth:{}", blake3_hex(nonce))
}

#[cfg(test)]
#[path = "../../../tests/in_source/src/http/authorization/tests/request.rs"]
mod tests;
