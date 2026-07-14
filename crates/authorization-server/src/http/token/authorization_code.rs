//! authorization_code grant 处理。
use crate::adapters::security::ValidatedClientAssertion;
use crate::adapters::security::blake3_hex;
use crate::adapters::security::constant_time_eq;
use crate::adapters::security::pkce_s256;
#[cfg(test)]
use crate::domain::TestAppState;
use crate::domain::client_policy::audiences_allowed;
#[cfg(test)]
use crate::domain::client_policy::authorization_code_key;
use crate::domain::client_policy::is_subset;
use crate::domain::client_policy::is_valid_pkce_value;
#[cfg(test)]
use crate::domain::tenancy::DEFAULT_ORGANIZATION_ID;
#[cfg(test)]
use crate::domain::tenancy::DEFAULT_REALM_ID;
#[cfg(test)]
use crate::domain::tenancy::DEFAULT_TENANT_ID;
use crate::domain::{
    AuthorizationCodeState, ClientRow, CodePayload, ConsumedAuthorizationCode, RefreshTokenPolicy,
    TokenIssue,
};
use crate::http::dpop::DpopError;
use crate::http::dpop::DpopErrorContext;
use crate::http::dpop::dpop_error_response;
use crate::http::dpop::validate_dpop_proof_with_authorization_service;
use crate::http::mtls::request_mtls_thumbprint_from_trusted_proxy;
#[cfg(test)]
use crate::settings::Settings;
#[cfg(test)]
use crate::test_support::valkey::valkey_get;
#[cfg(test)]
use crate::test_support::valkey::valkey_set_ex;
use actix_web::http::StatusCode;
#[cfg(test)]
use actix_web::http::header;
#[cfg(test)]
use actix_web::http::header::HeaderValue;
#[cfg(test)]
use actix_web::web::Data;
use actix_web::{HttpRequest, HttpResponse};
#[cfg(test)]
use base64::Engine;
use chrono::Utc;
#[cfg(test)]
use chrono::{DateTime, Duration};
#[cfg(test)]
use nazo_auth::OidcClaimRequest;
#[cfg(test)]
use nazo_http_actix::OAuthJsonErrorFields;
use nazo_http_actix::oauth_token_error;
#[cfg(test)]
use serde_json::{Value, json};
#[cfg(test)]
use uuid::Uuid;
// 只消费授权码并转入统一令牌签发逻辑。
use super::issue::TokenIssuanceConfig;
use super::{
    ServerTokenService, TokenForm, consume_token_client_assertion_with_authorization_service,
    issue::{TokenIssuanceContext, issue_token_response_with_service},
    native_sso_requested, new_native_sso_token_binding, revoke_issued_authorization_code_tokens,
};

enum AuthorizationCodeConsumption {
    Consuming(Box<CodePayload>),
    Busy,
    Consumed(ConsumedAuthorizationCode),
    Failed,
    Missing,
    Malformed,
}

#[cfg(test)]
fn parse_authorization_code_consumption_response(response: &str) -> AuthorizationCodeConsumption {
    if let Some(raw) = response.strip_prefix("consuming|") {
        return match serde_json::from_str::<CodePayload>(raw) {
            Ok(payload) => AuthorizationCodeConsumption::Consuming(Box::new(payload)),
            Err(error) => {
                tracing::warn!(%error, "authorization code pending payload is malformed");
                AuthorizationCodeConsumption::Malformed
            }
        };
    }
    if let Some(raw) = response.strip_prefix("consumed|") {
        return match serde_json::from_str::<AuthorizationCodeState>(raw) {
            Ok(AuthorizationCodeState::Consumed { marker }) => {
                AuthorizationCodeConsumption::Consumed(marker)
            }
            Ok(_) => AuthorizationCodeConsumption::Malformed,
            Err(error) => {
                tracing::warn!(%error, "consumed authorization code marker is malformed");
                AuthorizationCodeConsumption::Malformed
            }
        };
    }
    match response {
        "busy" => AuthorizationCodeConsumption::Busy,
        "failed" => AuthorizationCodeConsumption::Failed,
        "missing" => AuthorizationCodeConsumption::Missing,
        _ => AuthorizationCodeConsumption::Malformed,
    }
}

async fn load_pending_authorization_code_payload_with_service(
    service: &ServerTokenService,
    code_hash: &str,
) -> Result<Option<Box<CodePayload>>, HttpResponse> {
    let stored = match service.load_authorization_code(code_hash).await {
        Ok(value) => value,
        Err(error) => {
            tracing::warn!(
                ?error,
                "failed to read authorization code before dpop validation"
            );
            return Err(oauth_token_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "授权码校验失败.",
                false,
            ));
        }
    };
    let Some(stored) = stored else {
        return Ok(None);
    };
    match stored {
        AuthorizationCodeState::Pending { payload } => Ok(Some(Box::new(payload))),
        _ => Ok(None),
    }
}

fn redirect_uri_matches_authorization_request(
    payload: &CodePayload,
    token_redirect_uri: Option<&str>,
) -> bool {
    match (payload.redirect_uri_was_supplied, token_redirect_uri) {
        (true, Some(value)) => value == payload.redirect_uri.as_str(),
        (true, None) => false,
        (false, Some(value)) => value == payload.redirect_uri.as_str(),
        (false, None) => true,
    }
}

fn authorization_code_requires_pkce(client: &ClientRow, payload: &CodePayload) -> bool {
    client.client_type == "public"
        || client.require_dpop_bound_tokens
        || client.require_mtls_bound_tokens
        || payload.dpop_jkt.is_some()
        || payload.mtls_x5t_s256.is_some()
        || !client.allow_authorization_code_without_pkce
}

fn authorization_code_dpop_error_response(error: DpopError) -> HttpResponse {
    match error {
        DpopError::UseNonce(_) | DpopError::NonceStoreUnavailable => {
            dpop_error_response(error, DpopErrorContext::TokenEndpoint)
        }
        _ => oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "authorization code proof of possession validation failed.",
            false,
        ),
    }
}

fn authorization_code_mtls_holder_error_response() -> HttpResponse {
    oauth_token_error(
        StatusCode::BAD_REQUEST,
        "invalid_request",
        "authorization code mTLS binding validation failed.",
        false,
    )
}

fn authorization_code_client_mismatch_response() -> HttpResponse {
    oauth_token_error(
        StatusCode::BAD_REQUEST,
        "invalid_grant",
        "授权码与客户端或 redirect_uri 不匹配.",
        false,
    )
}

struct AuthorizationCodeIssueInput {
    payload: CodePayload,
    subject: String,
    audiences: Vec<String>,
    dpop_jkt: Option<String>,
    mtls_x5t_s256: Option<String>,
    code_hash: String,
    refresh_token_dpop_jkt: Option<String>,
    refresh_token_mtls_x5t_s256: Option<String>,
}

fn token_issue_from_authorization_code(input: AuthorizationCodeIssueInput) -> TokenIssue {
    let native_sso = native_sso_requested(&input.payload.scopes)
        .then(|| new_native_sso_token_binding(input.payload.oidc_sid.as_deref()))
        .flatten();
    TokenIssue {
        user_id: Some(input.payload.user_id),
        subject: input.subject,
        scopes: input.payload.scopes,
        authorization_details: input.payload.authorization_details,
        audiences: input.audiences,
        nonce: input.payload.nonce,
        auth_time: Some(input.payload.auth_time),
        amr: input.payload.amr,
        oidc_sid: input.payload.oidc_sid,
        acr: input.payload.acr,
        userinfo_claims: input.payload.userinfo_claims,
        userinfo_claim_requests: input.payload.userinfo_claim_requests,
        id_token_claims: input.payload.id_token_claims,
        id_token_claim_requests: input.payload.id_token_claim_requests,
        include_refresh: true,
        refresh_token_policy: RefreshTokenPolicy::IssueNew,
        dpop_jkt: input.dpop_jkt,
        refresh_token_dpop_jkt: input.refresh_token_dpop_jkt,
        mtls_x5t_s256: input.mtls_x5t_s256,
        refresh_token_mtls_x5t_s256: input.refresh_token_mtls_x5t_s256,
        authorization_code_hash: Some(input.code_hash),
        actor: None,
        issued_token_type: None,
        native_sso,
    }
}

fn authorization_code_audiences_with_default(
    default_audience: &str,
    payload: &CodePayload,
    form: &TokenForm,
) -> Result<Vec<String>, ()> {
    if payload.resource_indicators.is_empty() {
        return Ok(if form.audiences.is_empty() {
            vec![default_audience.to_owned()]
        } else {
            form.audiences.clone()
        });
    }
    if form.audiences.is_empty() {
        return Ok(payload.resource_indicators.clone());
    }
    is_subset(&form.audiences, &payload.resource_indicators)
        .then(|| form.audiences.clone())
        .ok_or(())
}

#[cfg(test)]
fn authorization_code_audiences(
    settings: &Settings,
    payload: &CodePayload,
    form: &TokenForm,
) -> Result<Vec<String>, ()> {
    authorization_code_audiences_with_default(&settings.protocol.default_audience, payload, form)
}

fn refresh_token_dpop_binding(
    client: &ClientRow,
    payload: &CodePayload,
    dpop_jkt: Option<String>,
) -> Option<String> {
    if client.client_type == "public" || payload.dpop_jkt.is_some() {
        dpop_jkt
    } else {
        None
    }
}

async fn begin_authorization_code_consumption_with_service(
    service: &ServerTokenService,
    code_hash: &str,
) -> Result<AuthorizationCodeConsumption, HttpResponse> {
    match service
        .begin_authorization_code(code_hash, Utc::now())
        .await
    {
        Ok(nazo_auth::AuthorizationCodeBeginResult::Consuming(payload)) => {
            Ok(AuthorizationCodeConsumption::Consuming(Box::new(payload)))
        }
        Ok(nazo_auth::AuthorizationCodeBeginResult::Busy) => Ok(AuthorizationCodeConsumption::Busy),
        Ok(nazo_auth::AuthorizationCodeBeginResult::Consumed(
            AuthorizationCodeState::Consumed { marker },
        )) => Ok(AuthorizationCodeConsumption::Consumed(marker)),
        Ok(
            nazo_auth::AuthorizationCodeBeginResult::Consumed(_)
            | nazo_auth::AuthorizationCodeBeginResult::Malformed,
        ) => Ok(AuthorizationCodeConsumption::Malformed),
        Ok(nazo_auth::AuthorizationCodeBeginResult::Failed) => {
            Ok(AuthorizationCodeConsumption::Failed)
        }
        Ok(nazo_auth::AuthorizationCodeBeginResult::Missing) => {
            Ok(AuthorizationCodeConsumption::Missing)
        }
        Err(error) => {
            tracing::warn!(?error, "failed to atomically consume authorization code");
            Err(oauth_token_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "授权码校验失败.",
                false,
            ))
        }
    }
}

async fn revoke_replayed_authorization_code(
    service: &ServerTokenService,
    marker: ConsumedAuthorizationCode,
) -> Result<bool, HttpResponse> {
    let client = match service.client_by_id(marker.client_id).await {
        Ok(Some(client)) => client,
        Ok(None) => {
            return Ok(false);
        }
        Err(error) => {
            tracing::warn!(?error, "failed to load replayed authorization code client");
            return Err(oauth_token_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "授权码重放撤销失败.",
                false,
            ));
        }
    };
    if let Err(error) = revoke_issued_authorization_code_tokens(
        service,
        &client,
        &marker.access_token_jti,
        marker.access_token_expires_at,
        marker.refresh_token_family_id,
    )
    .await
    {
        tracing::warn!(%error, "failed to revoke tokens after authorization code replay");
        return Err(oauth_token_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "授权码重放撤销失败.",
            false,
        ));
    }
    Ok(true)
}

pub(crate) async fn token_authorization_code_with_service(
    token_service: &ServerTokenService,
    issuance: &TokenIssuanceContext<'_>,
    req: &HttpRequest,
    client: &ClientRow,
    form: &TokenForm,
    client_assertion: Option<&ValidatedClientAssertion>,
) -> HttpResponse {
    let Some(code) = &form.code else {
        return oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "缺少 code.",
            false,
        );
    };
    let code_hash = blake3_hex(code);
    let expected_payload =
        match load_pending_authorization_code_payload_with_service(token_service, &code_hash).await
        {
            Ok(value) => value,
            Err(response) => return response,
        };
    if expected_payload
        .as_ref()
        .is_some_and(|payload| payload.client_id != client.client_id)
    {
        return authorization_code_client_mismatch_response();
    }
    let expected_dpop_jkt = expected_payload
        .as_ref()
        .and_then(|payload| payload.dpop_jkt.clone());
    let expected_mtls_x5t_s256 = expected_payload
        .as_ref()
        .and_then(|payload| payload.mtls_x5t_s256.clone());
    let dpop_jkt = match validate_dpop_proof_with_authorization_service(
        issuance.authorization,
        issuance.config.issuer(),
        issuance.config.mtls_endpoint_base_url(),
        issuance.config.dpop_nonce_policy(),
        req,
        None,
        expected_dpop_jkt.as_deref(),
    )
    .await
    {
        Ok(value) => value.or(expected_dpop_jkt),
        Err(error) => return authorization_code_dpop_error_response(error),
    };
    if client.require_dpop_bound_tokens && dpop_jkt.is_none() {
        return authorization_code_dpop_error_response(DpopError::MissingProof);
    }
    let request_mtls_x5t_s256 =
        request_mtls_thumbprint_from_trusted_proxy(req, issuance.config.trusted_proxy_cidrs());
    let mtls_x5t_s256 = match (expected_mtls_x5t_s256, request_mtls_x5t_s256) {
        (Some(expected), Some(actual))
            if constant_time_eq(expected.as_bytes(), actual.as_bytes()) =>
        {
            Some(expected)
        }
        (Some(_), _) => {
            return authorization_code_mtls_holder_error_response();
        }
        (None, actual) if client.require_mtls_bound_tokens => {
            let Some(actual) = actual else {
                return authorization_code_mtls_holder_error_response();
            };
            Some(actual)
        }
        (None, _) => None,
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
    let payload =
        match begin_authorization_code_consumption_with_service(token_service, &code_hash).await {
            Ok(AuthorizationCodeConsumption::Consuming(payload)) => payload,
            Ok(AuthorizationCodeConsumption::Consumed(marker)) => {
                match revoke_replayed_authorization_code(token_service, marker).await {
                    Ok(true) => {
                        return oauth_token_error(
                            StatusCode::BAD_REQUEST,
                            "invalid_grant",
                            "授权码已被使用，相关令牌已撤销.",
                            false,
                        );
                    }
                    Ok(false) => {}
                    Err(response) => return response,
                }
                return oauth_token_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "授权码已被使用.",
                    false,
                );
            }
            Ok(AuthorizationCodeConsumption::Busy) => {
                return oauth_token_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "授权码正在兑换.",
                    false,
                );
            }
            Ok(AuthorizationCodeConsumption::Failed) => {
                return oauth_token_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "授权码兑换已失败.",
                    false,
                );
            }
            Ok(AuthorizationCodeConsumption::Missing) => {
                return oauth_token_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "授权码无效或已过期.",
                    false,
                );
            }
            Ok(AuthorizationCodeConsumption::Malformed) => {
                return oauth_token_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "server_error",
                    "授权码状态无效.",
                    false,
                );
            }
            Err(response) => return response,
        };
    let payload = *payload;
    if payload.client_id != client.client_id
        || !redirect_uri_matches_authorization_request(&payload, form.redirect_uri.as_deref())
    {
        mark_failed_authorization_code(
            token_service,
            issuance.config.auth_code_ttl_seconds(),
            &code_hash,
            "client_or_redirect_uri_mismatch",
        )
        .await;
        return authorization_code_client_mismatch_response();
    }
    match (&payload.code_challenge, &payload.code_challenge_method) {
        (Some(code_challenge), Some(method)) if method == "S256" => {
            let Some(verifier) = &form.code_verifier else {
                mark_failed_authorization_code(
                    token_service,
                    issuance.config.auth_code_ttl_seconds(),
                    &code_hash,
                    "missing_code_verifier",
                )
                .await;
                return oauth_token_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "缺少 code_verifier.",
                    false,
                );
            };
            if !is_valid_pkce_value(verifier) || pkce_s256(verifier) != *code_challenge {
                mark_failed_authorization_code(
                    token_service,
                    issuance.config.auth_code_ttl_seconds(),
                    &code_hash,
                    "pkce_failed",
                )
                .await;
                return oauth_token_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "PKCE 校验失败.",
                    false,
                );
            }
        }
        (None, None) if !authorization_code_requires_pkce(client, &payload) => {}
        _ => {
            mark_failed_authorization_code(
                token_service,
                issuance.config.auth_code_ttl_seconds(),
                &code_hash,
                "pkce_state_invalid",
            )
            .await;
            return oauth_token_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "授权码 PKCE 状态无效.",
                false,
            );
        }
    }
    let audiences = match authorization_code_audiences_with_default(
        issuance.config.default_audience(),
        &payload,
        form,
    ) {
        Ok(audiences) => audiences,
        Err(()) => {
            mark_failed_authorization_code(
                token_service,
                issuance.config.auth_code_ttl_seconds(),
                &code_hash,
                "audience_exceeds_authorization",
            )
            .await;
            return oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_target",
                "请求的 resource 超出授权请求范围.",
                false,
            );
        }
    };
    if !audiences_allowed(client, &audiences) {
        mark_failed_authorization_code(
            token_service,
            issuance.config.auth_code_ttl_seconds(),
            &code_hash,
            "audience_not_allowed",
        )
        .await;
        return oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_target",
            "请求的 audience 不在客户端允许范围内.",
            false,
        );
    }
    if native_sso_requested(&payload.scopes) {
        if !issuance.permits(nazo_runtime_modules::ModuleId::NativeSso) {
            mark_failed_authorization_code(
                token_service,
                issuance.config.auth_code_ttl_seconds(),
                &code_hash,
                "native_sso_disabled",
            )
            .await;
            return oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_scope",
                "Native SSO is not enabled.",
                false,
            );
        }
        if !payload.scopes.iter().any(|scope| scope == "openid") {
            mark_failed_authorization_code(
                token_service,
                issuance.config.auth_code_ttl_seconds(),
                &code_hash,
                "native_sso_without_openid",
            )
            .await;
            return oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_scope",
                "Native SSO requires openid.",
                false,
            );
        }
    }
    let refresh_token_dpop_jkt = refresh_token_dpop_binding(client, &payload, dpop_jkt.clone());
    let refresh_token_mtls_x5t_s256 = mtls_x5t_s256.clone();
    let subject = match authorization_code_subject(issuance.config, &payload, client) {
        Ok(subject) => subject,
        Err(_) => {
            mark_failed_authorization_code(
                token_service,
                issuance.config.auth_code_ttl_seconds(),
                &code_hash,
                "subject_policy_invalid",
            )
            .await;
            let status = StatusCode::SERVICE_UNAVAILABLE;
            let error = "server_error";
            let description = "subject invalid";
            return oauth_token_error(status, error, description, false);
        }
    };
    issue_token_response_with_service(
        issuance,
        token_service,
        client,
        token_issue_from_authorization_code(AuthorizationCodeIssueInput {
            payload,
            subject,
            audiences,
            dpop_jkt,
            mtls_x5t_s256,
            code_hash,
            refresh_token_dpop_jkt,
            refresh_token_mtls_x5t_s256,
        }),
    )
    .await
}

#[cfg(test)]
fn test_token_service(state: &TestAppState) -> ServerTokenService {
    ServerTokenService::new(
        nazo_postgres::TokenIssuanceRepository::new(state.diesel_db.clone()),
        nazo_valkey::TokenIssuanceStateAdapter::new(&state.valkey_connection()),
        state.keyset.clone(),
    )
}

#[cfg(test)]
async fn load_pending_authorization_code_payload(
    state: &TestAppState,
    code_hash: &str,
) -> Result<Option<Box<CodePayload>>, HttpResponse> {
    load_pending_authorization_code_payload_with_service(&test_token_service(state), code_hash)
        .await
}

#[cfg(test)]
async fn begin_authorization_code_consumption(
    state: &TestAppState,
    code_hash: &str,
) -> Result<AuthorizationCodeConsumption, HttpResponse> {
    begin_authorization_code_consumption_with_service(&test_token_service(state), code_hash).await
}

#[cfg(test)]
pub(crate) async fn token_authorization_code(
    state: &TestAppState,
    req: &HttpRequest,
    client: &ClientRow,
    form: &TokenForm,
    client_assertion: Option<&ValidatedClientAssertion>,
) -> HttpResponse {
    let service = test_token_service(state);
    let config = TokenIssuanceConfig::from(state.settings.as_ref());
    let modules = state.active_module_snapshot();
    let authorization = super::issue::test_authorization_service(state);
    token_authorization_code_with_service(
        &service,
        &TokenIssuanceContext {
            config: &config,
            modules: &modules,
            authorization: &authorization,
        },
        req,
        client,
        form,
        client_assertion,
    )
    .await
}

async fn mark_failed_authorization_code(
    service: &ServerTokenService,
    ttl_seconds: u64,
    code_hash: &str,
    error_code: &str,
) {
    if let Err(error) =
        super::mark_failed_authorization_code(service, code_hash, error_code, ttl_seconds).await
    {
        tracing::warn!(%error, "failed to mark authorization code exchange as failed");
    }
}

fn authorization_code_subject(
    config: &TokenIssuanceConfig,
    payload: &CodePayload,
    client: &ClientRow,
) -> anyhow::Result<String> {
    let subject_type = client.subject_type.as_str();
    let sector_host = client.sector_identifier_host.as_deref();
    let redirect_uri = payload.redirect_uri.as_str();
    let user_id = payload.user_id;
    Ok(nazo_auth::oidc_subject_for_client(
        config.issuer(),
        config.pairwise_subject_secret(),
        user_id,
        subject_type,
        sector_host,
        redirect_uri,
    )?)
}

#[cfg(test)]
#[path = "../../../tests/in_source/src/http/token/tests/authorization_code.rs"]
mod tests;
