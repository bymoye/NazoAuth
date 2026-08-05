//! 令牌签发响应构造。
use std::collections::BTreeSet;

use crate::adapters::audit::{audit_event_required, audit_fields};
use crate::adapters::security::blake3_hex;
use crate::adapters::security::random_urlsafe_token;
use crate::domain::client_jwe::{JwePayloadKind, client_jwe_key, encrypt_compact_jwe};
use crate::domain::oidc_claims::oidc_id_token_user_claims;

use crate::domain::{ClientRow, RefreshTokenPolicy, TokenIssue};
use crate::http::dpop::DpopErrorContext;
use crate::http::dpop::dpop_error_response;
use crate::http::dpop::issue_dpop_nonce_with_authorization_service;
use crate::settings::{AuthorizationServerProfile, DpopNoncePolicy, Settings};
use actix_web::HttpResponse;
use actix_web::http::StatusCode;
use actix_web::http::header;
use actix_web::http::header::HeaderValue;
use chrono::{DateTime, Duration, Utc};

use nazo_auth::{
    PrepareTokenIssuance, PrepareTokenIssuanceResult, TokenIssuancePhase, TokenIssuanceRecord,
    TokenIssuanceTransitionResult, normalize_authorization_details,
};

use nazo_http_actix::{ClientIpHeaderMode, IpCidr};
use nazo_http_actix::{json_response_no_store, oauth_token_error};
use nazo_key_management::{signing_algorithm_from_name, signing_algorithm_name};
use serde_json::{Value, json};
use uuid::Uuid;
// 统一 access_token、refresh_token 和 id_token 的响应形状。

mod authorization_code_state;
mod refresh_persistence;

use super::{ServerTokenService, persist_native_sso_device_secret};

#[derive(Clone)]
pub(crate) struct TokenIssuanceConfig {
    issuer: Box<str>,
    mtls_endpoint_base_url: Box<str>,
    dpop_nonce_policy: DpopNoncePolicy,
    trusted_proxy_cidrs: Box<[IpCidr]>,
    default_audience: Box<str>,
    openid4vci_enabled: bool,
    openid4vci_credential_scopes: Box<[String]>,
    pairwise_subject_secret: Option<Box<str>>,
    authorization_server_profile: AuthorizationServerProfile,
    client_ip_header_mode: ClientIpHeaderMode,
    client_secret_pepper: Box<str>,
    rate_limit_window_seconds: u64,
    token_rate_limit_max_requests: u64,
    auth_code_ttl_seconds: u64,
    access_token_ttl_seconds: i64,
    id_token_ttl_seconds: i64,
    refresh_token_ttl_seconds: i64,
}

impl From<&Settings> for TokenIssuanceConfig {
    fn from(settings: &Settings) -> Self {
        Self {
            issuer: settings.endpoint.issuer.as_str().into(),
            mtls_endpoint_base_url: settings.endpoint.mtls_endpoint_base_url.as_str().into(),
            dpop_nonce_policy: settings.protocol.dpop_nonce_policy,
            trusted_proxy_cidrs: settings.endpoint.trusted_proxy_cidrs.clone().into(),
            default_audience: settings.protocol.default_audience.as_str().into(),
            openid4vci_enabled: settings.modules.enable_openid4vci_issuer,
            openid4vci_credential_scopes: settings
                .openid4vc
                .credential_configurations
                .values()
                .filter_map(|configuration| configuration.scope.clone())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>()
                .into_boxed_slice(),
            pairwise_subject_secret: settings
                .protocol
                .pairwise_subject_secret
                .as_deref()
                .map(Into::into),
            authorization_server_profile: settings.protocol.authorization_server_profile,
            client_ip_header_mode: settings.endpoint.client_ip_header_mode,
            client_secret_pepper: settings.protocol.client_secret_pepper.as_str().into(),
            rate_limit_window_seconds: settings.identity.rate_limit.window_seconds,
            token_rate_limit_max_requests: settings.identity.rate_limit.token_max_requests,
            auth_code_ttl_seconds: settings.protocol.auth_code_ttl_seconds,
            access_token_ttl_seconds: settings.protocol.access_token_ttl_seconds,
            id_token_ttl_seconds: settings.protocol.id_token_ttl_seconds,
            refresh_token_ttl_seconds: settings.protocol.refresh_token_ttl_seconds,
        }
    }
}

impl TokenIssuanceConfig {
    pub(crate) fn issuer(&self) -> &str {
        &self.issuer
    }

    pub(crate) fn mtls_endpoint_base_url(&self) -> &str {
        &self.mtls_endpoint_base_url
    }

    pub(crate) fn dpop_nonce_policy(&self) -> DpopNoncePolicy {
        self.dpop_nonce_policy
    }

    pub(crate) fn trusted_proxy_cidrs(&self) -> &[IpCidr] {
        &self.trusted_proxy_cidrs
    }

    pub(crate) fn default_audience(&self) -> &str {
        &self.default_audience
    }

    pub(crate) fn openid4vci_audience(
        &self,
        scopes: &[String],
        authorization_details: &Value,
    ) -> Option<&str> {
        let requested_by_scope = scopes.iter().any(|scope| {
            self.openid4vci_credential_scopes
                .iter()
                .any(|configured| configured == scope)
        });
        let requested_by_authorization_details = authorization_details
            .as_array()
            .into_iter()
            .flatten()
            .any(|detail| detail.get("type").and_then(Value::as_str) == Some("openid_credential"));
        (self.openid4vci_enabled && (requested_by_scope || requested_by_authorization_details))
            .then_some(self.issuer())
    }

    pub(crate) fn pairwise_subject_secret(&self) -> Option<&str> {
        self.pairwise_subject_secret.as_deref()
    }

    pub(crate) fn auth_code_ttl_seconds(&self) -> u64 {
        self.auth_code_ttl_seconds.max(1)
    }

    pub(crate) fn authorization_server_profile(&self) -> AuthorizationServerProfile {
        self.authorization_server_profile
    }

    pub(crate) fn client_ip_header_mode(&self) -> ClientIpHeaderMode {
        self.client_ip_header_mode
    }

    pub(crate) fn client_secret_pepper(&self) -> &str {
        &self.client_secret_pepper
    }

    pub(crate) fn rate_limit_window_seconds(&self) -> u64 {
        self.rate_limit_window_seconds
    }

    pub(crate) fn token_rate_limit_max_requests(&self) -> u64 {
        self.token_rate_limit_max_requests
    }
}

pub(crate) struct TokenIssuanceContext<'a> {
    pub(crate) config: &'a TokenIssuanceConfig,
    pub(crate) modules: &'a nazo_runtime_modules::ActiveModuleSnapshot,
    pub(crate) authorization: &'a crate::http::authorization::ServerAuthorizationService,
}

impl TokenIssuanceContext<'_> {
    pub(crate) fn accepts(&self, module: nazo_runtime_modules::ModuleId) -> bool {
        nazo_auth::module_admissible(
            self.modules,
            module,
            nazo_auth::CapabilityAdmission::NewRequest,
        )
    }

    pub(crate) fn permits(&self, module: nazo_runtime_modules::ModuleId) -> bool {
        nazo_auth::module_admissible(
            self.modules,
            module,
            nazo_auth::CapabilityAdmission::ExistingTransaction,
        )
    }
}

use authorization_code_state::{
    consumed_authorization_code_ttl_seconds, mark_failed_authorization_code_if_needed,
    persist_consumed_authorization_code,
};
pub(super) use authorization_code_state::{
    mark_failed_authorization_code, revoke_issued_authorization_code_tokens,
};
pub(crate) use refresh_persistence::should_issue_refresh_token;
use refresh_persistence::{PendingRefreshToken, RefreshPersistResult, persist_refresh_token};

fn client_session_sid_enabled(frontchannel_logout: bool, client: &ClientRow) -> bool {
    (frontchannel_logout
        && client.frontchannel_logout_uri.is_some()
        && client.frontchannel_logout_session_required)
        || (client.backchannel_logout_uri.is_some() && client.backchannel_logout_session_required)
}

fn id_token_session_sid<'a>(
    client: &ClientRow,
    issue: &'a TokenIssue,
    frontchannel_logout: bool,
) -> Option<&'a str> {
    if let Some(contract) = issue.refresh_id_token_sid.as_ref() {
        return contract.as_deref();
    }
    if let Some(native_sso) = issue.native_sso.as_ref() {
        return Some(native_sso.sid.as_str());
    }
    if client_session_sid_enabled(frontchannel_logout, client) {
        return issue.oidc_sid.as_deref();
    }
    let requested = issue.id_token_claims.iter().any(|claim| claim == "sid")
        || issue
            .id_token_claim_requests
            .iter()
            .any(|request| request.name == "sid");
    requested.then_some(issue.oidc_sid.as_deref()).flatten()
}

fn persisted_id_token_sid<'a>(
    issue: &'a TokenIssue,
    issued_id_token_sid: Option<&'a str>,
) -> Option<&'a str> {
    issued_id_token_sid.or_else(|| {
        issue
            .refresh_id_token_sid
            .as_ref()
            .and_then(|contract| contract.as_deref())
    })
}

fn claim_request_value_matches(request: &nazo_auth::OidcClaimRequest, actual: &Value) -> bool {
    match (&request.value, request.values.as_slice()) {
        (Some(expected), _) => expected == actual,
        (None, []) => true,
        (None, values) => values.iter().any(|expected| expected == actual),
    }
}

fn refreshed_id_token_essential_claims_satisfied(
    issue: &TokenIssue,
    client: &ClientRow,
    frontchannel_logout_enabled: bool,
    extra_claims: Option<&Value>,
) -> bool {
    issue
        .id_token_claim_requests
        .iter()
        .filter(|request| request.essential)
        .all(|request| {
            let actual = match request.name.as_str() {
                "auth_time" => issue.auth_time.map(|value| json!(value)),
                "amr" if !issue.amr.is_empty() => Some(json!(&issue.amr)),
                "acr" => issue.acr.as_ref().map(|value| json!(value)),
                "sid" => id_token_session_sid(client, issue, frontchannel_logout_enabled)
                    .map(|value| json!(value)),
                _ => extra_claims
                    .and_then(Value::as_object)
                    .and_then(|claims| claims.get(&request.name))
                    .cloned(),
            };
            actual.is_some_and(|actual| claim_request_value_matches(request, &actual))
        })
}

fn id_token_signing_alg_for_client(client: &ClientRow) -> jsonwebtoken::Algorithm {
    client
        .id_token_signed_response_alg
        .as_deref()
        .and_then(signing_algorithm_from_name)
        .unwrap_or_else(|| {
            if client.require_dpop_bound_tokens
                || client.require_mtls_bound_tokens
                || client.require_par_request_object
            {
                jsonwebtoken::Algorithm::PS256
            } else {
                jsonwebtoken::Algorithm::RS256
            }
        })
}

async fn persist_access_token_subject_mapping(
    service: &ServerTokenService,
    access_token_ttl_seconds: i64,
    jti: &str,
    tenant_id: Uuid,
    user_id: Option<Uuid>,
    subject: &str,
) -> anyhow::Result<()> {
    let Some(user_id) = user_id else {
        return Ok(());
    };
    if subject == user_id.to_string() {
        return Ok(());
    }
    service
        .store_access_token_subject(
            tenant_id,
            jti,
            user_id,
            access_token_ttl_seconds.max(1) as u64,
        )
        .await?;
    Ok(())
}

fn issuance_request_digest(client: &ClientRow, issue: &TokenIssue, grant_key: &str) -> String {
    // This digest is deliberately built from the normalized issue, not from
    // raw form fields.  A retry with a different client, subject, scope,
    // resource, sender binding or OIDC contract therefore cannot reuse a
    // response belonging to another logical grant.
    let material = json!({
        "client_id": client.id,
        "tenant_id": client.tenant_id,
        "grant_key": grant_key,
        "subject": issue.subject,
        "user_id": issue.user_id,
        "scopes": issue.scopes,
        "audiences": issue.audiences,
        "authorization_details": issue.authorization_details,
        "nonce": issue.nonce,
        "auth_time": issue.auth_time,
        "amr": issue.amr,
        "oidc_sid": issue.oidc_sid,
        "acr": issue.acr,
        "userinfo_claims": issue.userinfo_claims,
        "userinfo_claim_requests": issue.userinfo_claim_requests,
        "id_token_claims": issue.id_token_claims,
        "id_token_claim_requests": issue.id_token_claim_requests,
        "refresh_id_token_sid": issue.refresh_id_token_sid,
        "include_refresh": issue.include_refresh,
        "dpop_jkt": issue.dpop_jkt,
        "refresh_token_dpop_jkt": issue.refresh_token_dpop_jkt,
        "mtls_x5t_s256": issue.mtls_x5t_s256,
        "refresh_token_mtls_x5t_s256": issue.refresh_token_mtls_x5t_s256,
        "refresh_token_client_attestation_jkt": issue.refresh_token_client_attestation_jkt,
        "refresh_token_scopes": issue.refresh_token_scopes,
        "issued_token_type": issue.issued_token_type,
    });
    blake3_hex(
        &serde_json::to_string(&material)
            .expect("normalized token issue digest payload must serialize"),
    )
}

fn stable_grant_key(grant_key: Option<&str>) -> String {
    grant_key
        .filter(|value| !value.trim().is_empty())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| format!("ephemeral:{}", Uuid::now_v7()))
}

fn response_from_token_issuance(record: &TokenIssuanceRecord) -> Option<HttpResponse> {
    let body = record.response_body.as_ref()?.clone();
    if !matches!(
        record.phase,
        TokenIssuancePhase::Signed | TokenIssuancePhase::Persisted | TokenIssuancePhase::Delivered
    ) {
        return None;
    }
    Some(
        HttpResponse::Ok()
            .insert_header((header::CACHE_CONTROL, "no-store"))
            .content_type("application/json")
            .body(body),
    )
}

/// Recover a response that was durably persisted before the previous request
/// lost its HTTP connection.  This intentionally says nothing about socket
/// delivery: only the database-backed response handoff is recoverable.
pub(crate) async fn recover_token_issuance_response(
    token_service: &ServerTokenService,
    client: &ClientRow,
    grant_key: &str,
) -> Option<HttpResponse> {
    match token_service
        .token_issuance_by_grant(client.tenant_id, client.id, grant_key)
        .await
    {
        Ok(Some(record)) => response_from_token_issuance(&record),
        Ok(None) => None,
        Err(error) => {
            tracing::warn!(%error, "failed to recover token issuance response");
            None
        }
    }
}

pub(crate) fn request_idempotency_key(req: &actix_web::HttpRequest) -> Option<String> {
    let value = req.headers().get("idempotency-key")?.to_str().ok()?.trim();
    if value.is_empty() || value.len() > 256 {
        return None;
    }
    Some(format!("idempotency:{}", blake3_hex(value)))
}

pub(crate) async fn issue_token_response_with_service(
    context: &TokenIssuanceContext<'_>,
    token_service: &ServerTokenService,
    client: &ClientRow,
    issue: TokenIssue,
) -> HttpResponse {
    issue_token_response_with_service_and_grant(context, token_service, client, None, issue).await
}

pub(crate) async fn issue_token_response_with_service_and_grant(
    context: &TokenIssuanceContext<'_>,
    token_service: &ServerTokenService,
    client: &ClientRow,
    grant_key: Option<&str>,
    mut issue: TokenIssue,
) -> HttpResponse {
    let auth_code_ttl_seconds = context.config.auth_code_ttl_seconds.max(1);
    issue.authorization_details = match normalize_authorization_details(issue.authorization_details)
    {
        Ok(value) => value,
        Err(_) => {
            mark_failed_authorization_code_if_needed(
                token_service,
                issue.authorization_code_hash.as_deref(),
                "authorization_details_state_invalid",
                auth_code_ttl_seconds,
            )
            .await;
            return oauth_token_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "授权详情状态无效.",
                false,
            );
        }
    };
    let issue_includes_openid = issue.scopes.iter().any(|s| s == "openid");
    if issue_includes_openid && issue.user_id.is_none() {
        mark_failed_authorization_code_if_needed(
            token_service,
            issue.authorization_code_hash.as_deref(),
            "id_token_subject_missing",
            auth_code_ttl_seconds,
        )
        .await;
        return oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "openid 授权缺少用户主体.",
            false,
        );
    }
    if issue.native_sso.is_some() && !context.permits(nazo_runtime_modules::ModuleId::NativeSso) {
        mark_failed_authorization_code_if_needed(
            token_service,
            issue.authorization_code_hash.as_deref(),
            "native_sso_disabled",
            auth_code_ttl_seconds,
        )
        .await;
        return oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_scope",
            "Native SSO is not enabled.",
            false,
        );
    }
    if issue.native_sso.is_some() && !issue_includes_openid {
        mark_failed_authorization_code_if_needed(
            token_service,
            issue.authorization_code_hash.as_deref(),
            "native_sso_without_openid",
            auth_code_ttl_seconds,
        )
        .await;
        return oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_scope",
            "Native SSO requires openid.",
            false,
        );
    }
    let refresh_authorization_scopes = issue
        .refresh_token_scopes
        .as_deref()
        .unwrap_or(&issue.scopes);
    let openid4vci_credential_authorization = context
        .config
        .openid4vci_audience(refresh_authorization_scopes, &issue.authorization_details)
        .is_some();
    let will_issue_refresh = issue.include_refresh
        && should_issue_refresh_token(
            client,
            refresh_authorization_scopes,
            openid4vci_credential_authorization,
        );
    if will_issue_refresh
        && client.token_endpoint_auth_method == "attest_jwt_client_auth"
        && issue.refresh_token_client_attestation_jkt.is_none()
    {
        mark_failed_authorization_code_if_needed(
            token_service,
            issue.authorization_code_hash.as_deref(),
            "client_attestation_binding_missing",
            auth_code_ttl_seconds,
        )
        .await;
        return oauth_token_error(
            StatusCode::UNAUTHORIZED,
            "invalid_client_attestation",
            "Client attestation refresh-token binding is missing.",
            false,
        );
    }
    let grant_key = stable_grant_key(grant_key);
    let request_digest = issuance_request_digest(client, &issue, &grant_key);
    let issuance_id = match token_service
        .prepare_token_issuance(PrepareTokenIssuance {
            issuance_id: Uuid::now_v7(),
            tenant_id: client.tenant_id,
            client_id: client.id,
            grant_key: grant_key.clone(),
            request_digest: request_digest.clone(),
            expires_at: Utc::now()
                + Duration::seconds(context.config.access_token_ttl_seconds.max(1)),
        })
        .await
    {
        Ok(PrepareTokenIssuanceResult::Created(record)) => record.issuance_id,
        Ok(PrepareTokenIssuanceResult::Existing(record)) => {
            if record.request_digest != request_digest {
                mark_failed_authorization_code_if_needed(
                    token_service,
                    issue.authorization_code_hash.as_deref(),
                    "token_issuance_request_conflict",
                    auth_code_ttl_seconds,
                )
                .await;
                return oauth_token_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "令牌签发请求与既有事务不一致.",
                    false,
                );
            }
            if let Some(response) = response_from_token_issuance(&record) {
                return response;
            }
            record.issuance_id
        }
        Ok(PrepareTokenIssuanceResult::Conflict) => {
            mark_failed_authorization_code_if_needed(
                token_service,
                issue.authorization_code_hash.as_deref(),
                "token_issuance_request_conflict",
                auth_code_ttl_seconds,
            )
            .await;
            return oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "令牌签发请求与既有事务不一致.",
                false,
            );
        }
        Err(error) => {
            tracing::warn!(%error, "failed to prepare token issuance saga");
            mark_failed_authorization_code_if_needed(
                token_service,
                issue.authorization_code_hash.as_deref(),
                "token_issuance_prepare_failed",
                auth_code_ttl_seconds,
            )
            .await;
            return oauth_token_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "令牌签发状态准备失败.",
                false,
            );
        }
    };
    let now = Utc::now();
    let next_dpop_nonce = if issue.dpop_jkt.is_some() {
        match issue_dpop_nonce_with_authorization_service(context.authorization).await {
            Ok(nonce) => Some(nonce),
            Err(error) => {
                mark_failed_authorization_code_if_needed(
                    token_service,
                    issue.authorization_code_hash.as_deref(),
                    "dpop_next_nonce_failed",
                    auth_code_ttl_seconds,
                )
                .await;
                return dpop_error_response(error, DpopErrorContext::TokenEndpoint);
            }
        }
    } else {
        None
    };
    let issued_access_token = match token_service
        .sign_access_token(nazo_auth::AccessTokenSignInput {
            issuer: &context.config.issuer,
            tenant_id: client.tenant_id,
            subject: &issue.subject,
            user_id: issue.user_id,
            subject_type: if issue.user_id.is_some() {
                "user"
            } else {
                "client"
            },
            client_id: &client.client_id,
            audiences: &issue.audiences,
            scopes: &issue.scopes,
            authorization_details: &issue.authorization_details,
            userinfo_claims: &issue.userinfo_claims,
            userinfo_claim_requests: &issue.userinfo_claim_requests,
            ttl_seconds: context.config.access_token_ttl_seconds,
            dpop_jkt: issue.dpop_jkt.as_deref(),
            mtls_x5t_s256: issue.mtls_x5t_s256.as_deref(),
            actor: issue.actor.as_ref(),
        })
        .await
    {
        Ok(v) => v,
        Err(_) => {
            mark_failed_authorization_code_if_needed(
                token_service,
                issue.authorization_code_hash.as_deref(),
                "access_token_signing_failed",
                auth_code_ttl_seconds,
            )
            .await;
            return oauth_token_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "令牌签发失败.",
                false,
            );
        }
    };
    if let Err(error) = persist_access_token_subject_mapping(
        token_service,
        context.config.access_token_ttl_seconds,
        &issued_access_token.jti,
        client.tenant_id,
        issue.user_id,
        &issue.subject,
    )
    .await
    {
        tracing::warn!(%error, "failed to persist access token subject mapping");
        mark_failed_authorization_code_if_needed(
            token_service,
            issue.authorization_code_hash.as_deref(),
            "access_token_subject_mapping_failed",
            auth_code_ttl_seconds,
        )
        .await;
        return oauth_token_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "令牌主体状态写入失败.",
            false,
        );
    }
    let token_type = if issue.dpop_jkt.is_some() {
        "DPoP"
    } else {
        "Bearer"
    };
    let mut body = json!({
        "access_token": issued_access_token.token,
        "token_type": token_type,
        "expires_in": context.config.access_token_ttl_seconds,
        "scope": issue.scopes.join(" ")
    });
    if !nazo_auth::authorization_details_empty(&issue.authorization_details) {
        body["authorization_details"] = issue.authorization_details.clone();
    }
    if let Some(issued_token_type) = issue.issued_token_type.as_deref() {
        body["issued_token_type"] = json!(issued_token_type);
    }
    let mut refresh_token_family_id = None;
    let mut issued_id_token_sid = None;
    // A refreshed ID Token is optional under OIDC Core 12.2, but if it is
    // emitted it must carry the original authentication context. Legacy
    // refresh rows have no persisted context; keep their access/refresh
    // response usable while omitting an unverifiable ID Token.
    let can_issue_refresh_id_token =
        issue.refresh_token_scopes.is_none() || issue.auth_time.is_some();
    if issue_includes_openid && can_issue_refresh_id_token {
        let user_id = issue
            .user_id
            .expect("openid token issues are rejected before signing without a user subject");
        let sector_identifier_host = client.sector_identifier_host.as_deref();
        let id_token_claim_scopes = issue
            .refresh_token_scopes
            .as_deref()
            .unwrap_or(&issue.scopes);
        let loaded_claims = token_service
            .active_subject_claims(client.tenant_id, user_id)
            .await;
        let loaded_claims = match loaded_claims {
            Ok(Some(claims)) => Some(claims),
            Ok(None) => {
                mark_failed_authorization_code_if_needed(
                    token_service,
                    issue.authorization_code_hash.as_deref(),
                    "id_token_subject_invalid",
                    auth_code_ttl_seconds,
                )
                .await;
                return oauth_token_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "授权用户不存在或已停用.",
                    false,
                );
            }
            Err(error) => {
                tracing::warn!(?error, "failed to load id_token subject claims");
                mark_failed_authorization_code_if_needed(
                    token_service,
                    issue.authorization_code_hash.as_deref(),
                    "id_token_subject_load_failed",
                    auth_code_ttl_seconds,
                )
                .await;
                return oauth_token_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "server_error",
                    "id_token 用户声明加载失败.",
                    false,
                );
            }
        };
        let mut user_claims = loaded_claims.map(|claims| {
            oidc_id_token_user_claims(
                &claims,
                id_token_claim_scopes,
                &issue.subject,
                &issue.id_token_claims,
                &issue.id_token_claim_requests,
                sector_identifier_host,
            )
        });
        if let Some(native_sso) = issue.native_sso.as_ref() {
            let claims = user_claims.get_or_insert_with(|| json!({}));
            if let Some(claims) = claims.as_object_mut() {
                claims.insert("ds_hash".to_owned(), json!(native_sso.ds_hash));
            }
        }
        let frontchannel_logout_enabled =
            context.permits(nazo_runtime_modules::ModuleId::FrontchannelLogout);
        let id_token_sid = id_token_session_sid(client, &issue, frontchannel_logout_enabled)
            .map(ToOwned::to_owned);
        issued_id_token_sid = id_token_sid.clone();
        if issue.refresh_token_scopes.is_some()
            && !refreshed_id_token_essential_claims_satisfied(
                &issue,
                client,
                frontchannel_logout_enabled,
                user_claims.as_ref(),
            )
        {
            mark_failed_authorization_code_if_needed(
                token_service,
                issue.authorization_code_hash.as_deref(),
                "refresh_id_token_essential_claim_missing",
                auth_code_ttl_seconds,
            )
            .await;
            return oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "refresh_token 无法满足原始 ID Token 必需声明.",
                false,
            );
        }
        let signed_id_token = match token_service
            .sign_id_token(nazo_auth::IdTokenSignInput {
                issuer: &context.config.issuer,
                subject: &issue.subject,
                client_id: &client.client_id,
                // OIDC Core 12.2 says a refreshed ID Token SHOULD omit
                // nonce.  The original value remains in `issue.nonce` so
                // the successor refresh contract can retain it, but it is
                // never emitted for a refresh issuance.
                nonce: if issue.refresh_token_scopes.is_some() {
                    None
                } else {
                    issue.nonce.as_deref()
                },
                auth_time: issue.auth_time,
                amr: &issue.amr,
                sid: id_token_sid.as_deref(),
                acr: issue.acr.as_deref(),
                extra_claims: user_claims.as_ref(),
                ttl_seconds: context.config.id_token_ttl_seconds,
                signing_algorithm: signing_algorithm_name(id_token_signing_alg_for_client(client)),
            })
            .await
        {
            Ok(token) => token,
            Err(_) => {
                mark_failed_authorization_code_if_needed(
                    token_service,
                    issue.authorization_code_hash.as_deref(),
                    "id_token_signing_failed",
                    auth_code_ttl_seconds,
                )
                .await;
                return oauth_token_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "server_error",
                    "id_token 签发失败.",
                    false,
                );
            }
        };
        let id_token = match client_jwe_key(
            client.jwks.as_ref(),
            client.id_token_encrypted_response_alg.as_deref(),
            client.id_token_encrypted_response_enc.as_deref(),
            "id_token",
        )
        .and_then(|key| {
            key.map_or_else(
                || Ok(signed_id_token.clone()),
                |key| {
                    encrypt_compact_jwe(&key, signed_id_token.as_bytes(), JwePayloadKind::NestedJwt)
                },
            )
        }) {
            Ok(token) => token,
            Err(error) => {
                tracing::warn!(%error, "failed to encrypt id_token");
                mark_failed_authorization_code_if_needed(
                    token_service,
                    issue.authorization_code_hash.as_deref(),
                    "id_token_encryption_failed",
                    auth_code_ttl_seconds,
                )
                .await;
                return oauth_token_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "server_error",
                    "id_token 加密失败.",
                    false,
                );
            }
        };
        body["id_token"] = json!(id_token);
    }
    let mut refresh_rotated = None;
    // OIDC uses `offline_access` to request a refresh token. OpenID4VCI instead
    // authorizes credential issuance with a credential-type scope or an
    // `openid_credential` authorization detail; HAIP 1.0 section 4.4 recommends
    // refresh-token support for later credential refresh. Keep both paths behind
    // the client's explicit `refresh_token` grant registration.
    if will_issue_refresh {
        let refresh_family = match issue.refresh_token_policy {
            RefreshTokenPolicy::IssueNew => Some((Uuid::now_v7(), None, None)),
            RefreshTokenPolicy::Rotate {
                family_id,
                rotated_from_id,
            } => Some((family_id, Some(rotated_from_id), None)),
            RefreshTokenPolicy::RotateLostResponse {
                family_id,
                original_id,
                successor_id,
                retry_started_at,
            } => Some((
                family_id,
                Some(successor_id),
                Some((original_id, retry_started_at)),
            )),
            RefreshTokenPolicy::PreserveExisting => None,
        };
        if let Some((family, rotated_from, lost_response_retry)) = refresh_family {
            let refresh = PendingRefreshToken {
                raw: format!("{}.{}", random_urlsafe_token(), random_urlsafe_token()),
                family,
                rotated_from,
                lost_response_retry,
                issued_at: now,
                expires_at: now + Duration::seconds(context.config.refresh_token_ttl_seconds),
            };
            // A refresh request may narrow away `openid`, so no ID Token is
            // signed in this response.  The successor must nevertheless
            // retain the original SID contract for a later refresh that
            // requests OpenID again.
            let id_token_sid_for_refresh_persistence =
                persisted_id_token_sid(&issue, issued_id_token_sid.as_deref());
            match persist_refresh_token(
                token_service,
                client,
                context.config.issuer(),
                &issue,
                &refresh,
                id_token_sid_for_refresh_persistence,
            )
            .await
            {
                Ok(RefreshPersistResult::Inserted) => {
                    body["refresh_token"] = json!(refresh.raw);
                    refresh_token_family_id = Some(refresh.family);
                    refresh_rotated = refresh
                        .rotated_from
                        .map(|rotated_from_id| (refresh.family, rotated_from_id));
                }
                Ok(RefreshPersistResult::RotationConflict) => {
                    mark_failed_authorization_code_if_needed(
                        token_service,
                        issue.authorization_code_hash.as_deref(),
                        "refresh_rotation_conflict",
                        auth_code_ttl_seconds,
                    )
                    .await;
                    return oauth_token_error(
                        StatusCode::BAD_REQUEST,
                        "invalid_grant",
                        "refresh_token 无效或已撤销.",
                        false,
                    );
                }
                Err(error) => {
                    tracing::warn!(%error, "failed to persist refresh token");
                    mark_failed_authorization_code_if_needed(
                        token_service,
                        issue.authorization_code_hash.as_deref(),
                        "refresh_persist_failed",
                        auth_code_ttl_seconds,
                    )
                    .await;
                    let description = if refresh.rotated_from.is_some() {
                        "refresh_token 轮换失败."
                    } else {
                        "refresh token 持久化失败."
                    };
                    return oauth_token_error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "server_error",
                        description,
                        false,
                    );
                }
            }
        }
    }
    if let Some(native_sso) = issue.native_sso.as_ref() {
        let Some(refresh_token_family_id) = refresh_token_family_id else {
            mark_failed_authorization_code_if_needed(
                token_service,
                issue.authorization_code_hash.as_deref(),
                "native_sso_refresh_token_missing",
                auth_code_ttl_seconds,
            )
            .await;
            return oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "Native SSO requires a refresh token session.",
                false,
            );
        };
        if let Err(error) = persist_native_sso_device_secret(
            token_service,
            context.config.refresh_token_ttl_seconds,
            client,
            &issue,
            native_sso,
            refresh_token_family_id,
        )
        .await
        {
            tracing::warn!(%error, "failed to persist Native SSO device secret");
            mark_failed_authorization_code_if_needed(
                token_service,
                issue.authorization_code_hash.as_deref(),
                "native_sso_device_secret_persist_failed",
                auth_code_ttl_seconds,
            )
            .await;
            return oauth_token_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "Native SSO device secret persistence failed.",
                false,
            );
        }
        body["device_secret"] = json!(native_sso.device_secret);
    }
    if let Some(code_hash) = issue.authorization_code_hash.as_deref() {
        let consumed_state_ttl_seconds = consumed_authorization_code_ttl_seconds(
            context.config.access_token_ttl_seconds,
            context.config.refresh_token_ttl_seconds,
            refresh_token_family_id,
        );
        if let Err(error) = persist_consumed_authorization_code(
            token_service,
            nazo_auth::IssuedAuthorizationCodeTokens {
                tenant_id: client.tenant_id,
                client_id: client.id,
                code_hash,
                access_token_jti: &issued_access_token.jti,
                access_token_expires_at: issued_access_token.expires_at,
                refresh_token_family_id,
                consumed_state_ttl_seconds,
            },
        )
        .await
        {
            tracing::warn!(%error, "failed to persist consumed authorization code marker");
            return oauth_token_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "授权码兑换状态写入失败.",
                false,
            );
        }
    }
    let response_body = match serde_json::to_vec(&body) {
        Ok(body) => body,
        Err(error) => {
            tracing::warn!(%error, "failed to serialize token issuance response");
            let _ = token_service
                .revoke_issued_tokens(
                    client.tenant_id,
                    client.id,
                    &issued_access_token.jti,
                    DateTime::<Utc>::from_timestamp(issued_access_token.expires_at, 0),
                    refresh_token_family_id,
                )
                .await;
            return oauth_token_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "令牌签发响应序列化失败.",
                false,
            );
        }
    };
    let response_digest = blake3::hash(&response_body).to_hex().to_string();
    match token_service
        .record_token_issuance_signed(
            issuance_id,
            &request_digest,
            &issued_access_token.jti,
            issued_access_token.expires_at,
            &response_body,
            &response_digest,
        )
        .await
    {
        Ok(TokenIssuanceTransitionResult::Applied) => {}
        Ok(TokenIssuanceTransitionResult::Conflict) => {
            // A concurrent request may have won the transition.  Recover its
            // durable response rather than minting a second credential.
            if let Some(response) =
                recover_token_issuance_response(token_service, client, &grant_key).await
            {
                return response;
            }
            return oauth_token_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "令牌签发状态竞争.",
                false,
            );
        }
        Ok(TokenIssuanceTransitionResult::Missing) | Err(_) => {
            tracing::warn!(issuance_id = %issuance_id, "failed to persist signed token issuance");
            let _ = token_service
                .revoke_issued_tokens(
                    client.tenant_id,
                    client.id,
                    &issued_access_token.jti,
                    DateTime::<Utc>::from_timestamp(issued_access_token.expires_at, 0),
                    refresh_token_family_id,
                )
                .await;
            return oauth_token_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "令牌签发状态写入失败.",
                false,
            );
        }
    }
    match token_service
        .mark_token_issuance_persisted(issuance_id, &request_digest)
        .await
    {
        Ok(TokenIssuanceTransitionResult::Applied)
        | Ok(TokenIssuanceTransitionResult::Conflict) => {}
        Ok(TokenIssuanceTransitionResult::Missing) | Err(_) => {
            tracing::warn!(issuance_id = %issuance_id, "failed to mark token issuance persisted");
        }
    }
    // “Delivered” means the stable response handoff is recorded.  The actual
    // HTTP socket write is intentionally outside the saga's proof boundary.
    if let Err(error) = token_service
        .mark_token_issuance_delivered(issuance_id, &request_digest)
        .await
    {
        tracing::warn!(%error, issuance_id = %issuance_id, "failed to mark token issuance delivered");
    }
    if let Err(error) = audit_event_required(
        "token_issued",
        audit_fields(&[
            ("client_id", json!(client.client_id)),
            ("user_id", json!(issue.user_id)),
            ("subject_hash", json!(blake3_hex(&issue.subject))),
            ("scope", json!(issue.scopes.join(" "))),
            ("audience", json!(issue.audiences)),
            ("access_token_jti", json!(issued_access_token.jti)),
            ("refresh_token_family_id", json!(refresh_token_family_id)),
        ]),
    )
    .await
    {
        tracing::error!(%error, issuance_id = %issuance_id, "required token issuance audit failed");
        return oauth_token_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "令牌签发审计写入失败.",
            false,
        );
    }
    if let Some((family_id, rotated_from_id)) = refresh_rotated
        && let Err(error) = audit_event_required(
            "refresh_rotated",
            audit_fields(&[
                ("client_id", json!(client.client_id)),
                ("token_family_id", json!(family_id)),
                ("rotated_from_id", json!(rotated_from_id)),
            ]),
        )
        .await
    {
        tracing::error!(%error, issuance_id = %issuance_id, "required refresh rotation audit failed");
        return oauth_token_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "刷新令牌轮换审计写入失败.",
            false,
        );
    }
    let mut response = json_response_no_store(body);
    if let Some(nonce) = next_dpop_nonce
        && let Ok(value) = HeaderValue::from_str(&nonce)
    {
        response
            .headers_mut()
            .insert(header::HeaderName::from_static("dpop-nonce"), value);
    }
    response
}

#[cfg(test)]
#[path = "../../../tests/support/http/token/issue.rs"]
pub(crate) mod test_support;

#[cfg(test)]
#[path = "../../../tests/unit/http/token/issue.rs"]
mod tests;
