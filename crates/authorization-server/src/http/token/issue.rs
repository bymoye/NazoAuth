//! 令牌签发响应构造。
use crate::adapters::audit::audit_event;
use crate::adapters::audit::audit_fields;
use crate::adapters::security::blake3_hex;
use crate::adapters::security::random_urlsafe_token;
#[cfg(test)]
use crate::domain::TestAppState;
use crate::domain::oidc_claims::oidc_id_token_user_claims;
#[cfg(test)]
use crate::domain::tenancy::DEFAULT_ORGANIZATION_ID;
#[cfg(test)]
use crate::domain::tenancy::DEFAULT_REALM_ID;
#[cfg(test)]
use crate::domain::tenancy::DEFAULT_TENANT_ID;
use crate::domain::{ClientRow, RefreshTokenPolicy, TokenIssue};
use crate::http::client_ip::{ClientIpHeaderMode, IpCidr};
use crate::http::dpop::DpopErrorContext;
use crate::http::dpop::dpop_error_response;
use crate::http::dpop::issue_dpop_nonce_with_authorization_service;
use crate::settings::{AuthorizationServerProfile, DpopNoncePolicy, Settings};
use actix_web::HttpResponse;
use actix_web::http::StatusCode;
use actix_web::http::header;
use actix_web::http::header::HeaderValue;
use chrono::{Duration, Utc};
#[cfg(test)]
use nazo_auth::OidcClaimRequest;
use nazo_auth::normalize_authorization_details;
#[cfg(test)]
use nazo_http_actix::OAuthJsonErrorFields;
use nazo_http_actix::{json_response_no_store, oauth_token_error};
use nazo_key_management::signing_algorithm_name;
#[cfg(test)]
use serde_json::Value;
use serde_json::json;
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
    pairwise_subject_secret: Option<Box<str>>,
    authorization_server_profile: AuthorizationServerProfile,
    client_ip_header_mode: ClientIpHeaderMode,
    client_secret_pepper: Box<str>,
    enable_legacy_audience_param: bool,
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
            pairwise_subject_secret: settings
                .protocol
                .pairwise_subject_secret
                .as_deref()
                .map(Into::into),
            authorization_server_profile: settings.protocol.authorization_server_profile,
            client_ip_header_mode: settings.endpoint.client_ip_header_mode,
            client_secret_pepper: settings.protocol.client_secret_pepper.as_str().into(),
            enable_legacy_audience_param: settings.modules.enable_legacy_audience_param,
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

    pub(crate) fn legacy_audience_param_enabled(&self) -> bool {
        self.enable_legacy_audience_param
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

fn id_token_signing_alg_for_client(client: &ClientRow) -> jsonwebtoken::Algorithm {
    if client.require_dpop_bound_tokens
        || client.require_mtls_bound_tokens
        || client.require_par_request_object
        || matches!(
            client.token_endpoint_auth_method.as_str(),
            "private_key_jwt" | "tls_client_auth" | "self_signed_tls_client_auth"
        )
    {
        jsonwebtoken::Algorithm::PS256
    } else {
        jsonwebtoken::Algorithm::RS256
    }
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

#[cfg(test)]
pub(crate) fn access_token_subject_key(tenant_id: Uuid, jti: &str) -> String {
    format!(
        "oauth:access_token:subject:{}:{}",
        tenant_id,
        blake3_hex(jti)
    )
}

pub(crate) async fn issue_token_response_with_service(
    context: &TokenIssuanceContext<'_>,
    token_service: &ServerTokenService,
    client: &ClientRow,
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
    if let Some(issued_token_type) = issue.issued_token_type.as_deref() {
        body["issued_token_type"] = json!(issued_token_type);
    }
    let mut refresh_token_family_id = None;
    if issue_includes_openid {
        let user_id = issue
            .user_id
            .expect("openid token issues are rejected before signing without a user subject");
        let sector_identifier_host = client.sector_identifier_host.as_deref();
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
                &issue.scopes,
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
        let id_token = match token_service
            .sign_id_token(nazo_auth::IdTokenSignInput {
                issuer: &context.config.issuer,
                subject: &issue.subject,
                client_id: &client.client_id,
                nonce: issue.nonce.as_deref(),
                auth_time: issue.auth_time,
                amr: &issue.amr,
                sid: id_token_session_sid(
                    client,
                    &issue,
                    context.permits(nazo_runtime_modules::ModuleId::FrontchannelLogout),
                ),
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
        body["id_token"] = json!(id_token);
    }
    let mut refresh_rotated = None;
    if issue.include_refresh && should_issue_refresh_token(client, &issue.scopes) {
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
            match persist_refresh_token(token_service, client, &issue, &refresh).await {
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
    audit_event(
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
    );
    if let Some((family_id, rotated_from_id)) = refresh_rotated {
        audit_event(
            "refresh_rotated",
            audit_fields(&[
                ("client_id", json!(client.client_id)),
                ("token_family_id", json!(family_id)),
                ("rotated_from_id", json!(rotated_from_id)),
            ]),
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
pub(crate) fn test_authorization_service(
    state: &TestAppState,
) -> crate::http::authorization::ServerAuthorizationService {
    let connection = state.valkey_connection();
    crate::http::authorization::ServerAuthorizationService::new(
        nazo_postgres::AuthorizationFlowRepository::new(state.diesel_db.clone(), DEFAULT_TENANT_ID),
        nazo_valkey::AuthorizationStateAdapter::new(&connection),
        state.keyset.clone(),
    )
}

#[cfg(test)]
pub(crate) async fn issue_token_response(
    state: &TestAppState,
    client: &ClientRow,
    issue: TokenIssue,
) -> HttpResponse {
    let service = ServerTokenService::new(
        nazo_postgres::TokenIssuanceRepository::new(state.diesel_db.clone()),
        nazo_valkey::TokenIssuanceStateAdapter::new(&state.valkey_connection()),
        state.keyset.clone(),
    );
    let config = TokenIssuanceConfig::from(state.settings.as_ref());
    let modules = state.active_module_snapshot();
    let authorization = test_authorization_service(state);
    issue_token_response_with_service(
        &TokenIssuanceContext {
            config: &config,
            modules: &modules,
            authorization: &authorization,
        },
        &service,
        client,
        issue,
    )
    .await
}

#[cfg(test)]
#[path = "../../../tests/in_source/src/http/token/tests/issue.rs"]
mod tests;
