//! 令牌签发响应构造。
use std::collections::BTreeSet;

use crate::adapters::audit::{audit_event_required, audit_fields, ensure_audit_storage};
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
#[path = "issue_grant.rs"]
mod issue_grant;
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

fn matching_response_from_token_issuance(
    record: &TokenIssuanceRecord,
    request_digest: &str,
) -> Option<HttpResponse> {
    if record.request_digest != request_digest {
        return None;
    }
    response_from_token_issuance(record)
}

/// Recover only after this request lost the signed-response CAS to the same
/// issuance transaction. This is intentionally private: one-time grant
/// handlers must consume their grant before reaching issuance and must never
/// turn a later replay into a successful response recovery.
async fn recover_conflicting_token_issuance_response(
    token_service: &ServerTokenService,
    client: &ClientRow,
    grant_key: &str,
    request_digest: &str,
) -> Option<HttpResponse> {
    match token_service
        .token_issuance_by_grant(client.tenant_id, client.id, grant_key)
        .await
    {
        Ok(Some(record)) => matching_response_from_token_issuance(&record, request_digest),
        Ok(None) => None,
        Err(error) => {
            tracing::warn!(%error, "failed to recover token issuance response");
            None
        }
    }
}

async fn wait_for_token_issuance_response(
    token_service: &ServerTokenService,
    client: &ClientRow,
    grant_key: &str,
    request_digest: &str,
) -> Option<HttpResponse> {
    // A claimed Prepared row is never taken over. Waiting is bounded so a
    // crashed owner fails closed instead of allowing a second mint.
    const ATTEMPTS: usize = 80;
    const DELAY: std::time::Duration = std::time::Duration::from_millis(25);

    for attempt in 0..ATTEMPTS {
        match token_service
            .token_issuance_by_grant(client.tenant_id, client.id, grant_key)
            .await
        {
            Ok(Some(record)) => {
                if let Some(response) =
                    matching_response_from_token_issuance(&record, request_digest)
                {
                    return Some(response);
                }
            }
            Ok(None) => {}
            Err(error) => {
                tracing::warn!(%error, "failed to wait for token issuance response");
                return None;
            }
        }
        if attempt + 1 < ATTEMPTS {
            tokio::time::sleep(DELAY).await;
        }
    }
    None
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
    issue: TokenIssue,
) -> HttpResponse {
    issue_grant::issue_token_response_with_service_and_grant(
        context,
        token_service,
        client,
        grant_key,
        issue,
    )
    .await
}
#[cfg(test)]
#[path = "../../../tests/support/http/token/issue.rs"]
pub(crate) mod test_support;

#[cfg(test)]
#[path = "../../../tests/unit/http/token/issue.rs"]
pub(crate) mod tests;
