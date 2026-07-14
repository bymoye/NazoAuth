//! OpenID Connect Native SSO for Mobile Apps support.
use nazo_http_actix::oauth_token_error;

use super::{ServerTokenService, TokenForm};
use crate::adapters::security::ValidatedClientAssertion;
#[cfg(test)]
use crate::adapters::security::blake3_hex;
#[cfg(test)]
use crate::adapters::security::jwt_decoding_key_from_jwk;
use crate::adapters::security::random_urlsafe_token;
#[cfg(test)]
use crate::domain::TestAppState;
use crate::domain::client_policy::is_subset;
use crate::domain::client_policy::parse_scope;
use crate::domain::{ClientRow, NativeSsoTokenBinding, RefreshTokenPolicy, TokenIssue};
use crate::http::dpop::DpopError;
use crate::http::dpop::DpopErrorContext;
use crate::http::dpop::dpop_error_response;
use crate::http::dpop::validate_dpop_proof_with_authorization_service;
use crate::http::mtls::request_mtls_thumbprint_from_trusted_proxy;
use crate::http::token::client_auth::consume_token_client_assertion_with_authorization_service;
use crate::http::token::issue::{TokenIssuanceContext, issue_token_response_with_service};
use actix_web::http::StatusCode;
use actix_web::{HttpRequest, HttpResponse};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration, Utc};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub(crate) const DEVICE_SSO_SCOPE: &str = "device_sso";
pub(crate) const NATIVE_SSO_DEVICE_SECRET_TYPE: &str = "urn:openid:params:token-type:device-secret";
pub(crate) const NATIVE_SSO_ID_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:id_token";

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct NativeSsoDeviceSecretState {
    pub(crate) tenant_id: Uuid,
    pub(crate) user_id: Uuid,
    pub(crate) subject: String,
    pub(crate) sid: String,
    pub(crate) source_client_id: String,
    pub(crate) refresh_token_family_id: Uuid,
    pub(crate) expires_at: DateTime<Utc>,
}

#[derive(Deserialize)]
struct NativeSsoIdTokenClaims {
    iss: String,
    sub: String,
    aud: Value,
    ds_hash: String,
    sid: String,
}

pub(crate) fn native_sso_requested(scopes: &[String]) -> bool {
    scopes.iter().any(|scope| scope == DEVICE_SSO_SCOPE)
}

pub(crate) fn native_sso_client_authorized(client: &ClientRow) -> bool {
    client.scopes.iter().any(|scope| scope == DEVICE_SSO_SCOPE)
}

pub(crate) fn native_sso_device_secret_hash(device_secret: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(device_secret.as_bytes()))
}

#[cfg(test)]
pub(crate) fn native_sso_device_secret_key(device_secret: &str) -> String {
    format!(
        "oauth:native_sso:device_secret:{}",
        blake3_hex(device_secret)
    )
}

pub(crate) fn native_sso_profile_requested(form: &TokenForm) -> bool {
    form.grant_type == "urn:ietf:params:oauth:grant-type:token-exchange"
        && form.subject_token_type.as_deref() == Some(NATIVE_SSO_ID_TOKEN_TYPE)
        && form.actor_token_type.as_deref() == Some(NATIVE_SSO_DEVICE_SECRET_TYPE)
}

pub(crate) fn new_native_sso_token_binding(
    oidc_sid: Option<&str>,
) -> Option<NativeSsoTokenBinding> {
    let sid = oidc_sid?;
    let device_secret = format!("{}.{}", random_urlsafe_token(), random_urlsafe_token());
    Some(NativeSsoTokenBinding {
        ds_hash: native_sso_device_secret_hash(&device_secret),
        device_secret,
        sid: sid.to_owned(),
    })
}

fn native_sso_id_token_audience_contains(claims: &NativeSsoIdTokenClaims, client_id: &str) -> bool {
    match &claims.aud {
        Value::String(value) => value == client_id,
        Value::Array(values) => values.iter().any(|value| value.as_str() == Some(client_id)),
        _ => false,
    }
}

#[cfg(test)]
fn decode_native_sso_id_token(state: &TestAppState, token: &str) -> Option<NativeSsoIdTokenClaims> {
    let header = jsonwebtoken::decode_header(token).ok()?;
    let keyset = state.keyset.snapshot();
    let verification_key = keyset.verification_key(header.kid.as_deref()?)?;
    let decoding_key = jwt_decoding_key_from_jwk(&verification_key.public_jwk, header.alg)?;
    let mut validation = jsonwebtoken::Validation::new(header.alg);
    validation.validate_aud = false;
    validation.validate_exp = false;
    validation.set_issuer(&[state.settings.endpoint.issuer.as_str()]);
    let claims = jsonwebtoken::decode::<NativeSsoIdTokenClaims>(token, &decoding_key, &validation)
        .ok()?
        .claims;
    if claims.iss != state.settings.endpoint.issuer {
        return None;
    }
    Some(claims)
}

async fn decode_native_sso_id_token_with_service(
    token_service: &ServerTokenService,
    issuer: &str,
    token: &str,
) -> Result<Option<NativeSsoIdTokenClaims>, nazo_auth::TokenPortError> {
    let claims = token_service
        .decode_id_token(issuer, token)
        .await?
        .map(serde_json::from_value)
        .transpose()
        .map_err(|_| nazo_auth::TokenPortError::CorruptData)?;
    Ok(claims.filter(|claims: &NativeSsoIdTokenClaims| claims.iss == issuer))
}

async fn load_native_sso_device_secret_state(
    token_service: &ServerTokenService,
    device_secret: &str,
) -> Result<Option<NativeSsoDeviceSecretState>, HttpResponse> {
    let value = token_service
        .load_native_sso(device_secret)
        .await
        .map_err(|error| {
            tracing::warn!(%error, "failed to load Native SSO device secret state");
            oauth_token_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "Native SSO device secret state is unavailable.",
                false,
            )
        })?;
    let Some(value) = value else {
        return Ok(None);
    };
    serde_json::from_value(value).map(Some).map_err(|error| {
        tracing::warn!(%error, "Native SSO device secret state is malformed");
        oauth_token_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "Native SSO device secret state is invalid.",
            false,
        )
    })
}

async fn native_sso_refresh_family_active(
    token_service: &ServerTokenService,
    secret: &NativeSsoDeviceSecretState,
) -> Result<bool, HttpResponse> {
    token_service
        .refresh_family_active(
            secret.tenant_id,
            secret.refresh_token_family_id,
            secret.user_id,
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "failed to query Native SSO refresh family state");
            oauth_token_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "Native SSO session state is unavailable.",
                false,
            )
        })
}

fn native_sso_requested_scopes(
    client: &ClientRow,
    requested_scope: Option<&str>,
) -> Result<Vec<String>, HttpResponse> {
    let requested = parse_scope(requested_scope.unwrap_or("openid offline_access device_sso"));
    if !requested.iter().any(|scope| scope == "openid")
        || !requested.iter().any(|scope| scope == DEVICE_SSO_SCOPE)
        || !is_subset(&requested, &client.scopes)
    {
        return Err(oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_scope",
            "Native SSO scope must include allowed openid and device_sso scopes.",
            false,
        ));
    }
    Ok(requested)
}

fn native_sso_subject_for_client(
    config: &crate::http::token::issue::TokenIssuanceConfig,
    user_id: Uuid,
    client: &ClientRow,
) -> anyhow::Result<String> {
    let redirect_uri = client.redirect_uris.first().map_or("", String::as_str);
    Ok(nazo_auth::oidc_subject_for_client(
        config.issuer(),
        config.pairwise_subject_secret(),
        user_id,
        client.subject_type.as_str(),
        client.sector_identifier_host.as_deref(),
        redirect_uri,
    )?)
}

async fn native_sso_issue_binding(
    issuance: &TokenIssuanceContext<'_>,
    req: &HttpRequest,
    client: &ClientRow,
) -> Result<(Option<String>, Option<String>), HttpResponse> {
    if client.require_dpop_bound_tokens {
        let dpop_jkt = validate_dpop_proof_with_authorization_service(
            issuance.authorization,
            issuance.config.issuer(),
            issuance.config.mtls_endpoint_base_url(),
            issuance.config.dpop_nonce_policy(),
            req,
            None,
            None,
        )
        .await
        .map_err(|error| dpop_error_response(error, DpopErrorContext::TokenEndpoint))?;
        if dpop_jkt.is_none() {
            return Err(dpop_error_response(
                DpopError::MissingProof,
                DpopErrorContext::TokenEndpoint,
            ));
        }
        return Ok((dpop_jkt, None));
    }
    if client.require_mtls_bound_tokens {
        let Some(x5t_s256) =
            request_mtls_thumbprint_from_trusted_proxy(req, issuance.config.trusted_proxy_cidrs())
        else {
            return Err(oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "Native SSO requires mTLS sender constraint.",
                false,
            ));
        };
        return Ok((None, Some(x5t_s256)));
    }
    Ok((None, None))
}

pub(crate) async fn persist_native_sso_device_secret(
    token_service: &ServerTokenService,
    refresh_token_ttl_seconds: i64,
    client: &ClientRow,
    issue: &TokenIssue,
    binding: &NativeSsoTokenBinding,
    refresh_token_family_id: Uuid,
) -> anyhow::Result<()> {
    let Some(user_id) = issue.user_id else {
        return Ok(());
    };
    let expires_at = Utc::now() + Duration::seconds(refresh_token_ttl_seconds);
    let payload = NativeSsoDeviceSecretState {
        tenant_id: client.tenant_id,
        user_id,
        subject: issue.subject.clone(),
        sid: binding.sid.clone(),
        source_client_id: client.client_id.clone(),
        refresh_token_family_id,
        expires_at,
    };
    token_service
        .store_native_sso(
            &binding.device_secret,
            &serde_json::to_value(payload)?,
            refresh_token_ttl_seconds.max(1) as u64,
        )
        .await?;
    Ok(())
}

pub(crate) async fn token_native_sso_exchange(
    token_service: &ServerTokenService,
    issuance: &TokenIssuanceContext<'_>,
    req: &HttpRequest,
    client: &ClientRow,
    form: &TokenForm,
    client_assertion: Option<&ValidatedClientAssertion>,
) -> HttpResponse {
    if !issuance.permits(nazo_runtime_modules::ModuleId::NativeSso) {
        return oauth_token_error(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            "Native SSO is not enabled.",
            false,
        );
    }
    if !native_sso_client_authorized(client) {
        return oauth_token_error(
            StatusCode::BAD_REQUEST,
            "unauthorized_client",
            "Client is not authorized for Native SSO.",
            false,
        );
    }
    if let Err(error) = consume_token_client_assertion_with_authorization_service(
        issuance.authorization,
        client,
        client_assertion,
    )
    .await
    {
        return super::token_client_assertion_error(error);
    }
    if form.audiences.as_slice() != [issuance.config.issuer()] {
        return oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_target",
            "Native SSO token exchange audience must be the issuer.",
            false,
        );
    }
    let Some(subject_token) = form.subject_token.as_deref() else {
        return oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Native SSO requires subject_token.",
            false,
        );
    };
    let Some(device_secret) = form.actor_token.as_deref() else {
        return oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Native SSO requires actor_token.",
            false,
        );
    };
    let claims = match decode_native_sso_id_token_with_service(
        token_service,
        issuance.config.issuer(),
        subject_token,
    )
    .await
    {
        Ok(Some(claims)) => claims,
        Ok(None) | Err(_) => {
            return oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "Native SSO id_token is invalid.",
                false,
            );
        }
    };
    if claims.ds_hash != native_sso_device_secret_hash(device_secret) {
        return oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "Native SSO id_token is not bound to the device secret.",
            false,
        );
    }
    let secret = match load_native_sso_device_secret_state(token_service, device_secret).await {
        Ok(Some(secret)) => secret,
        Ok(None) => {
            return oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "Native SSO device secret is invalid.",
                false,
            );
        }
        Err(response) => return response,
    };
    if secret.tenant_id != client.tenant_id
        || secret.expires_at <= Utc::now()
        || secret.subject != claims.sub
        || secret.sid != claims.sid
        || !native_sso_id_token_audience_contains(&claims, &secret.source_client_id)
    {
        return oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "Native SSO device secret state does not match the id_token.",
            false,
        );
    }
    match native_sso_refresh_family_active(token_service, &secret).await {
        Ok(true) => {}
        Ok(false) => {
            return oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "Native SSO session is no longer active.",
                false,
            );
        }
        Err(response) => return response,
    }
    let scopes = match native_sso_requested_scopes(client, form.scope.as_deref()) {
        Ok(scopes) => scopes,
        Err(response) => return response,
    };
    let subject = match native_sso_subject_for_client(issuance.config, secret.user_id, client) {
        Ok(subject) => subject,
        Err(error) => {
            tracing::warn!(%error, "failed to compute Native SSO destination subject");
            return oauth_token_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "Native SSO subject policy failed.",
                false,
            );
        }
    };
    let (dpop_jkt, mtls_x5t_s256) = match native_sso_issue_binding(issuance, req, client).await {
        Ok(binding) => binding,
        Err(response) => return response,
    };
    issue_token_response_with_service(
        issuance,
        token_service,
        client,
        TokenIssue {
            user_id: Some(secret.user_id),
            subject,
            scopes,
            authorization_details: json!([]),
            audiences: vec![issuance.config.default_audience().to_owned()],
            nonce: None,
            auth_time: None,
            amr: vec!["native_sso".to_owned()],
            oidc_sid: Some(secret.sid),
            acr: None,
            userinfo_claims: Vec::new(),
            userinfo_claim_requests: Vec::new(),
            id_token_claims: Vec::new(),
            id_token_claim_requests: Vec::new(),
            include_refresh: true,
            refresh_token_policy: RefreshTokenPolicy::IssueNew,
            dpop_jkt: dpop_jkt.clone(),
            refresh_token_dpop_jkt: dpop_jkt,
            mtls_x5t_s256: mtls_x5t_s256.clone(),
            refresh_token_mtls_x5t_s256: mtls_x5t_s256,
            authorization_code_hash: None,
            actor: None,
            issued_token_type: Some("urn:ietf:params:oauth:token-type:access_token".to_owned()),
            native_sso: new_native_sso_token_binding(Some(&claims.sid)),
        },
    )
    .await
}

#[cfg(test)]
#[path = "../../../tests/in_source/src/http/token/tests/native_sso.rs"]
mod tests;
