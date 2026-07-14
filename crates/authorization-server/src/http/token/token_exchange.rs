//! RFC 8693 OAuth 2.0 Token Exchange grant.
//!
//! This implementation intentionally accepts only locally issued access tokens
//! and issues only locally signed access tokens. External token trust, refresh
//! token exchange, and ID-token issuance require separate policy models.
use nazo_http_actix::oauth_token_error;

use super::issue::{TokenIssuanceContext, issue_token_response_with_service};
use super::{
    ServerTokenService, TokenForm, consume_token_client_assertion_with_authorization_service,
};
use super::{native_sso_profile_requested, token_native_sso_exchange};
use crate::adapters::security::ValidatedClientAssertion;
use crate::adapters::security::constant_time_eq;
#[cfg(test)]
use crate::domain::tenancy::DEFAULT_ORGANIZATION_ID;
#[cfg(test)]
use crate::domain::tenancy::DEFAULT_REALM_ID;
#[cfg(test)]
use crate::domain::tenancy::DEFAULT_TENANT_ID;
use crate::domain::{ClientRow, RefreshTokenPolicy, TokenIssue};
use crate::http::dpop::DpopError;
use crate::http::dpop::DpopErrorContext;
use crate::http::dpop::dpop_error_response;
use crate::http::dpop::validate_dpop_proof_with_authorization_service;
use crate::http::mtls::request_mtls_thumbprint_from_trusted_proxy;
use actix_web::http::StatusCode;
use actix_web::{HttpRequest, HttpResponse};
use chrono::Utc;
#[cfg(test)]
use nazo_auth::ACCESS_TOKEN_TYPE;
use nazo_auth::{
    Claims, PresentedSenderConstraint, TokenExchangeError, TokenExchangePolicy,
    TokenExchangeRequestInput, TokenExchangeSenderBinding, admit_token_exchange, parse_scope,
    token_exchange_actor_claim, token_exchange_issuance_binding,
    validate_token_exchange_access_token, validate_token_exchange_grant_prerequisites,
    validate_token_exchange_subject,
};
use serde_json::{Value, json};
use uuid::Uuid;

pub(crate) const TOKEN_EXCHANGE_GRANT_TYPE: &str =
    "urn:ietf:params:oauth:grant-type:token-exchange";

#[derive(Debug, PartialEq, Eq)]
enum TokenExchangeTokenError {
    Invalid,
    StoreUnavailable,
}

fn token_exchange_error_response(error: TokenExchangeError) -> HttpResponse {
    match error {
        TokenExchangeError::Disabled => oauth_token_error(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            "Token exchange is disabled.",
            false,
        ),
        TokenExchangeError::UnauthorizedClient => oauth_token_error(
            StatusCode::BAD_REQUEST,
            "unauthorized_client",
            "token exchange requires a confidential client.",
            false,
        ),
        TokenExchangeError::MissingParameter => oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "token exchange request is missing required token parameters.",
            false,
        ),
        TokenExchangeError::UnsupportedTokenType => oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "unsupported token exchange token type.",
            false,
        ),
        TokenExchangeError::InvalidScope => oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_scope",
            "token exchange scope must be a subset of the subject token and client scopes.",
            false,
        ),
        TokenExchangeError::InvalidTarget => oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_target",
            "requested token exchange target is not allowed for this client.",
            false,
        ),
        TokenExchangeError::InvalidGrant => oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "token exchange input token is invalid.",
            false,
        ),
    }
}

fn token_exchange_request(form: &TokenForm) -> TokenExchangeRequestInput {
    TokenExchangeRequestInput {
        subject_token: form.subject_token.clone(),
        subject_token_type: form.subject_token_type.clone(),
        actor_token: form.actor_token.clone(),
        actor_token_type: form.actor_token_type.clone(),
        requested_token_type: form.requested_token_type.clone(),
        scope: form.scope.clone(),
        audiences: form.audiences.clone(),
    }
}

fn token_exchange_policy<'a>(
    issuance: &'a TokenIssuanceContext<'_>,
    client: &'a ClientRow,
    now: i64,
) -> TokenExchangePolicy<'a> {
    TokenExchangePolicy {
        enabled: issuance.accepts(nazo_runtime_modules::ModuleId::TokenExchange),
        client_id: &client.client_id,
        client_is_confidential: client.client_type == "confidential",
        client_tenant_id: client.tenant_id,
        allowed_scopes: &client.scopes,
        allowed_audiences: &client.allowed_audiences,
        require_dpop_bound_tokens: client.require_dpop_bound_tokens,
        require_mtls_bound_tokens: client.require_mtls_bound_tokens,
        now,
    }
}

fn token_exchange_admission_error_response(
    error: TokenExchangeError,
    form: &TokenForm,
) -> HttpResponse {
    if error == TokenExchangeError::InvalidTarget && form.audiences.is_empty() {
        return oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_target",
            "token exchange requires an explicit resource or audience.",
            false,
        );
    }
    token_exchange_error_response(error)
}

fn token_exchange_subject_error_response(
    error: TokenExchangeError,
    client: &ClientRow,
    form: &TokenForm,
    claims: &Claims,
) -> HttpResponse {
    if error == TokenExchangeError::InvalidScope {
        let requested = parse_scope(form.scope.as_deref().unwrap_or(""));
        let subject_scopes = parse_scope(&claims.scope);
        let safe_default_is_empty = requested.is_empty()
            && !subject_scopes
                .iter()
                .any(|scope| scope != "openid" && client.scopes.contains(scope));
        let description = if safe_default_is_empty {
            "token exchange cannot issue an access token without non-OIDC scopes."
        } else {
            "token exchange scope must be a subset of the subject token and client scopes."
        };
        return oauth_token_error(StatusCode::BAD_REQUEST, "invalid_scope", description, false);
    }
    if claims.client_id != client.client_id {
        return oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "client is not authorized to exchange this subject token.",
            false,
        );
    }
    if claims
        .user_id
        .as_deref()
        .is_some_and(|user_id| user_id.parse::<Uuid>().is_err())
    {
        return oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "subject token contains an invalid user boundary.",
            false,
        );
    }
    token_exchange_error_response(error)
}

async fn validate_exchange_access_token(
    token_service: &ServerTokenService,
    issuer: &str,
    client: &ClientRow,
    raw_token: &str,
    policy: TokenExchangePolicy<'_>,
) -> Result<Claims, TokenExchangeTokenError> {
    let Some(claims) = token_service
        .decode_access_token(issuer, raw_token)
        .await
        .map_err(|error| {
            tracing::warn!(?error, "failed to decode token exchange access token");
            TokenExchangeTokenError::StoreUnavailable
        })?
    else {
        return Err(TokenExchangeTokenError::Invalid);
    };
    validate_token_exchange_access_token(&claims, policy)
        .map_err(|_| TokenExchangeTokenError::Invalid)?;
    let revoked = token_service
        .access_token_revoked(client.tenant_id, &claims.jti)
        .await
        .map_err(|error| {
            tracing::warn!(%error, "failed to query token exchange access token revocation state");
            TokenExchangeTokenError::StoreUnavailable
        })?;
    if revoked {
        return Err(TokenExchangeTokenError::Invalid);
    }
    Ok(claims)
}

fn exchange_token_error_response(error: TokenExchangeTokenError) -> HttpResponse {
    match error {
        TokenExchangeTokenError::Invalid => oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "token exchange input token is invalid.",
            false,
        ),
        TokenExchangeTokenError::StoreUnavailable => oauth_token_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "token exchange token state is unavailable.",
            false,
        ),
    }
}

async fn validate_subject_sender_binding(
    authorization_service: &crate::http::authorization::ServerAuthorizationService,
    issuance: &TokenIssuanceContext<'_>,
    req: &HttpRequest,
    subject_token: &str,
    subject_binding: &TokenExchangeSenderBinding,
) -> Result<(), HttpResponse> {
    match subject_binding {
        TokenExchangeSenderBinding::Dpop(jkt) => {
            validate_dpop_proof_with_authorization_service(
                authorization_service,
                issuance.config.issuer(),
                issuance.config.mtls_endpoint_base_url(),
                issuance.config.dpop_nonce_policy(),
                req,
                Some(subject_token),
                Some(jkt),
            )
            .await
            .map_err(|error| dpop_error_response(error, DpopErrorContext::TokenEndpoint))?;
        }
        TokenExchangeSenderBinding::MutualTls(expected) => {
            let Some(actual) = request_mtls_thumbprint_from_trusted_proxy(
                req,
                issuance.config.trusted_proxy_cidrs(),
            ) else {
                return Err(oauth_token_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "mTLS-bound subject token requires a verified client certificate.",
                    false,
                ));
            };
            if !constant_time_eq(expected.as_bytes(), actual.as_bytes()) {
                return Err(oauth_token_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "mTLS-bound subject token certificate mismatch.",
                    false,
                ));
            }
        }
        TokenExchangeSenderBinding::Bearer => {}
    }
    Ok(())
}

async fn token_exchange_issue_binding(
    authorization_service: &crate::http::authorization::ServerAuthorizationService,
    issuance: &TokenIssuanceContext<'_>,
    req: &HttpRequest,
    client: &ClientRow,
    subject_binding: &TokenExchangeSenderBinding,
    policy: TokenExchangePolicy<'_>,
) -> Result<TokenExchangeSenderBinding, HttpResponse> {
    let (presented_dpop, presented_mtls) = match subject_binding {
        TokenExchangeSenderBinding::Bearer if client.require_dpop_bound_tokens => {
            let dpop_jkt = validate_dpop_proof_with_authorization_service(
                authorization_service,
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
            (dpop_jkt, None)
        }
        TokenExchangeSenderBinding::Bearer if client.require_mtls_bound_tokens => {
            let Some(x5t_s256) = request_mtls_thumbprint_from_trusted_proxy(
                req,
                issuance.config.trusted_proxy_cidrs(),
            ) else {
                return Err(oauth_token_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "token exchange requires mTLS sender constraint.",
                    false,
                ));
            };
            (None, Some(x5t_s256))
        }
        _ => (None, None),
    };
    token_exchange_issuance_binding(
        subject_binding,
        PresentedSenderConstraint {
            dpop_jkt: presented_dpop.as_deref(),
            mtls_x5t_s256: presented_mtls.as_deref(),
        },
        policy,
    )
    .map_err(|_| match subject_binding {
        TokenExchangeSenderBinding::Dpop(_) if client.require_mtls_bound_tokens => {
            oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "token exchange cannot convert DPoP subject binding to mTLS.",
                false,
            )
        }
        TokenExchangeSenderBinding::MutualTls(_) if client.require_dpop_bound_tokens => {
            oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "token exchange cannot convert mTLS subject binding to DPoP.",
                false,
            )
        }
        _ => token_exchange_error_response(TokenExchangeError::InvalidGrant),
    })
}

fn token_exchange_binding_claims(
    binding: TokenExchangeSenderBinding,
) -> (Option<String>, Option<String>) {
    match binding {
        TokenExchangeSenderBinding::Bearer => (None, None),
        TokenExchangeSenderBinding::Dpop(jkt) => (Some(jkt), None),
        TokenExchangeSenderBinding::MutualTls(thumbprint) => (None, Some(thumbprint)),
    }
}

async fn validate_actor_token(
    token_service: &ServerTokenService,
    issuer: &str,
    client: &ClientRow,
    actor_token: Option<&str>,
    policy: TokenExchangePolicy<'_>,
) -> Result<Option<Value>, HttpResponse> {
    let Some(actor_token) = actor_token else {
        return Ok(None);
    };
    let actor = validate_exchange_access_token(token_service, issuer, client, actor_token, policy)
        .await
        .map_err(exchange_token_error_response)?;
    match token_exchange_actor_claim(&actor, policy) {
        Ok(claim) => Ok(Some(claim)),
        Err(_) if actor.cnf.is_some() => Err(oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "sender-constrained actor tokens are not supported for token exchange.",
            false,
        )),
        Err(_) => Err(oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "actor token must be issued to the authenticated client.",
            false,
        )),
    }
}

pub(crate) async fn token_exchange(
    token_service: &ServerTokenService,
    authorization_service: &crate::http::authorization::ServerAuthorizationService,
    issuance: &TokenIssuanceContext<'_>,
    req: &HttpRequest,
    client: &ClientRow,
    form: &TokenForm,
    client_assertion: Option<&ValidatedClientAssertion>,
) -> HttpResponse {
    if native_sso_profile_requested(form) {
        return token_native_sso_exchange(
            token_service,
            issuance,
            req,
            client,
            form,
            client_assertion,
        )
        .await;
    }
    let request = token_exchange_request(form);
    let policy = token_exchange_policy(issuance, client, Utc::now().timestamp());
    if let Err(error) = validate_token_exchange_grant_prerequisites(&request, policy) {
        return token_exchange_error_response(error);
    }
    if let Err(error) = consume_token_client_assertion_with_authorization_service(
        authorization_service,
        client,
        client_assertion,
    )
    .await
    {
        return super::token_client_assertion_error(error);
    }
    let subject_token = form
        .subject_token
        .as_deref()
        .expect("validated token exchange form must contain subject_token");
    let subject = match validate_exchange_access_token(
        token_service,
        issuance.config.issuer(),
        client,
        subject_token,
        policy,
    )
    .await
    {
        Ok(claims) => claims,
        Err(error) => return exchange_token_error_response(error),
    };
    let validated_subject =
        match validate_token_exchange_subject(&subject, form.scope.as_deref(), policy) {
            Ok(subject) => subject,
            Err(error) => {
                return token_exchange_subject_error_response(error, client, form, &subject);
            }
        };
    if let Err(response) = validate_subject_sender_binding(
        authorization_service,
        issuance,
        req,
        subject_token,
        &validated_subject.sender_binding,
    )
    .await
    {
        return response;
    }
    let issuance_binding = match token_exchange_issue_binding(
        authorization_service,
        issuance,
        req,
        client,
        &validated_subject.sender_binding,
        policy,
    )
    .await
    {
        Ok(binding) => binding,
        Err(response) => return response,
    };
    let (dpop_jkt, mtls_x5t_s256) = token_exchange_binding_claims(issuance_binding);
    let actor = match validate_actor_token(
        token_service,
        issuance.config.issuer(),
        client,
        form.actor_token.as_deref(),
        policy,
    )
    .await
    {
        Ok(actor) => actor,
        Err(response) => return response,
    };
    let admission = match admit_token_exchange(&request, policy) {
        Ok(admission) => admission,
        Err(error) => return token_exchange_admission_error_response(error, form),
    };
    issue_token_response_with_service(
        issuance,
        token_service,
        client,
        TokenIssue {
            user_id: validated_subject.user_id,
            subject: validated_subject.subject,
            scopes: validated_subject.scopes,
            authorization_details: json!([]),
            audiences: admission.audiences,
            nonce: None,
            auth_time: None,
            amr: Vec::new(),
            oidc_sid: None,
            acr: None,
            userinfo_claims: Vec::new(),
            userinfo_claim_requests: Vec::new(),
            id_token_claims: Vec::new(),
            id_token_claim_requests: Vec::new(),
            include_refresh: false,
            refresh_token_policy: RefreshTokenPolicy::PreserveExisting,
            dpop_jkt,
            refresh_token_dpop_jkt: None,
            mtls_x5t_s256,
            refresh_token_mtls_x5t_s256: None,
            authorization_code_hash: None,
            actor,
            issued_token_type: Some(admission.issued_token_type),
            native_sso: None,
        },
    )
    .await
}

#[cfg(test)]
#[path = "../../../tests/in_source/src/http/token/tests/token_exchange.rs"]
mod tests;
