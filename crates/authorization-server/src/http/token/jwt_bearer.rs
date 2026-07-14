//! RFC 7523 JWT bearer authorization grant.
#[cfg(test)]
use nazo_http_actix::OAuthJsonErrorFields;
use nazo_http_actix::oauth_token_error;

use super::issue::{TokenIssuanceContext, issue_token_response_with_service};
use super::{
    ServerTokenService, TokenForm, consume_token_client_assertion_with_authorization_service,
};
use crate::adapters::security::ValidatedClientAssertion;
use crate::adapters::security::client_jwt_decoding_key;
#[cfg(test)]
use crate::domain::TestAppState;
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
#[cfg(test)]
use crate::settings::Settings;
#[cfg(test)]
use crate::test_support::{ClientSigningFixture, client_signing_fixture};
use actix_web::http::StatusCode;
use actix_web::{HttpRequest, HttpResponse};
#[cfg(test)]
use base64::Engine;
use chrono::Utc;
use nazo_auth::{
    JwtBearerAssertionClaims, JwtBearerGrantError, JwtBearerGrantPolicy,
    ValidatedJwtBearerAssertion, admit_jwt_bearer_grant, is_subset, parse_scope,
    validate_jwt_bearer_assertion_claims, validate_jwt_bearer_grant_prerequisites,
};
use serde_json::json;
#[cfg(test)]
use uuid::Uuid;

pub(crate) const JWT_BEARER_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";

#[derive(Debug)]
pub(crate) enum JwtBearerAssertionError {
    Invalid,
    ReplayDetected,
    StoreUnavailable,
}

fn jwt_bearer_policy<'a>(
    issuance: &'a TokenIssuanceContext<'_>,
    client: &'a ClientRow,
    now: i64,
) -> JwtBearerGrantPolicy<'a> {
    JwtBearerGrantPolicy {
        enabled: issuance.accepts(nazo_runtime_modules::ModuleId::JwtBearerGrant),
        issuer: issuance.config.issuer(),
        client_id: &client.client_id,
        client_is_confidential: client.client_type == "confidential",
        allowed_scopes: &client.scopes,
        allowed_audiences: &client.allowed_audiences,
        default_audience: issuance.config.default_audience(),
        now,
    }
}

fn validate_jwt_bearer_assertion_with_issuer(
    issuer: &str,
    client: &ClientRow,
    assertion: &str,
) -> Result<ValidatedJwtBearerAssertion, JwtBearerAssertionError> {
    let header =
        jsonwebtoken::decode_header(assertion).map_err(|_| JwtBearerAssertionError::Invalid)?;
    let kid = header.kid.ok_or(JwtBearerAssertionError::Invalid)?;
    let decoding_key = client_jwt_decoding_key(client, &kid, header.alg)
        .ok_or(JwtBearerAssertionError::Invalid)?;
    let mut validation = jsonwebtoken::Validation::new(header.alg);
    validation.validate_aud = false;
    validation.set_issuer(&[client.client_id.as_str()]);
    let token_data =
        jsonwebtoken::decode::<JwtBearerAssertionClaims>(assertion, &decoding_key, &validation)
            .map_err(|_| JwtBearerAssertionError::Invalid)?;
    let now = Utc::now().timestamp();
    validate_jwt_bearer_assertion_claims(
        token_data.claims,
        JwtBearerGrantPolicy {
            enabled: true,
            issuer,
            client_id: &client.client_id,
            client_is_confidential: true,
            allowed_scopes: &[],
            allowed_audiences: &[],
            default_audience: "",
            now,
        },
    )
    .map_err(|_| JwtBearerAssertionError::Invalid)
}

#[cfg(test)]
fn validate_jwt_bearer_assertion(
    settings: &Settings,
    client: &ClientRow,
    assertion: &str,
) -> Result<ValidatedJwtBearerAssertion, JwtBearerAssertionError> {
    validate_jwt_bearer_assertion_with_issuer(&settings.endpoint.issuer, client, assertion)
}

async fn consume_jwt_bearer_assertion_with_authorization_service(
    authorization_service: &crate::http::authorization::ServerAuthorizationService,
    client: &ClientRow,
    assertion: &ValidatedJwtBearerAssertion,
) -> Result<(), JwtBearerAssertionError> {
    match authorization_service
        .consume_jwt_bearer(
            &client.client_id,
            &assertion.jti,
            assertion.replay_ttl_seconds,
        )
        .await
    {
        Ok(true) => Ok(()),
        Ok(false) => Err(JwtBearerAssertionError::ReplayDetected),
        Err(error) => {
            tracing::warn!(%error, "failed to store JWT bearer grant jti");
            Err(JwtBearerAssertionError::StoreUnavailable)
        }
    }
}

fn jwt_bearer_grant_error_response(
    error: JwtBearerGrantError,
    client: &ClientRow,
    form: &TokenForm,
) -> HttpResponse {
    match error {
        JwtBearerGrantError::Disabled => oauth_token_error(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            "JWT bearer grant is disabled.",
            false,
        ),
        JwtBearerGrantError::UnauthorizedClient => oauth_token_error(
            StatusCode::BAD_REQUEST,
            "unauthorized_client",
            "JWT bearer grant requires a confidential client.",
            false,
        ),
        JwtBearerGrantError::MissingAssertion => oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "JWT bearer grant requires an assertion.",
            false,
        ),
        JwtBearerGrantError::InvalidScope => {
            let requested = parse_scope(form.scope.as_deref().unwrap_or(""));
            let description = if !requested.is_empty() && !is_subset(&requested, &client.scopes) {
                "请求的作用域超出客户端允许范围."
            } else {
                "client_credentials 不支持 openid scope."
            };
            oauth_token_error(StatusCode::BAD_REQUEST, "invalid_scope", description, false)
        }
        JwtBearerGrantError::InvalidTarget => oauth_token_error(
            StatusCode::BAD_REQUEST,
            "invalid_target",
            "请求的 audience 不在客户端允许范围内.",
            false,
        ),
        JwtBearerGrantError::InvalidAssertion | JwtBearerGrantError::ReplayDetected => {
            oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "JWT bearer assertion is invalid.",
                false,
            )
        }
        JwtBearerGrantError::Dependency(error) => {
            tracing::warn!(%error, "JWT bearer assertion state is unavailable");
            oauth_token_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "JWT bearer assertion replay state is unavailable.",
                false,
            )
        }
    }
}

#[cfg(test)]
async fn consume_jwt_bearer_assertion(
    state: &TestAppState,
    client: &ClientRow,
    assertion: &ValidatedJwtBearerAssertion,
) -> Result<(), JwtBearerAssertionError> {
    let authorization = super::issue::test_authorization_service(state);
    consume_jwt_bearer_assertion_with_authorization_service(&authorization, client, assertion).await
}

pub(crate) async fn token_jwt_bearer_with_service(
    token_service: &ServerTokenService,
    issuance: &TokenIssuanceContext<'_>,
    req: &HttpRequest,
    client: &ClientRow,
    form: &TokenForm,
    client_assertion: Option<&ValidatedClientAssertion>,
) -> HttpResponse {
    let policy = jwt_bearer_policy(issuance, client, Utc::now().timestamp());
    if let Err(error) = validate_jwt_bearer_grant_prerequisites(form.assertion.as_deref(), policy) {
        return jwt_bearer_grant_error_response(error, client, form);
    }
    let assertion = form
        .assertion
        .as_deref()
        .expect("validated JWT bearer grant must contain assertion");
    let dpop_jkt = match validate_dpop_proof_with_authorization_service(
        issuance.authorization,
        issuance.config.issuer(),
        issuance.config.mtls_endpoint_base_url(),
        issuance.config.dpop_nonce_policy(),
        req,
        None,
        None,
    )
    .await
    {
        Ok(value) => value,
        Err(error) => return dpop_error_response(error, DpopErrorContext::TokenEndpoint),
    };
    if client.require_dpop_bound_tokens && dpop_jkt.is_none() {
        return dpop_error_response(DpopError::MissingProof, DpopErrorContext::TokenEndpoint);
    }
    let mtls_x5t_s256 = if client.require_mtls_bound_tokens {
        match request_mtls_thumbprint_from_trusted_proxy(req, issuance.config.trusted_proxy_cidrs())
        {
            Some(value) => Some(value),
            None => {
                return oauth_token_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "JWT bearer grant requires mTLS sender constraint.",
                    false,
                );
            }
        }
    } else {
        None
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
    let assertion = match validate_jwt_bearer_assertion_with_issuer(
        issuance.config.issuer(),
        client,
        assertion,
    ) {
        Ok(assertion) => assertion,
        Err(_) => {
            return oauth_token_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "JWT bearer assertion is invalid.",
                false,
            );
        }
    };
    if let Err(error) = consume_jwt_bearer_assertion_with_authorization_service(
        issuance.authorization,
        client,
        &assertion,
    )
    .await
    {
        return match error {
            JwtBearerAssertionError::StoreUnavailable => oauth_token_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "JWT bearer assertion replay state is unavailable.",
                false,
            ),
            JwtBearerAssertionError::Invalid | JwtBearerAssertionError::ReplayDetected => {
                oauth_token_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "JWT bearer assertion is invalid.",
                    false,
                )
            }
        };
    }
    let admission = match admit_jwt_bearer_grant(
        form.assertion.as_deref(),
        form.scope.as_deref(),
        &form.audiences,
        policy,
    ) {
        Ok(admission) => admission,
        Err(error) => return jwt_bearer_grant_error_response(error, client, form),
    };
    issue_token_response_with_service(
        issuance,
        token_service,
        client,
        TokenIssue {
            user_id: None,
            subject: assertion.subject,
            scopes: admission.scopes,
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
            actor: None,
            issued_token_type: None,
            native_sso: None,
        },
    )
    .await
}

#[cfg(test)]
pub(crate) async fn token_jwt_bearer(
    state: &TestAppState,
    req: &HttpRequest,
    client: &ClientRow,
    form: &TokenForm,
    client_assertion: Option<&ValidatedClientAssertion>,
) -> HttpResponse {
    let connection = state.valkey_connection();
    let service = ServerTokenService::new(
        nazo_postgres::TokenIssuanceRepository::new(state.diesel_db.clone()),
        nazo_valkey::TokenIssuanceStateAdapter::new(&connection),
        state.keyset.clone(),
    );
    let config = super::issue::TokenIssuanceConfig::from(state.settings.as_ref());
    let modules = state.active_module_snapshot();
    let authorization = super::issue::test_authorization_service(state);
    token_jwt_bearer_with_service(
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

#[cfg(test)]
#[path = "../../../tests/in_source/src/http/token/tests/jwt_bearer.rs"]
mod tests;
