//! OAuth/OIDC token 相关 HTTP handler 聚合模块。
// 子模块按 grant type 或端点职责拆分，路由层通过显式模块路径调用。
pub(crate) mod authorization_code;
pub(crate) mod ciba;
pub(crate) mod client_auth;
pub(crate) mod client_credentials;
pub(crate) mod device;
pub(crate) mod device_config;
pub(crate) mod device_issuance;
pub(crate) mod dispatch;
pub(crate) mod issue;
pub(crate) mod jwt_bearer;
pub(crate) mod native_sso;
pub(crate) mod refresh;
pub(crate) mod token_exchange;
use authorization_code::token_authorization_code_with_service;
use ciba::{CIBA_GRANT_TYPE, token_ciba};
use client_auth::{
    ClientAuthRequestFacts, TokenManagementClientAuthError,
    consume_token_client_assertion_with_authorization_service,
};
use client_credentials::token_client_credentials_with_service;
use device::DEVICE_CODE_GRANT_TYPE;
use device_issuance::token_device_code_with_service;
use issue::{
    mark_failed_authorization_code, revoke_issued_authorization_code_tokens,
    should_issue_refresh_token,
};
use jwt_bearer::{JWT_BEARER_GRANT_TYPE, token_jwt_bearer_with_service};
use native_sso::{
    native_sso_profile_requested, native_sso_requested, new_native_sso_token_binding,
    persist_native_sso_device_secret, token_native_sso_exchange,
};
#[cfg(test)]
use nazo_http_actix::parse_token_form;
pub(crate) use nazo_http_actix::{TokenForm, TokenFormError};

use refresh::token_refresh_with_service;
use token_exchange::{TOKEN_EXCHANGE_GRANT_TYPE, token_exchange};

pub(crate) type ServerTokenService = nazo_auth::TokenService<
    nazo_postgres::TokenIssuanceRepository,
    nazo_valkey::TokenIssuanceStateAdapter,
    nazo_key_management::KeyManager,
>;

use crate::adapters::security::constant_time_eq;
use crate::domain::ClientRow;
use crate::http::dpop::{DpopError, validate_dpop_proof_with_authorization_service};
use crate::http::mtls::request_mtls_thumbprint_from_trusted_proxy;
use nazo_auth::{PresentedSenderConstraint, apply_sender_constraint, sender_constraint_policy};

use actix_web::{HttpRequest, HttpResponse, http::StatusCode};

use nazo_http_actix::{oauth_error, oauth_token_error};

/// Sender proofs admitted for one token request.
///
/// The token service stores at most one sender constraint in a token.  Keep
/// this exact-one invariant at the HTTP boundary too: when both client flags
/// are enabled, either proof is sufficient, but presenting both proofs is a
/// protocol error rather than an implicit AND binding.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct ValidatedSenderConstraints {
    pub(crate) dpop_jkt: Option<String>,
    pub(crate) mtls_x5t_s256: Option<String>,
}

#[derive(Debug)]
pub(crate) enum SenderConstraintValidationError {
    Dpop(DpopError),
    MissingMtls,
    Multiple,
}

/// Validate the DPoP and mTLS sender proofs for a token endpoint request.
///
/// `expected_*` bind redemption of a previously constrained grant/token.  The
/// optional `token_for_ath` is used by token exchange, where the DPoP proof is
/// also bound to the subject access token.  mTLS material is read only through
/// the configured trusted-proxy/direct-TLS extractor; ordinary request
/// headers never become sender proof.
pub(crate) async fn validate_token_sender_constraints(
    issuance: &issue::TokenIssuanceContext<'_>,
    req: &HttpRequest,
    client: &ClientRow,
    token_for_ath: Option<&str>,
    expected_dpop_jkt: Option<&str>,
    expected_mtls_x5t_s256: Option<&str>,
) -> Result<ValidatedSenderConstraints, SenderConstraintValidationError> {
    let dpop_jkt = validate_dpop_proof_with_authorization_service(
        issuance.authorization,
        issuance.config.issuer(),
        issuance.config.mtls_endpoint_base_url(),
        issuance.config.dpop_nonce_policy(),
        req,
        token_for_ath,
        expected_dpop_jkt,
    )
    .await
    .map_err(SenderConstraintValidationError::Dpop)?;

    // A client certificate may authenticate the token request without being
    // the sender constraint.  Only inspect it when mTLS binding is required by
    // policy or by an already-bound grant; otherwise a DPoP-only client using
    // mTLS client authentication must remain DPoP-only.
    let request_mtls_x5t_s256 = (expected_mtls_x5t_s256.is_some()
        || client.require_mtls_bound_tokens)
        .then(|| {
            request_mtls_thumbprint_from_trusted_proxy(req, issuance.config.trusted_proxy_cidrs())
        })
        .flatten();
    let mtls_x5t_s256 = match (expected_mtls_x5t_s256, request_mtls_x5t_s256) {
        (Some(expected), Some(actual))
            if constant_time_eq(expected.as_bytes(), actual.as_bytes()) =>
        {
            Some(expected.to_owned())
        }
        (Some(_), _) => return Err(SenderConstraintValidationError::MissingMtls),
        (None, actual) => actual,
    };

    let has_dpop = dpop_jkt.is_some();
    let has_mtls = mtls_x5t_s256.is_some();
    if apply_sender_constraint(
        sender_constraint_policy(
            client.require_dpop_bound_tokens,
            client.require_mtls_bound_tokens,
        ),
        PresentedSenderConstraint {
            dpop_jkt: dpop_jkt.as_deref(),
            mtls_x5t_s256: mtls_x5t_s256.as_deref(),
        },
    )
    .is_err()
    {
        if has_dpop && has_mtls {
            return Err(SenderConstraintValidationError::Multiple);
        }
        if client.require_dpop_bound_tokens && !client.require_mtls_bound_tokens {
            return Err(SenderConstraintValidationError::Dpop(
                DpopError::MissingProof,
            ));
        }
        return Err(SenderConstraintValidationError::MissingMtls);
    }

    Ok(ValidatedSenderConstraints {
        dpop_jkt,
        mtls_x5t_s256,
    })
}

pub(crate) fn sender_constraint_multiple_error() -> HttpResponse {
    oauth_token_error(
        StatusCode::BAD_REQUEST,
        "invalid_request",
        "multiple sender proofs are not allowed.",
        false,
    )
}

#[cfg(test)]
#[path = "../../tests/unit/http/token/forms.rs"]
mod forms_tests;

pub(crate) struct ServerTokenManagementRequestFactsExtractor {
    config: std::sync::Arc<crate::http::authorization::AuthorizationHttpConfig>,
}

impl ServerTokenManagementRequestFactsExtractor {
    pub(crate) fn new(
        config: std::sync::Arc<crate::http::authorization::AuthorizationHttpConfig>,
    ) -> Self {
        Self { config }
    }
}

impl nazo_http_actix::TokenManagementRequestFactsExtractor
    for ServerTokenManagementRequestFactsExtractor
{
    fn extract(&self, request: &HttpRequest) -> nazo_http_actix::TokenManagementRequestFacts {
        nazo_http_actix::TokenManagementRequestFacts {
            source_ip: nazo_http_actix::client_ip_with_config(request, &self.config.client_ip),
            endpoint_path: request.path().to_owned(),
            client_certificate: None,
        }
    }

    fn extract_client_certificate(
        &self,
        request: &HttpRequest,
    ) -> Option<nazo_http_actix::ClientCertificateFacts> {
        crate::http::mtls::request_mtls_client_certificate_from_trusted_proxy(
            request,
            &self.config.trusted_proxy_cidrs,
        )
    }
}

pub(crate) fn client_auth_request_facts(
    request: &HttpRequest,
    trusted_proxy_cidrs: &[nazo_http_actix::IpCidr],
) -> ClientAuthRequestFacts {
    ClientAuthRequestFacts::new(
        request.path(),
        crate::http::mtls::request_mtls_client_certificate_from_trusted_proxy(
            request,
            trusted_proxy_cidrs,
        ),
    )
}

pub(crate) fn token_management_auth_error(error: TokenManagementClientAuthError) -> HttpResponse {
    match error {
        TokenManagementClientAuthError::InvalidClient
        | TokenManagementClientAuthError::PublicClientCredentialsForbidden => oauth_error(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "客户端认证失败.",
        ),
        TokenManagementClientAuthError::StoreUnavailable => oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "客户端认证状态存储不可用.",
        ),
    }
}

pub(crate) fn token_client_assertion_error(error: TokenManagementClientAuthError) -> HttpResponse {
    match error {
        TokenManagementClientAuthError::InvalidClient
        | TokenManagementClientAuthError::PublicClientCredentialsForbidden => oauth_token_error(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "客户端认证失败.",
            false,
        ),
        TokenManagementClientAuthError::StoreUnavailable => oauth_token_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "客户端认证状态存储不可用.",
            false,
        ),
    }
}

#[cfg(test)]
#[path = "../../tests/unit/http/token/lifecycle_boundary.rs"]
mod lifecycle_boundary_tests;
