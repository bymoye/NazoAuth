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
pub(crate) use nazo_http_actix::{TokenForm, TokenFormError, parse_token_form};

use refresh::token_refresh_with_service;
use token_exchange::{TOKEN_EXCHANGE_GRANT_TYPE, token_exchange};

pub(crate) type ServerTokenService = nazo_auth::TokenService<
    nazo_postgres::TokenIssuanceRepository,
    nazo_valkey::TokenIssuanceStateAdapter,
    nazo_key_management::KeyManager,
>;

use actix_web::{HttpRequest, HttpResponse, http::StatusCode};

use nazo_http_actix::{oauth_error, oauth_token_error};
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
