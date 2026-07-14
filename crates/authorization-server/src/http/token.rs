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
#[cfg(test)]
pub(crate) mod userinfo;

use authorization_code::token_authorization_code_with_service;
use ciba::{CIBA_GRANT_TYPE, token_ciba};
use client_auth::{
    ClientAuthRequestFacts, TokenManagementClientAuthError,
    consume_token_client_assertion_with_authorization_service,
};
use client_credentials::token_client_credentials_with_service;
use device::DEVICE_CODE_GRANT_TYPE;
use device_issuance::token_device_code_with_service;
#[cfg(test)]
use dispatch::validate_token_request_profile;
#[cfg(test)]
use issue::access_token_subject_key;
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
#[cfg(test)]
pub(crate) use nazo_http_actix::{
    parse_token_management_form, token_management_form_error,
    token_management_has_conflicting_client_auth,
};
use refresh::token_refresh_with_service;
use token_exchange::{TOKEN_EXCHANGE_GRANT_TYPE, token_exchange};

pub(crate) type ServerTokenService = nazo_auth::TokenService<
    nazo_postgres::TokenIssuanceRepository,
    nazo_valkey::TokenIssuanceStateAdapter,
    nazo_key_management::KeyManager,
>;

#[cfg(test)]
use crate::adapters::security::CLIENT_ASSERTION_TYPE_JWT_BEARER;
use actix_web::{HttpRequest, HttpResponse, http::StatusCode};
#[cfg(test)]
use actix_web::{
    http::header::{self, HeaderValue},
    web::Bytes,
};
#[cfg(test)]
use nazo_http_actix::{TokenManagementFormError, TokenOnlyForm};
use nazo_http_actix::{oauth_error, oauth_token_error};
#[cfg(test)]
#[path = "../../tests/in_source/src/http/token/tests/forms.rs"]
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
            source_ip: crate::http::client_ip::client_ip_with_config(
                request,
                &self.config.client_ip,
            ),
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
    trusted_proxy_cidrs: &[crate::http::client_ip::IpCidr],
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
mod lifecycle_boundary_tests {
    #[test]
    fn token_management_request_facts_preserve_the_exact_endpoint_path() {
        let settings =
            crate::settings::Settings::from_config(&crate::config::ConfigSource::default())
                .expect("default settings should load");
        let extractor =
            super::ServerTokenManagementRequestFactsExtractor::new(std::sync::Arc::new(
                crate::http::authorization::AuthorizationHttpConfig::from(&settings),
            ));
        let request = actix_web::test::TestRequest::post()
            .uri("/introspect")
            .peer_addr("203.0.113.9:443".parse().unwrap())
            .to_http_request();
        let facts =
            nazo_http_actix::TokenManagementRequestFactsExtractor::extract(&extractor, &request);
        assert_eq!(facts.endpoint_path, "/introspect");
        assert_eq!(facts.source_ip, "203.0.113.9");
        assert!(facts.client_certificate.is_none());
    }

    fn function_body<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
        source
            .split_once(start)
            .unwrap_or_else(|| panic!("missing boundary start {start}"))
            .1
            .split_once(end)
            .unwrap_or_else(|| panic!("missing boundary end {end}"))
            .0
    }

    #[test]
    fn production_token_dispatch_and_grants_do_not_receive_app_state() {
        let dispatch = include_str!("token/dispatch.rs");
        let dispatch = function_body(
            dispatch,
            "pub(crate) async fn token_with_service(",
            "#[cfg(not(test))]",
        );
        for forbidden in [
            "Data<TestAppState>",
            "state.settings",
            "state.diesel_db",
            "state.valkey_connection()",
            "TokenIssuanceRepository::new",
            "AuthorizationStore::new",
            "ReplayStore::new",
        ] {
            assert!(
                !dispatch.contains(forbidden),
                "production token dispatch reintroduced {forbidden}"
            );
        }

        for (name, source, start, end) in [
            (
                "authorization_code",
                include_str!("token/authorization_code.rs"),
                "pub(crate) async fn token_authorization_code_with_service(",
                "#[cfg(test)]\nfn test_token_service",
            ),
            (
                "refresh_token",
                include_str!("token/refresh.rs"),
                "pub(crate) async fn token_refresh_with_service(",
                "#[cfg(test)]\npub(crate) async fn token_refresh",
            ),
            (
                "native_sso",
                include_str!("token/native_sso.rs"),
                "pub(crate) async fn token_native_sso_exchange(",
                "#[cfg(test)]\n#[path =",
            ),
            (
                "ciba",
                include_str!("token/ciba.rs"),
                "pub(crate) async fn token_ciba(",
                "fn ciba_auth_req_id_client_error(",
            ),
        ] {
            let body = function_body(source, start, end);
            for forbidden in [
                "TestAppState",
                "state.settings",
                "state.diesel_db",
                "state.valkey_connection()",
                "TokenRepository::new",
                "TokenStateStore::new",
                "ReplayStore::new",
            ] {
                assert!(
                    !body.contains(forbidden),
                    "{name} production grant reintroduced {forbidden}"
                );
            }
        }
    }

    #[test]
    fn userinfo_transport_does_not_construct_storage_adapters() {
        let source = include_str!("token/userinfo.rs");
        assert!(source.contains("handles: Data<UserinfoHandles>"));
        for forbidden in [
            "Data<TestAppState>",
            "Settings",
            "KeyManager",
            "nazo_postgres",
            "nazo_valkey",
            "diesel_db",
            "TokenRepository::new",
            "OAuthClientRepository::new",
            "UserRepository::new",
            "TokenStateStore::new",
        ] {
            assert!(
                !source.contains(forbidden),
                "userinfo handler reintroduced forbidden dependency {forbidden}"
            );
        }
    }

    #[test]
    fn client_authentication_handlers_use_the_focused_authorization_boundary() {
        for (name, source) in [
            ("token", include_str!("token/dispatch.rs")),
            ("ciba", include_str!("token/ciba.rs")),
            ("device", include_str!("token/device.rs")),
            ("par", include_str!("authorization/par.rs")),
        ] {
            assert!(
                !source.contains("OAuthClientRepository::new"),
                "{name} reintroduced a direct PostgreSQL client-auth dependency"
            );
        }
        let auth_source = include_str!("token/client_auth.rs");
        for forbidden in [
            "match client.token_endpoint_auth_method.as_str()",
            ".expect(\"private_key_jwt",
            ".expect(\"secret-based client credentials",
            ".expect(\"mTLS client credentials",
        ] {
            assert!(
                !auth_source.contains(forbidden),
                "client authentication adapter reintroduced policy or panic: {forbidden}"
            );
        }
    }

    #[test]
    fn ciba_transport_uses_composition_root_handles() {
        let source = include_str!("token/ciba.rs");
        for forbidden in [
            "CibaStore::new",
            "OAuthClientRepository::new",
            "UserRepository::new",
            "state.diesel_db",
            "state.valkey_connection()",
        ] {
            assert!(
                !source.contains(forbidden),
                "CIBA transport reintroduced composition dependency {forbidden}"
            );
        }
        assert!(!source.contains(
            "pub(crate) async fn backchannel_authentication(\n    state: Data<TestAppState>"
        ));
        assert!(
            !source
                .contains("pub(crate) async fn ciba_verification(\n    state: Data<TestAppState>")
        );
    }

    #[test]
    fn shared_issuance_core_uses_typed_context_and_existing_service() {
        let source = include_str!("token/issue.rs");
        let core = source
            .split("pub(crate) async fn issue_token_response_with_service")
            .nth(1)
            .and_then(|source| source.split("#[cfg(test)]").next())
            .expect("issuance core must precede test-only compatibility code");
        for forbidden in [
            "TestAppState",
            "state.settings",
            "state.diesel_db",
            "state.valkey_connection",
            "TokenIssuanceRepository::new",
            "TokenIssuanceStateAdapter::new",
        ] {
            assert!(
                !core.contains(forbidden),
                "shared issuance core reintroduced {forbidden}"
            );
        }
    }

    #[test]
    fn device_transport_uses_focused_composition_root_dependencies() {
        let source = include_str!("token/device.rs");
        for forbidden in [
            "Data<TestAppState>",
            "Settings",
            "DeviceStore::new",
            "AuthorizationFlowRepository::new",
            "state.diesel_db",
            "state.valkey_connection()",
        ] {
            assert!(
                !source.contains(forbidden),
                "device transport reintroduced composition dependency {forbidden}"
            );
        }
        for required in [
            "Data<ServerDeviceGrantService>",
            "Data<DeviceHttpConfig>",
            "Data<SessionProfileHandles>",
            "Data<TokenManagementRequestLimiter>",
            "Data<ServerRuntimeModuleRegistry>",
        ] {
            assert!(
                source.contains(required),
                "device transport lost focused dependency {required}"
            );
        }
    }

    #[test]
    fn ciba_decision_transport_uses_focused_composition_root_dependencies() {
        let source = include_str!("token/ciba.rs");
        for forbidden in [
            "Data<TestAppState>",
            "state.permits_existing_module_transaction",
            "client_ip(&req, &state.settings)",
            "has_valid_csrf_token(&state",
            "current_user_or_login_required(&state",
        ] {
            assert!(
                !source.contains(forbidden),
                "CIBA decision transport reintroduced composition dependency {forbidden}"
            );
        }
        for required in [
            "Data<ServerCibaService>",
            "Data<CibaHttpConfig>",
            "Data<AdminSessionHandles>",
            "Data<ServerRuntimeModuleRegistry>",
        ] {
            assert!(
                source.contains(required),
                "CIBA decision transport lost focused dependency {required}"
            );
        }
    }

    #[test]
    fn device_token_issuance_handoff_uses_focused_context_and_services() {
        let source = include_str!("token/device_issuance.rs");
        assert!(source.contains("device_service: &ServerDeviceGrantService"));
        assert!(source.contains("token_service: &ServerTokenService"));
        assert!(source.contains("issuance: &TokenIssuanceContext<'_>"));
        assert!(source.contains("issue_token_response_with_service"));
        assert!(source.contains("validate_dpop_proof_with_authorization_service"));
        assert!(source.contains("consume_token_client_assertion_with_authorization_service"));
        for forbidden in [
            "TestAppState",
            "Settings",
            "state.settings",
            "DeviceStore::new",
            "DeviceGrantService::new",
            "TokenIssuanceRepository::new",
            "TokenIssuanceStateAdapter::new",
            "nazo_postgres",
            "nazo_valkey",
        ] {
            assert!(
                !source.contains(forbidden),
                "device issuance handoff reintroduced direct infrastructure {forbidden}"
            );
        }
    }
}
