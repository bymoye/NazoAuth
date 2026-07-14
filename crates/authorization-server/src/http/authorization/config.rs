use crate::http::client_ip::{ClientIpConfig, IpCidr};
use crate::settings::{
    AuthorizationServerProfile, DpopNoncePolicy, RequestObjectJtiPolicy, Settings,
};

#[derive(Clone)]
pub(crate) struct AuthorizationHttpConfig {
    pub(crate) issuer: Box<str>,
    pub(crate) mtls_endpoint_base_url: Box<str>,
    pub(crate) frontend_base_url: Box<str>,
    pub(crate) profile: AuthorizationServerProfile,
    pub(crate) dpop_nonce_policy: DpopNoncePolicy,
    pub(crate) request_object_jti_policy: RequestObjectJtiPolicy,
    pub(crate) auth_code_ttl_seconds: u64,
    pub(crate) par_ttl_seconds: u64,
    pub(crate) require_pushed_authorization_requests: bool,
    pub(crate) enable_par_request_object: bool,
    pub(crate) client_secret_pepper: Box<str>,
    pub(crate) rate_limit_window_seconds: u64,
    pub(crate) token_management_max_requests: u64,
    pub(crate) client_ip_header_mode: crate::http::client_ip::ClientIpHeaderMode,
    pub(crate) client_ip: ClientIpConfig,
    pub(crate) trusted_proxy_cidrs: Box<[IpCidr]>,
}

impl From<&Settings> for AuthorizationHttpConfig {
    fn from(settings: &Settings) -> Self {
        let protocol = &settings.protocol;
        let modules = &settings.modules;
        let endpoint = &settings.endpoint;
        let rate_limit = &settings.identity.rate_limit;
        Self {
            issuer: endpoint.issuer.as_str().into(),
            mtls_endpoint_base_url: endpoint.mtls_endpoint_base_url.as_str().into(),
            frontend_base_url: endpoint.frontend_base_url.as_str().into(),
            profile: protocol.authorization_server_profile,
            dpop_nonce_policy: protocol.dpop_nonce_policy,
            request_object_jti_policy: protocol.request_object_jti_policy,
            auth_code_ttl_seconds: protocol.auth_code_ttl_seconds,
            par_ttl_seconds: protocol.par_ttl_seconds,
            require_pushed_authorization_requests: protocol.require_pushed_authorization_requests,
            enable_par_request_object: modules.enable_par_request_object,
            client_secret_pepper: protocol.client_secret_pepper.as_str().into(),
            rate_limit_window_seconds: rate_limit.window_seconds,
            token_management_max_requests: rate_limit.token_management_max_requests,
            client_ip_header_mode: endpoint.client_ip_header_mode,
            client_ip: ClientIpConfig::new(
                &endpoint.trusted_proxy_cidrs,
                endpoint.client_ip_header_mode,
            ),
            trusted_proxy_cidrs: endpoint.trusted_proxy_cidrs.clone().into(),
        }
    }
}
