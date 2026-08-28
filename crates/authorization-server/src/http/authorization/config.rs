use crate::settings::{
    AuthorizationServerProfile, DpopNoncePolicy, RequestObjectJtiPolicy, Settings,
};
use nazo_http_actix::{ClientIpConfig, IpCidr};

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
    pub(crate) client_secret_pepper: Box<str>,
    pub(crate) rate_limit_window_seconds: u64,
    pub(crate) token_management_max_requests: u64,
    pub(crate) client_ip_header_mode: nazo_http_actix::ClientIpHeaderMode,
    pub(crate) client_ip: ClientIpConfig,
    pub(crate) trusted_proxy_cidrs: Box<[IpCidr]>,
}

impl From<&Settings> for AuthorizationHttpConfig {
    fn from(settings: &Settings) -> Self {
        let protocol = &settings.protocol;
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

impl AuthorizationHttpConfig {
    pub(crate) fn requires_fapi2_security(&self, client: &nazo_auth::ClientSecurityPolicy) -> bool {
        self.profile.requires_fapi2_security() || client.requires_fapi2_security()
    }

    pub(crate) fn requires_signed_authorization_request(
        &self,
        client: &nazo_auth::ClientSecurityPolicy,
    ) -> bool {
        self.profile.requires_signed_authorization_request()
            || client.require_signed_authorization_request
    }

    pub(crate) fn requires_signed_authorization_response(
        &self,
        client: &nazo_auth::ClientSecurityPolicy,
    ) -> bool {
        self.profile.requires_signed_authorization_response()
            || client.require_signed_authorization_response
    }
}
