use crate::http::client_ip::{ClientIpHeaderMode, IpCidr};
use crate::settings::Settings;

/// Focused transport/configuration projection for RFC 8628 endpoints.
#[derive(Clone)]
pub(crate) struct DeviceHttpConfig {
    pub(crate) issuer: Box<str>,
    pub(crate) frontend_base_url: Box<str>,
    pub(crate) client_secret_pepper: Box<str>,
    pub(crate) trusted_proxy_cidrs: Box<[IpCidr]>,
    pub(crate) client_ip_header_mode: ClientIpHeaderMode,
    pub(crate) default_audience: Box<str>,
    pub(crate) ttl_seconds: u64,
    pub(crate) poll_interval_seconds: u64,
    pub(crate) pairwise_subject_secret: Option<Box<str>>,
}

impl From<&Settings> for DeviceHttpConfig {
    fn from(settings: &Settings) -> Self {
        Self {
            issuer: settings.endpoint.issuer.as_str().into(),
            frontend_base_url: settings.endpoint.frontend_base_url.as_str().into(),
            client_secret_pepper: settings.protocol.client_secret_pepper.as_str().into(),
            trusted_proxy_cidrs: settings.endpoint.trusted_proxy_cidrs.clone().into(),
            client_ip_header_mode: settings.endpoint.client_ip_header_mode,
            default_audience: settings.protocol.default_audience.as_str().into(),
            ttl_seconds: settings.device.device_authorization_ttl_seconds,
            poll_interval_seconds: settings.device.device_authorization_poll_interval_seconds,
            pairwise_subject_secret: settings
                .protocol
                .pairwise_subject_secret
                .as_deref()
                .map(Into::into),
        }
    }
}
