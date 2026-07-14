//! Actix client-IP compatibility exports used while server handlers move to the transport crate.

#[cfg(test)]
use crate::settings::Settings;
#[cfg(test)]
use actix_web::HttpRequest;

#[cfg(test)]
pub(crate) use nazo_http_actix::parse_forwarded_for_value;
pub(crate) use nazo_http_actix::{
    ClientIpConfig, ClientIpHeaderMode, IpCidr, client_ip_with_config, client_ip_with_context,
    parse_trusted_proxy_cidrs, request_from_trusted_proxy_cidrs,
};

#[cfg(test)]
pub(crate) fn client_ip(request: &HttpRequest, settings: &Settings) -> String {
    let endpoint = &settings.endpoint;
    client_ip_with_context(
        request,
        endpoint.client_ip_header_mode,
        &endpoint.trusted_proxy_cidrs,
    )
}

#[cfg(test)]
pub(crate) fn request_from_trusted_proxy(request: &HttpRequest, settings: &Settings) -> bool {
    request_from_trusted_proxy_cidrs(request, &settings.endpoint.trusted_proxy_cidrs)
}

#[cfg(test)]
#[path = "../../tests/in_source/src/support/tests/client_ip.rs"]
mod tests;
