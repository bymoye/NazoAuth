use std::{
    error::Error,
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use actix_web::HttpRequest;

#[derive(Clone)]
pub struct ClientIpConfig {
    trusted_proxy_cidrs: Box<[IpCidr]>,
    header_mode: ClientIpHeaderMode,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientIpHeaderMode {
    None,
    Forwarded,
    XForwardedFor,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IpCidr {
    addr: IpAddr,
    prefix: u8,
}

impl ClientIpConfig {
    #[must_use]
    pub fn new(trusted_proxy_cidrs: &[IpCidr], header_mode: ClientIpHeaderMode) -> Self {
        Self {
            trusted_proxy_cidrs: trusted_proxy_cidrs.into(),
            header_mode,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientIpParseError(pub(super) String);

impl fmt::Display for ClientIpParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Error for ClientIpParseError {}

impl ClientIpHeaderMode {
    pub fn parse(value: &str) -> Result<Self, ClientIpParseError> {
        match value.trim().to_ascii_lowercase().as_str() {
            "none" => Ok(Self::None),
            "forwarded" => Ok(Self::Forwarded),
            "x-forwarded-for" => Ok(Self::XForwardedFor),
            value => Err(ClientIpParseError(format!(
                "CLIENT_IP_HEADER_MODE must be none, forwarded, or x-forwarded-for, got {value}"
            ))),
        }
    }
}

impl IpCidr {
    pub fn parse(value: &str) -> Result<Self, ClientIpParseError> {
        let (addr, prefix) = value.trim().split_once('/').ok_or_else(|| {
            ClientIpParseError("trusted proxy CIDR must include prefix length".to_owned())
        })?;
        let addr = addr
            .parse::<IpAddr>()
            .map_err(|_| ClientIpParseError("trusted proxy CIDR address is invalid".to_owned()))?;
        let prefix = prefix
            .parse::<u8>()
            .map_err(|_| ClientIpParseError("trusted proxy CIDR prefix is invalid".to_owned()))?;
        let max_prefix = match addr {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if prefix > max_prefix {
            return Err(ClientIpParseError(
                "trusted proxy CIDR prefix is out of range".to_owned(),
            ));
        }
        Ok(Self { addr, prefix })
    }

    #[must_use]
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(network), IpAddr::V4(ip)) => {
                ipv4_prefix_value(network, self.prefix) == ipv4_prefix_value(ip, self.prefix)
            }
            (IpAddr::V6(network), IpAddr::V6(ip)) => {
                ipv6_prefix_value(network, self.prefix) == ipv6_prefix_value(ip, self.prefix)
            }
            _ => false,
        }
    }
}

pub fn parse_trusted_proxy_cidrs(raw: Option<String>) -> Result<Vec<IpCidr>, ClientIpParseError> {
    raw.unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(IpCidr::parse)
        .collect()
}

#[must_use]
pub fn client_ip_with_config(request: &HttpRequest, config: &ClientIpConfig) -> String {
    client_ip_with_context(request, config.header_mode, &config.trusted_proxy_cidrs)
}

#[must_use]
pub fn client_ip_with_context(
    request: &HttpRequest,
    header_mode: ClientIpHeaderMode,
    trusted_proxy_cidrs: &[IpCidr],
) -> String {
    let Some(peer_ip) = request.peer_addr().map(|address| address.ip()) else {
        return "unknown".to_owned();
    };
    if header_mode == ClientIpHeaderMode::None
        || !trusted_proxy_peer_ip(peer_ip, trusted_proxy_cidrs)
    {
        return peer_ip.to_string();
    }
    let parsed = match header_mode {
        ClientIpHeaderMode::None => None,
        ClientIpHeaderMode::Forwarded => forwarded_ip_chain(request)
            .and_then(|chain| nearest_untrusted_hop(chain, peer_ip, trusted_proxy_cidrs)),
        ClientIpHeaderMode::XForwardedFor => x_forwarded_for_ip_chain(request)
            .and_then(|chain| nearest_untrusted_hop(chain, peer_ip, trusted_proxy_cidrs)),
    };
    parsed.unwrap_or(peer_ip).to_string()
}

#[must_use]
pub fn request_from_trusted_proxy_cidrs(
    request: &HttpRequest,
    trusted_proxy_cidrs: &[IpCidr],
) -> bool {
    request
        .peer_addr()
        .is_some_and(|address| trusted_proxy_peer_ip(address.ip(), trusted_proxy_cidrs))
}

fn trusted_proxy_peer_ip(peer_ip: IpAddr, trusted_proxy_cidrs: &[IpCidr]) -> bool {
    trusted_proxy_cidrs
        .iter()
        .any(|cidr| cidr.contains(peer_ip))
}

fn forwarded_ip_chain(request: &HttpRequest) -> Option<Vec<IpAddr>> {
    let mut values = request.headers().get_all("forwarded");
    let raw = values.next()?.to_str().ok()?;
    if values.next().is_some() {
        return None;
    }
    let mut chain = Vec::new();
    for element in raw.split(',') {
        if element.trim().is_empty() {
            return None;
        }
        let mut forwarded_for = None;
        for parameter in element.split(';') {
            let (name, value) = parameter.trim().split_once('=')?;
            if name.trim().eq_ignore_ascii_case("for") {
                if forwarded_for.is_some() {
                    return None;
                }
                forwarded_for = Some(parse_forwarded_for_value(value.trim())?);
            }
        }
        chain.push(forwarded_for?);
    }
    (!chain.is_empty()).then_some(chain)
}

#[must_use]
pub fn parse_forwarded_for_value(value: &str) -> Option<IpAddr> {
    let value = match (value.strip_prefix('"'), value.strip_suffix('"')) {
        (Some(without_prefix), Some(_)) => without_prefix.strip_suffix('"')?,
        (None, None) => value,
        _ => return None,
    };
    if let Some(ip) = value
        .strip_prefix('[')
        .and_then(|rest| rest.split_once(']').map(|(ip, _)| ip))
    {
        return ip.parse().ok();
    }
    let host = value.rsplit_once(':').and_then(|(host, port)| {
        port.parse::<u16>().ok()?;
        Some(host)
    });
    host.unwrap_or(value).parse().ok()
}

fn x_forwarded_for_ip_chain(request: &HttpRequest) -> Option<Vec<IpAddr>> {
    let mut values = request.headers().get_all("x-forwarded-for");
    let raw = values.next()?.to_str().ok()?;
    if values.next().is_some() {
        return None;
    }
    let chain = raw
        .split(',')
        .map(str::trim)
        .map(str::parse::<IpAddr>)
        .collect::<Result<Vec<_>, _>>()
        .ok()?;
    (!chain.is_empty()).then_some(chain)
}

fn nearest_untrusted_hop(
    chain: Vec<IpAddr>,
    peer_ip: IpAddr,
    trusted_proxy_cidrs: &[IpCidr],
) -> Option<IpAddr> {
    chain
        .into_iter()
        .chain(std::iter::once(peer_ip))
        .rev()
        .find(|ip| !trusted_proxy_peer_ip(*ip, trusted_proxy_cidrs))
}

fn ipv4_prefix_value(ip: Ipv4Addr, prefix: u8) -> u32 {
    if prefix == 0 {
        return 0;
    }
    u32::from(ip) >> (32 - prefix)
}

fn ipv6_prefix_value(ip: Ipv6Addr, prefix: u8) -> u128 {
    if prefix == 0 {
        return 0;
    }
    u128::from(ip) >> (128 - prefix)
}
