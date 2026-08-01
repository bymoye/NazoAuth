use std::net::{IpAddr, SocketAddr};

use futures_util::StreamExt;

const MAX_RESPONSE_BYTES: u64 = 128 * 1024;

#[derive(Debug)]
pub(crate) enum SectorIdentifierError {
    InvalidUri,
    SchemeNotHttps,
    BlockedHost,
    DnsResolutionFailed,
    HttpError,
    Timeout,
    InvalidContentType,
    ResponseTooLarge,
    InvalidJson,
    #[allow(dead_code)]
    InvalidEntry(String),
}

pub(crate) fn is_blocked_host(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost")
        || host.eq_ignore_ascii_case("127.0.0.1")
        || host == "0.0.0.0"
        || host == "::1"
        || host == "::"
    {
        return true;
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        return is_blocked_ip(ip);
    }
    false
}

pub(crate) fn is_blocked_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => !is_globally_reachable_ipv4(v4),
        IpAddr::V6(v6) => {
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return is_blocked_ip(IpAddr::V4(mapped));
            }
            !is_globally_reachable_ipv6(v6)
        }
    }
}

fn ipv4_in_prefix(address: std::net::Ipv4Addr, network: [u8; 4], prefix_length: u32) -> bool {
    let mask = u32::MAX << (32 - prefix_length);
    u32::from(address) & mask == u32::from_be_bytes(network) & mask
}

fn is_globally_reachable_ipv4(address: std::net::Ipv4Addr) -> bool {
    // Mirror the IANA IPv4 Special-Purpose Address Registry's globally-reachable
    // column. The two anycast assignments are more specific exceptions to /24.
    if matches!(address.octets(), [192, 0, 0, 9] | [192, 0, 0, 10]) {
        return true;
    }
    ![
        ([0, 0, 0, 0], 8),
        ([10, 0, 0, 0], 8),
        ([100, 64, 0, 0], 10),
        ([127, 0, 0, 0], 8),
        ([169, 254, 0, 0], 16),
        ([172, 16, 0, 0], 12),
        ([192, 0, 0, 0], 24),
        ([192, 0, 2, 0], 24),
        ([192, 88, 99, 0], 24),
        ([192, 168, 0, 0], 16),
        ([198, 18, 0, 0], 15),
        ([198, 51, 100, 0], 24),
        ([203, 0, 113, 0], 24),
        ([224, 0, 0, 0], 4),
        ([240, 0, 0, 0], 4),
    ]
    .into_iter()
    .any(|(network, prefix_length)| ipv4_in_prefix(address, network, prefix_length))
}

fn ipv6_in_prefix(address: std::net::Ipv6Addr, network: u128, prefix_length: u32) -> bool {
    let mask = u128::MAX << (128 - prefix_length);
    u128::from(address) & mask == network & mask
}

fn is_globally_reachable_ipv6(address: std::net::Ipv6Addr) -> bool {
    // Mirror the IANA IPv6 Special-Purpose Address Registry. Only the listed
    // exceptions inside 2001::/23 and the well-known translation prefix remain
    // reachable in addition to ordinary global unicast space.
    let value = u128::from(address);
    let ietf_exception =
        matches!(
            address.segments(),
            [0x2001, 0x0001, 0, 0, 0, 0, 0, 1]
                | [0x2001, 0x0001, 0, 0, 0, 0, 0, 2]
                | [0x2001, 0x0001, 0, 0, 0, 0, 0, 3]
        ) || ipv6_in_prefix(address, 0x2001_0003_0000_0000_0000_0000_0000_0000, 32)
            || ipv6_in_prefix(address, 0x2001_0004_0112_0000_0000_0000_0000_0000, 48)
            || ipv6_in_prefix(address, 0x2001_0020_0000_0000_0000_0000_0000_0000, 28)
            || ipv6_in_prefix(address, 0x2001_0030_0000_0000_0000_0000_0000_0000, 28);
    if ietf_exception {
        return true;
    }
    if ipv6_in_prefix(address, 0x0064_ff9b_0000_0000_0000_0000_0000_0000, 96) {
        return true;
    }
    let is_global_unicast = ipv6_in_prefix(address, 0x2000_0000_0000_0000_0000_0000_0000_0000, 3);
    is_global_unicast
        && value != 0
        && ![
            (0x0064_ff9b_0001_0000_0000_0000_0000_0000, 48),
            (0x0100_0000_0000_0000_0000_0000_0000_0000, 64),
            (0x0100_0000_0000_0001_0000_0000_0000_0000, 64),
            (0x2001_0000_0000_0000_0000_0000_0000_0000, 23),
            (0x2001_0db8_0000_0000_0000_0000_0000_0000, 32),
            (0x2002_0000_0000_0000_0000_0000_0000_0000, 16),
            (0x3fff_0000_0000_0000_0000_0000_0000_0000, 20),
            (0x5f00_0000_0000_0000_0000_0000_0000_0000, 16),
            (0xfc00_0000_0000_0000_0000_0000_0000_0000, 7),
            (0xfe80_0000_0000_0000_0000_0000_0000_0000, 10),
            (0xff00_0000_0000_0000_0000_0000_0000_0000, 8),
        ]
        .into_iter()
        .any(|(network, prefix_length)| ipv6_in_prefix(address, network, prefix_length))
}

fn append_response_chunk(body: &mut Vec<u8>, chunk: &[u8]) -> Result<(), SectorIdentifierError> {
    if body.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES as usize {
        return Err(SectorIdentifierError::ResponseTooLarge);
    }
    body.extend_from_slice(chunk);
    Ok(())
}

pub(crate) fn parse_sector_identifier_document(
    content_type: &str,
    body: &[u8],
) -> Result<Vec<String>, SectorIdentifierError> {
    if !content_type.contains("application/json") {
        return Err(SectorIdentifierError::InvalidContentType);
    }
    if body.len() as u64 > MAX_RESPONSE_BYTES {
        return Err(SectorIdentifierError::ResponseTooLarge);
    }
    let uris: Vec<String> =
        serde_json::from_slice(body).map_err(|_| SectorIdentifierError::InvalidJson)?;
    for entry in &uris {
        if url::Url::parse(entry).is_err() {
            return Err(SectorIdentifierError::InvalidEntry(entry.clone()));
        }
    }
    Ok(uris)
}

pub(crate) async fn fetch_sector_identifier_uris(
    uri: &str,
) -> Result<Vec<String>, SectorIdentifierError> {
    let parsed = url::Url::parse(uri).map_err(|_| SectorIdentifierError::InvalidUri)?;
    if parsed.scheme() != "https" {
        return Err(SectorIdentifierError::SchemeNotHttps);
    }
    let host = parsed.host_str().ok_or(SectorIdentifierError::InvalidUri)?;
    if is_blocked_host(host) {
        return Err(SectorIdentifierError::BlockedHost);
    }
    if host.eq_ignore_ascii_case("invalid") || host.to_ascii_lowercase().ends_with(".invalid") {
        return Err(SectorIdentifierError::DnsResolutionFailed);
    }
    let port = parsed
        .port_or_known_default()
        .ok_or(SectorIdentifierError::InvalidUri)?;
    let addresses = tokio::net::lookup_host((host, port))
        .await
        .map_err(|_| SectorIdentifierError::DnsResolutionFailed)?
        .collect::<Vec<SocketAddr>>();
    if addresses.is_empty() {
        return Err(SectorIdentifierError::DnsResolutionFailed);
    }
    if addresses.iter().any(|addr| is_blocked_ip(addr.ip())) {
        return Err(SectorIdentifierError::BlockedHost);
    }
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(std::time::Duration::from_secs(10))
        .connect_timeout(std::time::Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .resolve_to_addrs(host, &addresses)
        .build()
        .map_err(|_| SectorIdentifierError::HttpError)?;
    let response = client
        .get(uri)
        .send()
        .await
        .map_err(|error| {
            if error.is_timeout() {
                SectorIdentifierError::Timeout
            } else {
                SectorIdentifierError::HttpError
            }
        })?
        .error_for_status()
        .map_err(|_| SectorIdentifierError::HttpError)?;
    if response
        .content_length()
        .is_some_and(|length| length > MAX_RESPONSE_BYTES)
    {
        return Err(SectorIdentifierError::ResponseTooLarge);
    }
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .to_owned();
    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| SectorIdentifierError::HttpError)?;
        append_response_chunk(&mut body, &chunk)?;
    }
    parse_sector_identifier_document(&content_type, &body)
}

#[cfg(test)]
#[path = "../../tests/unit/domain/sector_identifier.rs"]
mod tests;
