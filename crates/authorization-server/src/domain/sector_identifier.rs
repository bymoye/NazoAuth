use std::net::IpAddr;

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
        IpAddr::V4(v4) => {
            if v4.is_loopback() || v4.is_link_local() || v4.is_unspecified() {
                return true;
            }
            let octets = v4.octets();
            if octets[0] == 10 {
                return true;
            }
            if octets[0] == 172 && (16..=31).contains(&octets[1]) {
                return true;
            }
            if octets[0] == 192 && octets[1] == 168 {
                return true;
            }
            if octets[0] == 169 && octets[1] == 254 {
                return true;
            }
            if octets == [169, 254, 169, 254] {
                return true;
            }
            false
        }
        IpAddr::V6(v6) => {
            let segments = v6.segments();
            if v6.is_loopback()
                || segments[0] & 0xffc0 == 0xfe80  // link-local (fe80::/10)
                || v6.is_unspecified()
                || v6.is_multicast()
            {
                return true;
            }
            if segments[0] & 0xfe00 == 0xfc00 {
                return true;
            }
            if segments[0..4] == [0, 0, 0, 0]
                && segments[4] == 0
                && segments[5] == 0
                && segments[6] == 0
                && segments[7] == 0
            {
                return true;
            }
            if segments[0..5] == [0, 0, 0, 0, 0]
                && segments[5] == 0xffff
                && segments[6] == 0
                && segments[7] == 0
            {
                return true;
            }
            false
        }
    }
}

#[cfg(test)]
pub(crate) fn sector_identifier_hostname(uri: &str) -> Result<String, SectorIdentifierError> {
    let parsed = url::Url::parse(uri).map_err(|_| SectorIdentifierError::InvalidUri)?;
    parsed
        .host_str()
        .map(ToOwned::to_owned)
        .ok_or(SectorIdentifierError::InvalidUri)
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
    let dns_resolved = tokio::net::lookup_host((host, 443))
        .await
        .map_err(|_| SectorIdentifierError::DnsResolutionFailed)?;
    for addr in dns_resolved {
        if is_blocked_ip(addr.ip()) {
            return Err(SectorIdentifierError::BlockedHost);
        }
    }
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .connect_timeout(std::time::Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
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
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .to_owned();
    let body = response
        .bytes()
        .await
        .map_err(|_| SectorIdentifierError::HttpError)?;
    parse_sector_identifier_document(&content_type, &body)
}

#[cfg(test)]
#[path = "../../tests/in_source/src/support/tests/sector_identifier.rs"]
mod tests;
