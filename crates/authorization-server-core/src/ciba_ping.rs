use url::Url;

/// Maximum UTF-8 byte length accepted for CIBA and logout callback URIs.
///
/// Callback endpoints are persisted and used by background workers.  Keeping a
/// single bound across registration and delivery prevents an oversized URI
/// from turning into unbounded state/log/request work later in the lifecycle.
pub const MAX_CIBA_LOGOUT_URI_BYTES: usize = 2_048;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CibaPingResponseAction {
    Delivered,
    TerminalFailure,
    Retry,
}

pub fn validate_ciba_notification_endpoint(value: &str) -> Result<Url, &'static str> {
    if value.len() > MAX_CIBA_LOGOUT_URI_BYTES {
        return Err("CIBA ping endpoint exceeds the maximum URI length");
    }
    let parsed = Url::parse(value).map_err(|_| "CIBA ping endpoint is not a valid URI")?;
    if parsed.scheme() != "https"
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.fragment().is_some()
    {
        return Err(
            "CIBA ping endpoint must be an absolute HTTPS URI without userinfo or fragment",
        );
    }
    Ok(parsed)
}

pub const fn classify_ciba_ping_status(status: u16) -> CibaPingResponseAction {
    match status {
        200..=299 => CibaPingResponseAction::Delivered,
        300..=499 => CibaPingResponseAction::TerminalFailure,
        _ => CibaPingResponseAction::Retry,
    }
}

pub const fn next_ciba_ping_retry_at(attempts: u32, now: i64, expires_at: i64) -> Option<i64> {
    let delay = match attempts {
        1 => 1,
        2 => 3,
        3 => 9,
        _ => return None,
    };
    let next = now.saturating_add(delay);
    if next < expires_at { Some(next) } else { None }
}
