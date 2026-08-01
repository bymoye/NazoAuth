use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OidcSessionStatus {
    Unchanged,
    Changed,
    Error,
}

/// Computes the OP session-state value defined by OpenID Connect Session Management.
#[must_use]
pub fn oidc_session_state(
    client_id: &str,
    client_origin: &str,
    op_browser_state: &str,
    salt: &str,
) -> String {
    let input = format!("{client_id} {client_origin} {op_browser_state} {salt}");
    let digest = Sha256::digest(input.as_bytes());
    format!("{}.{}", URL_SAFE_NO_PAD.encode(digest), salt)
}

/// Issues session state only for redirect URIs with a browser origin.
///
/// `Url::origin` supplies RFC origin serialization, including IPv6 brackets and
/// default-port normalization, so it matches the origin emitted by browsers.
#[must_use]
pub fn issue_oidc_session_state(
    client_id: &str,
    redirect_uri: &str,
    op_browser_state: &str,
) -> Option<String> {
    let origin = oidc_redirect_uri_origin(redirect_uri)?;
    let salt = URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>());
    Some(oidc_session_state(
        client_id,
        &origin,
        op_browser_state,
        &salt,
    ))
}

/// Returns the browser-origin serialization for an HTTP(S) redirect URI.
#[must_use]
pub fn oidc_redirect_uri_origin(redirect_uri: &str) -> Option<String> {
    let url = url::Url::parse(redirect_uri).ok()?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return None;
    }
    Some(url.origin().ascii_serialization())
}

/// Compares an RP-provided session state without exposing digest timing.
#[must_use]
pub fn check_oidc_session_state(
    client_id: &str,
    client_origin: &str,
    provided_session_state: &str,
    op_browser_state: Option<&str>,
) -> OidcSessionStatus {
    let Some((_, salt)) = provided_session_state.rsplit_once('.') else {
        return OidcSessionStatus::Error;
    };
    let Some(op_browser_state) = op_browser_state else {
        return OidcSessionStatus::Changed;
    };
    let expected = oidc_session_state(client_id, client_origin, op_browser_state, salt);
    if expected
        .as_bytes()
        .ct_eq(provided_session_state.as_bytes())
        .into()
    {
        OidcSessionStatus::Unchanged
    } else {
        OidcSessionStatus::Changed
    }
}

#[cfg(test)]
#[path = "../tests/unit/session_management.rs"]
mod tests;
