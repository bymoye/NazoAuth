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
    let url = url::Url::parse(redirect_uri).ok()?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return None;
    }
    let origin = url.origin().ascii_serialization();
    let salt = URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>());
    Some(oidc_session_state(
        client_id,
        &origin,
        op_browser_state,
        &salt,
    ))
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
mod tests {
    use super::*;

    #[test]
    fn state_is_bound_to_client_origin_browser_state_and_salt() {
        let salt = URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>());
        let state = oidc_session_state("client-1", "https://client.example", "opbs-1", &salt);
        assert_eq!(
            check_oidc_session_state("client-1", "https://client.example", &state, Some("opbs-1")),
            OidcSessionStatus::Unchanged
        );
        assert_eq!(
            check_oidc_session_state("client-2", "https://client.example", &state, Some("opbs-1")),
            OidcSessionStatus::Changed
        );
        assert_eq!(
            check_oidc_session_state("client-1", "https://other.example", &state, Some("opbs-1")),
            OidcSessionStatus::Changed
        );
        assert_eq!(
            check_oidc_session_state("client-1", "https://client.example", "malformed", None),
            OidcSessionStatus::Error
        );
    }

    #[test]
    fn issuer_uses_browser_origin_serialization() {
        let ipv6 =
            issue_oidc_session_state("client-1", "https://[2001:db8::1]:8443/callback", "opbs-1")
                .unwrap();
        let (_, salt) = ipv6.rsplit_once('.').unwrap();
        assert_eq!(
            ipv6,
            oidc_session_state("client-1", "https://[2001:db8::1]:8443", "opbs-1", salt)
        );

        let default_port =
            issue_oidc_session_state("client-1", "https://client.example:443/cb", "opbs-1")
                .unwrap();
        let (_, salt) = default_port.rsplit_once('.').unwrap();
        assert_eq!(
            default_port,
            oidc_session_state("client-1", "https://client.example", "opbs-1", salt)
        );
        assert!(issue_oidc_session_state("client-1", "native://callback", "opbs-1").is_none());
        assert!(issue_oidc_session_state("client-1", "not-a-uri", "opbs-1").is_none());
    }
}
