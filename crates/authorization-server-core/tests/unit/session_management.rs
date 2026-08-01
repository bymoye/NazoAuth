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
        issue_oidc_session_state("client-1", "https://client.example:443/cb", "opbs-1").unwrap();
    let (_, salt) = default_port.rsplit_once('.').unwrap();
    assert_eq!(
        default_port,
        oidc_session_state("client-1", "https://client.example", "opbs-1", salt)
    );
    assert!(issue_oidc_session_state("client-1", "native://callback", "opbs-1").is_none());
    assert!(issue_oidc_session_state("client-1", "not-a-uri", "opbs-1").is_none());
}
