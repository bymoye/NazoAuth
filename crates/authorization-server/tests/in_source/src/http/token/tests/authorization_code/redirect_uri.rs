use super::*;

#[test]
fn token_redirect_uri_is_required_when_authorize_request_supplied_it() {
    let payload = code_payload(true);

    assert!(!redirect_uri_matches_authorization_request(&payload, None));
    assert!(redirect_uri_matches_authorization_request(
        &payload,
        Some("https://client.example/callback")
    ));
    assert!(!redirect_uri_matches_authorization_request(
        &payload,
        Some("https://client.example/callback/")
    ));
}

#[test]
fn token_redirect_uri_may_be_omitted_when_authorize_request_used_single_registered_uri() {
    let payload = code_payload(false);

    assert!(redirect_uri_matches_authorization_request(&payload, None));
    assert!(redirect_uri_matches_authorization_request(
        &payload,
        Some("https://client.example/callback")
    ));
    assert!(!redirect_uri_matches_authorization_request(
        &payload,
        Some("https://client.example/callback/")
    ));
}

#[test]
fn token_redirect_uri_is_still_bound_when_authorization_request_omitted_it() {
    let payload = code_payload(false);

    for attacker_redirect_uri in [
        "https://client.example/other-callback",
        "https://evil.example/callback",
        "http://client.example/callback",
        "https://client.example/callback?next=https://evil.example",
    ] {
        assert!(
            !redirect_uri_matches_authorization_request(&payload, Some(attacker_redirect_uri)),
            "authorization code exchange must not accept a different redirect_uri: {attacker_redirect_uri}"
        );
    }
}
