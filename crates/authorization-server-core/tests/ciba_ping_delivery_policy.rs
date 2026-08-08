use nazo_auth::{
    CibaPingResponseAction, MAX_CIBA_LOGOUT_URI_BYTES, classify_ciba_ping_status,
    next_ciba_ping_retry_at, validate_ciba_notification_endpoint,
};

#[test]
fn ciba_ping_endpoint_requires_an_https_origin_without_ambiguous_authority() {
    assert!(validate_ciba_notification_endpoint("https://client.example/ciba").is_ok());
    for invalid in [
        "http://client.example/ciba",
        "https://user@client.example/ciba",
        "https://client.example/ciba#fragment",
        "/relative/ciba",
    ] {
        assert!(
            validate_ciba_notification_endpoint(invalid).is_err(),
            "{invalid}"
        );
    }
}

#[test]
fn ciba_ping_endpoint_length_is_bounded_consistently() {
    let prefix = "https://client.example/";
    let at_limit = format!(
        "{prefix}{}",
        "x".repeat(MAX_CIBA_LOGOUT_URI_BYTES - prefix.len())
    );
    assert!(validate_ciba_notification_endpoint(&at_limit).is_ok());

    let over_limit = format!("{at_limit}x");
    assert!(validate_ciba_notification_endpoint(&over_limit).is_err());
}

#[test]
fn redirects_and_client_errors_are_terminal_but_server_errors_are_retryable() {
    assert_eq!(
        classify_ciba_ping_status(204),
        CibaPingResponseAction::Delivered
    );
    assert_eq!(
        classify_ciba_ping_status(302),
        CibaPingResponseAction::TerminalFailure
    );
    assert_eq!(
        classify_ciba_ping_status(401),
        CibaPingResponseAction::TerminalFailure
    );
    assert_eq!(
        classify_ciba_ping_status(503),
        CibaPingResponseAction::Retry
    );
}

#[test]
fn ciba_ping_retries_are_bounded_and_never_cross_authorization_expiry() {
    assert_eq!(next_ciba_ping_retry_at(1, 100, 200), Some(101));
    assert_eq!(next_ciba_ping_retry_at(2, 100, 200), Some(103));
    assert_eq!(next_ciba_ping_retry_at(3, 100, 200), Some(109));
    assert_eq!(next_ciba_ping_retry_at(4, 100, 200), None);
    assert_eq!(next_ciba_ping_retry_at(3, 100, 109), None);
}
