use nazo_auth::{
    RedirectUriError, is_loopback_http_url, is_valid_pkce_value, oauth_redirect_uri_matches,
    resolve_registered_redirect_uri, validate_cors_origin, validate_frontend_base_url,
    validate_issuer_url, validate_oauth_redirect_uri,
};
use proptest::prelude::*;

fn valid_dns_host() -> impl Strategy<Value = String> {
    "[a-z][a-z0-9]{0,16}\\.(example|test|invalid)"
}

#[test]
fn issuer_requires_https_except_loopback_http() {
    assert!(validate_issuer_url("https://auth.example").is_ok());
    assert!(validate_issuer_url("http://127.0.0.1:8000").is_ok());
    assert!(validate_issuer_url("https://").is_err());
    assert!(validate_issuer_url("file:///tmp/issuer").is_err());
    assert!(validate_issuer_url("http://auth.example").is_err());
    assert!(validate_issuer_url("https://auth.example/").is_err());
    assert!(validate_issuer_url("https://auth.example/oauth/").is_err());
    assert!(validate_issuer_url("https://auth.example?x=1").is_err());
    assert!(validate_issuer_url("https://user:pass@auth.example").is_err());
    assert!(validate_frontend_base_url("file:///tmp/app").is_err());
    assert!(validate_frontend_base_url("https://frontend.example/app?x=1").is_err());
    assert!(validate_cors_origin("file:///tmp/app").is_err());
    assert!(validate_cors_origin("https://user@frontend.example").is_err());
    assert!(validate_cors_origin("https://frontend.example/app").is_err());
    assert!(validate_cors_origin("https://").is_err());
}

#[test]
fn redirect_uri_policy_allows_only_oauth_bcp_exceptions() {
    assert!(validate_oauth_redirect_uri("confidential", "https://client.example/cb").is_ok());
    assert!(validate_oauth_redirect_uri("public", "http://127.0.0.1:49152/cb").is_ok());
    assert!(validate_oauth_redirect_uri("public", "http://[::1]:49152/cb").is_ok());
    assert!(validate_oauth_redirect_uri("public", "com.example.app:/oauth2redirect").is_ok());
    assert!(validate_oauth_redirect_uri("confidential", "http://127.0.0.1:49152/cb").is_err());
    assert!(validate_oauth_redirect_uri("public", "http://client.example/cb").is_err());
    assert!(validate_oauth_redirect_uri("public", "https://client.example/cb#frag").is_err());
    assert!(validate_oauth_redirect_uri("public", "https://user@client.example/cb").is_err());
    assert!(validate_oauth_redirect_uri("public", " https://client.example/cb ").is_err());
    assert!(
        validate_oauth_redirect_uri("confidential", "com.example.app:/oauth2redirect").is_err()
    );
}

#[test]
fn loopback_redirect_matching_ignores_only_port() {
    assert!(oauth_redirect_uri_matches(
        "public",
        "http://127.0.0.1:3000/callback?x=1",
        "http://127.0.0.1:49152/callback?x=1"
    ));
    assert!(!oauth_redirect_uri_matches(
        "public",
        "http://127.0.0.1:3000/callback?x=1",
        "http://127.0.0.1:49152/callback?x=2"
    ));
    assert!(!oauth_redirect_uri_matches(
        "public",
        "http://127.0.0.1:3000/callback",
        "http://user@127.0.0.1:49152/callback"
    ));
    assert!(!oauth_redirect_uri_matches(
        "confidential",
        "http://127.0.0.1:3000/callback",
        "http://127.0.0.1:49152/callback"
    ));
    assert!(!oauth_redirect_uri_matches(
        "public",
        "not a uri",
        "also not a uri"
    ));
    assert!(!is_loopback_http_url("http:/callback"));
    assert!(!is_loopback_http_url("http:///callback"));
}

#[test]
fn registered_redirect_resolution_is_framework_independent() {
    let registered = vec!["https://client.example/callback".to_owned()];
    assert_eq!(
        resolve_registered_redirect_uri("public", &registered, None).unwrap(),
        "https://client.example/callback"
    );
    assert_eq!(
        resolve_registered_redirect_uri(
            "public",
            &registered,
            Some("https://client.example/callback/")
        ),
        Err(RedirectUriError::Invalid)
    );
    assert_eq!(
        resolve_registered_redirect_uri(
            "public",
            &["http://127.0.0.1:3000/callback".to_owned()],
            Some("http://127.0.0.1:49152/callback")
        )
        .unwrap(),
        "http://127.0.0.1:49152/callback"
    );
    assert_eq!(
        resolve_registered_redirect_uri("public", &[], None),
        Err(RedirectUriError::Missing)
    );
}

#[test]
fn pkce_values_follow_rfc7636_length_and_charset() {
    assert!(is_valid_pkce_value(
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ"
    ));
    assert!(!is_valid_pkce_value("short"));
    assert!(!is_valid_pkce_value(
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNO!"
    ));
}

proptest! {
    #[test]
    fn https_redirect_uris_without_forbidden_parts_are_allowed(
        host in valid_dns_host(),
        path in "[a-zA-Z0-9/_-]{0,32}"
    ) {
        let uri = format!("https://{host}/{path}");
        prop_assert!(validate_oauth_redirect_uri("confidential", &uri).is_ok());
        prop_assert!(validate_oauth_redirect_uri("public", &uri).is_ok());
    }

    #[test]
    fn non_loopback_http_redirect_uris_are_rejected(
        host in valid_dns_host(),
        path in "[a-zA-Z0-9/_-]{0,32}"
    ) {
        let uri = format!("http://{host}/{path}");
        prop_assert!(validate_oauth_redirect_uri("public", &uri).is_err());
        prop_assert!(validate_oauth_redirect_uri("confidential", &uri).is_err());
    }

    #[test]
    fn redirect_uri_rejects_credentials_fragments_and_wildcards(
        user in "[a-zA-Z0-9_-]{1,16}",
        host in valid_dns_host(),
        path in "[a-zA-Z0-9/_-]{0,32}"
    ) {
        let with_credentials = format!("https://{user}@{host}/{path}");
        let with_fragment = format!("https://{host}/{path}#fragment");
        let with_wildcard = format!("https://*.{host}/{path}");

        prop_assert!(validate_oauth_redirect_uri("confidential", &with_credentials).is_err());
        prop_assert!(validate_oauth_redirect_uri("confidential", &with_fragment).is_err());
        prop_assert!(validate_oauth_redirect_uri("confidential", &with_wildcard).is_err());
    }

    #[test]
    fn loopback_redirect_matching_varies_only_by_port(
        path in "[a-zA-Z0-9/_-]{1,32}",
        query in prop::option::of("[a-zA-Z0-9_=&-]{1,32}"),
        registered_port in 1u16..=65535,
        requested_port in 1u16..=65535
    ) {
        let normalized_path = format!("/{}", path.trim_start_matches('/'));
        let query_suffix = query.as_deref().map(|value| format!("?{value}")).unwrap_or_default();
        let registered = format!("http://127.0.0.1:{registered_port}{normalized_path}{query_suffix}");
        let requested = format!("http://127.0.0.1:{requested_port}{normalized_path}{query_suffix}");
        let requested_with_different_path = format!("http://127.0.0.1:{requested_port}{normalized_path}/changed{query_suffix}");

        prop_assert!(oauth_redirect_uri_matches("public", &registered, &requested));
        if registered_port != requested_port {
            prop_assert!(!oauth_redirect_uri_matches("confidential", &registered, &requested));
        }
        prop_assert!(!oauth_redirect_uri_matches("public", &registered, &requested_with_different_path));
    }

    #[test]
    fn issuer_urls_reject_query_fragment_credentials_and_trailing_slash(
        user in "[a-zA-Z0-9_-]{1,16}",
        host in valid_dns_host(),
        query in "[a-zA-Z0-9_=&-]{1,32}"
    ) {
        let issuer = format!("https://{host}");
        let trailing_slash = format!("https://{host}/");
        let with_query = format!("https://{host}?{query}");
        let with_fragment = format!("https://{host}#fragment");
        let with_credentials = format!("https://{user}@{host}");

        prop_assert!(validate_issuer_url(&issuer).is_ok());
        prop_assert!(validate_issuer_url(&trailing_slash).is_err());
        prop_assert!(validate_issuer_url(&with_query).is_err());
        prop_assert!(validate_issuer_url(&with_fragment).is_err());
        prop_assert!(validate_issuer_url(&with_credentials).is_err());
    }
}
