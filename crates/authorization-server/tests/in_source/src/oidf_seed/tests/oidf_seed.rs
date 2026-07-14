use super::*;

#[test]
fn suite_base_urls_are_trimmed_deduplicated_and_sorted() {
    let urls = suite_base_urls_from_extra(
        "https://suite.example/",
        Some(" https://suite.example, https://local.example/ ,, https://z.example/path/ "),
    );

    assert_eq!(
        urls,
        vec![
            "https://local.example".to_owned(),
            "https://suite.example".to_owned(),
            "https://www.certification.openid.net".to_owned(),
            "https://z.example/path".to_owned(),
        ],
        "OIDF callback base URLs must be deterministic and must not duplicate redirect URIs"
    );
}

#[test]
fn callback_uri_never_preserves_trailing_slash_before_oidf_path() {
    assert_eq!(
        callback_uri("https://suite.example/", "alias-1"),
        "https://suite.example/test/a/alias-1/callback"
    );
}

#[test]
fn test_endpoint_uri_uses_same_alias_scope_as_callback() {
    assert_eq!(
        test_endpoint_uri("https://suite.example/", "alias-1", "frontchannel_logout"),
        "https://suite.example/test/a/alias-1/frontchannel_logout"
    );
    assert_eq!(
        test_endpoint_uri("https://suite.example", "alias-1", "post_logout_redirect"),
        "https://suite.example/test/a/alias-1/post_logout_redirect"
    );
}

#[test]
fn seed_client_secret_pepper_comes_from_loaded_config() {
    let config = crate::config::ConfigSource::from_pairs_for_test([(
        "CLIENT_SECRET_PEPPER",
        "production-client-secret-pepper",
    )]);

    assert_eq!(
        seed_client_secret_pepper(&config),
        "production-client-secret-pepper",
        "the OIDF seed must hash client secrets with the same loaded configuration as the server"
    );
}
