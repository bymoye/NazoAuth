//! Local OpenID Foundation conformance seed helpers.
//!
//! The binary performs database writes; this module owns deterministic parsing
//! and URL/JWKS normalization logic that can be tested without external state.

use crate::config::ConfigSource;
use std::{collections::BTreeSet, env};

const LOCAL_DEVELOPMENT_CLIENT_SECRET_PEPPER: &str =
    "local-development-client-secret-pepper-00000001";

pub mod config;

pub fn callback_uri(suite_base_url: &str, alias: &str) -> String {
    test_endpoint_uri(suite_base_url, alias, "callback")
}

pub fn test_endpoint_uri(suite_base_url: &str, alias: &str, endpoint: &str) -> String {
    format!(
        "{}/test/a/{}/{}",
        suite_base_url.trim_end_matches('/'),
        alias,
        endpoint.trim_start_matches('/')
    )
}

pub fn suite_base_urls(primary_suite_base_url: &str) -> Vec<String> {
    suite_base_urls_from_extra(
        primary_suite_base_url,
        env::var("OIDF_LOCAL_EXTRA_SUITE_BASE_URLS").ok().as_deref(),
    )
}

pub fn seed_client_secret_pepper(config: &ConfigSource) -> String {
    config.string(
        "CLIENT_SECRET_PEPPER",
        LOCAL_DEVELOPMENT_CLIENT_SECRET_PEPPER,
    )
}

fn suite_base_urls_from_extra(
    primary_suite_base_url: &str,
    extra_urls: Option<&str>,
) -> Vec<String> {
    let mut urls = BTreeSet::new();
    urls.insert(primary_suite_base_url.trim_end_matches('/').to_owned());
    urls.insert("https://www.certification.openid.net".to_owned());

    if let Some(extra_urls) = extra_urls {
        for url in extra_urls.split(',') {
            let url = url.trim().trim_end_matches('/');
            if !url.is_empty() {
                urls.insert(url.to_owned());
            }
        }
    }

    urls.into_iter().collect()
}

pub fn callback_uris(suite_base_urls: &[String], alias: &str) -> Vec<String> {
    test_endpoint_uris(suite_base_urls, alias, "callback")
}

pub fn test_endpoint_uris(suite_base_urls: &[String], alias: &str, endpoint: &str) -> Vec<String> {
    suite_base_urls
        .iter()
        .map(|suite_base_url| test_endpoint_uri(suite_base_url, alias, endpoint))
        .collect()
}

#[cfg(test)]
#[path = "../../tests/in_source/src/oidf_seed/tests/oidf_seed.rs"]
mod tests;
