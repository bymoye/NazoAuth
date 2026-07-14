use super::*;
use crate::test_support::valkey::valkey_del;
use crate::test_support::valkey::valkey_eval_string;
use crate::test_support::valkey::valkey_set_ex;
use nazo_http_actix::OAuthJsonErrorFields;
use std::sync::Arc;

use crate::config::ConfigSource;
use nazo_postgres::create_pool;

use actix_web::test::TestRequest;
use fred::interfaces::ClientLike;
use fred::prelude::{
    Builder as ValkeyBuilder, Config as ValkeyConfig, ConnectionConfig, PerformanceConfig,
};
use std::time::Duration as StdDuration;

async fn live_rate_limit_state() -> Option<TestAppState> {
    let valkey_url = std::env::var("VALKEY_URL").ok()?;
    let mut builder =
        ValkeyBuilder::from_config(ValkeyConfig::from_url(&valkey_url).expect("VALKEY_URL"));
    builder.with_performance_config(|performance: &mut PerformanceConfig| {
        performance.default_command_timeout = StdDuration::from_millis(1000);
    });
    builder.with_connection_config(|connection: &mut ConnectionConfig| {
        connection.connection_timeout = StdDuration::from_millis(1000);
        connection.internal_command_timeout = StdDuration::from_millis(1000);
        connection.max_command_attempts = 1;
    });
    let valkey = builder.build().expect("valkey client should build");
    valkey.init().await.expect("valkey should connect");

    Some(TestAppState {
        diesel_db: create_pool(
            "postgres://nazo_rate_limit_test_invalid:nazo_rate_limit_test_invalid@127.0.0.1:1/nazo"
                .to_owned(),
            1,
        )
        .expect("pool construction should not connect"),
        valkey,
        settings: Arc::new(
            Settings::from_config(&ConfigSource::default()).expect("default settings should load"),
        ),
        keyset: crate::test_support::test_key_manager(),
    })
}

async fn eval_rate_limit_key_ttl(state: &TestAppState, key: &str) -> i64 {
    valkey_eval_string(
        &state.valkey,
        "return tostring(redis.call('TTL', KEYS[1]))",
        vec![key.to_owned()],
        Vec::new(),
    )
    .await
    .expect("rate limit key TTL should be readable")
    .parse()
    .expect("rate limit key TTL should be an integer")
}

async fn set_rate_limit_key_without_ttl(state: &TestAppState, key: &str, value: &str) {
    valkey_eval_string(
        &state.valkey,
        "redis.call('SET', KEYS[1], ARGV[1]); return 'OK'",
        vec![key.to_owned()],
        vec![value.to_owned()],
    )
    .await
    .expect("rate limit key should be staged without TTL");
}

#[test]
fn rate_limit_key_does_not_store_raw_peer_identity() {
    let key = rate_limit_key(RateLimitPolicy::Auth, "203.0.113.9");

    assert!(key.starts_with("oauth:rate:auth:"));
    assert!(!key.contains("203.0.113.9"));
    assert_ne!(key, "oauth:rate:auth:203.0.113.9");
}

#[test]
fn rate_limit_keys_are_isolated_by_policy() {
    let subject = "203.0.113.9";

    let auth = rate_limit_key(RateLimitPolicy::Auth, subject);
    let token = rate_limit_key(RateLimitPolicy::Token, subject);
    let token_management = rate_limit_key(RateLimitPolicy::TokenManagement, subject);

    assert!(auth.starts_with("oauth:rate:auth:"));
    assert!(token.starts_with("oauth:rate:token:"));
    assert!(token_management.starts_with("oauth:rate:token_management:"));
    assert_ne!(auth, token);
    assert_ne!(auth, token_management);
    assert_ne!(token, token_management);
}

#[test]
fn rate_limited_response_is_exact_oauth_retryable_error() {
    let response = rate_limited_response(17);

    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        response.headers().get(header::RETRY_AFTER).unwrap(),
        HeaderValue::from_static("17")
    );
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        HeaderValue::from_static("no-store")
    );
    assert_eq!(
        response.headers().get(header::PRAGMA).unwrap(),
        HeaderValue::from_static("no-cache")
    );
    assert_eq!(
        response
            .extensions()
            .get::<OAuthJsonErrorFields>()
            .map(|fields| fields.error.as_str()),
        Some("temporarily_unavailable")
    );
}

#[actix_web::test]
async fn corrupt_rate_limit_counter_fails_closed_as_server_error() {
    let Some(state) = live_rate_limit_state().await else {
        return;
    };
    let req = TestRequest::default()
        .peer_addr("127.0.0.10:12345".parse().unwrap())
        .to_http_request();
    let key = rate_limit_key(
        RateLimitPolicy::Auth,
        &rate_limit_subject(&req, &state.settings),
    );
    valkey_set_ex(
        &state.valkey,
        key,
        "not-an-integer".to_owned(),
        state.settings.identity.rate_limit.window_seconds,
    )
    .await
    .expect("corrupt rate limit counter should be staged");

    let response = enforce_rate_limit(&state, &req, RateLimitPolicy::Auth)
        .await
        .expect_err("corrupt rate limit counter must fail closed");

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        response
            .extensions()
            .get::<OAuthJsonErrorFields>()
            .map(|fields| fields.error.as_str()),
        Some("server_error")
    );
    assert!(response.headers().get(header::WWW_AUTHENTICATE).is_none());
}

#[actix_web::test]
async fn rate_limit_counter_is_created_with_window_ttl() {
    let Some(state) = live_rate_limit_state().await else {
        return;
    };
    let req = TestRequest::default().to_http_request();
    let key = rate_limit_key(
        RateLimitPolicy::Token,
        &rate_limit_subject(&req, &state.settings),
    );
    valkey_del(&state.valkey, key.clone())
        .await
        .expect("rate limit key cleanup should succeed");

    enforce_rate_limit(&state, &req, RateLimitPolicy::Token)
        .await
        .expect("first request in a fresh window should pass");

    let ttl = eval_rate_limit_key_ttl(&state, &key).await;
    assert!(
        ttl > 0 && ttl <= state.settings.identity.rate_limit.window_seconds as i64,
        "rate limit counter must have a bounded TTL, got {ttl}"
    );
}

#[actix_web::test]
async fn rate_limit_counter_without_ttl_is_repaired() {
    let Some(state) = live_rate_limit_state().await else {
        return;
    };
    let req = TestRequest::default()
        .peer_addr("127.0.0.11:12345".parse().unwrap())
        .to_http_request();
    let key = rate_limit_key(
        RateLimitPolicy::Token,
        &rate_limit_subject(&req, &state.settings),
    );
    valkey_del(&state.valkey, key.clone())
        .await
        .expect("rate limit key cleanup should succeed");
    set_rate_limit_key_without_ttl(&state, &key, "0").await;
    assert_eq!(eval_rate_limit_key_ttl(&state, &key).await, -1);

    enforce_rate_limit(&state, &req, RateLimitPolicy::Token)
        .await
        .expect("valid legacy counter should be incremented");

    let ttl = eval_rate_limit_key_ttl(&state, &key).await;
    assert!(
        ttl > 0 && ttl <= state.settings.identity.rate_limit.window_seconds as i64,
        "legacy rate limit counter must be given a bounded TTL, got {ttl}"
    );
}
