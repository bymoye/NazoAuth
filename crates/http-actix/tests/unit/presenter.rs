use actix_web::http::{StatusCode, header};

use super::*;

#[test]
fn token_error_preserves_cache_and_challenge_contract() {
    let response = oauth_token_error(
        StatusCode::UNAUTHORIZED,
        "invalid_client",
        "Client authentication failed.",
        true,
    );
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    assert_eq!(response.headers().get(header::PRAGMA).unwrap(), "no-cache");
    assert_eq!(
        response.headers().get(header::WWW_AUTHENTICATE).unwrap(),
        r#"Basic realm="nazo-oauth""#
    );
    assert_eq!(
        response
            .extensions()
            .get::<OAuthJsonErrorFields>()
            .unwrap()
            .error,
        "invalid_client"
    );
}

#[test]
fn non_ascii_protocol_description_is_replaced() {
    assert_eq!(oauth_error_description("失败"), "Request failed.");
}
