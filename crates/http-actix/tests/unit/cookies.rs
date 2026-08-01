use actix_web::http::{StatusCode, header};

use super::*;

#[test]
fn cookies_preserve_exact_security_attributes() {
    let cookie = make_cookie("sid", "value", true, 60, true);
    assert_eq!(cookie.path(), Some("/"));
    assert_eq!(cookie.max_age(), Some(CookieDuration::seconds(60)));
    assert_eq!(cookie.secure(), Some(true));
    assert_eq!(cookie.http_only(), Some(true));
    assert_eq!(cookie.same_site(), Some(SameSite::Lax));

    let cookie = clear_cookie("sid", true);
    assert_eq!(cookie.path(), Some("/"));
    assert_eq!(cookie.secure(), Some(true));
    assert_eq!(cookie.http_only(), Some(true));
    assert_eq!(cookie.same_site(), Some(SameSite::Lax));
    assert_eq!(cookie.max_age(), Some(CookieDuration::seconds(0)));
}

#[test]
fn cookie_max_age_saturates_at_i64_max() {
    assert_eq!(
        make_cookie("sid", "value", true, u64::MAX, true).max_age(),
        Some(CookieDuration::seconds(i64::MAX))
    );
}

#[test]
fn cookie_headers_and_lookup_preserve_values() {
    let request = actix_web::test::TestRequest::default()
        .cookie(Cookie::new("sid", "session-value"))
        .to_http_request();
    assert_eq!(
        cookie_value(&request, "sid").as_deref(),
        Some("session-value")
    );

    let response = with_cookie_headers(
        HttpResponse::build(StatusCode::OK).finish(),
        &[make_cookie("sid", "session-value", true, 60, true)],
    );
    assert_eq!(response.headers().get_all(header::SET_COOKIE).count(), 1);
}
