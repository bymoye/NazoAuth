use actix_web::cookie::time::Duration as CookieDuration;
use actix_web::cookie::{Cookie, SameSite};
use actix_web::{HttpRequest, HttpResponse};

/// Builds a host cookie with the server's established security attributes.
#[must_use]
pub fn make_cookie(
    name: &str,
    value: &str,
    http_only: bool,
    max_age: u64,
    secure: bool,
) -> Cookie<'static> {
    Cookie::build(name.to_owned(), value.to_owned())
        .path("/")
        .max_age(CookieDuration::seconds(max_age.min(i64::MAX as u64) as i64))
        .same_site(SameSite::Lax)
        .http_only(http_only)
        .secure(secure)
        .finish()
}

#[must_use]
pub fn clear_cookie(name: &str, secure: bool) -> Cookie<'static> {
    let mut cookie = Cookie::build(name.to_owned(), String::new())
        .path("/")
        .same_site(SameSite::Lax)
        .http_only(true)
        .secure(secure)
        .finish();
    cookie.make_removal();
    cookie
}

#[must_use]
pub fn with_cookie_headers(
    mut response: HttpResponse,
    cookies: &[Cookie<'static>],
) -> HttpResponse {
    for cookie in cookies {
        let _ = response.add_cookie(cookie);
    }
    response
}

#[must_use]
pub fn cookie_value(req: &HttpRequest, name: &str) -> Option<String> {
    req.cookie(name).map(|cookie| cookie.value().to_owned())
}

#[cfg(test)]
mod tests {
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
}
