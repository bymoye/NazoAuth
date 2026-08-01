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
#[path = "../tests/unit/cookies.rs"]
mod tests;
