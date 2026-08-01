use actix_web::{HttpRequest, HttpResponse, http::StatusCode, web::Data};
use nazo_identity::{SessionId, SessionRotation, SessionService};
use serde_json::json;

use crate::{
    clear_cookie, cookie_value, has_valid_csrf_token_for_cookies, json_response, make_cookie,
    oauth_error, with_cookie_headers,
};

/// HTTP-only cookie configuration for identity sessions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionCookieConfig {
    session_cookie_name: Box<str>,
    csrf_cookie_name: Box<str>,
    secure: bool,
}

impl SessionCookieConfig {
    #[must_use]
    pub fn new(session_cookie_name: &str, csrf_cookie_name: &str, secure: bool) -> Self {
        Self {
            session_cookie_name: session_cookie_name.into(),
            csrf_cookie_name: csrf_cookie_name.into(),
            secure,
        }
    }

    #[must_use]
    pub fn session_cookie_name(&self) -> &str {
        &self.session_cookie_name
    }

    #[must_use]
    pub fn csrf_cookie_name(&self) -> &str {
        &self.csrf_cookie_name
    }

    #[must_use]
    pub const fn secure(&self) -> bool {
        self.secure
    }

    #[must_use]
    pub fn session_id(&self, request: &HttpRequest) -> Option<SessionId> {
        cookie_value(request, self.session_cookie_name()).map(SessionId::from)
    }

    #[must_use]
    pub fn has_valid_csrf_token(
        &self,
        request: &HttpRequest,
        fallback_token: Option<&str>,
    ) -> bool {
        has_valid_csrf_token_for_cookies(
            request,
            fallback_token,
            self.session_cookie_name(),
            self.csrf_cookie_name(),
        )
    }

    #[must_use]
    pub fn rotation_cookies(
        &self,
        rotation: &SessionRotation,
        ttl_seconds: u64,
    ) -> [actix_web::cookie::Cookie<'static>; 2] {
        [
            make_cookie(
                self.session_cookie_name(),
                rotation.session_id().as_str(),
                true,
                ttl_seconds,
                self.secure(),
            ),
            make_cookie(
                self.csrf_cookie_name(),
                rotation.csrf_token(),
                false,
                ttl_seconds,
                self.secure(),
            ),
        ]
    }

    #[must_use]
    pub fn clear_cookies(&self) -> [actix_web::cookie::Cookie<'static>; 2] {
        [
            clear_cookie(self.session_cookie_name(), self.secure()),
            clear_cookie(self.csrf_cookie_name(), self.secure()),
        ]
    }
}

/// Focused dependencies for the profile logout endpoint.
#[derive(Clone)]
pub struct SessionLogoutEndpoint {
    sessions: SessionService,
    cookies: SessionCookieConfig,
    on_delete_error: fn(&nazo_identity::ports::RepositoryError),
}

impl SessionLogoutEndpoint {
    #[must_use]
    pub fn new(
        sessions: SessionService,
        cookies: SessionCookieConfig,
        on_delete_error: fn(&nazo_identity::ports::RepositoryError),
    ) -> Self {
        Self {
            sessions,
            cookies,
            on_delete_error,
        }
    }
}

pub async fn profile_logout(
    endpoint: Data<SessionLogoutEndpoint>,
    request: HttpRequest,
) -> HttpResponse {
    if let Some(session_id) = endpoint.cookies.session_id(&request)
        && let Err(error) = endpoint.sessions.delete(&session_id).await
    {
        (endpoint.on_delete_error)(&error);
    }
    logout_response(&endpoint.cookies)
}

#[must_use]
pub fn logout_response(cookies: &SessionCookieConfig) -> HttpResponse {
    with_cookie_headers(
        json_response(json!({"success": true})),
        &cookies.clear_cookies(),
    )
}

#[must_use]
pub fn login_required_response(cookies: &SessionCookieConfig) -> HttpResponse {
    with_cookie_headers(
        oauth_error(
            StatusCode::UNAUTHORIZED,
            "login_required",
            "会话不存在或已过期,请重新登录.",
        ),
        &cookies.clear_cookies(),
    )
}

#[must_use]
pub fn session_lookup_error_response(
    error: &nazo_identity::ports::RepositoryError,
) -> HttpResponse {
    let _ = error;
    oauth_error(
        StatusCode::SERVICE_UNAVAILABLE,
        "server_error",
        "会话查询失败.",
    )
}

#[cfg(test)]
#[path = "../tests/unit/session.rs"]
mod tests;
