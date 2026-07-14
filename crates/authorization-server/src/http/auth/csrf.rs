//! CSRF token 刷新端点。
use crate::adapters::security::random_urlsafe_token;
use crate::http::sessions::SessionProfileHandles;
#[cfg(test)]
use actix_web::http::StatusCode;
use actix_web::web::Data;
use actix_web::{HttpRequest, HttpResponse};
use nazo_http_actix::json_response;
use nazo_http_actix::{make_cookie, with_cookie_headers};
#[cfg(test)]
use serde_json::Value;
use serde_json::json;
// 只有已登录用户可以刷新 token，避免匿名请求制造无意义状态。

#[derive(Clone, Debug)]
pub(crate) struct CsrfHttpConfig {
    cookie_name: Box<str>,
    session_ttl_seconds: u64,
    cookie_secure: bool,
}

impl CsrfHttpConfig {
    pub(crate) fn new(
        cookie_name: impl Into<Box<str>>,
        session_ttl_seconds: u64,
        cookie_secure: bool,
    ) -> Self {
        Self {
            cookie_name: cookie_name.into(),
            session_ttl_seconds,
            cookie_secure,
        }
    }
}

/// 为当前会话生成新的 CSRF token。
pub(crate) async fn csrf(
    sessions: Data<SessionProfileHandles>,
    config: Data<CsrfHttpConfig>,
    req: HttpRequest,
) -> HttpResponse {
    if let Err(response) = sessions.current_user_or_login_required(&req).await {
        return response;
    };

    let csrf_token = random_urlsafe_token();
    csrf_response(&config, csrf_token)
}

fn csrf_response(config: &CsrfHttpConfig, csrf_token: String) -> HttpResponse {
    with_cookie_headers(
        json_response(json!({"csrf_token": csrf_token})),
        &[make_cookie(
            &config.cookie_name,
            &csrf_token,
            false,
            config.session_ttl_seconds,
            config.cookie_secure,
        )],
    )
}

#[cfg(test)]
#[path = "../../../tests/in_source/src/http/auth/tests/csrf.rs"]
mod tests;
