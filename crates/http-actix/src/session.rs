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
mod tests {
    use std::sync::{Arc, Mutex};

    use actix_web::{body::to_bytes, cookie::Cookie, http::header, test::TestRequest, web::Data};
    use nazo_identity::{
        PublicAccount, SessionRotationOutcome, SessionSnapshot, TenantId, UserId,
        ports::{RepositoryError, RepositoryFuture, SessionAccountPort, SessionStorePort},
    };
    use serde_json::{Value, json};

    use super::*;

    #[derive(Default)]
    struct RecordingStore {
        deleted: Mutex<Vec<String>>,
        delete_error: Mutex<Option<RepositoryError>>,
    }

    impl SessionStorePort for RecordingStore {
        fn load<'a>(
            &'a self,
            _session_id: &'a SessionId,
        ) -> RepositoryFuture<'a, Option<SessionSnapshot>> {
            Box::pin(async { Ok(None) })
        }

        fn delete<'a>(&'a self, session_id: &'a SessionId) -> RepositoryFuture<'a, bool> {
            Box::pin(async move {
                if let Some(error) = self.delete_error.lock().unwrap().clone() {
                    return Err(error);
                }
                self.deleted
                    .lock()
                    .unwrap()
                    .push(session_id.as_str().to_owned());
                Ok(true)
            })
        }

        fn rotate<'a>(
            &'a self,
            _old_session_id: &'a SessionId,
            _expected: &'a SessionSnapshot,
            _new_session_id: &'a SessionId,
            _replacement: &'a nazo_identity::session::SessionRecord,
            _ttl_seconds: u64,
        ) -> RepositoryFuture<'a, SessionRotationOutcome> {
            Box::pin(async { Ok(SessionRotationOutcome::Conflict) })
        }
    }

    struct MissingAccounts;

    impl SessionAccountPort for MissingAccounts {
        fn public_account_by_id(
            &self,
            _tenant_id: TenantId,
            _user_id: UserId,
        ) -> RepositoryFuture<'_, Option<PublicAccount>> {
            Box::pin(async { Ok(None) })
        }
    }

    fn endpoint(store: Arc<RecordingStore>) -> Data<SessionLogoutEndpoint> {
        Data::new(SessionLogoutEndpoint::new(
            SessionService::new(
                store,
                Arc::new(MissingAccounts),
                TenantId::new(uuid::Uuid::from_u128(1)).unwrap(),
            ),
            SessionCookieConfig::new("session", "csrf", true),
            |_| {},
        ))
    }

    async fn assert_logout_response(response: HttpResponse) {
        assert_eq!(response.status(), StatusCode::OK);
        let set_cookie = response
            .headers()
            .get_all(header::SET_COOKIE)
            .filter_map(|value| value.to_str().ok())
            .collect::<Vec<_>>();
        assert_eq!(set_cookie.len(), 2);
        assert!(
            set_cookie
                .iter()
                .any(|cookie| { cookie.contains("session=") && cookie.contains("Max-Age=0") })
        );
        assert!(
            set_cookie
                .iter()
                .any(|cookie| { cookie.contains("csrf=") && cookie.contains("Max-Age=0") })
        );
        assert!(
            set_cookie
                .iter()
                .all(|cookie| { cookie.contains("SameSite=Lax") && cookie.contains("Secure") })
        );
        let body: Value =
            serde_json::from_slice(&to_bytes(response.into_body()).await.unwrap()).unwrap();
        assert_eq!(body, json!({"success": true}));
    }

    #[actix_web::test]
    async fn logout_deletes_the_cookie_session_and_preserves_response_contract() {
        let store = Arc::new(RecordingStore::default());
        let request = TestRequest::default()
            .cookie(Cookie::new("session", "sid-1"))
            .to_http_request();
        let response = profile_logout(endpoint(store.clone()), request).await;

        assert_eq!(store.deleted.lock().unwrap().as_slice(), ["sid-1"]);
        assert_logout_response(response).await;
    }

    #[actix_web::test]
    async fn logout_fails_closed_at_the_browser_boundary_when_store_is_unavailable() {
        let store = Arc::new(RecordingStore::default());
        *store.delete_error.lock().unwrap() = Some(RepositoryError::Unavailable);
        let request = TestRequest::default()
            .cookie(Cookie::new("session", "sid-1"))
            .to_http_request();

        assert_logout_response(profile_logout(endpoint(store), request).await).await;
    }

    #[actix_web::test]
    async fn login_required_contract_clears_both_cookies() {
        let response = login_required_response(&SessionCookieConfig::new("session", "csrf", true));
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(response.headers().get_all(header::SET_COOKIE).count(), 2);
        let body: Value =
            serde_json::from_slice(&to_bytes(response.into_body()).await.unwrap()).unwrap();
        assert_eq!(
            body,
            json!({
                "error": "login_required",
                "error_description": "Request failed."
            })
        );
    }
}
