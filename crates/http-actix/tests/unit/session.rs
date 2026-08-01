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

    fn compare_and_set<'a>(
        &'a self,
        _session_id: &'a SessionId,
        _expected: &'a SessionSnapshot,
        _replacement: &'a nazo_identity::session::SessionRecord,
    ) -> RepositoryFuture<'a, nazo_identity::SessionUpdateOutcome> {
        Box::pin(async { Ok(nazo_identity::SessionUpdateOutcome::Conflict) })
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
