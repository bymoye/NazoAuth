use std::{future::Future, pin::Pin, sync::Arc};

use actix_web::{
    HttpRequest, HttpResponse,
    http::StatusCode,
    web::{Data, Json},
};
use nazo_identity::{
    AccountProfileView, AuthorizedApplicationsView, PendingMfaProfileView, ProfilePatch,
    ProfileValidationError, SessionId,
};
use serde::{Deserialize, Serialize};

use crate::{
    SessionCookieConfig, csrf_error, json_response_no_store, login_required_response, oauth_error,
};

pub type ProfileAccountFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, ProfileAccountError>> + Send + 'a>>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProfileMe {
    Active(Box<AccountProfileView>),
    PendingMfa(PendingMfaProfileView),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProfileAccountError {
    LoginRequired,
    SessionLookupUnavailable,
    OverviewUnavailable,
    Validation(ProfileValidationError),
    UpdateUnavailable,
    UpdatedOverviewUnavailable,
    ApplicationsUnavailable,
}

pub trait ProfileAccountOperations: Send + Sync {
    fn me(&self, session_id: SessionId) -> ProfileAccountFuture<'_, ProfileMe>;

    fn update(
        &self,
        session_id: SessionId,
        patch: ProfilePatch,
    ) -> ProfileAccountFuture<'_, AccountProfileView>;

    fn applications(
        &self,
        session_id: SessionId,
    ) -> ProfileAccountFuture<'_, AuthorizedApplicationsView>;
}

#[derive(Clone)]
pub struct ProfileAccountEndpoint {
    operations: Arc<dyn ProfileAccountOperations>,
    cookies: SessionCookieConfig,
}

impl ProfileAccountEndpoint {
    #[must_use]
    pub fn new(
        operations: Arc<dyn ProfileAccountOperations>,
        cookies: SessionCookieConfig,
    ) -> Self {
        Self {
            operations,
            cookies,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct UpdateProfileRequest {
    pub display_name: Option<String>,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    pub middle_name: Option<String>,
    pub nickname: Option<String>,
    pub profile_url: Option<String>,
    pub website_url: Option<String>,
    pub gender: Option<String>,
    pub birthdate: Option<String>,
    pub zoneinfo: Option<String>,
    pub locale: Option<String>,
    pub address_formatted: Option<String>,
    pub address_street_address: Option<String>,
    pub address_locality: Option<String>,
    pub address_region: Option<String>,
    pub address_postal_code: Option<String>,
    pub address_country: Option<String>,
    pub phone_number: Option<String>,
}

impl From<UpdateProfileRequest> for ProfilePatch {
    fn from(payload: UpdateProfileRequest) -> Self {
        Self {
            display_name: payload.display_name,
            given_name: payload.given_name,
            family_name: payload.family_name,
            middle_name: payload.middle_name,
            nickname: payload.nickname,
            profile_url: payload.profile_url,
            website_url: payload.website_url,
            gender: payload.gender,
            birthdate: payload.birthdate,
            zoneinfo: payload.zoneinfo,
            locale: payload.locale,
            address_formatted: payload.address_formatted,
            address_street_address: payload.address_street_address,
            address_locality: payload.address_locality,
            address_region: payload.address_region,
            address_postal_code: payload.address_postal_code,
            address_country: payload.address_country,
            phone_number: payload.phone_number,
        }
    }
}

#[derive(Serialize)]
struct ActiveProfileDocument {
    #[serde(flatten)]
    profile: AccountProfileView,
    mfa_required: bool,
}

#[derive(Serialize)]
struct PendingMfaDocument<'a> {
    #[serde(flatten)]
    profile: PendingMfaProfileView,
    mfa_required: bool,
    csrf_token: Option<&'a str>,
}

pub async fn profile_me(
    endpoint: Data<ProfileAccountEndpoint>,
    request: HttpRequest,
) -> HttpResponse {
    let Some(session_id) = endpoint.cookies.session_id(&request) else {
        return login_required_response(&endpoint.cookies);
    };
    match endpoint.operations.me(session_id).await {
        Ok(ProfileMe::Active(profile)) => json_response_no_store(ActiveProfileDocument {
            profile: *profile,
            mfa_required: false,
        }),
        Ok(ProfileMe::PendingMfa(profile)) => {
            let csrf_token = crate::cookie_value(&request, endpoint.cookies.csrf_cookie_name());
            json_response_no_store(PendingMfaDocument {
                profile,
                mfa_required: true,
                csrf_token: csrf_token.as_deref(),
            })
        }
        Err(error) => profile_account_error_response(error, &endpoint.cookies),
    }
}

pub async fn profile_update(
    endpoint: Data<ProfileAccountEndpoint>,
    request: HttpRequest,
    Json(payload): Json<UpdateProfileRequest>,
) -> HttpResponse {
    if !endpoint.cookies.has_valid_csrf_token(&request, None) {
        return csrf_error();
    }
    let Some(session_id) = endpoint.cookies.session_id(&request) else {
        return login_required_response(&endpoint.cookies);
    };
    match endpoint.operations.update(session_id, payload.into()).await {
        Ok(profile) => json_response_no_store(profile),
        Err(error) => profile_account_error_response(error, &endpoint.cookies),
    }
}

pub async fn profile_applications(
    endpoint: Data<ProfileAccountEndpoint>,
    request: HttpRequest,
) -> HttpResponse {
    let Some(session_id) = endpoint.cookies.session_id(&request) else {
        return login_required_response(&endpoint.cookies);
    };
    match endpoint.operations.applications(session_id).await {
        Ok(applications) => json_response_no_store(applications),
        Err(error) => profile_account_error_response(error, &endpoint.cookies),
    }
}

fn profile_account_error_response(
    error: ProfileAccountError,
    cookies: &SessionCookieConfig,
) -> HttpResponse {
    match error {
        ProfileAccountError::LoginRequired => login_required_response(cookies),
        ProfileAccountError::SessionLookupUnavailable => oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "会话查询失败.",
        ),
        ProfileAccountError::OverviewUnavailable => oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "当前用户资料查询失败.",
        ),
        ProfileAccountError::Validation(error) => match error {
            ProfileValidationError::FieldTooLong(field) => oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                &format!("{field} 超出长度限制."),
            ),
            ProfileValidationError::InvalidAbsoluteUrl(field) => oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                &format!("{field} 必须是绝对 URL."),
            ),
            ProfileValidationError::InvalidHttpUrl(field) => oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                &format!("{field} 必须是 http 或 https URL."),
            ),
        },
        ProfileAccountError::UpdateUnavailable => oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "资料更新失败.",
        ),
        ProfileAccountError::UpdatedOverviewUnavailable => oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "当前用户资料查询失败.",
        ),
        ProfileAccountError::ApplicationsUnavailable => oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "授权应用查询失败.",
        ),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use actix_web::{body::to_bytes, cookie::Cookie, http::header, test};
    use chrono::{TimeZone, Utc};
    use serde_json::{Value, json};

    use super::*;

    async fn response_json(response: HttpResponse) -> Value {
        serde_json::from_slice(&to_bytes(response.into_body()).await.unwrap()).unwrap()
    }

    struct FakeOperations {
        me: Mutex<Result<ProfileMe, ProfileAccountError>>,
        update: Mutex<Result<AccountProfileView, ProfileAccountError>>,
        applications: Mutex<Result<AuthorizedApplicationsView, ProfileAccountError>>,
        update_calls: Mutex<usize>,
    }

    impl ProfileAccountOperations for FakeOperations {
        fn me(&self, _session_id: SessionId) -> ProfileAccountFuture<'_, ProfileMe> {
            let result = self.me.lock().unwrap().clone();
            Box::pin(async move { result })
        }

        fn update(
            &self,
            _session_id: SessionId,
            _patch: ProfilePatch,
        ) -> ProfileAccountFuture<'_, AccountProfileView> {
            *self.update_calls.lock().unwrap() += 1;
            let result = self.update.lock().unwrap().clone();
            Box::pin(async move { result })
        }

        fn applications(
            &self,
            _session_id: SessionId,
        ) -> ProfileAccountFuture<'_, AuthorizedApplicationsView> {
            let result = self.applications.lock().unwrap().clone();
            Box::pin(async move { result })
        }
    }

    fn profile() -> AccountProfileView {
        AccountProfileView {
            id: uuid::Uuid::from_u128(1),
            email: "alice@example.test".to_owned(),
            display_name: Some("Alice".to_owned()),
            avatar_url: None,
            given_name: None,
            family_name: None,
            middle_name: None,
            nickname: None,
            profile_url: None,
            website_url: None,
            gender: None,
            birthdate: None,
            zoneinfo: None,
            locale: None,
            address_formatted: None,
            address_street_address: None,
            address_locality: None,
            address_region: None,
            address_postal_code: None,
            address_country: None,
            phone_number: None,
            phone_number_verified: false,
            mfa_enabled: true,
            role: "user",
            admin_level: 0,
            authorized_app_count: 2,
        }
    }

    fn fake(
        me: Result<ProfileMe, ProfileAccountError>,
    ) -> (ProfileAccountEndpoint, Arc<FakeOperations>) {
        let operations = Arc::new(FakeOperations {
            me: Mutex::new(me),
            update: Mutex::new(Ok(profile())),
            applications: Mutex::new(Ok(AuthorizedApplicationsView {
                total: 1,
                items: vec![nazo_identity::AuthorizedApplicationView {
                    client_id: "client".to_owned(),
                    client_name: "Client".to_owned(),
                    last_scopes: vec!["openid".to_owned()],
                    last_authorized_at: Utc.timestamp_opt(1_700_000_000, 0).unwrap(),
                    authorization_count: 3,
                }],
            })),
            update_calls: Mutex::new(0),
        });
        (
            ProfileAccountEndpoint::new(
                operations.clone(),
                SessionCookieConfig::new("session", "csrf", true),
            ),
            operations,
        )
    }

    #[actix_web::test]
    async fn missing_session_keeps_login_required_body_and_cookie_clearing() {
        let (endpoint, _) = fake(Ok(ProfileMe::Active(Box::new(profile()))));
        let response = profile_me(
            Data::new(endpoint),
            test::TestRequest::get().to_http_request(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(response.headers().get_all(header::SET_COOKIE).count(), 2);
        assert!(response.headers().get(header::CACHE_CONTROL).is_none());
        assert!(response.headers().get(header::PRAGMA).is_none());
        let body = response_json(response).await;
        assert_eq!(body["error"], "login_required");
    }

    #[actix_web::test]
    async fn active_me_keeps_exact_profile_shape_without_csrf_token() {
        let (endpoint, _) = fake(Ok(ProfileMe::Active(Box::new(profile()))));
        let response = profile_me(
            Data::new(endpoint),
            test::TestRequest::get()
                .cookie(Cookie::new("session", "sid"))
                .cookie(Cookie::new("csrf", "csrf-token"))
                .to_http_request(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/json"
        );
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
        assert_eq!(response.headers().get(header::PRAGMA).unwrap(), "no-cache");
        let body = response_json(response).await;
        assert_eq!(body["id"], uuid::Uuid::from_u128(1).to_string());
        assert_eq!(body["mfa_required"], false);
        assert_eq!(body["authorized_app_count"], 2);
        assert!(body.get("csrf_token").is_none());
    }

    #[actix_web::test]
    async fn pending_mfa_me_returns_cookie_csrf_token_and_reduced_profile() {
        let (endpoint, _) = fake(Ok(ProfileMe::PendingMfa(PendingMfaProfileView {
            id: uuid::Uuid::from_u128(2),
            email: "pending@example.test".to_owned(),
        })));
        let response = profile_me(
            Data::new(endpoint),
            test::TestRequest::get()
                .cookie(Cookie::new("session", "sid"))
                .cookie(Cookie::new("csrf", "csrf-token"))
                .to_http_request(),
        )
        .await;
        let body = response_json(response).await;
        assert_eq!(
            body,
            json!({
                "id": uuid::Uuid::from_u128(2),
                "email": "pending@example.test",
                "mfa_required": true,
                "csrf_token": "csrf-token"
            })
        );
    }

    #[actix_web::test]
    async fn update_rejects_missing_csrf_before_calling_operations() {
        let (endpoint, operations) = fake(Ok(ProfileMe::Active(Box::new(profile()))));
        let response = profile_update(
            Data::new(endpoint),
            test::TestRequest::patch()
                .cookie(Cookie::new("session", "sid"))
                .to_http_request(),
            Json(UpdateProfileRequest {
                display_name: Some("Alice".to_owned()),
                given_name: None,
                family_name: None,
                middle_name: None,
                nickname: None,
                profile_url: None,
                website_url: None,
                gender: None,
                birthdate: None,
                zoneinfo: None,
                locale: None,
                address_formatted: None,
                address_street_address: None,
                address_locality: None,
                address_region: None,
                address_postal_code: None,
                address_country: None,
                phone_number: None,
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(*operations.update_calls.lock().unwrap(), 0);
    }

    #[actix_web::test]
    async fn update_and_applications_keep_success_contracts() {
        let (endpoint, _) = fake(Ok(ProfileMe::Active(Box::new(profile()))));
        let endpoint = Data::new(endpoint);
        let update = profile_update(
            endpoint.clone(),
            test::TestRequest::patch()
                .cookie(Cookie::new("session", "sid"))
                .cookie(Cookie::new("csrf", "csrf-token"))
                .insert_header(("x-csrf-token", "csrf-token"))
                .to_http_request(),
            Json(UpdateProfileRequest {
                display_name: Some("Alice".to_owned()),
                given_name: None,
                family_name: None,
                middle_name: None,
                nickname: None,
                profile_url: None,
                website_url: None,
                gender: None,
                birthdate: None,
                zoneinfo: None,
                locale: None,
                address_formatted: None,
                address_street_address: None,
                address_locality: None,
                address_region: None,
                address_postal_code: None,
                address_country: None,
                phone_number: None,
            }),
        )
        .await;
        assert_eq!(
            update.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
        let update_body = response_json(update).await;
        assert_eq!(update_body["display_name"], "Alice");
        assert!(update_body.get("mfa_required").is_none());

        let applications = profile_applications(
            endpoint,
            test::TestRequest::get()
                .cookie(Cookie::new("session", "sid"))
                .to_http_request(),
        )
        .await;
        assert_eq!(
            applications.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
        let applications_body = response_json(applications).await;
        assert_eq!(applications_body["total"], 1);
        assert_eq!(
            applications_body["items"][0]["last_scopes"],
            json!(["openid"])
        );
    }

    #[actix_web::test]
    async fn validation_and_dependency_errors_keep_status_and_oauth_codes() {
        let cases = [
            (
                ProfileAccountError::Validation(ProfileValidationError::FieldTooLong(
                    "display_name",
                )),
                StatusCode::BAD_REQUEST,
                "invalid_request",
            ),
            (
                ProfileAccountError::SessionLookupUnavailable,
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
            ),
            (
                ProfileAccountError::ApplicationsUnavailable,
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
            ),
        ];
        for (error, status, code) in cases {
            let response = profile_account_error_response(
                error,
                &SessionCookieConfig::new("session", "csrf", true),
            );
            assert_eq!(response.status(), status);
            assert!(response.headers().get(header::CACHE_CONTROL).is_none());
            assert!(response.headers().get(header::PRAGMA).is_none());
            let body = response_json(response).await;
            assert_eq!(body["error"], code);
        }
    }
}
