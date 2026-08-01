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
#[path = "../tests/unit/profile_account.rs"]
mod tests;
