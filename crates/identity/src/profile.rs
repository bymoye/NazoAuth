use std::collections::HashMap;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, KeyInit, Mac};
use serde_json::Value;
use sha2::Sha256;
use uuid::Uuid;

use crate::{
    AccessRequest, AccessRequestStatus, NewAccessRequest, PostalAddress, PublicAccount, UserId,
    UserProfile,
    ports::{
        AccessRequestRepositoryPort, AuthorizedApplication, AuthorizedApplicationRepositoryPort,
        DeliveryConsume, DeliveryStorePort, FederationLink, FederationLinkRepositoryPort,
        GrantSummaryRepositoryPort, ProfileRepositoryPort, ProfileUpdate, RepositoryError,
    },
};

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ProfilePatch {
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProfileValidationError {
    FieldTooLong(&'static str),
    InvalidAbsoluteUrl(&'static str),
    InvalidHttpUrl(&'static str),
}

impl std::fmt::Display for ProfileValidationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FieldTooLong(field) => write!(formatter, "{field} exceeds its length limit"),
            Self::InvalidAbsoluteUrl(field) => {
                write!(formatter, "{field} must be an absolute URL")
            }
            Self::InvalidHttpUrl(field) => {
                write!(formatter, "{field} must be an absolute HTTP URL")
            }
        }
    }
}

impl std::error::Error for ProfileValidationError {}

#[derive(Clone, Debug, PartialEq)]
pub struct AccountOverview {
    pub account: PublicAccount,
    pub authorized_application_count: i64,
}

/// Stable profile projection consumed by the browser-facing account endpoints.
///
/// Keeping this projection in the identity domain prevents HTTP adapters from
/// learning the internal shape of [`PublicAccount`] while preserving the
/// existing JSON field contract.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct AccountProfileView {
    pub id: uuid::Uuid,
    pub email: String,
    pub display_name: Option<String>,
    pub avatar_url: Option<String>,
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
    pub phone_number_verified: bool,
    pub mfa_enabled: bool,
    pub role: &'static str,
    pub admin_level: u32,
    pub authorized_app_count: i64,
}

impl From<AccountOverview> for AccountProfileView {
    fn from(overview: AccountOverview) -> Self {
        let account = overview.account;
        let id = account.id();
        let role = account.role_name();
        let admin_level = account.admin_level();
        Self {
            id,
            email: account.account.email,
            display_name: account.profile.display_name,
            avatar_url: account.profile.avatar_url,
            given_name: account.profile.given_name,
            family_name: account.profile.family_name,
            middle_name: account.profile.middle_name,
            nickname: account.profile.nickname,
            profile_url: account.profile.profile_url,
            website_url: account.profile.website_url,
            gender: account.profile.gender,
            birthdate: account.profile.birthdate,
            zoneinfo: account.profile.zoneinfo,
            locale: account.profile.locale,
            address_formatted: account.profile.address.formatted,
            address_street_address: account.profile.address.street_address,
            address_locality: account.profile.address.locality,
            address_region: account.profile.address.region,
            address_postal_code: account.profile.address.postal_code,
            address_country: account.profile.address.country,
            phone_number: account.profile.phone_number,
            phone_number_verified: account.profile.phone_number_verified,
            mfa_enabled: account.account.mfa_enabled,
            role,
            admin_level,
            authorized_app_count: overview.authorized_application_count,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct PendingMfaProfileView {
    pub id: uuid::Uuid,
    pub email: String,
}

impl From<PublicAccount> for PendingMfaProfileView {
    fn from(account: PublicAccount) -> Self {
        Self {
            id: account.id(),
            email: account.account.email,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct AuthorizedApplicationView {
    pub client_id: String,
    pub client_name: String,
    pub last_scopes: Vec<String>,
    pub last_authorized_at: chrono::DateTime<chrono::Utc>,
    pub authorization_count: i32,
}

impl From<AuthorizedApplication> for AuthorizedApplicationView {
    fn from(application: AuthorizedApplication) -> Self {
        Self {
            client_id: application.client_id,
            client_name: application.client_name,
            last_scopes: application
                .last_scopes
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(serde_json::Value::as_str)
                .map(str::to_owned)
                .collect(),
            last_authorized_at: application.last_authorized_at,
            authorization_count: application.authorization_count,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct AuthorizedApplicationsView {
    pub total: usize,
    pub items: Vec<AuthorizedApplicationView>,
}

impl From<Vec<AuthorizedApplication>> for AuthorizedApplicationsView {
    fn from(applications: Vec<AuthorizedApplication>) -> Self {
        let items = applications
            .into_iter()
            .map(AuthorizedApplicationView::from)
            .collect::<Vec<_>>();
        Self {
            total: items.len(),
            items,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UpdateProfileError {
    Validation(ProfileValidationError),
    UpdateRepository(RepositoryError),
    OverviewRepository(RepositoryError),
}

#[derive(Clone)]
pub struct AccountProfileService<P, G, A> {
    profiles: P,
    grants: G,
    applications: A,
}

impl<P, G, A> AccountProfileService<P, G, A>
where
    P: ProfileRepositoryPort,
    G: GrantSummaryRepositoryPort,
    A: AuthorizedApplicationRepositoryPort,
{
    pub fn new(profiles: P, grants: G, applications: A) -> Self {
        Self {
            profiles,
            grants,
            applications,
        }
    }

    pub async fn overview(
        &self,
        account: PublicAccount,
    ) -> Result<AccountOverview, RepositoryError> {
        let authorized_application_count =
            self.grants.authorized_client_count(account.id()).await?;
        Ok(AccountOverview {
            account,
            authorized_application_count,
        })
    }

    pub async fn update(
        &self,
        account: &PublicAccount,
        patch: ProfilePatch,
    ) -> Result<AccountOverview, UpdateProfileError> {
        let profile =
            normalize_profile_patch(account, patch).map_err(UpdateProfileError::Validation)?;
        let account = self
            .profiles
            .update_profile(
                account.tenant().tenant_id,
                account.user_id(),
                ProfileUpdate { profile },
            )
            .await
            .map_err(UpdateProfileError::UpdateRepository)?;
        self.overview(account)
            .await
            .map_err(UpdateProfileError::OverviewRepository)
    }

    pub async fn applications(
        &self,
        account: &PublicAccount,
    ) -> Result<Vec<AuthorizedApplication>, RepositoryError> {
        self.applications.applications_for_user(account.id()).await
    }
}

fn normalize_profile_patch(
    account: &PublicAccount,
    patch: ProfilePatch,
) -> Result<UserProfile, ProfileValidationError> {
    let display_name = profile_text(patch.display_name, 80, "display_name")?;
    let given_name = profile_text(patch.given_name, 80, "given_name")?;
    let family_name = profile_text(patch.family_name, 80, "family_name")?;
    let middle_name = profile_text(patch.middle_name, 80, "middle_name")?;
    let nickname = profile_text(patch.nickname, 80, "nickname")?;
    let profile_url = normalize_profile_url(patch.profile_url, "profile_url")?;
    let website_url = normalize_profile_url(patch.website_url, "website_url")?;
    let gender = profile_text(patch.gender, 40, "gender")?;
    let birthdate = profile_text(patch.birthdate, 10, "birthdate")?;
    let zoneinfo = profile_text(patch.zoneinfo, 64, "zoneinfo")?;
    let locale = profile_text(patch.locale, 35, "locale")?;
    let address_formatted = profile_text(patch.address_formatted, 512, "address_formatted")?;
    let address_street_address =
        profile_text(patch.address_street_address, 256, "address_street_address")?;
    let address_locality = profile_text(patch.address_locality, 128, "address_locality")?;
    let address_region = profile_text(patch.address_region, 128, "address_region")?;
    let address_postal_code = profile_text(patch.address_postal_code, 64, "address_postal_code")?;
    let address_country = profile_text(patch.address_country, 64, "address_country")?;
    let phone_number = profile_text(patch.phone_number, 32, "phone_number")?;
    let phone_number_verified =
        account.profile.phone_number_verified && account.profile.phone_number == phone_number;
    Ok(UserProfile {
        display_name,
        avatar_url: account.profile.avatar_url.clone(),
        given_name,
        family_name,
        middle_name,
        nickname,
        profile_url,
        website_url,
        gender,
        birthdate,
        zoneinfo,
        locale,
        address: PostalAddress {
            formatted: address_formatted,
            street_address: address_street_address,
            locality: address_locality,
            region: address_region,
            postal_code: address_postal_code,
            country: address_country,
        },
        phone_number,
        phone_number_verified,
    })
}

fn profile_text(
    value: Option<String>,
    max_bytes: usize,
    field: &'static str,
) -> Result<Option<String>, ProfileValidationError> {
    let Some(value) = value
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
    else {
        return Ok(None);
    };
    if value.len() > max_bytes {
        return Err(ProfileValidationError::FieldTooLong(field));
    }
    Ok(Some(value))
}

fn normalize_profile_url(
    value: Option<String>,
    field: &'static str,
) -> Result<Option<String>, ProfileValidationError> {
    let Some(value) = profile_text(value, 512, field)? else {
        return Ok(None);
    };
    let url =
        url::Url::parse(&value).map_err(|_| ProfileValidationError::InvalidAbsoluteUrl(field))?;
    if !matches!(url.scheme(), "https" | "http") || url.cannot_be_a_base() {
        return Err(ProfileValidationError::InvalidHttpUrl(field));
    }
    Ok(Some(value))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NewAccessRequestInput {
    pub site_name: String,
    pub site_url: String,
    pub request_description: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AvailableDelivery {
    pub token: String,
    pub url: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct AccessRequestWithDelivery {
    pub request: AccessRequest,
    pub delivery: Option<AvailableDelivery>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AccessRequestListError {
    Repository(RepositoryError),
    DeliveryStore(RepositoryError),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DeliveryReadError {
    Invalid,
    Repository(RepositoryError),
    DeliveryStore(RepositoryError),
}

#[derive(Clone)]
pub struct ClientAccessService<R, D> {
    requests: R,
    deliveries: D,
    client_secret_pepper: Box<str>,
    frontend_base_url: Box<str>,
}

impl<R, D> ClientAccessService<R, D>
where
    R: AccessRequestRepositoryPort,
    D: DeliveryStorePort,
{
    pub fn new(
        requests: R,
        deliveries: D,
        client_secret_pepper: &str,
        frontend_base_url: &str,
    ) -> Self {
        Self {
            requests,
            deliveries,
            client_secret_pepper: client_secret_pepper.into(),
            frontend_base_url: frontend_base_url.trim_end_matches('/').into(),
        }
    }

    pub async fn list(
        &self,
        account: &PublicAccount,
    ) -> Result<Vec<AccessRequestWithDelivery>, AccessRequestListError> {
        const DELIVERY_LOOKUP_BATCH_SIZE: usize = 128;
        let rows = self
            .requests
            .list_for_user(account.tenant().tenant_id, account.user_id())
            .await
            .map_err(AccessRequestListError::Repository)?;
        let candidates = rows
            .iter()
            .filter_map(|request| self.delivery_candidate(request))
            .collect::<Vec<_>>();
        let mut deliveries = HashMap::with_capacity(candidates.len());
        for batch in candidates.chunks(DELIVERY_LOOKUP_BATCH_SIZE) {
            let lookups = batch
                .iter()
                .map(|candidate| (candidate.user_id, candidate.token.as_str()))
                .collect::<Vec<_>>();
            let payloads = self
                .deliveries
                .load_many(&lookups)
                .await
                .map_err(AccessRequestListError::DeliveryStore)?;
            for (candidate, stored) in batch.iter().zip(payloads) {
                if let Some(stored) = stored
                    && delivery_payload_matches(candidate, &stored.value)
                {
                    deliveries.insert(
                        candidate.request_id,
                        AvailableDelivery {
                            token: candidate.token.clone(),
                            url: format!(
                                "{}/delivery?token={}",
                                self.frontend_base_url, candidate.token
                            ),
                        },
                    );
                }
            }
        }
        Ok(rows
            .into_iter()
            .map(|request| AccessRequestWithDelivery {
                delivery: deliveries.remove(&request.id),
                request,
            })
            .collect())
    }

    pub async fn create(
        &self,
        account: &PublicAccount,
        input: NewAccessRequestInput,
    ) -> Result<AccessRequest, RepositoryError> {
        self.requests
            .create(NewAccessRequest {
                tenant_id: account.tenant().tenant_id,
                user_id: account.user_id(),
                site_name: input.site_name,
                site_url: input.site_url,
                request_description: input.request_description,
            })
            .await
    }

    pub async fn claim_delivery(
        &self,
        account: &PublicAccount,
        token: &str,
    ) -> Result<Value, DeliveryReadError> {
        let stored = self
            .deliveries
            .load(account.user_id(), token)
            .await
            .map_err(DeliveryReadError::DeliveryStore)?
            .ok_or(DeliveryReadError::Invalid)?;
        let Some(claim) = delivery_claim(&stored.value) else {
            let _ = self.deliveries.delete(account.user_id(), token).await;
            return Err(DeliveryReadError::Invalid);
        };
        match self
            .requests
            .approved_delivery_matches(
                account.tenant().tenant_id,
                account.user_id(),
                claim.request_id,
                claim.approved_client_id,
                &claim.client_id,
            )
            .await
        {
            Ok(true) => {}
            Ok(false) => {
                let _ = self.deliveries.delete(account.user_id(), token).await;
                return Err(DeliveryReadError::Invalid);
            }
            Err(error) => return Err(DeliveryReadError::Repository(error)),
        }
        match self
            .deliveries
            .consume(account.user_id(), token, &stored)
            .await
        {
            Ok(DeliveryConsume::Consumed(value)) => Ok(value),
            Ok(DeliveryConsume::MissingOrChanged) => Err(DeliveryReadError::Invalid),
            Err(error) => Err(DeliveryReadError::DeliveryStore(error)),
        }
    }

    fn delivery_candidate(&self, request: &AccessRequest) -> Option<DeliveryCandidate> {
        let approved_client_id = request.approved_client_id?;
        if request.status != AccessRequestStatus::Approved {
            return None;
        }
        Some(DeliveryCandidate {
            request_id: request.id,
            user_id: request.user_id,
            approved_client_id,
            token: access_delivery_token(
                &self.client_secret_pepper,
                request.user_id.as_uuid(),
                request.id,
            ),
        })
    }
}

struct DeliveryCandidate {
    request_id: Uuid,
    user_id: UserId,
    approved_client_id: Uuid,
    token: String,
}

struct DeliveryClaim {
    request_id: Uuid,
    approved_client_id: Uuid,
    client_id: String,
}

fn delivery_payload_matches(candidate: &DeliveryCandidate, payload: &Value) -> bool {
    payload["delivery_state"] == "committed"
        && payload["request_id"] == serde_json::json!(candidate.request_id)
        && payload["user_id"] == serde_json::json!(candidate.user_id.as_uuid())
        && payload["approved_client_id"] == serde_json::json!(candidate.approved_client_id)
}

fn delivery_claim(value: &Value) -> Option<DeliveryClaim> {
    if value.get("delivery_state")?.as_str()? != "committed" {
        return None;
    }
    Some(DeliveryClaim {
        request_id: serde_json::from_value(value.get("request_id")?.clone()).ok()?,
        approved_client_id: serde_json::from_value(value.get("approved_client_id")?.clone())
            .ok()?,
        client_id: value.get("client_id")?.as_str()?.to_owned(),
    })
}

pub fn access_delivery_token(secret: &str, user_id: Uuid, request_id: Uuid) -> String {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key");
    mac.update(b"client-delivery-v1\0");
    mac.update(user_id.as_bytes());
    mac.update(request_id.as_bytes());
    URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
}

#[derive(Clone)]
pub struct FederationLinksService<F> {
    links: F,
}

impl<F> FederationLinksService<F>
where
    F: FederationLinkRepositoryPort,
{
    pub fn new(links: F) -> Self {
        Self { links }
    }

    pub async fn list(
        &self,
        account: &PublicAccount,
    ) -> Result<Vec<FederationLink>, RepositoryError> {
        self.links
            .list(account.tenant().tenant_id, account.user_id())
            .await
    }

    pub async fn unlink(
        &self,
        account: &PublicAccount,
        link_id: Uuid,
    ) -> Result<Option<FederationLink>, RepositoryError> {
        self.links
            .delete(account.tenant().tenant_id, account.user_id(), link_id)
            .await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    };

    use chrono::Utc;
    use uuid::Uuid;

    use crate::{
        AccountIdentity, Principal, PublicAccount, TenantContext, UserId, UserProfile, UserRole,
        ports::{
            AuthorizedApplication, AuthorizedApplicationRepositoryPort, GrantSummaryRepositoryPort,
            ProfileRepositoryPort, ProfileUpdate, RepositoryError, RepositoryFuture,
        },
    };

    use super::{
        AccountProfileService, ProfilePatch, ProfileValidationError, UpdateProfileError,
        normalize_profile_url, profile_text,
    };

    #[derive(Clone)]
    struct StoredProfileRepository {
        account: Arc<Mutex<PublicAccount>>,
        writes: Arc<AtomicUsize>,
    }

    impl ProfileRepositoryPort for StoredProfileRepository {
        fn update_profile<'a>(
            &'a self,
            _tenant_id: crate::TenantId,
            _user_id: UserId,
            update: ProfileUpdate,
        ) -> RepositoryFuture<'a, PublicAccount> {
            let mut account = self.account.lock().unwrap();
            account.profile = update.profile;
            self.writes.fetch_add(1, Ordering::Relaxed);
            let account = account.clone();
            Box::pin(async move { Ok(account) })
        }
    }

    #[derive(Clone)]
    struct FailFirstGrantSummary {
        calls: Arc<AtomicUsize>,
    }

    impl GrantSummaryRepositoryPort for FailFirstGrantSummary {
        fn authorized_client_count(&self, _user_id: Uuid) -> RepositoryFuture<'_, i64> {
            let call = self.calls.fetch_add(1, Ordering::Relaxed);
            Box::pin(async move {
                if call == 0 {
                    Err(RepositoryError::Unavailable)
                } else {
                    Ok(2)
                }
            })
        }
    }

    #[derive(Clone, Copy)]
    struct EmptyApplications;

    impl AuthorizedApplicationRepositoryPort for EmptyApplications {
        fn applications_for_user(
            &self,
            _user_id: Uuid,
        ) -> RepositoryFuture<'_, Vec<AuthorizedApplication>> {
            Box::pin(async { Ok(Vec::new()) })
        }
    }

    fn account() -> PublicAccount {
        let now = Utc::now();
        PublicAccount {
            principal: Principal {
                user_id: UserId::new(Uuid::from_u128(10)).unwrap(),
                tenant: TenantContext::default(),
                role: UserRole::User,
                active: true,
            },
            account: AccountIdentity {
                username: "alice".to_owned(),
                email: "alice@example.test".to_owned(),
                email_verified: true,
                mfa_enabled: false,
            },
            profile: UserProfile::default(),
            created_at: now,
            updated_at: now,
        }
    }

    #[test]
    fn profile_text_trims_blanks_and_enforces_byte_limit() {
        assert_eq!(profile_text(None, 8, "name").unwrap(), None);
        assert_eq!(profile_text(Some("   ".into()), 8, "name").unwrap(), None);
        assert_eq!(
            profile_text(Some(" Alice ".into()), 8, "name").unwrap(),
            Some("Alice".into())
        );
        assert_eq!(
            profile_text(Some("abcdefghi".into()), 8, "name"),
            Err(ProfileValidationError::FieldTooLong("name"))
        );
    }

    #[test]
    fn profile_url_accepts_only_absolute_http_urls() {
        assert_eq!(
            normalize_profile_url(Some(" https://example.com/u ".into()), "profile_url").unwrap(),
            Some("https://example.com/u".into())
        );
        for value in ["relative", "/relative", "javascript:alert(1)", "mailto:a@b"] {
            assert_eq!(
                normalize_profile_url(Some(value.into()), "profile_url"),
                Err(if matches!(value, "relative" | "/relative") {
                    ProfileValidationError::InvalidAbsoluteUrl("profile_url")
                } else {
                    ProfileValidationError::InvalidHttpUrl("profile_url")
                })
            );
        }
    }

    #[tokio::test]
    async fn retry_is_idempotent_when_profile_write_succeeds_before_overview_failure() {
        let original = account();
        let stored = Arc::new(Mutex::new(original.clone()));
        let writes = Arc::new(AtomicUsize::new(0));
        let service = AccountProfileService::new(
            StoredProfileRepository {
                account: stored.clone(),
                writes: writes.clone(),
            },
            FailFirstGrantSummary {
                calls: Arc::new(AtomicUsize::new(0)),
            },
            EmptyApplications,
        );
        let patch = ProfilePatch {
            display_name: Some(" Alice ".to_owned()),
            ..ProfilePatch::default()
        };

        let first = service.update(&original, patch.clone()).await;
        assert_eq!(
            first,
            Err(UpdateProfileError::OverviewRepository(
                RepositoryError::Unavailable
            ))
        );
        assert_eq!(
            stored.lock().unwrap().profile.display_name.as_deref(),
            Some("Alice"),
            "the profile write is committed before the independent overview read"
        );

        let retry = service.update(&original, patch).await.unwrap();
        assert_eq!(retry.account.profile.display_name.as_deref(), Some("Alice"));
        assert_eq!(retry.authorized_application_count, 2);
        assert_eq!(writes.load(Ordering::Relaxed), 2);
        assert_eq!(
            stored.lock().unwrap().profile.display_name.as_deref(),
            Some("Alice"),
            "repeating the same full profile replacement must not compound state"
        );
    }

    #[tokio::test]
    async fn profile_update_normalizes_only_profile_fields_and_resets_changed_phone_verification() {
        let mut original = account();
        original.profile.phone_number = Some("+15550000001".to_owned());
        original.profile.phone_number_verified = true;
        let stored = Arc::new(Mutex::new(original.clone()));
        let service = AccountProfileService::new(
            StoredProfileRepository {
                account: stored.clone(),
                writes: Arc::new(AtomicUsize::new(0)),
            },
            FailFirstGrantSummary {
                calls: Arc::new(AtomicUsize::new(1)),
            },
            EmptyApplications,
        );

        let updated = service
            .update(
                &original,
                ProfilePatch {
                    display_name: Some("  Alice Example  ".to_owned()),
                    given_name: Some(" Alice ".to_owned()),
                    middle_name: Some("   ".to_owned()),
                    profile_url: Some(" https://profile.example/alice ".to_owned()),
                    phone_number: Some(" +15559999999 ".to_owned()),
                    ..ProfilePatch::default()
                },
            )
            .await
            .unwrap();

        assert_eq!(updated.account.account.email, original.account.email);
        assert_eq!(updated.account.principal.role, original.principal.role);
        assert_eq!(
            updated.account.profile.display_name.as_deref(),
            Some("Alice Example")
        );
        assert_eq!(updated.account.profile.given_name.as_deref(), Some("Alice"));
        assert_eq!(updated.account.profile.middle_name, None);
        assert_eq!(
            updated.account.profile.profile_url.as_deref(),
            Some("https://profile.example/alice")
        );
        assert_eq!(
            updated.account.profile.phone_number.as_deref(),
            Some("+15559999999")
        );
        assert!(!updated.account.profile.phone_number_verified);
        assert_eq!(stored.lock().unwrap().profile, updated.account.profile);
    }
}
