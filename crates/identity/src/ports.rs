use std::{collections::HashMap, sync::Mutex};
use std::{future::Future, pin::Pin};

use chrono::{DateTime, Utc};
use serde_json::Value;
use uuid::Uuid;

use crate::{
    AccessRequest, IdentityModelError, NewAccessRequest, PasswordHash, Principal, PublicAccount,
    SubjectClaims, TenantContext, TenantId, UserId, UserProfile,
};

pub type RepositoryFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, RepositoryError>> + Send + 'a>>;
pub type AvatarStorageFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, AvatarStorageError>> + Send + 'a>>;
pub type SecretVerifyFuture<'a> =
    Pin<Box<dyn Future<Output = Result<bool, SecretVerifyError>> + Send + 'a>>;
pub type MfaHashFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, MfaHashError>> + Send + 'a>>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RepositoryError {
    Unavailable,
    Conflict,
    AlreadyProcessed,
    NotFound,
    Consistency(String),
    Unexpected(String),
}

impl std::fmt::Display for RepositoryError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unavailable => formatter.write_str("repository unavailable"),
            Self::Conflict => formatter.write_str("repository conflict"),
            Self::AlreadyProcessed => formatter.write_str("repository value already processed"),
            Self::NotFound => formatter.write_str("repository value not found"),
            Self::Consistency(message) => {
                write!(formatter, "repository consistency error: {message}")
            }
            Self::Unexpected(message) => {
                write!(formatter, "unexpected repository error: {message}")
            }
        }
    }
}

impl std::error::Error for RepositoryError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TotpCredential {
    pub secret_base32: String,
    pub last_used_step: Option<i64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TotpEnrollment {
    pub secret_base32: String,
    pub confirmed: bool,
    pub last_used_step: Option<i64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TotpVerificationOutcome {
    Accepted,
    Invalid,
    Replay,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncodedSecretHash(String);

impl EncodedSecretHash {
    pub fn new(value: impl Into<String>) -> Result<Self, IdentityModelError> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(IdentityModelError::EmptyPasswordHash);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackupCodeCandidate {
    pub id: Uuid,
    pub hash: EncodedSecretHash,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MfaHashError {
    Busy,
    Failed,
}

pub trait MfaSecretHashPort: Send + Sync {
    fn hash_secrets(&self, secrets: Vec<String>) -> MfaHashFuture<'_, Vec<EncodedSecretHash>>;

    fn find_matching_secret(
        &self,
        secret: String,
        candidates: Vec<EncodedSecretHash>,
    ) -> MfaHashFuture<'_, Option<usize>>;
}

#[derive(Clone, Debug, PartialEq)]
pub struct PasskeyCredential {
    pub id: Uuid,
    pub tenant_id: TenantId,
    pub user_id: UserId,
    pub credential_id: String,
    pub credential: Value,
    pub label: String,
    pub sign_count: i64,
    pub last_used_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct FederationLink {
    pub id: Uuid,
    pub tenant_id: TenantId,
    pub user_id: UserId,
    pub provider_type: String,
    pub provider_id: String,
    pub subject: String,
    pub email: String,
    pub claims: Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_login_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct NewFederationLink {
    pub tenant_id: TenantId,
    pub user_id: UserId,
    pub provider_type: String,
    pub provider_id: String,
    pub subject: String,
    pub email: String,
    pub claims: Value,
}

#[derive(Clone, Debug)]
pub struct FederationLogin {
    pub tenant: TenantContext,
    pub provider_type: String,
    pub provider_id: String,
    pub subject: String,
    pub email: Option<String>,
    pub claims: Value,
}

#[derive(Clone, Debug)]
pub struct NewFederatedIdentity {
    pub login: FederationLogin,
    pub email: String,
    pub display_name: Option<String>,
    pub password_hash: PasswordHashInput,
}

/// Write-side password verifier material.
///
/// This capability is accepted only by new-identity commands. Authentication
/// projections return [`PasswordHash`], which deliberately has no extraction
/// API.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PasswordHashInput(String);

impl PasswordHashInput {
    pub fn new(value: impl Into<String>) -> Result<Self, IdentityModelError> {
        let value = value.into();
        PasswordHash::new(value.clone())?;
        Ok(Self(value))
    }

    #[must_use]
    pub fn into_persistence_value(self) -> String {
        self.0
    }
}

#[derive(Clone, Debug)]
pub struct NewUser {
    pub tenant: TenantContext,
    pub username: String,
    pub email: String,
    pub password_hash: PasswordHashInput,
    pub email_verified: bool,
}

#[derive(Clone, Debug)]
pub struct ProfileUpdate {
    pub profile: UserProfile,
}

#[derive(Clone, Debug)]
pub struct AdminUserUpdate {
    pub role: Option<String>,
    pub admin_level: Option<i32>,
    pub active: Option<bool>,
}

#[derive(Clone, Debug)]
pub struct UserPage {
    pub total: i64,
    pub users: Vec<crate::PublicAccount>,
}

/// Persistence boundary for administrative account listing and atomic policy updates.
///
/// The update operation intentionally remains a single repository call: the
/// implementation must load the actor and target, evaluate
/// [`crate::authorize_admin_update`], and persist the result in one transaction.
pub trait AdminUserRepositoryPort: Send + Sync {
    fn page(&self, tenant_id: TenantId, limit: i64, offset: i64) -> RepositoryFuture<'_, UserPage>;

    fn update_authorized(
        &self,
        tenant_id: TenantId,
        actor_id: UserId,
        target_id: UserId,
        update: AdminUserUpdate,
    ) -> RepositoryFuture<'_, crate::AdminUserUpdateOutcome>;
}

#[derive(Clone, Debug)]
pub struct ScimListQuery {
    pub tenant_id: TenantId,
    pub email: Option<String>,
    pub after: Option<(DateTime<Utc>, Uuid)>,
    pub limit: i64,
    pub offset: i64,
}

#[derive(Clone, Debug)]
pub struct NewScimUser {
    pub tenant: TenantContext,
    pub input: crate::scim::NormalizedScimUser,
    pub password_hash: PasswordHashInput,
}

pub trait ScimRepositoryPort: Send + Sync {
    fn list<'a>(&'a self, query: ScimListQuery) -> RepositoryFuture<'a, UserPage>;

    fn get<'a>(
        &'a self,
        tenant: TenantContext,
        user_id: UserId,
    ) -> RepositoryFuture<'a, Option<crate::PublicAccount>>;

    fn create<'a>(&'a self, new_user: NewScimUser) -> RepositoryFuture<'a, crate::PublicAccount>;

    fn replace<'a>(
        &'a self,
        tenant: TenantContext,
        user_id: UserId,
        replacement: crate::scim::NormalizedScimUser,
    ) -> RepositoryFuture<'a, crate::PublicAccount>;

    fn patch<'a>(
        &'a self,
        tenant: TenantContext,
        user_id: UserId,
        patch: crate::scim::ScimPatch,
    ) -> RepositoryFuture<'a, crate::PublicAccount>;

    fn deactivate<'a>(
        &'a self,
        tenant: TenantContext,
        user_id: UserId,
    ) -> RepositoryFuture<'a, bool>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScimCredentialUse {
    pub token_id: Uuid,
    pub tenant_id: Uuid,
    pub scopes: Vec<String>,
    pub ip_hash: Option<String>,
    pub user_agent_hash: Option<String>,
}

pub trait ScimCredentialAuditPort: Send + Sync {
    fn active_credential<'a>(
        &'a self,
        token_hash: &'a str,
    ) -> RepositoryFuture<'a, Option<crate::scim::ScimTokenCredential>>;

    fn record_use<'a>(&'a self, usage: ScimCredentialUse) -> RepositoryFuture<'a, ()>;
}

pub trait UserRepositoryPort: Send + Sync {
    fn principal_by_id<'a>(
        &'a self,
        tenant: TenantContext,
        user_id: UserId,
    ) -> RepositoryFuture<'a, Option<Principal>>;

    fn subject_claims_by_id<'a>(
        &'a self,
        tenant: TenantContext,
        user_id: UserId,
    ) -> RepositoryFuture<'a, Option<SubjectClaims>>;
}

pub trait ProfileRepositoryPort: Send + Sync {
    fn update_profile<'a>(
        &'a self,
        tenant_id: TenantId,
        user_id: UserId,
        update: ProfileUpdate,
    ) -> RepositoryFuture<'a, PublicAccount>;
}

/// Persistence boundary for compare-and-set avatar metadata updates.
///
/// The expected URL is part of the write contract so a stale upload/delete cannot
/// overwrite a newer request after its file mutation has completed.
pub trait AvatarRepositoryPort: Send + Sync {
    fn compare_and_set_avatar<'a>(
        &'a self,
        tenant_id: TenantId,
        user_id: UserId,
        expected_avatar_url: Option<&'a str>,
        avatar_url: Option<String>,
    ) -> RepositoryFuture<'a, Option<PublicAccount>>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AvatarStorageError {
    Conflict,
    Missing,
    InvalidState,
    PreparationFailed(String),
    Unavailable(String),
}

impl std::fmt::Display for AvatarStorageError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Conflict => formatter.write_str("avatar storage state changed concurrently"),
            Self::Missing => formatter.write_str("avatar storage object is missing"),
            Self::InvalidState => formatter.write_str("avatar storage state is invalid"),
            Self::PreparationFailed(message) => {
                write!(formatter, "avatar storage preparation failed: {message}")
            }
            Self::Unavailable(message) => {
                write!(formatter, "avatar storage unavailable: {message}")
            }
        }
    }
}

impl std::error::Error for AvatarStorageError {}

pub trait AvatarStoragePort: Send + Sync {
    type Mutation: Send + Sync;

    fn begin_replace<'a>(
        &'a self,
        user_id: UserId,
        expected_version: Option<&'a str>,
        avatar: crate::AvatarObject,
    ) -> AvatarStorageFuture<'a, Self::Mutation>;

    fn begin_delete<'a>(
        &'a self,
        user_id: UserId,
        expected_version: Option<&'a str>,
        revision: &'a str,
    ) -> AvatarStorageFuture<'a, Self::Mutation>;

    fn commit<'a>(&'a self, mutation: &'a Self::Mutation) -> AvatarStorageFuture<'a, ()>;

    fn rollback<'a>(&'a self, mutation: &'a Self::Mutation) -> AvatarStorageFuture<'a, ()>;

    fn read<'a>(
        &'a self,
        user_id: UserId,
        expected_version: &'a str,
    ) -> AvatarStorageFuture<'a, crate::AvatarObject>;
}

pub trait GrantSummaryRepositoryPort: Send + Sync {
    fn authorized_client_count(&self, user_id: Uuid) -> RepositoryFuture<'_, i64>;
}

#[derive(Clone, Debug, PartialEq)]
pub struct AuthorizedApplication {
    pub client_id: String,
    pub client_name: String,
    pub last_scopes: Value,
    pub last_authorized_at: DateTime<Utc>,
    pub authorization_count: i32,
}

pub trait AuthorizedApplicationRepositoryPort: Send + Sync {
    fn applications_for_user(
        &self,
        user_id: Uuid,
    ) -> RepositoryFuture<'_, Vec<AuthorizedApplication>>;
}

pub trait AccessRequestRepositoryPort: Send + Sync {
    fn list_for_user(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> RepositoryFuture<'_, Vec<AccessRequest>>;

    fn create(&self, request: NewAccessRequest) -> RepositoryFuture<'_, AccessRequest>;

    fn approved_delivery_matches<'a>(
        &'a self,
        tenant_id: TenantId,
        user_id: UserId,
        request_id: Uuid,
        approved_client_id: Uuid,
        client_id: &'a str,
    ) -> RepositoryFuture<'a, bool>;
}

#[derive(Clone, Debug, PartialEq)]
pub struct DeliveryRecord {
    pub value: Value,
    pub opaque_version: String,
}

#[derive(Clone, Debug, PartialEq)]
pub enum DeliveryConsume {
    Consumed(Value),
    MissingOrChanged,
}

pub trait DeliveryStorePort: Send + Sync {
    fn load<'a>(
        &'a self,
        user_id: UserId,
        token: &'a str,
    ) -> RepositoryFuture<'a, Option<DeliveryRecord>>;

    fn load_many<'a>(
        &'a self,
        lookups: &'a [(UserId, &'a str)],
    ) -> RepositoryFuture<'a, Vec<Option<DeliveryRecord>>>;

    fn delete<'a>(&'a self, user_id: UserId, token: &'a str) -> RepositoryFuture<'a, ()>;

    fn consume<'a>(
        &'a self,
        user_id: UserId,
        token: &'a str,
        expected: &'a DeliveryRecord,
    ) -> RepositoryFuture<'a, DeliveryConsume>;
}

pub trait FederationLinkRepositoryPort: Send + Sync {
    fn list(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> RepositoryFuture<'_, Vec<FederationLink>>;

    fn delete(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
        link_id: Uuid,
    ) -> RepositoryFuture<'_, Option<FederationLink>>;
}

pub trait FederationLoginRepositoryPort: Send + Sync {
    fn resolve_existing(
        &self,
        login: FederationLogin,
    ) -> RepositoryFuture<'_, Option<PublicAccount>>;

    fn account_by_email<'a>(
        &'a self,
        tenant_id: TenantId,
        email: &'a str,
    ) -> RepositoryFuture<'a, Option<PublicAccount>>;

    fn create_federated(
        &self,
        identity: NewFederatedIdentity,
    ) -> RepositoryFuture<'_, PublicAccount>;
}

pub trait FederationStatePort: Send + Sync {
    fn store_oidc<'a>(
        &'a self,
        state: &'a str,
        value: &'a crate::federation::OidcFederationState,
        ttl_seconds: u64,
    ) -> RepositoryFuture<'a, ()>;

    fn take_oidc<'a>(
        &'a self,
        state: &'a str,
    ) -> RepositoryFuture<'a, Option<crate::federation::OidcFederationState>>;

    fn store_social<'a>(
        &'a self,
        state: &'a str,
        value: &'a crate::federation::SocialFederationState,
        ttl_seconds: u64,
    ) -> RepositoryFuture<'a, ()>;

    fn take_social<'a>(
        &'a self,
        state: &'a str,
    ) -> RepositoryFuture<'a, Option<crate::federation::SocialFederationState>>;

    fn reserve_saml_replay<'a>(
        &'a self,
        assertion_signature: &'a str,
        ttl_seconds: u64,
    ) -> RepositoryFuture<'a, bool>;
}

pub trait FederationPasswordHasherPort: Send + Sync {
    fn hash_bootstrap_secret(&self) -> RepositoryFuture<'_, PasswordHashInput>;
}

pub trait FederationAuditPort: Send + Sync {
    fn record(&self, event: crate::federation::FederationAuditEvent);
}

pub trait RegistrationAccountRepositoryPort: Send + Sync {
    fn account_by_email<'a>(
        &'a self,
        tenant_id: TenantId,
        email: &'a str,
    ) -> RepositoryFuture<'a, Option<PublicAccount>>;

    fn create_user(&self, user: NewUser) -> RepositoryFuture<'_, PublicAccount>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EmailVerificationRecord {
    pub password_hash: PasswordHash,
    pub opaque_version: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EmailVerificationConsume {
    Consumed,
    MissingOrChanged,
}

pub trait EmailVerificationStorePort: Send + Sync {
    fn reserve_peer_send<'a>(
        &'a self,
        subject: &'a str,
        ttl_seconds: u64,
    ) -> RepositoryFuture<'a, bool>;

    fn reserve_email_send<'a>(
        &'a self,
        email: &'a str,
        ttl_seconds: u64,
    ) -> RepositoryFuture<'a, bool>;

    fn store_code<'a>(
        &'a self,
        email: &'a str,
        password_hash: PasswordHashInput,
        ttl_seconds: u64,
    ) -> RepositoryFuture<'a, ()>;

    fn load_code<'a>(
        &'a self,
        email: &'a str,
    ) -> RepositoryFuture<'a, Option<EmailVerificationRecord>>;

    fn consume_code<'a>(
        &'a self,
        email: &'a str,
        expected: &'a EmailVerificationRecord,
    ) -> RepositoryFuture<'a, EmailVerificationConsume>;

    fn delete_code<'a>(&'a self, email: &'a str) -> RepositoryFuture<'a, ()>;
    fn release_email_send<'a>(&'a self, email: &'a str) -> RepositoryFuture<'a, ()>;
    fn release_peer_send<'a>(&'a self, subject: &'a str) -> RepositoryFuture<'a, ()>;
}

pub trait SecretHashPort: Send + Sync {
    fn hash_secret(&self, secret: String) -> RepositoryFuture<'_, PasswordHashInput>;

    fn verify_secret(
        &self,
        secret: String,
        password_hash: PasswordHash,
    ) -> RepositoryFuture<'_, bool>;
}

pub trait VerificationEmailDeliveryPort: Send + Sync {
    fn deliver<'a>(
        &'a self,
        normalized_email: &'a str,
        code: &'a str,
        code_ttl_seconds: u64,
    ) -> RepositoryFuture<'a, ()>;
}

pub trait LoginAccountRepositoryPort: Send + Sync {
    fn authentication_by_email<'a>(
        &'a self,
        tenant_id: TenantId,
        email: &'a str,
    ) -> RepositoryFuture<'a, Option<crate::AuthenticationIdentity>>;

    fn public_account_by_id(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> RepositoryFuture<'_, Option<PublicAccount>>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LoginFailureCounts {
    pub email: u64,
    pub ip_email: u64,
}

pub trait LoginThrottlePort: Send + Sync {
    fn failure_counts<'a>(
        &'a self,
        email: &'a str,
        source_ip: &'a str,
    ) -> RepositoryFuture<'a, LoginFailureCounts>;

    fn record_failure<'a>(
        &'a self,
        email: &'a str,
        source_ip: &'a str,
        window_seconds: u64,
    ) -> RepositoryFuture<'a, ()>;

    fn clear_failures<'a>(&'a self, email: &'a str, source_ip: &'a str)
    -> RepositoryFuture<'a, ()>;
}

pub trait SecretVerifyPort: Send + Sync {
    fn verify_secret(&self, secret: String, password_hash: PasswordHash) -> SecretVerifyFuture<'_>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecretVerifyError {
    Busy,
    Failed,
}

pub trait RememberedMfaDevicePort: Send + Sync {
    fn is_valid<'a>(
        &'a self,
        account: &'a PublicAccount,
        token_hash: &'a str,
        user_agent_hash: Option<&'a str>,
        now: DateTime<Utc>,
    ) -> RepositoryFuture<'a, bool>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LoginSessionCreate {
    Created,
    Collision,
}

pub trait LoginSessionPort: Send + Sync {
    fn create<'a>(
        &'a self,
        session_id: &'a str,
        record: &'a crate::session::SessionRecord,
        ttl_seconds: u64,
    ) -> RepositoryFuture<'a, LoginSessionCreate>;

    /// Creates a new login session and, when supplied, invalidates the
    /// previously presented session in the same storage transaction.
    ///
    /// Implementations must perform creation and invalidation atomically. This
    /// method intentionally has no fallback implementation: silently degrading
    /// to `create` would leave the previously authenticated session active.
    fn create_replacing<'a>(
        &'a self,
        previous_session_id: Option<&'a str>,
        session_id: &'a str,
        record: &'a crate::session::SessionRecord,
        ttl_seconds: u64,
    ) -> RepositoryFuture<'a, LoginSessionCreate>;
}

/// Reads the minimum account projection required to resolve an authenticated session.
pub trait SessionAccountPort: Send + Sync {
    fn public_account_by_id(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> RepositoryFuture<'_, Option<PublicAccount>>;
}

/// Persistence boundary for session lookup, deletion, and atomic rotation.
///
/// Implementations must treat `expected` as an opaque compare-and-swap snapshot.
/// A successful rotation must create the replacement and delete the old session
/// atomically; it must never expose both or neither as a partial success.
pub trait SessionStorePort: Send + Sync {
    fn load<'a>(
        &'a self,
        session_id: &'a crate::session::SessionId,
    ) -> RepositoryFuture<'a, Option<crate::session::SessionSnapshot>>;

    fn delete<'a>(
        &'a self,
        session_id: &'a crate::session::SessionId,
    ) -> RepositoryFuture<'a, bool>;

    fn rotate<'a>(
        &'a self,
        old_session_id: &'a crate::session::SessionId,
        expected: &'a crate::session::SessionSnapshot,
        new_session_id: &'a crate::session::SessionId,
        replacement: &'a crate::session::SessionRecord,
        ttl_seconds: u64,
    ) -> RepositoryFuture<'a, crate::session::SessionRotationOutcome>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthenticationAuditEvent {
    Failure {
        email: String,
        source_ip: String,
        user_id: Option<UserId>,
    },
    Success {
        user_id: UserId,
        source_ip: String,
        amr: Vec<String>,
    },
}

pub trait AuthenticationAuditPort: Send + Sync {
    fn record(&self, event: AuthenticationAuditEvent);
}

pub trait PasskeyAccountRepositoryPort: Send + Sync {
    fn by_email<'a>(
        &'a self,
        tenant_id: TenantId,
        email: &'a str,
    ) -> RepositoryFuture<'a, Option<PublicAccount>>;

    fn by_id(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> RepositoryFuture<'_, Option<PublicAccount>>;
}

pub trait PasskeyRepositoryPort: Send + Sync {
    fn list(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> RepositoryFuture<'_, Vec<PasskeyCredential>>;

    fn by_credential_id<'a>(
        &'a self,
        tenant_id: TenantId,
        user_id: UserId,
        credential_id: &'a str,
    ) -> RepositoryFuture<'a, Option<PasskeyCredential>>;

    fn insert(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
        credential_id: String,
        credential: Value,
        label: String,
        sign_count: i64,
    ) -> RepositoryFuture<'_, PasskeyCredential>;

    fn update_counter<'a>(
        &'a self,
        tenant_id: TenantId,
        user_id: UserId,
        credential_id: &'a str,
        expected_sign_count: i64,
        new_sign_count: i64,
        credential: Value,
    ) -> RepositoryFuture<'a, ()>;

    fn delete(&self, tenant_id: TenantId, user_id: UserId, id: Uuid) -> RepositoryFuture<'_, bool>;
}

pub trait PasskeyCeremonyPort: Send + Sync {
    fn store_registration<'a>(
        &'a self,
        ceremony_id: &'a str,
        ceremony: &'a crate::passkey::StoredPasskeyRegistration,
        ttl_seconds: u64,
    ) -> RepositoryFuture<'a, ()>;

    fn take_registration<'a>(
        &'a self,
        ceremony_id: &'a str,
    ) -> RepositoryFuture<'a, Option<crate::passkey::StoredPasskeyRegistration>>;

    fn store_authentication<'a>(
        &'a self,
        ceremony_id: &'a str,
        ceremony: &'a crate::passkey::StoredPasskeyAuthentication,
        ttl_seconds: u64,
    ) -> RepositoryFuture<'a, ()>;

    fn take_authentication<'a>(
        &'a self,
        ceremony_id: &'a str,
    ) -> RepositoryFuture<'a, Option<crate::passkey::StoredPasskeyAuthentication>>;
}

pub trait PasskeyAuditPort: Send + Sync {
    fn record(&self, event: crate::passkey::PasskeyAuditEvent);
}

pub trait MfaRepositoryPort: Send + Sync {
    fn totp_enrollment<'a>(
        &'a self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> RepositoryFuture<'a, Option<TotpEnrollment>>;

    fn begin_totp_enrollment(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
        secret: String,
        label: String,
    ) -> RepositoryFuture<'_, ()>;

    fn verify_and_confirm_totp<'a>(
        &'a self,
        tenant_id: TenantId,
        user_id: UserId,
        code: &'a str,
        timestamp: i64,
        hashes: Vec<EncodedSecretHash>,
    ) -> RepositoryFuture<'a, TotpVerificationOutcome>;

    fn record_invalid_totp_attempt(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> RepositoryFuture<'_, ()>;

    fn verify_and_consume_totp<'a>(
        &'a self,
        tenant_id: TenantId,
        user_id: UserId,
        code: &'a str,
        timestamp: i64,
    ) -> RepositoryFuture<'a, TotpVerificationOutcome>;

    fn totp_credential<'a>(
        &'a self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> RepositoryFuture<'a, Option<TotpCredential>>;
    fn compare_and_set_totp_step<'a>(
        &'a self,
        tenant_id: TenantId,
        user_id: UserId,
        step: i64,
    ) -> RepositoryFuture<'a, bool>;

    fn backup_code_candidates(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> RepositoryFuture<'_, Vec<BackupCodeCandidate>>;

    fn consume_backup_code_candidate(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
        candidate_id: Uuid,
    ) -> RepositoryFuture<'_, bool>;

    fn record_invalid_backup_code_attempt(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> RepositoryFuture<'_, ()>;

    fn replace_backup_code_hashes<'a>(
        &'a self,
        tenant_id: TenantId,
        user_id: UserId,
        hashes: Vec<EncodedSecretHash>,
    ) -> RepositoryFuture<'a, ()>;

    fn clear_mfa_state<'a>(
        &'a self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> RepositoryFuture<'a, ()>;

    fn remember_device(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
        token_hash: String,
        user_agent_hash: Option<String>,
        expires_at: DateTime<Utc>,
    ) -> RepositoryFuture<'_, ()>;
}

#[derive(Default)]
pub struct FakeUserRepository {
    principals: Mutex<HashMap<(TenantId, UserId), Principal>>,
    claims: Mutex<HashMap<(TenantId, UserId), SubjectClaims>>,
}

impl FakeUserRepository {
    pub fn insert_principal(&self, principal: Principal) {
        self.principals
            .lock()
            .expect("fake repository mutex poisoned")
            .insert((principal.tenant.tenant_id, principal.user_id), principal);
    }

    pub fn insert_subject_claims(&self, tenant_id: TenantId, claims: SubjectClaims) {
        self.claims
            .lock()
            .expect("fake repository mutex poisoned")
            .insert((tenant_id, claims.subject), claims);
    }
}

impl UserRepositoryPort for FakeUserRepository {
    fn principal_by_id<'a>(
        &'a self,
        tenant: TenantContext,
        user_id: UserId,
    ) -> RepositoryFuture<'a, Option<Principal>> {
        Box::pin(async move {
            Ok(self
                .principals
                .lock()
                .map_err(|error| RepositoryError::Unexpected(error.to_string()))?
                .get(&(tenant.tenant_id, user_id))
                .cloned())
        })
    }

    fn subject_claims_by_id<'a>(
        &'a self,
        tenant: TenantContext,
        user_id: UserId,
    ) -> RepositoryFuture<'a, Option<SubjectClaims>> {
        Box::pin(async move {
            Ok(self
                .claims
                .lock()
                .map_err(|error| RepositoryError::Unexpected(error.to_string()))?
                .get(&(tenant.tenant_id, user_id))
                .cloned())
        })
    }
}
