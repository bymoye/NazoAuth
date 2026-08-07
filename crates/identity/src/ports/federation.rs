use chrono::{DateTime, Utc};
use serde_json::Value;
use uuid::Uuid;

use crate::{PublicAccount, TenantContext, TenantId, UserId};

use super::common::{PasswordHashInput, RepositoryFuture};

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
