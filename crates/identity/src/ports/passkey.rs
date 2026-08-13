use chrono::{DateTime, Utc};
use serde_json::Value;
use uuid::Uuid;

use crate::{PublicAccount, TenantId, UserId};

use super::common::RepositoryFuture;

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
