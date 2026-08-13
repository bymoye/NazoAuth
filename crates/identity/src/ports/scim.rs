use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::{TenantContext, TenantId, UserId};

use super::{
    account::UserPage,
    common::{PasswordHashInput, RepositoryFuture},
};

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
    pub mutation: nazo_scim_events::MutationContext,
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
        mutation: nazo_scim_events::MutationContext,
    ) -> RepositoryFuture<'a, crate::PublicAccount>;

    fn patch<'a>(
        &'a self,
        tenant: TenantContext,
        user_id: UserId,
        patch: crate::scim::ScimPatch,
        mutation: nazo_scim_events::MutationContext,
    ) -> RepositoryFuture<'a, crate::PublicAccount>;

    fn deactivate<'a>(
        &'a self,
        tenant: TenantContext,
        user_id: UserId,
        mutation: nazo_scim_events::MutationContext,
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
