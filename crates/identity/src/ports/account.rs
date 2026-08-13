use std::{collections::HashMap, sync::Mutex};

use crate::{
    Principal, PublicAccount, SubjectClaims, TenantContext, TenantId, UserId, UserProfile,
};

use super::common::{PasswordHashInput, RepositoryError, RepositoryFuture};

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
/// implementation must load the actor and target, evaluate the authorization
/// policy, and persist the result in one transaction.
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
