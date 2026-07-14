#[cfg(test)]
use crate::domain::{ClientRow, DatabaseUserFixture};
#[cfg(test)]
use chrono::Utc;
#[cfg(test)]
use nazo_identity::PublicAccount;
#[cfg(test)]
use serde_json::json;
use uuid::Uuid;

pub(crate) const DEFAULT_TENANT_ID: Uuid = Uuid::from_u128(1);
pub(crate) const DEFAULT_REALM_ID: Uuid = Uuid::from_u128(2);
pub(crate) const DEFAULT_ORGANIZATION_ID: Uuid = Uuid::from_u128(3);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct TenantContext {
    pub(crate) tenant_id: Uuid,
    pub(crate) realm_id: Uuid,
    pub(crate) organization_id: Uuid,
}

impl Default for TenantContext {
    fn default() -> Self {
        Self {
            tenant_id: DEFAULT_TENANT_ID,
            realm_id: DEFAULT_REALM_ID,
            organization_id: DEFAULT_ORGANIZATION_ID,
        }
    }
}

impl TenantContext {
    #[cfg(test)]
    pub(crate) fn includes_user(&self, user: &PublicAccount) -> bool {
        self.as_identity_context().is_some_and(|context| {
            context.matches_raw(user.tenant_id(), user.realm_id(), user.organization_id())
        })
    }

    #[cfg(test)]
    pub(crate) fn includes_client(&self, client: &ClientRow) -> bool {
        self.as_identity_context().is_some_and(|context| {
            context.matches_raw(client.tenant_id, client.realm_id, client.organization_id)
        })
    }

    #[cfg(test)]
    pub(crate) fn same_tenant(&self, tenant_id: Uuid) -> bool {
        self.as_identity_context().is_some_and(|context| {
            nazo_identity::TenantId::new(tenant_id)
                .is_ok_and(|tenant_id| context.same_tenant(tenant_id))
        })
    }

    pub(crate) fn as_identity_context(&self) -> Option<nazo_identity::TenantContext> {
        Some(nazo_identity::TenantContext {
            tenant_id: nazo_identity::TenantId::new(self.tenant_id).ok()?,
            realm_id: nazo_identity::RealmId::new(self.realm_id).ok()?,
            organization_id: nazo_identity::OrganizationId::new(self.organization_id).ok()?,
        })
    }
}

pub(crate) fn default_tenant_context() -> TenantContext {
    TenantContext::default()
}

#[cfg(test)]
#[path = "../../tests/in_source/src/support/tests/tenancy.rs"]
mod tests;
