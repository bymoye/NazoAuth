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
#[path = "../../tests/unit/domain/tenancy.rs"]
mod tests;
