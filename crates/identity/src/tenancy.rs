use serde::{Deserialize, Deserializer, Serialize, de};
use uuid::Uuid;

use crate::IdentityModelError;

macro_rules! identity_id {
    ($name:ident) => {
        #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize)]
        #[serde(transparent)]
        pub struct $name(Uuid);

        impl $name {
            pub fn new(value: Uuid) -> Result<Self, IdentityModelError> {
                if value.is_nil() {
                    return Err(IdentityModelError::EmptyId);
                }
                Ok(Self(value))
            }

            #[must_use]
            pub const fn as_uuid(self) -> Uuid {
                self.0
            }
        }

        impl TryFrom<Uuid> for $name {
            type Error = IdentityModelError;

            fn try_from(value: Uuid) -> Result<Self, Self::Error> {
                Self::new(value)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = Uuid::deserialize(deserializer)?;
                Self::new(value).map_err(de::Error::custom)
            }
        }

        impl From<$name> for Uuid {
            fn from(value: $name) -> Self {
                value.0
            }
        }
    };
}

identity_id!(UserId);
identity_id!(TenantId);
identity_id!(RealmId);
identity_id!(OrganizationId);

pub const DEFAULT_TENANT_ID: Uuid = Uuid::from_u128(1);
pub const DEFAULT_REALM_ID: Uuid = Uuid::from_u128(2);
pub const DEFAULT_ORGANIZATION_ID: Uuid = Uuid::from_u128(3);

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TenantContext {
    pub tenant_id: TenantId,
    pub realm_id: RealmId,
    pub organization_id: OrganizationId,
}

impl TenantContext {
    #[must_use]
    pub fn default_system() -> Self {
        Self {
            tenant_id: TenantId(DEFAULT_TENANT_ID),
            realm_id: RealmId(DEFAULT_REALM_ID),
            organization_id: OrganizationId(DEFAULT_ORGANIZATION_ID),
        }
    }

    #[must_use]
    pub fn matches(
        self,
        tenant_id: TenantId,
        realm_id: RealmId,
        organization_id: OrganizationId,
    ) -> bool {
        self.tenant_id == tenant_id
            && self.realm_id == realm_id
            && self.organization_id == organization_id
    }

    #[must_use]
    pub fn matches_raw(self, tenant_id: Uuid, realm_id: Uuid, organization_id: Uuid) -> bool {
        self.tenant_id.as_uuid() == tenant_id
            && self.realm_id.as_uuid() == realm_id
            && self.organization_id.as_uuid() == organization_id
    }

    #[must_use]
    pub fn same_tenant(self, tenant_id: TenantId) -> bool {
        self.tenant_id == tenant_id
    }
}

impl Default for TenantContext {
    fn default() -> Self {
        Self::default_system()
    }
}
