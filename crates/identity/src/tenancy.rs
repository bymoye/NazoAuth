use serde::{Deserialize, Deserializer, Serialize, de};
use url::Url;
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

/// One active tenant's public routing identity and default placement.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TenantDirectoryBinding {
    pub tenant: TenantContext,
    pub issuer: String,
    pub external_host: String,
}

/// Immutable, revisioned view of every active tenant.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TenantDirectorySnapshot {
    pub revision: u64,
    pub tenants: Vec<TenantDirectoryBinding>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TenantHostError(&'static str);

impl std::fmt::Display for TenantHostError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.0)
    }
}

impl std::error::Error for TenantHostError {}

/// Canonicalizes the host identity shared by routing and directory caches.
pub fn canonical_tenant_host(host: &str) -> Result<String, TenantHostError> {
    let host = host.trim();
    if host.is_empty() {
        return Err(TenantHostError("tenant host must not be empty"));
    }
    if host.starts_with('[') {
        if !host.ends_with(']') {
            return Err(TenantHostError("tenant host must be a host without a port"));
        }
    } else if host.contains(':') {
        return Err(TenantHostError("tenant host must not include a port"));
    }

    let parsed = Url::parse(&format!("https://{host}/"))
        .map_err(|_| TenantHostError("tenant host is invalid"))?;
    if !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.port().is_some()
        || parsed.path() != "/"
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(TenantHostError(
            "tenant host must be a host without userinfo, path, query, fragment, or port",
        ));
    }
    let canonical = match parsed.host() {
        Some(url::Host::Domain(domain)) => domain.trim_end_matches('.').to_ascii_lowercase(),
        Some(url::Host::Ipv4(address)) => address.to_string(),
        Some(url::Host::Ipv6(address)) => format!("[{address}]"),
        None => return Err(TenantHostError("tenant host is invalid")),
    };
    if canonical.is_empty() {
        return Err(TenantHostError("tenant host must not be empty"));
    }
    Ok(canonical)
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

#[cfg(test)]
#[path = "../tests/unit/tenancy.rs"]
mod tests;
