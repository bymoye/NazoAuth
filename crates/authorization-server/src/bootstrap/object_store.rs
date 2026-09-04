//! Backend-neutral avatar object-store composition.

use std::{path::PathBuf, sync::Arc};

use nazo_identity::{TenantId, ports::AvatarDirectUploadPort};

/// A tenant has storage only when the administrator configured a global
/// default or tenant override. The server selects a capability, never a
/// concrete storage protocol.
#[derive(Clone)]
pub enum ServerAvatarStorageCapability {
    Disabled,
    Local { directory: Option<PathBuf> },
    Direct(Arc<dyn AvatarDirectUploadPort>),
}

/// Object-store capabilities for one deployment. Providers bind storage to a
/// tenant before identity receives an object identifier, preventing shared
/// buckets from making user ids a cross-tenant namespace.
pub trait ServerAvatarObjectStoreProvider: Send + Sync {
    fn for_tenant(&self, tenant_id: TenantId) -> ServerAvatarStorageCapability;
}

#[derive(Clone)]
pub struct ServerAvatarObjectStoreBindings {
    provider: Arc<dyn ServerAvatarObjectStoreProvider>,
}

impl ServerAvatarObjectStoreBindings {
    #[must_use]
    pub fn new(provider: Arc<dyn ServerAvatarObjectStoreProvider>) -> Self {
        Self { provider }
    }

    pub(super) fn provider(&self) -> &Arc<dyn ServerAvatarObjectStoreProvider> {
        &self.provider
    }
}
