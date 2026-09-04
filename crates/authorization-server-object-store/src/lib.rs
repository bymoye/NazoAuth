#![forbid(unsafe_code)]

//! Concrete S3-compatible avatar object storage adapter.
//!
//! S3 credentials, bucket topology, and signing live here.  The identity
//! crate receives only its provider-neutral object-store port.

mod s3;

use nazo_identity::TenantId;
use nazo_oauth_server::bootstrap::{
    ServerAvatarObjectStoreProvider, ServerAvatarStorageCapability,
};

/// Composition marker for the existing server-multipart local avatar path.
/// It deliberately has no direct-object implementation.
#[derive(Clone, Copy, Debug, Default)]
pub struct LocalAvatarObjectStoreProvider;

impl ServerAvatarObjectStoreProvider for LocalAvatarObjectStoreProvider {
    fn for_tenant(&self, _tenant_id: TenantId) -> ServerAvatarStorageCapability {
        ServerAvatarStorageCapability::Local { directory: None }
    }
}

pub use s3::{
    AvatarObjectStoreLauncher, S3AvatarObjectStore, S3AvatarObjectStoreConfig,
    S3AvatarObjectStoreProvider,
};
