#![forbid(unsafe_code)]

//! Concrete local and S3-compatible avatar object storage adapters.
//!
//! S3 credentials, bucket topology, and signing live here.  The identity
//! crate receives only its provider-neutral object-store port.

mod local;
mod s3;

pub use local::{LocalAvatarObjectStore, LocalAvatarObjectStoreProvider};
pub use s3::{
    AvatarObjectStoreLauncher, S3AvatarObjectStore, S3AvatarObjectStoreConfig,
    S3AvatarObjectStoreProvider,
};
