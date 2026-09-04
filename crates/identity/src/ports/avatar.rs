use std::collections::BTreeMap;

use chrono::{DateTime, Utc};

use crate::{AvatarContentType, AvatarObject, PublicAccount, TenantId, UserId};

use super::common::{AvatarStorageFuture, RepositoryFuture};

/// Persistence boundary for compare-and-set avatar metadata updates.
///
/// The expected URL is part of the write contract so a stale upload/delete
/// cannot overwrite a newer request after its file mutation has completed.
pub trait AvatarRepositoryPort: Send + Sync {
    fn compare_and_set_avatar<'a>(
        &'a self,
        tenant_id: TenantId,
        user_id: UserId,
        expected_avatar_url: Option<&'a str>,
        avatar_url: Option<String>,
    ) -> RepositoryFuture<'a, Option<PublicAccount>>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AvatarStorageError {
    Conflict,
    Missing,
    InvalidState,
    PreparationFailed(String),
    Unavailable(String),
    Unsupported,
}

impl std::fmt::Display for AvatarStorageError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Conflict => formatter.write_str("avatar storage state changed concurrently"),
            Self::Missing => formatter.write_str("avatar storage object is missing"),
            Self::InvalidState => formatter.write_str("avatar storage state is invalid"),
            Self::PreparationFailed(message) => {
                write!(formatter, "avatar storage preparation failed: {message}")
            }
            Self::Unavailable(message) => {
                write!(formatter, "avatar storage unavailable: {message}")
            }
            Self::Unsupported => formatter.write_str("avatar storage capability is unavailable"),
        }
    }
}

/// A provider-neutral browser upload request. The caller forwards these opaque
/// values verbatim; neither identity nor HTTP code understands object-store
/// headers, buckets, or signatures.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AvatarUploadTarget {
    pub url: String,
    pub method: String,
    pub headers: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AvatarStagedObject {
    pub bytes: Vec<u8>,
    /// Provider-issued immutable snapshot identifier (for example an ETag).
    pub version: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AvatarUploadAuthorization {
    pub upload_id: String,
    pub tenant_id: TenantId,
    pub user_id: UserId,
    pub expected_avatar_url: Option<String>,
    pub staging_object_id: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AvatarUploadClaim {
    Pending {
        authorization: AvatarUploadAuthorization,
        ownership_token: String,
    },
    /// A previous worker fixed the exact staged snapshot and immutable
    /// candidate before publishing. A new lease must resume this same work.
    Publishing {
        authorization: AvatarUploadAuthorization,
        ownership_token: String,
        staged_version: String,
        final_object_id: String,
    },
    Completed {
        final_object_id: String,
    },
    Busy,
    Missing,
}

/// Short-lived, tenant-scoped authorization state. Implementations must make
/// claims atomic and refuse completion or release from a stale owner token.
pub trait AvatarUploadStatePort: Send + Sync {
    fn create<'a>(
        &'a self,
        authorization: &'a AvatarUploadAuthorization,
        ttl_seconds: u64,
    ) -> RepositoryFuture<'a, ()>;

    fn claim<'a>(
        &'a self,
        user_id: UserId,
        upload_id: &'a str,
        lease_until: DateTime<Utc>,
    ) -> RepositoryFuture<'a, AvatarUploadClaim>;

    /// Records the only candidate this upload may publish. The owner token
    /// prevents an expired worker from fixing data for a newer lease.
    fn record_candidate<'a>(
        &'a self,
        user_id: UserId,
        upload_id: &'a str,
        ownership_token: &'a str,
        staged_version: &'a str,
        final_object_id: &'a str,
    ) -> RepositoryFuture<'a, bool>;

    fn complete<'a>(
        &'a self,
        user_id: UserId,
        upload_id: &'a str,
        ownership_token: &'a str,
        final_object_id: &'a str,
    ) -> RepositoryFuture<'a, bool>;

    fn release<'a>(
        &'a self,
        user_id: UserId,
        upload_id: &'a str,
        ownership_token: &'a str,
    ) -> RepositoryFuture<'a, bool>;
}

/// Object-store capability bound by the composition root to one tenant.
/// Final object identifiers are application-generated opaque values. The
/// authorization target is bound to the caller's declared request-body length;
/// completion still applies the service's maximum read bound.
pub trait AvatarDirectUploadPort: Send + Sync {
    fn authorize_upload<'a>(
        &'a self,
        staging_object_id: &'a str,
        content_length: usize,
        expires_at: DateTime<Utc>,
    ) -> AvatarStorageFuture<'a, AvatarUploadTarget>;

    fn read_staged<'a>(
        &'a self,
        staging_object_id: &'a str,
        max_bytes: usize,
    ) -> AvatarStorageFuture<'a, AvatarStagedObject>;

    fn publish_staged<'a>(
        &'a self,
        staging_object_id: &'a str,
        expected_version: &'a str,
        final_object_id: &'a str,
        content_type: AvatarContentType,
    ) -> AvatarStorageFuture<'a, ()>;

    fn read_final<'a>(&'a self, final_object_id: &'a str) -> AvatarStorageFuture<'a, AvatarObject>;

    fn delete_staging<'a>(&'a self, staging_object_id: &'a str) -> AvatarStorageFuture<'a, ()>;

    /// Deletes a final object only after its database reference has been
    /// compare-and-set away. Ambiguous metadata failures must retain it.
    fn delete_final<'a>(&'a self, final_object_id: &'a str) -> AvatarStorageFuture<'a, ()>;
}

impl std::error::Error for AvatarStorageError {}

pub trait AvatarStoragePort: Send + Sync {
    type Mutation: Send + Sync;

    fn begin_replace<'a>(
        &'a self,
        user_id: UserId,
        expected_version: Option<&'a str>,
        avatar: AvatarObject,
    ) -> AvatarStorageFuture<'a, Self::Mutation>;

    fn begin_delete<'a>(
        &'a self,
        user_id: UserId,
        expected_version: Option<&'a str>,
        revision: &'a str,
    ) -> AvatarStorageFuture<'a, Self::Mutation>;

    fn commit<'a>(&'a self, mutation: &'a Self::Mutation) -> AvatarStorageFuture<'a, ()>;

    fn rollback<'a>(&'a self, mutation: &'a Self::Mutation) -> AvatarStorageFuture<'a, ()>;

    fn read<'a>(
        &'a self,
        user_id: UserId,
        expected_version: &'a str,
    ) -> AvatarStorageFuture<'a, AvatarObject>;
}
