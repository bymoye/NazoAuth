use crate::{AvatarObject, PublicAccount, TenantId, UserId};

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
        }
    }
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
