use crate::{PublicAccount, TenantId, UserId};

use super::common::RepositoryFuture;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LoginSessionCreate {
    Created,
    Collision,
}

pub trait LoginSessionPort: Send + Sync {
    fn create<'a>(
        &'a self,
        session_id: &'a str,
        record: &'a crate::session::SessionRecord,
        ttl_seconds: u64,
    ) -> RepositoryFuture<'a, LoginSessionCreate>;

    /// Creates a new login session and, when supplied, invalidates the
    /// previously presented session in the same storage transaction.
    ///
    /// Implementations must perform creation and invalidation atomically. This
    /// method intentionally has no fallback implementation: silently degrading
    /// to create would leave the previously authenticated session active.
    fn create_replacing<'a>(
        &'a self,
        previous_session_id: Option<&'a str>,
        session_id: &'a str,
        record: &'a crate::session::SessionRecord,
        ttl_seconds: u64,
    ) -> RepositoryFuture<'a, LoginSessionCreate>;
}

impl<T> LoginSessionPort for std::sync::Arc<T>
where
    T: LoginSessionPort + ?Sized,
{
    fn create<'a>(
        &'a self,
        session_id: &'a str,
        record: &'a crate::session::SessionRecord,
        ttl_seconds: u64,
    ) -> RepositoryFuture<'a, LoginSessionCreate> {
        self.as_ref().create(session_id, record, ttl_seconds)
    }

    fn create_replacing<'a>(
        &'a self,
        previous_session_id: Option<&'a str>,
        session_id: &'a str,
        record: &'a crate::session::SessionRecord,
        ttl_seconds: u64,
    ) -> RepositoryFuture<'a, LoginSessionCreate> {
        self.as_ref()
            .create_replacing(previous_session_id, session_id, record, ttl_seconds)
    }
}

/// Reads the minimum account projection required to resolve an authenticated session.
pub trait SessionAccountPort: Send + Sync {
    fn public_account_by_id(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> RepositoryFuture<'_, Option<PublicAccount>>;
}

/// Persistence boundary for session lookup, deletion, and atomic rotation.
///
/// Implementations must treat expected as an opaque compare-and-swap snapshot.
/// A successful rotation must create the replacement and delete the old session
/// atomically; it must never expose both or neither as a partial success.
pub trait SessionStorePort: Send + Sync {
    fn load<'a>(
        &'a self,
        session_id: &'a crate::session::SessionId,
    ) -> RepositoryFuture<'a, Option<crate::session::SessionSnapshot>>;

    fn delete<'a>(
        &'a self,
        session_id: &'a crate::session::SessionId,
    ) -> RepositoryFuture<'a, bool>;

    fn rotate<'a>(
        &'a self,
        old_session_id: &'a crate::session::SessionId,
        expected: &'a crate::session::SessionSnapshot,
        new_session_id: &'a crate::session::SessionId,
        replacement: &'a crate::session::SessionRecord,
        ttl_seconds: u64,
    ) -> RepositoryFuture<'a, crate::session::SessionRotationOutcome>;

    /// Replaces a session only when its opaque storage revision still matches.
    /// The implementation must preserve the existing expiry.
    fn compare_and_set<'a>(
        &'a self,
        session_id: &'a crate::session::SessionId,
        expected: &'a crate::session::SessionSnapshot,
        replacement: &'a crate::session::SessionRecord,
    ) -> RepositoryFuture<'a, crate::session::SessionUpdateOutcome>;
}

impl<T> SessionStorePort for std::sync::Arc<T>
where
    T: SessionStorePort + ?Sized,
{
    fn load<'a>(
        &'a self,
        session_id: &'a crate::session::SessionId,
    ) -> RepositoryFuture<'a, Option<crate::session::SessionSnapshot>> {
        self.as_ref().load(session_id)
    }

    fn delete<'a>(
        &'a self,
        session_id: &'a crate::session::SessionId,
    ) -> RepositoryFuture<'a, bool> {
        self.as_ref().delete(session_id)
    }

    fn rotate<'a>(
        &'a self,
        old_session_id: &'a crate::session::SessionId,
        expected: &'a crate::session::SessionSnapshot,
        new_session_id: &'a crate::session::SessionId,
        replacement: &'a crate::session::SessionRecord,
        ttl_seconds: u64,
    ) -> RepositoryFuture<'a, crate::session::SessionRotationOutcome> {
        self.as_ref().rotate(
            old_session_id,
            expected,
            new_session_id,
            replacement,
            ttl_seconds,
        )
    }

    fn compare_and_set<'a>(
        &'a self,
        session_id: &'a crate::session::SessionId,
        expected: &'a crate::session::SessionSnapshot,
        replacement: &'a crate::session::SessionRecord,
    ) -> RepositoryFuture<'a, crate::session::SessionUpdateOutcome> {
        self.as_ref()
            .compare_and_set(session_id, expected, replacement)
    }
}
