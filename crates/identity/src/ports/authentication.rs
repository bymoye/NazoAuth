use chrono::{DateTime, Utc};

use crate::{PasswordHash, PublicAccount, TenantId, UserId};

use super::common::{RepositoryFuture, SecretVerifyFuture};

pub trait LoginAccountRepositoryPort: Send + Sync {
    fn authentication_by_email<'a>(
        &'a self,
        tenant_id: TenantId,
        email: &'a str,
    ) -> RepositoryFuture<'a, Option<crate::AuthenticationIdentity>>;

    fn public_account_by_id(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> RepositoryFuture<'_, Option<PublicAccount>>;
}

pub trait LoginThrottlePort: Send + Sync {
    fn failure_count<'a>(&'a self, email: &'a str, source_ip: &'a str)
    -> RepositoryFuture<'a, u64>;

    fn record_failure<'a>(
        &'a self,
        email: &'a str,
        source_ip: &'a str,
        window_seconds: u64,
    ) -> RepositoryFuture<'a, ()>;

    fn clear_failure<'a>(&'a self, email: &'a str, source_ip: &'a str) -> RepositoryFuture<'a, ()>;
}

/// Atomic budget for MFA factor attempts on one authenticated login session.
///
/// The session-bound subject deliberately avoids a global email/account lock:
/// an unrelated caller cannot consume another user's pending challenge budget,
/// while the same challenge cannot evade the budget by changing source IPs.
pub trait MfaAttemptThrottlePort: Send + Sync {
    fn reserve_attempt<'a>(
        &'a self,
        tenant_id: TenantId,
        user_id: UserId,
        session_id: &'a str,
        window_seconds: u64,
        max_attempts: u64,
    ) -> RepositoryFuture<'a, MfaAttemptThrottleDecision>;

    fn clear_attempts<'a>(
        &'a self,
        tenant_id: TenantId,
        user_id: UserId,
        session_id: &'a str,
    ) -> RepositoryFuture<'a, ()>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MfaAttemptThrottleDecision {
    Allowed,
    Limited { retry_after_seconds: u64 },
}

pub trait SecretVerifyPort: Send + Sync {
    fn verify_secret(&self, secret: String, password_hash: PasswordHash) -> SecretVerifyFuture<'_>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecretVerifyError {
    Busy,
    Failed,
}

pub trait RememberedMfaDevicePort: Send + Sync {
    fn is_valid<'a>(
        &'a self,
        account: &'a PublicAccount,
        token_hash: &'a str,
        user_agent_hash: Option<&'a str>,
        now: DateTime<Utc>,
    ) -> RepositoryFuture<'a, bool>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthenticationAuditEvent {
    Failure {
        email: String,
        source_ip: String,
        user_id: Option<UserId>,
    },
    Success {
        user_id: UserId,
        source_ip: String,
        amr: Vec<String>,
    },
}

pub trait AuthenticationAuditPort: Send + Sync {
    fn record(&self, event: AuthenticationAuditEvent);
}
