use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::{TenantId, UserId};

use super::common::{EncodedSecretHash, RepositoryFuture};

pub type MfaHashFuture<'a, T> =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<T, MfaHashError>> + Send + 'a>>;

/// Versioned key material used by the persistence adapter to protect TOTP
/// seeds at rest. The identity crate deliberately does not implement a
/// concrete cipher; it only carries the key-ring contract across the MFA
/// repository port.
#[derive(Clone)]
pub struct MfaTotpKeyRing {
    current: MfaTotpKey,
    previous: Option<MfaTotpKey>,
}

#[derive(Clone)]
pub struct MfaTotpKey {
    id: String,
    key: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MfaTotpKeyError {
    EmptyId,
    IdTooLong,
    DuplicateId,
}

impl std::fmt::Display for MfaTotpKeyError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::EmptyId => "MFA TOTP encryption key id must not be empty",
            Self::IdTooLong => "MFA TOTP encryption key id must be at most 128 bytes",
            Self::DuplicateId => "MFA TOTP current and previous key ids must differ",
        })
    }
}

impl std::error::Error for MfaTotpKeyError {}

impl MfaTotpKey {
    pub fn new(id: impl Into<String>, key: [u8; 32]) -> Result<Self, MfaTotpKeyError> {
        let id = id.into();
        if id.trim().is_empty() {
            return Err(MfaTotpKeyError::EmptyId);
        }
        if id.len() > 128 {
            return Err(MfaTotpKeyError::IdTooLong);
        }
        Ok(Self { id, key })
    }

    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    #[must_use]
    pub fn key(&self) -> &[u8; 32] {
        &self.key
    }
}

impl MfaTotpKeyRing {
    pub fn new(current: MfaTotpKey, previous: Option<MfaTotpKey>) -> Result<Self, MfaTotpKeyError> {
        if previous
            .as_ref()
            .is_some_and(|candidate| candidate.id() == current.id())
        {
            return Err(MfaTotpKeyError::DuplicateId);
        }
        Ok(Self { current, previous })
    }

    #[must_use]
    pub fn current(&self) -> &MfaTotpKey {
        &self.current
    }

    #[must_use]
    pub fn previous(&self) -> Option<&MfaTotpKey> {
        self.previous.as_ref()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TotpCredential {
    pub secret_base32: String,
    pub last_used_step: Option<i64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TotpEnrollment {
    pub secret_base32: String,
    pub confirmed: bool,
    pub last_used_step: Option<i64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TotpVerificationOutcome {
    Accepted,
    Invalid,
    Replay,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackupCodeCandidate {
    pub id: Uuid,
    pub hash: EncodedSecretHash,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MfaHashError {
    Busy,
    Failed,
}

pub trait MfaSecretHashPort: Send + Sync {
    fn hash_secrets(&self, secrets: Vec<String>) -> MfaHashFuture<'_, Vec<EncodedSecretHash>>;

    fn find_matching_secret(
        &self,
        secret: String,
        candidates: Vec<EncodedSecretHash>,
    ) -> MfaHashFuture<'_, Option<usize>>;
}

pub trait MfaRepositoryPort: Send + Sync {
    fn totp_enrollment<'a>(
        &'a self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> RepositoryFuture<'a, Option<TotpEnrollment>>;

    fn begin_totp_enrollment(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
        secret: String,
        label: String,
    ) -> RepositoryFuture<'_, ()>;

    fn verify_and_confirm_totp<'a>(
        &'a self,
        tenant_id: TenantId,
        user_id: UserId,
        code: &'a str,
        timestamp: i64,
        hashes: Vec<EncodedSecretHash>,
    ) -> RepositoryFuture<'a, TotpVerificationOutcome>;

    fn record_invalid_totp_attempt(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> RepositoryFuture<'_, ()>;

    fn verify_and_consume_totp<'a>(
        &'a self,
        tenant_id: TenantId,
        user_id: UserId,
        code: &'a str,
        timestamp: i64,
    ) -> RepositoryFuture<'a, TotpVerificationOutcome>;

    fn totp_credential<'a>(
        &'a self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> RepositoryFuture<'a, Option<TotpCredential>>;

    fn compare_and_set_totp_step<'a>(
        &'a self,
        tenant_id: TenantId,
        user_id: UserId,
        step: i64,
    ) -> RepositoryFuture<'a, bool>;

    fn backup_code_candidates(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> RepositoryFuture<'_, Vec<BackupCodeCandidate>>;

    fn consume_backup_code_candidate(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
        candidate_id: Uuid,
    ) -> RepositoryFuture<'_, bool>;

    fn record_invalid_backup_code_attempt(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> RepositoryFuture<'_, ()>;

    fn replace_backup_code_hashes<'a>(
        &'a self,
        tenant_id: TenantId,
        user_id: UserId,
        hashes: Vec<EncodedSecretHash>,
    ) -> RepositoryFuture<'a, ()>;

    fn clear_mfa_state<'a>(
        &'a self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> RepositoryFuture<'a, ()>;

    fn remember_device(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
        token_hash: String,
        user_agent_hash: Option<String>,
        expires_at: DateTime<Utc>,
    ) -> RepositoryFuture<'_, ()>;
}
