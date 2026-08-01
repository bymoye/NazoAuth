use std::sync::Arc;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};

use crate::{
    PublicAccount,
    mfa::{
        MFA_BACKUP_CODE_COUNT, MfaVerificationMethod, generate_backup_code,
        generate_totp_secret_base32, normalize_backup_code, otpauth_uri, verified_totp_step,
    },
    ports::{
        EncodedSecretHash, MfaHashError, MfaRepositoryPort, MfaSecretHashPort, RepositoryError,
        TotpVerificationOutcome,
    },
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TotpEnrollmentStart {
    pub secret_base32: String,
    pub otpauth_uri: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedTotpConfirmation {
    code: String,
    backup_codes: Vec<String>,
    hashes: Vec<EncodedSecretHash>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TotpConfirmationOutcome {
    Accepted { backup_codes: Vec<String> },
    Invalid,
    Replay,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MfaServiceErrorKind {
    AlreadyEnabled,
    EnrollmentMissing,
    InvalidCode,
    HashBusy,
    HashFailed,
    Repository,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MfaServiceError {
    kind: MfaServiceErrorKind,
    repository: Option<RepositoryError>,
}

impl MfaServiceError {
    #[must_use]
    pub const fn kind(&self) -> MfaServiceErrorKind {
        self.kind
    }

    #[must_use]
    pub fn repository_error(&self) -> Option<&RepositoryError> {
        self.repository.as_ref()
    }

    const fn policy(kind: MfaServiceErrorKind) -> Self {
        Self {
            kind,
            repository: None,
        }
    }

    fn repository(error: RepositoryError) -> Self {
        Self {
            kind: MfaServiceErrorKind::Repository,
            repository: Some(error),
        }
    }
}

#[derive(Clone)]
pub struct MfaService {
    repository: Arc<dyn MfaRepositoryPort>,
    hasher: Arc<dyn MfaSecretHashPort>,
}

impl MfaService {
    #[must_use]
    pub fn new(repository: Arc<dyn MfaRepositoryPort>, hasher: Arc<dyn MfaSecretHashPort>) -> Self {
        Self { repository, hasher }
    }

    pub async fn begin_totp(
        &self,
        account: &PublicAccount,
        issuer: &str,
    ) -> Result<TotpEnrollmentStart, MfaServiceError> {
        let existing = self
            .repository
            .totp_enrollment(account.tenant().tenant_id, account.user_id())
            .await
            .map_err(MfaServiceError::repository)?;
        if existing.as_ref().is_some_and(|value| value.confirmed) {
            return Err(MfaServiceError::policy(MfaServiceErrorKind::AlreadyEnabled));
        }

        let secret = generate_totp_secret_base32();
        self.repository
            .begin_totp_enrollment(
                account.tenant().tenant_id,
                account.user_id(),
                secret.clone(),
                format!("{} ({issuer})", account.account.email),
            )
            .await
            .map_err(MfaServiceError::repository)?;
        Ok(TotpEnrollmentStart {
            otpauth_uri: otpauth_uri(issuer, &account.account.email, &secret),
            secret_base32: secret,
        })
    }

    pub async fn prepare_totp_confirmation(
        &self,
        account: &PublicAccount,
        code: &str,
        now: i64,
    ) -> Result<PreparedTotpConfirmation, MfaServiceError> {
        let enrollment = self
            .repository
            .totp_enrollment(account.tenant().tenant_id, account.user_id())
            .await
            .map_err(MfaServiceError::repository)?
            .ok_or_else(|| MfaServiceError::policy(MfaServiceErrorKind::EnrollmentMissing))?;
        if enrollment.confirmed {
            return Err(MfaServiceError::policy(MfaServiceErrorKind::AlreadyEnabled));
        }
        if verified_totp_step(
            &enrollment.secret_base32,
            code,
            now,
            enrollment.last_used_step,
        )
        .is_none()
        {
            self.repository
                .record_invalid_totp_attempt(account.tenant().tenant_id, account.user_id())
                .await
                .map_err(MfaServiceError::repository)?;
            return Err(MfaServiceError::policy(MfaServiceErrorKind::InvalidCode));
        }

        let (backup_codes, normalized) = generate_backup_codes();
        let hashes = self
            .hasher
            .hash_secrets(normalized)
            .await
            .map_err(mfa_hash_error)?;
        Ok(PreparedTotpConfirmation {
            code: code.to_owned(),
            backup_codes,
            hashes,
        })
    }

    pub async fn confirm_totp(
        &self,
        account: &PublicAccount,
        prepared: PreparedTotpConfirmation,
        now: i64,
    ) -> Result<TotpConfirmationOutcome, MfaServiceError> {
        let outcome = self
            .repository
            .verify_and_confirm_totp(
                account.tenant().tenant_id,
                account.user_id(),
                &prepared.code,
                now,
                prepared.hashes,
            )
            .await
            .map_err(MfaServiceError::repository)?;
        Ok(match outcome {
            TotpVerificationOutcome::Accepted => TotpConfirmationOutcome::Accepted {
                backup_codes: prepared.backup_codes,
            },
            TotpVerificationOutcome::Invalid => TotpConfirmationOutcome::Invalid,
            TotpVerificationOutcome::Replay => TotpConfirmationOutcome::Replay,
        })
    }

    pub async fn verify_factor(
        &self,
        account: &PublicAccount,
        code: &str,
        now: i64,
    ) -> Result<Option<MfaVerificationMethod>, MfaServiceError> {
        if let Some(normalized) = normalize_backup_code(code) {
            return self.verify_backup_code(account, normalized).await;
        }
        let outcome = self
            .repository
            .verify_and_consume_totp(account.tenant().tenant_id, account.user_id(), code, now)
            .await
            .map_err(MfaServiceError::repository)?;
        Ok((outcome == TotpVerificationOutcome::Accepted).then_some(MfaVerificationMethod::Totp))
    }

    pub async fn regenerate_backup_codes(
        &self,
        account: &PublicAccount,
    ) -> Result<Vec<String>, MfaServiceError> {
        let (codes, normalized) = generate_backup_codes();
        let hashes = self
            .hasher
            .hash_secrets(normalized)
            .await
            .map_err(mfa_hash_error)?;
        self.repository
            .replace_backup_code_hashes(account.tenant().tenant_id, account.user_id(), hashes)
            .await
            .map_err(MfaServiceError::repository)?;
        Ok(codes)
    }

    pub async fn disable(&self, account: &PublicAccount) -> Result<(), MfaServiceError> {
        self.repository
            .clear_mfa_state(account.tenant().tenant_id, account.user_id())
            .await
            .map_err(MfaServiceError::repository)
    }

    pub async fn remember_device(
        &self,
        account: &PublicAccount,
        user_agent_hash: Option<String>,
        expires_at: DateTime<Utc>,
    ) -> Result<String, MfaServiceError> {
        let token = random_urlsafe_token();
        self.repository
            .remember_device(
                account.tenant().tenant_id,
                account.user_id(),
                blake3::hash(token.as_bytes()).to_hex().to_string(),
                user_agent_hash,
                expires_at,
            )
            .await
            .map_err(MfaServiceError::repository)?;
        Ok(token)
    }

    async fn verify_backup_code(
        &self,
        account: &PublicAccount,
        normalized: String,
    ) -> Result<Option<MfaVerificationMethod>, MfaServiceError> {
        let candidates = self
            .repository
            .backup_code_candidates(account.tenant().tenant_id, account.user_id())
            .await
            .map_err(MfaServiceError::repository)?;
        if candidates.len() > MFA_BACKUP_CODE_COUNT {
            return Err(MfaServiceError::repository(RepositoryError::Consistency(
                "persisted backup-code count exceeds the supported maximum".to_owned(),
            )));
        }
        let hashes = candidates
            .iter()
            .map(|candidate| candidate.hash.clone())
            .collect();
        let matching = self
            .hasher
            .find_matching_secret(normalized, hashes)
            .await
            .map_err(mfa_hash_error)?;
        let Some(candidate) = matching.and_then(|index| candidates.get(index)) else {
            self.repository
                .record_invalid_backup_code_attempt(account.tenant().tenant_id, account.user_id())
                .await
                .map_err(MfaServiceError::repository)?;
            return Ok(None);
        };
        let consumed = self
            .repository
            .consume_backup_code_candidate(
                account.tenant().tenant_id,
                account.user_id(),
                candidate.id,
            )
            .await
            .map_err(MfaServiceError::repository)?;
        Ok(consumed.then_some(MfaVerificationMethod::BackupCode))
    }
}

fn generate_backup_codes() -> (Vec<String>, Vec<String>) {
    let mut codes = Vec::with_capacity(MFA_BACKUP_CODE_COUNT);
    let mut normalized = Vec::with_capacity(MFA_BACKUP_CODE_COUNT);
    for _ in 0..MFA_BACKUP_CODE_COUNT {
        let code = generate_backup_code();
        normalized.push(normalize_backup_code(&code).expect("generated backup code is valid"));
        codes.push(code);
    }
    (codes, normalized)
}

const fn mfa_hash_error(error: MfaHashError) -> MfaServiceError {
    match error {
        MfaHashError::Busy => MfaServiceError::policy(MfaServiceErrorKind::HashBusy),
        MfaHashError::Failed => MfaServiceError::policy(MfaServiceErrorKind::HashFailed),
    }
}

fn random_urlsafe_token() -> String {
    URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>())
}

#[cfg(test)]
#[path = "../tests/unit/mfa_service.rs"]
mod tests;
