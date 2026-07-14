use std::sync::Arc;

use chrono::{DateTime, Duration, Utc};
use nazo_http_actix::{
    AuthenticationRateLimit, MfaBackupCodesRegenerated, MfaChallengeCommand, MfaChallengeSuccess,
    MfaCodeCommand, MfaProfileError, MfaProfileErrorKind, MfaProfileFuture, MfaProfileOperations,
    MfaRequestContext, MfaSessionRotation, MfaStepUpSuccess, MfaTotpConfirmation,
    MfaTotpEnrollment,
};
use nazo_identity::{
    MfaService, MfaServiceError, MfaServiceErrorKind, PublicAccount, SessionId, SessionResolution,
    SessionRotation, SessionService, TotpConfirmationOutcome,
    mfa::MfaVerificationMethod,
    ports::{EncodedSecretHash, MfaHashError, MfaHashFuture, MfaSecretHashPort},
};

use crate::adapters::security::{
    PasswordHashingError, PasswordVerificationError, hash_password_blocking_limited,
    verify_encoded_hashes_blocking_limited,
};

pub(crate) const MFA_REMEMBERED_COOKIE_NAME: &str = "nazo_oauth_mfa_remembered";
pub(crate) const MFA_REMEMBERED_TTL_SECONDS: u64 = 2_592_000;

#[derive(Clone, Copy)]
pub(crate) struct ServerMfaSecretHasher;

impl MfaSecretHashPort for ServerMfaSecretHasher {
    fn hash_secrets(&self, secrets: Vec<String>) -> MfaHashFuture<'_, Vec<EncodedSecretHash>> {
        Box::pin(async move {
            let mut hashes = Vec::with_capacity(secrets.len());
            for secret in secrets {
                let hash =
                    hash_password_blocking_limited(secret)
                        .await
                        .map_err(|error| match error {
                            PasswordHashingError::Saturated => MfaHashError::Busy,
                            PasswordHashingError::WorkerFailed
                            | PasswordHashingError::HashFailed => MfaHashError::Failed,
                        })?;
                hashes.push(EncodedSecretHash::new(hash).map_err(|_| MfaHashError::Failed)?);
            }
            Ok(hashes)
        })
    }

    fn find_matching_secret(
        &self,
        secret: String,
        candidates: Vec<EncodedSecretHash>,
    ) -> MfaHashFuture<'_, Option<usize>> {
        Box::pin(async move {
            verify_encoded_hashes_blocking_limited(secret, candidates)
                .await
                .map_err(|error| match error {
                    PasswordVerificationError::Saturated => MfaHashError::Busy,
                    PasswordVerificationError::WorkerFailed => MfaHashError::Failed,
                })
        })
    }
}

#[derive(Clone)]
pub(crate) struct ServerMfaProfileOperations {
    mfa: MfaService,
    sessions: SessionService,
    rate_limit: Arc<dyn AuthenticationRateLimit>,
    issuer: Box<str>,
    session_ttl_seconds: u64,
    remembered_mfa_ttl_seconds: u64,
}

impl ServerMfaProfileOperations {
    pub(crate) fn new(
        mfa: MfaService,
        sessions: SessionService,
        rate_limit: Arc<dyn AuthenticationRateLimit>,
        issuer: impl Into<Box<str>>,
        session_ttl_seconds: u64,
        remembered_mfa_ttl_seconds: u64,
    ) -> Self {
        Self {
            mfa,
            sessions,
            rate_limit,
            issuer: issuer.into(),
            session_ttl_seconds,
            remembered_mfa_ttl_seconds,
        }
    }

    async fn current_account(
        &self,
        context: &MfaRequestContext,
        pending_mfa: bool,
    ) -> Result<PublicAccount, MfaProfileError> {
        let session_id = SessionId::new(context.session_id.as_str());
        let resolution = if pending_mfa {
            self.sessions.pending_mfa(&session_id, context.now).await
        } else {
            self.sessions.current(&session_id, context.now).await
        }
        .map_err(|error| {
            tracing::warn!(%error, "failed to resolve current MFA session");
            MfaProfileError::new(MfaProfileErrorKind::SessionUnavailable)
        })?;
        match resolution {
            SessionResolution::Present(session) => Ok(session.into_user()),
            SessionResolution::Missing if pending_mfa => {
                match self.sessions.current(&session_id, context.now).await {
                    Ok(SessionResolution::Present(_)) => {
                        Err(MfaProfileError::new(MfaProfileErrorKind::ChallengeMissing))
                    }
                    Ok(SessionResolution::Missing | SessionResolution::Invalidated) => {
                        Err(MfaProfileError::new(MfaProfileErrorKind::SessionMissing))
                    }
                    Err(error) => {
                        tracing::warn!(%error, "failed to distinguish missing MFA challenge");
                        Err(MfaProfileError::new(
                            MfaProfileErrorKind::SessionUnavailable,
                        ))
                    }
                }
            }
            SessionResolution::Missing | SessionResolution::Invalidated => {
                Err(MfaProfileError::new(MfaProfileErrorKind::SessionMissing))
            }
        }
    }

    async fn enforce_rate_limit(&self, context: &MfaRequestContext) -> Result<(), MfaProfileError> {
        self.rate_limit
            .enforce(&context.source_ip)
            .await
            .map_err(MfaProfileError::rate_limit)
    }

    async fn rotate(
        &self,
        context: &MfaRequestContext,
        method: MfaVerificationMethod,
        require_pending_mfa: bool,
    ) -> Result<MfaSessionRotation, MfaProfileError> {
        self.sessions
            .step_up(
                &SessionId::new(context.session_id.as_str()),
                method.amr(),
                self.session_ttl_seconds,
                require_pending_mfa,
                context.now,
            )
            .await
            .map_err(|error| {
                tracing::warn!(%error, "failed to atomically rotate MFA session");
                MfaProfileError::new(MfaProfileErrorKind::SessionWriteFailed)
            })?
            .map(session_rotation)
            .ok_or_else(|| MfaProfileError::new(MfaProfileErrorKind::SessionMissing))
    }

    async fn verify_factor(
        &self,
        account: &PublicAccount,
        code: &str,
        now: i64,
    ) -> Result<MfaVerificationMethod, MfaProfileError> {
        self.mfa
            .verify_factor(account, code, now)
            .await
            .map_err(map_core_error)?
            .ok_or_else(|| MfaProfileError::new(MfaProfileErrorKind::InvalidCode))
    }
}

impl MfaProfileOperations for ServerMfaProfileOperations {
    fn begin_totp(&self, context: MfaRequestContext) -> MfaProfileFuture<'_, MfaTotpEnrollment> {
        Box::pin(async move {
            let account = self.current_account(&context, false).await?;
            let enrollment = self
                .mfa
                .begin_totp(&account, &self.issuer)
                .await
                .map_err(map_core_error)?;
            Ok(MfaTotpEnrollment {
                secret_base32: enrollment.secret_base32,
                otpauth_uri: enrollment.otpauth_uri,
            })
        })
    }

    fn confirm_totp(&self, command: MfaCodeCommand) -> MfaProfileFuture<'_, MfaTotpConfirmation> {
        Box::pin(async move {
            let account = self.current_account(&command.context, false).await?;
            self.enforce_rate_limit(&command.context).await?;
            let prepared = self
                .mfa
                .prepare_totp_confirmation(&account, &command.code, command.context.now)
                .await
                .map_err(map_core_error)?;
            let rotation = self
                .rotate(&command.context, MfaVerificationMethod::Totp, false)
                .await?;
            let result = self
                .mfa
                .confirm_totp(&account, prepared, command.context.now)
                .await;
            match result {
                Ok(TotpConfirmationOutcome::Accepted { backup_codes }) => {
                    tracing::info!(user_id = %account.id(), "MFA TOTP enabled");
                    Ok(MfaTotpConfirmation {
                        rotation,
                        backup_codes,
                    })
                }
                Ok(TotpConfirmationOutcome::Invalid | TotpConfirmationOutcome::Replay) => {
                    self.discard_unpublished_rotation(&rotation).await;
                    let mut error = MfaProfileError::new(MfaProfileErrorKind::InvalidCode);
                    error.clear_session_cookies = true;
                    Err(error)
                }
                Err(error) => {
                    tracing::warn!(?error, "failed to confirm TOTP enrollment");
                    self.discard_unpublished_rotation(&rotation).await;
                    let mut mapped = map_core_error(error);
                    mapped.clear_session_cookies = true;
                    Err(mapped)
                }
            }
        })
    }

    fn verify_challenge(
        &self,
        command: MfaChallengeCommand,
    ) -> MfaProfileFuture<'_, MfaChallengeSuccess> {
        Box::pin(async move {
            let account = self.current_account(&command.context, true).await?;
            self.enforce_rate_limit(&command.context).await?;
            let method = self
                .verify_factor(&account, &command.code, command.context.now)
                .await?;
            let remembered_device_token = if command.remember_device {
                let now = DateTime::<Utc>::from_timestamp(command.context.now, 0)
                    .unwrap_or_else(Utc::now);
                let ttl = i64::try_from(self.remembered_mfa_ttl_seconds).unwrap_or(i64::MAX);
                Some(
                    self.mfa
                        .remember_device(
                            &account,
                            command.context.user_agent_hash.clone(),
                            now + Duration::seconds(ttl),
                        )
                        .await
                        .map_err(|error| {
                            tracing::warn!(?error, "failed to remember MFA device");
                            MfaProfileError::new(MfaProfileErrorKind::RememberDeviceFailed)
                        })?,
                )
            } else {
                None
            };
            let rotation = self.rotate(&command.context, method, true).await?;
            tracing::info!(user_id = %account.id(), method = method.amr(), "MFA challenge completed");
            Ok(MfaChallengeSuccess {
                rotation,
                method: method.amr().to_owned(),
                remembered_device_token,
            })
        })
    }

    fn step_up(&self, command: MfaCodeCommand) -> MfaProfileFuture<'_, MfaStepUpSuccess> {
        Box::pin(async move {
            let account = self.current_account(&command.context, false).await?;
            self.enforce_rate_limit(&command.context).await?;
            if !account.account.mfa_enabled {
                return Err(MfaProfileError::new(MfaProfileErrorKind::MfaDisabled));
            }
            let method = self
                .verify_factor(&account, &command.code, command.context.now)
                .await?;
            let rotation = self.rotate(&command.context, method, false).await?;
            tracing::info!(user_id = %account.id(), method = method.amr(), "MFA session stepped up");
            Ok(MfaStepUpSuccess {
                rotation,
                method: method.amr().to_owned(),
            })
        })
    }

    fn regenerate_backup_codes(
        &self,
        command: MfaCodeCommand,
    ) -> MfaProfileFuture<'_, MfaBackupCodesRegenerated> {
        Box::pin(async move {
            let account = self.current_account(&command.context, false).await?;
            self.enforce_rate_limit(&command.context).await?;
            if !account.account.mfa_enabled {
                return Err(MfaProfileError::new(MfaProfileErrorKind::MfaDisabled));
            }
            let method = self
                .verify_factor(&account, &command.code, command.context.now)
                .await?;
            let rotation = self.rotate(&command.context, method, false).await?;
            match self.mfa.regenerate_backup_codes(&account).await {
                Ok(backup_codes) => {
                    tracing::info!(user_id = %account.id(), "MFA backup codes regenerated");
                    Ok(MfaBackupCodesRegenerated {
                        rotation,
                        backup_codes,
                    })
                }
                Err(error) => {
                    tracing::warn!(?error, "failed to regenerate MFA backup codes");
                    let mut mapped = MfaProfileError::new(MfaProfileErrorKind::BackupCodesFailed);
                    mapped.rotation = Some(rotation);
                    Err(mapped)
                }
            }
        })
    }

    fn disable(&self, command: MfaCodeCommand) -> MfaProfileFuture<'_, bool> {
        Box::pin(async move {
            let account = self.current_account(&command.context, false).await?;
            self.enforce_rate_limit(&command.context).await?;
            if !account.account.mfa_enabled {
                return Ok(false);
            }
            self.verify_factor(&account, &command.code, command.context.now)
                .await?;
            self.mfa.disable(&account).await.map_err(|error| {
                tracing::warn!(?error, "failed to disable MFA");
                MfaProfileError::new(MfaProfileErrorKind::DisableFailed)
            })?;
            tracing::info!(user_id = %account.id(), "MFA disabled");
            Ok(true)
        })
    }
}

impl ServerMfaProfileOperations {
    async fn discard_unpublished_rotation(&self, rotation: &MfaSessionRotation) {
        if let Err(error) = self
            .sessions
            .delete(&SessionId::new(rotation.session_id.as_str()))
            .await
        {
            tracing::error!(%error, "failed to discard unpublished MFA session rotation");
        }
    }
}

fn session_rotation(rotation: SessionRotation) -> MfaSessionRotation {
    MfaSessionRotation {
        session_id: rotation.session_id().as_str().to_owned(),
        csrf_token: rotation.csrf_token().to_owned(),
    }
}

fn map_core_error(error: MfaServiceError) -> MfaProfileError {
    let kind = match error.kind() {
        MfaServiceErrorKind::AlreadyEnabled => MfaProfileErrorKind::AlreadyEnabled,
        MfaServiceErrorKind::EnrollmentMissing => MfaProfileErrorKind::EnrollmentMissing,
        MfaServiceErrorKind::InvalidCode => MfaProfileErrorKind::InvalidCode,
        MfaServiceErrorKind::HashBusy | MfaServiceErrorKind::HashFailed => {
            MfaProfileErrorKind::HashUnavailable
        }
        MfaServiceErrorKind::Repository => MfaProfileErrorKind::CredentialUnavailable,
    };
    MfaProfileError::new(kind)
}
