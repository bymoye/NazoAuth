use crate::{
    DbPool,
    repositories::audit::insert_identity_security_event,
    schema::{user_mfa_backup_codes, user_mfa_remembered_devices, user_totp_credentials, users},
};
use diesel::{BoolExpressionMethods, ExpressionMethods, OptionalExtension, QueryDsl, dsl::now};
use diesel_async::{AsyncConnection, RunQueryDsl};
use nazo_identity::{
    IdentitySecurityEvent, IdentitySecurityEventType, IdentitySecurityOutcome,
    IdentitySecurityReason, TenantId, UserId,
    mfa::{MFA_BACKUP_CODE_COUNT, verified_totp_step},
    ports::{
        BackupCodeCandidate, EncodedSecretHash, MfaRepositoryPort, RepositoryError,
        RepositoryFuture, TotpCredential, TotpEnrollment, TotpVerificationOutcome,
    },
};

#[derive(Clone)]
pub struct MfaRepository {
    pool: DbPool,
}
impl MfaRepository {
    #[must_use]
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }
    pub async fn totp_credential(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> Result<Option<TotpCredential>, RepositoryError> {
        let mut connection = self
            .pool
            .get()
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        user_totp_credentials::table
            .filter(user_totp_credentials::tenant_id.eq(tenant_id.as_uuid()))
            .filter(user_totp_credentials::user_id.eq(user_id.as_uuid()))
            .filter(user_totp_credentials::confirmed_at.is_not_null())
            .select((
                user_totp_credentials::secret_base32,
                user_totp_credentials::last_used_step,
            ))
            .first::<(String, Option<i64>)>(&mut connection)
            .await
            .optional()
            .map(|value| {
                value.map(|(secret_base32, last_used_step)| TotpCredential {
                    secret_base32,
                    last_used_step,
                })
            })
            .map_err(|error| RepositoryError::Unexpected(error.to_string()))
    }
    pub async fn totp_enrollment(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> Result<Option<TotpEnrollment>, RepositoryError> {
        let mut connection = self
            .pool
            .get()
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        user_totp_credentials::table
            .filter(user_totp_credentials::tenant_id.eq(tenant_id.as_uuid()))
            .filter(user_totp_credentials::user_id.eq(user_id.as_uuid()))
            .select((
                user_totp_credentials::secret_base32,
                user_totp_credentials::confirmed_at.is_not_null(),
                user_totp_credentials::last_used_step,
            ))
            .first::<(String, bool, Option<i64>)>(&mut connection)
            .await
            .optional()
            .map(|value| {
                value.map(
                    |(secret_base32, confirmed, last_used_step)| TotpEnrollment {
                        secret_base32,
                        confirmed,
                        last_used_step,
                    },
                )
            })
            .map_err(|error| RepositoryError::Unexpected(error.to_string()))
    }
    pub async fn begin_totp_enrollment(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
        secret: String,
        label: String,
    ) -> Result<(), RepositoryError> {
        let mut connection = self
            .pool
            .get()
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        connection
            .transaction::<_, diesel::result::Error, _>(async move |connection| {
                let existing = user_totp_credentials::table
                    .filter(user_totp_credentials::tenant_id.eq(tenant_id.as_uuid()))
                    .filter(user_totp_credentials::user_id.eq(user_id.as_uuid()))
                    .for_update()
                    .select((
                        user_totp_credentials::id,
                        user_totp_credentials::confirmed_at,
                    ))
                    .first::<(uuid::Uuid, Option<chrono::DateTime<chrono::Utc>>)>(connection)
                    .await
                    .optional()?;
                match existing {
                    Some((_, Some(_))) => Err(diesel::result::Error::RollbackTransaction),
                    Some((id, None)) => {
                        diesel::update(user_totp_credentials::table.find(id))
                            .set((
                                user_totp_credentials::secret_base32.eq(secret),
                                user_totp_credentials::label.eq(label),
                                user_totp_credentials::last_used_step.eq::<Option<i64>>(None),
                                user_totp_credentials::updated_at.eq(now),
                            ))
                            .execute(connection)
                            .await?;
                        Ok(())
                    }
                    None => {
                        diesel::insert_into(user_totp_credentials::table)
                            .values((
                                user_totp_credentials::tenant_id.eq(tenant_id.as_uuid()),
                                user_totp_credentials::user_id.eq(user_id.as_uuid()),
                                user_totp_credentials::secret_base32.eq(secret),
                                user_totp_credentials::label.eq(label),
                            ))
                            .execute(connection)
                            .await?;
                        Ok(())
                    }
                }
            })
            .await
            .map_err(map_mfa_error)
    }
    pub async fn verify_and_confirm_totp(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
        code: &str,
        timestamp: i64,
        hashes: Vec<String>,
    ) -> Result<TotpVerificationOutcome, RepositoryError> {
        if hashes.len() != MFA_BACKUP_CODE_COUNT {
            return Err(RepositoryError::Conflict);
        }
        let mut connection = self
            .pool
            .get()
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        connection
            .transaction::<TotpVerificationOutcome, MfaAuditError, _>(async move |connection| {
                let credential = user_totp_credentials::table
                    .filter(user_totp_credentials::tenant_id.eq(tenant_id.as_uuid()))
                    .filter(user_totp_credentials::user_id.eq(user_id.as_uuid()))
                    .filter(user_totp_credentials::confirmed_at.is_null())
                    .for_update()
                    .select(user_totp_credentials::secret_base32)
                    .first::<String>(connection)
                    .await
                    .optional()?;
                let Some(secret) = credential else {
                    insert_identity_security_event(
                        connection,
                        &mfa_event(
                            tenant_id,
                            user_id,
                            IdentitySecurityEventType::MfaTotpAttempt,
                            IdentitySecurityOutcome::Replay,
                            IdentitySecurityReason::TotpReplay,
                        ),
                    )
                    .await
                    .map_err(MfaAuditError::Repository)?;
                    return Ok(TotpVerificationOutcome::Replay);
                };
                let Some(step) = verified_totp_step(&secret, code, timestamp, None) else {
                    insert_identity_security_event(
                        connection,
                        &mfa_event(
                            tenant_id,
                            user_id,
                            IdentitySecurityEventType::MfaTotpAttempt,
                            IdentitySecurityOutcome::InvalidCredential,
                            IdentitySecurityReason::TotpInvalid,
                        ),
                    )
                    .await
                    .map_err(MfaAuditError::Repository)?;
                    return Ok(TotpVerificationOutcome::Invalid);
                };
                diesel::update(
                    user_totp_credentials::table
                        .filter(user_totp_credentials::tenant_id.eq(tenant_id.as_uuid()))
                        .filter(user_totp_credentials::user_id.eq(user_id.as_uuid()))
                        .filter(user_totp_credentials::confirmed_at.is_null()),
                )
                .set((
                    user_totp_credentials::confirmed_at.eq(now),
                    user_totp_credentials::last_used_step.eq(step),
                    user_totp_credentials::updated_at.eq(now),
                ))
                .execute(connection)
                .await?;
                diesel::update(
                    users::table
                        .find(user_id.as_uuid())
                        .filter(users::tenant_id.eq(tenant_id.as_uuid())),
                )
                .set((users::mfa_enabled.eq(true), users::updated_at.eq(now)))
                .execute(connection)
                .await?;
                diesel::delete(
                    user_mfa_backup_codes::table
                        .filter(user_mfa_backup_codes::tenant_id.eq(tenant_id.as_uuid()))
                        .filter(user_mfa_backup_codes::user_id.eq(user_id.as_uuid())),
                )
                .execute(connection)
                .await?;
                for hash in hashes {
                    diesel::insert_into(user_mfa_backup_codes::table)
                        .values((
                            user_mfa_backup_codes::tenant_id.eq(tenant_id.as_uuid()),
                            user_mfa_backup_codes::user_id.eq(user_id.as_uuid()),
                            user_mfa_backup_codes::code_hash.eq(hash),
                        ))
                        .execute(connection)
                        .await?;
                }
                insert_identity_security_event(
                    connection,
                    &mfa_event(
                        tenant_id,
                        user_id,
                        IdentitySecurityEventType::MfaTotpAttempt,
                        IdentitySecurityOutcome::Success,
                        IdentitySecurityReason::TotpAccepted,
                    ),
                )
                .await
                .map_err(MfaAuditError::Repository)?;
                Ok(TotpVerificationOutcome::Accepted)
            })
            .await
            .map_err(MfaAuditError::into_repository)
    }
    pub async fn record_invalid_totp_attempt(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> Result<(), RepositoryError> {
        let mut connection = self
            .pool
            .get()
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        insert_identity_security_event(
            &mut connection,
            &mfa_event(
                tenant_id,
                user_id,
                IdentitySecurityEventType::MfaTotpAttempt,
                IdentitySecurityOutcome::InvalidCredential,
                IdentitySecurityReason::TotpInvalid,
            ),
        )
        .await
    }
    pub async fn verify_and_consume_totp(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
        code: &str,
        timestamp: i64,
    ) -> Result<TotpVerificationOutcome, RepositoryError> {
        let mut connection = self
            .pool
            .get()
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        connection
            .transaction::<TotpVerificationOutcome, MfaAuditError, _>(async |connection| {
                let credential = user_totp_credentials::table
                    .filter(user_totp_credentials::tenant_id.eq(tenant_id.as_uuid()))
                    .filter(user_totp_credentials::user_id.eq(user_id.as_uuid()))
                    .filter(user_totp_credentials::confirmed_at.is_not_null())
                    .for_update()
                    .select((
                        user_totp_credentials::secret_base32,
                        user_totp_credentials::last_used_step,
                    ))
                    .first::<(String, Option<i64>)>(connection)
                    .await
                    .optional()?;
                let outcome = match credential {
                    Some((secret, last_step)) => {
                        match verified_totp_step(&secret, code, timestamp, None) {
                            Some(step) if last_step.is_some_and(|last| step <= last) => {
                                TotpVerificationOutcome::Replay
                            }
                            Some(step) => {
                                diesel::update(
                                    user_totp_credentials::table
                                        .filter(
                                            user_totp_credentials::tenant_id
                                                .eq(tenant_id.as_uuid()),
                                        )
                                        .filter(
                                            user_totp_credentials::user_id.eq(user_id.as_uuid()),
                                        ),
                                )
                                .set((
                                    user_totp_credentials::last_used_step.eq(step),
                                    user_totp_credentials::updated_at.eq(now),
                                ))
                                .execute(connection)
                                .await?;
                                TotpVerificationOutcome::Accepted
                            }
                            None => TotpVerificationOutcome::Invalid,
                        }
                    }
                    None => TotpVerificationOutcome::Invalid,
                };
                let (audit_outcome, reason) = match outcome {
                    TotpVerificationOutcome::Accepted => (
                        IdentitySecurityOutcome::Success,
                        IdentitySecurityReason::TotpAccepted,
                    ),
                    TotpVerificationOutcome::Invalid => (
                        IdentitySecurityOutcome::InvalidCredential,
                        IdentitySecurityReason::TotpInvalid,
                    ),
                    TotpVerificationOutcome::Replay => (
                        IdentitySecurityOutcome::Replay,
                        IdentitySecurityReason::TotpReplay,
                    ),
                };
                insert_identity_security_event(
                    connection,
                    &mfa_event(
                        tenant_id,
                        user_id,
                        IdentitySecurityEventType::MfaTotpAttempt,
                        audit_outcome,
                        reason,
                    ),
                )
                .await
                .map_err(MfaAuditError::Repository)?;
                Ok(outcome)
            })
            .await
            .map_err(MfaAuditError::into_repository)
    }
    pub async fn compare_and_set_totp_step(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
        step: i64,
    ) -> Result<bool, RepositoryError> {
        let mut connection = self
            .pool
            .get()
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        connection
            .transaction::<bool, MfaAuditError, _>(async |connection| {
                let changed = diesel::update(
                    user_totp_credentials::table
                        .filter(user_totp_credentials::tenant_id.eq(tenant_id.as_uuid()))
                        .filter(user_totp_credentials::user_id.eq(user_id.as_uuid()))
                        .filter(user_totp_credentials::confirmed_at.is_not_null())
                        .filter(
                            user_totp_credentials::last_used_step
                                .is_null()
                                .or(user_totp_credentials::last_used_step.lt(step)),
                        ),
                )
                .set((
                    user_totp_credentials::last_used_step.eq(step),
                    user_totp_credentials::updated_at.eq(now),
                ))
                .execute(connection)
                .await?
                    == 1;
                insert_identity_security_event(
                    connection,
                    &mfa_event(
                        tenant_id,
                        user_id,
                        IdentitySecurityEventType::MfaTotpAttempt,
                        if changed {
                            IdentitySecurityOutcome::Success
                        } else {
                            IdentitySecurityOutcome::Replay
                        },
                        if changed {
                            IdentitySecurityReason::TotpAccepted
                        } else {
                            IdentitySecurityReason::TotpReplay
                        },
                    ),
                )
                .await
                .map_err(MfaAuditError::Repository)?;
                Ok(changed)
            })
            .await
            .map_err(MfaAuditError::into_repository)
    }
    pub async fn backup_code_candidates(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> Result<Vec<BackupCodeCandidate>, RepositoryError> {
        let mut connection = self
            .pool
            .get()
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        let rows = user_mfa_backup_codes::table
            .filter(user_mfa_backup_codes::tenant_id.eq(tenant_id.as_uuid()))
            .filter(user_mfa_backup_codes::user_id.eq(user_id.as_uuid()))
            .filter(user_mfa_backup_codes::used_at.is_null())
            .select((user_mfa_backup_codes::id, user_mfa_backup_codes::code_hash))
            .limit(i64::try_from(MFA_BACKUP_CODE_COUNT + 1).expect("backup-code limit fits i64"))
            .load::<(uuid::Uuid, String)>(&mut connection)
            .await
            .map_err(|error| RepositoryError::Unexpected(error.to_string()))?;
        if rows.len() > MFA_BACKUP_CODE_COUNT {
            return Err(RepositoryError::Consistency(
                "persisted backup-code count exceeds the supported maximum".to_owned(),
            ));
        }
        rows.into_iter()
            .map(|(id, hash)| {
                EncodedSecretHash::new(hash)
                    .map(|hash| BackupCodeCandidate { id, hash })
                    .map_err(|_| {
                        RepositoryError::Consistency(
                            "persisted backup-code hash is empty".to_owned(),
                        )
                    })
            })
            .collect()
    }

    pub async fn consume_backup_code_candidate(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
        candidate_id: uuid::Uuid,
    ) -> Result<bool, RepositoryError> {
        let mut connection = self
            .pool
            .get()
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        connection
            .transaction::<bool, MfaAuditError, _>(async |connection| {
                let changed = diesel::update(
                    user_mfa_backup_codes::table
                        .find(candidate_id)
                        .filter(user_mfa_backup_codes::tenant_id.eq(tenant_id.as_uuid()))
                        .filter(user_mfa_backup_codes::user_id.eq(user_id.as_uuid()))
                        .filter(user_mfa_backup_codes::used_at.is_null()),
                )
                .set(user_mfa_backup_codes::used_at.eq(now))
                .execute(connection)
                .await?
                    == 1;
                insert_identity_security_event(
                    connection,
                    &mfa_event(
                        tenant_id,
                        user_id,
                        IdentitySecurityEventType::MfaBackupCodeAttempt,
                        if changed {
                            IdentitySecurityOutcome::Success
                        } else {
                            IdentitySecurityOutcome::Replay
                        },
                        if changed {
                            IdentitySecurityReason::BackupCodeAccepted
                        } else {
                            IdentitySecurityReason::BackupCodeReplay
                        },
                    ),
                )
                .await
                .map_err(MfaAuditError::Repository)?;
                Ok(changed)
            })
            .await
            .map_err(MfaAuditError::into_repository)
    }

    pub async fn record_invalid_backup_code_attempt(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> Result<(), RepositoryError> {
        let mut connection = self
            .pool
            .get()
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        insert_identity_security_event(
            &mut connection,
            &mfa_event(
                tenant_id,
                user_id,
                IdentitySecurityEventType::MfaBackupCodeAttempt,
                IdentitySecurityOutcome::InvalidCredential,
                IdentitySecurityReason::BackupCodeInvalid,
            ),
        )
        .await
    }
    pub async fn replace_backup_code_hashes(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
        hashes: Vec<String>,
    ) -> Result<(), RepositoryError> {
        validate_backup_hash_count(&hashes)?;
        let mut connection = self
            .pool
            .get()
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        connection
            .transaction::<_, diesel::result::Error, _>(async move |connection| {
                diesel::delete(
                    user_mfa_backup_codes::table
                        .filter(user_mfa_backup_codes::tenant_id.eq(tenant_id.as_uuid()))
                        .filter(user_mfa_backup_codes::user_id.eq(user_id.as_uuid())),
                )
                .execute(connection)
                .await?;
                for hash in hashes {
                    diesel::insert_into(user_mfa_backup_codes::table)
                        .values((
                            user_mfa_backup_codes::tenant_id.eq(tenant_id.as_uuid()),
                            user_mfa_backup_codes::user_id.eq(user_id.as_uuid()),
                            user_mfa_backup_codes::code_hash.eq(hash),
                        ))
                        .execute(connection)
                        .await?;
                }
                Ok(())
            })
            .await
            .map_err(|error| RepositoryError::Unexpected(error.to_string()))
    }
    pub async fn clear_mfa_state(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> Result<(), RepositoryError> {
        let mut connection = self
            .pool
            .get()
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        connection
            .transaction::<_, diesel::result::Error, _>(async move |connection| {
                diesel::delete(
                    user_mfa_backup_codes::table
                        .filter(user_mfa_backup_codes::tenant_id.eq(tenant_id.as_uuid()))
                        .filter(user_mfa_backup_codes::user_id.eq(user_id.as_uuid())),
                )
                .execute(connection)
                .await?;
                diesel::delete(
                    user_mfa_remembered_devices::table
                        .filter(user_mfa_remembered_devices::tenant_id.eq(tenant_id.as_uuid()))
                        .filter(user_mfa_remembered_devices::user_id.eq(user_id.as_uuid())),
                )
                .execute(connection)
                .await?;
                diesel::delete(
                    user_totp_credentials::table
                        .filter(user_totp_credentials::tenant_id.eq(tenant_id.as_uuid()))
                        .filter(user_totp_credentials::user_id.eq(user_id.as_uuid())),
                )
                .execute(connection)
                .await?;
                diesel::update(
                    users::table
                        .find(user_id.as_uuid())
                        .filter(users::tenant_id.eq(tenant_id.as_uuid())),
                )
                .set((users::mfa_enabled.eq(false), users::updated_at.eq(now)))
                .execute(connection)
                .await?;
                Ok(())
            })
            .await
            .map_err(|error| RepositoryError::Unexpected(error.to_string()))
    }
    pub async fn remembered_device_valid(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
        token_hash: &str,
        user_agent_hash: Option<&str>,
        at: chrono::DateTime<chrono::Utc>,
    ) -> Result<bool, RepositoryError> {
        let mut connection = self
            .pool
            .get()
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        let row = user_mfa_remembered_devices::table
            .filter(user_mfa_remembered_devices::tenant_id.eq(tenant_id.as_uuid()))
            .filter(user_mfa_remembered_devices::user_id.eq(user_id.as_uuid()))
            .filter(user_mfa_remembered_devices::token_hash.eq(token_hash))
            .filter(user_mfa_remembered_devices::expires_at.gt(at))
            .select((
                user_mfa_remembered_devices::id,
                user_mfa_remembered_devices::user_agent_hash,
            ))
            .first::<(uuid::Uuid, Option<String>)>(&mut connection)
            .await
            .optional()
            .map_err(|error| RepositoryError::Unexpected(error.to_string()))?;
        let Some((id, stored_hash)) = row else {
            return Ok(false);
        };
        if stored_hash.as_deref() != user_agent_hash {
            return Ok(false);
        }
        diesel::update(user_mfa_remembered_devices::table.find(id))
            .set(user_mfa_remembered_devices::last_used_at.eq(now))
            .execute(&mut connection)
            .await
            .map_err(|error| RepositoryError::Unexpected(error.to_string()))?;
        Ok(true)
    }
    pub async fn remember_device(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
        token_hash: String,
        user_agent_hash: Option<String>,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), RepositoryError> {
        let mut connection = self
            .pool
            .get()
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        connection
            .transaction::<_, diesel::result::Error, _>(async move |connection| {
                diesel::delete(
                    user_mfa_remembered_devices::table
                        .filter(user_mfa_remembered_devices::tenant_id.eq(tenant_id.as_uuid()))
                        .filter(user_mfa_remembered_devices::user_id.eq(user_id.as_uuid()))
                        .filter(user_mfa_remembered_devices::expires_at.le(now)),
                )
                .execute(connection)
                .await?;
                diesel::insert_into(user_mfa_remembered_devices::table)
                    .values((
                        user_mfa_remembered_devices::tenant_id.eq(tenant_id.as_uuid()),
                        user_mfa_remembered_devices::user_id.eq(user_id.as_uuid()),
                        user_mfa_remembered_devices::token_hash.eq(token_hash),
                        user_mfa_remembered_devices::user_agent_hash.eq(user_agent_hash),
                        user_mfa_remembered_devices::expires_at.eq(expires_at),
                    ))
                    .execute(connection)
                    .await?;
                Ok(())
            })
            .await
            .map_err(|error| RepositoryError::Unexpected(error.to_string()))
    }
}

impl nazo_identity::ports::RememberedMfaDevicePort for MfaRepository {
    fn is_valid<'a>(
        &'a self,
        account: &'a nazo_identity::PublicAccount,
        token_hash: &'a str,
        user_agent_hash: Option<&'a str>,
        at: chrono::DateTime<chrono::Utc>,
    ) -> nazo_identity::ports::RepositoryFuture<'a, bool> {
        Box::pin(async move {
            self.remembered_device_valid(
                account.tenant().tenant_id,
                account.user_id(),
                token_hash,
                user_agent_hash,
                at,
            )
            .await
        })
    }
}

fn mfa_event(
    tenant_id: TenantId,
    user_id: UserId,
    event_type: IdentitySecurityEventType,
    outcome: IdentitySecurityOutcome,
    reason: IdentitySecurityReason,
) -> IdentitySecurityEvent {
    IdentitySecurityEvent {
        tenant_id,
        event_type,
        outcome,
        actor_id: Some(user_id),
        target_user_id: Some(user_id),
        reason,
        occurred_at: std::time::SystemTime::now(),
    }
}

enum MfaAuditError {
    Diesel(diesel::result::Error),
    Repository(RepositoryError),
}

impl From<diesel::result::Error> for MfaAuditError {
    fn from(error: diesel::result::Error) -> Self {
        Self::Diesel(error)
    }
}

impl MfaAuditError {
    fn into_repository(self) -> RepositoryError {
        match self {
            Self::Diesel(error) => map_mfa_error(error),
            Self::Repository(error) => error,
        }
    }
}

fn validate_backup_hash_count(hashes: &[String]) -> Result<(), RepositoryError> {
    if hashes.len() > MFA_BACKUP_CODE_COUNT {
        Err(RepositoryError::Conflict)
    } else {
        Ok(())
    }
}

fn map_mfa_error(error: diesel::result::Error) -> RepositoryError {
    match error {
        diesel::result::Error::NotFound
        | diesel::result::Error::RollbackTransaction
        | diesel::result::Error::DatabaseError(
            diesel::result::DatabaseErrorKind::UniqueViolation,
            _,
        ) => RepositoryError::Conflict,
        other => RepositoryError::Unexpected(other.to_string()),
    }
}

impl MfaRepositoryPort for MfaRepository {
    fn totp_enrollment<'a>(
        &'a self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> RepositoryFuture<'a, Option<TotpEnrollment>> {
        Box::pin(async move { self.totp_enrollment(tenant_id, user_id).await })
    }

    fn begin_totp_enrollment(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
        secret: String,
        label: String,
    ) -> RepositoryFuture<'_, ()> {
        Box::pin(async move {
            self.begin_totp_enrollment(tenant_id, user_id, secret, label)
                .await
        })
    }

    fn verify_and_confirm_totp<'a>(
        &'a self,
        tenant_id: TenantId,
        user_id: UserId,
        code: &'a str,
        timestamp: i64,
        hashes: Vec<EncodedSecretHash>,
    ) -> RepositoryFuture<'a, TotpVerificationOutcome> {
        Box::pin(async move {
            self.verify_and_confirm_totp(
                tenant_id,
                user_id,
                code,
                timestamp,
                hashes
                    .into_iter()
                    .map(|hash| hash.as_str().to_owned())
                    .collect(),
            )
            .await
        })
    }

    fn record_invalid_totp_attempt(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> RepositoryFuture<'_, ()> {
        Box::pin(async move { self.record_invalid_totp_attempt(tenant_id, user_id).await })
    }

    fn verify_and_consume_totp<'a>(
        &'a self,
        tenant_id: TenantId,
        user_id: UserId,
        code: &'a str,
        timestamp: i64,
    ) -> RepositoryFuture<'a, TotpVerificationOutcome> {
        Box::pin(async move {
            self.verify_and_consume_totp(tenant_id, user_id, code, timestamp)
                .await
        })
    }

    fn totp_credential<'a>(
        &'a self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> RepositoryFuture<'a, Option<TotpCredential>> {
        Box::pin(async move { self.totp_credential(tenant_id, user_id).await })
    }
    fn compare_and_set_totp_step<'a>(
        &'a self,
        tenant_id: TenantId,
        user_id: UserId,
        step: i64,
    ) -> RepositoryFuture<'a, bool> {
        Box::pin(async move {
            self.compare_and_set_totp_step(tenant_id, user_id, step)
                .await
        })
    }
    fn backup_code_candidates(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> RepositoryFuture<'_, Vec<BackupCodeCandidate>> {
        Box::pin(async move { self.backup_code_candidates(tenant_id, user_id).await })
    }

    fn consume_backup_code_candidate(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
        candidate_id: uuid::Uuid,
    ) -> RepositoryFuture<'_, bool> {
        Box::pin(async move {
            self.consume_backup_code_candidate(tenant_id, user_id, candidate_id)
                .await
        })
    }

    fn record_invalid_backup_code_attempt(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> RepositoryFuture<'_, ()> {
        Box::pin(async move {
            self.record_invalid_backup_code_attempt(tenant_id, user_id)
                .await
        })
    }

    fn replace_backup_code_hashes<'a>(
        &'a self,
        tenant_id: TenantId,
        user_id: UserId,
        hashes: Vec<EncodedSecretHash>,
    ) -> RepositoryFuture<'a, ()> {
        Box::pin(async move {
            self.replace_backup_code_hashes(
                tenant_id,
                user_id,
                hashes
                    .into_iter()
                    .map(|hash| hash.as_str().to_owned())
                    .collect(),
            )
            .await
        })
    }
    fn clear_mfa_state<'a>(
        &'a self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> RepositoryFuture<'a, ()> {
        Box::pin(async move { self.clear_mfa_state(tenant_id, user_id).await })
    }

    fn remember_device(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
        token_hash: String,
        user_agent_hash: Option<String>,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> RepositoryFuture<'_, ()> {
        Box::pin(async move {
            self.remember_device(tenant_id, user_id, token_hash, user_agent_hash, expires_at)
                .await
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enrollment_unique_violation_is_a_typed_conflict() {
        let error = diesel::result::Error::DatabaseError(
            diesel::result::DatabaseErrorKind::UniqueViolation,
            Box::new("duplicate enrollment".to_owned()),
        );
        assert_eq!(map_mfa_error(error), RepositoryError::Conflict);
    }
}
