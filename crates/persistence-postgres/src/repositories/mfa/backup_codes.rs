use super::{MfaAuditError, MfaRepository, mfa_event};
use crate::{repositories::audit::insert_identity_security_event, schema::user_mfa_backup_codes};
use diesel::{ExpressionMethods, QueryDsl, dsl::now};
use diesel_async::{AsyncConnection, RunQueryDsl};
use nazo_identity::{
    IdentitySecurityEventType, IdentitySecurityOutcome, IdentitySecurityReason, TenantId, UserId,
    mfa::MFA_BACKUP_CODE_COUNT,
    ports::{BackupCodeCandidate, EncodedSecretHash, RepositoryError},
};

impl MfaRepository {
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
}

pub(super) fn validate_backup_hash_count(hashes: &[String]) -> Result<(), RepositoryError> {
    if hashes.len() > MFA_BACKUP_CODE_COUNT {
        Err(RepositoryError::Conflict)
    } else {
        Ok(())
    }
}
