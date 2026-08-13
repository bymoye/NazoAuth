use super::{MfaAuditError, MfaRepository, map_mfa_error, mfa_event};
use crate::{
    repositories::audit::insert_identity_security_event,
    schema::{user_mfa_backup_codes, user_totp_credentials, users},
};
use aes_gcm::{
    Aes256Gcm, KeyInit,
    aead::{Aead, Payload},
};
use diesel::{BoolExpressionMethods, ExpressionMethods, OptionalExtension, QueryDsl, dsl::now};
use diesel_async::{AsyncConnection, RunQueryDsl};
use nazo_identity::{
    IdentitySecurityEventType, IdentitySecurityOutcome, IdentitySecurityReason, TenantId, UserId,
    mfa::{MFA_BACKUP_CODE_COUNT, verified_totp_step},
    ports::{
        MfaTotpKeyRing, RepositoryError, TotpCredential, TotpEnrollment, TotpVerificationOutcome,
    },
};
use rand::Rng;

pub(super) const TOTP_ENVELOPE_VERSION: u8 = 1;
pub(super) const TOTP_NONCE_LEN: usize = 12;
pub(super) const TOTP_MIN_PROTECTED_LEN: usize = 1 + TOTP_NONCE_LEN + 16 + 1;
const TOTP_AAD_PREFIX: &[u8] = b"nazo-totp-seed-v1";

impl MfaRepository {
    fn require_totp_keys(&self) -> Result<&MfaTotpKeyRing, RepositoryError> {
        self.totp_keys.as_ref().ok_or_else(|| {
            RepositoryError::Consistency(
                "MFA TOTP encryption key is not configured; TOTP operations are disabled"
                    .to_owned(),
            )
        })
    }

    fn protect_totp_secret(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
        secret: &str,
    ) -> Result<(Vec<u8>, String), RepositoryError> {
        let keys = self.require_totp_keys()?;
        protect_totp_secret(keys, tenant_id, user_id, secret)
    }

    /// Encrypts legacy plaintext rows and clears the plaintext column in one
    /// transaction.  This operation is intentionally explicit: a deployment
    /// must present the current key before any old plaintext is removed.
    pub async fn migrate_legacy_totp_secrets(&self) -> Result<usize, RepositoryError> {
        let keyring = self.require_totp_keys()?.clone();
        let mut connection = self
            .pool
            .get()
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        connection
            .transaction::<usize, MfaSecretMigrationError, _>(async move |connection| {
                let rows = user_totp_credentials::table
                    .filter(user_totp_credentials::secret_base32.is_not_null())
                    .for_update()
                    .select((
                        user_totp_credentials::id,
                        user_totp_credentials::tenant_id,
                        user_totp_credentials::user_id,
                        user_totp_credentials::secret_base32,
                        user_totp_credentials::secret_ciphertext,
                        user_totp_credentials::secret_key_id,
                    ))
                    .load::<(
                        uuid::Uuid,
                        uuid::Uuid,
                        uuid::Uuid,
                        Option<String>,
                        Option<Vec<u8>>,
                        Option<String>,
                    )>(connection)
                    .await?;
                let mut migrated = 0;
                for (id, tenant_id, user_id, secret, ciphertext, key_id) in rows {
                    if ciphertext.is_some() || key_id.is_some() {
                        return Err(MfaSecretMigrationError::Repository(
                            RepositoryError::Consistency(
                                "legacy TOTP row contains an encrypted secret".to_owned(),
                            ),
                        ));
                    }
                    let secret = secret.ok_or_else(|| {
                        MfaSecretMigrationError::Repository(RepositoryError::Consistency(
                            "legacy TOTP row has a null plaintext secret".to_owned(),
                        ))
                    })?;
                    let tenant_id = TenantId::new(tenant_id).map_err(|_| {
                        MfaSecretMigrationError::Repository(RepositoryError::Consistency(
                            "legacy TOTP row has an invalid tenant id".to_owned(),
                        ))
                    })?;
                    let user_id = UserId::new(user_id).map_err(|_| {
                        MfaSecretMigrationError::Repository(RepositoryError::Consistency(
                            "legacy TOTP row has an invalid user id".to_owned(),
                        ))
                    })?;
                    let (secret_ciphertext, secret_key_id) =
                        protect_totp_secret(&keyring, tenant_id, user_id, &secret)
                            .map_err(MfaSecretMigrationError::Repository)?;
                    diesel::update(user_totp_credentials::table.find(id))
                        .set((
                            user_totp_credentials::secret_base32.eq::<Option<String>>(None),
                            user_totp_credentials::secret_ciphertext.eq(Some(secret_ciphertext)),
                            user_totp_credentials::secret_key_id.eq(Some(secret_key_id)),
                            user_totp_credentials::updated_at.eq(now),
                        ))
                        .execute(connection)
                        .await?;
                    migrated += 1;
                }
                Ok(migrated)
            })
            .await
            .map_err(MfaSecretMigrationError::into_repository)
    }

    /// Re-wraps ciphertext written with the previous key under the current
    /// key.  Unknown key ids fail closed and roll the whole transaction back.
    pub async fn rotate_totp_secrets(&self) -> Result<usize, RepositoryError> {
        let keyring = self.require_totp_keys()?.clone();
        let mut connection = self
            .pool
            .get()
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        connection
            .transaction::<usize, MfaSecretMigrationError, _>(async move |connection| {
                let rows = user_totp_credentials::table
                    .filter(user_totp_credentials::secret_ciphertext.is_not_null())
                    .for_update()
                    .select((
                        user_totp_credentials::id,
                        user_totp_credentials::tenant_id,
                        user_totp_credentials::user_id,
                        user_totp_credentials::secret_ciphertext,
                        user_totp_credentials::secret_key_id,
                    ))
                    .load::<(
                        uuid::Uuid,
                        uuid::Uuid,
                        uuid::Uuid,
                        Option<Vec<u8>>,
                        Option<String>,
                    )>(connection)
                    .await?;
                let mut rotated = 0;
                for (id, tenant_id, user_id, ciphertext, key_id) in rows {
                    let tenant_id = TenantId::new(tenant_id).map_err(|_| {
                        MfaSecretMigrationError::Repository(RepositoryError::Consistency(
                            "TOTP row has an invalid tenant id".to_owned(),
                        ))
                    })?;
                    let user_id = UserId::new(user_id).map_err(|_| {
                        MfaSecretMigrationError::Repository(RepositoryError::Consistency(
                            "TOTP row has an invalid user id".to_owned(),
                        ))
                    })?;
                    let already_current = key_id.as_deref() == Some(keyring.current().id());
                    let secret = decode_totp_secret(
                        Some(&keyring),
                        tenant_id,
                        user_id,
                        None,
                        ciphertext,
                        key_id,
                    )
                    .map_err(MfaSecretMigrationError::Repository)?;
                    if already_current {
                        continue;
                    }
                    let (secret_ciphertext, secret_key_id) =
                        protect_totp_secret(&keyring, tenant_id, user_id, &secret)
                            .map_err(MfaSecretMigrationError::Repository)?;
                    diesel::update(user_totp_credentials::table.find(id))
                        .set((
                            user_totp_credentials::secret_ciphertext.eq(Some(secret_ciphertext)),
                            user_totp_credentials::secret_key_id.eq(Some(secret_key_id)),
                            user_totp_credentials::updated_at.eq(now),
                        ))
                        .execute(connection)
                        .await?;
                    rotated += 1;
                }
                Ok(rotated)
            })
            .await
            .map_err(MfaSecretMigrationError::into_repository)
    }

    /// Returns whether any tenant has a persisted TOTP credential.
    ///
    /// This process-wide query is for bootstrap preflight checks. Tenant and
    /// user flows must use the scoped credential and enrollment queries.
    pub async fn has_totp_credentials(&self) -> Result<bool, RepositoryError> {
        let mut connection = self
            .pool
            .get()
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        user_totp_credentials::table
            .select(user_totp_credentials::id)
            .first::<uuid::Uuid>(&mut connection)
            .await
            .optional()
            .map(|value| value.is_some())
            .map_err(|error| RepositoryError::Unexpected(error.to_string()))
    }

    pub async fn totp_credential(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> Result<Option<TotpCredential>, RepositoryError> {
        self.require_totp_keys()?;
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
                user_totp_credentials::secret_ciphertext,
                user_totp_credentials::secret_key_id,
                user_totp_credentials::last_used_step,
            ))
            .first::<(Option<String>, Option<Vec<u8>>, Option<String>, Option<i64>)>(
                &mut connection,
            )
            .await
            .optional()
            .map_err(|error| RepositoryError::Unexpected(error.to_string()))?
            .map(|(plaintext, ciphertext, key_id, last_used_step)| {
                decode_totp_secret(
                    self.totp_keys.as_ref(),
                    tenant_id,
                    user_id,
                    plaintext,
                    ciphertext,
                    key_id,
                )
                .map(|secret_base32| TotpCredential {
                    secret_base32,
                    last_used_step,
                })
            })
            .transpose()
    }
    pub async fn totp_enrollment(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> Result<Option<TotpEnrollment>, RepositoryError> {
        self.require_totp_keys()?;
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
                user_totp_credentials::secret_ciphertext,
                user_totp_credentials::secret_key_id,
                user_totp_credentials::confirmed_at.is_not_null(),
                user_totp_credentials::last_used_step,
            ))
            .first::<(
                Option<String>,
                Option<Vec<u8>>,
                Option<String>,
                bool,
                Option<i64>,
            )>(&mut connection)
            .await
            .optional()
            .map_err(|error| RepositoryError::Unexpected(error.to_string()))?
            .map(
                |(plaintext, ciphertext, key_id, confirmed, last_used_step)| {
                    decode_totp_secret(
                        self.totp_keys.as_ref(),
                        tenant_id,
                        user_id,
                        plaintext,
                        ciphertext,
                        key_id,
                    )
                    .map(|secret_base32| TotpEnrollment {
                        secret_base32,
                        confirmed,
                        last_used_step,
                    })
                },
            )
            .transpose()
    }
    pub async fn begin_totp_enrollment(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
        secret: String,
        label: String,
    ) -> Result<(), RepositoryError> {
        let (secret_ciphertext, secret_key_id) =
            self.protect_totp_secret(tenant_id, user_id, &secret)?;
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
                                user_totp_credentials::secret_base32.eq::<Option<String>>(None),
                                user_totp_credentials::secret_ciphertext
                                    .eq(Some(secret_ciphertext)),
                                user_totp_credentials::secret_key_id.eq(Some(secret_key_id)),
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
                                user_totp_credentials::secret_base32.eq::<Option<String>>(None),
                                user_totp_credentials::secret_ciphertext
                                    .eq(Some(secret_ciphertext)),
                                user_totp_credentials::secret_key_id.eq(Some(secret_key_id)),
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
        self.require_totp_keys()?;
        let mut connection = self
            .pool
            .get()
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        let totp_keys = self.totp_keys.clone();
        connection
            .transaction::<TotpVerificationOutcome, MfaAuditError, _>(async move |connection| {
                let credential = user_totp_credentials::table
                    .filter(user_totp_credentials::tenant_id.eq(tenant_id.as_uuid()))
                    .filter(user_totp_credentials::user_id.eq(user_id.as_uuid()))
                    .filter(user_totp_credentials::confirmed_at.is_null())
                    .for_update()
                    .select((
                        user_totp_credentials::secret_base32,
                        user_totp_credentials::secret_ciphertext,
                        user_totp_credentials::secret_key_id,
                    ))
                    .first::<(Option<String>, Option<Vec<u8>>, Option<String>)>(connection)
                    .await
                    .optional()?;
                let Some((plaintext, ciphertext, key_id)) = credential else {
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
                let secret = decode_totp_secret(
                    totp_keys.as_ref(),
                    tenant_id,
                    user_id,
                    plaintext,
                    ciphertext,
                    key_id,
                )
                .map_err(MfaAuditError::Repository)?;
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
        self.require_totp_keys()?;
        let mut connection = self
            .pool
            .get()
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        let totp_keys = self.totp_keys.clone();
        connection
            .transaction::<TotpVerificationOutcome, MfaAuditError, _>(async move |connection| {
                let credential = user_totp_credentials::table
                    .filter(user_totp_credentials::tenant_id.eq(tenant_id.as_uuid()))
                    .filter(user_totp_credentials::user_id.eq(user_id.as_uuid()))
                    .filter(user_totp_credentials::confirmed_at.is_not_null())
                    .for_update()
                    .select((
                        user_totp_credentials::secret_base32,
                        user_totp_credentials::secret_ciphertext,
                        user_totp_credentials::secret_key_id,
                        user_totp_credentials::last_used_step,
                    ))
                    .first::<(Option<String>, Option<Vec<u8>>, Option<String>, Option<i64>)>(
                        connection,
                    )
                    .await
                    .optional()?;
                let outcome = match credential {
                    Some((plaintext, ciphertext, key_id, last_step)) => {
                        let secret = decode_totp_secret(
                            totp_keys.as_ref(),
                            tenant_id,
                            user_id,
                            plaintext,
                            ciphertext,
                            key_id,
                        )
                        .map_err(MfaAuditError::Repository)?;
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
        self.require_totp_keys()?;
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
}

pub(super) fn totp_aad(tenant_id: TenantId, user_id: UserId, key_id: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(TOTP_AAD_PREFIX.len() + 16 + 16 + key_id.len() + 8);
    aad.extend_from_slice(TOTP_AAD_PREFIX);
    aad.extend_from_slice(tenant_id.as_uuid().as_bytes());
    aad.extend_from_slice(user_id.as_uuid().as_bytes());
    aad.extend_from_slice(&(key_id.len() as u64).to_be_bytes());
    aad.extend_from_slice(key_id.as_bytes());
    aad
}

pub(super) fn protect_totp_secret(
    keyring: &MfaTotpKeyRing,
    tenant_id: TenantId,
    user_id: UserId,
    secret: &str,
) -> Result<(Vec<u8>, String), RepositoryError> {
    if secret.trim().len() < 16 || secret.len() > 128 {
        return Err(RepositoryError::Consistency(
            "TOTP secret is shorter than 16 bytes or exceeds the supported length".to_owned(),
        ));
    }
    let key_id = keyring.current().id();
    let cipher = Aes256Gcm::new_from_slice(keyring.current().key())
        .map_err(|_| RepositoryError::Consistency("invalid TOTP encryption key".to_owned()))?;
    let mut nonce = [0_u8; TOTP_NONCE_LEN];
    rand::rng().fill_bytes(&mut nonce);
    let ciphertext = cipher
        .encrypt(
            (&nonce).into(),
            Payload {
                msg: secret.as_bytes(),
                aad: &totp_aad(tenant_id, user_id, key_id),
            },
        )
        .map_err(|_| RepositoryError::Unexpected("TOTP secret encryption failed".to_owned()))?;
    let mut protected = Vec::with_capacity(1 + nonce.len() + ciphertext.len());
    protected.push(TOTP_ENVELOPE_VERSION);
    protected.extend_from_slice(&nonce);
    protected.extend_from_slice(&ciphertext);
    Ok((protected, key_id.to_owned()))
}

pub(super) fn decode_totp_secret(
    keyring: Option<&MfaTotpKeyRing>,
    tenant_id: TenantId,
    user_id: UserId,
    plaintext: Option<String>,
    protected: Option<Vec<u8>>,
    key_id: Option<String>,
) -> Result<String, RepositoryError> {
    match (plaintext, protected, key_id) {
        (Some(_), Some(_), _) => Err(RepositoryError::Consistency(
            "TOTP row contains both plaintext and encrypted secrets".to_owned(),
        )),
        (Some(_), None, _) => Err(RepositoryError::Consistency(
            "legacy plaintext TOTP secret requires explicit migration".to_owned(),
        )),
        (None, None, _) => Err(RepositoryError::Consistency(
            "TOTP row has no protected secret".to_owned(),
        )),
        (None, Some(protected), Some(key_id)) => {
            let keyring = keyring.ok_or_else(|| {
                RepositoryError::Consistency(
                    "MFA TOTP encryption key is not configured; TOTP operations are disabled"
                        .to_owned(),
                )
            })?;
            let key = if keyring.current().id() == key_id {
                keyring.current()
            } else if keyring.previous().is_some_and(|key| key.id() == key_id) {
                keyring.previous().expect("previous key was checked")
            } else {
                return Err(RepositoryError::Consistency(
                    "TOTP secret uses an unavailable encryption key version".to_owned(),
                ));
            };
            if protected.len() < TOTP_MIN_PROTECTED_LEN || protected[0] != TOTP_ENVELOPE_VERSION {
                return Err(RepositoryError::Consistency(
                    "TOTP secret envelope is malformed".to_owned(),
                ));
            }
            let nonce: &[u8; TOTP_NONCE_LEN] =
                protected[1..1 + TOTP_NONCE_LEN].try_into().map_err(|_| {
                    RepositoryError::Consistency("TOTP secret nonce is malformed".to_owned())
                })?;
            let plaintext = Aes256Gcm::new_from_slice(key.key())
                .map_err(|_| {
                    RepositoryError::Consistency("invalid TOTP encryption key".to_owned())
                })?
                .decrypt(
                    nonce.into(),
                    Payload {
                        msg: &protected[1 + TOTP_NONCE_LEN..],
                        aad: &totp_aad(tenant_id, user_id, &key_id),
                    },
                )
                .map_err(|_| {
                    RepositoryError::Consistency("TOTP secret authentication failed".to_owned())
                })?;
            let secret = String::from_utf8(plaintext).map_err(|_| {
                RepositoryError::Consistency("TOTP secret is not valid UTF-8".to_owned())
            })?;
            if secret.trim().len() < 16 || secret.len() > 128 {
                return Err(RepositoryError::Consistency(
                    "TOTP secret is shorter than 16 bytes or exceeds the supported length"
                        .to_owned(),
                ));
            }
            Ok(secret)
        }
        (None, Some(_), None) => Err(RepositoryError::Consistency(
            "encrypted TOTP row has no key id".to_owned(),
        )),
    }
}

pub(super) enum MfaSecretMigrationError {
    Diesel(diesel::result::Error),
    Repository(RepositoryError),
}

impl From<diesel::result::Error> for MfaSecretMigrationError {
    fn from(error: diesel::result::Error) -> Self {
        Self::Diesel(error)
    }
}

impl MfaSecretMigrationError {
    pub(super) fn into_repository(self) -> RepositoryError {
        match self {
            Self::Diesel(error) => map_mfa_error(error),
            Self::Repository(error) => error,
        }
    }
}
