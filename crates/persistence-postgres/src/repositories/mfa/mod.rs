use crate::{
    DbPool,
    schema::{user_mfa_backup_codes, user_mfa_remembered_devices, user_totp_credentials, users},
};
use diesel::{ExpressionMethods, QueryDsl, dsl::now};
use diesel_async::{AsyncConnection, RunQueryDsl};
use nazo_identity::{
    IdentitySecurityEvent, IdentitySecurityEventType, IdentitySecurityOutcome,
    IdentitySecurityReason, TenantId, UserId, ports::RepositoryError,
};

mod backup_codes;
mod ports;
mod remembered_devices;
mod totp;

#[cfg(test)]
use backup_codes::validate_backup_hash_count;
#[cfg(test)]
use totp::{
    MfaSecretMigrationError, TOTP_ENVELOPE_VERSION, TOTP_MIN_PROTECTED_LEN, TOTP_NONCE_LEN,
    decode_totp_secret, protect_totp_secret, totp_aad,
};

#[derive(Clone)]
pub struct MfaRepository {
    pool: DbPool,
    totp_keys: Option<nazo_identity::ports::MfaTotpKeyRing>,
}

impl MfaRepository {
    #[must_use]
    pub fn new(pool: DbPool) -> Self {
        Self {
            pool,
            totp_keys: None,
        }
    }

    #[must_use]
    pub fn with_totp_key_ring(
        pool: DbPool,
        totp_keys: Option<nazo_identity::ports::MfaTotpKeyRing>,
    ) -> Self {
        Self { pool, totp_keys }
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

pub(super) fn map_mfa_error(error: diesel::result::Error) -> RepositoryError {
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

#[cfg(test)]
use aes_gcm::{
    Aes256Gcm, KeyInit,
    aead::{Aead, Payload},
};
#[cfg(test)]
use nazo_identity::{mfa::MFA_BACKUP_CODE_COUNT, ports::MfaTotpKeyRing};

#[cfg(test)]
#[path = "../../../tests/unit/repositories/mfa.rs"]
mod tests;
