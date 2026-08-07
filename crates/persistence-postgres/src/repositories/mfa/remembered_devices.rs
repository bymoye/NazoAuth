use super::MfaRepository;
use crate::schema::user_mfa_remembered_devices;
use diesel::{ExpressionMethods, OptionalExtension, QueryDsl, dsl::now};
use diesel_async::{AsyncConnection, RunQueryDsl};
use nazo_identity::{TenantId, UserId, ports::RepositoryError};

impl MfaRepository {
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
