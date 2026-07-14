use chrono::{DateTime, Utc};
use diesel::{ExpressionMethods, QueryDsl};
use diesel_async::{AsyncConnection, RunQueryDsl};
use nazo_identity::ports::RepositoryError;
use uuid::Uuid;

use crate::{
    DbPool,
    schema::{access_token_revocations, oauth_tokens},
};

use super::tokens::lock_refresh_family;

#[derive(Clone)]
pub struct AuthorizationRepository {
    pool: DbPool,
}

impl AuthorizationRepository {
    #[must_use]
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    pub async fn revoke_issued_tokens(
        &self,
        tenant_id: Uuid,
        client_id: Uuid,
        access_token_jti: &str,
        access_token_expires_at: Option<DateTime<Utc>>,
        refresh_token_family_id: Option<Uuid>,
    ) -> Result<(), RepositoryError> {
        let mut connection = self
            .pool
            .get()
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        connection
            .transaction::<(), diesel::result::Error, _>(async |connection| {
                if let Some(family_id) = refresh_token_family_id {
                    lock_refresh_family(connection, family_id).await?;
                }
                if let Some(access_token_expires_at) = access_token_expires_at {
                    diesel::insert_into(access_token_revocations::table)
                        .values((
                            access_token_revocations::access_token_jti_blake3
                                .eq(blake3_hex(access_token_jti)),
                            access_token_revocations::tenant_id.eq(tenant_id),
                            access_token_revocations::client_id.eq(client_id),
                            access_token_revocations::revoked_at.eq(Utc::now()),
                            access_token_revocations::expires_at.eq(access_token_expires_at),
                        ))
                        .on_conflict((
                            access_token_revocations::tenant_id,
                            access_token_revocations::access_token_jti_blake3,
                        ))
                        .do_nothing()
                        .execute(connection)
                        .await?;
                }
                if let Some(family_id) = refresh_token_family_id {
                    diesel::update(
                        oauth_tokens::table
                            .filter(oauth_tokens::tenant_id.eq(tenant_id))
                            .filter(oauth_tokens::client_id.eq(client_id))
                            .filter(oauth_tokens::token_family_id.eq(family_id))
                            .filter(oauth_tokens::revoked_at.is_null()),
                    )
                    .set(oauth_tokens::revoked_at.eq(diesel::dsl::now))
                    .execute(connection)
                    .await?;
                }
                Ok(())
            })
            .await
            .map_err(map_error)
    }
}

fn blake3_hex(value: &str) -> String {
    blake3::hash(value.as_bytes()).to_hex().to_string()
}

fn map_error(error: diesel::result::Error) -> RepositoryError {
    RepositoryError::Unexpected(error.to_string())
}
