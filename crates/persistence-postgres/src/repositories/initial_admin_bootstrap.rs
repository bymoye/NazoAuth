use chrono::{DateTime, Utc};
use diesel::{ExpressionMethods, OptionalExtension, QueryDsl, sql_query};
use diesel_async::{AsyncConnection as _, RunQueryDsl};
use uuid::Uuid;

use crate::{
    DbPool, get_conn,
    schema::{initial_admin_bootstrap, users},
};

const INITIAL_ADMIN_BOOTSTRAP_LOCK: i64 = 564_196_923_451_771_042;

#[derive(Clone)]
pub struct InitialAdminBootstrapRepository {
    pool: DbPool,
}

impl InitialAdminBootstrapRepository {
    #[must_use]
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    pub async fn ensure_claim(
        &self,
        token_hash: &str,
        expires_at: DateTime<Utc>,
    ) -> anyhow::Result<InitialAdminBootstrapState> {
        let mut connection = get_conn(&self.pool).await?;
        let token_hash = token_hash.to_owned();
        connection
            .transaction::<_, diesel::result::Error, _>(async move |connection| {
                lock_initial_admin_bootstrap(connection).await?;
                if administrator_exists(connection).await? {
                    diesel::delete(initial_admin_bootstrap::table)
                        .execute(connection)
                        .await?;
                    return Ok(InitialAdminBootstrapState::Closed);
                }

                let existing = initial_admin_bootstrap::table
                    .find(true)
                    .select((
                        initial_admin_bootstrap::token_hash,
                        initial_admin_bootstrap::expires_at,
                        initial_admin_bootstrap::consumed_at,
                    ))
                    .first::<(String, DateTime<Utc>, Option<DateTime<Utc>>)>(connection)
                    .await
                    .optional()?;
                if let Some((existing_hash, existing_expiry, None)) = existing
                    && existing_expiry > Utc::now()
                {
                    return if existing_hash == token_hash {
                        Ok(InitialAdminBootstrapState::Ready {
                            expires_at: existing_expiry,
                        })
                    } else {
                        Ok(InitialAdminBootstrapState::OwnedByAnotherInstance {
                            expires_at: existing_expiry,
                        })
                    };
                }

                diesel::insert_into(initial_admin_bootstrap::table)
                    .values((
                        initial_admin_bootstrap::singleton.eq(true),
                        initial_admin_bootstrap::token_hash.eq(token_hash),
                        initial_admin_bootstrap::expires_at.eq(expires_at),
                        initial_admin_bootstrap::consumed_at.eq::<Option<DateTime<Utc>>>(None),
                        initial_admin_bootstrap::created_at.eq(Utc::now()),
                        initial_admin_bootstrap::updated_at.eq(Utc::now()),
                    ))
                    .on_conflict(initial_admin_bootstrap::singleton)
                    .do_update()
                    .set((
                        initial_admin_bootstrap::token_hash.eq(diesel::upsert::excluded(
                            initial_admin_bootstrap::token_hash,
                        )),
                        initial_admin_bootstrap::expires_at.eq(diesel::upsert::excluded(
                            initial_admin_bootstrap::expires_at,
                        )),
                        initial_admin_bootstrap::consumed_at.eq::<Option<DateTime<Utc>>>(None),
                        initial_admin_bootstrap::created_at.eq(Utc::now()),
                        initial_admin_bootstrap::updated_at.eq(Utc::now()),
                    ))
                    .execute(connection)
                    .await?;
                Ok(InitialAdminBootstrapState::Ready { expires_at })
            })
            .await
            .map_err(anyhow::Error::from)
    }

    pub async fn claim(
        &self,
        token_hash: &str,
        email: &str,
        password_hash: nazo_identity::ports::PasswordHashInput,
    ) -> anyhow::Result<InitialAdminClaimOutcome> {
        let mut connection = get_conn(&self.pool).await?;
        let token_hash = token_hash.to_owned();
        let email = email.to_owned();
        let password_hash = password_hash.into_persistence_value();
        connection
            .transaction::<_, diesel::result::Error, _>(async move |connection| {
                lock_initial_admin_bootstrap(connection).await?;
                if administrator_exists(connection).await? {
                    return Ok(InitialAdminClaimOutcome::Closed);
                }
                let claim = initial_admin_bootstrap::table
                    .find(true)
                    .select((
                        initial_admin_bootstrap::token_hash,
                        initial_admin_bootstrap::expires_at,
                        initial_admin_bootstrap::consumed_at,
                    ))
                    .for_update()
                    .first::<(String, DateTime<Utc>, Option<DateTime<Utc>>)>(connection)
                    .await
                    .optional()?;
                let Some((expected_hash, expires_at, None)) = claim else {
                    return Ok(InitialAdminClaimOutcome::InvalidOrExpired);
                };
                if expected_hash != token_hash || expires_at <= Utc::now() {
                    return Ok(InitialAdminClaimOutcome::InvalidOrExpired);
                }
                if users::table
                    .filter(users::tenant_id.eq(Uuid::from_u128(1)))
                    .filter(users::email.eq(&email))
                    .select(users::id)
                    .first::<Uuid>(connection)
                    .await
                    .optional()?
                    .is_some()
                {
                    return Ok(InitialAdminClaimOutcome::EmailConflict);
                }

                let id = Uuid::now_v7();
                let username = format!("admin_{}", id.simple());
                diesel::insert_into(users::table)
                    .values((
                        users::id.eq(id),
                        users::tenant_id.eq(Uuid::from_u128(1)),
                        users::realm_id.eq(Uuid::from_u128(2)),
                        users::organization_id.eq(Uuid::from_u128(3)),
                        users::username.eq(username),
                        users::email.eq(&email),
                        users::password_hash.eq(password_hash),
                        users::email_verified.eq(true),
                        users::role.eq("admin"),
                        users::admin_level.eq(1),
                    ))
                    .execute(connection)
                    .await?;
                diesel::update(initial_admin_bootstrap::table.find(true))
                    .set((
                        initial_admin_bootstrap::consumed_at.eq(Some(Utc::now())),
                        initial_admin_bootstrap::updated_at.eq(Utc::now()),
                    ))
                    .execute(connection)
                    .await?;
                Ok(InitialAdminClaimOutcome::Created { id, email })
            })
            .await
            .map_err(anyhow::Error::from)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InitialAdminBootstrapState {
    Closed,
    Ready { expires_at: DateTime<Utc> },
    OwnedByAnotherInstance { expires_at: DateTime<Utc> },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InitialAdminClaimOutcome {
    Created { id: Uuid, email: String },
    Closed,
    InvalidOrExpired,
    EmailConflict,
}

async fn administrator_exists(
    connection: &mut diesel_async::AsyncPgConnection,
) -> diesel::QueryResult<bool> {
    diesel::select(diesel::dsl::exists(
        users::table
            .filter(users::tenant_id.eq(Uuid::from_u128(1)))
            .filter(users::role.eq("admin"))
            .filter(users::admin_level.gt(0))
            .filter(users::is_active.eq(true)),
    ))
    .get_result(connection)
    .await
}

async fn lock_initial_admin_bootstrap(
    connection: &mut diesel_async::AsyncPgConnection,
) -> diesel::QueryResult<()> {
    sql_query("SELECT pg_advisory_xact_lock($1)")
        .bind::<diesel::sql_types::BigInt, _>(INITIAL_ADMIN_BOOTSTRAP_LOCK)
        .execute(connection)
        .await?;
    Ok(())
}
