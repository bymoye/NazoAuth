use chrono::Utc;
use diesel::{ExpressionMethods, OptionalExtension, QueryDsl, sql_query};
use diesel_async::{AsyncConnection as _, RunQueryDsl};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

pub use nazo_persistence::{InitialAdminBootstrapState, InitialAdminClaimOutcome};

use crate::{
    DbPool, get_conn,
    schema::{identity_security_events, initial_admin_bootstrap_receipts, users},
};

const INITIAL_ADMIN_BOOTSTRAP_LOCK: i64 = 564_196_923_451_771_042;

#[derive(Clone)]
pub struct InitialAdminBootstrapRepository {
    pool: DbPool,
    tenant: nazo_identity::TenantContext,
}

impl InitialAdminBootstrapRepository {
    #[must_use]
    pub fn new(pool: DbPool, tenant: nazo_identity::TenantContext) -> Self {
        Self { pool, tenant }
    }

    pub async fn load_state(&self) -> anyhow::Result<InitialAdminBootstrapState> {
        let mut connection = get_conn(&self.pool).await?;
        let tenant_id = self.tenant.tenant_id.as_uuid();
        if let Some(expected_token_hash) = initial_admin_bootstrap_receipts::table
            .find(true)
            .select(initial_admin_bootstrap_receipts::token_hash)
            .first::<String>(&mut connection)
            .await
            .optional()?
        {
            return Ok(InitialAdminBootstrapState::Claimed {
                expected_token_hash,
            });
        }
        if administrator_exists(&mut connection, tenant_id).await? {
            return Ok(InitialAdminBootstrapState::Closed);
        }
        Ok(InitialAdminBootstrapState::Ready)
    }

    pub async fn claim(
        &self,
        request_id: &str,
        token_hash: &str,
        email: &str,
        password_hash: nazo_identity::ports::PasswordHashInput,
    ) -> anyhow::Result<InitialAdminClaimOutcome> {
        let mut connection = get_conn(&self.pool).await?;
        let request_id = request_id.to_owned();
        let token_hash = token_hash.to_owned();
        let email = email.to_owned();
        let email_hash = hash_value(&email);
        let password_hash = password_hash.into_persistence_value();
        let tenant_id = self.tenant.tenant_id.as_uuid();
        let realm_id = self.tenant.realm_id.as_uuid();
        let organization_id = self.tenant.organization_id.as_uuid();
        connection
            .transaction::<_, diesel::result::Error, _>(async move |connection| {
                lock_initial_admin_bootstrap(connection).await?;
                let claim = initial_admin_bootstrap_receipts::table
                    .find(true)
                    .select((
                        initial_admin_bootstrap_receipts::token_hash,
                        initial_admin_bootstrap_receipts::request_id,
                        initial_admin_bootstrap_receipts::request_email_hash,
                        initial_admin_bootstrap_receipts::claimed_user_id,
                    ))
                    .for_update()
                    .first::<(String, String, String, Uuid)>(connection)
                    .await
                    .optional()?;
                if let Some((
                    expected_hash,
                    stored_request_id,
                    stored_email_hash,
                    claimed_user_id,
                )) = claim
                {
                    if expected_hash != token_hash {
                        return Ok(InitialAdminClaimOutcome::Closed);
                    }
                    if stored_request_id != request_id || stored_email_hash != email_hash {
                        return Ok(InitialAdminClaimOutcome::IdempotencyConflict);
                    }
                    let audit_count = identity_security_events::table
                        .filter(identity_security_events::request_id.eq(&request_id))
                        .filter(identity_security_events::event_type.eq("initial_admin_bootstrap"))
                        .filter(identity_security_events::outcome.eq("success"))
                        .filter(identity_security_events::tenant_id.eq(tenant_id))
                        .filter(identity_security_events::target_user_id.eq(Some(claimed_user_id)))
                        .select(diesel::dsl::count_star())
                        .first::<i64>(connection)
                        .await?;
                    if audit_count != 1 {
                        return Err(diesel::result::Error::NotFound);
                    }
                    return Ok(InitialAdminClaimOutcome::Created {
                        request_id,
                        id: claimed_user_id,
                        email,
                    });
                }
                if administrator_exists(connection, tenant_id).await? {
                    return Ok(InitialAdminClaimOutcome::Closed);
                }
                if users::table
                    .filter(users::tenant_id.eq(tenant_id))
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
                let now = Utc::now();
                let username = format!("admin_{}", id.simple());
                diesel::insert_into(users::table)
                    .values((
                        users::id.eq(id),
                        users::tenant_id.eq(tenant_id),
                        users::realm_id.eq(realm_id),
                        users::organization_id.eq(organization_id),
                        users::username.eq(username),
                        users::email.eq(&email),
                        users::password_hash.eq(password_hash),
                        users::email_verified.eq(true),
                        users::role.eq("admin"),
                        users::admin_level.eq(1),
                    ))
                    .execute(connection)
                    .await?;
                diesel::insert_into(initial_admin_bootstrap_receipts::table)
                    .values((
                        initial_admin_bootstrap_receipts::singleton.eq(true),
                        initial_admin_bootstrap_receipts::token_hash.eq(&token_hash),
                        initial_admin_bootstrap_receipts::request_id.eq(&request_id),
                        initial_admin_bootstrap_receipts::request_email_hash.eq(&email_hash),
                        initial_admin_bootstrap_receipts::claimed_user_id.eq(id),
                        initial_admin_bootstrap_receipts::created_at.eq(now),
                    ))
                    .execute(connection)
                    .await?;
                super::audit::insert_initial_admin_created_event(
                    connection,
                    &request_id,
                    id,
                    tenant_id,
                    now,
                )
                .await?;
                Ok(InitialAdminClaimOutcome::Created {
                    request_id,
                    id,
                    email,
                })
            })
            .await
            .map_err(anyhow::Error::from)
    }
}

fn hash_value(value: &str) -> String {
    let mut encoded = String::with_capacity(64);
    for byte in Sha256::digest(value.as_bytes()) {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    encoded
}

async fn administrator_exists(
    connection: &mut diesel_async::AsyncPgConnection,
    tenant_id: Uuid,
) -> diesel::QueryResult<bool> {
    diesel::select(diesel::dsl::exists(
        users::table
            .filter(users::tenant_id.eq(tenant_id))
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

impl nazo_persistence::InitialAdminBootstrapStore for InitialAdminBootstrapRepository {
    fn load_state(
        &self,
    ) -> futures_util::future::BoxFuture<
        '_,
        Result<InitialAdminBootstrapState, nazo_identity::ports::RepositoryError>,
    > {
        Box::pin(async {
            InitialAdminBootstrapRepository::load_state(self)
                .await
                .map_err(|_| nazo_identity::ports::RepositoryError::Unavailable)
        })
    }

    fn claim<'a>(
        &'a self,
        request_id: &'a str,
        token_hash: &'a str,
        email: &'a str,
        password_hash: nazo_identity::ports::PasswordHashInput,
    ) -> futures_util::future::BoxFuture<
        'a,
        Result<InitialAdminClaimOutcome, nazo_identity::ports::RepositoryError>,
    > {
        Box::pin(async move {
            InitialAdminBootstrapRepository::claim(
                self,
                request_id,
                token_hash,
                email,
                password_hash,
            )
            .await
            .map_err(|_| nazo_identity::ports::RepositoryError::Unavailable)
        })
    }
}
