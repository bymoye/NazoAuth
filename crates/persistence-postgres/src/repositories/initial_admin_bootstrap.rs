use chrono::{DateTime, Utc};
use diesel::{ExpressionMethods, OptionalExtension, QueryDsl, sql_query};
use diesel_async::{AsyncConnection as _, RunQueryDsl};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use crate::{
    DbPool, get_conn,
    schema::{identity_security_events, initial_admin_bootstrap, users},
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

    pub async fn ensure_claim(
        &self,
        token_hash: &str,
        expires_at: DateTime<Utc>,
    ) -> anyhow::Result<InitialAdminBootstrapState> {
        let mut connection = get_conn(&self.pool).await?;
        let token_hash = token_hash.to_owned();
        let tenant_id = self.tenant.tenant_id.as_uuid();
        connection
            .transaction::<_, diesel::result::Error, _>(async move |connection| {
                lock_initial_admin_bootstrap(connection).await?;
                let existing = initial_admin_bootstrap::table
                    .find(true)
                    .select((
                        initial_admin_bootstrap::token_hash,
                        initial_admin_bootstrap::expires_at,
                        initial_admin_bootstrap::consumed_at,
                        initial_admin_bootstrap::request_id,
                        initial_admin_bootstrap::request_email_hash,
                        initial_admin_bootstrap::claimed_user_id,
                        initial_admin_bootstrap::claim_result,
                        initial_admin_bootstrap::receipt_version,
                        initial_admin_bootstrap::claimed_at,
                    ))
                    .first::<(
                        String,
                        DateTime<Utc>,
                        Option<DateTime<Utc>>,
                        Option<String>,
                        Option<String>,
                        Option<Uuid>,
                        Option<String>,
                        Option<i16>,
                        Option<DateTime<Utc>>,
                    )>(connection)
                    .await
                    .optional()?;
                if let Some((
                    existing_hash,
                    existing_expiry,
                    Some(_),
                    request_id,
                    request_email_hash,
                    claimed_user_id,
                    claim_result,
                    receipt_version,
                    claimed_at,
                )) = &existing
                {
                    let complete_receipt = request_id.is_some()
                        && request_email_hash.is_some()
                        && claimed_user_id.is_some()
                        && claim_result.as_deref() == Some("created")
                        && *receipt_version == Some(1)
                        && claimed_at.is_some();
                    return if complete_receipt {
                        Ok(InitialAdminBootstrapState::Claimed {
                            expires_at: *existing_expiry,
                            expected_token_hash: existing_hash.clone(),
                        })
                    } else {
                        // Pre-receipt releases only persisted consumed_at. They are closed,
                        // not replayable: there is no durable response identity to prove.
                        Ok(InitialAdminBootstrapState::Closed)
                    };
                }
                if administrator_exists(connection, tenant_id).await? {
                    diesel::delete(initial_admin_bootstrap::table)
                        .execute(connection)
                        .await?;
                    return Ok(InitialAdminBootstrapState::Closed);
                }
                if let Some((existing_hash, existing_expiry, None, ..)) = existing
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
                        initial_admin_bootstrap::request_id.eq::<Option<String>>(None),
                        initial_admin_bootstrap::request_email_hash.eq::<Option<String>>(None),
                        initial_admin_bootstrap::claimed_user_id.eq::<Option<Uuid>>(None),
                        initial_admin_bootstrap::claim_result.eq::<Option<String>>(None),
                        initial_admin_bootstrap::receipt_version.eq::<Option<i16>>(None),
                        initial_admin_bootstrap::claimed_at.eq::<Option<DateTime<Utc>>>(None),
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
                        initial_admin_bootstrap::request_id.eq::<Option<String>>(None),
                        initial_admin_bootstrap::request_email_hash.eq::<Option<String>>(None),
                        initial_admin_bootstrap::claimed_user_id.eq::<Option<Uuid>>(None),
                        initial_admin_bootstrap::claim_result.eq::<Option<String>>(None),
                        initial_admin_bootstrap::receipt_version.eq::<Option<i16>>(None),
                        initial_admin_bootstrap::claimed_at.eq::<Option<DateTime<Utc>>>(None),
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
                let claim = initial_admin_bootstrap::table
                    .find(true)
                    .select((
                        initial_admin_bootstrap::token_hash,
                        initial_admin_bootstrap::expires_at,
                        initial_admin_bootstrap::consumed_at,
                        initial_admin_bootstrap::request_id,
                        initial_admin_bootstrap::request_email_hash,
                        initial_admin_bootstrap::claimed_user_id,
                        initial_admin_bootstrap::claim_result,
                        initial_admin_bootstrap::receipt_version,
                    ))
                    .for_update()
                    .first::<(
                        String,
                        DateTime<Utc>,
                        Option<DateTime<Utc>>,
                        Option<String>,
                        Option<String>,
                        Option<Uuid>,
                        Option<String>,
                        Option<i16>,
                    )>(connection)
                    .await
                    .optional()?;
                let Some((
                    expected_hash,
                    expires_at,
                    consumed_at,
                    stored_request_id,
                    stored_email_hash,
                    claimed_user_id,
                    claim_result,
                    receipt_version,
                )) = claim
                else {
                    return Ok(InitialAdminClaimOutcome::InvalidOrExpired);
                };
                if consumed_at.is_some() {
                    if stored_request_id.is_none()
                        && stored_email_hash.is_none()
                        && claimed_user_id.is_none()
                        && claim_result.is_none()
                        && receipt_version.is_none()
                    {
                        return Ok(InitialAdminClaimOutcome::Closed);
                    }
                    if expected_hash != token_hash {
                        return Ok(InitialAdminClaimOutcome::InvalidOrExpired);
                    }
                    if stored_request_id.as_deref() != Some(request_id.as_str())
                        || stored_email_hash.as_deref() != Some(email_hash.as_str())
                        || claim_result.as_deref() != Some("created")
                        || receipt_version != Some(1)
                    {
                        return Ok(InitialAdminClaimOutcome::IdempotencyConflict);
                    }
                    let Some(id) = claimed_user_id else {
                        return Ok(InitialAdminClaimOutcome::IdempotencyConflict);
                    };
                    let audit_count = identity_security_events::table
                        .filter(identity_security_events::request_id.eq(&request_id))
                        .filter(identity_security_events::event_type.eq("initial_admin_bootstrap"))
                        .filter(identity_security_events::outcome.eq("success"))
                        .filter(identity_security_events::tenant_id.eq(tenant_id))
                        .filter(identity_security_events::target_user_id.eq(Some(id)))
                        .select(diesel::dsl::count_star())
                        .first::<i64>(connection)
                        .await?;
                    if audit_count != 1 {
                        return Err(diesel::result::Error::NotFound);
                    }
                    return Ok(InitialAdminClaimOutcome::Created {
                        request_id,
                        id,
                        email,
                    });
                }
                if administrator_exists(connection, tenant_id).await? {
                    return Ok(InitialAdminClaimOutcome::Closed);
                }
                if expected_hash != token_hash || expires_at <= Utc::now() {
                    return Ok(InitialAdminClaimOutcome::InvalidOrExpired);
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
                diesel::update(initial_admin_bootstrap::table.find(true))
                    .set((
                        initial_admin_bootstrap::consumed_at.eq(Some(now)),
                        initial_admin_bootstrap::request_id.eq(Some(&request_id)),
                        initial_admin_bootstrap::request_email_hash.eq(Some(&email_hash)),
                        initial_admin_bootstrap::claimed_user_id.eq(Some(id)),
                        initial_admin_bootstrap::claim_result.eq(Some("created")),
                        initial_admin_bootstrap::receipt_version.eq(Some(1_i16)),
                        initial_admin_bootstrap::claimed_at.eq(Some(now)),
                        initial_admin_bootstrap::updated_at.eq(now),
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InitialAdminBootstrapState {
    Closed,
    Ready {
        expires_at: DateTime<Utc>,
    },
    Claimed {
        expires_at: DateTime<Utc>,
        expected_token_hash: String,
    },
    OwnedByAnotherInstance {
        expires_at: DateTime<Utc>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InitialAdminClaimOutcome {
    Created {
        request_id: String,
        id: Uuid,
        email: String,
    },
    Closed,
    InvalidOrExpired,
    EmailConflict,
    IdempotencyConflict,
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
