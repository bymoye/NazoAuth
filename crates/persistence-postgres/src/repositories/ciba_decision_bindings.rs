use chrono::{DateTime, Duration, Utc};
use diesel::{OptionalExtension, QueryableByName, sql_query, sql_types};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use nazo_identity::ports::RepositoryError;
use uuid::Uuid;

use crate::{DbPool, get_conn};

const CIBA_GRANT_TYPE: &str = "urn:openid:params:grant-type:ciba";
pub const CIBA_DECISION_CLAIM_SECONDS: i64 = 30;

#[derive(Clone, Eq, PartialEq)]
pub struct CibaDecisionBinding {
    pub generation: Uuid,
    pub tenant_id: Uuid,
    pub resource_id: String,
    pub resource_digest: String,
    pub oauth_client_id: Uuid,
    pub user_id: Uuid,
    pub token_sha256: String,
    pub expires_at: DateTime<Utc>,
    pub active: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

impl std::fmt::Debug for CibaDecisionBinding {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CibaDecisionBinding")
            .field("generation", &self.generation)
            .field("tenant_id", &self.tenant_id)
            .field("resource_id", &self.resource_id)
            .field("resource_digest", &"[REDACTED]")
            .field("oauth_client_id", &self.oauth_client_id)
            .field("user_id", &self.user_id)
            .field("token_sha256", &"[REDACTED]")
            .field("expires_at", &self.expires_at)
            .field("active", &self.active)
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .field("revoked_at", &self.revoked_at)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CibaDecisionBindingWrite {
    Applied(CibaDecisionBinding),
    Replayed(CibaDecisionBinding),
    Conflict(CibaDecisionBinding),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CibaDecisionClaimOutcome {
    Acquired {
        binding: Box<CibaDecisionBinding>,
        claim_id: Uuid,
        claim_expires_at: DateTime<Utc>,
    },
    Busy {
        claim_expires_at: DateTime<Utc>,
    },
    NotFound,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CibaDecisionBindingRevoke {
    Revoked(CibaDecisionBinding),
    AlreadyAbsent,
    Conflict(CibaDecisionBinding),
    Busy { claim_expires_at: DateTime<Utc> },
}

pub struct NewCibaDecisionBinding<'a> {
    pub generation: Uuid,
    pub tenant_id: Uuid,
    pub resource_id: &'a str,
    pub resource_digest: &'a str,
    pub oauth_client_id: Uuid,
    pub user_id: Uuid,
    pub token_sha256: &'a str,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone)]
pub struct CibaDecisionBindingRepository {
    pool: DbPool,
}

#[derive(QueryableByName)]
struct BindingRow {
    #[diesel(sql_type = sql_types::Uuid)]
    generation: Uuid,
    #[diesel(sql_type = sql_types::Uuid)]
    tenant_id: Uuid,
    #[diesel(sql_type = sql_types::Varchar)]
    resource_id: String,
    #[diesel(sql_type = sql_types::Varchar)]
    resource_digest: String,
    #[diesel(sql_type = sql_types::Uuid)]
    oauth_client_id: Uuid,
    #[diesel(sql_type = sql_types::Uuid)]
    user_id: Uuid,
    #[diesel(sql_type = sql_types::Varchar)]
    token_sha256: String,
    #[diesel(sql_type = sql_types::Timestamptz)]
    expires_at: DateTime<Utc>,
    #[diesel(sql_type = sql_types::Bool)]
    active: bool,
    #[diesel(sql_type = sql_types::Nullable<sql_types::Uuid>)]
    decision_claim_id: Option<Uuid>,
    #[diesel(sql_type = sql_types::Nullable<sql_types::Timestamptz>)]
    decision_claim_acquired_at: Option<DateTime<Utc>>,
    #[diesel(sql_type = sql_types::Nullable<sql_types::Timestamptz>)]
    decision_claim_expires_at: Option<DateTime<Utc>>,
    #[diesel(sql_type = sql_types::Timestamptz)]
    created_at: DateTime<Utc>,
    #[diesel(sql_type = sql_types::Timestamptz)]
    updated_at: DateTime<Utc>,
    #[diesel(sql_type = sql_types::Nullable<sql_types::Timestamptz>)]
    revoked_at: Option<DateTime<Utc>>,
}

#[derive(QueryableByName)]
struct DependencyStateRow {
    #[diesel(sql_type = sql_types::Bool)]
    client_active: bool,
    #[diesel(sql_type = sql_types::Bool)]
    client_has_ciba_grant: bool,
    #[diesel(sql_type = sql_types::Bool)]
    user_active: bool,
}

#[derive(QueryableByName)]
struct AdvisoryLockRow {
    #[diesel(sql_type = sql_types::Bool)]
    locked: bool,
}

impl TryFrom<BindingRow> for CibaDecisionBinding {
    type Error = RepositoryError;

    fn try_from(row: BindingRow) -> Result<Self, Self::Error> {
        validate_resource_identity(&row.resource_id, &row.resource_digest)?;
        validate_sha256("CIBA automated-decision token", &row.token_sha256)?;
        if row.active == row.revoked_at.is_some() {
            return Err(RepositoryError::Consistency(
                "CIBA decision binding active state is inconsistent".to_owned(),
            ));
        }
        validate_claim_state(
            row.decision_claim_id,
            row.decision_claim_acquired_at,
            row.decision_claim_expires_at,
            row.expires_at,
        )?;
        Ok(Self {
            generation: row.generation,
            tenant_id: row.tenant_id,
            resource_id: row.resource_id,
            resource_digest: row.resource_digest,
            oauth_client_id: row.oauth_client_id,
            user_id: row.user_id,
            token_sha256: row.token_sha256,
            expires_at: row.expires_at,
            active: row.active,
            created_at: row.created_at,
            updated_at: row.updated_at,
            revoked_at: row.revoked_at,
        })
    }
}

impl CibaDecisionBindingRepository {
    #[must_use]
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    pub async fn claim_active(
        &self,
        tenant_id: Uuid,
        token_sha256: &str,
        oauth_client_public_id: &str,
        user_id: Uuid,
        claim_id: Uuid,
        now: DateTime<Utc>,
    ) -> Result<CibaDecisionClaimOutcome, RepositoryError> {
        let mut connection = get_conn(&self.pool)
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        Self::claim_active_on_connection(
            &mut connection,
            tenant_id,
            token_sha256,
            oauth_client_public_id,
            user_id,
            claim_id,
            now,
        )
        .await
    }

    pub async fn release_claim(
        &self,
        tenant_id: Uuid,
        generation: Uuid,
        claim_id: Uuid,
    ) -> Result<bool, RepositoryError> {
        let mut connection = get_conn(&self.pool)
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        Self::release_claim_on_connection(&mut connection, tenant_id, generation, claim_id).await
    }

    pub async fn apply_on_connection(
        connection: &mut AsyncPgConnection,
        binding: NewCibaDecisionBinding<'_>,
    ) -> Result<CibaDecisionBindingWrite, RepositoryError> {
        validate_resource_identity(binding.resource_id, binding.resource_digest)?;
        validate_sha256("CIBA automated-decision token", binding.token_sha256)?;
        if binding.expires_at <= Utc::now() {
            return Err(RepositoryError::Consistency(
                "CIBA decision binding expiry must be in the future".to_owned(),
            ));
        }
        lock_identity_on_connection(connection, binding.tenant_id, binding.resource_id).await?;
        validate_active_dependencies_on_connection(
            connection,
            binding.tenant_id,
            binding.oauth_client_id,
            binding.user_id,
        )
        .await?;

        if let Some(current) = select_active_by_resource_on_connection(
            connection,
            binding.tenant_id,
            binding.resource_id,
        )
        .await?
        {
            return if current.generation == binding.generation
                && current.resource_digest == binding.resource_digest
                && current.oauth_client_id == binding.oauth_client_id
                && current.user_id == binding.user_id
                && current.token_sha256 == binding.token_sha256
                // PostgreSQL stores `timestamptz` at microsecond precision.
                // Compare at that authoritative precision so an exact retry
                // of the original higher-precision request is idempotent.
                && current.expires_at.timestamp_micros()
                    == binding.expires_at.timestamp_micros()
            {
                Ok(CibaDecisionBindingWrite::Replayed(current))
            } else {
                Ok(CibaDecisionBindingWrite::Conflict(current))
            };
        }
        if let Some(current) =
            Self::by_generation_on_connection(connection, binding.tenant_id, binding.generation)
                .await?
        {
            return Ok(CibaDecisionBindingWrite::Conflict(current));
        }

        let inserted = sql_query(
            "INSERT INTO ciba_decision_bindings
                (generation, tenant_id, resource_id, resource_digest,
                 oauth_client_id, user_id, token_sha256, expires_at, active)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, TRUE)
             RETURNING generation, tenant_id, resource_id, resource_digest,
                       oauth_client_id, user_id, token_sha256, expires_at, active,
                       decision_claim_id, decision_claim_acquired_at,
                       decision_claim_expires_at, created_at, updated_at, revoked_at",
        )
        .bind::<sql_types::Uuid, _>(binding.generation)
        .bind::<sql_types::Uuid, _>(binding.tenant_id)
        .bind::<sql_types::Varchar, _>(binding.resource_id)
        .bind::<sql_types::Varchar, _>(binding.resource_digest)
        .bind::<sql_types::Uuid, _>(binding.oauth_client_id)
        .bind::<sql_types::Uuid, _>(binding.user_id)
        .bind::<sql_types::Varchar, _>(binding.token_sha256)
        .bind::<sql_types::Timestamptz, _>(binding.expires_at)
        .get_result::<BindingRow>(connection)
        .await
        .map_err(map_error)?
        .try_into()?;
        Ok(CibaDecisionBindingWrite::Applied(inserted))
    }

    pub async fn by_generation_on_connection(
        connection: &mut AsyncPgConnection,
        tenant_id: Uuid,
        generation: Uuid,
    ) -> Result<Option<CibaDecisionBinding>, RepositoryError> {
        select_binding_by_uuid_on_connection(
            connection,
            "binding.generation = $2",
            tenant_id,
            generation,
        )
        .await
    }

    pub async fn active_for_oauth_client_on_connection(
        connection: &mut AsyncPgConnection,
        tenant_id: Uuid,
        oauth_client_id: Uuid,
    ) -> Result<Option<CibaDecisionBinding>, RepositoryError> {
        select_binding_by_uuid_on_connection(
            connection,
            "binding.oauth_client_id = $2 AND binding.active",
            tenant_id,
            oauth_client_id,
        )
        .await
    }

    pub async fn active_for_user_on_connection(
        connection: &mut AsyncPgConnection,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<CibaDecisionBinding>, RepositoryError> {
        select_binding_by_uuid_on_connection(
            connection,
            "binding.user_id = $2 AND binding.active",
            tenant_id,
            user_id,
        )
        .await
    }

    pub async fn lookup_active_on_connection(
        connection: &mut AsyncPgConnection,
        tenant_id: Uuid,
        token_sha256: &str,
        oauth_client_public_id: &str,
        user_id: Uuid,
        now: DateTime<Utc>,
    ) -> Result<Option<CibaDecisionBinding>, RepositoryError> {
        validate_lookup_input(token_sha256, oauth_client_public_id)?;
        eligible_binding_on_connection(
            connection,
            tenant_id,
            token_sha256,
            oauth_client_public_id,
            user_id,
            now,
        )
        .await?
        .map(CibaDecisionBinding::try_from)
        .transpose()
    }

    pub async fn claim_active_on_connection(
        connection: &mut AsyncPgConnection,
        tenant_id: Uuid,
        token_sha256: &str,
        oauth_client_public_id: &str,
        user_id: Uuid,
        claim_id: Uuid,
        now: DateTime<Utc>,
    ) -> Result<CibaDecisionClaimOutcome, RepositoryError> {
        validate_lookup_input(token_sha256, oauth_client_public_id)?;
        let claim_expires_at = now
            .checked_add_signed(Duration::seconds(CIBA_DECISION_CLAIM_SECONDS))
            .ok_or_else(|| {
                RepositoryError::Consistency(
                    "CIBA decision claim deadline is out of range".to_owned(),
                )
            })?;
        let acquired = sql_query(
            "UPDATE ciba_decision_bindings AS binding
             SET decision_claim_id = $6,
                 decision_claim_acquired_at = CASE
                     WHEN decision_claim_id = $6 AND decision_claim_expires_at > $5
                     THEN decision_claim_acquired_at ELSE $5 END,
                 decision_claim_expires_at = CASE
                     WHEN decision_claim_id = $6 AND decision_claim_expires_at > $5
                     THEN decision_claim_expires_at ELSE LEAST(binding.expires_at, $7) END,
                 updated_at = CURRENT_TIMESTAMP
             FROM oauth_clients AS client, users AS subject
             WHERE binding.tenant_id = $1
               AND binding.token_sha256 = $2
               AND client.tenant_id = binding.tenant_id
               AND client.id = binding.oauth_client_id
               AND client.client_id = $3
               AND client.is_active
               AND jsonb_typeof(client.grant_types) = 'array'
               AND client.grant_types @> jsonb_build_array($8::TEXT)
               AND subject.tenant_id = binding.tenant_id
               AND subject.id = binding.user_id
               AND subject.id = $4
               AND subject.is_active
               AND binding.active
               AND binding.expires_at > $5
               AND (
                   binding.decision_claim_id IS NULL
                   OR binding.decision_claim_expires_at <= $5
                   OR binding.decision_claim_id = $6
               )
             RETURNING binding.generation, binding.tenant_id, binding.resource_id,
                       binding.resource_digest, binding.oauth_client_id, binding.user_id,
                       binding.token_sha256, binding.expires_at, binding.active,
                       binding.decision_claim_id, binding.decision_claim_acquired_at,
                       binding.decision_claim_expires_at, binding.created_at,
                       binding.updated_at, binding.revoked_at",
        )
        .bind::<sql_types::Uuid, _>(tenant_id)
        .bind::<sql_types::Varchar, _>(token_sha256)
        .bind::<sql_types::Varchar, _>(oauth_client_public_id)
        .bind::<sql_types::Uuid, _>(user_id)
        .bind::<sql_types::Timestamptz, _>(now)
        .bind::<sql_types::Uuid, _>(claim_id)
        .bind::<sql_types::Timestamptz, _>(claim_expires_at)
        .bind::<sql_types::Text, _>(CIBA_GRANT_TYPE)
        .get_result::<BindingRow>(connection)
        .await
        .optional()
        .map_err(map_error)?;
        if let Some(row) = acquired {
            let persisted_deadline = row.decision_claim_expires_at.ok_or_else(|| {
                RepositoryError::Consistency(
                    "acquired CIBA decision claim has no deadline".to_owned(),
                )
            })?;
            return Ok(CibaDecisionClaimOutcome::Acquired {
                binding: Box::new(row.try_into()?),
                claim_id,
                claim_expires_at: persisted_deadline,
            });
        }

        let Some(row) = eligible_binding_on_connection(
            connection,
            tenant_id,
            token_sha256,
            oauth_client_public_id,
            user_id,
            now,
        )
        .await?
        else {
            return Ok(CibaDecisionClaimOutcome::NotFound);
        };
        match (row.decision_claim_id, row.decision_claim_expires_at) {
            (Some(other_claim_id), Some(deadline))
                if other_claim_id != claim_id && deadline > now =>
            {
                Ok(CibaDecisionClaimOutcome::Busy {
                    claim_expires_at: deadline,
                })
            }
            _ => Err(RepositoryError::Conflict),
        }
    }

    pub async fn release_claim_on_connection(
        connection: &mut AsyncPgConnection,
        tenant_id: Uuid,
        generation: Uuid,
        claim_id: Uuid,
    ) -> Result<bool, RepositoryError> {
        sql_query(
            "UPDATE ciba_decision_bindings
             SET decision_claim_id = NULL,
                 decision_claim_acquired_at = NULL,
                 decision_claim_expires_at = NULL,
                 updated_at = CURRENT_TIMESTAMP
             WHERE tenant_id = $1 AND generation = $2 AND decision_claim_id = $3",
        )
        .bind::<sql_types::Uuid, _>(tenant_id)
        .bind::<sql_types::Uuid, _>(generation)
        .bind::<sql_types::Uuid, _>(claim_id)
        .execute(connection)
        .await
        .map(|updated| updated == 1)
        .map_err(map_error)
    }

    pub async fn revoke_on_connection(
        connection: &mut AsyncPgConnection,
        tenant_id: Uuid,
        generation: Uuid,
        resource_id: &str,
        expected_digest: &str,
        now: DateTime<Utc>,
    ) -> Result<CibaDecisionBindingRevoke, RepositoryError> {
        validate_resource_identity(resource_id, expected_digest)?;
        lock_identity_on_connection(connection, tenant_id, resource_id).await?;
        let Some(current) =
            select_active_by_resource_on_connection(connection, tenant_id, resource_id).await?
        else {
            return Ok(CibaDecisionBindingRevoke::AlreadyAbsent);
        };
        if current.generation != generation || current.resource_digest != expected_digest {
            return Ok(CibaDecisionBindingRevoke::Conflict(current));
        }
        if let Some(claim_expires_at) =
            current_claim_deadline_on_connection(connection, tenant_id, generation)
                .await?
                .filter(|deadline| *deadline > now)
        {
            return Ok(CibaDecisionBindingRevoke::Busy { claim_expires_at });
        }
        let revoked = sql_query(
            "UPDATE ciba_decision_bindings
             SET active = FALSE,
                 decision_claim_id = NULL,
                 decision_claim_acquired_at = NULL,
                 decision_claim_expires_at = NULL,
                 revoked_at = $6,
                 updated_at = CURRENT_TIMESTAMP
             WHERE tenant_id = $1 AND generation = $2 AND resource_id = $3
               AND resource_digest = $4 AND active
               AND (decision_claim_id IS NULL OR decision_claim_expires_at <= $5)
             RETURNING generation, tenant_id, resource_id, resource_digest,
                       oauth_client_id, user_id, token_sha256, expires_at, active,
                       decision_claim_id, decision_claim_acquired_at,
                       decision_claim_expires_at, created_at, updated_at, revoked_at",
        )
        .bind::<sql_types::Uuid, _>(tenant_id)
        .bind::<sql_types::Uuid, _>(generation)
        .bind::<sql_types::Varchar, _>(resource_id)
        .bind::<sql_types::Varchar, _>(expected_digest)
        .bind::<sql_types::Timestamptz, _>(now)
        .bind::<sql_types::Timestamptz, _>(now)
        .get_result::<BindingRow>(connection)
        .await
        .optional()
        .map_err(map_error)?;
        if let Some(row) = revoked {
            return Ok(CibaDecisionBindingRevoke::Revoked(row.try_into()?));
        }
        if let Some(claim_expires_at) =
            current_claim_deadline_on_connection(connection, tenant_id, generation)
                .await?
                .filter(|deadline| *deadline > now)
        {
            return Ok(CibaDecisionBindingRevoke::Busy { claim_expires_at });
        }
        Err(RepositoryError::Conflict)
    }
}

async fn validate_active_dependencies_on_connection(
    connection: &mut AsyncPgConnection,
    tenant_id: Uuid,
    oauth_client_id: Uuid,
    user_id: Uuid,
) -> Result<(), RepositoryError> {
    let state = sql_query(
        "SELECT client.is_active AS client_active,
                (jsonb_typeof(client.grant_types) = 'array'
                 AND client.grant_types @> jsonb_build_array($4::TEXT))
                    AS client_has_ciba_grant,
                subject.is_active AS user_active
         FROM oauth_clients AS client
         JOIN users AS subject ON subject.tenant_id = client.tenant_id
         WHERE client.tenant_id = $1 AND client.id = $2 AND subject.id = $3
         FOR UPDATE OF client, subject",
    )
    .bind::<sql_types::Uuid, _>(tenant_id)
    .bind::<sql_types::Uuid, _>(oauth_client_id)
    .bind::<sql_types::Uuid, _>(user_id)
    .bind::<sql_types::Text, _>(CIBA_GRANT_TYPE)
    .get_result::<DependencyStateRow>(connection)
    .await
    .optional()
    .map_err(map_error)?
    .ok_or(RepositoryError::NotFound)?;
    if !state.client_active || !state.user_active {
        return Err(RepositoryError::NotFound);
    }
    if !state.client_has_ciba_grant {
        return Err(RepositoryError::Conflict);
    }
    Ok(())
}

async fn eligible_binding_on_connection(
    connection: &mut AsyncPgConnection,
    tenant_id: Uuid,
    token_sha256: &str,
    oauth_client_public_id: &str,
    user_id: Uuid,
    now: DateTime<Utc>,
) -> Result<Option<BindingRow>, RepositoryError> {
    sql_query(
        "SELECT binding.generation, binding.tenant_id, binding.resource_id,
                binding.resource_digest, binding.oauth_client_id, binding.user_id,
                binding.token_sha256, binding.expires_at, binding.active,
                binding.decision_claim_id, binding.decision_claim_acquired_at,
                binding.decision_claim_expires_at, binding.created_at,
                binding.updated_at, binding.revoked_at
         FROM ciba_decision_bindings AS binding
         JOIN oauth_clients AS client
           ON client.tenant_id = binding.tenant_id
          AND client.id = binding.oauth_client_id
         JOIN users AS subject
           ON subject.tenant_id = binding.tenant_id
          AND subject.id = binding.user_id
         WHERE binding.tenant_id = $1 AND binding.token_sha256 = $2
           AND client.client_id = $3 AND client.is_active
           AND jsonb_typeof(client.grant_types) = 'array'
           AND client.grant_types @> jsonb_build_array($6::TEXT)
           AND subject.id = $4 AND subject.is_active
           AND binding.active AND binding.expires_at > $5
         LIMIT 1",
    )
    .bind::<sql_types::Uuid, _>(tenant_id)
    .bind::<sql_types::Varchar, _>(token_sha256)
    .bind::<sql_types::Varchar, _>(oauth_client_public_id)
    .bind::<sql_types::Uuid, _>(user_id)
    .bind::<sql_types::Timestamptz, _>(now)
    .bind::<sql_types::Text, _>(CIBA_GRANT_TYPE)
    .get_result::<BindingRow>(connection)
    .await
    .optional()
    .map_err(map_error)
}

async fn select_active_by_resource_on_connection(
    connection: &mut AsyncPgConnection,
    tenant_id: Uuid,
    resource_id: &str,
) -> Result<Option<CibaDecisionBinding>, RepositoryError> {
    sql_query(
        "SELECT generation, tenant_id, resource_id, resource_digest,
                oauth_client_id, user_id, token_sha256, expires_at, active,
                decision_claim_id, decision_claim_acquired_at,
                decision_claim_expires_at, created_at, updated_at, revoked_at
         FROM ciba_decision_bindings
         WHERE tenant_id = $1 AND resource_id = $2 AND active
         LIMIT 1 FOR UPDATE",
    )
    .bind::<sql_types::Uuid, _>(tenant_id)
    .bind::<sql_types::Varchar, _>(resource_id)
    .get_result::<BindingRow>(connection)
    .await
    .optional()
    .map_err(map_error)?
    .map(CibaDecisionBinding::try_from)
    .transpose()
}

async fn select_binding_by_uuid_on_connection(
    connection: &mut AsyncPgConnection,
    predicate: &str,
    tenant_id: Uuid,
    identity: Uuid,
) -> Result<Option<CibaDecisionBinding>, RepositoryError> {
    let query = format!(
        "SELECT binding.generation, binding.tenant_id, binding.resource_id,
                binding.resource_digest, binding.oauth_client_id, binding.user_id,
                binding.token_sha256, binding.expires_at, binding.active,
                binding.decision_claim_id, binding.decision_claim_acquired_at,
                binding.decision_claim_expires_at, binding.created_at,
                binding.updated_at, binding.revoked_at
         FROM ciba_decision_bindings AS binding
         WHERE binding.tenant_id = $1 AND {predicate}
         ORDER BY binding.updated_at DESC, binding.generation DESC
         LIMIT 1"
    );
    sql_query(query)
        .bind::<sql_types::Uuid, _>(tenant_id)
        .bind::<sql_types::Uuid, _>(identity)
        .get_result::<BindingRow>(connection)
        .await
        .optional()
        .map_err(map_error)?
        .map(CibaDecisionBinding::try_from)
        .transpose()
}

async fn current_claim_deadline_on_connection(
    connection: &mut AsyncPgConnection,
    tenant_id: Uuid,
    generation: Uuid,
) -> Result<Option<DateTime<Utc>>, RepositoryError> {
    #[derive(QueryableByName)]
    struct DeadlineRow {
        #[diesel(sql_type = sql_types::Nullable<sql_types::Timestamptz>)]
        decision_claim_expires_at: Option<DateTime<Utc>>,
    }
    sql_query(
        "SELECT decision_claim_expires_at
         FROM ciba_decision_bindings
         WHERE tenant_id = $1 AND generation = $2 AND active
         FOR UPDATE",
    )
    .bind::<sql_types::Uuid, _>(tenant_id)
    .bind::<sql_types::Uuid, _>(generation)
    .get_result::<DeadlineRow>(connection)
    .await
    .optional()
    .map_err(map_error)
    .map(|row| row.and_then(|row| row.decision_claim_expires_at))
}

async fn lock_identity_on_connection(
    connection: &mut AsyncPgConnection,
    tenant_id: Uuid,
    resource_id: &str,
) -> Result<(), RepositoryError> {
    let key = format!(
        "nazoauth:ciba-decision-binding:{tenant_id}:{}:{resource_id}",
        resource_id.len()
    );
    let lock = sql_query(
        "SELECT TRUE AS locked
         FROM pg_advisory_xact_lock(hashtextextended($1, 8711))",
    )
    .bind::<sql_types::Text, _>(key)
    .get_result::<AdvisoryLockRow>(connection)
    .await
    .map_err(map_error)?;
    debug_assert!(lock.locked);
    Ok(())
}

fn validate_lookup_input(
    token_sha256: &str,
    oauth_client_public_id: &str,
) -> Result<(), RepositoryError> {
    validate_sha256("CIBA automated-decision token", token_sha256)?;
    if oauth_client_public_id.is_empty()
        || oauth_client_public_id.len() > 255
        || oauth_client_public_id != oauth_client_public_id.trim()
        || oauth_client_public_id.chars().any(char::is_control)
    {
        return Err(RepositoryError::Consistency(
            "CIBA decision OAuth client public ID is invalid".to_owned(),
        ));
    }
    Ok(())
}

fn validate_resource_identity(
    resource_id: &str,
    resource_digest: &str,
) -> Result<(), RepositoryError> {
    if resource_id.is_empty()
        || resource_id.len() > 255
        || resource_id != resource_id.trim()
        || resource_id.chars().any(char::is_control)
    {
        return Err(RepositoryError::Consistency(
            "CIBA decision binding resource ID is invalid".to_owned(),
        ));
    }
    validate_sha256("CIBA decision binding resource", resource_digest)
}

fn validate_sha256(label: &str, digest: &str) -> Result<(), RepositoryError> {
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(RepositoryError::Consistency(format!(
            "{label} SHA-256 is invalid"
        )));
    }
    Ok(())
}

fn validate_claim_state(
    claim_id: Option<Uuid>,
    acquired_at: Option<DateTime<Utc>>,
    expires_at: Option<DateTime<Utc>>,
    binding_expires_at: DateTime<Utc>,
) -> Result<(), RepositoryError> {
    match (claim_id, acquired_at, expires_at) {
        (None, None, None) => Ok(()),
        (Some(_), Some(acquired_at), Some(expires_at))
            if expires_at > acquired_at
                && expires_at <= acquired_at + Duration::seconds(CIBA_DECISION_CLAIM_SECONDS)
                && expires_at <= binding_expires_at =>
        {
            Ok(())
        }
        _ => Err(RepositoryError::Consistency(
            "CIBA decision binding claim state is inconsistent".to_owned(),
        )),
    }
}

fn map_error(error: diesel::result::Error) -> RepositoryError {
    match error {
        diesel::result::Error::DatabaseError(
            diesel::result::DatabaseErrorKind::UniqueViolation,
            _,
        ) => RepositoryError::Conflict,
        diesel::result::Error::NotFound => RepositoryError::NotFound,
        _ => RepositoryError::Unavailable,
    }
}
