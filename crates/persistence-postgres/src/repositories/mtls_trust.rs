use chrono::{DateTime, Utc};
use diesel::{OptionalExtension, QueryableByName, sql_query, sql_types};
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl};
use nazo_identity::{
    MtlsTrustAnchorRequest, MtlsTrustAnchorRequestPage, MtlsTrustAnchorStatus,
    NewMtlsTrustAnchorRequest, TenantId, UserId, ports::RepositoryError,
};
use uuid::Uuid;

use crate::DbPool;

const MAX_ACTIVE_TRUST_ANCHORS_PER_CLIENT: i64 = 8;
const MAX_ACTIVE_TRUST_ANCHORS_PER_TENANT: i64 = 128;
const MAX_PENDING_TRUST_REQUESTS_PER_CLIENT: i64 = 4;
const MAX_PENDING_TRUST_REQUESTS_PER_USER: i64 = 16;

#[derive(Clone)]
pub struct MtlsTrustAnchorRepository {
    pool: DbPool,
}

#[derive(QueryableByName)]
struct RequestRow {
    #[diesel(sql_type = sql_types::Uuid)]
    id: Uuid,
    #[diesel(sql_type = sql_types::Uuid)]
    tenant_id: Uuid,
    #[diesel(sql_type = sql_types::Uuid)]
    user_id: Uuid,
    #[diesel(sql_type = sql_types::Nullable<sql_types::Text>)]
    requester_email: Option<String>,
    #[diesel(sql_type = sql_types::Text)]
    client_id: String,
    #[diesel(sql_type = sql_types::Text)]
    certificate_pem: String,
    #[diesel(sql_type = sql_types::Text)]
    certificate_sha256: String,
    #[diesel(sql_type = sql_types::Text)]
    subject_dn: String,
    #[diesel(sql_type = sql_types::Timestamptz)]
    not_before: DateTime<Utc>,
    #[diesel(sql_type = sql_types::Timestamptz)]
    not_after: DateTime<Utc>,
    #[diesel(sql_type = sql_types::SmallInt)]
    status: i16,
    #[diesel(sql_type = sql_types::Nullable<sql_types::Text>)]
    admin_note: Option<String>,
    #[diesel(sql_type = sql_types::Timestamptz)]
    created_at: DateTime<Utc>,
    #[diesel(sql_type = sql_types::Nullable<sql_types::Timestamptz>)]
    resolved_at: Option<DateTime<Utc>>,
    #[diesel(sql_type = sql_types::Nullable<sql_types::Timestamptz>)]
    revoked_at: Option<DateTime<Utc>>,
}

#[derive(QueryableByName)]
struct CountRow {
    #[diesel(sql_type = sql_types::BigInt)]
    count: i64,
}

#[derive(QueryableByName)]
struct PemRow {
    #[diesel(sql_type = sql_types::Text)]
    certificate_pem: String,
}

#[derive(QueryableByName)]
struct AdvisoryLockRow {
    #[diesel(sql_type = sql_types::Bool)]
    locked: bool,
}

#[derive(QueryableByName)]
struct CreateOutcomeRow {
    #[diesel(sql_type = sql_types::Nullable<sql_types::Uuid>)]
    id: Option<Uuid>,
    #[diesel(sql_type = sql_types::Bool)]
    eligible: bool,
}

impl From<RequestRow> for MtlsTrustAnchorRequest {
    fn from(row: RequestRow) -> Self {
        Self {
            id: row.id,
            tenant_id: row.tenant_id,
            user_id: row.user_id,
            requester_email: row.requester_email,
            client_id: row.client_id,
            certificate_pem: row.certificate_pem,
            certificate_sha256: row.certificate_sha256,
            subject_dn: row.subject_dn,
            not_before: row.not_before,
            not_after: row.not_after,
            status: row.status,
            admin_note: row.admin_note,
            created_at: row.created_at,
            resolved_at: row.resolved_at,
            revoked_at: row.revoked_at,
        }
    }
}

const REQUEST_PROJECTION: &str = "
    r.id, r.tenant_id, r.user_id, u.email AS requester_email,
    c.client_id, r.certificate_pem, r.certificate_sha256, r.subject_dn,
    r.not_before, r.not_after, r.status, r.admin_note, r.created_at,
    r.resolved_at, r.revoked_at";

impl MtlsTrustAnchorRepository {
    #[must_use]
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    pub async fn create_for_owned_client(
        &self,
        request: NewMtlsTrustAnchorRequest,
    ) -> Result<MtlsTrustAnchorRequest, RepositoryError> {
        let id = Uuid::now_v7();
        let mut connection = self.connection().await?;
        let outcome = connection
            .transaction::<CreateOutcomeRow, diesel::result::Error, _>(async |connection| {
                acquire_tenant_trust_lock(connection, request.tenant_id).await?;
                sql_query(
                    "WITH eligible AS MATERIALIZED (
                 SELECT c.id
                 FROM oauth_clients c
                 WHERE c.tenant_id = $2 AND c.client_id = $4 AND c.is_active = TRUE
                   AND nazo_oauth_conformance_lease_is_active(
                       c.tenant_id, c.conformance_lease_id
                   )
                   AND (
                       (
                           c.token_endpoint_auth_method = 'tls_client_auth'
                           AND c.tls_client_auth_cert_sha256 IS NOT NULL
                       )
                       OR c.require_mtls_bound_tokens = TRUE
                   )
                   AND $8 <= CURRENT_TIMESTAMP AND $9 > CURRENT_TIMESTAMP
                   AND EXISTS (
                       SELECT 1 FROM users requester
                       WHERE requester.tenant_id = $2 AND requester.id = $3
                         AND requester.is_active = TRUE
                   )
                   AND EXISTS (
                       SELECT 1 FROM client_access_requests a
                       WHERE a.tenant_id = c.tenant_id AND a.user_id = $3
                         AND a.approved_client_id = c.id AND a.status = 1
                   )
             ), inserted AS (
             INSERT INTO oauth_client_mtls_trust_anchor_requests (
                id, tenant_id, user_id, client_id, certificate_pem,
                certificate_sha256, subject_dn, not_before, not_after
             )
             SELECT $1, $2, $3, eligible.id, $5, $6, $7, $8, $9
             FROM eligible
             WHERE (
                 SELECT COUNT(*)
                 FROM oauth_client_mtls_trust_anchor_requests pending
                 WHERE pending.tenant_id = $2 AND pending.client_id = eligible.id
                   AND pending.status = 0
             ) < $10
               AND (
                   SELECT COUNT(*)
                   FROM oauth_client_mtls_trust_anchor_requests pending
                   WHERE pending.tenant_id = $2 AND pending.user_id = $3
                     AND pending.status = 0
               ) < $11
             RETURNING id, tenant_id, user_id
             ), recorded AS (
                 INSERT INTO oauth_client_mtls_trust_anchor_events (
                     tenant_id, request_id, actor_user_id, action
                 )
                 SELECT tenant_id, id, user_id, 0 FROM inserted
                 RETURNING request_id
             )
             SELECT (SELECT request_id FROM recorded) AS id,
                    EXISTS(SELECT 1 FROM eligible) AS eligible",
                )
                .bind::<sql_types::Uuid, _>(id)
                .bind::<sql_types::Uuid, _>(request.tenant_id.as_uuid())
                .bind::<sql_types::Uuid, _>(request.user_id.as_uuid())
                .bind::<sql_types::Text, _>(&request.client_id)
                .bind::<sql_types::Text, _>(&request.certificate_pem)
                .bind::<sql_types::Text, _>(&request.certificate_sha256)
                .bind::<sql_types::Text, _>(&request.subject_dn)
                .bind::<sql_types::Timestamptz, _>(request.not_before)
                .bind::<sql_types::Timestamptz, _>(request.not_after)
                .bind::<sql_types::BigInt, _>(MAX_PENDING_TRUST_REQUESTS_PER_CLIENT)
                .bind::<sql_types::BigInt, _>(MAX_PENDING_TRUST_REQUESTS_PER_USER)
                .get_result::<CreateOutcomeRow>(connection)
                .await
            })
            .await
            .map_err(map_error)?;
        if outcome.id.is_none() && outcome.eligible {
            return Err(RepositoryError::Conflict);
        }
        if outcome.id.is_none() {
            return Err(RepositoryError::NotFound);
        }
        drop(connection);
        self.by_id(request.tenant_id, id).await?.ok_or_else(|| {
            RepositoryError::Consistency("created trust request is missing".to_owned())
        })
    }

    pub async fn list_for_user(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> Result<Vec<MtlsTrustAnchorRequest>, RepositoryError> {
        let mut connection = self.connection().await?;
        sql_query(format!(
            "SELECT {REQUEST_PROJECTION}
             FROM oauth_client_mtls_trust_anchor_requests r
             JOIN users u ON u.id = r.user_id AND u.tenant_id = r.tenant_id
             JOIN oauth_clients c ON c.id = r.client_id AND c.tenant_id = r.tenant_id
             WHERE r.tenant_id = $1 AND r.user_id = $2
             ORDER BY r.created_at DESC"
        ))
        .bind::<sql_types::Uuid, _>(tenant_id.as_uuid())
        .bind::<sql_types::Uuid, _>(user_id.as_uuid())
        .load::<RequestRow>(&mut connection)
        .await
        .map(|rows| rows.into_iter().map(Into::into).collect())
        .map_err(map_error)
    }

    pub async fn page(
        &self,
        tenant_id: TenantId,
        status: Option<MtlsTrustAnchorStatus>,
        limit: i64,
        offset: i64,
    ) -> Result<MtlsTrustAnchorRequestPage, RepositoryError> {
        let mut connection = self.connection().await?;
        let status = status.map(MtlsTrustAnchorStatus::code);
        let count = sql_query(
            "SELECT COUNT(*)::bigint AS count
             FROM oauth_client_mtls_trust_anchor_requests
             WHERE tenant_id = $1 AND ($2::smallint IS NULL OR status = $2)",
        )
        .bind::<sql_types::Uuid, _>(tenant_id.as_uuid())
        .bind::<sql_types::Nullable<sql_types::SmallInt>, _>(status)
        .get_result::<CountRow>(&mut connection)
        .await
        .map_err(map_error)?
        .count;
        let items = sql_query(format!(
            "SELECT {REQUEST_PROJECTION}
             FROM oauth_client_mtls_trust_anchor_requests r
             JOIN users u ON u.id = r.user_id AND u.tenant_id = r.tenant_id
             JOIN oauth_clients c ON c.id = r.client_id AND c.tenant_id = r.tenant_id
             WHERE r.tenant_id = $1 AND ($2::smallint IS NULL OR r.status = $2)
             ORDER BY r.created_at DESC LIMIT $3 OFFSET $4"
        ))
        .bind::<sql_types::Uuid, _>(tenant_id.as_uuid())
        .bind::<sql_types::Nullable<sql_types::SmallInt>, _>(status)
        .bind::<sql_types::BigInt, _>(limit)
        .bind::<sql_types::BigInt, _>(offset)
        .load::<RequestRow>(&mut connection)
        .await
        .map_err(map_error)?
        .into_iter()
        .map(Into::into)
        .collect();
        Ok(MtlsTrustAnchorRequestPage {
            total: count,
            items,
        })
    }

    pub async fn by_id(
        &self,
        tenant_id: TenantId,
        id: Uuid,
    ) -> Result<Option<MtlsTrustAnchorRequest>, RepositoryError> {
        let mut connection = self.connection().await?;
        sql_query(format!(
            "SELECT {REQUEST_PROJECTION}
             FROM oauth_client_mtls_trust_anchor_requests r
             JOIN users u ON u.id = r.user_id AND u.tenant_id = r.tenant_id
             JOIN oauth_clients c ON c.id = r.client_id AND c.tenant_id = r.tenant_id
             WHERE r.tenant_id = $1 AND r.id = $2"
        ))
        .bind::<sql_types::Uuid, _>(tenant_id.as_uuid())
        .bind::<sql_types::Uuid, _>(id)
        .get_result::<RequestRow>(&mut connection)
        .await
        .optional()
        .map(|row| row.map(Into::into))
        .map_err(map_error)
    }

    pub async fn approve(
        &self,
        tenant_id: TenantId,
        id: Uuid,
        actor: UserId,
        note: Option<String>,
    ) -> Result<MtlsTrustAnchorRequest, RepositoryError> {
        self.resolve(tenant_id, id, actor, MtlsTrustAnchorStatus::Approved, note)
            .await
    }

    pub async fn reject(
        &self,
        tenant_id: TenantId,
        id: Uuid,
        actor: UserId,
        note: Option<String>,
    ) -> Result<MtlsTrustAnchorRequest, RepositoryError> {
        self.resolve(tenant_id, id, actor, MtlsTrustAnchorStatus::Rejected, note)
            .await
    }

    async fn resolve(
        &self,
        tenant_id: TenantId,
        id: Uuid,
        actor: UserId,
        status: MtlsTrustAnchorStatus,
        note: Option<String>,
    ) -> Result<MtlsTrustAnchorRequest, RepositoryError> {
        let mut connection = self.connection().await?;
        let updated = connection
            .transaction::<Option<Uuid>, diesel::result::Error, _>(async |connection| {
                acquire_tenant_trust_lock(connection, tenant_id).await?;
                sql_query(
                    "WITH admin_actor AS (
                 SELECT id FROM users
                 WHERE tenant_id = $1 AND id = $3 AND is_active = TRUE
                   AND role = 'admin' AND admin_level > 0
             ), updated AS (
             UPDATE oauth_client_mtls_trust_anchor_requests
             SET status = $4, admin_note = $5, resolved_by_user_id = $3,
                 resolved_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
             WHERE tenant_id = $1 AND id = $2 AND status = 0 AND user_id <> $3
               AND EXISTS (SELECT 1 FROM admin_actor)
               AND ($4 <> 1 OR (
                   not_before <= CURRENT_TIMESTAMP AND not_after > CURRENT_TIMESTAMP
                   AND EXISTS (
                       SELECT 1 FROM oauth_clients requested_client
                       WHERE requested_client.tenant_id = $1
                         AND requested_client.id = oauth_client_mtls_trust_anchor_requests.client_id
                         AND requested_client.is_active = TRUE
                         AND nazo_oauth_conformance_lease_is_active(
                             requested_client.tenant_id,
                             requested_client.conformance_lease_id
                         )
                   )
                   AND (
                       EXISTS (
                           SELECT 1
                           FROM oauth_client_mtls_trust_anchor_requests existing
                           WHERE existing.tenant_id = $1 AND existing.status = 1
                             AND existing.not_before <= CURRENT_TIMESTAMP
                             AND existing.not_after > CURRENT_TIMESTAMP
                             AND existing.certificate_sha256 =
                                 oauth_client_mtls_trust_anchor_requests.certificate_sha256
                       )
                       OR (
                           SELECT COUNT(DISTINCT active.certificate_sha256)
                           FROM oauth_client_mtls_trust_anchor_requests active
                           JOIN oauth_clients active_client
                             ON active_client.id = active.client_id
                            AND active_client.tenant_id = active.tenant_id
                           WHERE active.tenant_id = $1 AND active.status = 1
                             AND active.not_before <= CURRENT_TIMESTAMP
                             AND active.not_after > CURRENT_TIMESTAMP
                             AND active_client.is_active = TRUE
                             AND nazo_oauth_conformance_lease_is_active(
                                 active_client.tenant_id,
                                 active_client.conformance_lease_id
                             )
                       ) < $6
                   )
                   AND (
                       SELECT COUNT(*)
                       FROM oauth_client_mtls_trust_anchor_requests active
                       WHERE active.tenant_id = $1 AND active.status = 1
                         AND active.not_before <= CURRENT_TIMESTAMP
                         AND active.not_after > CURRENT_TIMESTAMP
                         AND active.client_id =
                             oauth_client_mtls_trust_anchor_requests.client_id
                   ) < $7
               ))
             RETURNING id, tenant_id, resolved_by_user_id
             ), recorded AS (
                 INSERT INTO oauth_client_mtls_trust_anchor_events (
                     tenant_id, request_id, actor_user_id, action, note
                 )
                 SELECT tenant_id, id, resolved_by_user_id, $4, $5 FROM updated
                 RETURNING request_id
             )
             SELECT request_id AS id FROM recorded",
                )
                .bind::<sql_types::Uuid, _>(tenant_id.as_uuid())
                .bind::<sql_types::Uuid, _>(id)
                .bind::<sql_types::Uuid, _>(actor.as_uuid())
                .bind::<sql_types::SmallInt, _>(status.code())
                .bind::<sql_types::Nullable<sql_types::Text>, _>(note)
                .bind::<sql_types::BigInt, _>(MAX_ACTIVE_TRUST_ANCHORS_PER_TENANT)
                .bind::<sql_types::BigInt, _>(MAX_ACTIVE_TRUST_ANCHORS_PER_CLIENT)
                .get_result::<IdRow>(connection)
                .await
                .optional()
                .map(|row| row.map(|row| row.id))
            })
            .await
            .map_err(map_error)?;
        if updated.is_none() {
            return Err(RepositoryError::Conflict);
        }
        drop(connection);
        self.by_id(tenant_id, id).await?.ok_or_else(|| {
            RepositoryError::Consistency("resolved trust request is missing".to_owned())
        })
    }

    pub async fn revoke(
        &self,
        tenant_id: TenantId,
        id: Uuid,
        actor: UserId,
        note: String,
    ) -> Result<MtlsTrustAnchorRequest, RepositoryError> {
        let mut connection = self.connection().await?;
        let updated = sql_query(
            "WITH admin_actor AS (
                 SELECT id FROM users
                 WHERE tenant_id = $1 AND id = $3 AND is_active = TRUE
                   AND role = 'admin' AND admin_level > 0
             ), updated AS (
             UPDATE oauth_client_mtls_trust_anchor_requests
             SET status = 3, admin_note = $4, revoked_by_user_id = $3,
                 revoked_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
             WHERE tenant_id = $1 AND id = $2 AND status = 1
               AND EXISTS (SELECT 1 FROM admin_actor)
             RETURNING id, tenant_id, revoked_by_user_id
             ), recorded AS (
                 INSERT INTO oauth_client_mtls_trust_anchor_events (
                     tenant_id, request_id, actor_user_id, action, note
                 )
                 SELECT tenant_id, id, revoked_by_user_id, 3, $4 FROM updated
                 RETURNING request_id
             )
             SELECT request_id AS id FROM recorded",
        )
        .bind::<sql_types::Uuid, _>(tenant_id.as_uuid())
        .bind::<sql_types::Uuid, _>(id)
        .bind::<sql_types::Uuid, _>(actor.as_uuid())
        .bind::<sql_types::Text, _>(note)
        .get_result::<IdRow>(&mut connection)
        .await
        .optional()
        .map(|row| row.map(|row| row.id))
        .map_err(map_error)?;
        if updated.is_none() {
            return Err(RepositoryError::Conflict);
        }
        drop(connection);
        self.by_id(tenant_id, id).await?.ok_or_else(|| {
            RepositoryError::Consistency("revoked trust request is missing".to_owned())
        })
    }

    pub async fn active_bundle(&self, tenant_id: TenantId) -> Result<String, RepositoryError> {
        let mut connection = self.connection().await?;
        let rows = sql_query(
            "SELECT DISTINCT r.certificate_pem
             FROM oauth_client_mtls_trust_anchor_requests r
             JOIN oauth_clients c ON c.id = r.client_id AND c.tenant_id = r.tenant_id
             WHERE r.tenant_id = $1 AND r.status = 1 AND r.not_before <= CURRENT_TIMESTAMP
               AND r.not_after > CURRENT_TIMESTAMP AND c.is_active = TRUE
               AND nazo_oauth_conformance_lease_is_active(
                   c.tenant_id, c.conformance_lease_id
               )
               AND (
                   c.token_endpoint_auth_method = 'tls_client_auth'
                   OR c.require_mtls_bound_tokens = TRUE
               )
             ORDER BY r.certificate_pem
             LIMIT 129",
        )
        .bind::<sql_types::Uuid, _>(tenant_id.as_uuid())
        .load::<PemRow>(&mut connection)
        .await
        .map_err(map_error)?;
        if rows.len() > MAX_ACTIVE_TRUST_ANCHORS_PER_TENANT as usize {
            return Err(RepositoryError::Conflict);
        }
        Ok(rows.into_iter().map(|row| row.certificate_pem).collect())
    }

    async fn connection(&self) -> Result<crate::DbConnection, RepositoryError> {
        self.pool
            .get()
            .await
            .map_err(|_| RepositoryError::Unavailable)
    }
}

#[derive(QueryableByName)]
struct IdRow {
    #[diesel(sql_type = sql_types::Uuid)]
    id: Uuid,
}

fn map_error(error: diesel::result::Error) -> RepositoryError {
    match error {
        diesel::result::Error::DatabaseError(
            diesel::result::DatabaseErrorKind::UniqueViolation,
            _,
        ) => RepositoryError::Conflict,
        _ => RepositoryError::Unavailable,
    }
}

async fn acquire_tenant_trust_lock(
    connection: &mut AsyncPgConnection,
    tenant_id: TenantId,
) -> Result<(), diesel::result::Error> {
    let lock = sql_query(
        "SELECT TRUE AS locked
         FROM pg_advisory_xact_lock(hashtextextended($1::text, 8705))",
    )
    .bind::<sql_types::Uuid, _>(tenant_id.as_uuid())
    .get_result::<AdvisoryLockRow>(connection)
    .await?;
    debug_assert!(lock.locked);
    Ok(())
}
