use chrono::{DateTime, Duration, Utc};
use diesel::{ExpressionMethods, QueryDsl, SelectableHelper};
use diesel_async::RunQueryDsl;
use nazo_identity::ports::RepositoryError;
use uuid::Uuid;

use crate::{DbPool, get_conn, schema::conformance_leases};

pub const MIN_CONFORMANCE_LEASE_SECONDS: i64 = 60;
pub const MAX_CONFORMANCE_LEASE_SECONDS: i64 = 24 * 60 * 60;

#[derive(Clone, Debug, diesel::Queryable, diesel::Selectable)]
#[diesel(table_name = crate::schema::conformance_leases)]
pub struct ConformanceLease {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub profile: String,
    pub material_sha256: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub cleaned_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConformanceLeaseCleanup {
    pub cleaned_leases: i32,
    pub deleted_clients: i32,
}

#[derive(Clone)]
pub struct ConformanceLeaseRepository {
    pool: DbPool,
}

impl ConformanceLeaseRepository {
    #[must_use]
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    pub async fn create(
        &self,
        tenant_id: Uuid,
        profile: &str,
        material_sha256: &str,
        ttl_seconds: i64,
    ) -> Result<ConformanceLease, RepositoryError> {
        if !(MIN_CONFORMANCE_LEASE_SECONDS..=MAX_CONFORMANCE_LEASE_SECONDS).contains(&ttl_seconds) {
            return Err(RepositoryError::Consistency(format!(
                "conformance lease ttl_seconds must be between {MIN_CONFORMANCE_LEASE_SECONDS} and {MAX_CONFORMANCE_LEASE_SECONDS}"
            )));
        }
        let profile = profile.trim();
        if profile.is_empty() || profile.len() > 64 {
            return Err(RepositoryError::Consistency(
                "conformance lease profile must contain 1 to 64 bytes".to_owned(),
            ));
        }
        if material_sha256.len() != 64
            || !material_sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(RepositoryError::Consistency(
                "conformance lease material_sha256 must be a lowercase SHA-256 digest".to_owned(),
            ));
        }

        let now = Utc::now();
        let expires_at = now
            .checked_add_signed(Duration::seconds(ttl_seconds))
            .ok_or_else(|| {
                RepositoryError::Consistency("conformance lease ttl overflow".to_owned())
            })?;
        let mut connection = get_conn(&self.pool).await.map_err(map_pool_error)?;
        diesel::insert_into(conformance_leases::table)
            .values((
                conformance_leases::tenant_id.eq(tenant_id),
                conformance_leases::profile.eq(profile),
                conformance_leases::material_sha256.eq(material_sha256),
                conformance_leases::created_at.eq(now),
                conformance_leases::expires_at.eq(expires_at),
            ))
            .returning(ConformanceLease::as_returning())
            .get_result(&mut connection)
            .await
            .map_err(map_diesel_error)
    }

    pub async fn list(&self, tenant_id: Uuid) -> Result<Vec<ConformanceLease>, RepositoryError> {
        let mut connection = get_conn(&self.pool).await.map_err(map_pool_error)?;
        conformance_leases::table
            .filter(conformance_leases::tenant_id.eq(tenant_id))
            .order(conformance_leases::created_at.desc())
            .limit(100)
            .select(ConformanceLease::as_select())
            .load(&mut connection)
            .await
            .map_err(map_diesel_error)
    }

    pub async fn revoke(&self, tenant_id: Uuid, lease_id: Uuid) -> Result<i64, RepositoryError> {
        let mut connection = get_conn(&self.pool).await.map_err(map_pool_error)?;
        let row = diesel::sql_query(
            r#"
            WITH revoked AS (
                UPDATE conformance_leases
                SET revoked_at = COALESCE(revoked_at, CURRENT_TIMESTAMP)
                WHERE tenant_id = $1 AND id = $2
                RETURNING id, tenant_id
            ), deactivated AS (
                UPDATE oauth_clients client
                SET is_active = FALSE, updated_at = CURRENT_TIMESTAMP
                FROM revoked
                WHERE client.tenant_id = revoked.tenant_id
                  AND client.conformance_lease_id = revoked.id
                RETURNING client.id
            )
            SELECT EXISTS(SELECT 1 FROM revoked) AS found,
                   (SELECT COUNT(*) FROM deactivated)::BIGINT AS deactivated_clients
            "#,
        )
        .bind::<diesel::sql_types::Uuid, _>(tenant_id)
        .bind::<diesel::sql_types::Uuid, _>(lease_id)
        .get_result::<RevokeRow>(&mut connection)
        .await
        .map_err(map_diesel_error)?;
        if !row.found {
            return Err(RepositoryError::NotFound);
        }
        Ok(row.deactivated_clients)
    }

    pub async fn cleanup(&self) -> Result<ConformanceLeaseCleanup, RepositoryError> {
        let mut connection = get_conn(&self.pool).await.map_err(map_pool_error)?;
        diesel::sql_query(
            "SELECT cleaned_leases, deleted_clients FROM nazo_oauth_cleanup_expired_conformance_leases()",
        )
        .get_result::<CleanupRow>(&mut connection)
        .await
        .map(|row| ConformanceLeaseCleanup {
            cleaned_leases: row.cleaned_leases,
            deleted_clients: row.deleted_clients,
        })
        .map_err(map_diesel_error)
    }
}

#[derive(diesel::QueryableByName)]
struct RevokeRow {
    #[diesel(sql_type = diesel::sql_types::Bool)]
    found: bool,
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    deactivated_clients: i64,
}

#[derive(diesel::QueryableByName)]
struct CleanupRow {
    #[diesel(sql_type = diesel::sql_types::Integer)]
    cleaned_leases: i32,
    #[diesel(sql_type = diesel::sql_types::Integer)]
    deleted_clients: i32,
}

fn map_pool_error(error: anyhow::Error) -> RepositoryError {
    RepositoryError::Unexpected(error.to_string())
}

fn map_diesel_error(error: diesel::result::Error) -> RepositoryError {
    match error {
        diesel::result::Error::DatabaseError(
            diesel::result::DatabaseErrorKind::UniqueViolation,
            _,
        ) => RepositoryError::Conflict,
        diesel::result::Error::DatabaseError(
            diesel::result::DatabaseErrorKind::CheckViolation,
            details,
        ) => RepositoryError::Consistency(details.message().to_owned()),
        other => RepositoryError::Unexpected(other.to_string()),
    }
}
