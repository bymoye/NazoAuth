use chrono::{DateTime, Duration, Utc};
use diesel::{ExpressionMethods, OptionalExtension, QueryDsl, SelectableHelper};
use diesel_async::RunQueryDsl;
use nazo_identity::ports::RepositoryError;
use serde_json::Value;
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
    pub public_material: Option<Value>,
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

#[derive(Clone, Debug, diesel::QueryableByName)]
pub struct ConformanceLeasePublicMaterial {
    #[diesel(sql_type = diesel::sql_types::Uuid)]
    pub lease_id: Uuid,
    #[diesel(sql_type = diesel::sql_types::Jsonb)]
    pub public_material: Value,
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
        public_material: Option<Value>,
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
                conformance_leases::public_material.eq(public_material),
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
                SET revoked_at = COALESCE(revoked_at, CURRENT_TIMESTAMP),
                    public_material = NULL
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
        let result = diesel::sql_query(
            "SELECT cleaned_leases, deleted_clients FROM nazo_oauth_cleanup_expired_conformance_leases()",
        )
        .get_result::<CleanupRow>(&mut connection)
        .await
        .map(|row| ConformanceLeaseCleanup {
            cleaned_leases: row.cleaned_leases,
            deleted_clients: row.deleted_clients,
        })
        .map_err(map_diesel_error)?;
        diesel::update(
            conformance_leases::table.filter(conformance_leases::cleaned_at.is_not_null()),
        )
        .set(conformance_leases::public_material.eq::<Option<Value>>(None))
        .execute(&mut connection)
        .await
        .map_err(map_diesel_error)?;
        Ok(result)
    }

    pub async fn active_public_material_for_client(
        &self,
        tenant_id: Uuid,
        client_id: &str,
    ) -> Result<Option<Value>, RepositoryError> {
        let mut connection = get_conn(&self.pool).await.map_err(map_pool_error)?;
        diesel::sql_query(
            r#"
            SELECT lease.public_material
            FROM oauth_clients client
            JOIN conformance_leases lease
              ON lease.tenant_id = client.tenant_id
             AND lease.id = client.conformance_lease_id
            WHERE client.tenant_id = $1
              AND client.client_id = $2
              AND client.is_active = TRUE
              AND lease.expires_at > CURRENT_TIMESTAMP
              AND lease.revoked_at IS NULL
              AND lease.cleaned_at IS NULL
              AND lease.public_material IS NOT NULL
            "#,
        )
        .bind::<diesel::sql_types::Uuid, _>(tenant_id)
        .bind::<diesel::sql_types::Text, _>(client_id)
        .get_result::<PublicMaterialRow>(&mut connection)
        .await
        .optional()
        .map(|row| row.and_then(|row| row.public_material))
        .map_err(map_diesel_error)
    }

    /// Returns whether the tenant-scoped client is bound to an effective lease
    /// for the exact conformance profile.  This deliberately checks the
    /// binding and lease state in one database statement so callers cannot
    /// accidentally turn any active lease into a process-wide capability.
    pub async fn active_for_client_profile(
        &self,
        tenant_id: Uuid,
        client_id: &str,
        profile: &str,
    ) -> Result<bool, RepositoryError> {
        let mut connection = get_conn(&self.pool).await.map_err(map_pool_error)?;
        diesel::sql_query(
            r#"
            SELECT EXISTS(
                SELECT 1
                FROM oauth_clients client
                JOIN conformance_leases lease
                  ON lease.tenant_id = client.tenant_id
                 AND lease.id = client.conformance_lease_id
                WHERE client.tenant_id = $1
                  AND client.client_id = $2
                  AND client.is_active = TRUE
                  AND lease.profile = $3
                  AND lease.expires_at > CURRENT_TIMESTAMP
                  AND lease.revoked_at IS NULL
                  AND lease.cleaned_at IS NULL
            ) AS active
            "#,
        )
        .bind::<diesel::sql_types::Uuid, _>(tenant_id)
        .bind::<diesel::sql_types::Text, _>(client_id)
        .bind::<diesel::sql_types::Text, _>(profile)
        .get_result::<ActiveLeaseRow>(&mut connection)
        .await
        .map(|row| row.active)
        .map_err(map_diesel_error)
    }

    pub async fn active_public_materials_for_profile(
        &self,
        tenant_id: Uuid,
        profile: &str,
    ) -> Result<Vec<ConformanceLeasePublicMaterial>, RepositoryError> {
        let mut connection = get_conn(&self.pool).await.map_err(map_pool_error)?;
        diesel::sql_query(
            r#"
            SELECT id AS lease_id, public_material
            FROM conformance_leases
            WHERE tenant_id = $1
              AND profile = $2
              AND expires_at > CURRENT_TIMESTAMP
              AND revoked_at IS NULL
              AND cleaned_at IS NULL
              AND public_material IS NOT NULL
            ORDER BY created_at, id
            "#,
        )
        .bind::<diesel::sql_types::Uuid, _>(tenant_id)
        .bind::<diesel::sql_types::Text, _>(profile)
        .load(&mut connection)
        .await
        .map_err(map_diesel_error)
    }

    pub async fn active_public_material_for_lease(
        &self,
        tenant_id: Uuid,
        lease_id: Uuid,
    ) -> Result<Option<Value>, RepositoryError> {
        let mut connection = get_conn(&self.pool).await.map_err(map_pool_error)?;
        diesel::sql_query(
            r#"
            SELECT public_material
            FROM conformance_leases
            WHERE tenant_id = $1
              AND id = $2
              AND expires_at > CURRENT_TIMESTAMP
              AND revoked_at IS NULL
              AND cleaned_at IS NULL
              AND public_material IS NOT NULL
            "#,
        )
        .bind::<diesel::sql_types::Uuid, _>(tenant_id)
        .bind::<diesel::sql_types::Uuid, _>(lease_id)
        .get_result::<PublicMaterialRow>(&mut connection)
        .await
        .optional()
        .map(|row| row.and_then(|row| row.public_material))
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

#[derive(diesel::QueryableByName)]
struct PublicMaterialRow {
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Jsonb>)]
    public_material: Option<Value>,
}

#[derive(diesel::QueryableByName)]
struct ActiveLeaseRow {
    #[diesel(sql_type = diesel::sql_types::Bool)]
    active: bool,
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
