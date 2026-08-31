use diesel::{QueryableByName, sql_query, sql_types};
use diesel_async::RunQueryDsl;
use nazo_identity::{
    OrganizationId, RealmId, TenantContext, TenantDirectoryBinding, TenantDirectorySnapshot,
    TenantId, ports::RepositoryError,
};
use nazo_persistence::TenantDirectoryStore;
use uuid::Uuid;

use crate::{DbPool, get_conn};

/// The database-backed active tenant boundary used while composing the
/// process-wide runtime. This is intentionally a focused preflight rather
/// than a general tenancy repository: every runtime must prove that its tenant
/// is active and its configured default realm and organization are active
/// placements belonging to that tenant.
#[derive(Clone)]
pub struct ActiveTenantBoundaryRepository {
    pool: DbPool,
}

#[derive(Clone)]
pub struct TenantDirectoryRepository {
    pool: DbPool,
}

#[derive(Debug, QueryableByName)]
struct ActiveTenantBoundaryRow {
    #[diesel(sql_type = sql_types::Nullable<sql_types::Uuid>)]
    tenant_id: Option<Uuid>,
    #[diesel(sql_type = sql_types::Nullable<sql_types::Text>)]
    tenant_status: Option<String>,
    #[diesel(sql_type = sql_types::Nullable<sql_types::Uuid>)]
    realm_id: Option<Uuid>,
    #[diesel(sql_type = sql_types::Nullable<sql_types::Uuid>)]
    realm_tenant_id: Option<Uuid>,
    #[diesel(sql_type = sql_types::Nullable<sql_types::Text>)]
    realm_status: Option<String>,
    #[diesel(sql_type = sql_types::Nullable<sql_types::Uuid>)]
    organization_id: Option<Uuid>,
    #[diesel(sql_type = sql_types::Nullable<sql_types::Uuid>)]
    organization_tenant_id: Option<Uuid>,
    #[diesel(sql_type = sql_types::Nullable<sql_types::Text>)]
    organization_status: Option<String>,
}

#[derive(Debug, QueryableByName)]
struct TenantDirectoryRow {
    #[diesel(sql_type = sql_types::BigInt)]
    revision: i64,
    #[diesel(sql_type = sql_types::Nullable<sql_types::Uuid>)]
    tenant_id: Option<Uuid>,
    #[diesel(sql_type = sql_types::Nullable<sql_types::Uuid>)]
    realm_id: Option<Uuid>,
    #[diesel(sql_type = sql_types::Nullable<sql_types::Uuid>)]
    organization_id: Option<Uuid>,
    #[diesel(sql_type = sql_types::Nullable<sql_types::Text>)]
    issuer: Option<String>,
    #[diesel(sql_type = sql_types::Nullable<sql_types::Text>)]
    external_host: Option<String>,
}

#[derive(Debug, QueryableByName)]
struct TenantDirectoryRevisionRow {
    #[diesel(sql_type = sql_types::BigInt)]
    revision: i64,
}

impl ActiveTenantBoundaryRepository {
    #[must_use]
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    /// Prove that `context` resolves to one active tenant/realm/organization
    /// boundary.  Any missing row, disabled row, or cross-tenant relationship
    /// fails closed before the runtime is composed.
    pub async fn preflight(&self, context: TenantContext) -> Result<(), RepositoryError> {
        let mut connection = get_conn(&self.pool)
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        let row = sql_query(
            "SELECT
                 t.id AS tenant_id,
                 t.status AS tenant_status,
                 r.id AS realm_id,
                 r.tenant_id AS realm_tenant_id,
                 r.status AS realm_status,
                 o.id AS organization_id,
                 o.tenant_id AS organization_tenant_id,
                 o.status AS organization_status
             FROM (SELECT $1::uuid AS id) AS requested
             LEFT JOIN tenants AS t ON t.id = requested.id
             LEFT JOIN realms AS r ON r.id = $2
             LEFT JOIN organizations AS o ON o.id = $3",
        )
        .bind::<sql_types::Uuid, _>(context.tenant_id.as_uuid())
        .bind::<sql_types::Uuid, _>(context.realm_id.as_uuid())
        .bind::<sql_types::Uuid, _>(context.organization_id.as_uuid())
        .get_result::<ActiveTenantBoundaryRow>(&mut connection)
        .await
        .map_err(map_query_error)?;

        validate_active_boundary(context, row)
    }
}

impl nazo_persistence::ActiveTenantBoundaryStore for ActiveTenantBoundaryRepository {
    fn preflight(
        &self,
        context: TenantContext,
    ) -> futures_util::future::BoxFuture<'_, Result<(), RepositoryError>> {
        Box::pin(async move { ActiveTenantBoundaryRepository::preflight(self, context).await })
    }
}

impl TenantDirectoryRepository {
    #[must_use]
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    pub async fn current_revision(&self) -> Result<u64, RepositoryError> {
        let mut connection = get_conn(&self.pool)
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        let row = sql_query(
            "SELECT revision
             FROM tenant_runtime_directory_state
             WHERE singleton",
        )
        .get_result::<TenantDirectoryRevisionRow>(&mut connection)
        .await
        .map_err(map_query_error)?;
        decode_directory_revision(row.revision)
    }

    pub async fn load_active(&self) -> Result<TenantDirectorySnapshot, RepositoryError> {
        let mut connection = get_conn(&self.pool)
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        let rows = sql_query(
            "SELECT directory.revision,
                    active.tenant_id, active.realm_id, active.organization_id,
                    active.issuer, active.external_host
             FROM tenant_runtime_directory_state AS directory
             LEFT JOIN (
                 SELECT binding.tenant_id, binding.realm_id, binding.organization_id,
                        binding.issuer, binding.external_host
                 FROM tenant_runtime_bindings AS binding
                 JOIN tenants AS tenant
                   ON tenant.id = binding.tenant_id AND tenant.status = 'active'
                 JOIN realms AS realm
                   ON realm.id = binding.realm_id
                  AND realm.tenant_id = binding.tenant_id
                  AND realm.status = 'active'
                 JOIN organizations AS organization
                   ON organization.id = binding.organization_id
                  AND organization.tenant_id = binding.tenant_id
                  AND organization.status = 'active'
             ) AS active ON TRUE
             WHERE directory.singleton
             ORDER BY active.external_host, active.tenant_id",
        )
        .load::<TenantDirectoryRow>(&mut connection)
        .await
        .map_err(map_query_error)?;

        directory_snapshot(rows)
    }
}

impl TenantDirectoryStore for TenantDirectoryRepository {
    fn current_revision(
        &self,
    ) -> futures_util::future::BoxFuture<'_, Result<u64, RepositoryError>> {
        Box::pin(async move { TenantDirectoryRepository::current_revision(self).await })
    }

    fn load_active(
        &self,
    ) -> futures_util::future::BoxFuture<'_, Result<TenantDirectorySnapshot, RepositoryError>> {
        Box::pin(async move { TenantDirectoryRepository::load_active(self).await })
    }
}

fn map_query_error(error: diesel::result::Error) -> RepositoryError {
    match error {
        diesel::result::Error::NotFound => RepositoryError::NotFound,
        error => RepositoryError::Unexpected(error.to_string()),
    }
}

fn validate_active_boundary(
    context: TenantContext,
    row: ActiveTenantBoundaryRow,
) -> Result<(), RepositoryError> {
    let expected_tenant_id = context.tenant_id.as_uuid();
    let expected_realm_id = context.realm_id.as_uuid();
    let expected_organization_id = context.organization_id.as_uuid();

    if row.tenant_id != Some(expected_tenant_id) {
        return Err(RepositoryError::NotFound);
    }
    if row.realm_id != Some(expected_realm_id) || row.realm_tenant_id.is_none() {
        return Err(RepositoryError::NotFound);
    }
    if row.organization_id != Some(expected_organization_id) || row.organization_tenant_id.is_none()
    {
        return Err(RepositoryError::NotFound);
    }

    if row.tenant_status.as_deref() != Some("active") {
        return Err(RepositoryError::Consistency(
            "tenant boundary row is not active".to_owned(),
        ));
    }
    if row.realm_status.as_deref() != Some("active") {
        return Err(RepositoryError::Consistency(
            "realm boundary row is not active".to_owned(),
        ));
    }
    if row.organization_status.as_deref() != Some("active") {
        return Err(RepositoryError::Consistency(
            "organization boundary row is not active".to_owned(),
        ));
    }

    if row.realm_tenant_id != Some(expected_tenant_id) {
        return Err(RepositoryError::Consistency(
            "realm boundary row belongs to another tenant".to_owned(),
        ));
    }
    if row.organization_tenant_id != Some(expected_tenant_id) {
        return Err(RepositoryError::Consistency(
            "organization boundary row belongs to another tenant".to_owned(),
        ));
    }

    Ok(())
}

fn directory_snapshot(
    rows: Vec<TenantDirectoryRow>,
) -> Result<TenantDirectorySnapshot, RepositoryError> {
    let stored_revision = rows
        .as_slice()
        .first()
        .map(|row| row.revision)
        .ok_or_else(|| {
            RepositoryError::Consistency("tenant directory state is missing".to_owned())
        })?;
    let revision = decode_directory_revision(stored_revision)?;
    let mut tenants = Vec::with_capacity(rows.len());
    for row in rows {
        if row.revision != stored_revision {
            return Err(RepositoryError::Consistency(
                "tenant directory snapshot contains mixed revisions".to_owned(),
            ));
        }
        match (
            row.tenant_id,
            row.realm_id,
            row.organization_id,
            row.issuer,
            row.external_host,
        ) {
            (None, None, None, None, None) => {}
            (
                Some(tenant_id),
                Some(realm_id),
                Some(organization_id),
                Some(issuer),
                Some(external_host),
            ) => tenants.push(TenantDirectoryBinding {
                tenant: TenantContext {
                    tenant_id: TenantId::new(tenant_id).map_err(|_| {
                        RepositoryError::Consistency("tenant directory tenant id is nil".to_owned())
                    })?,
                    realm_id: RealmId::new(realm_id).map_err(|_| {
                        RepositoryError::Consistency("tenant directory realm id is nil".to_owned())
                    })?,
                    organization_id: OrganizationId::new(organization_id).map_err(|_| {
                        RepositoryError::Consistency(
                            "tenant directory organization id is nil".to_owned(),
                        )
                    })?,
                },
                issuer,
                external_host,
            }),
            _ => {
                return Err(RepositoryError::Consistency(
                    "tenant directory binding is incomplete".to_owned(),
                ));
            }
        }
    }
    Ok(TenantDirectorySnapshot { revision, tenants })
}

fn decode_directory_revision(value: i64) -> Result<u64, RepositoryError> {
    u64::try_from(value).map_err(|_| {
        RepositoryError::Consistency("tenant directory revision is invalid".to_owned())
    })
}

// The focused unit test is mounted here so the production module remains the
// stable test boundary while implementation details evolve.
#[cfg(test)]
#[path = "../../tests/unit/repositories/tenancy.rs"]
mod tests;
