use diesel::{QueryableByName, sql_query, sql_types};
use diesel_async::RunQueryDsl;
use nazo_identity::{TenantContext, ports::RepositoryError};
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

// The focused unit test is mounted here so the production module remains the
// stable test boundary while implementation details evolve.
#[cfg(test)]
#[path = "../../tests/unit/repositories/tenancy.rs"]
mod tests;
