use diesel::{OptionalExtension as _, QueryableByName, sql_query, sql_types};
use diesel_async::{AsyncConnection as _, AsyncPgConnection, RunQueryDsl};
use nazo_identity::{
    OrganizationId, RealmId, TenantContext, TenantDirectoryBinding, TenantDirectorySnapshot,
    TenantId, canonical_tenant_host, ports::RepositoryError,
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

#[derive(Debug, QueryableByName)]
struct TenantDirectoryBindingRow {
    #[diesel(sql_type = sql_types::Uuid)]
    tenant_id: Uuid,
    #[diesel(sql_type = sql_types::Uuid)]
    realm_id: Uuid,
    #[diesel(sql_type = sql_types::Uuid)]
    organization_id: Uuid,
    #[diesel(sql_type = sql_types::Text)]
    issuer: String,
    #[diesel(sql_type = sql_types::Text)]
    external_host: String,
}

enum TenantDirectoryInitialization {
    Inserted,
    AlreadyInitialized,
    Conflict,
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

    /// Initializes the authoritative directory exactly once after migrations.
    /// A directory with any history is never rewritten from process config.
    pub async fn initialize(
        &self,
        binding: TenantDirectoryBinding,
    ) -> Result<bool, RepositoryError> {
        let mut connection = get_conn(&self.pool)
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        let result = connection
            .transaction::<_, diesel::result::Error, _>(async move |connection| {
                let state = sql_query(
                    "SELECT revision
                     FROM tenant_runtime_directory_state
                     WHERE singleton
                     FOR UPDATE",
                )
                .get_result::<TenantDirectoryRevisionRow>(connection)
                .await?;
                if state.revision != 0 {
                    let existing = sql_query(
                        "SELECT tenant_id, realm_id, organization_id, issuer, external_host
                         FROM tenant_runtime_bindings
                         WHERE tenant_id = $1",
                    )
                    .bind::<sql_types::Uuid, _>(binding.tenant.tenant_id.as_uuid())
                    .get_result::<TenantDirectoryBindingRow>(connection)
                    .await
                    .optional()?;
                    let matches = existing.is_some_and(|existing| {
                        existing.tenant_id == binding.tenant.tenant_id.as_uuid()
                            && existing.realm_id == binding.tenant.realm_id.as_uuid()
                            && existing.organization_id == binding.tenant.organization_id.as_uuid()
                            && existing.issuer == binding.issuer
                            && existing.external_host == binding.external_host
                    });
                    return Ok(if matches {
                        TenantDirectoryInitialization::AlreadyInitialized
                    } else {
                        TenantDirectoryInitialization::Conflict
                    });
                }

                sql_query(
                    "INSERT INTO tenant_runtime_bindings
                        (tenant_id, realm_id, organization_id, issuer, external_host)
                     VALUES ($1, $2, $3, $4, $5)",
                )
                .bind::<sql_types::Uuid, _>(binding.tenant.tenant_id.as_uuid())
                .bind::<sql_types::Uuid, _>(binding.tenant.realm_id.as_uuid())
                .bind::<sql_types::Uuid, _>(binding.tenant.organization_id.as_uuid())
                .bind::<sql_types::Text, _>(binding.issuer)
                .bind::<sql_types::Text, _>(binding.external_host)
                .execute(connection)
                .await?;
                Ok(TenantDirectoryInitialization::Inserted)
            })
            .await
            .map_err(map_query_error)?;
        match result {
            TenantDirectoryInitialization::Inserted => Ok(true),
            TenantDirectoryInitialization::AlreadyInitialized => Ok(false),
            TenantDirectoryInitialization::Conflict => Err(RepositoryError::Consistency(
                "tenant runtime directory is already initialized with a different binding"
                    .to_owned(),
            )),
        }
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

/// One identity boundary row a provisioning request must place or bind.
#[derive(Clone, Debug)]
pub struct TenantBoundaryDefinition<Id> {
    pub id: Id,
    pub slug: String,
    pub display_name: String,
}

/// A complete tenant boundary plus its canonical routing binding. The
/// transaction either creates every referenced row or proves that an existing
/// row already satisfies the request; it never rewrites a provisioned
/// binding.
#[derive(Clone, Debug)]
pub struct TenantProvisioningRequest {
    pub tenant: TenantBoundaryDefinition<TenantId>,
    pub realm: TenantBoundaryDefinition<RealmId>,
    pub organization: TenantBoundaryDefinition<OrganizationId>,
    pub binding: TenantDirectoryBinding,
}

/// Runtime lifecycle status of one tenant row. The directory snapshot only
/// routes tenants whose row is active.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TenantRuntimeStatus {
    Active,
    Suspended,
    Deleted,
}

impl TenantRuntimeStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Suspended => "suspended",
            Self::Deleted => "deleted",
        }
    }
}

/// Transaction-scoped error for the directory mutations. The transaction
/// boundary requires `From<diesel::result::Error>`; `RepositoryError` is a
/// foreign type, so the mutation commits roll through this wrapper.
enum DirectoryMutationError {
    Repository(RepositoryError),
    Query(diesel::result::Error),
}

impl From<diesel::result::Error> for DirectoryMutationError {
    fn from(error: diesel::result::Error) -> Self {
        Self::Query(error)
    }
}

impl From<RepositoryError> for DirectoryMutationError {
    fn from(error: RepositoryError) -> Self {
        Self::Repository(error)
    }
}

impl From<DirectoryMutationError> for RepositoryError {
    fn from(error: DirectoryMutationError) -> Self {
        match error {
            DirectoryMutationError::Repository(repository) => repository,
            DirectoryMutationError::Query(query) => map_query_error(query),
        }
    }
}

/// Locks the singleton directory state row and returns the current revision.
/// Every mutation must hold this lock before comparing its expected revision.
async fn lock_directory_revision(
    connection: &mut AsyncPgConnection,
) -> Result<u64, DirectoryMutationError> {
    let row = sql_query(
        "SELECT revision
         FROM tenant_runtime_directory_state
         WHERE singleton
         FOR UPDATE",
    )
    .get_result::<TenantDirectoryRevisionRow>(connection)
    .await
    .map_err(map_query_error)?;
    Ok(decode_directory_revision(row.revision)?)
}

/// Re-reads the revision advanced by the mutation trigger inside the same
/// transaction. The held state row lock guarantees no concurrent writer can
/// interleave between the mutation and this read.
async fn read_directory_revision(
    connection: &mut AsyncPgConnection,
) -> Result<u64, DirectoryMutationError> {
    let row = sql_query("SELECT revision FROM tenant_runtime_directory_state WHERE singleton")
        .get_result::<TenantDirectoryRevisionRow>(connection)
        .await
        .map_err(map_query_error)?;
    Ok(decode_directory_revision(row.revision)?)
}

/// Inserts one tenant, realm, or organization row when absent and proves that
/// an existing row is active and, for realms and organizations, owned by the
/// provisioning tenant.
async fn upsert_active_tenant_boundary(
    connection: &mut AsyncPgConnection,
    id: Uuid,
    slug: &str,
    display_name: &str,
) -> Result<(), RepositoryError> {
    sql_query(
        "INSERT INTO tenants (id, slug, display_name) VALUES ($1, $2, $3)
         ON CONFLICT (id) DO NOTHING",
    )
    .bind::<sql_types::Uuid, _>(id)
    .bind::<sql_types::Text, _>(slug)
    .bind::<sql_types::Text, _>(display_name)
    .execute(connection)
    .await
    .map_err(map_query_error)?;
    let row = sql_query("SELECT status FROM tenants WHERE id = $1 FOR UPDATE")
        .bind::<sql_types::Uuid, _>(id)
        .get_result::<BoundaryStatusRow>(connection)
        .await
        .map_err(map_query_error)?;
    if row.status.as_deref() != Some("active") {
        return Err(RepositoryError::Consistency(
            "provisioned tenant boundary row is not active".to_owned(),
        ));
    }
    Ok(())
}

/// Inserts one realm or organization row when absent and proves that an
/// existing row is active and owned by the provisioning tenant.
async fn upsert_active_owned_boundary(
    connection: &mut AsyncPgConnection,
    table: OwnedBoundaryTable,
    id: Uuid,
    tenant_id: Uuid,
    slug: &str,
    display_name: &str,
) -> Result<(), RepositoryError> {
    let (table, status_query) = match table {
        OwnedBoundaryTable::Realm => (
            "realms",
            "SELECT tenant_id, status FROM realms WHERE id = $1 FOR UPDATE",
        ),
        OwnedBoundaryTable::Organization => (
            "organizations",
            "SELECT tenant_id, status FROM organizations WHERE id = $1 FOR UPDATE",
        ),
    };
    sql_query(format!(
        "INSERT INTO {table} (id, tenant_id, slug, display_name)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (id) DO NOTHING"
    ))
    .bind::<sql_types::Uuid, _>(id)
    .bind::<sql_types::Uuid, _>(tenant_id)
    .bind::<sql_types::Text, _>(slug)
    .bind::<sql_types::Text, _>(display_name)
    .execute(connection)
    .await
    .map_err(map_query_error)?;
    let row = sql_query(status_query)
        .bind::<sql_types::Uuid, _>(id)
        .get_result::<BoundaryOwnershipRow>(connection)
        .await
        .map_err(map_query_error)?;
    if row.tenant_id != Some(tenant_id) {
        return Err(RepositoryError::Consistency(
            "boundary row belongs to another tenant".to_owned(),
        ));
    }
    if row.status.as_deref() != Some("active") {
        return Err(RepositoryError::Consistency(
            "boundary row is not active".to_owned(),
        ));
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum OwnedBoundaryTable {
    Realm,
    Organization,
}

#[derive(Debug, QueryableByName)]
struct TenantBindingPresenceRow {
    #[diesel(sql_type = sql_types::Uuid)]
    tenant_id: Uuid,
}

#[derive(Debug, QueryableByName)]
struct BoundaryStatusRow {
    #[diesel(sql_type = sql_types::Nullable<sql_types::Text>)]
    status: Option<String>,
}

#[derive(Debug, QueryableByName)]
struct BoundaryOwnershipRow {
    #[diesel(sql_type = sql_types::Nullable<sql_types::Uuid>)]
    tenant_id: Option<Uuid>,
    #[diesel(sql_type = sql_types::Nullable<sql_types::Text>)]
    status: Option<String>,
}

fn binding_rows_equal(row: &TenantDirectoryBindingRow, binding: &TenantDirectoryBinding) -> bool {
    row.tenant_id == binding.tenant.tenant_id.as_uuid()
        && row.realm_id == binding.tenant.realm_id.as_uuid()
        && row.organization_id == binding.tenant.organization_id.as_uuid()
        && row.issuer == binding.issuer
        && row.external_host == binding.external_host
}

/// Applies the same routing-identity rules as the runtime snapshot reader so
/// an invalid binding fails closed before the transaction can commit.
fn validate_binding_routing_identity(
    issuer: &str,
    external_host: &str,
) -> Result<(), RepositoryError> {
    nazo_auth::validate_issuer_url(issuer).map_err(|error| {
        RepositoryError::Consistency(format!("tenant issuer is invalid: {error}"))
    })?;
    let host = canonical_tenant_host(external_host).map_err(|error| {
        RepositoryError::Consistency(format!("tenant external host is invalid: {error}"))
    })?;
    if host != external_host {
        return Err(RepositoryError::Consistency(
            "tenant external host is not canonical".to_owned(),
        ));
    }
    let issuer_url = url::Url::parse(issuer).map_err(|error| {
        RepositoryError::Consistency(format!("tenant issuer is invalid: {error}"))
    })?;
    let issuer_host = issuer_url.host().ok_or_else(|| {
        RepositoryError::Consistency("tenant issuer must include a host".to_owned())
    })?;
    let issuer_host = match issuer_host {
        url::Host::Domain(domain) => canonical_tenant_host(domain),
        url::Host::Ipv4(address) => canonical_tenant_host(&address.to_string()),
        url::Host::Ipv6(address) => canonical_tenant_host(&format!("[{address}]")),
    }
    .map_err(|error| {
        RepositoryError::Consistency(format!("tenant issuer host is invalid: {error}"))
    })?;
    if issuer_host != host {
        return Err(RepositoryError::Consistency(format!(
            "tenant issuer host {issuer_host} does not match external_host {host}"
        )));
    }
    Ok(())
}

impl TenantDirectoryRepository {
    /// Creates the tenant boundary and its canonical binding under one
    /// revision-fenced transaction:
    ///
    /// ```text
    /// lock/recheck current revision
    ///   -> validate referenced tenant/realm/organization
    ///   -> apply boundary and binding writes
    ///   -> database trigger advances the revision
    ///   -> commit
    /// ```
    ///
    /// Replaying the identical request succeeds without moving the revision;
    /// a different request for an already-provisioned tenant fails closed.
    pub async fn provision_tenant_binding(
        &self,
        expected_revision: u64,
        request: TenantProvisioningRequest,
    ) -> Result<u64, RepositoryError> {
        validate_binding_routing_identity(&request.binding.issuer, &request.binding.external_host)?;
        if request.tenant.id != request.binding.tenant.tenant_id {
            return Err(RepositoryError::Consistency(
                "provisioned tenant row id does not match the binding tenant".to_owned(),
            ));
        }
        if request.binding.tenant.realm_id != request.realm.id
            || request.binding.tenant.organization_id != request.organization.id
        {
            return Err(RepositoryError::Consistency(
                "provisioning request boundary ids do not match the binding context".to_owned(),
            ));
        }
        let mut connection = get_conn(&self.pool)
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        connection
            .transaction::<_, DirectoryMutationError, _>(async move |connection| {
                let current = lock_directory_revision(connection).await?;
                if current != expected_revision {
                    return Err(RepositoryError::Conflict.into());
                }

                upsert_active_tenant_boundary(
                    connection,
                    request.tenant.id.as_uuid(),
                    &request.tenant.slug,
                    &request.tenant.display_name,
                )
                .await?;
                upsert_active_owned_boundary(
                    connection,
                    OwnedBoundaryTable::Realm,
                    request.realm.id.as_uuid(),
                    request.binding.tenant.tenant_id.as_uuid(),
                    &request.realm.slug,
                    &request.realm.display_name,
                )
                .await?;
                upsert_active_owned_boundary(
                    connection,
                    OwnedBoundaryTable::Organization,
                    request.organization.id.as_uuid(),
                    request.binding.tenant.tenant_id.as_uuid(),
                    &request.organization.slug,
                    &request.organization.display_name,
                )
                .await?;

                let inserted = sql_query(
                    "INSERT INTO tenant_runtime_bindings
                        (tenant_id, realm_id, organization_id, issuer, external_host)
                     VALUES ($1, $2, $3, $4, $5)
                     ON CONFLICT (tenant_id) DO NOTHING",
                )
                .bind::<sql_types::Uuid, _>(request.binding.tenant.tenant_id.as_uuid())
                .bind::<sql_types::Uuid, _>(request.binding.tenant.realm_id.as_uuid())
                .bind::<sql_types::Uuid, _>(request.binding.tenant.organization_id.as_uuid())
                .bind::<sql_types::Text, _>(&request.binding.issuer)
                .bind::<sql_types::Text, _>(&request.binding.external_host)
                .execute(connection)
                .await
                .map_err(map_query_error)?;
                if inserted == 0 {
                    let existing = sql_query(
                        "SELECT tenant_id, realm_id, organization_id, issuer, external_host
                         FROM tenant_runtime_bindings
                         WHERE tenant_id = $1
                         FOR UPDATE",
                    )
                    .bind::<sql_types::Uuid, _>(request.binding.tenant.tenant_id.as_uuid())
                    .get_result::<TenantDirectoryBindingRow>(connection)
                    .await
                    .map_err(map_query_error)?;
                    if !binding_rows_equal(&existing, &request.binding) {
                        return Err(RepositoryError::Consistency(
                            "tenant runtime directory is already provisioned with a different binding"
                                .to_owned(),
                        ).into());
                    }
                }
                read_directory_revision(connection).await
            })
            .await
            .map_err(RepositoryError::from)
    }

    /// Updates the canonical issuer/host of one existing binding under the
    /// revision fence. Replaying identical values is a bounded no-op that
    /// returns the current revision without advancing it.
    pub async fn update_tenant_binding(
        &self,
        expected_revision: u64,
        tenant_id: TenantId,
        issuer: String,
        external_host: String,
    ) -> Result<u64, RepositoryError> {
        validate_binding_routing_identity(&issuer, &external_host)?;
        let mut connection = get_conn(&self.pool)
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        connection
            .transaction::<_, DirectoryMutationError, _>(async move |connection| {
                let current = lock_directory_revision(connection).await?;
                if current != expected_revision {
                    return Err(RepositoryError::Conflict.into());
                }
                let existing = sql_query(
                    "SELECT tenant_id, realm_id, organization_id, issuer, external_host
                     FROM tenant_runtime_bindings
                     WHERE tenant_id = $1
                     FOR UPDATE",
                )
                .bind::<sql_types::Uuid, _>(tenant_id.as_uuid())
                .get_result::<TenantDirectoryBindingRow>(connection)
                .await
                .optional()
                .map_err(map_query_error)?
                .ok_or(RepositoryError::NotFound)?;
                if existing.issuer == issuer && existing.external_host == external_host {
                    return Ok(current);
                }
                sql_query(
                    "UPDATE tenant_runtime_bindings
                     SET issuer = $2, external_host = $3, updated_at = CURRENT_TIMESTAMP
                     WHERE tenant_id = $1",
                )
                .bind::<sql_types::Uuid, _>(tenant_id.as_uuid())
                .bind::<sql_types::Text, _>(&issuer)
                .bind::<sql_types::Text, _>(&external_host)
                .execute(connection)
                .await
                .map_err(map_query_error)?;
                read_directory_revision(connection).await
            })
            .await
            .map_err(RepositoryError::from)
    }

    /// Changes one routed tenant's lifecycle status under the revision fence.
    /// The tenant must currently own a binding, so every accepted transition
    /// is visible through the directory revision. Replaying the same status is
    /// a bounded no-op that returns the current revision without advancing it.
    pub async fn set_tenant_runtime_status(
        &self,
        expected_revision: u64,
        tenant_id: TenantId,
        status: TenantRuntimeStatus,
    ) -> Result<u64, RepositoryError> {
        let mut connection = get_conn(&self.pool)
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        connection
            .transaction::<_, DirectoryMutationError, _>(async move |connection| {
                let current = lock_directory_revision(connection).await?;
                if current != expected_revision {
                    return Err(RepositoryError::Conflict.into());
                }
                let bound = sql_query(
                    "SELECT tenant_id FROM tenant_runtime_bindings
                     WHERE tenant_id = $1
                     FOR UPDATE",
                )
                .bind::<sql_types::Uuid, _>(tenant_id.as_uuid())
                .get_result::<TenantBindingPresenceRow>(connection)
                .await
                .optional()
                .map_err(map_query_error)?;
                match bound {
                    Some(row) if row.tenant_id == tenant_id.as_uuid() => {}
                    _ => return Err(RepositoryError::NotFound.into()),
                }
                let row = sql_query("SELECT status FROM tenants WHERE id = $1 FOR UPDATE")
                    .bind::<sql_types::Uuid, _>(tenant_id.as_uuid())
                    .get_result::<BoundaryStatusRow>(connection)
                    .await
                    .optional()
                    .map_err(map_query_error)?
                    .ok_or(RepositoryError::NotFound)?;
                if row.status.as_deref() == Some(status.as_str()) {
                    return Ok(current);
                }
                sql_query(
                    "UPDATE tenants SET status = $2, updated_at = CURRENT_TIMESTAMP WHERE id = $1",
                )
                .bind::<sql_types::Uuid, _>(tenant_id.as_uuid())
                .bind::<sql_types::Text, _>(status.as_str())
                .execute(connection)
                .await
                .map_err(map_query_error)?;
                read_directory_revision(connection).await
            })
            .await
            .map_err(RepositoryError::from)
    }

    /// Removes the binding of one routed tenant under the revision fence. A
    /// tenant already finalized to `deleted` status is an idempotent no-op;
    /// every other missing binding fails closed.
    pub async fn remove_tenant_binding(
        &self,
        expected_revision: u64,
        tenant_id: TenantId,
    ) -> Result<u64, RepositoryError> {
        let mut connection = get_conn(&self.pool)
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        connection
            .transaction::<_, DirectoryMutationError, _>(async move |connection| {
                let current = lock_directory_revision(connection).await?;
                if current != expected_revision {
                    return Err(RepositoryError::Conflict.into());
                }
                let deleted = sql_query("DELETE FROM tenant_runtime_bindings WHERE tenant_id = $1")
                    .bind::<sql_types::Uuid, _>(tenant_id.as_uuid())
                    .execute(connection)
                    .await
                    .map_err(map_query_error)?;
                if deleted == 0 {
                    let status = sql_query("SELECT status FROM tenants WHERE id = $1 FOR UPDATE")
                        .bind::<sql_types::Uuid, _>(tenant_id.as_uuid())
                        .get_result::<BoundaryStatusRow>(connection)
                        .await
                        .optional()
                        .map_err(map_query_error)?;
                    let finalized = matches!(
                        status.as_ref().and_then(|row| row.status.as_deref()),
                        Some("deleted")
                    );
                    return if finalized {
                        Ok(current)
                    } else {
                        Err(RepositoryError::NotFound.into())
                    };
                }
                read_directory_revision(connection).await
            })
            .await
            .map_err(RepositoryError::from)
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
