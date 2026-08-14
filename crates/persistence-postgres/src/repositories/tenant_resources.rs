use chrono::{DateTime, Utc};
use diesel::{OptionalExtension, QueryableByName, sql_query, sql_types};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use nazo_identity::ports::RepositoryError;
use serde_json::Value;
use uuid::Uuid;

use crate::{DbPool, get_conn};

/// Authoritative tenant-scoped resource revision and manifest digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TenantResourceState {
    pub tenant_id: Uuid,
    pub revision: u64,
    pub resource_manifest_sha256: String,
    pub updated_at: DateTime<Utc>,
}

/// Persisted idempotency key and signed receipt for one machine operation.
#[derive(Clone, Debug, PartialEq)]
pub struct TenantResourceOperationRecord {
    pub id: Uuid,
    pub deployment_id: String,
    pub tenant_id: Uuid,
    pub jti: String,
    pub change_set_id: String,
    pub change_set_sha256: String,
    pub request_sha256: String,
    pub operation: String,
    pub expected_revision: u64,
    pub result_revision: u64,
    pub receipt_json: Value,
    pub receipt_jws: String,
    pub created_at: DateTime<Utc>,
}

/// Result of recording an operation.  A replay is safe only when the request
/// digest matches; a different digest for the same deployment/tenant/JTI is a
/// conflict and must not replace the original receipt.
#[derive(Clone, Debug, PartialEq)]
pub enum TenantResourceOperationWrite {
    Inserted(TenantResourceOperationRecord),
    Replayed(TenantResourceOperationRecord),
    Conflict(TenantResourceOperationRecord),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TenantResourceBinding {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub resource_kind: String,
    pub resource_id: String,
    pub resource_digest: String,
    pub change_set_id: String,
    pub change_set_sha256: String,
    pub active: bool,
    pub locator: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Outcome of a revision-guarded state transition.
#[derive(Clone, Debug, PartialEq)]
pub enum TenantResourceStateCas {
    Applied(TenantResourceState),
    Conflict(Option<TenantResourceState>),
}

#[derive(Clone, Debug, PartialEq)]
pub enum TenantResourceBindingDeactivate {
    Deactivated(TenantResourceBinding),
    Conflict(Option<TenantResourceBinding>),
}

#[derive(Clone)]
pub struct TenantResourceRepository {
    pool: DbPool,
}

#[derive(QueryableByName)]
struct StateRow {
    #[diesel(sql_type = sql_types::Uuid)]
    tenant_id: Uuid,
    #[diesel(sql_type = sql_types::BigInt)]
    revision: i64,
    #[diesel(sql_type = sql_types::Varchar)]
    resource_manifest_sha256: String,
    #[diesel(sql_type = sql_types::Timestamptz)]
    updated_at: DateTime<Utc>,
}

#[derive(QueryableByName)]
struct OperationRow {
    #[diesel(sql_type = sql_types::Uuid)]
    id: Uuid,
    #[diesel(sql_type = sql_types::Varchar)]
    deployment_id: String,
    #[diesel(sql_type = sql_types::Uuid)]
    tenant_id: Uuid,
    #[diesel(sql_type = sql_types::Varchar)]
    jti: String,
    #[diesel(sql_type = sql_types::Varchar)]
    change_set_id: String,
    #[diesel(sql_type = sql_types::Varchar)]
    change_set_sha256: String,
    #[diesel(sql_type = sql_types::Varchar)]
    request_sha256: String,
    #[diesel(sql_type = sql_types::Varchar)]
    operation: String,
    #[diesel(sql_type = sql_types::BigInt)]
    expected_revision: i64,
    #[diesel(sql_type = sql_types::BigInt)]
    result_revision: i64,
    #[diesel(sql_type = sql_types::Jsonb)]
    receipt_json: Value,
    #[diesel(sql_type = sql_types::Text)]
    receipt_jws: String,
    #[diesel(sql_type = sql_types::Timestamptz)]
    created_at: DateTime<Utc>,
}

#[derive(QueryableByName)]
struct BindingRow {
    #[diesel(sql_type = sql_types::Uuid)]
    id: Uuid,
    #[diesel(sql_type = sql_types::Uuid)]
    tenant_id: Uuid,
    #[diesel(sql_type = sql_types::Varchar)]
    resource_kind: String,
    #[diesel(sql_type = sql_types::Varchar)]
    resource_id: String,
    #[diesel(sql_type = sql_types::Varchar)]
    resource_digest: String,
    #[diesel(sql_type = sql_types::Varchar)]
    change_set_id: String,
    #[diesel(sql_type = sql_types::Varchar)]
    change_set_sha256: String,
    #[diesel(sql_type = sql_types::Bool)]
    active: bool,
    #[diesel(sql_type = sql_types::Text)]
    locator: String,
    #[diesel(sql_type = sql_types::Timestamptz)]
    created_at: DateTime<Utc>,
    #[diesel(sql_type = sql_types::Timestamptz)]
    updated_at: DateTime<Utc>,
}

#[derive(QueryableByName)]
struct AdvisoryLockRow {
    #[diesel(sql_type = sql_types::Bool)]
    locked: bool,
}

impl TryFrom<StateRow> for TenantResourceState {
    type Error = RepositoryError;

    fn try_from(row: StateRow) -> Result<Self, Self::Error> {
        Ok(Self {
            tenant_id: row.tenant_id,
            revision: decode_revision(row.revision)?,
            resource_manifest_sha256: row.resource_manifest_sha256,
            updated_at: row.updated_at,
        })
    }
}

impl TryFrom<OperationRow> for TenantResourceOperationRecord {
    type Error = RepositoryError;

    fn try_from(row: OperationRow) -> Result<Self, Self::Error> {
        Ok(Self {
            id: row.id,
            deployment_id: row.deployment_id,
            tenant_id: row.tenant_id,
            jti: row.jti,
            change_set_id: row.change_set_id,
            change_set_sha256: row.change_set_sha256,
            request_sha256: row.request_sha256,
            operation: row.operation,
            expected_revision: decode_revision(row.expected_revision)?,
            result_revision: decode_revision(row.result_revision)?,
            receipt_json: row.receipt_json,
            receipt_jws: row.receipt_jws,
            created_at: row.created_at,
        })
    }
}

impl From<BindingRow> for TenantResourceBinding {
    fn from(row: BindingRow) -> Self {
        Self {
            id: row.id,
            tenant_id: row.tenant_id,
            resource_kind: row.resource_kind,
            resource_id: row.resource_id,
            resource_digest: row.resource_digest,
            change_set_id: row.change_set_id,
            change_set_sha256: row.change_set_sha256,
            active: row.active,
            locator: row.locator,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

impl TenantResourceRepository {
    #[must_use]
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    /// Acquire one connection for a caller-owned transaction.  All *_on_connection
    /// methods below deliberately accept the same connection so a resource
    /// mutation, revision CAS, binding change, audit append, and receipt insert
    /// can commit or roll back together.
    pub async fn connection(&self) -> Result<crate::DbConnection, RepositoryError> {
        get_conn(&self.pool)
            .await
            .map_err(|_| RepositoryError::Unavailable)
    }

    pub async fn state(
        &self,
        tenant_id: Uuid,
    ) -> Result<Option<TenantResourceState>, RepositoryError> {
        let mut connection = self.connection().await?;
        Self::state_on_connection(&mut connection, tenant_id).await
    }

    pub async fn state_on_connection(
        connection: &mut AsyncPgConnection,
        tenant_id: Uuid,
    ) -> Result<Option<TenantResourceState>, RepositoryError> {
        sql_query(
            "SELECT tenant_id, revision, resource_manifest_sha256, updated_at
             FROM tenant_resource_states
             WHERE tenant_id = $1",
        )
        .bind::<sql_types::Uuid, _>(tenant_id)
        .get_result::<StateRow>(connection)
        .await
        .optional()
        .map_err(map_error)?
        .map(TenantResourceState::try_from)
        .transpose()
    }

    pub async fn compare_and_set_state_on_connection(
        connection: &mut AsyncPgConnection,
        tenant_id: Uuid,
        expected_revision: u64,
        next_revision: u64,
        resource_manifest_sha256: &str,
    ) -> Result<TenantResourceStateCas, RepositoryError> {
        let required_next_revision = expected_revision.checked_add(1).ok_or_else(|| {
            RepositoryError::Consistency(
                "tenant resource revision cannot advance past u64::MAX".to_owned(),
            )
        })?;
        if next_revision != required_next_revision {
            return Err(RepositoryError::Consistency(
                "tenant resource revision must advance exactly one step".to_owned(),
            ));
        }
        let expected_revision = encode_revision(expected_revision)?;
        let next_revision = encode_revision(next_revision)?;
        let row = sql_query(
            "WITH updated AS (
                 UPDATE tenant_resource_states
                 SET revision = $3,
                     resource_manifest_sha256 = $4,
                     updated_at = CURRENT_TIMESTAMP
                 WHERE tenant_id = $1 AND revision = $2
                 RETURNING tenant_id, revision, resource_manifest_sha256, updated_at
             ), inserted AS (
                 INSERT INTO tenant_resource_states
                     (tenant_id, revision, resource_manifest_sha256)
                 SELECT $1, $3, $4
                 WHERE $2 = 0 AND NOT EXISTS (SELECT 1 FROM updated)
                 ON CONFLICT (tenant_id) DO NOTHING
                 RETURNING tenant_id, revision, resource_manifest_sha256, updated_at
             )
             SELECT tenant_id, revision, resource_manifest_sha256, updated_at FROM updated
             UNION ALL
             SELECT tenant_id, revision, resource_manifest_sha256, updated_at FROM inserted",
        )
        .bind::<sql_types::Uuid, _>(tenant_id)
        .bind::<sql_types::BigInt, _>(expected_revision)
        .bind::<sql_types::BigInt, _>(next_revision)
        .bind::<sql_types::Varchar, _>(resource_manifest_sha256)
        .get_result::<StateRow>(connection)
        .await
        .optional()
        .map_err(map_error)?;
        if let Some(row) = row {
            return Ok(TenantResourceStateCas::Applied(row.try_into()?));
        }
        Ok(TenantResourceStateCas::Conflict(
            Self::state_on_connection(connection, tenant_id).await?,
        ))
    }

    pub async fn operation_on_connection(
        connection: &mut AsyncPgConnection,
        deployment_id: &str,
        tenant_id: Uuid,
        jti: &str,
        change_set_id: &str,
    ) -> Result<Option<TenantResourceOperationRecord>, RepositoryError> {
        Self::lock_operation_identity_on_connection(
            connection,
            deployment_id,
            tenant_id,
            jti,
            change_set_id,
        )
        .await?;
        sql_query(
            "SELECT id, deployment_id, tenant_id, jti, request_sha256,
                    change_set_id, change_set_sha256,
                    operation, expected_revision, result_revision,
                    receipt_json, receipt_jws, created_at
             FROM tenant_resource_operations
             WHERE deployment_id = $1 AND tenant_id = $2 AND jti = $3
             FOR UPDATE",
        )
        .bind::<sql_types::Varchar, _>(deployment_id)
        .bind::<sql_types::Uuid, _>(tenant_id)
        .bind::<sql_types::Varchar, _>(jti)
        .get_result::<OperationRow>(connection)
        .await
        .optional()
        .map_err(map_error)?
        .map(TenantResourceOperationRecord::try_from)
        .transpose()
    }

    pub async fn operation_by_change_set_on_connection(
        connection: &mut AsyncPgConnection,
        deployment_id: &str,
        tenant_id: Uuid,
        change_set_id: &str,
    ) -> Result<Option<TenantResourceOperationRecord>, RepositoryError> {
        lock_operation_change_set_on_connection(
            connection,
            deployment_id,
            tenant_id,
            change_set_id,
        )
        .await?;
        Self::operation_by_change_set_without_lock(
            connection,
            deployment_id,
            tenant_id,
            change_set_id,
        )
        .await
    }

    async fn operation_by_change_set_without_lock(
        connection: &mut AsyncPgConnection,
        deployment_id: &str,
        tenant_id: Uuid,
        change_set_id: &str,
    ) -> Result<Option<TenantResourceOperationRecord>, RepositoryError> {
        sql_query(
            "SELECT id, deployment_id, tenant_id, jti, change_set_id,
                    change_set_sha256, request_sha256, operation,
                    expected_revision, result_revision,
                    receipt_json, receipt_jws, created_at
             FROM tenant_resource_operations
             WHERE deployment_id = $1 AND tenant_id = $2 AND change_set_id = $3
             FOR UPDATE",
        )
        .bind::<sql_types::Varchar, _>(deployment_id)
        .bind::<sql_types::Uuid, _>(tenant_id)
        .bind::<sql_types::Varchar, _>(change_set_id)
        .get_result::<OperationRow>(connection)
        .await
        .optional()
        .map_err(map_error)?
        .map(TenantResourceOperationRecord::try_from)
        .transpose()
    }

    pub async fn record_operation_on_connection(
        connection: &mut AsyncPgConnection,
        operation: NewTenantResourceOperation<'_>,
    ) -> Result<TenantResourceOperationWrite, RepositoryError> {
        Self::lock_operation_identity_on_connection(
            connection,
            operation.deployment_id,
            operation.tenant_id,
            operation.jti,
            operation.change_set_id,
        )
        .await?;
        let expected_revision = encode_revision(operation.expected_revision)?;
        let result_revision = encode_revision(operation.result_revision)?;
        let id = Uuid::now_v7();
        let inserted = sql_query(
            "INSERT INTO tenant_resource_operations
                (id, deployment_id, tenant_id, jti, change_set_id, change_set_sha256,
                 request_sha256, operation, expected_revision, result_revision,
                 receipt_json, receipt_jws)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
             ON CONFLICT DO NOTHING
             RETURNING id, deployment_id, tenant_id, jti, change_set_id,
                       change_set_sha256, request_sha256,
                       operation, expected_revision, result_revision,
                       receipt_json, receipt_jws, created_at",
        )
        .bind::<sql_types::Uuid, _>(id)
        .bind::<sql_types::Varchar, _>(operation.deployment_id)
        .bind::<sql_types::Uuid, _>(operation.tenant_id)
        .bind::<sql_types::Varchar, _>(operation.jti)
        .bind::<sql_types::Varchar, _>(operation.change_set_id)
        .bind::<sql_types::Varchar, _>(operation.change_set_sha256)
        .bind::<sql_types::Varchar, _>(operation.request_sha256)
        .bind::<sql_types::Varchar, _>(operation.operation)
        .bind::<sql_types::BigInt, _>(expected_revision)
        .bind::<sql_types::BigInt, _>(result_revision)
        .bind::<sql_types::Jsonb, _>(operation.receipt_json)
        .bind::<sql_types::Text, _>(operation.receipt_jws)
        .get_result::<OperationRow>(connection)
        .await
        .optional()
        .map_err(map_error)?;
        if let Some(row) = inserted {
            return Ok(TenantResourceOperationWrite::Inserted(row.try_into()?));
        }
        let existing_jti = Self::operation_on_connection(
            connection,
            operation.deployment_id,
            operation.tenant_id,
            operation.jti,
            operation.change_set_id,
        )
        .await?;
        if let Some(existing) = existing_jti {
            if existing.request_sha256 == operation.request_sha256
                && existing.change_set_id == operation.change_set_id
                && existing.change_set_sha256 == operation.change_set_sha256
            {
                return Ok(TenantResourceOperationWrite::Replayed(existing));
            }
            return Ok(TenantResourceOperationWrite::Conflict(existing));
        }
        if let Some(existing) = Self::operation_by_change_set_without_lock(
            connection,
            operation.deployment_id,
            operation.tenant_id,
            operation.change_set_id,
        )
        .await?
        {
            return Ok(TenantResourceOperationWrite::Conflict(existing));
        }
        Err(RepositoryError::Consistency(
            "operation conflict disappeared before receipt lookup".to_owned(),
        ))
    }

    /// Serialize all reads and writes for one deployment/tenant/JTI/change-set
    /// pair until the caller-owned transaction ends.  JTI is always locked
    /// before change-set so callers cannot introduce inverse lock ordering.
    pub async fn lock_operation_identity_on_connection(
        connection: &mut AsyncPgConnection,
        deployment_id: &str,
        tenant_id: Uuid,
        jti: &str,
        change_set_id: &str,
    ) -> Result<(), RepositoryError> {
        lock_operation_jti_on_connection(connection, deployment_id, tenant_id, jti).await?;
        lock_operation_change_set_on_connection(
            connection,
            deployment_id,
            tenant_id,
            change_set_id,
        )
        .await?;
        Ok(())
    }

    /// Lock one tenant resource identity for the duration of the caller's
    /// transaction. Callers that mutate more than one identity must acquire
    /// these locks in one deterministic `(kind, resource_id)` order before
    /// changing any resource rows.
    pub async fn lock_binding_identity_on_connection(
        connection: &mut AsyncPgConnection,
        tenant_id: Uuid,
        resource_kind: &str,
        resource_id: &str,
    ) -> Result<(), RepositoryError> {
        lock_binding_identity_on_connection(connection, tenant_id, resource_kind, resource_id).await
    }

    pub async fn upsert_binding_on_connection(
        connection: &mut AsyncPgConnection,
        binding: NewTenantResourceBinding<'_>,
    ) -> Result<TenantResourceBinding, RepositoryError> {
        lock_binding_identity_on_connection(
            connection,
            binding.tenant_id,
            binding.resource_kind,
            binding.resource_id,
        )
        .await?;
        let requested_active = binding.active;
        let id = Uuid::now_v7();
        let inserted = sql_query(
            "INSERT INTO tenant_resource_bindings
                (id, tenant_id, resource_kind, resource_id, resource_digest,
                 change_set_id, change_set_sha256, active, locator)
             VALUES ($1, $2, $3, $4, $5, $6, $7, FALSE, $8)
             ON CONFLICT (tenant_id, resource_kind, resource_id, change_set_id)
             DO NOTHING
             RETURNING id, tenant_id, resource_kind, resource_id, resource_digest,
                       change_set_id, change_set_sha256, active, locator,
                       created_at, updated_at",
        )
        .bind::<sql_types::Uuid, _>(id)
        .bind::<sql_types::Uuid, _>(binding.tenant_id)
        .bind::<sql_types::Varchar, _>(binding.resource_kind)
        .bind::<sql_types::Varchar, _>(binding.resource_id)
        .bind::<sql_types::Varchar, _>(binding.resource_digest)
        .bind::<sql_types::Varchar, _>(binding.change_set_id)
        .bind::<sql_types::Varchar, _>(binding.change_set_sha256)
        .bind::<sql_types::Text, _>(binding.locator)
        .get_result::<BindingRow>(connection)
        .await
        .optional()
        .map_err(map_error)?;
        if let Some(row) = inserted {
            if !requested_active {
                return Ok(row.into());
            }
            sql_query(
                "UPDATE tenant_resource_bindings
                 SET active = FALSE, updated_at = CURRENT_TIMESTAMP
                 WHERE tenant_id = $1 AND resource_kind = $2
                   AND resource_id = $3 AND active
                   AND change_set_id <> $4",
            )
            .bind::<sql_types::Uuid, _>(binding.tenant_id)
            .bind::<sql_types::Varchar, _>(binding.resource_kind)
            .bind::<sql_types::Varchar, _>(binding.resource_id)
            .bind::<sql_types::Varchar, _>(binding.change_set_id)
            .execute(connection)
            .await
            .map_err(map_error)?;
            return sql_query(
                "UPDATE tenant_resource_bindings
                 SET active = TRUE, updated_at = CURRENT_TIMESTAMP
                 WHERE id = $1
                 RETURNING id, tenant_id, resource_kind, resource_id, resource_digest,
                           change_set_id, change_set_sha256, active, locator,
                           created_at, updated_at",
            )
            .bind::<sql_types::Uuid, _>(row.id)
            .get_result::<BindingRow>(connection)
            .await
            .map(BindingRow::into)
            .map_err(map_error);
        }
        let existing = sql_query(
            "SELECT id, tenant_id, resource_kind, resource_id, resource_digest,
                    change_set_id, change_set_sha256, active, locator,
                    created_at, updated_at
             FROM tenant_resource_bindings
             WHERE tenant_id = $1 AND resource_kind = $2
               AND resource_id = $3 AND change_set_id = $4
             FOR UPDATE",
        )
        .bind::<sql_types::Uuid, _>(binding.tenant_id)
        .bind::<sql_types::Varchar, _>(binding.resource_kind)
        .bind::<sql_types::Varchar, _>(binding.resource_id)
        .bind::<sql_types::Varchar, _>(binding.change_set_id)
        .get_result::<BindingRow>(connection)
        .await
        .map_err(map_error)?;
        let existing_binding: TenantResourceBinding = existing.into();
        if existing_binding.resource_digest == binding.resource_digest
            && existing_binding.change_set_sha256 == binding.change_set_sha256
            && existing_binding.active == requested_active
            && existing_binding.locator == binding.locator
        {
            return Ok(existing_binding);
        }
        Err(RepositoryError::Conflict)
    }

    pub async fn active_bindings_on_connection(
        connection: &mut AsyncPgConnection,
        tenant_id: Uuid,
    ) -> Result<Vec<TenantResourceBinding>, RepositoryError> {
        sql_query(
            "SELECT id, tenant_id, resource_kind, resource_id, resource_digest,
                    change_set_id, change_set_sha256, active, locator,
                    created_at, updated_at
             FROM tenant_resource_bindings
             WHERE tenant_id = $1 AND active
             ORDER BY resource_kind, resource_id, id",
        )
        .bind::<sql_types::Uuid, _>(tenant_id)
        .load::<BindingRow>(connection)
        .await
        .map(|rows| rows.into_iter().map(Into::into).collect())
        .map_err(map_error)
    }

    /// Deactivate exactly one active binding, fenced by its current digest.
    /// A stale digest never changes the row and returns the current active
    /// binding (when one exists), so the caller can emit a failed receipt
    /// without conflating a missing resource with a stale version.
    pub async fn deactivate_binding_on_connection(
        connection: &mut AsyncPgConnection,
        tenant_id: Uuid,
        resource_kind: &str,
        resource_id: &str,
        expected_digest: &str,
    ) -> Result<TenantResourceBindingDeactivate, RepositoryError> {
        lock_binding_identity_on_connection(connection, tenant_id, resource_kind, resource_id)
            .await?;
        let changed = sql_query(
            "UPDATE tenant_resource_bindings
             SET active = FALSE, updated_at = CURRENT_TIMESTAMP
             WHERE tenant_id = $1 AND resource_kind = $2
               AND resource_id = $3 AND resource_digest = $4 AND active
             RETURNING id, tenant_id, resource_kind, resource_id, resource_digest,
                       change_set_id, change_set_sha256, active, locator,
                       created_at, updated_at",
        )
        .bind::<sql_types::Uuid, _>(tenant_id)
        .bind::<sql_types::Varchar, _>(resource_kind)
        .bind::<sql_types::Varchar, _>(resource_id)
        .bind::<sql_types::Varchar, _>(expected_digest)
        .get_result::<BindingRow>(connection)
        .await
        .optional()
        .map_err(map_error)?;
        if let Some(row) = changed {
            return Ok(TenantResourceBindingDeactivate::Deactivated(row.into()));
        }
        let current = sql_query(
            "SELECT id, tenant_id, resource_kind, resource_id, resource_digest,
                    change_set_id, change_set_sha256, active, locator,
                    created_at, updated_at
             FROM tenant_resource_bindings
             WHERE tenant_id = $1 AND resource_kind = $2
               AND resource_id = $3 AND active
             FOR UPDATE",
        )
        .bind::<sql_types::Uuid, _>(tenant_id)
        .bind::<sql_types::Varchar, _>(resource_kind)
        .bind::<sql_types::Varchar, _>(resource_id)
        .get_result::<BindingRow>(connection)
        .await
        .optional()
        .map_err(map_error)?
        .map(Into::into);
        Ok(TenantResourceBindingDeactivate::Conflict(current))
    }
}

async fn lock_operation_jti_on_connection(
    connection: &mut AsyncPgConnection,
    deployment_id: &str,
    tenant_id: Uuid,
    jti: &str,
) -> Result<(), RepositoryError> {
    let key = format!(
        "nazoauth:tenant-resource-operation:jti:{tenant_id}:{}:{deployment_id}:{}:{jti}",
        deployment_id.len(),
        jti.len(),
    );
    lock_advisory_key_on_connection(connection, key).await
}

async fn lock_operation_change_set_on_connection(
    connection: &mut AsyncPgConnection,
    deployment_id: &str,
    tenant_id: Uuid,
    change_set_id: &str,
) -> Result<(), RepositoryError> {
    let key = format!(
        "nazoauth:tenant-resource-operation:change-set:{tenant_id}:{}:{deployment_id}:{}:{change_set_id}",
        deployment_id.len(),
        change_set_id.len(),
    );
    lock_advisory_key_on_connection(connection, key).await
}

async fn lock_advisory_key_on_connection(
    connection: &mut AsyncPgConnection,
    key: String,
) -> Result<(), RepositoryError> {
    let lock = sql_query(
        "SELECT TRUE AS locked
         FROM pg_advisory_xact_lock(hashtextextended($1, 8706))",
    )
    .bind::<sql_types::Text, _>(key)
    .get_result::<AdvisoryLockRow>(connection)
    .await
    .map_err(map_error)?;
    debug_assert!(lock.locked);
    Ok(())
}

pub struct NewTenantResourceOperation<'a> {
    pub deployment_id: &'a str,
    pub tenant_id: Uuid,
    pub jti: &'a str,
    pub change_set_id: &'a str,
    pub change_set_sha256: &'a str,
    pub request_sha256: &'a str,
    pub operation: &'a str,
    pub expected_revision: u64,
    pub result_revision: u64,
    pub receipt_json: &'a Value,
    pub receipt_jws: &'a str,
}

pub struct NewTenantResourceBinding<'a> {
    pub tenant_id: Uuid,
    pub resource_kind: &'a str,
    pub resource_id: &'a str,
    pub resource_digest: &'a str,
    pub change_set_id: &'a str,
    pub change_set_sha256: &'a str,
    pub active: bool,
    pub locator: &'a str,
}

async fn lock_binding_identity_on_connection(
    connection: &mut AsyncPgConnection,
    tenant_id: Uuid,
    resource_kind: &str,
    resource_id: &str,
) -> Result<(), RepositoryError> {
    let key = format!(
        "nazoauth:tenant-resource-binding:{tenant_id}:{}:{resource_kind}:{}:{resource_id}",
        resource_kind.len(),
        resource_id.len(),
    );
    let lock = sql_query(
        "SELECT TRUE AS locked
         FROM pg_advisory_xact_lock(hashtextextended($1, 8707))",
    )
    .bind::<sql_types::Text, _>(key)
    .get_result::<AdvisoryLockRow>(connection)
    .await
    .map_err(map_error)?;
    debug_assert!(lock.locked);
    Ok(())
}

fn encode_revision(value: u64) -> Result<i64, RepositoryError> {
    i64::try_from(value).map_err(|_| {
        RepositoryError::Consistency("tenant resource revision exceeds BIGINT".to_owned())
    })
}

fn decode_revision(value: i64) -> Result<u64, RepositoryError> {
    u64::try_from(value).map_err(|_| {
        RepositoryError::Consistency("tenant resource revision is negative".to_owned())
    })
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
