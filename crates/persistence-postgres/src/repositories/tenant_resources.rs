use chrono::{DateTime, Utc};
use diesel::{OptionalExtension, QueryableByName, sql_query, sql_types};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use nazo_identity::ports::RepositoryError;
use nazo_persistence::{ClientTrustPolicy, Openid4vcTrustPolicyRecord, Openid4vcTrustPolicyStore};
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TenantResourceBinding {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub resource_kind: String,
    pub resource_id: String,
    pub resource_digest: String,
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

/// Public OpenID4VC trust policy installed through the ordinary tenant
/// resource control plane. Private key material is rejected before storage
/// and by the database constraint.
#[derive(Clone, Debug, PartialEq)]
pub struct StoredOpenid4vcTrustPolicy {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub resource_id: String,
    pub resource_digest: String,
    pub public_material: Value,
    pub wallet_origins: Vec<String>,
    pub active: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Openid4vcTrustPolicyWrite {
    Applied(StoredOpenid4vcTrustPolicy),
    Replayed(StoredOpenid4vcTrustPolicy),
    Conflict(StoredOpenid4vcTrustPolicy),
}

#[derive(Clone, Debug, PartialEq)]
pub enum Openid4vcTrustPolicyRevoke {
    Revoked(StoredOpenid4vcTrustPolicy),
    AlreadyAbsent,
    Conflict(StoredOpenid4vcTrustPolicy),
}

#[derive(Clone, Debug, PartialEq)]
pub enum Openid4vcTrustPolicyForClient {
    Unbound,
    BoundInactive,
    Active(StoredOpenid4vcTrustPolicy),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Openid4vcTrustPolicyClientBind {
    Bound { binding_id: Uuid },
    Replayed { binding_id: Uuid },
    Conflict { binding_id: Uuid },
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

#[derive(QueryableByName)]
struct CountRow {
    #[diesel(sql_type = sql_types::BigInt)]
    count: i64,
}

#[derive(QueryableByName)]
struct OAuthClientStateRow {
    #[diesel(sql_type = sql_types::Uuid)]
    id: Uuid,
    #[diesel(sql_type = sql_types::Bool)]
    is_active: bool,
}

#[derive(QueryableByName)]
struct Openid4vcTrustPolicyClientBindingRow {
    #[diesel(sql_type = sql_types::Uuid)]
    id: Uuid,
    #[diesel(sql_type = sql_types::Uuid)]
    policy_id: Uuid,
}

#[derive(QueryableByName)]
struct Openid4vcTrustPolicyRow {
    #[diesel(sql_type = sql_types::Uuid)]
    id: Uuid,
    #[diesel(sql_type = sql_types::Uuid)]
    tenant_id: Uuid,
    #[diesel(sql_type = sql_types::Varchar)]
    resource_id: String,
    #[diesel(sql_type = sql_types::Varchar)]
    resource_digest: String,
    #[diesel(sql_type = sql_types::Jsonb)]
    public_material: Value,
    #[diesel(sql_type = sql_types::Jsonb)]
    wallet_origins: Value,
    #[diesel(sql_type = sql_types::Varchar)]
    source: String,
    #[diesel(sql_type = sql_types::Bool)]
    active: bool,
    #[diesel(sql_type = sql_types::Timestamptz)]
    created_at: DateTime<Utc>,
    #[diesel(sql_type = sql_types::Timestamptz)]
    updated_at: DateTime<Utc>,
    #[diesel(sql_type = sql_types::Nullable<sql_types::Timestamptz>)]
    revoked_at: Option<DateTime<Utc>>,
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

impl From<BindingRow> for TenantResourceBinding {
    fn from(row: BindingRow) -> Self {
        Self {
            id: row.id,
            tenant_id: row.tenant_id,
            resource_kind: row.resource_kind,
            resource_id: row.resource_id,
            resource_digest: row.resource_digest,
            active: row.active,
            locator: row.locator,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

impl TryFrom<Openid4vcTrustPolicyRow> for StoredOpenid4vcTrustPolicy {
    type Error = RepositoryError;

    fn try_from(row: Openid4vcTrustPolicyRow) -> Result<Self, Self::Error> {
        if row.source != "operator-managed" {
            return Err(RepositoryError::Consistency(
                "OpenID4VC trust policy has an invalid source".to_owned(),
            ));
        }
        validate_stored_openid4vc_trust_policy_identity(
            &row.resource_id,
            Some(&row.resource_digest),
        )?;
        validate_bounded_public_material(&row.public_material)?;
        let wallet_origins = validate_stored_wallet_origins(&row.wallet_origins)?;
        if row.active == row.revoked_at.is_some() {
            return Err(RepositoryError::Consistency(
                "OpenID4VC trust policy active state is inconsistent".to_owned(),
            ));
        }
        Ok(Self {
            id: row.id,
            tenant_id: row.tenant_id,
            resource_id: row.resource_id,
            resource_digest: row.resource_digest,
            public_material: row.public_material,
            wallet_origins,
            active: row.active,
            created_at: row.created_at,
            updated_at: row.updated_at,
            revoked_at: row.revoked_at,
        })
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

    /// Serialize one accepted operation's resource transition until the
    /// caller-owned transaction ends. The control-outcome ledger is the
    /// sole replay authority for that operation id.
    pub async fn lock_operation_identity_on_connection(
        connection: &mut AsyncPgConnection,
        deployment_id: &str,
        tenant_id: Uuid,
        jti: &str,
    ) -> Result<(), RepositoryError> {
        lock_operation_jti_on_connection(connection, deployment_id, tenant_id, jti).await
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
        let id = Uuid::now_v7();
        let inserted = sql_query(
            "INSERT INTO tenant_resource_bindings
                (id, tenant_id, resource_kind, resource_id, resource_digest,
                 active, locator)
             VALUES ($1, $2, $3, $4, $5, $6, $7)
             ON CONFLICT (tenant_id, resource_kind, resource_id)
             DO NOTHING
             RETURNING id, tenant_id, resource_kind, resource_id, resource_digest,
                       active, locator,
                       created_at, updated_at",
        )
        .bind::<sql_types::Uuid, _>(id)
        .bind::<sql_types::Uuid, _>(binding.tenant_id)
        .bind::<sql_types::Varchar, _>(binding.resource_kind)
        .bind::<sql_types::Varchar, _>(binding.resource_id)
        .bind::<sql_types::Varchar, _>(binding.resource_digest)
        .bind::<sql_types::Bool, _>(binding.active)
        .bind::<sql_types::Text, _>(binding.locator)
        .get_result::<BindingRow>(connection)
        .await
        .optional()
        .map_err(map_error)?;
        if let Some(row) = inserted {
            return Ok(row.into());
        }
        let existing = sql_query(
            "SELECT id, tenant_id, resource_kind, resource_id, resource_digest,
                    active, locator,
                    created_at, updated_at
             FROM tenant_resource_bindings
             WHERE tenant_id = $1 AND resource_kind = $2
               AND resource_id = $3
             FOR UPDATE",
        )
        .bind::<sql_types::Uuid, _>(binding.tenant_id)
        .bind::<sql_types::Varchar, _>(binding.resource_kind)
        .bind::<sql_types::Varchar, _>(binding.resource_id)
        .get_result::<BindingRow>(connection)
        .await
        .map_err(map_error)?;
        let existing_binding: TenantResourceBinding = existing.into();
        if existing_binding.resource_digest == binding.resource_digest
            && existing_binding.active == binding.active
            && existing_binding.locator == binding.locator
        {
            return Ok(existing_binding);
        }
        if !existing_binding.active {
            return sql_query(
                "UPDATE tenant_resource_bindings
                 SET resource_digest = $2, active = $3, locator = $4,
                     updated_at = CURRENT_TIMESTAMP
                 WHERE id = $1 AND NOT active
                 RETURNING id, tenant_id, resource_kind, resource_id, resource_digest,
                           active, locator, created_at, updated_at",
            )
            .bind::<sql_types::Uuid, _>(existing_binding.id)
            .bind::<sql_types::Varchar, _>(binding.resource_digest)
            .bind::<sql_types::Bool, _>(binding.active)
            .bind::<sql_types::Text, _>(binding.locator)
            .get_result::<BindingRow>(connection)
            .await
            .map(BindingRow::into)
            .map_err(map_error);
        }
        Err(RepositoryError::Conflict)
    }

    pub async fn active_bindings_on_connection(
        connection: &mut AsyncPgConnection,
        tenant_id: Uuid,
    ) -> Result<Vec<TenantResourceBinding>, RepositoryError> {
        sql_query(
            "SELECT id, tenant_id, resource_kind, resource_id, resource_digest,
                    active, locator,
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
                       active, locator,
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
                    active, locator,
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

    pub async fn get_openid4vc_trust_policy_on_connection(
        connection: &mut AsyncPgConnection,
        tenant_id: Uuid,
        resource_id: &str,
    ) -> Result<Option<StoredOpenid4vcTrustPolicy>, RepositoryError> {
        validate_stored_openid4vc_trust_policy_identity(resource_id, None)?;
        sql_query(
            "SELECT id, tenant_id, resource_id, resource_digest, public_material,
                    wallet_origins,
                    source, active, created_at, updated_at, revoked_at
             FROM openid4vc_trust_policies
             WHERE tenant_id = $1 AND resource_id = $2 AND active",
        )
        .bind::<sql_types::Uuid, _>(tenant_id)
        .bind::<sql_types::Varchar, _>(resource_id)
        .get_result::<Openid4vcTrustPolicyRow>(connection)
        .await
        .optional()
        .map_err(map_error)?
        .map(StoredOpenid4vcTrustPolicy::try_from)
        .transpose()
    }

    pub async fn active_openid4vc_trust_policy_by_resource_digest_on_connection(
        connection: &mut AsyncPgConnection,
        tenant_id: Uuid,
        resource_id: &str,
        expected_digest: &str,
    ) -> Result<Option<StoredOpenid4vcTrustPolicy>, RepositoryError> {
        validate_stored_openid4vc_trust_policy_identity(resource_id, Some(expected_digest))?;
        let policy =
            Self::get_openid4vc_trust_policy_on_connection(connection, tenant_id, resource_id)
                .await?;
        Ok(policy.filter(|policy| policy.resource_digest == expected_digest))
    }

    pub async fn active_openid4vc_trust_policy_for_origin_on_connection(
        connection: &mut AsyncPgConnection,
        tenant_id: Uuid,
        resource_id: &str,
        wallet_origin: &str,
        expected_digest: &str,
    ) -> Result<Option<StoredOpenid4vcTrustPolicy>, RepositoryError> {
        validate_wallet_origin(wallet_origin)?;
        let policy = Self::active_openid4vc_trust_policy_by_resource_digest_on_connection(
            connection,
            tenant_id,
            resource_id,
            expected_digest,
        )
        .await?;
        Ok(policy.filter(|policy| {
            policy
                .wallet_origins
                .iter()
                .any(|origin| origin == wallet_origin)
        }))
    }

    pub async fn active_openid4vc_trust_policy_for_origin(
        &self,
        tenant_id: Uuid,
        resource_id: &str,
        wallet_origin: &str,
        expected_digest: &str,
    ) -> Result<Option<StoredOpenid4vcTrustPolicy>, RepositoryError> {
        let mut connection = self.connection().await?;
        Self::active_openid4vc_trust_policy_for_origin_on_connection(
            &mut connection,
            tenant_id,
            resource_id,
            wallet_origin,
            expected_digest,
        )
        .await
    }

    pub async fn active_openid4vc_trust_policy_binding_on_connection(
        connection: &mut AsyncPgConnection,
        tenant_id: Uuid,
        binding_id: Uuid,
    ) -> Result<Option<StoredOpenid4vcTrustPolicy>, RepositoryError> {
        sql_query(
            "SELECT id, tenant_id, resource_id, resource_digest, public_material,
                    wallet_origins, source, active, created_at, updated_at, revoked_at
             FROM openid4vc_trust_policies
             WHERE tenant_id = $1 AND id = $2 AND active",
        )
        .bind::<sql_types::Uuid, _>(tenant_id)
        .bind::<sql_types::Uuid, _>(binding_id)
        .get_result::<Openid4vcTrustPolicyRow>(connection)
        .await
        .optional()
        .map_err(map_error)?
        .map(StoredOpenid4vcTrustPolicy::try_from)
        .transpose()
    }

    pub async fn openid4vc_trust_policy_for_client_on_connection(
        connection: &mut AsyncPgConnection,
        tenant_id: Uuid,
        public_client_id: &str,
    ) -> Result<Openid4vcTrustPolicyForClient, RepositoryError> {
        if public_client_id.is_empty()
            || public_client_id.len() > 255
            || public_client_id != public_client_id.trim()
        {
            return Err(RepositoryError::Consistency(
                "OpenID4VC trust policy client ID is invalid".to_owned(),
            ));
        }
        let client = sql_query(
            "SELECT id, is_active
             FROM oauth_clients
             WHERE tenant_id = $1 AND client_id = $2",
        )
        .bind::<sql_types::Uuid, _>(tenant_id)
        .bind::<sql_types::Varchar, _>(public_client_id)
        .get_result::<OAuthClientStateRow>(connection)
        .await
        .optional()
        .map_err(map_error)?;
        let Some(client) = client else {
            return Ok(Openid4vcTrustPolicyForClient::Unbound);
        };
        let binding_count = sql_query(
            "SELECT COUNT(*)::BIGINT AS count
             FROM openid4vc_trust_policy_clients
             WHERE tenant_id = $1 AND oauth_client_id = $2",
        )
        .bind::<sql_types::Uuid, _>(tenant_id)
        .bind::<sql_types::Uuid, _>(client.id)
        .get_result::<CountRow>(connection)
        .await
        .map_err(map_error)?;
        if binding_count.count == 0 {
            return Ok(Openid4vcTrustPolicyForClient::Unbound);
        }
        if !client.is_active {
            return Ok(Openid4vcTrustPolicyForClient::BoundInactive);
        }
        match active_openid4vc_trust_policy_for_internal_client_on_connection(
            connection, tenant_id, client.id,
        )
        .await?
        {
            Some(policy) => Ok(Openid4vcTrustPolicyForClient::Active(policy)),
            None => Ok(Openid4vcTrustPolicyForClient::BoundInactive),
        }
    }

    pub async fn openid4vc_trust_policy_for_client(
        &self,
        tenant_id: Uuid,
        public_client_id: &str,
    ) -> Result<Openid4vcTrustPolicyForClient, RepositoryError> {
        let mut connection = self.connection().await?;
        Self::openid4vc_trust_policy_for_client_on_connection(
            &mut connection,
            tenant_id,
            public_client_id,
        )
        .await
    }

    /// Install one validated public trust policy. The protocol/provider layer
    /// owns the OpenID4VC schema; persistence owns bounded storage and the
    /// active-version digest fence.
    pub async fn apply_openid4vc_trust_policy_on_connection(
        connection: &mut AsyncPgConnection,
        policy: NewStoredOpenid4vcTrustPolicy<'_>,
    ) -> Result<Openid4vcTrustPolicyWrite, RepositoryError> {
        validate_stored_openid4vc_trust_policy_identity(
            policy.resource_id,
            Some(policy.resource_digest),
        )?;
        validate_bounded_public_material(policy.public_material)?;
        let wallet_origins = validate_new_wallet_origins(policy.wallet_origins)?;
        let wallet_origins_json = serde_json::to_value(&wallet_origins).map_err(|_| {
            RepositoryError::Consistency(
                "OpenID4VC trust policy wallet origins are not JSON".to_owned(),
            )
        })?;
        lock_binding_identity_on_connection(
            connection,
            policy.tenant_id,
            "openid4vc-trust-policy",
            policy.resource_id,
        )
        .await?;

        if let Some(current) = select_openid4vc_trust_policy_on_connection(
            connection,
            policy.tenant_id,
            policy.resource_id,
            true,
        )
        .await?
        {
            return if current.resource_digest == policy.resource_digest
                && current.public_material == *policy.public_material
                && current.wallet_origins == wallet_origins
            {
                Ok(Openid4vcTrustPolicyWrite::Replayed(current))
            } else {
                Ok(Openid4vcTrustPolicyWrite::Conflict(current))
            };
        }

        let inserted = sql_query(
            "INSERT INTO openid4vc_trust_policies
                (id, tenant_id, resource_id, resource_digest, public_material,
                 wallet_origins, source, active)
             VALUES ($1, $2, $3, $4, $5, $6, 'operator-managed', TRUE)
             RETURNING id, tenant_id, resource_id, resource_digest, public_material,
                       wallet_origins,
                       source, active, created_at, updated_at, revoked_at",
        )
        .bind::<sql_types::Uuid, _>(Uuid::now_v7())
        .bind::<sql_types::Uuid, _>(policy.tenant_id)
        .bind::<sql_types::Varchar, _>(policy.resource_id)
        .bind::<sql_types::Varchar, _>(policy.resource_digest)
        .bind::<sql_types::Jsonb, _>(policy.public_material)
        .bind::<sql_types::Jsonb, _>(&wallet_origins_json)
        .get_result::<Openid4vcTrustPolicyRow>(connection)
        .await
        .map_err(map_error)?
        .try_into()?;
        Ok(Openid4vcTrustPolicyWrite::Applied(inserted))
    }

    pub async fn bind_openid4vc_trust_policy_client_on_connection(
        connection: &mut AsyncPgConnection,
        tenant_id: Uuid,
        policy_resource_id: &str,
        expected_policy_digest: &str,
        oauth_client_id: Uuid,
    ) -> Result<Openid4vcTrustPolicyClientBind, RepositoryError> {
        validate_stored_openid4vc_trust_policy_identity(
            policy_resource_id,
            Some(expected_policy_digest),
        )?;
        lock_binding_identity_on_connection(
            connection,
            tenant_id,
            "openid4vc-trust-policy",
            policy_resource_id,
        )
        .await?;
        lock_binding_identity_on_connection(
            connection,
            tenant_id,
            "openid4vc-trust-policy-client",
            &oauth_client_id.to_string(),
        )
        .await?;
        let client = sql_query(
            "SELECT id, is_active
             FROM oauth_clients
             WHERE tenant_id = $1 AND id = $2
             FOR UPDATE",
        )
        .bind::<sql_types::Uuid, _>(tenant_id)
        .bind::<sql_types::Uuid, _>(oauth_client_id)
        .get_result::<OAuthClientStateRow>(connection)
        .await
        .optional()
        .map_err(map_error)?
        .filter(|client| client.is_active)
        .ok_or(RepositoryError::NotFound)?;
        debug_assert_eq!(client.id, oauth_client_id);
        let policy = Self::active_openid4vc_trust_policy_by_resource_digest_on_connection(
            connection,
            tenant_id,
            policy_resource_id,
            expected_policy_digest,
        )
        .await?
        .ok_or(RepositoryError::Conflict)?;

        let active_binding = select_openid4vc_trust_policy_client_binding_on_connection(
            connection,
            tenant_id,
            oauth_client_id,
            true,
            None,
        )
        .await?;
        if let Some(active_binding) = active_binding {
            return if active_binding.policy_id == policy.id {
                Ok(Openid4vcTrustPolicyClientBind::Replayed {
                    binding_id: active_binding.id,
                })
            } else {
                Ok(Openid4vcTrustPolicyClientBind::Conflict {
                    binding_id: active_binding.id,
                })
            };
        }

        let binding_id = Uuid::now_v7();
        sql_query(
            "INSERT INTO openid4vc_trust_policy_clients
                (id, policy_id, tenant_id, oauth_client_id, active)
             VALUES ($1, $2, $3, $4, TRUE)",
        )
        .bind::<sql_types::Uuid, _>(binding_id)
        .bind::<sql_types::Uuid, _>(policy.id)
        .bind::<sql_types::Uuid, _>(tenant_id)
        .bind::<sql_types::Uuid, _>(oauth_client_id)
        .execute(connection)
        .await
        .map_err(map_error)?;
        Ok(Openid4vcTrustPolicyClientBind::Bound { binding_id })
    }

    pub async fn revoke_openid4vc_trust_policy_on_connection(
        connection: &mut AsyncPgConnection,
        tenant_id: Uuid,
        resource_id: &str,
        expected_digest: &str,
    ) -> Result<Openid4vcTrustPolicyRevoke, RepositoryError> {
        validate_stored_openid4vc_trust_policy_identity(resource_id, Some(expected_digest))?;
        lock_binding_identity_on_connection(
            connection,
            tenant_id,
            "openid4vc-trust-policy",
            resource_id,
        )
        .await?;
        let Some(current) =
            select_openid4vc_trust_policy_on_connection(connection, tenant_id, resource_id, true)
                .await?
        else {
            return Ok(Openid4vcTrustPolicyRevoke::AlreadyAbsent);
        };
        if current.resource_digest != expected_digest {
            return Ok(Openid4vcTrustPolicyRevoke::Conflict(current));
        }
        sql_query(
            "UPDATE openid4vc_trust_policy_clients
             SET active = FALSE, updated_at = CURRENT_TIMESTAMP
             WHERE tenant_id = $1 AND policy_id = $2 AND active",
        )
        .bind::<sql_types::Uuid, _>(tenant_id)
        .bind::<sql_types::Uuid, _>(current.id)
        .execute(connection)
        .await
        .map_err(map_error)?;
        let revoked = sql_query(
            "UPDATE openid4vc_trust_policies
             SET active = FALSE, revoked_at = CURRENT_TIMESTAMP,
                 updated_at = CURRENT_TIMESTAMP
             WHERE id = $1 AND active AND resource_digest = $2
             RETURNING id, tenant_id, resource_id, resource_digest, public_material,
                       wallet_origins,
                       source, active, created_at, updated_at, revoked_at",
        )
        .bind::<sql_types::Uuid, _>(current.id)
        .bind::<sql_types::Varchar, _>(expected_digest)
        .get_result::<Openid4vcTrustPolicyRow>(connection)
        .await
        .map_err(map_error)?
        .try_into()?;
        Ok(Openid4vcTrustPolicyRevoke::Revoked(revoked))
    }
}

async fn select_openid4vc_trust_policy_on_connection(
    connection: &mut AsyncPgConnection,
    tenant_id: Uuid,
    resource_id: &str,
    active: bool,
) -> Result<Option<StoredOpenid4vcTrustPolicy>, RepositoryError> {
    sql_query(
        "SELECT id, tenant_id, resource_id, resource_digest, public_material,
                wallet_origins,
                source, active, created_at, updated_at, revoked_at
         FROM openid4vc_trust_policies
         WHERE tenant_id = $1 AND resource_id = $2 AND active = $3
         ORDER BY updated_at DESC, id DESC
         LIMIT 1
         FOR UPDATE",
    )
    .bind::<sql_types::Uuid, _>(tenant_id)
    .bind::<sql_types::Varchar, _>(resource_id)
    .bind::<sql_types::Bool, _>(active)
    .get_result::<Openid4vcTrustPolicyRow>(connection)
    .await
    .optional()
    .map_err(map_error)?
    .map(StoredOpenid4vcTrustPolicy::try_from)
    .transpose()
}

async fn select_openid4vc_trust_policy_client_binding_on_connection(
    connection: &mut AsyncPgConnection,
    tenant_id: Uuid,
    oauth_client_id: Uuid,
    active: bool,
    policy_id: Option<Uuid>,
) -> Result<Option<Openid4vcTrustPolicyClientBindingRow>, RepositoryError> {
    sql_query(
        "SELECT id, policy_id
         FROM openid4vc_trust_policy_clients
         WHERE tenant_id = $1 AND oauth_client_id = $2 AND active = $3
           AND ($4::UUID IS NULL OR policy_id = $4)
         ORDER BY updated_at DESC, id DESC
         LIMIT 1
         FOR UPDATE",
    )
    .bind::<sql_types::Uuid, _>(tenant_id)
    .bind::<sql_types::Uuid, _>(oauth_client_id)
    .bind::<sql_types::Bool, _>(active)
    .bind::<sql_types::Nullable<sql_types::Uuid>, _>(policy_id)
    .get_result::<Openid4vcTrustPolicyClientBindingRow>(connection)
    .await
    .optional()
    .map_err(map_error)
}

async fn active_openid4vc_trust_policy_for_internal_client_on_connection(
    connection: &mut AsyncPgConnection,
    tenant_id: Uuid,
    oauth_client_id: Uuid,
) -> Result<Option<StoredOpenid4vcTrustPolicy>, RepositoryError> {
    let rows = sql_query(
        "SELECT policy.id, policy.tenant_id, policy.resource_id,
                policy.resource_digest, policy.public_material, policy.wallet_origins,
                policy.source,
                policy.active, policy.created_at, policy.updated_at, policy.revoked_at
         FROM openid4vc_trust_policy_clients binding
         JOIN openid4vc_trust_policies policy
           ON policy.tenant_id = binding.tenant_id
          AND policy.id = binding.policy_id
          AND policy.active
         WHERE binding.tenant_id = $1 AND binding.oauth_client_id = $2
           AND binding.active
         ORDER BY policy.id
         LIMIT 2
         FOR UPDATE OF binding, policy",
    )
    .bind::<sql_types::Uuid, _>(tenant_id)
    .bind::<sql_types::Uuid, _>(oauth_client_id)
    .load::<Openid4vcTrustPolicyRow>(connection)
    .await
    .map_err(map_error)?;
    if rows.len() > 1 {
        return Err(RepositoryError::Consistency(
            "OAuth client has multiple active OpenID4VC trust policies".to_owned(),
        ));
    }
    rows.into_iter()
        .next()
        .map(StoredOpenid4vcTrustPolicy::try_from)
        .transpose()
}

impl Openid4vcTrustPolicyStore for TenantResourceRepository {
    fn for_client<'a>(
        &'a self,
        tenant_id: Uuid,
        public_client_id: &'a str,
    ) -> futures_util::future::BoxFuture<'a, Result<ClientTrustPolicy, RepositoryError>> {
        Box::pin(async move {
            match self
                .openid4vc_trust_policy_for_client(tenant_id, public_client_id)
                .await?
            {
                Openid4vcTrustPolicyForClient::Unbound => Ok(ClientTrustPolicy::Unbound),
                Openid4vcTrustPolicyForClient::BoundInactive => {
                    Ok(ClientTrustPolicy::BoundInactive)
                }
                Openid4vcTrustPolicyForClient::Active(policy) => {
                    let material =
                        serde_json::from_value(policy.public_material).map_err(|_| {
                            RepositoryError::Consistency(
                                "stored OpenID4VC trust policy is invalid".to_owned(),
                            )
                        })?;
                    nazo_operator_protocol::validate_openid4vc_trust_policy(&material).map_err(
                        |_| {
                            RepositoryError::Consistency(
                                "stored OpenID4VC trust policy is invalid".to_owned(),
                            )
                        },
                    )?;
                    Ok(ClientTrustPolicy::Active(Box::new(
                        Openid4vcTrustPolicyRecord {
                            id: policy.id,
                            resource_id: policy.resource_id,
                            resource_digest: policy.resource_digest,
                            material,
                        },
                    )))
                }
            }
        })
    }

    fn active_for_origin<'a>(
        &'a self,
        tenant_id: Uuid,
        resource_id: &'a str,
        wallet_origin: &'a str,
        expected_digest: &'a str,
    ) -> futures_util::future::BoxFuture<
        'a,
        Result<Option<Openid4vcTrustPolicyRecord>, RepositoryError>,
    > {
        Box::pin(async move {
            self.active_openid4vc_trust_policy_for_origin(
                tenant_id,
                resource_id,
                wallet_origin,
                expected_digest,
            )
            .await?
            .map(|policy| {
                let material = serde_json::from_value(policy.public_material).map_err(|_| {
                    RepositoryError::Consistency(
                        "stored OpenID4VC trust policy is invalid".to_owned(),
                    )
                })?;
                nazo_operator_protocol::validate_openid4vc_trust_policy(&material).map_err(
                    |_| {
                        RepositoryError::Consistency(
                            "stored OpenID4VC trust policy is invalid".to_owned(),
                        )
                    },
                )?;
                Ok(Openid4vcTrustPolicyRecord {
                    id: policy.id,
                    resource_id: policy.resource_id,
                    resource_digest: policy.resource_digest,
                    material,
                })
            })
            .transpose()
        })
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

pub struct NewTenantResourceBinding<'a> {
    pub tenant_id: Uuid,
    pub resource_kind: &'a str,
    pub resource_id: &'a str,
    pub resource_digest: &'a str,
    pub active: bool,
    pub locator: &'a str,
}

pub struct NewStoredOpenid4vcTrustPolicy<'a> {
    pub tenant_id: Uuid,
    pub resource_id: &'a str,
    pub resource_digest: &'a str,
    pub public_material: &'a Value,
    /// Canonical wallet origins extracted and validated by the provider.
    pub wallet_origins: &'a [String],
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

fn validate_stored_openid4vc_trust_policy_identity(
    resource_id: &str,
    resource_digest: Option<&str>,
) -> Result<(), RepositoryError> {
    if resource_id.is_empty()
        || resource_id.len() > 255
        || resource_id != resource_id.trim()
        || resource_id.chars().any(char::is_control)
    {
        return Err(RepositoryError::Consistency(
            "OpenID4VC trust policy resource ID is invalid".to_owned(),
        ));
    }
    if resource_digest.is_some_and(|digest| {
        digest.len() != 64
            || !digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    }) {
        return Err(RepositoryError::Consistency(
            "OpenID4VC trust policy digest is invalid".to_owned(),
        ));
    }
    Ok(())
}

fn validate_bounded_public_material(public_material: &Value) -> Result<(), RepositoryError> {
    if !public_material.is_object()
        || serde_json::to_vec(public_material)
            .map_err(|_| {
                RepositoryError::Consistency(
                    "OpenID4VC trust policy material is not JSON".to_owned(),
                )
            })?
            .len()
            > 32 * 1024
    {
        return Err(RepositoryError::Consistency(
            "OpenID4VC trust policy material is not a bounded JSON object".to_owned(),
        ));
    }
    Ok(())
}

fn validate_new_wallet_origins(wallet_origins: &[String]) -> Result<Vec<String>, RepositoryError> {
    if wallet_origins.is_empty() || wallet_origins.len() > 16 {
        return Err(RepositoryError::Consistency(
            "OpenID4VC trust policy wallet origins are out of bounds".to_owned(),
        ));
    }
    let mut normalized = wallet_origins.to_vec();
    for origin in &normalized {
        validate_wallet_origin(origin)?;
    }
    normalized.sort();
    let original_len = normalized.len();
    normalized.dedup();
    if normalized.len() != original_len {
        return Err(RepositoryError::Consistency(
            "OpenID4VC trust policy wallet origins must be unique".to_owned(),
        ));
    }
    Ok(normalized)
}

fn validate_stored_wallet_origins(value: &Value) -> Result<Vec<String>, RepositoryError> {
    let origins = serde_json::from_value::<Vec<String>>(value.clone()).map_err(|_| {
        RepositoryError::Consistency(
            "stored OpenID4VC trust policy wallet origins are invalid".to_owned(),
        )
    })?;
    let normalized = validate_new_wallet_origins(&origins)?;
    if origins != normalized {
        return Err(RepositoryError::Consistency(
            "stored OpenID4VC trust policy wallet origins are not canonical".to_owned(),
        ));
    }
    Ok(origins)
}

fn validate_wallet_origin(origin: &str) -> Result<(), RepositoryError> {
    if origin.len() > 2048
        || origin != origin.trim()
        || !origin.starts_with("https://")
        || origin.chars().any(char::is_control)
    {
        return Err(RepositoryError::Consistency(
            "OpenID4VC trust policy wallet origin is invalid".to_owned(),
        ));
    }
    Ok(())
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
