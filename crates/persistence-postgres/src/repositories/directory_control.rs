//! Atomic control-plane boundary for tenant-directory lifecycle operations.
//!
//! One accepted operation identity (jti + request hash) commits its directory
//! mutation, its security-audit event, and its replay-safe outcome ledger row
//! in a single PostgreSQL transaction. The revision fence lives inside the
//! directory mutation, so a stale expected revision never moves the directory.

use chrono::Utc;
use diesel::{OptionalExtension as _, QueryableByName, sql_query, sql_types};
use diesel_async::{AsyncConnection as _, AsyncPgConnection, RunQueryDsl};
use nazo_identity::{TenantRuntimeStatus, ports::RepositoryError};
use nazo_persistence::directory_control::{
    DirectoryControlAction, DirectoryControlFrame, DirectoryControlOutcome,
    DirectoryDescribeOutcome, DirectoryMutationOutcome, TenantDirectoryControlError,
    TenantDirectoryControlPort,
};
use serde_json::json;
use uuid::Uuid;

use super::tenancy::{
    load_active_on_connection, provision_tenant_binding_on_connection,
    reload_tenant_runtime_on_connection, remove_tenant_binding_on_connection,
    set_tenant_runtime_status_on_connection, update_tenant_binding_on_connection,
};
use crate::{
    DbPool, get_conn, repositories::audit_ledger::append_fresh_security_audit_on_connection,
};

/// The concrete directory lifecycle engine handed to the operator task.
#[derive(Clone)]
pub struct TenantDirectoryControlRepository {
    pool: DbPool,
}

impl TenantDirectoryControlRepository {
    #[must_use]
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    pub async fn execute_control_operation(
        &self,
        frame: DirectoryControlFrame<'_>,
    ) -> Result<DirectoryControlOutcome, TenantDirectoryControlError> {
        let DirectoryControlFrame {
            deployment_id,
            jti,
            request_sha256,
            actor,
            action,
        } = frame;
        if !is_lower_sha256(request_sha256) {
            return Err(TenantDirectoryControlError::Rejected);
        }
        let operation_id =
            Uuid::parse_str(jti).map_err(|_| TenantDirectoryControlError::Rejected)?;
        let operation_name = directory_operation_name(&action);
        if action_requires_tenant(&action) {
            // Boundaries are validated by the authoritative mutation itself.
            tenant_id_of(&action).map_err(|_| TenantDirectoryControlError::Rejected)?;
        }

        let mut connection = get_conn(&self.pool)
            .await
            .map_err(|_| TenantDirectoryControlError::Unavailable)?;

        connection
            .transaction::<_, DirectoryControlTransactionError, _>(async move |connection| {
                lock_directory_operation_jti_on_connection(connection, deployment_id, operation_id)
                    .await?;
                if let Some(outcome) = recorded_outcome_on_connection(
                    connection,
                    operation_id,
                    request_sha256,
                    &operation_name,
                )
                .await?
                {
                    return Ok(outcome);
                }

                let previous_revision = read_current_revision(connection).await?;
                let outcome = match &action {
                    DirectoryControlAction::Create {
                        expected_revision,
                        provisioning,
                    } => {
                        let revision = provision_tenant_binding_on_connection(
                            connection,
                            *expected_revision,
                            (**provisioning).clone(),
                        )
                        .await?;
                        DirectoryControlOutcome::Mutation(DirectoryMutationOutcome {
                            action: operation_name.clone(),
                            tenant_id: provisioning.binding.tenant.tenant_id.as_uuid().to_string(),
                            previous_revision,
                            revision,
                        })
                    }
                    DirectoryControlAction::Update {
                        expected_revision,
                        tenant_id,
                        issuer,
                        external_host,
                    } => {
                        let revision = update_tenant_binding_on_connection(
                            connection,
                            *expected_revision,
                            *tenant_id,
                            issuer.clone(),
                            external_host.clone(),
                        )
                        .await?;
                        DirectoryControlOutcome::Mutation(DirectoryMutationOutcome {
                            action: operation_name.clone(),
                            tenant_id: tenant_id.as_uuid().to_string(),
                            previous_revision,
                            revision,
                        })
                    }
                    DirectoryControlAction::Disable {
                        expected_revision,
                        tenant_id,
                    } => {
                        let revision = set_tenant_runtime_status_on_connection(
                            connection,
                            *expected_revision,
                            *tenant_id,
                            TenantRuntimeStatus::Suspended,
                        )
                        .await?;
                        DirectoryControlOutcome::Mutation(DirectoryMutationOutcome {
                            action: operation_name.clone(),
                            tenant_id: tenant_id.as_uuid().to_string(),
                            previous_revision,
                            revision,
                        })
                    }
                    DirectoryControlAction::Reload {
                        expected_revision,
                        tenant_id,
                    } => {
                        let revision = reload_tenant_runtime_on_connection(
                            connection,
                            *expected_revision,
                            *tenant_id,
                        )
                        .await?;
                        DirectoryControlOutcome::Mutation(DirectoryMutationOutcome {
                            action: operation_name.clone(),
                            tenant_id: tenant_id.as_uuid().to_string(),
                            previous_revision,
                            revision,
                        })
                    }
                    DirectoryControlAction::Finalize {
                        expected_revision,
                        tenant_id,
                    } => {
                        let revision = remove_tenant_binding_on_connection(
                            connection,
                            *expected_revision,
                            *tenant_id,
                        )
                        .await?;
                        DirectoryControlOutcome::Mutation(DirectoryMutationOutcome {
                            action: operation_name.clone(),
                            tenant_id: tenant_id.as_uuid().to_string(),
                            previous_revision,
                            revision,
                        })
                    }
                    DirectoryControlAction::Describe => {
                        let snapshot = load_active_on_connection(connection).await?;
                        DirectoryControlOutcome::Describe(DirectoryDescribeOutcome {
                            revision: snapshot.revision,
                            tenants: snapshot.tenants,
                        })
                    }
                };

                let audit_event = directory_audit_event(
                    deployment_id,
                    &operation_id.to_string(),
                    request_sha256,
                    actor,
                    &action,
                    previous_revision,
                    &outcome,
                );
                append_fresh_security_audit_on_connection(connection, &audit_event)
                    .await
                    .map_err(DirectoryControlTransactionError::Diesel)?;

                record_outcome_on_connection(
                    connection,
                    operation_id,
                    request_sha256,
                    tenant_id_of(&action).ok(),
                    &operation_name,
                    &outcome,
                )
                .await?;
                Ok(outcome)
            })
            .await
            .map_err(|error| match error {
                DirectoryControlTransactionError::Repository(repository) => {
                    map_repository_error(repository)
                }
                DirectoryControlTransactionError::Diesel(diesel_error) => {
                    tracing::warn!(
                        %diesel_error,
                        "tenant directory control transaction failed on storage"
                    );
                    TenantDirectoryControlError::Unavailable
                }
            })
    }
}

impl TenantDirectoryControlPort for TenantDirectoryControlRepository {
    fn execute_control_operation<'a>(
        &'a self,
        frame: DirectoryControlFrame<'a>,
    ) -> futures_util::future::BoxFuture<
        'a,
        Result<DirectoryControlOutcome, TenantDirectoryControlError>,
    > {
        Box::pin(async move {
            TenantDirectoryControlRepository::execute_control_operation(self, frame).await
        })
    }
}

#[derive(Debug)]
enum DirectoryControlTransactionError {
    Repository(RepositoryError),
    Diesel(diesel::result::Error),
}

impl From<RepositoryError> for DirectoryControlTransactionError {
    fn from(error: RepositoryError) -> Self {
        Self::Repository(error)
    }
}

impl From<diesel::result::Error> for DirectoryControlTransactionError {
    fn from(error: diesel::result::Error) -> Self {
        Self::Diesel(error)
    }
}

fn map_repository_error(error: RepositoryError) -> TenantDirectoryControlError {
    match error {
        RepositoryError::Conflict => TenantDirectoryControlError::Conflict,
        RepositoryError::NotFound | RepositoryError::Consistency(_) => {
            TenantDirectoryControlError::Rejected
        }
        RepositoryError::Unavailable | RepositoryError::Unexpected(_) => {
            TenantDirectoryControlError::Unavailable
        }
        RepositoryError::AlreadyProcessed => TenantDirectoryControlError::Rejected,
    }
}

fn directory_operation_name(action: &DirectoryControlAction) -> String {
    match action {
        DirectoryControlAction::Create { .. } => "create".to_owned(),
        DirectoryControlAction::Update { .. } => "update".to_owned(),
        DirectoryControlAction::Disable { .. } => "disable".to_owned(),
        DirectoryControlAction::Reload { .. } => "reload".to_owned(),
        DirectoryControlAction::Finalize { .. } => "finalize".to_owned(),
        DirectoryControlAction::Describe => "describe".to_owned(),
    }
}

fn action_requires_tenant(action: &DirectoryControlAction) -> bool {
    !matches!(action, DirectoryControlAction::Describe)
}

fn tenant_id_of(action: &DirectoryControlAction) -> Result<Uuid, ()> {
    match action {
        DirectoryControlAction::Create { provisioning, .. } => {
            Ok(provisioning.binding.tenant.tenant_id.as_uuid())
        }
        DirectoryControlAction::Update { tenant_id, .. }
        | DirectoryControlAction::Disable { tenant_id, .. }
        | DirectoryControlAction::Reload { tenant_id, .. }
        | DirectoryControlAction::Finalize { tenant_id, .. } => Ok(tenant_id.as_uuid()),
        DirectoryControlAction::Describe => Err(()),
    }
}

fn is_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Serializes concurrent jti accept/replay decisions for one deployment.
async fn lock_directory_operation_jti_on_connection(
    connection: &mut AsyncPgConnection,
    deployment_id: &str,
    operation_id: Uuid,
) -> Result<(), RepositoryError> {
    let key = format!(
        "nazoauth:tenant-directory-operation:jti:{}:{deployment_id}:{}:{operation_id}",
        deployment_id.len(),
        operation_id,
    );
    sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind::<sql_types::Text, _>(&key)
        .execute(connection)
        .await
        .map_err(map_query_error)?;
    Ok(())
}

fn map_query_error(error: diesel::result::Error) -> RepositoryError {
    match error {
        diesel::result::Error::NotFound => RepositoryError::NotFound,
        error => RepositoryError::Unexpected(error.to_string()),
    }
}

async fn read_current_revision(connection: &mut AsyncPgConnection) -> Result<u64, RepositoryError> {
    let row = sql_query("SELECT revision FROM tenant_runtime_directory_state WHERE singleton")
        .get_result::<DirectoryRevisionRow>(connection)
        .await
        .map_err(map_query_error)?;
    u64::try_from(row.revision).map_err(|_| {
        RepositoryError::Consistency("tenant directory revision is invalid".to_owned())
    })
}

#[derive(Debug, QueryableByName)]
struct DirectoryRevisionRow {
    #[diesel(sql_type = sql_types::BigInt)]
    revision: i64,
}

#[derive(Debug, QueryableByName)]
struct DirectoryOutcomeRow {
    #[diesel(sql_type = sql_types::Text)]
    request_hash: String,
    #[diesel(sql_type = sql_types::Text)]
    operation: String,
    #[diesel(sql_type = sql_types::Jsonb)]
    outcome: serde_json::Value,
}

async fn recorded_outcome_on_connection(
    connection: &mut AsyncPgConnection,
    operation_id: Uuid,
    request_sha256: &str,
    operation_name: &str,
) -> Result<Option<DirectoryControlOutcome>, DirectoryControlTransactionError> {
    let row = sql_query(
        "SELECT request_hash, operation, outcome
         FROM tenant_directory_control_operations
         WHERE operation_id = $1",
    )
    .bind::<sql_types::Uuid, _>(operation_id)
    .get_result::<DirectoryOutcomeRow>(connection)
    .await
    .optional()
    .map_err(DirectoryControlTransactionError::Diesel)?;
    let Some(row) = row else {
        return Ok(None);
    };
    if row.request_hash != request_sha256 || row.operation != operation_name {
        // Same operation id with different content is a permanent conflict.
        return Err(DirectoryControlTransactionError::Repository(
            RepositoryError::Conflict,
        ));
    }
    let outcome = serde_json::from_value(row.outcome).map_err(|_| {
        DirectoryControlTransactionError::Repository(RepositoryError::Unexpected(
            "recorded tenant directory outcome is undecodable".to_owned(),
        ))
    })?;
    Ok(Some(outcome))
}

async fn record_outcome_on_connection(
    connection: &mut AsyncPgConnection,
    operation_id: Uuid,
    request_sha256: &str,
    tenant_id: Option<Uuid>,
    operation_name: &str,
    outcome: &DirectoryControlOutcome,
) -> Result<(), DirectoryControlTransactionError> {
    let outcome = serde_json::to_value(outcome).map_err(|_| {
        DirectoryControlTransactionError::Repository(RepositoryError::Unexpected(
            "tenant directory outcome is unencodable".to_owned(),
        ))
    })?;
    sql_query(
        "INSERT INTO tenant_directory_control_operations
             (operation_id, request_hash, tenant_id, operation, outcome)
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind::<sql_types::Uuid, _>(operation_id)
    .bind::<sql_types::Text, _>(request_sha256)
    .bind::<sql_types::Nullable<sql_types::Uuid>, _>(tenant_id)
    .bind::<sql_types::Text, _>(operation_name)
    .bind::<sql_types::Jsonb, _>(outcome)
    .execute(connection)
    .await
    .map_err(DirectoryControlTransactionError::Diesel)?;
    Ok(())
}

fn directory_audit_event(
    deployment_id: &str,
    jti: &str,
    request_sha256: &str,
    actor: &serde_json::Value,
    action: &DirectoryControlAction,
    previous_revision: u64,
    outcome: &DirectoryControlOutcome,
) -> nazo_persistence::SecurityAuditEvent {
    let mut payload = json!({
        "deployment_id": deployment_id,
        "jti": jti,
        "request_sha256": request_sha256,
        "actor": actor,
        "operation": directory_operation_name(action),
        "expected_revision": expected_revision_of(action),
        "previous_revision": previous_revision,
        "revision": outcome.revision(),
    });
    if let Ok(tenant_id) = tenant_id_of(action) {
        payload["tenant_id"] = json!(tenant_id.to_string());
    }
    if let DirectoryControlAction::Create { provisioning, .. } = action {
        payload["issuer"] = json!(provisioning.binding.issuer);
        payload["external_host"] = json!(provisioning.binding.external_host);
    }
    if let DirectoryControlAction::Update {
        issuer,
        external_host,
        ..
    } = action
    {
        payload["issuer"] = json!(issuer);
        payload["external_host"] = json!(external_host);
    }
    nazo_persistence::SecurityAuditEvent {
        event_id: Uuid::now_v7(),
        event_type: format!("tenant_directory_{}", directory_operation_name(action)),
        event_category: "tenant_directory".to_owned(),
        payload,
        occurred_at: Utc::now(),
    }
}

fn expected_revision_of(action: &DirectoryControlAction) -> u64 {
    match action {
        DirectoryControlAction::Create {
            expected_revision, ..
        }
        | DirectoryControlAction::Update {
            expected_revision, ..
        }
        | DirectoryControlAction::Disable {
            expected_revision, ..
        }
        | DirectoryControlAction::Reload {
            expected_revision, ..
        }
        | DirectoryControlAction::Finalize {
            expected_revision, ..
        } => *expected_revision,
        DirectoryControlAction::Describe => 0,
    }
}
