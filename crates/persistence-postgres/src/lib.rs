#![forbid(unsafe_code)]

//! PostgreSQL repository adapters for NazoAuth.
//!
//! Persistence records and Diesel schema are intentionally private:
//!
//! ```compile_fail
//! use nazo_postgres::schema::users;
//! ```
//!
//! ```compile_fail
//! use nazo_postgres::rows::identity::UserRow;
//! ```

mod convert;
mod pool;
mod repositories;
pub(crate) mod rows;
pub(crate) mod schema;
mod tenant_resource_executor;

pub use pool::{
    DbConnection, DbPool, DbPoolMetrics, cleanup_expired_security_state, configure_runtime_role,
    create_pool, db_pool_metrics, get_conn, health_check, run_pending_migrations,
};
pub use repositories::{
    AccessRequestRepository, ActiveTenantBoundaryRepository, AdminProvisionError,
    AdminProvisionReceipt, AdminProvisionRepository, AdminProvisionRequest, AdmittedController,
    AdmittedControllerSummary, AuditLedgerRepository, AuditRepository, AuthorizationFlowRepository,
    AuthorizationRepository, CONTROLLER_KEY_TTL_SECONDS, CommitWithApprovalError,
    ControllerIdentityAction, ControllerRegistryError, ControllerRegistryRepository,
    ControllerSlotStatus, ControllerSlotSummary, DEPLOYMENT_IDENTITY_LOCK_SEED,
    FederationRepository, FreshSecurityAuditReceipt, GrantAuthorization, GrantRepository,
    IDENTITY_APPROVAL_TTL_SECONDS, IdentityApprovalError, IssuedIdentityApproval,
    IssuedOpenid4vpVerificationEvidence, IssuedRecoveryChallenge, MAX_ACTIVE_CONTROLLER_SLOTS,
    MAX_RECOVERY_CHALLENGE_ATTEMPTS, MAX_SECURITY_AUDIT_PAYLOAD_BYTES, ManagedCredentialDataset,
    ManagedCredentialDatasetWrite, MfaRepository, MtlsTrustAnchorRepository, NewControllerSlot,
    NewOpenid4vpVerificationAttachment, NewOpenid4vpVerificationEvidence, NewRecoveryChallenge,
    NewRecoveryRoot, NewStoredOpenid4vcTrustPolicy, NewTenantResourceBinding,
    OAuthClientRepository, Openid4vcTrustPolicyClientBind, Openid4vcTrustPolicyForClient,
    Openid4vcTrustPolicyRevoke, Openid4vcTrustPolicyWrite, Openid4vciDatasetRepository,
    Openid4vciRepository, Openid4vpRepository, Openid4vpVerificationAttachmentState,
    OperatorManagedTrustAnchor, PasskeyRepository, PreparedOpenid4vpVerificationEvidence,
    RECOVERY_CHALLENGE_TTL_SECONDS, RecoveredSlotCommit, RecoveryInvalidation, RecoveryRootError,
    RecoveryRootRepository, RecoveryRootSummary, RecoveryRotationError, RecoverySubmission,
    RotateControllerKey, RuntimeModuleEventPage, RuntimeModuleRepository, ScimEventRepository,
    ScimRepository, SecurityAuditAnchorFreshness, SecurityAuditAnchorHealth, SecurityAuditEvent,
    SecurityAuditOutboxDelivery, SecurityAuditReceipt, StoredControllerSlot,
    StoredOpenid4vcTrustPolicy, StoredOpenid4vpVerificationAttachment,
    StoredOpenid4vpVerificationEvidence, StoredRecoveryRoot, TenantBoundaryDefinition,
    TenantDirectoryRepository, TenantProvisioningRequest, TenantResourceBinding,
    TenantResourceBindingDeactivate, TenantResourceRepository, TenantResourceState,
    TenantResourceStateCas, TenantRuntimeStatus, TokenIssuanceRepository, TokenRepository,
    UserInsert, UserRepository, active_public_client_id_on_connection,
    append_fresh_security_audit_on_connection, deactivate_client_on_connection,
    delete_operator_managed_dataset_on_connection, disable_user_on_connection,
    insert_client_on_connection, insert_operator_managed_trust_anchor_on_connection,
    insert_user_on_connection, protect_dataset_claims,
    revoke_operator_managed_trust_anchor_on_connection, unprotect_dataset_claims,
    upsert_operator_managed_dataset_on_connection,
};
pub use tenant_resource_executor::PostgresTenantResourceExecutor;

#[derive(Clone)]
pub struct PostgresHealthCheck {
    pool: DbPool,
}

impl PostgresHealthCheck {
    #[must_use]
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}

impl nazo_persistence::DatabaseHealthPort for PostgresHealthCheck {
    fn check(
        &self,
    ) -> futures_util::future::BoxFuture<'_, Result<(), nazo_persistence::DatabaseHealthError>>
    {
        Box::pin(async {
            health_check(&self.pool)
                .await
                .map_err(|_| nazo_persistence::DatabaseHealthError)
        })
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct PostgresPoolMetrics;

impl nazo_persistence::DatabasePoolMetricsPort for PostgresPoolMetrics {
    fn snapshot(&self) -> nazo_persistence::DatabasePoolMetrics {
        let metrics = db_pool_metrics();
        nazo_persistence::DatabasePoolMetrics {
            acquire_count: metrics.acquire_count,
            wait_nanos_total: metrics.wait_nanos_total,
            wait_nanos_max: metrics.wait_nanos_max,
        }
    }
}

impl nazo_persistence::SecurityAuditLedger for AuditLedgerRepository {
    fn check_available(
        &self,
        require_least_privilege: bool,
    ) -> futures_util::future::BoxFuture<'_, Result<(), nazo_identity::ports::RepositoryError>>
    {
        Box::pin(async move {
            self.check_available_with_policy(require_least_privilege)
                .await
        })
    }

    fn anchor_freshness(
        &self,
    ) -> futures_util::future::BoxFuture<
        '_,
        Result<nazo_persistence::SecurityAuditFreshness, nazo_identity::ports::RepositoryError>,
    > {
        Box::pin(async move {
            AuditLedgerRepository::anchor_freshness(self)
                .await
                .map(|freshness| nazo_persistence::SecurityAuditFreshness {
                    head_sequence: freshness.head_sequence,
                    head_hash: freshness.head_hash,
                    checked_at: freshness.checked_at,
                })
        })
    }

    fn append(
        &self,
        event: nazo_persistence::SecurityAuditEvent,
    ) -> futures_util::future::BoxFuture<
        '_,
        Result<nazo_persistence::SecurityAuditReceipt, nazo_identity::ports::RepositoryError>,
    > {
        Box::pin(async move {
            AuditLedgerRepository::append(
                self,
                SecurityAuditEvent {
                    event_id: event.event_id,
                    event_type: event.event_type,
                    event_category: event.event_category,
                    payload: event.payload,
                    occurred_at: event.occurred_at,
                },
            )
            .await
            .map(|receipt| nazo_persistence::SecurityAuditReceipt {
                event_id: receipt.event_id,
                sequence: receipt.sequence,
                event_hash: receipt.event_hash,
            })
        })
    }
}

impl nazo_persistence::SecurityAuditExporter for AuditLedgerRepository {
    fn check_available(
        &self,
    ) -> futures_util::future::BoxFuture<'_, Result<(), nazo_identity::ports::RepositoryError>>
    {
        Box::pin(async move { self.check_exporter_available().await })
    }

    fn anchor_health(
        &self,
    ) -> futures_util::future::BoxFuture<
        '_,
        Result<nazo_persistence::SecurityAuditAnchorHealth, nazo_identity::ports::RepositoryError>,
    > {
        Box::pin(async move {
            AuditLedgerRepository::anchor_health(self)
                .await
                .map(|health| nazo_persistence::SecurityAuditAnchorHealth {
                    head_sequence: health.head_sequence,
                    head_hash: health.head_hash,
                    pending_count: health.pending_count,
                    oldest_pending_occurred_at: health.oldest_pending_occurred_at,
                    last_exported_sequence: health.last_exported_sequence,
                    last_exported_hash: health.last_exported_hash,
                    last_exported_occurred_at: health.last_exported_occurred_at,
                    last_exported_at: health.last_exported_at,
                })
        })
    }

    fn claim_due(
        &self,
        limit: i64,
        lock_timeout_seconds: i32,
    ) -> futures_util::future::BoxFuture<
        '_,
        Result<
            Vec<nazo_persistence::SecurityAuditOutboxDelivery>,
            nazo_identity::ports::RepositoryError,
        >,
    > {
        Box::pin(async move {
            AuditLedgerRepository::claim_due(self, limit, lock_timeout_seconds)
                .await
                .map(|deliveries| {
                    deliveries
                        .into_iter()
                        .map(|delivery| nazo_persistence::SecurityAuditOutboxDelivery {
                            event_id: delivery.event_id,
                            sequence: delivery.sequence,
                            event_type: delivery.event_type,
                            event_category: delivery.event_category,
                            payload: delivery.payload,
                            occurred_at: delivery.occurred_at,
                            previous_hash: delivery.previous_hash,
                            event_hash: delivery.event_hash,
                            attempts: delivery.attempts,
                        })
                        .collect()
                })
        })
    }

    fn mark_exported(
        &self,
        event_id: uuid::Uuid,
        expected_attempts: i32,
    ) -> futures_util::future::BoxFuture<'_, Result<(), nazo_identity::ports::RepositoryError>>
    {
        Box::pin(async move {
            AuditLedgerRepository::mark_exported(self, event_id, expected_attempts).await
        })
    }

    fn reschedule<'a>(
        &'a self,
        event_id: uuid::Uuid,
        expected_attempts: i32,
        available_at: chrono::DateTime<chrono::Utc>,
        last_error: &'a str,
    ) -> futures_util::future::BoxFuture<'a, Result<(), nazo_identity::ports::RepositoryError>>
    {
        Box::pin(async move {
            AuditLedgerRepository::reschedule(
                self,
                event_id,
                expected_attempts,
                available_at,
                last_error,
            )
            .await
        })
    }
}
