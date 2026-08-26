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

pub use pool::{
    DbConnection, DbPool, DbPoolMetrics, cleanup_expired_security_state, create_pool,
    db_pool_metrics, get_conn, health_check, run_pending_migrations,
};
pub use repositories::{
    AccessRequestRepository, ActiveTenantBoundaryRepository, AdmittedController,
    AdmittedControllerSummary, AuditLedgerRepository, AuditRepository, AuthorizationFlowRepository,
    AuthorizationRepository, CONTROLLER_KEY_TTL_SECONDS, CommitWithApprovalError,
    ControllerIdentityAction, ControllerRegistryError, ControllerRegistryRepository,
    ControllerSlotStatus, ControllerSlotSummary, DEPLOYMENT_IDENTITY_LOCK_SEED,
    FederationRepository, FreshSecurityAuditReceipt, GrantAuthorization, GrantRepository,
    IDENTITY_APPROVAL_TTL_SECONDS, IdentityApprovalError, InitialAdminBootstrapRepository,
    InitialAdminBootstrapState, InitialAdminClaimOutcome, IssuedIdentityApproval,
    IssuedOpenid4vpVerificationEvidence, IssuedRecoveryChallenge, MAX_ACTIVE_CONTROLLER_SLOTS,
    MAX_RECOVERY_CHALLENGE_ATTEMPTS, MAX_SECURITY_AUDIT_PAYLOAD_BYTES, ManagedCredentialDataset,
    ManagedCredentialDatasetWrite, MfaRepository, MtlsTrustAnchorRepository, NewControllerSlot,
    NewOpenid4vpVerificationAttachment, NewOpenid4vpVerificationEvidence, NewRecoveryChallenge,
    NewRecoveryRoot, NewStoredOpenid4vcTrustPolicy, NewTenantResourceBinding,
    NewTenantResourceOperation, OAuthClientRepository, Openid4vcTrustPolicyClientBind,
    Openid4vcTrustPolicyForClient, Openid4vcTrustPolicyRevoke, Openid4vcTrustPolicyWrite,
    Openid4vciDatasetRepository, Openid4vciRepository, Openid4vpRepository,
    Openid4vpVerificationAttachmentState, OperatorManagedTrustAnchor, PasskeyRepository,
    PreparedOpenid4vpVerificationEvidence, RECOVERY_CHALLENGE_TTL_SECONDS, RecoveredSlotCommit,
    RecoveryRootError, RecoveryRootRepository, RecoveryRootSummary, RecoveryRotationError,
    RecoverySubmission, RotateControllerKey, RuntimeModuleEventPage, RuntimeModuleRepository,
    ScimEventRepository, ScimRepository, SecurityAuditAnchorFreshness, SecurityAuditAnchorHealth,
    SecurityAuditEvent, SecurityAuditOutboxDelivery, SecurityAuditReceipt, StoredControllerSlot,
    StoredOpenid4vcTrustPolicy, StoredOpenid4vpVerificationAttachment,
    StoredOpenid4vpVerificationEvidence, StoredRecoveryRoot, TenantResourceBinding,
    TenantResourceBindingDeactivate, TenantResourceOperationRecord, TenantResourceOperationWrite,
    TenantResourceRepository, TenantResourceState, TenantResourceStateCas, TokenIssuanceRepository,
    TokenIssuanceResponseKeyError, TokenIssuanceResponseKeyRing, TokenRepository, UserInsert,
    UserRepository, active_public_client_id_on_connection,
    append_fresh_security_audit_on_connection, deactivate_client_on_connection,
    delete_operator_managed_dataset_on_connection, disable_user_on_connection,
    insert_client_on_connection, insert_operator_managed_trust_anchor_on_connection,
    insert_user_on_connection, protect_dataset_claims,
    revoke_operator_managed_trust_anchor_on_connection, unprotect_dataset_claims,
    upsert_operator_managed_dataset_on_connection,
};
