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
    AccessRequestRepository, ActiveTenantBoundaryRepository, AuditLedgerRepository,
    AuditRepository, AuthorizationFlowRepository, AuthorizationRepository, ConformanceApplicant,
    ConformanceClient, ConformanceClientMapping, ConformanceLease, ConformanceLeaseCleanup,
    ConformanceLeasePublicMaterial, ConformanceLeaseRepository, ConformanceLeaseTokenDigests,
    ConformanceMtlsTrustAnchor, ConformanceOnboardingRequest, ConformanceOnboardingResult,
    FederationRepository, FreshSecurityAuditReceipt, GrantAuthorization, GrantRepository,
    InitialAdminBootstrapRepository, InitialAdminBootstrapState, InitialAdminClaimOutcome,
    MAX_CONFORMANCE_LEASE_SECONDS, MAX_SECURITY_AUDIT_PAYLOAD_BYTES, MIN_CONFORMANCE_LEASE_SECONDS,
    ManagedCredentialDataset, ManagedCredentialDatasetWrite, MfaRepository,
    MtlsTrustAnchorRepository, NewTenantResourceBinding, NewTenantResourceOperation,
    OAuthClientRepository, Openid4vciDatasetRepository, Openid4vciRepository, Openid4vpRepository,
    OperatorManagedTrustAnchor, PasskeyRepository, RuntimeModuleEventPage, RuntimeModuleRepository,
    ScimEventRepository, ScimRepository, SecurityAuditAnchorFreshness, SecurityAuditAnchorHealth,
    SecurityAuditEvent, SecurityAuditOutboxDelivery, SecurityAuditReceipt, TenantResourceBinding,
    TenantResourceBindingDeactivate, TenantResourceOperationRecord, TenantResourceOperationWrite,
    TenantResourceRepository, TenantResourceState, TenantResourceStateCas, TokenIssuanceRepository,
    TokenIssuanceResponseKeyError, TokenIssuanceResponseKeyRing, TokenRepository, UserInsert,
    UserRepository, append_fresh_security_audit_on_connection, canonicalize_suite_origin,
    deactivate_client_on_connection, delete_operator_managed_dataset_on_connection,
    disable_user_on_connection, insert_client_on_connection,
    insert_operator_managed_trust_anchor_on_connection, insert_user_on_connection,
    protect_dataset_claims, revoke_operator_managed_trust_anchor_on_connection,
    unprotect_dataset_claims, upsert_operator_managed_dataset_on_connection,
};
