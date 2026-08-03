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
    AccessRequestRepository, AuditRepository, AuthorizationFlowRepository, AuthorizationRepository,
    ConformanceLease, ConformanceLeaseCleanup, ConformanceLeasePublicMaterial,
    ConformanceLeaseRepository, FederationRepository, GrantAuthorization, GrantRepository,
    InitialAdminBootstrapRepository,
    InitialAdminBootstrapState, InitialAdminClaimOutcome, MAX_CONFORMANCE_LEASE_SECONDS,
    MIN_CONFORMANCE_LEASE_SECONDS, ManagedCredentialDataset, ManagedCredentialDatasetWrite,
    MfaRepository, MtlsTrustAnchorRepository, OAuthClientRepository, Openid4vciDatasetRepository,
    Openid4vciRepository, Openid4vpRepository, PasskeyRepository, RuntimeModuleEventPage,
    RuntimeModuleRepository, ScimEventRepository, ScimRepository, TokenIssuanceRepository,
    TokenRepository, UserRepository,
};
