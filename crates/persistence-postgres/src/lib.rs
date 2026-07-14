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
mod oidf_seed;
mod pool;
mod repositories;
pub(crate) mod rows;
pub(crate) mod schema;

pub use oidf_seed::{OidfSeedClient, OidfSeedUser, seed_oidf_atomically};
pub use pool::{
    DbConnection, DbPool, DbPoolMetrics, cleanup_expired_security_state, create_pool,
    db_pool_metrics, get_conn, run_pending_migrations,
};
pub use repositories::{
    AccessRequestRepository, AuditRepository, AuthorizationFlowRepository, AuthorizationRepository,
    FederationRepository, GrantAuthorization, GrantRepository, MfaRepository,
    OAuthClientRepository, PasskeyRepository, RuntimeModuleEventPage, RuntimeModuleRepository,
    ScimRepository, TokenIssuanceRepository, TokenRepository, UserRepository,
};
