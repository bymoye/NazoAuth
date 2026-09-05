#![forbid(unsafe_code)]

//! Database-independent persistence capabilities consumed by NazoAuth.
//!
//! This crate defines business operations and their atomicity/error contracts.
//! It deliberately does not expose SQL, connections, transactions, rows, or a
//! generic CRUD interface. Database adapters implement these focused ports.

pub mod control_plane;
pub mod directory_control;
pub mod openid4vc;
pub mod operator;
pub mod tenant_resources;

pub use control_plane::*;
pub use openid4vc::*;
pub use operator::*;

use std::fmt;

use futures_util::future::BoxFuture;
use nazo_identity::ports::RepositoryError;
use nazo_operator_protocol::Openid4vcTrustPolicy;

#[derive(Clone)]
pub struct TokenIssuanceResponseKeyRing {
    current: TokenIssuanceResponseKey,
    previous: Option<TokenIssuanceResponseKey>,
}

impl fmt::Debug for TokenIssuanceResponseKeyRing {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TokenIssuanceResponseKeyRing")
            .field("current_id", &self.current.id)
            .field(
                "previous_id",
                &self.previous.as_ref().map(|key| key.id.as_str()),
            )
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
struct TokenIssuanceResponseKey {
    id: String,
    key: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TokenIssuanceResponseKeyError {
    EmptyId,
    IdTooLong,
    DuplicateId,
}

impl fmt::Display for TokenIssuanceResponseKeyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::EmptyId => "token issuance response encryption key id must not be empty",
            Self::IdTooLong => {
                "token issuance response encryption key id must be at most 128 bytes"
            }
            Self::DuplicateId => "token issuance response current and previous key ids must differ",
        })
    }
}

impl std::error::Error for TokenIssuanceResponseKeyError {}

impl TokenIssuanceResponseKeyRing {
    pub fn new(
        current_id: impl Into<String>,
        current_key: [u8; 32],
        previous: Option<(String, [u8; 32])>,
    ) -> Result<Self, TokenIssuanceResponseKeyError> {
        let current = TokenIssuanceResponseKey::new(current_id.into(), current_key)?;
        let previous = previous
            .map(|(id, key)| TokenIssuanceResponseKey::new(id, key))
            .transpose()?;
        if previous
            .as_ref()
            .is_some_and(|candidate| candidate.id == current.id)
        {
            return Err(TokenIssuanceResponseKeyError::DuplicateId);
        }
        Ok(Self { current, previous })
    }

    #[must_use]
    pub fn current_id(&self) -> &str {
        &self.current.id
    }

    #[must_use]
    pub fn current_key(&self) -> &[u8; 32] {
        &self.current.key
    }

    #[must_use]
    pub fn key_for(&self, id: &str) -> Option<&[u8; 32]> {
        if self.current.id == id {
            Some(&self.current.key)
        } else {
            self.previous
                .as_ref()
                .filter(|key| key.id == id)
                .map(|key| &key.key)
        }
    }
}

impl TokenIssuanceResponseKey {
    fn new(id: String, key: [u8; 32]) -> Result<Self, TokenIssuanceResponseKeyError> {
        if id.trim().is_empty() {
            return Err(TokenIssuanceResponseKeyError::EmptyId);
        }
        if id.len() > 128 {
            return Err(TokenIssuanceResponseKeyError::IdTooLong);
        }
        Ok(Self { id, key })
    }
}

pub const MAX_SECURITY_AUDIT_PAYLOAD_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug)]
pub struct SecurityAuditEvent {
    pub event_id: uuid::Uuid,
    pub event_type: String,
    pub event_category: String,
    pub payload: serde_json::Value,
    pub occurred_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecurityAuditReceipt {
    pub event_id: uuid::Uuid,
    pub sequence: i64,
    pub event_hash: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecurityAuditFreshness {
    pub head_sequence: i64,
    pub head_hash: Vec<u8>,
    pub checked_at: chrono::DateTime<chrono::Utc>,
}

/// Append-only security-ledger capability used by the application audit
/// boundary. Database roles, functions and chain storage remain adapter-owned.
pub trait SecurityAuditLedger: Send + Sync {
    fn check_available(
        &self,
        require_least_privilege: bool,
    ) -> BoxFuture<'_, Result<(), RepositoryError>>;

    fn anchor_freshness(&self) -> BoxFuture<'_, Result<SecurityAuditFreshness, RepositoryError>>;

    fn anchor_health(&self) -> BoxFuture<'_, Result<SecurityAuditAnchorHealth, RepositoryError>>;

    fn append(
        &self,
        event: SecurityAuditEvent,
    ) -> BoxFuture<'_, Result<SecurityAuditReceipt, RepositoryError>>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecurityAuditAnchorHealth {
    pub head_sequence: i64,
    pub head_hash: Vec<u8>,
    pub pending_count: i64,
    pub oldest_pending_occurred_at: Option<chrono::DateTime<chrono::Utc>>,
    pub last_exported_sequence: Option<i64>,
    pub last_exported_hash: Option<Vec<u8>>,
    pub last_exported_occurred_at: Option<chrono::DateTime<chrono::Utc>>,
    pub last_exported_at: Option<chrono::DateTime<chrono::Utc>>,
    pub deployment_id: Option<String>,
    pub observed_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Clone, Debug)]
pub struct SecurityAuditOutboxDelivery {
    pub event_id: uuid::Uuid,
    pub sequence: i64,
    pub event_type: String,
    pub event_category: String,
    pub payload: serde_json::Value,
    pub occurred_at: chrono::DateTime<chrono::Utc>,
    pub previous_hash: Vec<u8>,
    pub event_hash: Vec<u8>,
    pub attempts: i32,
}

/// Exporter-only security-ledger capability. Implementations must fence claims
/// and compare the expected attempt revision on acknowledgement/reschedule.
pub trait SecurityAuditExporter: Send + Sync {
    fn check_available(&self) -> BoxFuture<'_, Result<(), RepositoryError>>;

    fn anchor_health(&self) -> BoxFuture<'_, Result<SecurityAuditAnchorHealth, RepositoryError>>;

    fn observe_anchor<'a>(
        &'a self,
        deployment_id: &'a str,
    ) -> BoxFuture<'a, Result<(), RepositoryError>>;

    fn record_genesis<'a>(
        &'a self,
        deployment_id: &'a str,
        head_hash: &'a [u8],
    ) -> BoxFuture<'a, Result<(), RepositoryError>>;

    fn claim_due(
        &self,
        limit: i64,
        lock_timeout_seconds: i32,
    ) -> BoxFuture<'_, Result<Vec<SecurityAuditOutboxDelivery>, RepositoryError>>;

    fn mark_exported<'a>(
        &'a self,
        event_id: uuid::Uuid,
        expected_attempts: i32,
        deployment_id: &'a str,
    ) -> BoxFuture<'a, Result<(), RepositoryError>>;

    fn reschedule<'a>(
        &'a self,
        event_id: uuid::Uuid,
        expected_attempts: i32,
        available_at: chrono::DateTime<chrono::Utc>,
        last_error: &'a str,
    ) -> BoxFuture<'a, Result<(), RepositoryError>>;
}

impl<T> SecurityAuditExporter for std::sync::Arc<T>
where
    T: SecurityAuditExporter + ?Sized,
{
    fn check_available(&self) -> BoxFuture<'_, Result<(), RepositoryError>> {
        (**self).check_available()
    }

    fn anchor_health(&self) -> BoxFuture<'_, Result<SecurityAuditAnchorHealth, RepositoryError>> {
        (**self).anchor_health()
    }

    fn observe_anchor<'a>(
        &'a self,
        deployment_id: &'a str,
    ) -> BoxFuture<'a, Result<(), RepositoryError>> {
        (**self).observe_anchor(deployment_id)
    }

    fn record_genesis<'a>(
        &'a self,
        deployment_id: &'a str,
        head_hash: &'a [u8],
    ) -> BoxFuture<'a, Result<(), RepositoryError>> {
        (**self).record_genesis(deployment_id, head_hash)
    }

    fn claim_due(
        &self,
        limit: i64,
        lock_timeout_seconds: i32,
    ) -> BoxFuture<'_, Result<Vec<SecurityAuditOutboxDelivery>, RepositoryError>> {
        (**self).claim_due(limit, lock_timeout_seconds)
    }

    fn mark_exported<'a>(
        &'a self,
        event_id: uuid::Uuid,
        expected_attempts: i32,
        deployment_id: &'a str,
    ) -> BoxFuture<'a, Result<(), RepositoryError>> {
        (**self).mark_exported(event_id, expected_attempts, deployment_id)
    }

    fn reschedule<'a>(
        &'a self,
        event_id: uuid::Uuid,
        expected_attempts: i32,
        available_at: chrono::DateTime<chrono::Utc>,
        last_error: &'a str,
    ) -> BoxFuture<'a, Result<(), RepositoryError>> {
        (**self).reschedule(event_id, expected_attempts, available_at, last_error)
    }
}

/// Durable runtime-module state machine. Desired-state CAS and its matching
/// event append must be committed atomically by the adapter.
pub trait RuntimeModuleStore: Send + Sync {
    fn read_desired(
        &self,
        module_id: nazo_runtime_modules::ModuleId,
    ) -> BoxFuture<'_, Result<Option<nazo_runtime_modules::DesiredStateRecord>, RepositoryError>>;

    fn read_all_desired(
        &self,
    ) -> BoxFuture<'_, Result<Vec<nazo_runtime_modules::DesiredStateRecord>, RepositoryError>>;

    fn compare_and_set_desired(
        &self,
        change: nazo_runtime_modules::DesiredStateChange,
    ) -> BoxFuture<
        '_,
        Result<
            nazo_runtime_modules::CasOutcome<nazo_runtime_modules::DesiredStateRecord>,
            RepositoryError,
        >,
    >;

    fn compare_and_set_desired_guarded(
        &self,
        change: nazo_runtime_modules::DesiredStateChange,
        required_revisions: Vec<nazo_runtime_modules::DesiredRevisionGuard>,
    ) -> BoxFuture<
        '_,
        Result<
            nazo_runtime_modules::CasOutcome<nazo_runtime_modules::DesiredStateRecord>,
            RepositoryError,
        >,
    >;

    fn read_instance<'a>(
        &'a self,
        instance_id: &'a str,
        module_id: nazo_runtime_modules::ModuleId,
    ) -> BoxFuture<'a, Result<Option<nazo_runtime_modules::InstanceStateRecord>, RepositoryError>>;

    fn read_all_instances<'a>(
        &'a self,
        instance_id: &'a str,
    ) -> BoxFuture<'a, Result<Vec<nazo_runtime_modules::InstanceStateRecord>, RepositoryError>>;

    fn page_events(
        &self,
        offset: i64,
        limit: i64,
    ) -> BoxFuture<'_, Result<nazo_runtime_modules::ModuleEventPage, RepositoryError>>;

    fn compare_and_set_instance(
        &self,
        required_desired_revision: nazo_runtime_modules::ModuleRevision,
        mutation: nazo_runtime_modules::InstanceStateMutation,
    ) -> BoxFuture<
        '_,
        Result<
            nazo_runtime_modules::CasOutcome<nazo_runtime_modules::InstanceStateRecord>,
            RepositoryError,
        >,
    >;

    fn validate_revision(
        &self,
        module_id: nazo_runtime_modules::ModuleId,
        expected: nazo_runtime_modules::ModuleRevision,
    ) -> BoxFuture<'_, Result<bool, RepositoryError>>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DatabaseHealthError;

impl fmt::Display for DatabaseHealthError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("database health check failed")
    }
}

impl std::error::Error for DatabaseHealthError {}

/// Backend-neutral readiness capability. Implementations must perform a real
/// round trip against the database, not merely inspect a local pool handle.
pub trait DatabaseHealthPort: Send + Sync {
    fn check(&self) -> BoxFuture<'_, Result<(), DatabaseHealthError>>;
}

#[derive(Clone, Copy, Debug, serde::Serialize)]
pub struct DatabasePoolMetrics {
    pub acquire_count: u64,
    pub wait_nanos_total: u64,
    pub wait_nanos_max: u64,
}

/// Backend-neutral pool telemetry exposed by the optional performance endpoint.
pub trait DatabasePoolMetricsPort: Send + Sync {
    fn snapshot(&self) -> DatabasePoolMetrics;
}

/// Startup admission check for the configured tenant, realm, and organization.
/// The adapter must fail closed if any configured boundary is missing, inactive,
/// or belongs to another tenant.
pub trait ActiveTenantBoundaryStore: Send + Sync {
    fn preflight(
        &self,
        context: nazo_identity::TenantContext,
    ) -> BoxFuture<'_, Result<(), RepositoryError>>;
}

/// Authoritative read side of the dynamic tenant directory.
pub trait TenantDirectoryStore: Send + Sync {
    fn current_revision(&self) -> BoxFuture<'_, Result<u64, RepositoryError>>;

    fn load_active(
        &self,
    ) -> BoxFuture<'_, Result<nazo_identity::TenantDirectorySnapshot, RepositoryError>>;
}

#[derive(Clone)]
pub enum ClientTrustPolicy {
    Unbound,
    BoundInactive,
    Active(Box<Openid4vcTrustPolicyRecord>),
}

#[derive(Clone)]
pub struct Openid4vcTrustPolicyRecord {
    pub id: uuid::Uuid,
    pub resource_id: String,
    pub resource_digest: String,
    pub material: Openid4vcTrustPolicy,
}

/// Typed OpenID4VC trust-policy reads. Adapters must reject malformed stored
/// material instead of returning backend rows or unvalidated JSON.
pub trait Openid4vcTrustPolicyStore: Send + Sync {
    fn for_client<'a>(
        &'a self,
        tenant_id: uuid::Uuid,
        public_client_id: &'a str,
    ) -> BoxFuture<'a, Result<ClientTrustPolicy, RepositoryError>>;

    fn active_for_origin<'a>(
        &'a self,
        tenant_id: uuid::Uuid,
        resource_id: &'a str,
        wallet_origin: &'a str,
        expected_digest: &'a str,
    ) -> BoxFuture<'a, Result<Option<Openid4vcTrustPolicyRecord>, RepositoryError>>;
}

#[derive(Clone, Debug)]
pub struct AdminProvisionRequest {
    pub tenant: nazo_identity::TenantContext,
    pub operation_id: String,
    pub deployment_id: String,
    pub email: String,
    pub password_hash: nazo_identity::ports::PasswordHashInput,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdminProvisionReceipt {
    pub operation_id: String,
    pub deployment_id: String,
    pub user_id: uuid::Uuid,
    pub email: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdminProvisionError {
    InvalidInput,
    EmailConflict,
    OperationConflict,
    Unavailable,
    Storage,
}

impl fmt::Display for AdminProvisionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("administrator provisioning failed")
    }
}

impl std::error::Error for AdminProvisionError {}

/// Atomic, idempotent out-of-band administrator provisioning capability.
pub trait AdminProvisionStore: Send + Sync {
    fn provision(
        &self,
        request: AdminProvisionRequest,
    ) -> BoxFuture<'_, Result<AdminProvisionReceipt, AdminProvisionError>>;
}

/// Account projection needed by CIBA admission and token issuance.
pub trait CibaAccountStore: Send + Sync {
    fn by_email<'a>(
        &'a self,
        tenant_id: nazo_identity::TenantId,
        email: &'a str,
    ) -> BoxFuture<'a, Result<Option<nazo_identity::PublicAccount>, RepositoryError>>;

    fn by_id(
        &self,
        tenant_id: nazo_identity::TenantId,
        user_id: nazo_identity::UserId,
    ) -> BoxFuture<'_, Result<Option<nazo_identity::PublicAccount>, RepositoryError>>;
}

/// Administrative access-request workflow. Approval is intentionally one
/// capability because creating the OAuth client and resolving the request must
/// remain atomic inside the selected adapter.
pub trait AdminAccessRequestStore: Send + Sync {
    fn page<'a>(
        &'a self,
        tenant_id: nazo_identity::TenantId,
        limit: i64,
        offset: i64,
        search: Option<&'a str>,
        status: Option<nazo_identity::AccessRequestStatus>,
    ) -> BoxFuture<'a, Result<nazo_identity::AccessRequestPage, RepositoryError>>;

    fn by_id(
        &self,
        tenant_id: nazo_identity::TenantId,
        id: uuid::Uuid,
    ) -> BoxFuture<'_, Result<Option<nazo_identity::AccessRequest>, RepositoryError>>;

    fn approve<'a>(
        &'a self,
        tenant: nazo_identity::TenantContext,
        request_id: uuid::Uuid,
        actor_user_id: nazo_identity::UserId,
        client: &'a nazo_auth::PreparedClientRegistration,
    ) -> BoxFuture<'a, Result<nazo_auth::ApprovedClient, RepositoryError>>;

    fn reject(
        &self,
        tenant_id: nazo_identity::TenantId,
        request_id: uuid::Uuid,
        actor_user_id: nazo_identity::UserId,
        admin_note: String,
    ) -> BoxFuture<'_, Result<(), RepositoryError>>;
}

/// Durable delivery queue used by the back-channel logout worker. Claiming a
/// batch must fence concurrent workers; completion/failure must compare the
/// adapter-owned attempt revision before mutating the delivery.
pub trait BackchannelLogoutDeliveryStore: Send + Sync {
    fn claim_due(
        &self,
        limit: i64,
        lock_timeout_seconds: i32,
    ) -> BoxFuture<'_, Result<Vec<nazo_auth::BackchannelLogoutDelivery>, RepositoryError>>;

    fn complete(
        &self,
        delivery_id: uuid::Uuid,
        expected_attempts: i32,
    ) -> BoxFuture<'_, Result<(), RepositoryError>>;

    fn fail<'a>(
        &'a self,
        delivery_id: uuid::Uuid,
        expected_attempts: i32,
        next_attempt_at: Option<chrono::DateTime<chrono::Utc>>,
        last_error: &'a str,
    ) -> BoxFuture<'a, Result<(), RepositoryError>>;
}
