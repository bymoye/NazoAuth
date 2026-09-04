//! Backend-neutral composition for ephemeral protocol and identity state.
//!
//! The HTTP server depends on semantic state-machine operations only.  The
//! statically selected launcher owns the concrete client, namespace, scripts,
//! topology restrictions, and tenant binding.

use std::{future::Future, pin::Pin, sync::Arc};

use nazo_auth::{
    AuthorizationStateStorePort, CibaStateStorePort, CibaStateVersion, DeviceStateStorePort,
    DeviceStateVersion, DpopStateStorePort, TokenStateStorePort,
};
use nazo_identity::ports::{
    AvatarUploadStatePort, DeliveryStorePort, EmailVerificationStorePort, FederationStatePort,
    LoginSessionPort, LoginThrottlePort, MfaAttemptThrottlePort, PasskeyCeremonyPort,
    SessionStorePort,
};
use nazo_identity::{TenantDirectorySnapshot, TenantId};

pub type TransientStateFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, TransientStateError>> + Send + 'a>>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransientStateError {
    Unavailable,
    CorruptData,
    Unexpected,
}

impl std::fmt::Display for TransientStateError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Unavailable => "transient state is unavailable",
            Self::CorruptData => "transient state is corrupt",
            Self::Unexpected => "transient state operation returned an unexpected result",
        })
    }
}

impl std::error::Error for TransientStateError {}

pub trait TransientStateHealthPort: Send + Sync {
    fn check(&self) -> TransientStateFuture<'_, ()>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CibaPingDelivery {
    pub auth_req_id_hash: String,
    pub auth_req_id: String,
    pub endpoint: String,
    pub client_notification_token: String,
    pub attempts: u32,
    pub expires_at: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CibaPingFinishOutcome {
    Delivered,
    RetryAt(i64),
    Failed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CibaPingFinishResult {
    Applied,
    Missing,
    Conflict,
}

pub trait CibaPingDeliveryPort: Send + Sync {
    fn claim_due<'a>(
        &'a self,
        now: i64,
        lock_until: i64,
        limit: usize,
    ) -> TransientStateFuture<'a, Vec<CibaPingDelivery>>;

    fn finish<'a>(
        &'a self,
        delivery: &'a CibaPingDelivery,
        outcome: CibaPingFinishOutcome,
    ) -> TransientStateFuture<'a, CibaPingFinishResult>;
}

/// Complete set of transient-state capabilities required by one server.
///
/// Methods deliberately return narrow Ports rather than a connection or a
/// generic key/value store.  This keeps atomicity and TTL policy inside the
/// selected adapter while allowing the application to remain backend-neutral.
pub trait ServerTransientStateProvider: Send + Sync {
    fn health(&self) -> Arc<dyn TransientStateHealthPort>;
    fn authorization_state(&self) -> Arc<dyn AuthorizationStateStorePort>;
    fn token_state(&self) -> Arc<dyn TokenStateStorePort>;
    fn ciba_state(&self) -> Arc<dyn CibaStateStorePort<Version = CibaStateVersion>>;
    fn ciba_ping_deliveries(&self) -> Arc<dyn CibaPingDeliveryPort>;
    fn device_state(&self) -> Arc<dyn DeviceStateStorePort<Version = DeviceStateVersion>>;
    fn dpop_state(&self) -> Arc<dyn DpopStateStorePort>;
    fn protected_resource_dpop_state(
        &self,
    ) -> Arc<dyn nazo_resource_server::ProtectedResourceDpopStateStore>;
    fn fapi_http_signature_replay(&self) -> Arc<dyn crate::FapiHttpSignatureReplayStore>;
    fn request_rate_limits(&self) -> Arc<dyn nazo_auth::RequestRateLimitPort>;

    fn email_verification(&self) -> Arc<dyn EmailVerificationStorePort>;
    fn passkey_ceremonies(&self) -> Arc<dyn PasskeyCeremonyPort>;
    fn federation_state(&self) -> Arc<dyn FederationStatePort>;
    fn login_sessions(&self) -> Arc<dyn LoginSessionPort>;
    fn sessions(&self) -> Arc<dyn SessionStorePort>;
    fn login_throttle(&self) -> Arc<dyn LoginThrottlePort>;
    fn mfa_attempt_throttle(&self) -> Arc<dyn MfaAttemptThrottlePort>;
    fn delivery(&self) -> Arc<dyn DeliveryStorePort>;
    fn avatar_upload_state(&self) -> Arc<dyn AvatarUploadStatePort>;
}

/// Shared, backend-neutral cache for the authoritative tenant directory.
///
/// This port is used only by the runtime refresher. Request handlers resolve a
/// tenant from the process-local snapshot and never call this cache.
pub trait TenantDirectoryCachePort: Send + Sync {
    fn load(&self) -> TransientStateFuture<'_, Option<TenantDirectorySnapshot>>;

    /// Publishes a snapshot loaded from the authoritative database.
    ///
    /// A missing, corrupt, older, or same-revision-but-different cache entry is
    /// replaced. A valid entry with a higher revision, or the exact same
    /// snapshot, is retained and returns `false`. Cache-derived snapshots must
    /// never be passed back into this method.
    fn publish_authoritative<'a>(
        &'a self,
        snapshot: &'a TenantDirectorySnapshot,
    ) -> TransientStateFuture<'a, bool>;
}

/// Creates tenant-bound semantic state capabilities from one initialized
/// deployment backend. Implementations must not reconnect for each tenant.
pub trait TenantTransientStateFactory: Send + Sync {
    fn for_tenant(
        &self,
        tenant_id: TenantId,
    ) -> Result<ServerTransientStateBindings, TransientStateError>;
}

#[derive(Clone)]
pub struct ServerTransientStateBindings {
    provider: Arc<dyn ServerTransientStateProvider>,
}

impl ServerTransientStateBindings {
    #[must_use]
    pub fn new(provider: Arc<dyn ServerTransientStateProvider>) -> Self {
        Self { provider }
    }

    pub(super) fn provider(&self) -> &Arc<dyn ServerTransientStateProvider> {
        &self.provider
    }
}

/// Deployment-level state capabilities initialized once by the selected
/// backend launcher.
#[derive(Clone)]
pub struct ServerStateBackendBindings {
    tenant_state: Arc<dyn TenantTransientStateFactory>,
    tenant_directory_cache: Arc<dyn TenantDirectoryCachePort>,
}

impl ServerStateBackendBindings {
    #[must_use]
    pub fn new(
        tenant_state: Arc<dyn TenantTransientStateFactory>,
        tenant_directory_cache: Arc<dyn TenantDirectoryCachePort>,
    ) -> Self {
        Self {
            tenant_state,
            tenant_directory_cache,
        }
    }

    pub fn for_tenant(
        &self,
        tenant_id: TenantId,
    ) -> Result<ServerTransientStateBindings, TransientStateError> {
        self.tenant_state.for_tenant(tenant_id)
    }

    #[must_use]
    pub fn tenant_directory_cache(&self) -> Arc<dyn TenantDirectoryCachePort> {
        self.tenant_directory_cache.clone()
    }
}
