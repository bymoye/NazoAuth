//! Backend-neutral persistence composition for the HTTP server.
//!
//! The server asks for complete business capabilities here.  An adapter may
//! allocate pools, run transactions, or derive encryption state internally,
//! but none of those mechanisms cross into the application crate.

use std::sync::Arc;

use nazo_auth::{
    AdminClientRepositoryPort, AdminGrantRepositoryPort, AuthorizationRepositoryPort,
    DeviceGrantRepositoryPort, DynamicRegistrationClientStore, LogoutClientRepositoryPort,
    TokenRepositoryPort,
};
use nazo_identity::{
    TenantContext,
    ports::{
        AccessRequestRepositoryPort, AdminUserRepositoryPort, AuthorizedApplicationRepositoryPort,
        AvatarRepositoryPort, FederationLinkRepositoryPort, FederationLoginRepositoryPort,
        GrantSummaryRepositoryPort, LoginAccountRepositoryPort, MfaRepositoryPort,
        MtlsTrustAnchorStore, PasskeyAccountRepositoryPort, PasskeyRepositoryPort,
        ProfileRepositoryPort, RegistrationAccountRepositoryPort, RememberedMfaDevicePort,
        ScimCredentialAuditPort, ScimRepositoryPort, SessionAccountPort,
    },
};

/// All database capabilities required by one NazoAuth server process.
///
/// Each method returns a narrow semantic Port.  In particular, this is not a
/// connection factory: launchers own adapter construction and may select a
/// completely different static backend without pulling another driver's code
/// into the binary.
pub trait ServerPersistenceProvider: Send + Sync {
    fn active_tenant_boundary(&self) -> Arc<dyn nazo_persistence::ActiveTenantBoundaryStore>;
    fn security_audit_ledger(&self) -> Arc<dyn nazo_persistence::SecurityAuditLedger>;
    fn database_health(&self) -> Arc<dyn nazo_persistence::DatabaseHealthPort>;
    fn database_pool_metrics(&self) -> Arc<dyn nazo_persistence::DatabasePoolMetricsPort>;
    fn initial_admin_bootstrap(
        &self,
        tenant: TenantContext,
    ) -> Arc<dyn nazo_persistence::InitialAdminBootstrapStore>;
    fn runtime_modules(&self) -> Arc<dyn nazo_persistence::RuntimeModuleStore>;

    fn authorization_repository(
        &self,
        tenant_id: uuid::Uuid,
    ) -> Arc<dyn AuthorizationRepositoryPort>;
    fn device_grant_repository(&self, tenant_id: uuid::Uuid) -> Arc<dyn DeviceGrantRepositoryPort>;
    fn token_repository(
        &self,
        response_keys: nazo_persistence::TokenIssuanceResponseKeyRing,
    ) -> Arc<dyn TokenRepositoryPort>;
    fn access_token_revocations(
        &self,
    ) -> Arc<dyn nazo_resource_server::AccessTokenRevocationLookup>;

    fn admin_clients(&self) -> Arc<dyn AdminClientRepositoryPort>;
    fn dynamic_registration_clients(&self) -> Arc<dyn DynamicRegistrationClientStore>;
    fn logout_clients(&self) -> Arc<dyn LogoutClientRepositoryPort>;
    fn authorized_applications(&self) -> Arc<dyn AuthorizedApplicationRepositoryPort>;
    fn grant_summaries(&self) -> Arc<dyn GrantSummaryRepositoryPort>;
    fn admin_grants(&self) -> Arc<dyn AdminGrantRepositoryPort>;

    fn session_accounts(&self) -> Arc<dyn SessionAccountPort>;
    fn login_accounts(&self) -> Arc<dyn LoginAccountRepositoryPort>;
    fn registration_accounts(&self) -> Arc<dyn RegistrationAccountRepositoryPort>;
    fn admin_users(&self) -> Arc<dyn AdminUserRepositoryPort>;
    fn profiles(&self) -> Arc<dyn ProfileRepositoryPort>;
    fn avatars(&self) -> Arc<dyn AvatarRepositoryPort>;
    fn passkey_accounts(&self) -> Arc<dyn PasskeyAccountRepositoryPort>;
    fn passkeys(&self) -> Arc<dyn PasskeyRepositoryPort>;
    fn ciba_accounts(&self) -> Arc<dyn nazo_persistence::CibaAccountStore>;
    fn openid4vc_subjects(&self) -> Arc<dyn nazo_persistence::Openid4vcSubjectStore>;

    fn mfa_repository(
        &self,
        keys: Option<nazo_identity::ports::MfaTotpKeyRing>,
    ) -> Arc<dyn MfaRepositoryPort>;
    fn remembered_mfa_devices(
        &self,
        keys: Option<nazo_identity::ports::MfaTotpKeyRing>,
    ) -> Arc<dyn RememberedMfaDevicePort>;
    fn federation_links(&self) -> Arc<dyn FederationLinkRepositoryPort>;
    fn federation_logins(&self) -> Arc<dyn FederationLoginRepositoryPort>;

    fn access_requests(&self) -> Arc<dyn AccessRequestRepositoryPort>;
    fn admin_access_requests(&self) -> Arc<dyn nazo_persistence::AdminAccessRequestStore>;
    fn scim_repository(&self, event_retention_seconds: u64) -> Arc<dyn ScimRepositoryPort>;
    fn scim_credential_audit(&self) -> Arc<dyn ScimCredentialAuditPort>;
    fn scim_event_store(&self) -> Arc<dyn nazo_scim_events::EventStorePort>;
    fn logout_outbox(&self) -> Arc<dyn nazo_auth::BackchannelLogoutOutboxPort>;
    fn logout_delivery_store(&self) -> Arc<dyn nazo_persistence::BackchannelLogoutDeliveryStore>;

    fn controller_registry(&self) -> Arc<dyn nazo_persistence::ControllerRegistryPort>;
    fn recovery_root(&self) -> Arc<dyn nazo_persistence::RecoveryRootPort>;
    fn mtls_trust_anchors(&self) -> Arc<dyn MtlsTrustAnchorStore>;

    fn openid4vc_trust_policies(
        &self,
        data_key: [u8; 32],
    ) -> Arc<dyn nazo_persistence::Openid4vcTrustPolicyStore>;
    fn openid4vci_store(&self, data_key: [u8; 32]) -> Arc<dyn nazo_persistence::Openid4vciStore>;
    fn openid4vci_authorization_offers(
        &self,
        data_key: [u8; 32],
    ) -> Arc<dyn nazo_openid4vci::AuthorizationOfferPort>;
    fn openid4vci_datasets(
        &self,
        data_key: [u8; 32],
    ) -> Arc<dyn nazo_persistence::Openid4vciDatasetStore>;
    fn openid4vp_store(
        &self,
        tenant_id: uuid::Uuid,
        data_key: [u8; 32],
    ) -> Arc<dyn nazo_persistence::Openid4vpStore>;
}

/// Cloneable application-facing handle supplied by a statically selected
/// launcher.  The inner provider is intentionally private so startup code can
/// only request the focused capabilities above.
#[derive(Clone)]
pub struct ServerPersistenceBindings {
    provider: Arc<dyn ServerPersistenceProvider>,
}

impl ServerPersistenceBindings {
    #[must_use]
    pub fn new(provider: Arc<dyn ServerPersistenceProvider>) -> Self {
        Self { provider }
    }

    pub(super) fn provider(&self) -> &Arc<dyn ServerPersistenceProvider> {
        &self.provider
    }
}
