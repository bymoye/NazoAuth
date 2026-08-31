#![forbid(unsafe_code)]

use std::sync::Arc;

use nazo_oauth_server::{
    bootstrap::{ServerPersistenceBindings, ServerPersistenceProvider},
    cli::{LauncherFuture, PersistenceLauncher},
    config::{self, ConfigSource},
    operator_task::{OperatorBackendFuture, OperatorPersistence},
};
use nazo_postgres::{
    AccessRequestRepository, ActiveTenantBoundaryRepository, AdminProvisionRepository,
    AuditLedgerRepository, AuditRepository, AuthorizationFlowRepository,
    ControllerRegistryRepository, DbPool, FederationRepository, GrantRepository, MfaRepository,
    MtlsTrustAnchorRepository, OAuthClientRepository, Openid4vciDatasetRepository,
    Openid4vciRepository, Openid4vpRepository, PasskeyRepository, PostgresHealthCheck,
    PostgresPoolMetrics, PostgresTenantResourceExecutor, RecoveryRootRepository,
    RuntimeModuleRepository, ScimEventRepository, ScimRepository, TenantDirectoryControlRepository,
    TenantDirectoryRepository, TenantResourceRepository, TokenIssuanceRepository, TokenRepository,
    UserRepository,
};

const DEFAULT_DATABASE_URL: &str = "postgresql://postgres:postgres@127.0.0.1:5432/oauth";
const OPERATOR_DATABASE_MAX_CONNECTIONS: usize = 2;
const ADMIN_PROVISION_DATABASE_MAX_CONNECTIONS: usize = 2;
const MIGRATION_RUNTIME_ROLE_ENV: &str = "NAZOAUTH_MIGRATION_RUNTIME_ROLE";

#[derive(Clone)]
struct PostgresProvider {
    pool: DbPool,
}

impl PostgresProvider {
    fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}

impl ServerPersistenceProvider for PostgresProvider {
    fn active_tenant_boundary(&self) -> Arc<dyn nazo_persistence::ActiveTenantBoundaryStore> {
        Arc::new(ActiveTenantBoundaryRepository::new(self.pool.clone()))
    }

    fn tenant_directory(&self) -> Arc<dyn nazo_persistence::TenantDirectoryStore> {
        Arc::new(TenantDirectoryRepository::new(self.pool.clone()))
    }

    fn security_audit_ledger(&self) -> Arc<dyn nazo_persistence::SecurityAuditLedger> {
        Arc::new(AuditLedgerRepository::new(self.pool.clone()))
    }

    fn database_health(&self) -> Arc<dyn nazo_persistence::DatabaseHealthPort> {
        Arc::new(PostgresHealthCheck::new(self.pool.clone()))
    }

    fn database_pool_metrics(&self) -> Arc<dyn nazo_persistence::DatabasePoolMetricsPort> {
        Arc::new(PostgresPoolMetrics)
    }

    fn runtime_modules(&self) -> Arc<dyn nazo_persistence::RuntimeModuleStore> {
        Arc::new(RuntimeModuleRepository::new(self.pool.clone()))
    }

    fn authorization_repository(
        &self,
        tenant_id: uuid::Uuid,
    ) -> Arc<dyn nazo_auth::AuthorizationRepositoryPort> {
        Arc::new(AuthorizationFlowRepository::new(
            self.pool.clone(),
            tenant_id,
        ))
    }

    fn device_grant_repository(
        &self,
        tenant_id: uuid::Uuid,
    ) -> Arc<dyn nazo_auth::DeviceGrantRepositoryPort> {
        Arc::new(AuthorizationFlowRepository::new(
            self.pool.clone(),
            tenant_id,
        ))
    }

    fn token_repository(
        &self,
        response_keys: nazo_persistence::TokenIssuanceResponseKeyRing,
    ) -> Arc<dyn nazo_auth::TokenRepositoryPort> {
        Arc::new(TokenIssuanceRepository::new_with_response_key_ring(
            self.pool.clone(),
            response_keys,
        ))
    }

    fn access_token_revocations(
        &self,
    ) -> Arc<dyn nazo_resource_server::AccessTokenRevocationLookup> {
        Arc::new(TokenRepository::new(self.pool.clone()))
    }

    fn admin_clients(&self) -> Arc<dyn nazo_auth::AdminClientRepositoryPort> {
        Arc::new(OAuthClientRepository::new(self.pool.clone()))
    }

    fn dynamic_registration_clients(&self) -> Arc<dyn nazo_auth::DynamicRegistrationClientStore> {
        Arc::new(OAuthClientRepository::new(self.pool.clone()))
    }

    fn logout_clients(&self) -> Arc<dyn nazo_auth::LogoutClientRepositoryPort> {
        Arc::new(OAuthClientRepository::new(self.pool.clone()))
    }

    fn authorized_applications(
        &self,
    ) -> Arc<dyn nazo_identity::ports::AuthorizedApplicationRepositoryPort> {
        Arc::new(OAuthClientRepository::new(self.pool.clone()))
    }

    fn grant_summaries(&self) -> Arc<dyn nazo_identity::ports::GrantSummaryRepositoryPort> {
        Arc::new(GrantRepository::new(self.pool.clone()))
    }

    fn admin_grants(&self) -> Arc<dyn nazo_auth::AdminGrantRepositoryPort> {
        Arc::new(GrantRepository::new(self.pool.clone()))
    }

    fn session_accounts(&self) -> Arc<dyn nazo_identity::ports::SessionAccountPort> {
        Arc::new(UserRepository::new(self.pool.clone()))
    }

    fn login_accounts(&self) -> Arc<dyn nazo_identity::ports::LoginAccountRepositoryPort> {
        Arc::new(UserRepository::new(self.pool.clone()))
    }

    fn registration_accounts(
        &self,
    ) -> Arc<dyn nazo_identity::ports::RegistrationAccountRepositoryPort> {
        Arc::new(UserRepository::new(self.pool.clone()))
    }

    fn admin_users(&self) -> Arc<dyn nazo_identity::ports::AdminUserRepositoryPort> {
        Arc::new(UserRepository::new(self.pool.clone()))
    }

    fn profiles(&self) -> Arc<dyn nazo_identity::ports::ProfileRepositoryPort> {
        Arc::new(UserRepository::new(self.pool.clone()))
    }

    fn avatars(&self) -> Arc<dyn nazo_identity::ports::AvatarRepositoryPort> {
        Arc::new(UserRepository::new(self.pool.clone()))
    }

    fn passkey_accounts(&self) -> Arc<dyn nazo_identity::ports::PasskeyAccountRepositoryPort> {
        Arc::new(UserRepository::new(self.pool.clone()))
    }

    fn passkeys(&self) -> Arc<dyn nazo_identity::ports::PasskeyRepositoryPort> {
        Arc::new(PasskeyRepository::new(self.pool.clone()))
    }

    fn ciba_accounts(&self) -> Arc<dyn nazo_persistence::CibaAccountStore> {
        Arc::new(UserRepository::new(self.pool.clone()))
    }

    fn openid4vc_subjects(&self) -> Arc<dyn nazo_persistence::Openid4vcSubjectStore> {
        Arc::new(UserRepository::new(self.pool.clone()))
    }

    fn mfa_repository(
        &self,
        keys: Option<nazo_identity::ports::MfaTotpKeyRing>,
    ) -> Arc<dyn nazo_identity::ports::MfaRepositoryPort> {
        Arc::new(MfaRepository::with_totp_key_ring(self.pool.clone(), keys))
    }

    fn remembered_mfa_devices(
        &self,
        keys: Option<nazo_identity::ports::MfaTotpKeyRing>,
    ) -> Arc<dyn nazo_identity::ports::RememberedMfaDevicePort> {
        Arc::new(MfaRepository::with_totp_key_ring(self.pool.clone(), keys))
    }

    fn federation_links(&self) -> Arc<dyn nazo_identity::ports::FederationLinkRepositoryPort> {
        Arc::new(FederationRepository::new(self.pool.clone()))
    }

    fn federation_logins(&self) -> Arc<dyn nazo_identity::ports::FederationLoginRepositoryPort> {
        Arc::new(FederationRepository::new(self.pool.clone()))
    }

    fn access_requests(&self) -> Arc<dyn nazo_identity::ports::AccessRequestRepositoryPort> {
        Arc::new(AccessRequestRepository::new(self.pool.clone()))
    }

    fn admin_access_requests(&self) -> Arc<dyn nazo_persistence::AdminAccessRequestStore> {
        Arc::new(AccessRequestRepository::new(self.pool.clone()))
    }

    fn scim_repository(
        &self,
        event_retention_seconds: u64,
    ) -> Arc<dyn nazo_identity::ports::ScimRepositoryPort> {
        Arc::new(ScimRepository::with_event_retention_seconds(
            self.pool.clone(),
            event_retention_seconds,
        ))
    }

    fn scim_credential_audit(&self) -> Arc<dyn nazo_identity::ports::ScimCredentialAuditPort> {
        Arc::new(AuditRepository::new(self.pool.clone()))
    }

    fn scim_event_store(&self) -> Arc<dyn nazo_scim_events::EventStorePort> {
        Arc::new(ScimEventRepository::new(self.pool.clone()))
    }

    fn logout_outbox(&self) -> Arc<dyn nazo_auth::BackchannelLogoutOutboxPort> {
        Arc::new(AuditRepository::new(self.pool.clone()))
    }

    fn logout_delivery_store(&self) -> Arc<dyn nazo_persistence::BackchannelLogoutDeliveryStore> {
        Arc::new(AuditRepository::new(self.pool.clone()))
    }

    fn controller_registry(&self) -> Arc<dyn nazo_persistence::ControllerRegistryPort> {
        Arc::new(ControllerRegistryRepository::new(self.pool.clone()))
    }

    fn recovery_root(&self) -> Arc<dyn nazo_persistence::RecoveryRootPort> {
        Arc::new(RecoveryRootRepository::new(self.pool.clone()))
    }

    fn mtls_trust_anchors(&self) -> Arc<dyn nazo_identity::ports::MtlsTrustAnchorStore> {
        Arc::new(MtlsTrustAnchorRepository::new(self.pool.clone()))
    }

    fn openid4vc_trust_policies(
        &self,
        _data_key: [u8; 32],
    ) -> Arc<dyn nazo_persistence::Openid4vcTrustPolicyStore> {
        Arc::new(TenantResourceRepository::new(self.pool.clone()))
    }

    fn openid4vci_store(&self, data_key: [u8; 32]) -> Arc<dyn nazo_persistence::Openid4vciStore> {
        Arc::new(Openid4vciRepository::new(self.pool.clone(), data_key))
    }

    fn openid4vci_authorization_offers(
        &self,
        data_key: [u8; 32],
    ) -> Arc<dyn nazo_openid4vci::AuthorizationOfferPort> {
        Arc::new(Openid4vciRepository::new(self.pool.clone(), data_key))
    }

    fn openid4vci_datasets(
        &self,
        data_key: [u8; 32],
    ) -> Arc<dyn nazo_persistence::Openid4vciDatasetStore> {
        Arc::new(Openid4vciDatasetRepository::new(
            self.pool.clone(),
            data_key,
        ))
    }

    fn openid4vp_store(
        &self,
        tenant_id: uuid::Uuid,
        data_key: [u8; 32],
    ) -> Arc<dyn nazo_persistence::Openid4vpStore> {
        Arc::new(Openid4vpRepository::new(
            self.pool.clone(),
            tenant_id,
            data_key,
        ))
    }
}

#[derive(Clone)]
struct PostgresOperatorPersistence {
    pool: DbPool,
    database_url: String,
}

impl OperatorPersistence for PostgresOperatorPersistence {
    fn controller_registry(&self) -> Arc<dyn nazo_persistence::ControllerRegistryPort> {
        Arc::new(ControllerRegistryRepository::new(self.pool.clone()))
    }

    fn recovery_invalidations(&self) -> Arc<dyn nazo_persistence::RecoveryInvalidationStore> {
        Arc::new(TokenRepository::new(self.pool.clone()))
    }

    fn admin_clients(&self) -> Arc<dyn nazo_auth::AdminClientRepositoryPort> {
        Arc::new(OAuthClientRepository::new(self.pool.clone()))
    }

    fn tenant_resource_executor(
        &self,
        tenant: nazo_identity::TenantContext,
        data_encryption_key: Option<[u8; 32]>,
        preparation: Arc<dyn nazo_persistence::tenant_resources::TenantResourcePreparation>,
    ) -> Arc<dyn nazo_persistence::tenant_resources::TenantResourceExecutorPort> {
        Arc::new(PostgresTenantResourceExecutor::new(
            TenantResourceRepository::new(self.pool.clone()),
            tenant,
            data_encryption_key,
            preparation,
        ))
    }

    fn tenant_directory_executor(
        &self,
    ) -> Arc<dyn nazo_persistence::directory_control::TenantDirectoryControlPort> {
        Arc::new(TenantDirectoryControlRepository::new(self.pool.clone()))
    }

    fn run_migrations(&self) -> OperatorBackendFuture<'_, bool> {
        Box::pin(async move {
            let runtime_role = std::env::var(MIGRATION_RUNTIME_ROLE_ENV)
                .map_err(|_| anyhow::anyhow!("{MIGRATION_RUNTIME_ROLE_ENV} is required"))?;
            let applied = nazo_postgres::run_pending_migrations(&self.database_url).await?;
            nazo_postgres::configure_runtime_role(&self.database_url, runtime_role.trim()).await?;
            nazo_postgres::cleanup_expired_security_state(&self.database_url).await?;
            Ok(applied)
        })
    }

    fn initialize_tenant_directory(
        &self,
        binding: nazo_identity::TenantDirectoryBinding,
    ) -> OperatorBackendFuture<'_, bool> {
        Box::pin(async move {
            Ok(TenantDirectoryRepository::new(self.pool.clone())
                .initialize(binding)
                .await?)
        })
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct PostgresLauncher;

impl PersistenceLauncher for PostgresLauncher {
    fn default_database_url(&self) -> &'static str {
        DEFAULT_DATABASE_URL
    }

    fn server_bindings<'a>(
        &'a self,
        source: &'a ConfigSource,
    ) -> LauncherFuture<'a, ServerPersistenceBindings> {
        Box::pin(async move {
            let database_url = config::database_url(source)?;
            let max_connections = config::database_max_connections(source)?;
            let pool = nazo_postgres::create_pool(database_url, max_connections)?;
            Ok(ServerPersistenceBindings::new(Arc::new(
                PostgresProvider::new(pool),
            )))
        })
    }

    fn operator_persistence<'a>(
        &'a self,
        source: &'a ConfigSource,
    ) -> LauncherFuture<'a, Arc<dyn OperatorPersistence>> {
        Box::pin(async move {
            let database_url = config::database_url(source)?;
            let pool = nazo_postgres::create_pool(
                database_url.clone(),
                OPERATOR_DATABASE_MAX_CONNECTIONS,
            )?;
            Ok(Arc::new(PostgresOperatorPersistence { pool, database_url })
                as Arc<dyn OperatorPersistence>)
        })
    }

    fn audit_exporter<'a>(
        &'a self,
        database_url: &'a str,
        database_max_connections: usize,
    ) -> LauncherFuture<'a, Arc<dyn nazo_persistence::SecurityAuditExporter>> {
        Box::pin(async move {
            let pool = nazo_postgres::create_pool(database_url, database_max_connections)?;
            Ok(Arc::new(AuditLedgerRepository::new(pool))
                as Arc<dyn nazo_persistence::SecurityAuditExporter>)
        })
    }

    fn admin_provisioner<'a>(
        &'a self,
        source: &'a ConfigSource,
    ) -> LauncherFuture<'a, Arc<dyn nazo_persistence::AdminProvisionStore>> {
        Box::pin(async move {
            let database_url = config::database_url(source)?;
            let pool =
                nazo_postgres::create_pool(database_url, ADMIN_PROVISION_DATABASE_MAX_CONNECTIONS)?;
            Ok(Arc::new(AdminProvisionRepository::new(pool))
                as Arc<dyn nazo_persistence::AdminProvisionStore>)
        })
    }
}
