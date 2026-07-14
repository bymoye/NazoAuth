//! 应用启动入口。
// 负责组装配置、外部连接、共享状态和 Actix HTTP server。

mod authentication_services;
mod cors;
mod federation_services;
mod observability;
mod passkey_services;
mod profile_services;
mod registration_services;
pub(crate) mod routes;
pub(crate) use authentication_services::{
    LocalAuthenticationService, LoginPasswordVerifier, TracingAuthenticationAudit,
};
pub(crate) use federation_services::{
    FederationBootstrapPasswordHasher, LocalFederationService, TracingFederationAudit,
};
pub(crate) use passkey_services::{
    LocalPasskeyService, PASSKEY_CEREMONY_TTL_SECONDS, TracingPasskeyAudit,
};
pub(crate) use profile_services::{
    AccountProfileService, AvatarProfileService, ClientAccessProfileService,
    FederationProfileService,
};
pub(crate) use registration_services::{LocalRegistrationService, RegistrationSecretHasher};

use std::{net::SocketAddr, sync::Arc, time::Duration};

use actix_web::{App, HttpServer, dev::Service, middleware::from_fn, web};

use crate::adapters::email::{SmtpVerificationEmailDelivery, email_delivery_configured};
use crate::adapters::security::{
    configure_password_hash_limits, default_password_hash_max_concurrency,
    default_password_hash_queue_timeout_ms, dummy_password_hash, initialize_dummy_password_hash,
};
use crate::config::{ConfigSource, database_max_connections, database_url};
#[cfg(test)]
use crate::domain::DynamicRegistrationHandles;
use crate::domain::tenancy::{DEFAULT_TENANT_ID, default_tenant_context};
#[cfg(not(test))]
use crate::domain::{
    BackchannelLogoutWorker, ServerScimBootstrapPasswordProvider, ServerScimCursorProtector,
    ServerScimRequestAuthorizer, ServerTokenManagementOperations,
    ServerTokenManagementRequestGuard, ServerUserinfoOperations, dynamic_registration_endpoint,
    spawn_backchannel_logout_delivery_worker,
};
use crate::domain::{
    DynamicRegistrationConfig, MFA_REMEMBERED_COOKIE_NAME, MFA_REMEMBERED_TTL_SECONDS,
    MetadataConfig, OidcLogoutConfig, OidcLogoutHandles, PasskeyOperationsProvider,
    ResourceServerConfig, ServerAuthenticationRateLimit, ServerAuthorizationDecisionOperations,
    ServerLocalRegistrationOperations, ServerMetadataSnapshotSource, ServerMfaProfileOperations,
    ServerMfaSecretHasher, ServerPasswordLoginOperations, ServerProfileAccountOperations,
    ServerSessionManagementOperations, UserinfoConfig, UserinfoHandles,
};
use crate::domain::{
    ServerFapiHttpMessageSignatures, ServerFapiMtlsResolver, ServerFapiResourceAuthorizer,
};
use crate::http::admin::access_requests::AdminAccessRequestConfig;
use crate::http::admin::clients::{
    AdminClientConfig, ServerAdminClientCrypto, ServerAdminClientService,
    ServerSectorIdentifierResolver, admin_client_policy,
};
use crate::http::admin::federation::AdminFederationConfig;
use crate::http::auth::csrf::CsrfHttpConfig;
use crate::http::auth::federation::{
    FEDERATION_STATE_TTL_SECONDS, FederationHttpConfig, SAML_REPLAY_TTL_SECONDS,
};
use crate::http::authorization::{
    AuthorizationEndpoint, AuthorizationHttpConfig, ServerAuthorizationService,
};
use crate::http::client_ip::ClientIpConfig;
use crate::http::rate_limit::{AuthRequestLimiter, TokenManagementRequestLimiter};
#[cfg(test)]
use crate::http::scim::{ScimConfig, ScimEndpoint, ScimRuntimeAdmission};
use crate::http::sessions::{AdminSessionHandles, SessionHttpConfig, SessionProfileHandles};
#[cfg(not(test))]
use crate::http::token::ServerTokenManagementRequestFactsExtractor;
use crate::http::token::ciba::{CibaHttpConfig, CibaTokenHandles, ServerCibaService};
use crate::http::token::device::{DeviceDecisionHandles, ServerDeviceGrantService};
use crate::http::token::device_config::DeviceHttpConfig;
use crate::http::token::dispatch::TokenEndpointHandles;
use crate::http::token::issue::TokenIssuanceConfig;
use crate::runtime_modules::{RuntimeModules, ServerRuntimeModuleRegistry};
use crate::settings::Settings;
#[cfg(test)]
use actix_web::http::header;
use nazo_http_actix::{
    AuthorizationDecisionEndpoint, LocalRegistrationEndpoint, MfaProfileConfig, MfaProfileEndpoint,
    OidcLogoutConfig as OidcLogoutHttpConfig, OidcLogoutEndpoint, PasskeyLoginConfig,
    PasskeyLoginEndpoint, PasskeyProfileConfig, PasskeyProfileEndpoint, PasswordLoginConfig,
    PasswordLoginEndpoint, ProfileAccountEndpoint, RuntimeModuleAdminEndpoint, SessionCookieConfig,
    SessionLogoutEndpoint, SessionManagementConfig, SessionManagementEndpoint, security_headers,
};
use nazo_postgres::create_pool;
use tracing::Instrument;

pub async fn run() -> anyhow::Result<()> {
    let config = ConfigSource::load()?;
    let _observability = observability::init(&config)?;
    let perf_metrics_enabled = config.bool("PERF_METRICS_ENABLED", false)?;
    let password_hash_max_concurrency = config.parse::<usize>(
        "PASSWORD_HASH_MAX_CONCURRENCY",
        default_password_hash_max_concurrency(),
    )?;
    let password_hash_queue_timeout_ms = config.parse::<u64>(
        "PASSWORD_HASH_QUEUE_TIMEOUT_MS",
        default_password_hash_queue_timeout_ms(),
    )?;
    configure_password_hash_limits(
        password_hash_max_concurrency,
        password_hash_queue_timeout_ms,
    )?;
    initialize_dummy_password_hash()?;

    // 配置只在启动阶段读取；运行期只向 handler 注入其所需的 focused handles。
    let database_url = database_url(&config);
    let valkey_url = config.string("VALKEY_URL", "redis://127.0.0.1:6379/0");
    let valkey_command_timeout_ms = config.parse::<u64>("VALKEY_COMMAND_TIMEOUT_MS", 1_000)?;
    if valkey_command_timeout_ms == 0 {
        anyhow::bail!("VALKEY_COMMAND_TIMEOUT_MS must be greater than zero");
    }
    let valkey_command_timeout = Duration::from_millis(valkey_command_timeout_ms);

    // 数据库和 Valkey 客户端在 server factory 外创建，避免每个 worker 重复初始化。
    let diesel_db = create_pool(database_url.clone(), database_max_connections(&config)?)?;
    #[cfg(not(test))]
    let valkey =
        nazo_valkey::ValkeyConnection::connect(&valkey_url, valkey_command_timeout).await?;
    #[cfg(test)]
    let valkey = nazo_valkey::test_support::connect(&valkey_url, valkey_command_timeout).await?;

    let settings = Arc::new(Settings::from_config(&config)?);
    let runtime_modules =
        web::Data::new(RuntimeModules::initialize(diesel_db.clone(), &settings).await?);
    RuntimeModules::spawn_reconciler(runtime_modules.clone());
    tokio::fs::create_dir_all(&settings.storage.avatar_storage_dir).await?;
    let keyset = nazo_key_management::KeyManager::load_or_create(settings.key_settings()).await?;
    tokio::spawn(keyset.clone().run_lifecycle());
    let metadata_config = MetadataConfig::from(settings.as_ref());
    let metadata_handles = web::Data::new(nazo_http_actix::MetadataHandles::new(
        metadata_config.endpoint_config(),
        Arc::new(ServerMetadataSnapshotSource::new(
            keyset.clone(),
            runtime_modules.registry.clone(),
        )),
    ));
    #[cfg(not(test))]
    let resource_replay_connection = valkey.clone();
    #[cfg(test)]
    let resource_replay_connection =
        nazo_valkey::ValkeyConnection::from_existing_client(valkey.clone());
    let resource_server_config = ResourceServerConfig::from(settings.as_ref());
    let resource_server_http_data = {
        let replay = nazo_valkey::ReplayStore::new(&resource_replay_connection);
        let authorizer = Arc::new(ServerFapiResourceAuthorizer::new(
            resource_server_config.clone(),
            keyset.clone(),
            nazo_postgres::TokenRepository::new(diesel_db.clone()),
            replay.clone(),
        ));
        let mtls = Arc::new(ServerFapiMtlsResolver::new(
            resource_server_config.trusted_proxy_cidrs.clone(),
        ));
        let signatures = Arc::new(ServerFapiHttpMessageSignatures::new(
            nazo_postgres::OAuthClientRepository::new(diesel_db.clone()),
            replay,
            keyset.clone(),
            runtime_modules.registry.clone(),
            resource_server_config.fapi_http_signature_max_age_seconds,
        ));
        web::Data::new(nazo_http_actix::FapiResourceEndpoint::new(
            resource_server_config.issuer.clone(),
            resource_server_config.mtls_endpoint_base_url.clone(),
            resource_server_config.fapi_http_signature_max_age_seconds,
            authorizer,
            mtls,
            signatures,
        ))
    };
    #[cfg(not(test))]
    let dynamic_registration_rate_limit_connection = valkey.clone();
    #[cfg(test)]
    let dynamic_registration_rate_limit_connection =
        nazo_valkey::ValkeyConnection::from_existing_client(valkey.clone());
    let dynamic_registration_config = DynamicRegistrationConfig::from(settings.as_ref());
    #[cfg(not(test))]
    let dynamic_registration_handles = web::Data::new(dynamic_registration_endpoint(
        dynamic_registration_config,
        nazo_postgres::OAuthClientRepository::new(diesel_db.clone()),
        nazo_valkey::RateLimitStore::new(&dynamic_registration_rate_limit_connection),
        keyset.clone(),
        runtime_modules.registry.clone(),
    ));
    #[cfg(test)]
    let dynamic_registration_handles = web::Data::new(DynamicRegistrationHandles {
        config: dynamic_registration_config,
        clients: nazo_postgres::OAuthClientRepository::new(diesel_db.clone()),
        rate_limits: nazo_valkey::RateLimitStore::new(&dynamic_registration_rate_limit_connection),
        keyset: keyset.clone(),
        enabled: settings.modules.enable_dynamic_client_registration,
    });
    let admin_client_config = web::Data::new(AdminClientConfig::from_settings(&settings));
    let admin_client_service = web::Data::new(ServerAdminClientService::new(
        nazo_postgres::OAuthClientRepository::new(diesel_db.clone()),
        ServerSectorIdentifierResolver,
        ServerAdminClientCrypto::new(keyset.clone()),
        admin_client_policy(&settings),
    ));
    let scim_endpoint = &settings.endpoint;
    let scim_protocol = &settings.protocol;
    let scim_storage = &settings.storage;
    let scim_service = nazo_identity::scim::ScimService::new(
        Arc::new(nazo_postgres::ScimRepository::new(diesel_db.clone())),
        Arc::new(nazo_postgres::AuditRepository::new(diesel_db.clone())),
    );
    let scim_client_ip = ClientIpConfig::new(
        &scim_endpoint.trusted_proxy_cidrs,
        scim_endpoint.client_ip_header_mode,
    );
    #[cfg(test)]
    let scim_endpoint = web::Data::new(ScimEndpoint::new(
        scim_service,
        ScimConfig::new(
            scim_storage.scim_bearer_token.as_deref(),
            &scim_protocol.client_secret_pepper,
            scim_client_ip,
        )?,
        ScimRuntimeAdmission::new(runtime_modules.registry.clone()),
    ));
    #[cfg(not(test))]
    let scim_endpoint = web::Data::new(nazo_http_actix::ScimEndpoint::new(
        scim_service.clone(),
        Arc::new(ServerScimRequestAuthorizer::new(
            scim_service,
            scim_storage.scim_bearer_token.as_deref(),
            scim_client_ip,
            runtime_modules.registry.clone(),
        )),
        Arc::new(ServerScimCursorProtector::new(
            &scim_protocol.client_secret_pepper,
        )?),
        Arc::new(ServerScimBootstrapPasswordProvider),
    ));
    #[cfg(not(test))]
    let valkey_connection = valkey.clone();
    #[cfg(test)]
    let valkey_connection = nazo_valkey::ValkeyConnection::from_existing_client(valkey.clone());
    let authorization_service = web::Data::new(ServerAuthorizationService::new(
        nazo_postgres::AuthorizationFlowRepository::new(diesel_db.clone(), DEFAULT_TENANT_ID),
        nazo_valkey::AuthorizationStateAdapter::new(&valkey_connection),
        keyset.clone(),
    ));
    let token_service = web::Data::new(crate::http::token::ServerTokenService::new(
        nazo_postgres::TokenIssuanceRepository::new(diesel_db.clone()),
        nazo_valkey::TokenIssuanceStateAdapter::new(&valkey_connection),
        keyset.clone(),
    ));
    let ciba_service = web::Data::new(ServerCibaService::new(nazo_valkey::CibaStore::new(
        &valkey_connection,
    )));
    let ciba_users = web::Data::new(nazo_postgres::UserRepository::new(diesel_db.clone()));
    let ciba_config = web::Data::new(CibaHttpConfig::from(settings.as_ref()));
    let token_issuance_config = web::Data::new(TokenIssuanceConfig::from(settings.as_ref()));
    let device_service = web::Data::new(ServerDeviceGrantService::new(
        nazo_valkey::DeviceStore::new(&valkey_connection),
    ));
    let device_grants = web::Data::new(nazo_postgres::AuthorizationFlowRepository::new(
        diesel_db.clone(),
        DEFAULT_TENANT_ID,
    ));
    let device_config = web::Data::new(DeviceHttpConfig::from(settings.as_ref()));
    let userinfo_handles = UserinfoHandles::new(
        nazo_valkey::ReplayStore::new(&valkey_connection),
        keyset.clone(),
        UserinfoConfig::from(settings.as_ref()),
    );
    #[cfg(test)]
    let userinfo_handles = web::Data::new(userinfo_handles);
    #[cfg(not(test))]
    let userinfo_endpoint = web::Data::new(nazo_http_actix::UserinfoEndpoint::new(Arc::new(
        ServerUserinfoOperations::new(token_service.clone().into_inner(), userinfo_handles),
    )));
    let authorization_config = web::Data::new(AuthorizationHttpConfig::from(settings.as_ref()));
    #[cfg(not(test))]
    let token_management_endpoint = web::Data::new(nazo_http_actix::TokenManagementEndpoint::new(
        Arc::new(ServerTokenManagementRequestFactsExtractor::new(
            authorization_config.clone().into_inner(),
        )),
        Arc::new(ServerTokenManagementRequestGuard::new(
            token_service.clone().into_inner(),
            authorization_config.clone().into_inner(),
        )),
        Arc::new(ServerTokenManagementOperations::new(
            token_service.clone().into_inner(),
            authorization_service.clone().into_inner(),
            authorization_config.clone().into_inner(),
        )),
    ));
    let authorization_runtime: web::Data<ServerRuntimeModuleRegistry> =
        web::Data::from(runtime_modules.registry.clone());
    let token_endpoint_handles = web::Data::new(TokenEndpointHandles::new(
        token_service.clone(),
        authorization_service.clone(),
        CibaTokenHandles::new(
            ciba_service.clone(),
            ciba_users.clone(),
            ciba_config.clone(),
        ),
        token_issuance_config.clone(),
        device_service.clone(),
        authorization_runtime.clone(),
    ));

    let session = &settings.session;
    let session_http_config = SessionHttpConfig::new(
        &session.session_cookie_name,
        &session.csrf_cookie_name,
        session.cookie_secure,
    );
    let session_cookie_config = SessionCookieConfig::new(
        &session.session_cookie_name,
        &session.csrf_cookie_name,
        session.cookie_secure,
    );
    let identity_session_service = nazo_identity::SessionService::new(
        Arc::new(nazo_valkey::SessionStore::new(&valkey_connection)),
        Arc::new(nazo_postgres::UserRepository::new(diesel_db.clone())),
        nazo_identity::TenantId::new(DEFAULT_TENANT_ID).expect("default tenant ID is valid"),
    );
    let profile_logout_endpoint = web::Data::new(SessionLogoutEndpoint::new(
        identity_session_service.clone(),
        session_cookie_config.clone(),
        |error| tracing::warn!(%error, "failed to delete session during logout"),
    ));
    let runtime_module_admin_endpoint = web::Data::new(RuntimeModuleAdminEndpoint::new(
        identity_session_service.clone(),
        session_cookie_config.clone(),
        runtime_modules.administration(),
    ));
    let admin_sessions = web::Data::new(AdminSessionHandles::new(
        nazo_valkey::SessionStore::new(&valkey_connection),
        nazo_postgres::UserRepository::new(diesel_db.clone()),
        session_http_config.clone(),
    ));
    let authorization_endpoint = web::Data::new(AuthorizationEndpoint::new(
        authorization_service.clone().into_inner(),
        authorization_config.clone().into_inner(),
        admin_sessions.clone().into_inner(),
        runtime_modules.registry.clone(),
    ));
    let admin_federation = web::Data::new(AdminFederationConfig::from_settings(&settings));
    #[cfg(not(test))]
    let session_profiles = web::Data::new(SessionProfileHandles::new(
        nazo_valkey::SessionStore::new(&valkey_connection),
        nazo_postgres::UserRepository::new(diesel_db.clone()),
        session_http_config,
    ));
    #[cfg(test)]
    let session_profiles = web::Data::new(SessionProfileHandles::new(
        nazo_valkey::SessionStore::new(&valkey_connection),
        nazo_postgres::UserRepository::new(diesel_db.clone()),
        session_http_config,
    ));
    let session_management_endpoint = web::Data::new(SessionManagementEndpoint::new(
        Arc::new(ServerSessionManagementOperations::new(
            session_profiles.get_ref().clone(),
            runtime_modules.registry.clone(),
        )),
        SessionManagementConfig::new(
            settings.endpoint.issuer.as_str(),
            session.session_cookie_name.as_str(),
        ),
    ));
    let device_decision_handles = web::Data::new(DeviceDecisionHandles::new(
        authorization_service.clone(),
        device_service.clone(),
        device_grants.clone(),
        session_profiles.clone(),
        device_config.clone(),
        authorization_runtime.clone(),
    ));
    let logout_deliveries = nazo_postgres::AuditRepository::new(diesel_db.clone());
    #[cfg(not(test))]
    let oidc_logout_operations = OidcLogoutHandles::new(
        session_profiles.get_ref().clone(),
        nazo_postgres::OAuthClientRepository::new(diesel_db.clone()),
        logout_deliveries.clone(),
        keyset.clone(),
        OidcLogoutConfig::from(settings.as_ref()),
        runtime_modules.registry.clone(),
    );
    #[cfg(test)]
    let oidc_logout_operations = OidcLogoutHandles::new(
        session_profiles.get_ref().clone(),
        nazo_postgres::OAuthClientRepository::new(diesel_db.clone()),
        logout_deliveries.clone(),
        keyset.clone(),
        OidcLogoutConfig::from(settings.as_ref()),
        settings.modules.enable_frontchannel_logout,
    );
    let oidc_logout = web::Data::new(OidcLogoutEndpoint::new(
        Arc::new(oidc_logout_operations),
        OidcLogoutHttpConfig::new(
            session.session_cookie_name.as_str(),
            session.csrf_cookie_name.as_str(),
            session.cookie_secure,
        ),
    ));
    let csrf_http_config = web::Data::new(CsrfHttpConfig::new(
        session.csrf_cookie_name.as_str(),
        session.session_ttl_seconds,
        session.cookie_secure,
    ));
    let account_profile_service = AccountProfileService::new(
        nazo_postgres::UserRepository::new(diesel_db.clone()),
        nazo_postgres::GrantRepository::new(diesel_db.clone()),
        nazo_postgres::OAuthClientRepository::new(diesel_db.clone()),
    );
    let profile_account_endpoint = web::Data::new(ProfileAccountEndpoint::new(
        Arc::new(ServerProfileAccountOperations::new(
            identity_session_service.clone(),
            account_profile_service.clone(),
        )),
        session_cookie_config.clone(),
    ));
    let account_profiles = web::Data::new(account_profile_service);
    let avatar_profiles = web::Data::new(AvatarProfileService::new(
        nazo_postgres::UserRepository::new(diesel_db.clone()),
        nazo_postgres::GrantRepository::new(diesel_db.clone()),
        crate::adapters::avatar_files::LocalAvatarStorage::new(
            settings.storage.avatar_storage_dir.clone(),
        ),
        settings.storage.avatar_max_bytes,
    ));
    let profile_delivery_store = nazo_valkey::DeliveryStore::new(&valkey_connection);
    let profile_access_requests = web::Data::new(ClientAccessProfileService::new(
        nazo_postgres::AccessRequestRepository::new(diesel_db.clone()),
        profile_delivery_store,
        &settings.protocol.client_secret_pepper,
        &settings.endpoint.frontend_base_url,
    ));
    let profile_federation = web::Data::new(FederationProfileService::new(
        nazo_postgres::FederationRepository::new(diesel_db.clone()),
    ));
    let admin_users: web::Data<dyn nazo_identity::ports::AdminUserRepositoryPort> = web::Data::from(
        Arc::new(nazo_postgres::UserRepository::new(diesel_db.clone()))
            as Arc<dyn nazo_identity::ports::AdminUserRepositoryPort>,
    );
    let admin_grants: web::Data<dyn nazo_auth::AdminGrantRepositoryPort> = web::Data::from(
        Arc::new(nazo_postgres::GrantRepository::new(diesel_db.clone()))
            as Arc<dyn nazo_auth::AdminGrantRepositoryPort>,
    );
    let admin_access_requests = web::Data::new(nazo_postgres::AccessRequestRepository::new(
        diesel_db.clone(),
    ));
    let admin_access_delivery = web::Data::new(nazo_valkey::DeliveryStore::new(&valkey_connection));
    let protocol = &settings.protocol;
    let storage = &settings.storage;
    let admin_access_request_config = web::Data::new(AdminAccessRequestConfig::new(
        &protocol.client_secret_pepper,
        storage.client_delivery_ttl_seconds,
    ));
    let endpoint = &settings.endpoint;
    let client_ip_config = web::Data::new(ClientIpConfig::new(
        &endpoint.trusted_proxy_cidrs,
        endpoint.client_ip_header_mode,
    ));
    let authorization_decision_endpoint = web::Data::new(AuthorizationDecisionEndpoint::new(
        Arc::new(ServerAuthorizationDecisionOperations::new(
            authorization_service.clone().into_inner(),
            identity_session_service.clone(),
            authorization_config.clone().into_inner(),
            runtime_modules.registry.clone(),
        )),
        session_cookie_config,
        client_ip_config.get_ref().clone(),
    ));
    let identity = &settings.identity;
    let auth_request_limiter = web::Data::new(AuthRequestLimiter::new(
        nazo_valkey::RateLimitStore::new(&valkey_connection),
        identity.rate_limit.window_seconds,
        identity.rate_limit.auth_max_requests,
        client_ip_config.get_ref().clone(),
    ));
    let token_management_limiter = web::Data::new(TokenManagementRequestLimiter::new(
        nazo_valkey::RateLimitStore::new(&valkey_connection),
        identity.rate_limit.window_seconds,
        identity.rate_limit.token_management_max_requests,
        client_ip_config.get_ref().clone(),
    ));
    let email_delivery = SmtpVerificationEmailDelivery::from_delivery(&identity.email.delivery);
    let registration = LocalRegistrationService::new(
        nazo_postgres::UserRepository::new(diesel_db.clone()),
        nazo_valkey::AuthenticationStore::new(&valkey_connection),
        RegistrationSecretHasher,
        email_delivery,
        default_tenant_context()
            .as_identity_context()
            .expect("default tenant identifiers are valid"),
        nazo_identity::RegistrationServiceConfig {
            delivery_enabled: email_delivery_configured(&settings),
            send_peer_cooldown_seconds: identity.email.send_peer_cooldown_seconds,
            send_cooldown_seconds: identity.email.send_cooldown_seconds,
            code_ttl_seconds: identity.email.code_ttl_seconds,
        },
    );
    let authentication_rate_limit = Arc::new(ServerAuthenticationRateLimit::new(
        nazo_valkey::RateLimitStore::new(&valkey_connection),
        identity.rate_limit.window_seconds,
        identity.rate_limit.auth_max_requests,
    ));
    let mfa_profiles = web::Data::new(MfaProfileEndpoint::new(
        Arc::new(ServerMfaProfileOperations::new(
            nazo_identity::MfaService::new(
                Arc::new(nazo_postgres::MfaRepository::new(diesel_db.clone())),
                Arc::new(ServerMfaSecretHasher),
            ),
            identity_session_service.clone(),
            authentication_rate_limit.clone(),
            settings.endpoint.issuer.as_str(),
            session.session_ttl_seconds,
            MFA_REMEMBERED_TTL_SECONDS,
        )),
        client_ip_config.get_ref().clone(),
        MfaProfileConfig::new(
            session.session_cookie_name.as_str(),
            session.csrf_cookie_name.as_str(),
            MFA_REMEMBERED_COOKIE_NAME,
            session.session_ttl_seconds,
            MFA_REMEMBERED_TTL_SECONDS,
            session.cookie_secure,
        ),
    ));
    let local_registration_endpoint = web::Data::new(LocalRegistrationEndpoint::new(
        Arc::new(ServerLocalRegistrationOperations::new(registration)),
        authentication_rate_limit.clone(),
        client_ip_config.get_ref().clone(),
        identity.email_code_dev_response_enabled,
    ));
    let authentication = LocalAuthenticationService::new(
        nazo_postgres::UserRepository::new(diesel_db.clone()),
        nazo_valkey::RateLimitStore::new(&valkey_connection),
        LoginPasswordVerifier,
        nazo_postgres::MfaRepository::new(diesel_db.clone()),
        nazo_valkey::SessionStore::new(&valkey_connection),
        TracingAuthenticationAudit,
        nazo_identity::AuthenticationServiceConfig {
            tenant_id: nazo_identity::TenantId::new(DEFAULT_TENANT_ID)
                .expect("default tenant ID is valid"),
            dummy_password_hash: nazo_identity::PasswordHash::new(dummy_password_hash()?)?,
            failure_window_seconds: identity.rate_limit.login_failure_window_seconds,
            failure_email_max_attempts: identity.rate_limit.login_failure_email_max_attempts,
            failure_ip_email_max_attempts: identity.rate_limit.login_failure_ip_email_max_attempts,
            session_ttl_seconds: session.session_ttl_seconds,
        },
    );
    let password_login_endpoint = web::Data::new(PasswordLoginEndpoint::new(
        Arc::new(ServerPasswordLoginOperations::new(authentication)),
        authentication_rate_limit.clone(),
        client_ip_config.get_ref().clone(),
        PasswordLoginConfig::new(
            settings.endpoint.issuer.as_str(),
            settings.endpoint.frontend_base_url.as_str(),
            session.session_cookie_name.as_str(),
            session.csrf_cookie_name.as_str(),
            MFA_REMEMBERED_COOKIE_NAME,
            session.session_ttl_seconds,
            session.cookie_secure,
        ),
    ));
    let passkey = &identity.passkey;
    let passkey_operations = Arc::new(PasskeyOperationsProvider::new(
        LocalPasskeyService::new(
            nazo_postgres::UserRepository::new(diesel_db.clone()),
            nazo_postgres::PasskeyRepository::new(diesel_db.clone()),
            nazo_valkey::AuthenticationStore::new(&valkey_connection),
            nazo_postgres::MfaRepository::new(diesel_db.clone()),
            nazo_valkey::SessionStore::new(&valkey_connection),
            TracingPasskeyAudit,
            nazo_identity::PasskeyServiceConfig {
                tenant_id: nazo_identity::TenantId::new(DEFAULT_TENANT_ID)
                    .expect("default tenant ID is valid"),
                rp_id: passkey.rp_id.to_owned(),
                rp_name: passkey.rp_name.to_owned(),
                origin: passkey.origin.to_owned(),
                require_user_verification: passkey.require_user_verification,
                require_user_handle: passkey.require_user_handle,
                strict_base64: passkey.strict_base64,
                ceremony_ttl_seconds: PASSKEY_CEREMONY_TTL_SECONDS,
                session_ttl_seconds: session.session_ttl_seconds,
            },
        ),
        identity_session_service,
    ));
    let passkey_login_endpoint = web::Data::new(PasskeyLoginEndpoint::new(
        passkey_operations.clone(),
        authentication_rate_limit,
        client_ip_config.get_ref().clone(),
        PasskeyLoginConfig::new(
            session.session_cookie_name.as_str(),
            session.csrf_cookie_name.as_str(),
            MFA_REMEMBERED_COOKIE_NAME,
            session.session_ttl_seconds,
            session.cookie_secure,
        ),
    ));
    let passkey_profile_endpoint = web::Data::new(PasskeyProfileEndpoint::new(
        passkey_operations,
        PasskeyProfileConfig::new(
            session.session_cookie_name.as_str(),
            session.csrf_cookie_name.as_str(),
            session.cookie_secure,
        ),
    ));
    let federation = web::Data::new(LocalFederationService::new(
        nazo_postgres::FederationRepository::new(diesel_db.clone()),
        nazo_valkey::AuthenticationStore::new(&valkey_connection),
        FederationBootstrapPasswordHasher,
        nazo_valkey::SessionStore::new(&valkey_connection),
        TracingFederationAudit,
        nazo_identity::FederationServiceConfig {
            tenant: default_tenant_context()
                .as_identity_context()
                .expect("default tenant identifiers are valid"),
            state_ttl_seconds: FEDERATION_STATE_TTL_SECONDS,
            saml_replay_ttl_seconds: SAML_REPLAY_TTL_SECONDS,
            session_ttl_seconds: session.session_ttl_seconds,
        },
    ));
    let federation_http_config = web::Data::new(FederationHttpConfig::new(
        identity.federation.providers.clone(),
        identity.federation.saml_gateway.clone(),
        session.session_cookie_name.as_str(),
        session.csrf_cookie_name.as_str(),
        session.session_ttl_seconds,
        session.cookie_secure,
    ));
    #[cfg(not(test))]
    spawn_backchannel_logout_delivery_worker(BackchannelLogoutWorker::new(logout_deliveries)?);

    let bind = config.string("BIND", "0.0.0.0:8000");
    let addr: SocketAddr = bind.parse()?;
    tracing::info!("nazo-oauth-server(actix-web) listening on {addr}");

    HttpServer::new(move || {
        let app = App::new()
            .wrap_fn(|req, service| {
                let method = req.method().clone();
                let path = req.path().to_owned();
                let started = std::time::Instant::now();
                let span = tracing::info_span!(
                    "http.request",
                    "otel.kind" = "server",
                    "http.request.method" = %method,
                    "url.path" = %path
                );
                let future = service.call(req);
                async move {
                    let result = future.await;
                    if let Ok(response) = &result {
                        let status = response.status().as_u16();
                        let elapsed_ms = started.elapsed().as_secs_f64() * 1_000.0;
                        tracing::info!(
                            monotonic_counter.http_server_requests = 1_u64,
                            histogram.http_server_request_duration_ms = elapsed_ms,
                            "http.request.method" = %method,
                            "http.response.status_code" = status as i64,
                            "url.path" = %path,
                            "HTTP request completed"
                        );
                    }
                    result
                }
                .instrument(span)
            })
            .wrap(from_fn(security_headers))
            .app_data(runtime_module_admin_endpoint.clone())
            .app_data(authorization_decision_endpoint.clone())
            .app_data(authorization_endpoint.clone())
            .app_data(authorization_service.clone())
            .app_data(token_service.clone());
        #[cfg(not(test))]
        let app = app
            .app_data(token_management_endpoint.clone())
            .app_data(userinfo_endpoint.clone());
        let app = app
            .app_data(token_endpoint_handles.clone())
            .app_data(ciba_service.clone())
            .app_data(ciba_users.clone())
            .app_data(ciba_config.clone())
            .app_data(token_issuance_config.clone())
            .app_data(device_service.clone())
            .app_data(device_grants.clone())
            .app_data(device_decision_handles.clone())
            .app_data(device_config.clone());
        #[cfg(test)]
        let app = app.app_data(userinfo_handles.clone());
        let app = app
            .app_data(authorization_config.clone())
            .app_data(authorization_runtime.clone())
            .app_data(metadata_handles.clone())
            .app_data(admin_sessions.clone())
            .app_data(admin_federation.clone())
            .app_data(session_profiles.clone())
            .app_data(session_management_endpoint.clone())
            .app_data(profile_logout_endpoint.clone())
            .app_data(profile_account_endpoint.clone())
            .app_data(oidc_logout.clone())
            .app_data(csrf_http_config.clone())
            .app_data(mfa_profiles.clone())
            .app_data(account_profiles.clone())
            .app_data(avatar_profiles.clone())
            .app_data(profile_access_requests.clone())
            .app_data(profile_federation.clone())
            .app_data(resource_server_http_data.clone())
            .app_data(admin_users.clone())
            .app_data(admin_grants.clone())
            .app_data(admin_access_requests.clone())
            .app_data(admin_access_delivery.clone())
            .app_data(admin_access_request_config.clone())
            .app_data(admin_client_service.clone())
            .app_data(admin_client_config.clone())
            .app_data(client_ip_config.clone())
            .app_data(auth_request_limiter.clone())
            .app_data(token_management_limiter.clone())
            .app_data(local_registration_endpoint.clone())
            .app_data(password_login_endpoint.clone())
            .app_data(passkey_login_endpoint.clone())
            .app_data(passkey_profile_endpoint.clone())
            .app_data(federation.clone())
            .app_data(federation_http_config.clone())
            .app_data(dynamic_registration_handles.clone())
            .app_data(scim_endpoint.clone());
        app.configure(|cfg| routes::configure(cfg, &settings, perf_metrics_enabled))
    })
    .bind(addr)?
    .run()
    .await?;
    Ok(())
}

#[cfg(test)]
#[path = "../../tests/in_source/src/bootstrap/tests/bootstrap.rs"]
mod tests;
