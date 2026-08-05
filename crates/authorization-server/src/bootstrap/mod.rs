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
mod ui_release;
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
    FederationProfileService, MtlsTrustAnchorService,
};
pub(crate) use registration_services::{LocalRegistrationService, RegistrationSecretHasher};

use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use actix_files::{Files, NamedFile};
use actix_web::{
    App, HttpResponse, HttpServer,
    dev::{Service, ServiceRequest, ServiceResponse, fn_service},
    middleware::from_fn,
    web,
};
use anyhow::Context as _;

use crate::adapters::email::{SmtpVerificationEmailDelivery, email_delivery_configured};
use crate::adapters::security::{
    configure_password_hash_limits, default_password_hash_max_concurrency,
    default_password_hash_queue_timeout_ms, dummy_password_hash, initialize_dummy_password_hash,
};
use crate::config::{ConfigSource, database_max_connections, database_url};
use crate::domain::tenancy::{DEFAULT_TENANT_ID, default_tenant_context};
#[cfg(not(test))]
use crate::domain::{
    BackchannelLogoutWorker, CibaPingDeliveryWorker, ServerTokenManagementOperations,
    ServerTokenManagementRequestGuard, spawn_backchannel_logout_delivery_worker,
    spawn_ciba_ping_delivery_worker,
};
use crate::domain::{
    CredentialDatasetAdminService, Openid4vcClientAttestationValidator, Openid4vcCredentialCrypto,
    Openid4vcProofValidator, PresentationVerifierConfig, ServerCredentialIssuerOperations,
    ServerPresentationOperations,
};
use crate::domain::{
    DynamicRegistrationConfig, ServerUserinfoOperations, dynamic_registration_endpoint,
};
use crate::domain::{
    MFA_REMEMBERED_COOKIE_NAME, MFA_REMEMBERED_TTL_SECONDS, MetadataConfig, OidcLogoutConfig,
    OidcLogoutHandles, PasskeyOperationsProvider, ResourceServerConfig,
    ServerAuthenticationRateLimit, ServerAuthorizationDecisionOperations,
    ServerLocalRegistrationOperations, ServerMetadataSnapshotSource, ServerMfaProfileOperations,
    ServerMfaSecretHasher, ServerPasswordLoginOperations, ServerProfileAccountOperations,
    ServerSessionManagementOperations, UserinfoConfig, UserinfoHandles,
};
use crate::domain::{
    ServerFapiHttpMessageSignatures, ServerFapiMtlsResolver, ServerFapiResourceAuthorizer,
};
use crate::domain::{
    ServerScimBootstrapPasswordProvider, ServerScimCursorProtector, ServerScimEventSigner,
    ServerScimRequestAuthorizer,
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
use crate::http::rate_limit::{AuthRequestLimiter, TokenManagementRequestLimiter};
use crate::http::sessions::{AdminSessionHandles, SessionHttpConfig, SessionProfileHandles};
#[cfg(not(test))]
use crate::http::token::ServerTokenManagementRequestFactsExtractor;
use crate::http::token::ciba::{CibaHttpConfig, CibaTokenHandles, ServerCibaService};
use crate::http::token::device::{DeviceDecisionHandles, ServerDeviceGrantService};
use crate::http::token::device_config::DeviceHttpConfig;
use crate::http::token::dispatch::{Openid4vcTokenHandles, TokenCoreHandles, TokenEndpointHandles};
use crate::http::token::issue::TokenIssuanceConfig;
use crate::runtime_modules::{RuntimeModules, ServerRuntimeModuleRegistry};
use crate::settings::{
    Openid4vcRevocationPolicy, Settings, mfa_totp_key_ring, token_issuance_response_key_ring,
};
use nazo_digital_credentials::{CertificateRevocationPolicy, CertificateRevocationSnapshot};
use nazo_http_actix::ClientIpConfig;
use nazo_http_actix::{
    AuthorizationDecisionEndpoint, LocalRegistrationEndpoint, MfaProfileConfig, MfaProfileEndpoint,
    OidcLogoutConfig as OidcLogoutHttpConfig, OidcLogoutEndpoint, PasskeyLoginConfig,
    PasskeyLoginEndpoint, PasskeyProfileConfig, PasskeyProfileEndpoint, PasswordLoginConfig,
    PasswordLoginEndpoint, ProfileAccountEndpoint, RuntimeModuleAdminEndpoint, SessionCookieConfig,
    SessionLogoutEndpoint, SessionManagementConfig, SessionManagementEndpoint, security_headers,
};
use nazo_openid4vc_http_actix::{CredentialIssuerEndpoint, PresentationEndpoint};
use nazo_postgres::create_pool;
use rustls::{
    RootCertStore, ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
    server::WebPkiClientVerifier,
};
use tracing::Instrument;

const MAX_REVOCATION_SNAPSHOT_BYTES: u64 = 4 * 1024 * 1024;

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
    let require_audit_least_privilege =
        config.bool("SECURITY_AUDIT_REQUIRE_LEAST_PRIVILEGE", true)?;
    let audit_repository = nazo_postgres::AuditLedgerRepository::new(diesel_db.clone());
    audit_repository
        .check_available_with_policy(require_audit_least_privilege)
        .await
        .map_err(|error| anyhow::anyhow!("security audit writer preflight failed: {error}"))?;
    crate::adapters::audit::install_persistent_audit_sink(
        audit_repository,
        require_audit_least_privilege,
    )?;
    crate::conformance_lease::spawn_cleanup(diesel_db.clone());
    #[cfg(not(test))]
    let valkey =
        nazo_valkey::ValkeyConnection::connect(&valkey_url, valkey_command_timeout).await?;
    #[cfg(test)]
    let valkey = nazo_valkey::test_support::connect(&valkey_url, valkey_command_timeout).await?;
    #[cfg(not(test))]
    let valkey_connection = valkey;
    #[cfg(test)]
    let valkey_connection = nazo_valkey::ValkeyConnection::from_existing_client(valkey);

    let settings = Arc::new(Settings::from_config(&config)?);
    crate::adapters::audit::configure_audit_anchor_preflight(
        crate::adapters::audit_anchor::preflight_config_from_source(
            &config,
            &settings.storage.data_dir,
        )?,
    )?;
    let token_issuance_response_keys = token_issuance_response_key_ring(&config)?;
    let instance_identity_dir = config
        .optional_string("INSTANCE_IDENTITY_DIR")
        .map(PathBuf::from);
    let control_discovery = web::Data::new(
        crate::control_discovery::ControlDiscoveryEndpoint::initialize(
            &settings.storage.data_dir,
            instance_identity_dir.as_deref(),
            config.optional_string("DEPLOYMENT_ID").as_deref(),
            config.optional_string("RUNTIME_INSTANCE_ID").as_deref(),
            &settings.endpoint.issuer,
        )?,
    );
    let mtls_certificate_source = web::Data::new(crate::http::mtls::MtlsCertificateSource::new(
        settings.endpoint.mtls_certificate_source,
    ));
    let readiness_dependencies =
        web::Data::new(crate::http::well_known::ReadinessDependencies::new(
            diesel_db.clone(),
            valkey_connection.clone(),
        ));
    let initial_admin_bootstrap = web::Data::new(
        crate::http::bootstrap_admin::InitialAdminBootstrapEndpoint::initialize(
            diesel_db.clone(),
            &settings.storage.data_dir,
            &settings.endpoint.issuer,
        )
        .await?,
    );
    let remote_client_documents = Arc::new(
        crate::domain::remote_client_documents::RemoteClientDocumentResolver::new(
            &settings.modules.remote_client_document_private_origins,
        )
        .map_err(anyhow::Error::msg)?,
    );
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
    let resource_replay_connection = valkey_connection.clone();
    let resource_server_config = ResourceServerConfig::from(settings.as_ref());
    tracing::info!(
        dpop_nonce_policy = ?settings.protocol.dpop_nonce_policy,
        fapi_resource_dpop_nonce_policy = ?settings.protocol.fapi_resource_dpop_nonce_policy,
        "loaded DPoP nonce policies"
    );
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
    let dynamic_registration_config = DynamicRegistrationConfig::from(settings.as_ref());
    let dynamic_registration_handles = web::Data::new(dynamic_registration_endpoint(
        dynamic_registration_config,
        nazo_postgres::OAuthClientRepository::new(diesel_db.clone()),
        nazo_valkey::RateLimitStore::new(&valkey_connection),
        keyset.clone(),
        runtime_modules.registry.clone(),
        remote_client_documents.clone(),
    ));
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
        Arc::new(nazo_postgres::ScimRepository::with_event_retention_seconds(
            diesel_db.clone(),
            scim_storage.scim_event_retention_seconds,
        )),
        Arc::new(nazo_postgres::AuditRepository::new(diesel_db.clone())),
    );
    let scim_client_ip = ClientIpConfig::new(
        &scim_endpoint.trusted_proxy_cidrs,
        scim_endpoint.client_ip_header_mode,
    );
    let scim_endpoint = web::Data::new(
        nazo_http_actix::ScimEndpoint::new(
            scim_service.clone(),
            Arc::new(ServerScimRequestAuthorizer::new(
                scim_service,
                scim_client_ip,
                runtime_modules.registry.clone(),
            )),
            Arc::new(ServerScimCursorProtector::new(
                &scim_protocol.client_secret_pepper,
            )?),
            Arc::new(ServerScimBootstrapPasswordProvider),
        )
        .with_security_events(Arc::new(nazo_scim_events::EventPublisher::new(
            nazo_postgres::ScimEventRepository::new(diesel_db.clone()),
            ServerScimEventSigner::new(keyset.clone()),
            settings.endpoint.issuer.clone(),
        ))),
    );
    let authorization_service = web::Data::new(ServerAuthorizationService::new(
        nazo_postgres::AuthorizationFlowRepository::new(diesel_db.clone(), DEFAULT_TENANT_ID),
        nazo_valkey::AuthorizationStateAdapter::new(&valkey_connection),
        keyset.clone(),
    ));
    let token_issuance_repository =
        nazo_postgres::TokenIssuanceRepository::new_with_response_key_ring(
            diesel_db.clone(),
            token_issuance_response_keys,
        );
    token_issuance_repository
        .validate_response_key_ring()
        .await
        .map_err(|error| {
            anyhow::anyhow!("token issuance response key-ring preflight failed: {error}")
        })?;
    let token_service = web::Data::new(crate::http::token::ServerTokenService::new(
        token_issuance_repository,
        nazo_valkey::TokenIssuanceStateAdapter::new(&valkey_connection),
        keyset.clone(),
    ));
    let ciba_service = web::Data::new(ServerCibaService::new(nazo_valkey::CibaStore::new(
        &valkey_connection,
    )));
    #[cfg(not(test))]
    if nazo_auth::module_admissible(
        runtime_modules.registry.snapshot().as_ref(),
        nazo_runtime_modules::ModuleId::Ciba,
        nazo_auth::CapabilityAdmission::NewRequest,
    ) {
        spawn_ciba_ping_delivery_worker(CibaPingDeliveryWorker::new(
            nazo_valkey::CibaStore::new(&valkey_connection),
            &settings.ciba.ciba_notification_private_origins,
        )?);
    }
    let ciba_users = web::Data::new(nazo_postgres::UserRepository::new(diesel_db.clone()));
    let ciba_config = web::Data::new(CibaHttpConfig::from(settings.as_ref()));
    let conformance_leases = web::Data::new(nazo_postgres::ConformanceLeaseRepository::new(
        diesel_db.clone(),
    ));
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
    let openid4vc_crypto = if settings.modules.enable_openid4vci_issuer
        || settings.modules.enable_openid4vp_verifier
    {
        let revocation_policy = load_revocation_policy(&settings.openid4vc).await?;
        let certificate_chain = tokio::fs::read(
            settings
                .openid4vc
                .signing_certificate_chain_file
                .as_ref()
                .expect("enabled OpenID4VC modules require a certificate chain"),
        )
        .await
        .with_context(|| {
            format!(
                "failed to read OpenID4VC signing certificate chain from {}",
                settings
                    .openid4vc
                    .signing_certificate_chain_file
                    .as_ref()
                    .expect("enabled OpenID4VC modules require a certificate chain")
                    .display()
            )
        })?;
        let trust_anchors_path = settings
            .openid4vc
            .trust_anchors_file
            .as_ref()
            .expect("enabled OpenID4VC modules require trust anchors");
        let trust_anchors = tokio::fs::read(trust_anchors_path).await.with_context(|| {
            format!(
                "failed to read OpenID4VC trust anchors from {}",
                trust_anchors_path.display()
            )
        })?;
        Some(Openid4vcCredentialCrypto::new_with_policies(
            keyset.clone(),
            &certificate_chain,
            &trust_anchors,
            nazo_digital_credentials::VcIssuerTrustPolicy::san_bound(),
            revocation_policy,
        )
        .with_context(|| {
            format!(
                "failed to initialize OpenID4VC credential crypto from certificate chain {} and trust anchors {}",
                settings
                    .openid4vc
                    .signing_certificate_chain_file
                    .as_ref()
                    .expect("enabled OpenID4VC modules require a certificate chain")
                    .display(),
                trust_anchors_path.display()
            )
        })?)
    } else {
        None
    };
    let static_client_attestation =
        settings
            .openid4vc
            .client_attestation_issuer
            .as_ref()
            .map(|issuer| {
                (
                    issuer.clone(),
                    settings
                        .openid4vc
                        .client_attestation_jwks
                        .clone()
                        .expect("configured client attestation requires trust keys"),
                )
            });
    let client_attestation_validator = settings
        .modules
        .enable_openid4vci_issuer
        .then(|| {
            Openid4vcClientAttestationValidator::with_conformance_leases(
                static_client_attestation,
                nazo_postgres::ConformanceLeaseRepository::new(diesel_db.clone()),
                DEFAULT_TENANT_ID,
            )
            .map(Arc::new)
        })
        .transpose()?;
    let (credential_issuer_endpoint, credential_dataset_admin) =
        if settings.modules.enable_openid4vci_issuer {
            let data_key = settings
                .openid4vc
                .data_encryption_key
                .expect("enabled OpenID4VCI requires a data encryption key");
            let proof_validator = Openid4vcProofValidator::new(
                settings
                    .openid4vc
                    .key_attestation_jwks
                    .clone()
                    .unwrap_or_else(|| serde_json::json!({"keys": []})),
            )?
            .with_conformance_leases(
                nazo_postgres::ConformanceLeaseRepository::new(diesel_db.clone()),
                DEFAULT_TENANT_ID,
            );
            let operations = Arc::new(ServerCredentialIssuerOperations::new(
                diesel_db.clone(),
                DEFAULT_TENANT_ID,
                data_key,
                token_service.clone().into_inner(),
                authorization_service.clone().into_inner(),
                runtime_modules.registry.clone(),
                openid4vc_crypto
                    .as_ref()
                    .expect("enabled OpenID4VCI requires crypto")
                    .clone(),
                proof_validator,
                client_attestation_validator.clone(),
                settings.endpoint.issuer.clone(),
                settings.openid4vc.credential_configurations.clone(),
                settings
                    .openid4vc
                    .deferred_credential_configurations
                    .clone(),
                settings.protocol.dpop_nonce_policy,
            )?);
            (
                Some(web::Data::new(CredentialIssuerEndpoint::new(
                    operations.clone(),
                    settings
                        .openid4vc
                        .issuer_management_token
                        .clone()
                        .expect("enabled OpenID4VCI requires a management token")
                        .into_bytes(),
                ))),
                Some(web::Data::new(CredentialDatasetAdminService::new(
                    operations,
                ))),
            )
        } else {
            (None, None)
        };
    let presentation_endpoint = if settings.modules.enable_openid4vp_verifier {
        Some(web::Data::new(PresentationEndpoint::new(
            Arc::new(ServerPresentationOperations::new(
                diesel_db.clone(),
                DEFAULT_TENANT_ID,
                settings
                    .openid4vc
                    .data_encryption_key
                    .expect("enabled OpenID4VP requires a data encryption key"),
                openid4vc_crypto
                    .as_ref()
                    .expect("enabled OpenID4VP requires crypto")
                    .clone(),
                runtime_modules.registry.clone(),
                PresentationVerifierConfig {
                    issuer: settings.endpoint.issuer.clone(),
                    wallet_origins: settings.openid4vc.wallet_authorization_origins.clone(),
                    transaction_ttl_seconds: settings.openid4vc.transaction_ttl_seconds,
                },
            )),
            settings
                .openid4vc
                .verifier_management_token
                .clone()
                .expect("enabled OpenID4VP requires a management token")
                .into_bytes(),
        )))
    } else {
        None
    };
    let token_endpoint_handles = web::Data::new(TokenEndpointHandles::new(
        TokenCoreHandles {
            token_service: token_service.clone(),
            authorization_service: authorization_service.clone(),
            device_service: device_service.clone(),
        },
        CibaTokenHandles::new(
            ciba_service.clone(),
            ciba_users.clone(),
            ciba_config.clone(),
        ),
        token_issuance_config.clone(),
        authorization_runtime.clone(),
        remote_client_documents.clone(),
        Openid4vcTokenHandles {
            credential_issuer: credential_issuer_endpoint.clone(),
            client_attestation: client_attestation_validator.clone(),
        },
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
        remote_client_documents.clone(),
        keyset.clone(),
        if settings.modules.enable_openid4vci_issuer {
            Some(Arc::new(nazo_postgres::Openid4vciRepository::new(
                diesel_db.clone(),
                settings
                    .openid4vc
                    .data_encryption_key
                    .expect("enabled OpenID4VCI requires a data encryption key"),
            ))
                as Arc<dyn nazo_openid4vci::AuthorizationOfferPort>)
        } else {
            None
        },
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
    let client_repository = nazo_postgres::OAuthClientRepository::new(diesel_db.clone());
    let session_management_endpoint = web::Data::new(SessionManagementEndpoint::new(
        Arc::new(ServerSessionManagementOperations::new(
            session_profiles.get_ref().clone(),
            client_repository.clone(),
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
    let oidc_logout_operations = OidcLogoutHandles::new(
        session_profiles.get_ref().clone(),
        client_repository,
        logout_deliveries.clone(),
        keyset.clone(),
        OidcLogoutConfig::from(settings.as_ref()),
        runtime_modules.registry.clone(),
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
    ));
    let profile_federation = web::Data::new(FederationProfileService::new(
        nazo_postgres::FederationRepository::new(diesel_db.clone()),
    ));
    let admin_users: web::Data<dyn nazo_identity::ports::AdminUserRepositoryPort> = web::Data::from(
        Arc::new(nazo_postgres::UserRepository::new(diesel_db.clone()))
            as Arc<dyn nazo_identity::ports::AdminUserRepositoryPort>,
    );
    let admin_user_registration: web::Data<
        dyn nazo_identity::ports::RegistrationAccountRepositoryPort,
    > = web::Data::from(
        Arc::new(nazo_postgres::UserRepository::new(diesel_db.clone()))
            as Arc<dyn nazo_identity::ports::RegistrationAccountRepositoryPort>,
    );
    let admin_grants: web::Data<dyn nazo_auth::AdminGrantRepositoryPort> = web::Data::from(
        Arc::new(nazo_postgres::GrantRepository::new(diesel_db.clone()))
            as Arc<dyn nazo_auth::AdminGrantRepositoryPort>,
    );
    let admin_access_requests = web::Data::new(nazo_postgres::AccessRequestRepository::new(
        diesel_db.clone(),
    ));
    let mtls_trust_anchors = web::Data::new(MtlsTrustAnchorService::new(diesel_db.clone()));
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
    let mfa_totp_keys = mfa_totp_key_ring(&config)?;
    let mfa_repository =
        nazo_postgres::MfaRepository::with_totp_key_ring(diesel_db.clone(), mfa_totp_keys.clone());
    if mfa_totp_keys.is_some() {
        let migrated = mfa_repository.migrate_legacy_totp_secrets().await?;
        let rotated = mfa_repository.rotate_totp_secrets().await?;
        if migrated > 0 || rotated > 0 {
            tracing::info!(migrated, rotated, "migrated TOTP secret envelopes");
        }
    } else if mfa_repository.has_totp_credentials().await? {
        anyhow::bail!(
            "MFA_TOTP_ENCRYPTION_KEY is required before starting with persisted TOTP credentials"
        );
    }
    let mfa_profiles = web::Data::new(MfaProfileEndpoint::new(
        Arc::new(ServerMfaProfileOperations::new(
            nazo_identity::MfaService::new(
                Arc::new(mfa_repository.clone()),
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
        mfa_repository.clone(),
        nazo_valkey::SessionStore::new(&valkey_connection),
        TracingAuthenticationAudit,
        nazo_identity::AuthenticationServiceConfig {
            tenant_id: nazo_identity::TenantId::new(DEFAULT_TENANT_ID)
                .expect("default tenant ID is valid"),
            dummy_password_hash: nazo_identity::PasswordHash::new(dummy_password_hash()?)?,
            failure_window_seconds: identity.rate_limit.login_failure_window_seconds,
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
            mfa_repository.clone(),
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
    spawn_backchannel_logout_delivery_worker(BackchannelLogoutWorker::new(
        logout_deliveries,
        &settings.modules.backchannel_logout_private_origins,
    )?);

    let bind = config.string("BIND", "0.0.0.0:8000");
    let addr: SocketAddr = bind.parse()?;
    let direct_tls = direct_tls_listener(&config, &settings)?;
    let ui_static_dir = ui_release::resolve(&config).await?;
    tracing::info!("nazo-oauth-server(actix-web) listening on {addr}");

    let server = HttpServer::new(move || {
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
        let app = app.app_data(token_management_endpoint.clone());
        let app = app.app_data(userinfo_endpoint.clone());
        let app = app
            .app_data(mtls_certificate_source.clone())
            .app_data(readiness_dependencies.clone())
            .app_data(control_discovery.clone())
            .app_data(initial_admin_bootstrap.clone())
            .app_data(token_endpoint_handles.clone())
            .app_data(ciba_service.clone())
            .app_data(ciba_users.clone())
            .app_data(ciba_config.clone())
            .app_data(conformance_leases.clone())
            .app_data(token_issuance_config.clone())
            .app_data(device_service.clone())
            .app_data(device_grants.clone())
            .app_data(device_decision_handles.clone())
            .app_data(device_config.clone());
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
            .app_data(admin_user_registration.clone())
            .app_data(admin_grants.clone())
            .app_data(admin_access_requests.clone())
            .app_data(mtls_trust_anchors.clone())
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
        let app = if let Some(endpoint) = credential_issuer_endpoint.clone() {
            app.app_data(endpoint)
        } else {
            app
        };
        let app = if let Some(service) = credential_dataset_admin.clone() {
            app.app_data(service)
        } else {
            app
        };
        let app = if let Some(endpoint) = presentation_endpoint.clone() {
            app.app_data(endpoint)
        } else {
            app
        };
        let app = if let Some(validator) = client_attestation_validator.clone() {
            app.app_data(web::Data::from(validator))
        } else {
            app
        };
        let app = if let Some(path) = ui_static_dir.clone() {
            app.service(ui_static_files(path))
        } else {
            app
        };
        app.configure(|cfg| routes::configure(cfg, &settings, perf_metrics_enabled))
    })
    .on_connect(|io, extensions| {
        let Some(stream) = io.downcast_ref::<
            actix_tls::accept::rustls_0_23::TlsStream<actix_web::rt::net::TcpStream>,
        >()
        else {
            return;
        };
        let Some(certificate) = stream
            .get_ref()
            .1
            .peer_certificates()
            .and_then(|certificates| certificates.first())
        else {
            return;
        };
        if let Some(identity) = crate::http::mtls::certificate_der_identity(certificate.as_ref()) {
            extensions.insert(identity);
        }
    })
    .bind(addr)?;
    let server = if let Some((tls_addr, acceptor)) = direct_tls {
        tracing::info!("nazo-oauth-server direct mTLS listener on {tls_addr}");
        server.bind_rustls_0_23(tls_addr, acceptor)?
    } else {
        server
    };
    server.run().await?;
    Ok(())
}

async fn load_revocation_policy(
    settings: &crate::settings::Openid4vcSettings,
) -> anyhow::Result<CertificateRevocationPolicy> {
    let Some(path) = settings.revocation_snapshot_file.as_ref() else {
        return Ok(CertificateRevocationPolicy::disabled());
    };
    let snapshot = read_revocation_snapshot(path).await.with_context(|| {
        format!(
            "failed to load OpenID4VC revocation snapshot from {}",
            path.display()
        )
    })?;
    let policy = match settings.revocation_policy {
        Openid4vcRevocationPolicy::Disabled => CertificateRevocationPolicy::disabled(),
        Openid4vcRevocationPolicy::Optional => {
            CertificateRevocationPolicy::optional(Arc::new(snapshot))
        }
        Openid4vcRevocationPolicy::Required => {
            CertificateRevocationPolicy::required(Arc::new(snapshot))
        }
    };
    if policy.is_enabled() {
        spawn_revocation_snapshot_reloader(
            policy.clone(),
            path.clone(),
            Duration::from_secs(settings.revocation_reload_interval_seconds),
        );
    }
    Ok(policy)
}

async fn read_revocation_snapshot(
    path: &std::path::Path,
) -> anyhow::Result<CertificateRevocationSnapshot> {
    use tokio::io::AsyncReadExt as _;

    let file = tokio::fs::File::open(path).await?;
    let mut bytes = Vec::new();
    file.take(MAX_REVOCATION_SNAPSHOT_BYTES + 1)
        .read_to_end(&mut bytes)
        .await?;
    if bytes.len() as u64 > MAX_REVOCATION_SNAPSHOT_BYTES {
        anyhow::bail!("revocation snapshot exceeds {MAX_REVOCATION_SNAPSHOT_BYTES} bytes");
    }
    let snapshot =
        CertificateRevocationSnapshot::from_json(&bytes).map_err(|error| anyhow::anyhow!(error))?;
    snapshot
        .validate_freshness_at(chrono::Utc::now())
        .map_err(|error| anyhow::anyhow!(error))?;
    Ok(snapshot)
}

fn spawn_revocation_snapshot_reloader(
    policy: CertificateRevocationPolicy,
    path: PathBuf,
    interval: Duration,
) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        ticker.tick().await;
        loop {
            ticker.tick().await;
            match read_revocation_snapshot(&path).await {
                Ok(snapshot) => {
                    if let Err(error) =
                        policy.replace_snapshot(Arc::new(snapshot), chrono::Utc::now())
                    {
                        tracing::warn!(
                            target: "openid4vc.revocation",
                            snapshot_path = %path.display(),
                            %error,
                            "rejected OpenID4VC revocation snapshot reload"
                        );
                    }
                }
                Err(error) => tracing::warn!(
                    target: "openid4vc.revocation",
                    snapshot_path = %path.display(),
                    %error,
                    "failed to reload OpenID4VC revocation snapshot; retaining previous snapshot"
                ),
            }
        }
    });
}

fn ui_static_files(root: PathBuf) -> Files {
    let index = root.join("index.html");
    Files::new("/ui", root)
        .index_file("index.html")
        .disable_content_disposition()
        .default_handler(fn_service(move |request: ServiceRequest| {
            let index = index.clone();
            async move {
                let missing_asset = request
                    .path()
                    .rsplit('/')
                    .next()
                    .is_some_and(|segment| segment.contains('.'));
                let (request, _) = request.into_parts();
                if missing_asset {
                    return Ok(ServiceResponse::new(
                        request,
                        HttpResponse::NotFound().finish(),
                    ));
                }
                let file = NamedFile::open_async(index).await?;
                let response = file.into_response(&request);
                Ok(ServiceResponse::new(request, response))
            }
        }))
}

fn direct_tls_listener(
    config: &ConfigSource,
    settings: &Settings,
) -> anyhow::Result<Option<(SocketAddr, ServerConfig)>> {
    use crate::http::mtls::MtlsCertificateSourceMode;

    if settings.endpoint.mtls_certificate_source != MtlsCertificateSourceMode::DirectTls {
        return Ok(None);
    }
    let required = |key: &str| {
        config
            .optional_string(key)
            .ok_or_else(|| anyhow::anyhow!("{key} is required for direct-tls mTLS"))
    };
    let bind: SocketAddr = required("TLS_BIND")?.parse()?;
    let certificate = required("TLS_CERTIFICATE_FILE")?;
    let private_key = required("TLS_PRIVATE_KEY_FILE")?;
    let client_ca = required("TLS_CLIENT_CA_FILE")?;

    let certificates = CertificateDer::pem_file_iter(&certificate)
        .with_context(|| format!("failed to open TLS certificate chain {certificate}"))?
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("failed to parse TLS certificate chain {certificate}"))?;
    if certificates.is_empty() {
        anyhow::bail!("TLS certificate chain {certificate} contains no certificates");
    }
    let private_key = PrivateKeyDer::from_pem_file(&private_key)
        .with_context(|| format!("failed to parse TLS private key {private_key}"))?;

    let mut client_roots = RootCertStore::empty();
    let client_ca_certificates = CertificateDer::pem_file_iter(&client_ca)
        .with_context(|| format!("failed to open TLS client CA bundle {client_ca}"))?
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("failed to parse TLS client CA bundle {client_ca}"))?;
    if client_ca_certificates.is_empty() {
        anyhow::bail!("TLS client CA bundle {client_ca} contains no certificates");
    }
    for certificate in client_ca_certificates {
        client_roots.add(certificate).with_context(|| {
            format!("TLS client CA bundle {client_ca} contains an invalid certificate")
        })?;
    }

    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let client_verifier =
        WebPkiClientVerifier::builder_with_provider(Arc::new(client_roots), Arc::clone(&provider))
            .build()
            .context("failed to build mutual TLS client certificate verifier")?;
    let server_config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(rustls::DEFAULT_VERSIONS)
        .context("failed to configure TLS protocol versions")?
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(certificates, private_key)
        .context("TLS certificate chain does not match the configured private key")?;
    Ok(Some((bind, server_config)))
}

#[cfg(test)]
#[path = "../../tests/unit/bootstrap.rs"]
mod tests;
