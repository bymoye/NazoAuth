use super::super::configuration::StartupConfiguration;
use super::dependencies::CoreServices;
use super::*;

/// Identity, session, administration, and local-login endpoints.  These
/// adapters share session/cookie policy and are kept together so that the
/// factory only has to register the already-composed handles.
pub(super) struct IdentityServices {
    pub(super) profile_logout_endpoint: web::Data<SessionLogoutEndpoint>,
    pub(super) runtime_module_admin_endpoint: web::Data<RuntimeModuleAdminEndpoint>,
    pub(super) admin_sessions: web::Data<AdminSessionHandles>,
    pub(super) authorization_endpoint: web::Data<AuthorizationEndpoint>,
    pub(super) admin_federation: web::Data<AdminFederationConfig>,
    pub(super) session_profiles: web::Data<SessionProfileHandles>,
    pub(super) session_management_endpoint: web::Data<SessionManagementEndpoint>,
    pub(super) device_decision_handles: web::Data<DeviceDecisionHandles>,
    pub(super) authorization_decision_endpoint: web::Data<AuthorizationDecisionEndpoint>,
    pub(super) oidc_logout: web::Data<OidcLogoutEndpoint>,
    pub(super) csrf_http_config: web::Data<CsrfHttpConfig>,
    pub(super) profile_account_endpoint: web::Data<ProfileAccountEndpoint>,
    pub(super) account_profiles: web::Data<AccountProfileService>,
    pub(super) avatar_profiles: web::Data<AvatarProfileService>,
    pub(super) profile_access_requests: web::Data<ClientAccessProfileService>,
    pub(super) profile_federation: web::Data<FederationProfileService>,
    pub(super) admin_users: web::Data<dyn nazo_identity::ports::AdminUserRepositoryPort>,
    pub(super) admin_user_registration:
        web::Data<dyn nazo_identity::ports::RegistrationAccountRepositoryPort>,
    pub(super) admin_grants: web::Data<dyn nazo_auth::AdminGrantRepositoryPort>,
    pub(super) admin_access_requests: web::Data<nazo_postgres::AccessRequestRepository>,
    pub(super) mtls_trust_anchors: web::Data<MtlsTrustAnchorService>,
    pub(super) admin_access_delivery: web::Data<nazo_valkey::DeliveryStore>,
    pub(super) admin_access_request_config: web::Data<AdminAccessRequestConfig>,
    pub(super) client_ip_config: web::Data<ClientIpConfig>,
    pub(super) mfa_profiles: web::Data<MfaProfileEndpoint>,
    pub(super) auth_request_limiter: web::Data<AuthRequestLimiter>,
    pub(super) token_management_limiter: web::Data<TokenManagementRequestLimiter>,
    pub(super) local_registration_endpoint: web::Data<LocalRegistrationEndpoint>,
    pub(super) password_login_endpoint: web::Data<PasswordLoginEndpoint>,
    pub(super) passkey_login_endpoint: web::Data<PasskeyLoginEndpoint>,
    pub(super) passkey_profile_endpoint: web::Data<PasskeyProfileEndpoint>,
    pub(super) federation: web::Data<LocalFederationService>,
    pub(super) federation_http_config: web::Data<FederationHttpConfig>,
}

pub(super) async fn build(
    startup: &StartupConfiguration,
    core: &CoreServices,
) -> anyhow::Result<IdentityServices> {
    let settings = startup.settings.as_ref();
    let diesel_db = startup.diesel_db.clone();
    let valkey_connection = startup.valkey_connection.clone();
    let runtime_registry = startup.runtime_modules.registry.clone();
    let keyset = startup.keyset.clone();

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
        startup.runtime_modules.administration(),
    ));
    let admin_sessions = web::Data::new(AdminSessionHandles::new(
        nazo_valkey::SessionStore::new(&valkey_connection),
        nazo_postgres::UserRepository::new(diesel_db.clone()),
        session_http_config.clone(),
    ));
    let authorization_endpoint = web::Data::new(AuthorizationEndpoint::new(
        core.authorization_service.clone().into_inner(),
        core.authorization_config.clone().into_inner(),
        admin_sessions.clone().into_inner(),
        runtime_registry.clone(),
        startup.remote_client_documents.clone(),
        keyset.clone(),
        DEFAULT_TENANT_ID,
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
    let admin_federation = web::Data::new(AdminFederationConfig::from_settings(&startup.settings));
    #[cfg(not(test))]
    let session_profiles = web::Data::new(SessionProfileHandles::new(
        nazo_valkey::SessionStore::new(&valkey_connection),
        nazo_postgres::UserRepository::new(diesel_db.clone()),
        session_http_config.clone(),
    ));
    #[cfg(test)]
    let session_profiles = web::Data::new(SessionProfileHandles::new(
        nazo_valkey::SessionStore::new(&valkey_connection),
        nazo_postgres::UserRepository::new(diesel_db.clone()),
        session_http_config.clone(),
    ));
    let client_repository = nazo_postgres::OAuthClientRepository::new(diesel_db.clone());
    let session_management_endpoint = web::Data::new(SessionManagementEndpoint::new(
        Arc::new(ServerSessionManagementOperations::new(
            session_profiles.get_ref().clone(),
            client_repository.clone(),
            runtime_registry.clone(),
        )),
        SessionManagementConfig::new(
            settings.endpoint.issuer.as_str(),
            session.session_cookie_name.as_str(),
        ),
    ));
    let device_decision_handles = web::Data::new(DeviceDecisionHandles::new(
        core.authorization_service.clone(),
        core.device_service.clone(),
        core.device_grants.clone(),
        session_profiles.clone(),
        core.device_config.clone(),
        core.authorization_runtime.clone(),
    ));
    let logout_deliveries = nazo_postgres::AuditRepository::new(diesel_db.clone());
    let oidc_logout_operations = OidcLogoutHandles::new(
        session_profiles.get_ref().clone(),
        client_repository,
        logout_deliveries.clone(),
        keyset.clone(),
        OidcLogoutConfig::from(settings),
        runtime_registry.clone(),
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
            core.authorization_service.clone().into_inner(),
            identity_session_service.clone(),
            core.authorization_config.clone().into_inner(),
            runtime_registry.clone(),
        )),
        session_cookie_config.clone(),
        client_ip_config.get_ref().clone(),
    ));
    let identity_settings = &settings.identity;
    let auth_request_limiter = web::Data::new(AuthRequestLimiter::new(
        nazo_valkey::RateLimitStore::new(&valkey_connection),
        identity_settings.rate_limit.window_seconds,
        identity_settings.rate_limit.auth_max_requests,
        client_ip_config.get_ref().clone(),
    ));
    let token_management_limiter = web::Data::new(TokenManagementRequestLimiter::new(
        nazo_valkey::RateLimitStore::new(&valkey_connection),
        identity_settings.rate_limit.window_seconds,
        identity_settings.rate_limit.token_management_max_requests,
        client_ip_config.get_ref().clone(),
    ));
    let email_delivery =
        SmtpVerificationEmailDelivery::from_delivery(&identity_settings.email.delivery);
    let registration = LocalRegistrationService::new(
        nazo_postgres::UserRepository::new(diesel_db.clone()),
        nazo_valkey::AuthenticationStore::new(&valkey_connection),
        RegistrationSecretHasher,
        email_delivery,
        default_tenant_context()
            .as_identity_context()
            .expect("default tenant identifiers are valid"),
        nazo_identity::RegistrationServiceConfig {
            delivery_enabled: email_delivery_configured(&startup.settings),
            send_peer_cooldown_seconds: identity_settings.email.send_peer_cooldown_seconds,
            send_cooldown_seconds: identity_settings.email.send_cooldown_seconds,
            code_ttl_seconds: identity_settings.email.code_ttl_seconds,
        },
    );
    let authentication_rate_limit = Arc::new(ServerAuthenticationRateLimit::new(
        nazo_valkey::RateLimitStore::new(&valkey_connection),
        identity_settings.rate_limit.window_seconds,
        identity_settings.rate_limit.auth_max_requests,
    ));
    let mfa_attempt_throttle: Arc<dyn nazo_identity::ports::MfaAttemptThrottlePort> =
        Arc::new(nazo_valkey::RateLimitStore::new(&valkey_connection));
    let mfa_totp_keys = mfa_totp_key_ring(&startup.config)?;
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
            mfa_attempt_throttle,
            identity_settings.rate_limit.mfa_failure_window_seconds,
            identity_settings.rate_limit.mfa_failure_max_attempts,
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
        identity_settings.email_code_dev_response_enabled,
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
            failure_window_seconds: identity_settings.rate_limit.login_failure_window_seconds,
            failure_ip_email_max_attempts: identity_settings
                .rate_limit
                .login_failure_ip_email_max_attempts,
            session_ttl_seconds: session.session_ttl_seconds,
            pending_mfa_session_ttl_seconds: session.pending_mfa_session_ttl_seconds,
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
    let passkey = &identity_settings.passkey;
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
        identity_settings.federation.providers.clone(),
        identity_settings.federation.saml_gateway.clone(),
        session.session_cookie_name.as_str(),
        session.csrf_cookie_name.as_str(),
        session.session_ttl_seconds,
        session.cookie_secure,
    ));

    #[cfg(not(test))]
    super::super::background::spawn_backchannel_logout_worker(
        logout_deliveries,
        &startup.settings,
    )?;

    Ok(IdentityServices {
        profile_logout_endpoint,
        runtime_module_admin_endpoint,
        admin_sessions,
        authorization_endpoint,
        admin_federation,
        session_profiles,
        session_management_endpoint,
        device_decision_handles,
        authorization_decision_endpoint,
        oidc_logout,
        csrf_http_config,
        profile_account_endpoint,
        account_profiles,
        avatar_profiles,
        profile_access_requests,
        profile_federation,
        admin_users,
        admin_user_registration,
        admin_grants,
        admin_access_requests,
        mtls_trust_anchors,
        admin_access_delivery,
        admin_access_request_config,
        client_ip_config,
        mfa_profiles,
        auth_request_limiter,
        token_management_limiter,
        local_registration_endpoint,
        password_login_endpoint,
        passkey_login_endpoint,
        passkey_profile_endpoint,
        federation,
        federation_http_config,
    })
}
