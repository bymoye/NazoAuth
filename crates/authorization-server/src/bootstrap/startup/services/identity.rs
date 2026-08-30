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
    pub(super) admin_access_requests: web::Data<dyn nazo_persistence::AdminAccessRequestStore>,
    pub(super) controller_registry:
        web::Data<crate::controller_registry::ControllerRegistryService>,
    pub(super) recovery_root: web::Data<crate::recovery_root::RecoveryRootService>,
    pub(super) mtls_trust_anchors: web::Data<MtlsTrustAnchorService>,
    pub(super) admin_access_delivery: web::Data<dyn nazo_identity::ports::DeliveryStorePort>,
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
    let persistence = startup.persistence.provider();
    let transient_state = startup.transient_state.provider();
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
        transient_state.sessions(),
        persistence.session_accounts(),
        settings.tenant.context.tenant_id,
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
    let admin_sessions = web::Data::new(AdminSessionHandles::from_port(
        transient_state.sessions(),
        persistence.session_accounts(),
        settings.tenant.context.tenant_id,
        session_http_config.clone(),
    ));
    let authorization_endpoint = web::Data::new(AuthorizationEndpoint::new(
        core.authorization_service.clone().into_inner(),
        core.authorization_config.clone().into_inner(),
        admin_sessions.clone().into_inner(),
        runtime_registry.clone(),
        startup.remote_client_documents.clone(),
        keyset.clone(),
        settings.tenant.context.tenant_id.as_uuid(),
        if settings.modules.enable_openid4vci_issuer {
            Some(
                persistence.openid4vci_authorization_offers(
                    settings
                        .openid4vc
                        .data_encryption_key
                        .expect("enabled OpenID4VCI requires a data encryption key"),
                ),
            )
        } else {
            None
        },
    ));
    let admin_federation = web::Data::new(AdminFederationConfig::from_settings(&startup.settings));
    let session_profiles = web::Data::new(SessionProfileHandles::from_port(
        transient_state.sessions(),
        persistence.session_accounts(),
        settings.tenant.context.tenant_id,
        session_http_config.clone(),
    ));
    let session_management_endpoint = web::Data::new(SessionManagementEndpoint::new(
        Arc::new(ServerSessionManagementOperations::new(
            session_profiles.get_ref().clone(),
            persistence.admin_clients(),
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
    #[cfg(not(test))]
    let logout_deliveries = persistence.logout_delivery_store();
    let oidc_logout_operations = OidcLogoutHandles::new(
        session_profiles.get_ref().clone(),
        persistence.logout_clients(),
        persistence.logout_outbox(),
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
    let account_profile_service = AccountProfileService::from_ports(
        persistence.profiles(),
        persistence.grant_summaries(),
        persistence.authorized_applications(),
    );
    let profile_account_endpoint = web::Data::new(ProfileAccountEndpoint::new(
        Arc::new(ServerProfileAccountOperations::new(
            identity_session_service.clone(),
            account_profile_service.clone(),
        )),
        session_cookie_config.clone(),
    ));
    let account_profiles = web::Data::new(account_profile_service);
    let avatar_profiles = web::Data::new(AvatarProfileService::from_ports(
        persistence.avatars(),
        persistence.grant_summaries(),
        crate::adapters::avatar_files::LocalAvatarStorage::new(
            settings.storage.avatar_storage_dir.clone(),
        ),
        settings.storage.avatar_max_bytes,
    ));
    let profile_delivery_store = transient_state.delivery();
    let profile_access_requests = web::Data::new(ClientAccessProfileService::from_port(
        persistence.access_requests(),
        profile_delivery_store,
        &settings.protocol.client_secret_pepper,
    ));
    let profile_federation = web::Data::new(FederationProfileService::from_port(
        persistence.federation_links(),
    ));
    let admin_users: web::Data<dyn nazo_identity::ports::AdminUserRepositoryPort> =
        web::Data::from(persistence.admin_users());
    let admin_user_registration: web::Data<
        dyn nazo_identity::ports::RegistrationAccountRepositoryPort,
    > = web::Data::from(persistence.registration_accounts());
    let admin_grants: web::Data<dyn nazo_auth::AdminGrantRepositoryPort> =
        web::Data::from(persistence.admin_grants());
    let admin_access_requests: web::Data<dyn nazo_persistence::AdminAccessRequestStore> =
        web::Data::from(persistence.admin_access_requests());
    // D01/D02/D05: authoritative controller registry behind fresh-2FA
    // approvals.  Built once here so handlers only ever see the typed facade.
    let controller_registry =
        web::Data::new(crate::controller_registry::ControllerRegistryService::new(
            persistence.controller_registry(),
        ));
    // 04A D10/D11/D12: Recovery Root anchor, break-glass challenges and
    // approved rotations share the registry's database authority.
    let recovery_root = web::Data::new(crate::recovery_root::RecoveryRootService::new(
        persistence.recovery_root(),
    ));
    let mtls_trust_anchors: web::Data<MtlsTrustAnchorService> =
        web::Data::from(persistence.mtls_trust_anchors());
    let admin_access_delivery: web::Data<dyn nazo_identity::ports::DeliveryStorePort> =
        web::Data::from(transient_state.delivery());
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
            settings.tenant.context.tenant_id,
            core.authorization_config.clone().into_inner(),
            runtime_registry.clone(),
        )),
        session_cookie_config.clone(),
        client_ip_config.get_ref().clone(),
    ));
    let identity_settings = &settings.identity;
    let auth_request_limiter = web::Data::new(AuthRequestLimiter::new(
        transient_state.request_rate_limits(),
        identity_settings.rate_limit.window_seconds,
        identity_settings.rate_limit.auth_max_requests,
        client_ip_config.get_ref().clone(),
    ));
    let token_management_limiter = web::Data::new(TokenManagementRequestLimiter::new(
        transient_state.request_rate_limits(),
        identity_settings.rate_limit.window_seconds,
        identity_settings.rate_limit.token_management_max_requests,
        client_ip_config.get_ref().clone(),
    ));
    let email_delivery =
        SmtpVerificationEmailDelivery::from_delivery(&identity_settings.email.delivery);
    let registration = LocalRegistrationService::from_port(
        persistence.registration_accounts(),
        transient_state.email_verification(),
        RegistrationSecretHasher,
        email_delivery,
        settings.tenant.context,
        nazo_identity::RegistrationServiceConfig {
            delivery_enabled: email_delivery_configured(&startup.settings),
            send_peer_cooldown_seconds: identity_settings.email.send_peer_cooldown_seconds,
            send_cooldown_seconds: identity_settings.email.send_cooldown_seconds,
            code_ttl_seconds: identity_settings.email.code_ttl_seconds,
        },
    );
    let authentication_rate_limit = Arc::new(ServerAuthenticationRateLimit::new(
        transient_state.request_rate_limits(),
        identity_settings.rate_limit.window_seconds,
        identity_settings.rate_limit.auth_max_requests,
    ));
    let mfa_attempt_throttle: Arc<dyn nazo_identity::ports::MfaAttemptThrottlePort> =
        transient_state.mfa_attempt_throttle();
    let mfa_totp_keys = mfa_totp_key_ring(&startup.config)?;
    let mfa_repository = persistence.mfa_repository(mfa_totp_keys.clone());
    let mfa_profiles = web::Data::new(MfaProfileEndpoint::new(
        Arc::new(ServerMfaProfileOperations::new(
            nazo_identity::MfaService::new(mfa_repository.clone(), Arc::new(ServerMfaSecretHasher)),
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
    let authentication = LocalAuthenticationService::from_ports(
        persistence.login_accounts(),
        transient_state.login_throttle(),
        LoginPasswordVerifier,
        persistence.remembered_mfa_devices(mfa_totp_keys.clone()),
        transient_state.login_sessions(),
        TracingAuthenticationAudit,
        nazo_identity::AuthenticationServiceConfig {
            tenant_id: settings.tenant.context.tenant_id,
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
        LocalPasskeyService::from_ports(
            persistence.passkey_accounts(),
            persistence.passkeys(),
            transient_state.passkey_ceremonies(),
            persistence.remembered_mfa_devices(mfa_totp_keys),
            transient_state.login_sessions(),
            TracingPasskeyAudit,
            nazo_identity::PasskeyServiceConfig {
                tenant_id: settings.tenant.context.tenant_id,
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
    let federation = web::Data::new(LocalFederationService::from_port(
        persistence.federation_logins(),
        transient_state.federation_state(),
        FederationBootstrapPasswordHasher,
        transient_state.login_sessions(),
        TracingFederationAudit,
        nazo_identity::FederationServiceConfig {
            tenant: settings.tenant.context,
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
        controller_registry,
        recovery_root,
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
