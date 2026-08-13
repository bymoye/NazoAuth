use super::super::configuration::StartupConfiguration;
use super::*;

mod openid4vc;

/// Request-facing protocol and OAuth service handles.  Each handle is built
/// once outside the Actix worker factory and cloned into worker applications.
pub(super) struct CoreServices {
    pub(super) metadata_handles: web::Data<nazo_http_actix::MetadataHandles>,
    pub(super) resource_server_http_data: web::Data<nazo_http_actix::FapiResourceEndpoint>,
    pub(super) dynamic_registration_handles:
        web::Data<nazo_http_actix::DynamicRegistrationEndpoint>,
    pub(super) admin_client_config: web::Data<AdminClientConfig>,
    pub(super) admin_client_service: web::Data<ServerAdminClientService>,
    pub(super) scim_endpoint: web::Data<nazo_http_actix::ScimEndpoint>,
    pub(super) authorization_service: web::Data<ServerAuthorizationService>,
    pub(super) token_service: web::Data<crate::http::token::ServerTokenService>,
    pub(super) ciba_service: web::Data<ServerCibaService>,
    pub(super) ciba_users: web::Data<nazo_postgres::UserRepository>,
    pub(super) ciba_config: web::Data<CibaHttpConfig>,
    pub(super) conformance_leases: web::Data<nazo_postgres::ConformanceLeaseRepository>,
    pub(super) token_issuance_config: web::Data<TokenIssuanceConfig>,
    pub(super) device_service: web::Data<ServerDeviceGrantService>,
    pub(super) device_grants: web::Data<nazo_postgres::AuthorizationFlowRepository>,
    pub(super) device_config: web::Data<DeviceHttpConfig>,
    pub(super) userinfo_endpoint: web::Data<nazo_http_actix::UserinfoEndpoint>,
    pub(super) authorization_config: web::Data<AuthorizationHttpConfig>,
    #[cfg(not(test))]
    pub(super) token_management_endpoint: web::Data<nazo_http_actix::TokenManagementEndpoint>,
    pub(super) authorization_runtime: web::Data<ServerRuntimeModuleRegistry>,
    pub(super) credential_issuer_endpoint: Option<web::Data<CredentialIssuerEndpoint>>,
    pub(super) credential_dataset_admin: Option<web::Data<CredentialDatasetAdminService>>,
    pub(super) presentation_endpoint: Option<web::Data<PresentationEndpoint>>,
    pub(super) client_attestation_validator: Option<Arc<Openid4vcClientAttestationValidator>>,
    pub(super) token_endpoint_handles: web::Data<TokenEndpointHandles>,
}

pub(super) async fn build(startup: &StartupConfiguration) -> anyhow::Result<CoreServices> {
    let settings = startup.settings.as_ref();
    let diesel_db = startup.diesel_db.clone();
    let valkey_connection = startup.valkey_connection.clone();
    let keyset = startup.keyset.clone();
    let runtime_registry = startup.runtime_modules.registry.clone();
    let remote_client_documents = startup.remote_client_documents.clone();

    let metadata_config = MetadataConfig::from(settings);
    let metadata_handles = web::Data::new(nazo_http_actix::MetadataHandles::new(
        metadata_config.endpoint_config(),
        Arc::new(ServerMetadataSnapshotSource::new(
            keyset.clone(),
            runtime_registry.clone(),
        )),
    ));
    let resource_replay_connection = valkey_connection.clone();
    let resource_server_config = ResourceServerConfig::from(settings);
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
            runtime_registry.clone(),
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
    let dynamic_registration_config = DynamicRegistrationConfig::from(settings);
    let dynamic_registration_handles = web::Data::new(dynamic_registration_endpoint(
        dynamic_registration_config,
        nazo_postgres::OAuthClientRepository::new(diesel_db.clone()),
        nazo_postgres::ConformanceLeaseRepository::new(diesel_db.clone()),
        nazo_valkey::RateLimitStore::new(&valkey_connection),
        keyset.clone(),
        runtime_registry.clone(),
        remote_client_documents.clone(),
    ));
    let admin_client_config = web::Data::new(AdminClientConfig::from_settings(&startup.settings));
    let admin_client_service = web::Data::new(ServerAdminClientService::new(
        nazo_postgres::OAuthClientRepository::new(diesel_db.clone()),
        ServerSectorIdentifierResolver,
        ServerAdminClientCrypto::new(keyset.clone()),
        admin_client_policy(&startup.settings),
    ));
    let scim_endpoint_settings = &startup.settings.endpoint;
    let scim_protocol = &startup.settings.protocol;
    let scim_storage = &startup.settings.storage;
    let scim_service = nazo_identity::scim::ScimService::new(
        Arc::new(nazo_postgres::ScimRepository::with_event_retention_seconds(
            diesel_db.clone(),
            scim_storage.scim_event_retention_seconds,
        )),
        Arc::new(nazo_postgres::AuditRepository::new(diesel_db.clone())),
    );
    let scim_client_ip = ClientIpConfig::new(
        &scim_endpoint_settings.trusted_proxy_cidrs,
        scim_endpoint_settings.client_ip_header_mode,
    );
    let scim_endpoint = web::Data::new(
        nazo_http_actix::ScimEndpoint::new(
            scim_service.clone(),
            Arc::new(ServerScimRequestAuthorizer::new(
                scim_service,
                scim_client_ip,
                runtime_registry.clone(),
            )),
            Arc::new(ServerScimCursorProtector::new(
                &scim_protocol.client_secret_pepper,
            )?),
            Arc::new(ServerScimBootstrapPasswordProvider),
        )
        .with_security_events(Arc::new(nazo_scim_events::EventPublisher::new(
            nazo_postgres::ScimEventRepository::new(diesel_db.clone()),
            ServerScimEventSigner::new(keyset.clone()),
            startup.settings.endpoint.issuer.clone(),
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
            startup.token_issuance_response_keys.clone(),
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
    super::super::background::spawn_ciba_ping_worker(
        &valkey_connection,
        &startup.settings,
        startup.runtime_modules.get_ref(),
    )?;
    let ciba_users = web::Data::new(nazo_postgres::UserRepository::new(diesel_db.clone()));
    let ciba_config = web::Data::new(CibaHttpConfig::from(settings));
    let conformance_leases = web::Data::new(nazo_postgres::ConformanceLeaseRepository::new(
        diesel_db.clone(),
    ));
    let token_issuance_config = web::Data::new(TokenIssuanceConfig::from(settings));
    let device_service = web::Data::new(ServerDeviceGrantService::new(
        nazo_valkey::DeviceStore::new(&valkey_connection),
    ));
    let device_grants = web::Data::new(nazo_postgres::AuthorizationFlowRepository::new(
        diesel_db.clone(),
        DEFAULT_TENANT_ID,
    ));
    let device_config = web::Data::new(DeviceHttpConfig::from(settings));
    let userinfo_handles = UserinfoHandles::new(
        nazo_valkey::ReplayStore::new(&valkey_connection),
        keyset.clone(),
        UserinfoConfig::from(settings),
    );
    let userinfo_endpoint = web::Data::new(nazo_http_actix::UserinfoEndpoint::new(Arc::new(
        ServerUserinfoOperations::new(token_service.clone().into_inner(), userinfo_handles),
    )));
    let authorization_config = web::Data::new(AuthorizationHttpConfig::from(settings));
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
        web::Data::from(runtime_registry.clone());

    let openid4vc = openid4vc::build(
        startup,
        &diesel_db,
        &token_service,
        &authorization_service,
        runtime_registry,
        &keyset,
    )
    .await?;
    let openid4vc::Openid4vcServices {
        credential_issuer_endpoint,
        credential_dataset_admin,
        presentation_endpoint,
        client_attestation_validator,
    } = openid4vc;
    let token_endpoint_handles = web::Data::new(TokenEndpointHandles::new(
        TokenCoreHandles {
            token_service: token_service.clone(),
            authorization_service: authorization_service.clone(),
            device_service: device_service.clone(),
        },
        CibaTokenHandles::new(
            ciba_service.clone(),
            ciba_users.clone(),
            conformance_leases.clone(),
            ciba_config.clone(),
        ),
        token_issuance_config.clone(),
        authorization_runtime.clone(),
        remote_client_documents,
        Openid4vcTokenHandles {
            credential_issuer: credential_issuer_endpoint.clone(),
            client_attestation: client_attestation_validator.clone(),
        },
    ));

    Ok(CoreServices {
        metadata_handles,
        resource_server_http_data,
        dynamic_registration_handles,
        admin_client_config,
        admin_client_service,
        scim_endpoint,
        authorization_service,
        token_service,
        ciba_service,
        ciba_users,
        ciba_config,
        conformance_leases,
        token_issuance_config,
        device_service,
        device_grants,
        device_config,
        userinfo_endpoint,
        authorization_config,
        #[cfg(not(test))]
        token_management_endpoint,
        authorization_runtime,
        credential_issuer_endpoint,
        credential_dataset_admin,
        presentation_endpoint,
        client_attestation_validator,
        token_endpoint_handles,
    })
}
