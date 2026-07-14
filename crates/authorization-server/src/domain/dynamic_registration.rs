#[cfg(not(test))]
use std::{future::Future, pin::Pin, sync::Arc};

#[cfg(not(test))]
use nazo_http_actix::{
    DynamicRegistrationEndpoint, DynamicRegistrationEndpointConfig,
    DynamicRegistrationRateLimitError, DynamicRegistrationRequestGuard,
};
#[cfg(not(test))]
use serde_json::json;

#[cfg(not(test))]
use crate::adapters::audit::{audit_event, audit_fields};
#[cfg(not(test))]
use crate::adapters::security::{blake3_hex, constant_time_eq, random_urlsafe_token};
#[cfg(not(test))]
use crate::http::admin::clients::ServerSectorIdentifierResolver;
use crate::http::client_ip::{ClientIpHeaderMode, IpCidr};
#[cfg(not(test))]
use crate::runtime_modules::ServerRuntimeModuleRegistry;
use crate::settings::Settings;

#[derive(Clone)]
pub(crate) struct DynamicRegistrationConfig {
    pub(crate) issuer: String,
    pub(crate) default_audience: String,
    pub(crate) pairwise_subject_secret: Option<String>,
    pub(crate) client_secret_pepper: String,
    pub(crate) initial_access_token: Option<String>,
    pub(crate) rate_limit_window_seconds: u64,
    pub(crate) rate_limit_max_requests: u64,
    pub(crate) client_ip_header_mode: ClientIpHeaderMode,
    pub(crate) trusted_proxy_cidrs: Vec<IpCidr>,
}

impl From<&Settings> for DynamicRegistrationConfig {
    fn from(settings: &Settings) -> Self {
        let endpoint = &settings.endpoint;
        let identity = &settings.identity;
        let modules = &settings.modules;
        let protocol = &settings.protocol;
        Self {
            issuer: endpoint.issuer.clone(),
            default_audience: protocol.default_audience.to_owned(),
            pairwise_subject_secret: protocol
                .pairwise_subject_secret
                .as_deref()
                .map(ToOwned::to_owned),
            client_secret_pepper: protocol.client_secret_pepper.to_owned(),
            initial_access_token: modules
                .dynamic_client_registration_initial_access_token
                .as_deref()
                .map(ToOwned::to_owned),
            rate_limit_window_seconds: identity.rate_limit.window_seconds,
            rate_limit_max_requests: identity.rate_limit.token_management_max_requests,
            client_ip_header_mode: endpoint.client_ip_header_mode,
            trusted_proxy_cidrs: endpoint.trusted_proxy_cidrs.to_vec(),
        }
    }
}

#[cfg(test)]
#[derive(Clone)]
pub(crate) struct DynamicRegistrationHandles {
    pub(crate) config: DynamicRegistrationConfig,
    pub(crate) clients: nazo_postgres::OAuthClientRepository,
    pub(crate) rate_limits: nazo_valkey::RateLimitStore,
    pub(crate) keyset: nazo_key_management::KeyManager,
    pub(crate) enabled: bool,
}

#[cfg(test)]
impl DynamicRegistrationHandles {
    pub(crate) fn accepts_new_requests(&self) -> bool {
        self.enabled
    }

    pub(crate) fn from_app_state(state: &super::TestAppState) -> Self {
        Self {
            config: DynamicRegistrationConfig::from(state.settings.as_ref()),
            clients: nazo_postgres::OAuthClientRepository::new(state.diesel_db.clone()),
            rate_limits: nazo_valkey::RateLimitStore::new(&state.valkey_connection()),
            keyset: state.keyset.clone(),
            enabled: state.settings.modules.enable_dynamic_client_registration,
        }
    }
}

#[cfg(not(test))]
#[derive(Clone, Copy)]
struct ServerDynamicRegistrationTokens;

#[cfg(not(test))]
impl nazo_auth::DynamicRegistrationSecretPort for ServerDynamicRegistrationTokens {
    fn random_token(&self) -> String {
        random_urlsafe_token()
    }

    fn token_hash(&self, token: &str) -> String {
        blake3_hex(token)
    }

    fn constant_time_eq(&self, left: &[u8], right: &[u8]) -> bool {
        constant_time_eq(left, right)
    }
}

#[cfg(not(test))]
#[derive(Clone)]
pub(crate) struct ServerDynamicRegistrationRequestGuard {
    rate_limits: nazo_valkey::RateLimitStore,
    window_seconds: u64,
    max_requests: u64,
    runtime_modules: Arc<ServerRuntimeModuleRegistry>,
}

#[cfg(not(test))]
impl ServerDynamicRegistrationRequestGuard {
    pub(crate) fn new(
        rate_limits: nazo_valkey::RateLimitStore,
        config: &DynamicRegistrationConfig,
        runtime_modules: Arc<ServerRuntimeModuleRegistry>,
    ) -> Self {
        Self {
            rate_limits,
            window_seconds: config.rate_limit_window_seconds,
            max_requests: config.rate_limit_max_requests,
            runtime_modules,
        }
    }
}

#[cfg(not(test))]
impl DynamicRegistrationRequestGuard for ServerDynamicRegistrationRequestGuard {
    fn accepts_new_requests(&self) -> bool {
        nazo_auth::module_admissible(
            &self.runtime_modules.snapshot(),
            nazo_runtime_modules::ModuleId::DynamicClientRegistration,
            nazo_auth::CapabilityAdmission::NewRequest,
        )
    }

    fn enforce_rate_limit<'a>(
        &'a self,
        source_ip: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(), DynamicRegistrationRateLimitError>> + Send + 'a>>
    {
        Box::pin(async move {
            let count = self
                .rate_limits
                .increment(
                    nazo_valkey::RateDimension::TokenManagement,
                    source_ip,
                    self.window_seconds,
                )
                .await
                .map_err(|error| {
                    tracing::warn!(%error, "dynamic registration rate-limit increment failed");
                    DynamicRegistrationRateLimitError::Unavailable
                })?;
            if count > self.max_requests {
                return Err(DynamicRegistrationRateLimitError::Limited {
                    retry_after_seconds: self.window_seconds,
                });
            }
            Ok(())
        })
    }

    fn audit(&self, event: &'static str, client: &nazo_auth::OAuthClient, source_ip: &str) {
        audit_event(
            event,
            audit_fields(&[
                ("client_id", json!(client.client_id)),
                ("client_type", json!(client.client_type)),
                ("grant_types", json!(client.grant_types)),
                (
                    "token_endpoint_auth_method",
                    json!(client.token_endpoint_auth_method),
                ),
                ("source_ip_hash", json!(blake3_hex(source_ip))),
            ]),
        );
    }
}

#[cfg(not(test))]
pub(crate) fn dynamic_registration_endpoint(
    config: DynamicRegistrationConfig,
    clients: nazo_postgres::OAuthClientRepository,
    rate_limits: nazo_valkey::RateLimitStore,
    keyset: nazo_key_management::KeyManager,
    runtime_modules: Arc<ServerRuntimeModuleRegistry>,
) -> DynamicRegistrationEndpoint {
    let crypto = Arc::new(nazo_key_management::ClientRegistrationCrypto::new(keyset));
    let request_guard = Arc::new(ServerDynamicRegistrationRequestGuard::new(
        rate_limits,
        &config,
        runtime_modules,
    ));
    DynamicRegistrationEndpoint::new(
        DynamicRegistrationEndpointConfig {
            issuer: config.issuer,
            default_audience: config.default_audience,
            pairwise_subject_secret: config.pairwise_subject_secret,
            client_secret_pepper: config.client_secret_pepper,
            initial_access_token: config.initial_access_token,
            client_ip_header_mode: config.client_ip_header_mode,
            trusted_proxy_cidrs: config.trusted_proxy_cidrs,
        },
        Arc::new(clients),
        Arc::new(ServerSectorIdentifierResolver),
        crypto.clone(),
        crypto,
        Arc::new(ServerDynamicRegistrationTokens),
        request_guard,
    )
}
