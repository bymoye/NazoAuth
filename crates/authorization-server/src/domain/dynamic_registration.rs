use std::{fmt::Write as _, future::Future, pin::Pin, sync::Arc};

use nazo_http_actix::{
    DynamicRegistrationDependencyError, DynamicRegistrationEndpoint,
    DynamicRegistrationEndpointConfig, DynamicRegistrationFuture,
    DynamicRegistrationRateLimitError, DynamicRegistrationRequestGuard,
};
use serde_json::json;
use sha2::{Digest as _, Sha256};

use crate::adapters::audit::{audit_event, audit_fields};
use crate::adapters::security::{blake3_hex, constant_time_eq, random_urlsafe_token};
use crate::domain::remote_client_documents::RemoteClientDocumentResolver;
use crate::domain::tenancy::DEFAULT_TENANT_ID;
use crate::http::admin::clients::ServerSectorIdentifierResolver;
use crate::runtime_modules::ServerRuntimeModuleRegistry;
use crate::settings::Settings;
use nazo_http_actix::{ClientIpHeaderMode, IpCidr};

const CONFORMANCE_DCR_PROFILE: &str = "oidc-fapi-ciba";

#[derive(Clone)]
#[cfg_attr(test, allow(dead_code))]
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

#[derive(Clone, Copy)]
struct ServerDynamicRegistrationTokens;

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

#[derive(Clone)]
pub(crate) struct ServerDynamicRegistrationRequestGuard {
    rate_limits: nazo_valkey::RateLimitStore,
    window_seconds: u64,
    max_requests: u64,
    runtime_modules: Arc<ServerRuntimeModuleRegistry>,
    conformance_leases: nazo_postgres::ConformanceLeaseRepository,
}

impl ServerDynamicRegistrationRequestGuard {
    pub(crate) fn new(
        rate_limits: nazo_valkey::RateLimitStore,
        config: &DynamicRegistrationConfig,
        runtime_modules: Arc<ServerRuntimeModuleRegistry>,
        conformance_leases: nazo_postgres::ConformanceLeaseRepository,
    ) -> Self {
        Self {
            rate_limits,
            window_seconds: config.rate_limit_window_seconds,
            max_requests: config.rate_limit_max_requests,
            runtime_modules,
            conformance_leases,
        }
    }
}

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

    fn conformance_lease_for_initial_access_token<'a>(
        &'a self,
        token: &'a str,
    ) -> DynamicRegistrationFuture<'a, Option<uuid::Uuid>> {
        Box::pin(async move {
            let token_sha256 = sha256_hex(token.as_bytes());
            self.conformance_leases
                .active_dynamic_registration_lease_id(
                    DEFAULT_TENANT_ID,
                    CONFORMANCE_DCR_PROFILE,
                    &token_sha256,
                )
                .await
                .map_err(|_error| {
                    tracing::warn!("dynamic registration conformance lease lookup failed");
                    DynamicRegistrationDependencyError::Unavailable
                })
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

pub(crate) fn dynamic_registration_endpoint(
    config: DynamicRegistrationConfig,
    clients: nazo_postgres::OAuthClientRepository,
    conformance_leases: nazo_postgres::ConformanceLeaseRepository,
    rate_limits: nazo_valkey::RateLimitStore,
    keyset: nazo_key_management::KeyManager,
    runtime_modules: Arc<ServerRuntimeModuleRegistry>,
    remote_client_documents: Arc<RemoteClientDocumentResolver>,
) -> DynamicRegistrationEndpoint {
    let key_snapshot = keyset.snapshot();
    let crypto = Arc::new(nazo_key_management::ClientRegistrationCrypto::new(keyset));
    let request_guard = Arc::new(ServerDynamicRegistrationRequestGuard::new(
        rate_limits,
        &config,
        runtime_modules,
        conformance_leases,
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
            id_token_signing_algs: key_snapshot.id_token_signing_alg_values_supported(),
            response_signing_algs: key_snapshot.response_signing_alg_values_supported(),
            request_object_encryption_algs: vec!["RSA-OAEP-256"],
            request_object_encryption_encs: vec!["A256GCM"],
        },
        Arc::new(clients),
        Arc::new(ServerSectorIdentifierResolver),
        nazo_http_actix::DynamicRegistrationSecurityServices::new(
            remote_client_documents,
            crypto.clone(),
            crypto,
            Arc::new(ServerDynamicRegistrationTokens),
        ),
        request_guard,
    )
}

fn sha256_hex(value: &[u8]) -> String {
    Sha256::digest(value)
        .iter()
        .fold(String::with_capacity(64), |mut output, byte| {
            write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
            output
        })
}

#[cfg(test)]
#[path = "../../tests/unit/domain/dynamic_registration.rs"]
mod tests;
