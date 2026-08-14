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
mod startup;
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
pub(crate) use startup::run;
#[cfg(test)]
pub(crate) use startup::{load_revocation_policy, read_revocation_snapshot};

use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use actix_files::{Files, NamedFile};
#[cfg(test)]
#[allow(unused_imports)]
use actix_web::{App, middleware::from_fn};
use actix_web::{
    HttpResponse,
    dev::{ServiceRequest, ServiceResponse, fn_service},
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
    Openid4vcRevocationPolicy, Settings, TransportMode, mfa_totp_key_ring,
    token_issuance_response_key_ring,
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

const MAX_REVOCATION_SNAPSHOT_BYTES: u64 = 4 * 1024 * 1024;

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

struct DirectTlsListeners {
    public: ServerConfig,
    mtls_bind: SocketAddr,
    mtls: ServerConfig,
}

fn direct_tls_listeners(
    config: &ConfigSource,
    settings: &Settings,
) -> anyhow::Result<Option<DirectTlsListeners>> {
    if settings.endpoint.transport_mode != TransportMode::DirectTls {
        return Ok(None);
    }
    let required = |key: &str| {
        config
            .optional_string(key)
            .ok_or_else(|| anyhow::anyhow!("{key} is required for direct-tls transport"))
    };
    let mtls_bind: SocketAddr = required("TLS_BIND")?.parse()?;
    let certificate = required("TLS_CERTIFICATE_FILE")?;
    let private_key = required("TLS_PRIVATE_KEY_FILE")?;
    let client_ca = required("TLS_CLIENT_CA_FILE")?;

    validate_tls_private_key_file(&private_key)?;

    let certificates = CertificateDer::pem_file_iter(&certificate)
        .with_context(|| format!("failed to open TLS certificate chain {certificate}"))?
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("failed to parse TLS certificate chain {certificate}"))?;
    if certificates.is_empty() {
        anyhow::bail!("TLS certificate chain {certificate} contains no certificates");
    }
    let (_, leaf) =
        x509_parser::parse_x509_certificate(certificates[0].as_ref()).map_err(|error| {
            anyhow::anyhow!("failed to parse TLS leaf certificate {certificate}: {error}")
        })?;
    if !leaf.validity().is_valid() {
        anyhow::bail!("TLS leaf certificate {certificate} is not currently valid");
    }
    validate_tls_server_names(
        &certificates[0],
        &certificate,
        [
            &settings.endpoint.issuer,
            &settings.endpoint.mtls_endpoint_base_url,
        ],
    )?;
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
    let public = ServerConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(rustls::DEFAULT_VERSIONS)
        .context("failed to configure TLS protocol versions")?
        .with_no_client_auth()
        .with_single_cert(certificates.clone(), private_key.clone_key())
        .context("TLS certificate chain does not match the configured private key")?;
    let mtls = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(rustls::DEFAULT_VERSIONS)
        .context("failed to configure TLS protocol versions")?
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(certificates, private_key)
        .context("TLS certificate chain does not match the configured private key")?;
    Ok(Some(DirectTlsListeners {
        public,
        mtls_bind,
        mtls,
    }))
}

fn validate_tls_server_names<'a>(
    certificate: &'a CertificateDer<'a>,
    certificate_path: &str,
    urls: impl IntoIterator<Item = &'a String>,
) -> anyhow::Result<()> {
    let certificate = webpki::EndEntityCert::try_from(certificate).map_err(|error| {
        anyhow::anyhow!("invalid TLS leaf certificate {certificate_path}: {error}")
    })?;
    for url in urls {
        let host = url::Url::parse(url)
            .with_context(|| format!("invalid TLS endpoint URL {url}"))?
            .host_str()
            .ok_or_else(|| anyhow::anyhow!("TLS endpoint URL {url} has no host"))?
            .to_owned();
        let server_name = rustls::pki_types::ServerName::try_from(host.clone())
            .map_err(|error| anyhow::anyhow!("invalid TLS endpoint host {host}: {error}"))?;
        certificate
            .verify_is_valid_for_subject_name(&server_name)
            .map_err(|error| {
                anyhow::anyhow!(
                    "TLS leaf certificate {certificate_path} is not valid for endpoint host {host}: {error}"
                )
            })?;
    }
    Ok(())
}

fn validate_tls_private_key_file(path: &str) -> anyhow::Result<()> {
    let metadata = std::fs::metadata(path)
        .with_context(|| format!("failed to inspect TLS private key {path}"))?;
    if !metadata.is_file() {
        anyhow::bail!("TLS private key {path} is not a regular file");
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        let mode = metadata.permissions().mode();
        if mode & 0o077 != 0 {
            anyhow::bail!(
                "TLS private key {path} must not be accessible by group or other users (mode {:o})",
                mode & 0o777
            );
        }
    }

    Ok(())
}

#[cfg(test)]
#[path = "../../tests/unit/bootstrap.rs"]
mod tests;
