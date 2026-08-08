//! Runtime settings.
// Settings are built from the startup configuration snapshot.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use anyhow::bail;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use nazo_auth::{
    is_loopback_http_url, validate_cors_origin, validate_frontend_base_url, validate_issuer_url,
    validate_protected_resource_identifier,
};
use url::Url;

use crate::adapters::security::LOCAL_DEVELOPMENT_CLIENT_SECRET_PEPPER;
use crate::config::{ConfigSource, DEFAULT_DATA_DIR};
use crate::http::mtls::MtlsCertificateSourceMode;
use nazo_http_actix::{ClientIpHeaderMode, IpCidr, parse_trusted_proxy_cidrs};

mod config_loader;
mod email;
mod federation;
mod passkey;
mod profile;
mod rate_limit;

pub(crate) use email::{EmailDelivery, EmailSettings, SmtpEmailSettings, SmtpTlsMode};
pub(crate) use federation::{
    ExternalLoginProvider, ExternalLoginProviderAdapter, FederationProviderRegistry,
    FederationSettings, OidcFederationSettings, SamlGatewaySettings, SocialProviderKind,
    SocialProviderSettings,
};
pub(crate) use passkey::PasskeySettings;
pub(crate) use profile::{
    AuthorizationServerProfile, CibaSecurityProfile, DpopNoncePolicy, RequestObjectJtiPolicy,
    SubjectType,
};
pub(crate) use rate_limit::RateLimitSettings;

/// OAuth service runtime parameters.
#[derive(Clone)]
pub(crate) struct Settings {
    pub(crate) endpoint: EndpointSettings,
    pub(crate) protocol: ProtocolSettings,
    pub(crate) session: SessionSettings,
    pub(crate) storage: StorageSettings,
    pub(crate) identity: IdentityRuntimeSettings,
    pub(crate) keys: KeyManagementSettings,
    pub(crate) modules: ModuleSettings,
    pub(crate) device: DeviceGrantSettings,
    pub(crate) ciba: CibaSettings,
    pub(crate) openid4vc: Openid4vcSettings,
}

#[derive(Clone)]
pub(crate) struct EndpointSettings {
    pub(crate) issuer: String,
    pub(crate) mtls_endpoint_base_url: String,
    pub(crate) frontend_base_url: String,
    pub(crate) cors_allowed_origins: Vec<String>,
    pub(crate) trusted_proxy_cidrs: Vec<IpCidr>,
    pub(crate) client_ip_header_mode: ClientIpHeaderMode,
    pub(crate) mtls_certificate_source: MtlsCertificateSourceMode,
}

#[derive(Clone)]
pub(crate) struct ProtocolSettings {
    pub(crate) default_audience: String,
    pub(crate) protected_resource_identifier: String,
    pub(crate) authorization_server_profile: AuthorizationServerProfile,
    pub(crate) ciba_security_profile: CibaSecurityProfile,
    pub(crate) dpop_nonce_policy: DpopNoncePolicy,
    pub(crate) fapi_resource_dpop_nonce_policy: DpopNoncePolicy,
    pub(crate) request_object_jti_policy: RequestObjectJtiPolicy,
    pub(crate) auth_code_ttl_seconds: u64,
    pub(crate) access_token_ttl_seconds: i64,
    pub(crate) id_token_ttl_seconds: i64,
    pub(crate) refresh_token_ttl_seconds: i64,
    pub(crate) client_secret_pepper: String,
    pub(crate) subject_type: SubjectType,
    pub(crate) pairwise_subject_secret: Option<String>,
    pub(crate) par_ttl_seconds: u64,
    pub(crate) require_pushed_authorization_requests: bool,
    pub(crate) fapi_http_signature_max_age_seconds: i64,
}

#[derive(Clone)]
pub(crate) struct SessionSettings {
    pub(crate) session_cookie_name: String,
    pub(crate) csrf_cookie_name: String,
    pub(crate) cookie_secure: bool,
    pub(crate) session_ttl_seconds: u64,
    pub(crate) pending_mfa_session_ttl_seconds: u64,
}

#[derive(Clone)]
pub(crate) struct StorageSettings {
    pub(crate) avatar_max_bytes: usize,
    pub(crate) client_delivery_ttl_seconds: u64,
    pub(crate) data_dir: PathBuf,
    pub(crate) avatar_storage_dir: PathBuf,
    pub(crate) scim_event_retention_seconds: u64,
}

#[derive(Clone)]
pub(crate) struct IdentityRuntimeSettings {
    pub(crate) rate_limit: RateLimitSettings,
    pub(crate) email: EmailSettings,
    pub(crate) email_code_dev_response_enabled: bool,
    pub(crate) passkey: PasskeySettings,
    pub(crate) federation: FederationSettings,
}

#[derive(Clone)]
pub(crate) struct KeyManagementSettings {
    pub(crate) jwk_keys_dir: PathBuf,
    pub(crate) signing_external_command: Vec<String>,
    pub(crate) signing_external_timeout_ms: u64,
    pub(crate) signing_key_rotation_interval_seconds: i64,
    pub(crate) signing_key_prepublish_seconds: i64,
}

#[derive(Clone)]
pub(crate) struct ModuleSettings {
    // These fields are retained as an internal fixture seam for endpoint
    // tests. They are no longer configuration inputs; runtime module state in
    // the database is the sole authority for these stable capabilities.
    #[allow(dead_code)]
    pub(crate) enable_request_object: bool,
    #[allow(dead_code)]
    pub(crate) enable_par_request_object: bool,
    pub(crate) enable_authorization_details: bool,
    #[allow(dead_code)]
    pub(crate) enable_device_authorization_grant: bool,
    #[allow(dead_code)]
    pub(crate) enable_dynamic_client_registration: bool,
    #[allow(dead_code)]
    pub(crate) enable_frontchannel_logout: bool,
    #[allow(dead_code)]
    pub(crate) enable_session_management: bool,
    #[allow(dead_code)]
    pub(crate) enable_ciba: bool,
    pub(crate) enable_native_sso: bool,
    pub(crate) enable_fapi_http_signatures: bool,
    pub(crate) enable_scim_security_events: bool,
    pub(crate) enable_openid4vci_issuer: bool,
    pub(crate) enable_openid4vp_verifier: bool,
    pub(crate) dynamic_client_registration_initial_access_token: Option<String>,
    pub(crate) remote_client_document_private_origins: Vec<String>,
    pub(crate) backchannel_logout_private_origins: Vec<String>,
}

#[derive(Clone)]
pub(crate) struct DeviceGrantSettings {
    pub(crate) device_authorization_ttl_seconds: u64,
    pub(crate) device_authorization_poll_interval_seconds: u64,
}

#[derive(Clone)]
pub(crate) struct CibaSettings {
    pub(crate) ciba_auth_req_id_ttl_seconds: u64,
    pub(crate) ciba_poll_interval_seconds: u64,
    pub(crate) ciba_automated_decision_token: Option<String>,
    pub(crate) ciba_automated_decision_mode: CibaAutomatedDecisionMode,
    pub(crate) ciba_notification_private_origins: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CibaAutomatedDecisionMode {
    Disabled,
    Header,
    QueryParameter,
}

impl CibaAutomatedDecisionMode {
    fn from_config(config: &ConfigSource) -> anyhow::Result<Self> {
        match config
            .string("CIBA_AUTOMATED_DECISION_MODE", "disabled")
            .as_str()
        {
            "disabled" => Ok(Self::Disabled),
            "header" => Ok(Self::Header),
            "query" => Ok(Self::QueryParameter),
            value => bail!(
                "CIBA_AUTOMATED_DECISION_MODE must be disabled, header, or query; got {value}"
            ),
        }
    }
}

#[derive(Clone)]
pub(crate) struct Openid4vcSettings {
    pub(crate) signing_certificate_chain_file: Option<PathBuf>,
    pub(crate) trust_anchors_file: Option<PathBuf>,
    pub(crate) data_encryption_key: Option<[u8; 32]>,
    pub(crate) client_attestation_jwks: Option<serde_json::Value>,
    pub(crate) key_attestation_jwks: Option<serde_json::Value>,
    pub(crate) client_attestation_issuer: Option<String>,
    pub(crate) credential_configurations:
        BTreeMap<String, nazo_openid4vci::CredentialConfiguration>,
    pub(crate) deferred_credential_configurations: std::collections::BTreeSet<String>,
    pub(crate) issuer_management_token: Option<String>,
    pub(crate) wallet_authorization_origins: Vec<String>,
    pub(crate) verifier_management_token: Option<String>,
    pub(crate) transaction_ttl_seconds: u64,
    pub(crate) revocation_policy: Openid4vcRevocationPolicy,
    pub(crate) revocation_snapshot_file: Option<PathBuf>,
    pub(crate) revocation_reload_interval_seconds: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Openid4vcRevocationPolicy {
    Disabled,
    Optional,
    Required,
}

impl Openid4vcRevocationPolicy {
    fn from_config(config: &ConfigSource) -> anyhow::Result<Self> {
        match config
            .string("OPENID4VC_REVOCATION_POLICY", "disabled")
            .as_str()
        {
            "disabled" => Ok(Self::Disabled),
            "optional" => Ok(Self::Optional),
            "required" => Ok(Self::Required),
            value => bail!(
                "OPENID4VC_REVOCATION_POLICY must be disabled, optional, or required; got {value}"
            ),
        }
    }
}

impl Settings {
    pub(crate) fn key_settings(&self) -> nazo_key_management::KeySettings {
        nazo_key_management::KeySettings {
            keys_dir: self.keys.jwk_keys_dir.clone(),
            external_command: self.keys.signing_external_command.clone(),
            external_timeout: std::time::Duration::from_millis(
                self.keys.signing_external_timeout_ms,
            ),
            rotation_interval: chrono::Duration::seconds(
                self.keys.signing_key_rotation_interval_seconds,
            ),
            prepublish_window: chrono::Duration::seconds(self.keys.signing_key_prepublish_seconds),
            verification_grace: chrono::Duration::seconds(
                self.protocol
                    .access_token_ttl_seconds
                    .max(self.protocol.id_token_ttl_seconds),
            ),
        }
    }
}

pub(crate) fn mfa_totp_key_ring(
    config: &ConfigSource,
) -> anyhow::Result<Option<nazo_identity::ports::MfaTotpKeyRing>> {
    let current_key = parse_optional_32_byte_key(config, "MFA_TOTP_ENCRYPTION_KEY")?;
    let current_key_id = config.optional_string("MFA_TOTP_ENCRYPTION_KEY_ID");
    let previous_key = parse_optional_32_byte_key(config, "MFA_TOTP_PREVIOUS_ENCRYPTION_KEY")?;
    let previous_key_id = config.optional_string("MFA_TOTP_PREVIOUS_ENCRYPTION_KEY_ID");
    validate_mfa_totp_key_pair(
        "MFA_TOTP_ENCRYPTION_KEY",
        current_key,
        "MFA_TOTP_ENCRYPTION_KEY_ID",
        current_key_id.as_deref(),
    )?;
    validate_mfa_totp_key_pair(
        "MFA_TOTP_PREVIOUS_ENCRYPTION_KEY",
        previous_key,
        "MFA_TOTP_PREVIOUS_ENCRYPTION_KEY_ID",
        previous_key_id.as_deref(),
    )?;
    if current_key.is_none() && (previous_key.is_some() || previous_key_id.is_some()) {
        bail!(
            "MFA_TOTP_ENCRYPTION_KEY is required when a previous TOTP encryption key is configured"
        );
    }
    if let (Some(current), Some(previous)) = (current_key_id.as_deref(), previous_key_id.as_deref())
        && current == previous
    {
        bail!("MFA_TOTP_ENCRYPTION_KEY_ID and MFA_TOTP_PREVIOUS_ENCRYPTION_KEY_ID must differ");
    }
    let Some(current_key) = current_key else {
        return Ok(None);
    };
    let current = nazo_identity::ports::MfaTotpKey::new(
        current_key_id.expect("validated MFA TOTP current key id"),
        current_key,
    )?;
    let previous = previous_key
        .zip(previous_key_id)
        .map(|(key, id)| nazo_identity::ports::MfaTotpKey::new(id, key))
        .transpose()?;
    Ok(Some(nazo_identity::ports::MfaTotpKeyRing::new(
        current, previous,
    )?))
}

/// Parses the independent response-envelope key ring used by durable token
/// issuance recovery. The current key/id pair is mandatory for the running
/// server; the previous pair is optional only during a bounded rotation
/// overlap. `Settings::from_config` calls the optional validator so malformed
/// values fail early, while bootstrap calls this strict function before
/// constructing the token repository.
pub(crate) fn token_issuance_response_key_ring(
    config: &ConfigSource,
) -> anyhow::Result<nazo_postgres::TokenIssuanceResponseKeyRing> {
    let current_key = parse_required_32_byte_key(config, "TOKEN_ISSUANCE_RESPONSE_ENCRYPTION_KEY")?;
    let current_id = config.required_string("TOKEN_ISSUANCE_RESPONSE_ENCRYPTION_KEY_ID")?;
    let previous_key =
        parse_optional_32_byte_key(config, "TOKEN_ISSUANCE_RESPONSE_PREVIOUS_ENCRYPTION_KEY")?;
    let previous_id = config.optional_string("TOKEN_ISSUANCE_RESPONSE_PREVIOUS_ENCRYPTION_KEY_ID");
    if previous_key.is_some() != previous_id.is_some() {
        bail!(
            "TOKEN_ISSUANCE_RESPONSE_PREVIOUS_ENCRYPTION_KEY and TOKEN_ISSUANCE_RESPONSE_PREVIOUS_ENCRYPTION_KEY_ID must be configured together"
        );
    }
    let previous = previous_key.zip(previous_id).map(|(key, id)| (id, key));
    nazo_postgres::TokenIssuanceResponseKeyRing::new(current_id, current_key, previous)
        .map_err(anyhow::Error::from)
}

fn validate_optional_token_issuance_response_key_config(
    config: &ConfigSource,
) -> anyhow::Result<()> {
    let current_key = config.optional_string("TOKEN_ISSUANCE_RESPONSE_ENCRYPTION_KEY");
    let current_id = config.optional_string("TOKEN_ISSUANCE_RESPONSE_ENCRYPTION_KEY_ID");
    let previous_key = config.optional_string("TOKEN_ISSUANCE_RESPONSE_PREVIOUS_ENCRYPTION_KEY");
    let previous_id = config.optional_string("TOKEN_ISSUANCE_RESPONSE_PREVIOUS_ENCRYPTION_KEY_ID");
    if current_key.is_none()
        && current_id.is_none()
        && previous_key.is_none()
        && previous_id.is_none()
    {
        return Ok(());
    }
    let _ = token_issuance_response_key_ring(config)?;
    Ok(())
}

fn parse_required_32_byte_key(
    config: &ConfigSource,
    name: &'static str,
) -> anyhow::Result<[u8; 32]> {
    let value = config.required_string(name)?;
    let decoded = URL_SAFE_NO_PAD.decode(value).map_err(anyhow::Error::from)?;
    <[u8; 32]>::try_from(decoded)
        .map_err(|_| anyhow::anyhow!("{name} must decode to exactly 32 bytes"))
}

fn parse_optional_32_byte_key(
    config: &ConfigSource,
    name: &'static str,
) -> anyhow::Result<Option<[u8; 32]>> {
    config
        .optional_string(name)
        .map(|value| URL_SAFE_NO_PAD.decode(value).map_err(anyhow::Error::from))
        .transpose()?
        .map(|value| {
            <[u8; 32]>::try_from(value)
                .map_err(|_| anyhow::anyhow!("{name} must decode to exactly 32 bytes"))
        })
        .transpose()
}

fn validate_mfa_totp_key_pair(
    key_name: &'static str,
    key: Option<[u8; 32]>,
    id_name: &'static str,
    id: Option<&str>,
) -> anyhow::Result<()> {
    if key.is_some() != id.is_some() {
        bail!("{key_name} and {id_name} must be configured together");
    }
    if id.is_some_and(|value| value.len() > 128) {
        bail!("{id_name} must be at most 128 bytes");
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum AttestationTrustPurpose {
    Client,
    HolderKey,
}

fn parse_attestation_jwk_set(
    config: &ConfigSource,
    key: &'static str,
    purpose: AttestationTrustPurpose,
) -> anyhow::Result<Option<serde_json::Value>> {
    let Some(encoded) = config.optional_string(key) else {
        return Ok(None);
    };
    let jwks = serde_json::from_str::<serde_json::Value>(&encoded)?;
    let keys = jwks
        .get("keys")
        .and_then(serde_json::Value::as_array)
        .filter(|keys| !keys.is_empty())
        .ok_or_else(|| anyhow::anyhow!("{key} must be a non-empty JWK Set"))?;
    let mut key_ids = BTreeSet::new();
    for jwk in keys {
        let object = jwk
            .as_object()
            .ok_or_else(|| anyhow::anyhow!("{key} must contain JWK objects"))?;
        if ["d", "p", "q", "dp", "dq", "qi", "oth", "k"]
            .iter()
            .any(|name| object.contains_key(*name))
        {
            bail!("{key} must contain public verification keys only");
        }
        let kid = object
            .get("kid")
            .and_then(serde_json::Value::as_str)
            .filter(|kid| !kid.is_empty())
            .ok_or_else(|| anyhow::anyhow!("{key} keys must have a non-empty kid"))?;
        if !key_ids.insert(kid) {
            bail!("{key} must not contain duplicate kid values");
        }
        let supported = match (
            purpose,
            object.get("kty").and_then(serde_json::Value::as_str),
            object.get("crv").and_then(serde_json::Value::as_str),
        ) {
            (AttestationTrustPurpose::Client, Some("EC"), Some("P-256")) => {
                object.get("x").is_some_and(serde_json::Value::is_string)
                    && object.get("y").is_some_and(serde_json::Value::is_string)
            }
            (AttestationTrustPurpose::HolderKey, Some("EC"), Some("P-256")) => {
                object.get("x").is_some_and(serde_json::Value::is_string)
                    && object.get("y").is_some_and(serde_json::Value::is_string)
            }
            (AttestationTrustPurpose::HolderKey, Some("OKP"), Some("Ed25519")) => {
                object.get("x").is_some_and(serde_json::Value::is_string)
            }
            _ => false,
        };
        if !supported {
            let purpose = match purpose {
                AttestationTrustPurpose::Client => "client attestation",
                AttestationTrustPurpose::HolderKey => "holder key attestation",
            };
            bail!("{key} contains a key unsupported for {purpose}");
        }
    }
    Ok(Some(jwks))
}

pub(super) fn positive_u64(
    config: &ConfigSource,
    key: &str,
    default: u64,
    label: &str,
) -> anyhow::Result<u64> {
    let value = config.parse(key, default)?;
    if value == 0 {
        bail!("{label} must be positive");
    }
    Ok(value)
}

pub(super) fn positive_i64(
    config: &ConfigSource,
    key: &str,
    default: i64,
    label: &str,
) -> anyhow::Result<i64> {
    let value = config.parse(key, default)?;
    if value <= 0 {
        bail!("{label} must be positive");
    }
    Ok(value)
}

fn url_origin(value: &str) -> anyhow::Result<String> {
    let url = Url::parse(value).map_err(|_| anyhow::anyhow!("PUBLIC_BASE_URL must be absolute"))?;
    let Some(host) = url.host_str() else {
        bail!("PUBLIC_BASE_URL must include host");
    };
    let mut origin = format!("{}://{}", url.scheme(), host);
    if let Some(port) = url.port() {
        origin.push(':');
        origin.push_str(&port.to_string());
    }
    Ok(origin)
}

fn parse_signing_external_command(value: Option<String>) -> Vec<String> {
    value
        .map(|value| {
            value
                .split(',')
                .map(str::trim)
                .filter(|part| !part.is_empty())
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

pub(crate) fn key_settings_from_config(
    config: &ConfigSource,
) -> anyhow::Result<nazo_key_management::KeySettings> {
    let rotation_interval_seconds =
        config.parse("SIGNING_KEY_ROTATION_INTERVAL_SECONDS", 7_776_000)?;
    let prepublish_seconds = config.parse("SIGNING_KEY_PREPUBLISH_SECONDS", 86_400)?;
    if rotation_interval_seconds <= 0 {
        bail!("SIGNING_KEY_ROTATION_INTERVAL_SECONDS must be positive");
    }
    if prepublish_seconds <= 0 {
        bail!("SIGNING_KEY_PREPUBLISH_SECONDS must be positive");
    }
    if prepublish_seconds >= rotation_interval_seconds {
        bail!(
            "SIGNING_KEY_PREPUBLISH_SECONDS must be less than SIGNING_KEY_ROTATION_INTERVAL_SECONDS"
        );
    }
    let data_dir = config.persistent_path("DATA_DIR", Some(DEFAULT_DATA_DIR))?;
    let access_token_ttl_seconds = positive_i64(
        config,
        "ACCESS_TOKEN_TTL_SECONDS",
        300,
        "ACCESS_TOKEN_TTL_SECONDS",
    )?;
    let id_token_ttl_seconds =
        positive_i64(config, "ID_TOKEN_TTL_SECONDS", 600, "ID_TOKEN_TTL_SECONDS")?;
    Ok(nazo_key_management::KeySettings {
        keys_dir: match config.optional_string("JWK_KEYS_DIR") {
            Some(_) => config.persistent_path("JWK_KEYS_DIR", None)?,
            None => data_dir.join("keys"),
        },
        external_command: parse_signing_external_command(
            config.optional_string("SIGNING_EXTERNAL_COMMAND"),
        ),
        external_timeout: std::time::Duration::from_millis(
            config.parse("SIGNING_EXTERNAL_TIMEOUT_MS", 2_000)?,
        ),
        rotation_interval: chrono::Duration::seconds(rotation_interval_seconds),
        prepublish_window: chrono::Duration::seconds(prepublish_seconds),
        verification_grace: chrono::Duration::seconds(
            access_token_ttl_seconds.max(id_token_ttl_seconds),
        ),
    })
}

fn default_protected_resource_identifier(issuer: &str) -> String {
    format!("{}/fapi/resource", issuer.trim_end_matches('/'))
}

#[cfg(test)]
#[path = "../tests/unit/settings.rs"]
mod tests;
