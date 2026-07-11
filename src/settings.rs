//! Runtime settings.
// Settings are built from the startup configuration snapshot.

use std::path::PathBuf;

use anyhow::bail;
use url::Url;

use crate::config::ConfigSource;
use crate::support::{
    ClientIpHeaderMode, IpCidr, LOCAL_DEVELOPMENT_CLIENT_SECRET_PEPPER, is_loopback_http_url,
    parse_trusted_proxy_cidrs, validate_cors_origin, validate_frontend_base_url,
    validate_issuer_url, validate_protected_resource_identifier,
};

mod email;
mod federation;
mod passkey;
mod profile;
mod rate_limit;

pub(crate) use email::{EmailDelivery, EmailSettings, SmtpEmailSettings, SmtpTlsMode};
#[cfg(test)]
// provider registry 在生产路径通过 FederationSettings 持有；测试夹具需要直接构造。
pub(crate) use federation::FederationProviderRegistry;
pub(crate) use federation::{
    ExternalLoginProvider, ExternalLoginProviderAdapter, FederationSettings,
    OidcFederationSettings, SamlGatewaySettings, SocialProviderKind, SocialProviderSettings,
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
    pub(crate) issuer: String,
    pub(crate) mtls_endpoint_base_url: String,
    pub(crate) frontend_base_url: String,
    pub(crate) cors_allowed_origins: Vec<String>,
    pub(crate) default_audience: String,
    pub(crate) protected_resource_identifier: String,
    pub(crate) authorization_server_profile: AuthorizationServerProfile,
    pub(crate) ciba_security_profile: CibaSecurityProfile,
    pub(crate) dpop_nonce_policy: DpopNoncePolicy,
    pub(crate) request_object_jti_policy: RequestObjectJtiPolicy,
    pub(crate) session_cookie_name: String,
    pub(crate) csrf_cookie_name: String,
    pub(crate) cookie_secure: bool,
    pub(crate) session_ttl_seconds: u64,
    pub(crate) auth_code_ttl_seconds: u64,
    pub(crate) access_token_ttl_seconds: i64,
    pub(crate) id_token_ttl_seconds: i64,
    pub(crate) refresh_token_ttl_seconds: i64,
    pub(crate) avatar_max_bytes: usize,
    pub(crate) client_delivery_ttl_seconds: u64,
    pub(crate) client_secret_pepper: String,
    pub(crate) rate_limit: RateLimitSettings,
    pub(crate) email: EmailSettings,
    pub(crate) email_code_dev_response_enabled: bool,
    pub(crate) avatar_storage_dir: PathBuf,
    pub(crate) jwk_keys_dir: PathBuf,
    pub(crate) signing_external_command: Vec<String>,
    pub(crate) signing_external_timeout_ms: u64,
    pub(crate) signing_key_rotation_interval_seconds: i64,
    pub(crate) signing_key_prepublish_seconds: i64,
    pub(crate) trusted_proxy_cidrs: Vec<IpCidr>,
    pub(crate) client_ip_header_mode: ClientIpHeaderMode,
    pub(crate) subject_type: SubjectType,
    pub(crate) pairwise_subject_secret: Option<String>,
    pub(crate) par_ttl_seconds: u64,
    pub(crate) require_pushed_authorization_requests: bool,
    pub(crate) scim_bearer_token: Option<String>,
    pub(crate) passkey: PasskeySettings,
    pub(crate) federation: FederationSettings,
    pub(crate) enable_request_object: bool,
    pub(crate) enable_request_uri_parameter: bool,
    pub(crate) enable_par_request_object: bool,
    pub(crate) enable_authorization_details: bool,
    pub(crate) enable_legacy_audience_param: bool,
    pub(crate) enable_device_authorization_grant: bool,
    pub(crate) enable_dynamic_client_registration: bool,
    pub(crate) enable_frontchannel_logout: bool,
    pub(crate) enable_session_management: bool,
    pub(crate) enable_ciba: bool,
    pub(crate) enable_native_sso: bool,
    pub(crate) dynamic_client_registration_initial_access_token: Option<String>,
    pub(crate) device_authorization_ttl_seconds: u64,
    pub(crate) device_authorization_poll_interval_seconds: u64,
    pub(crate) ciba_auth_req_id_ttl_seconds: u64,
    pub(crate) ciba_poll_interval_seconds: u64,
    pub(crate) ciba_automated_decision_token: Option<String>,
}

impl Settings {
    /// Builds settings from the startup configuration source.
    pub(crate) fn from_config(config: &ConfigSource) -> anyhow::Result<Self> {
        let public_base_url = config.string("PUBLIC_BASE_URL", "http://127.0.0.1:8000");
        validate_issuer_url(&public_base_url)?;
        let public_origin = url_origin(&public_base_url)?;

        let issuer = config.string("ISSUER", &public_base_url);
        validate_issuer_url(&issuer)?;
        let mtls_endpoint_base_url = config
            .optional_string("MTLS_ENDPOINT_BASE_URL")
            .unwrap_or_else(|| issuer.clone());
        validate_issuer_url(&mtls_endpoint_base_url)?;
        let frontend_base_url =
            config.string("FRONTEND_BASE_URL", &format!("{}/ui/", public_base_url));
        validate_frontend_base_url(&frontend_base_url)?;
        let cors_allowed_origins = config
            .get("CORS_ALLOWED_ORIGINS")
            .map(|value| {
                value
                    .split(',')
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(ToOwned::to_owned)
                    .collect()
            })
            .filter(|values: &Vec<String>| !values.is_empty())
            .unwrap_or_else(|| vec![public_origin]);
        for origin in &cors_allowed_origins {
            validate_cors_origin(origin)?;
        }
        let default_cookie_secure = issuer.starts_with("https://");
        let cookie_secure = config.bool("COOKIE_SECURE", default_cookie_secure)?;
        if !cookie_secure && !is_loopback_http_url(&issuer) {
            bail!("COOKIE_SECURE=false 只允许用于 loopback HTTP 本地开发 issuer");
        }
        let subject_type = SubjectType::from_config(config)?;
        let pairwise_subject_secret = config.optional_string("PAIRWISE_SUBJECT_SECRET");
        if subject_type == SubjectType::Pairwise && pairwise_subject_secret.is_none() {
            bail!("PAIRWISE_SUBJECT_SECRET is required when SUBJECT_TYPE=pairwise");
        }
        if let Some(secret) = &pairwise_subject_secret
            && secret.len() < 32
        {
            bail!("pairwise_subject_secret must be at least 32 bytes");
        }
        let client_secret_pepper = match config.optional_string("CLIENT_SECRET_PEPPER") {
            Some(secret) if secret.len() >= 32 => secret,
            Some(_) => bail!("CLIENT_SECRET_PEPPER must be at least 32 bytes"),
            None if is_loopback_http_url(&issuer) => {
                LOCAL_DEVELOPMENT_CLIENT_SECRET_PEPPER.to_owned()
            }
            None => bail!("CLIENT_SECRET_PEPPER is required for non-loopback issuers"),
        };
        let authorization_server_profile = AuthorizationServerProfile::from_config(config)?;
        let ciba_security_profile = CibaSecurityProfile::from_config(config)?;
        let protected_resource_identifier = config
            .optional_string("PROTECTED_RESOURCE_IDENTIFIER")
            .unwrap_or_else(|| default_protected_resource_identifier(&issuer));
        validate_protected_resource_identifier(&protected_resource_identifier)?;
        let dpop_nonce_policy = DpopNoncePolicy::from_config(config)?;
        let request_object_jti_policy = RequestObjectJtiPolicy::from_config(config)?;
        let auth_code_ttl_seconds =
            positive_u64(config, "AUTH_CODE_TTL_SECONDS", 60, "AUTH_CODE_TTL_SECONDS")?;
        if authorization_server_profile.requires_fapi2_security() && auth_code_ttl_seconds > 60 {
            bail!("AUTH_CODE_TTL_SECONDS must be 60 or less for FAPI2 profiles");
        }
        let par_ttl_seconds = positive_u64(config, "PAR_TTL_SECONDS", 90, "PAR_TTL_SECONDS")?;
        if authorization_server_profile.requires_fapi2_security() && par_ttl_seconds >= 600 {
            bail!("PAR_TTL_SECONDS must be less than 600 for FAPI2 profiles");
        }
        let require_pushed_authorization_requests = config
            .bool("REQUIRE_PUSHED_AUTHORIZATION_REQUESTS", false)?
            || authorization_server_profile.requires_fapi2_security();
        let device_authorization_ttl_seconds =
            config.parse("DEVICE_AUTHORIZATION_TTL_SECONDS", 600)?;
        if device_authorization_ttl_seconds == 0 {
            bail!("DEVICE_AUTHORIZATION_TTL_SECONDS must be positive");
        }
        let device_authorization_poll_interval_seconds =
            config.parse("DEVICE_AUTHORIZATION_POLL_INTERVAL_SECONDS", 5)?;
        if device_authorization_poll_interval_seconds == 0 {
            bail!("DEVICE_AUTHORIZATION_POLL_INTERVAL_SECONDS must be positive");
        }
        if device_authorization_poll_interval_seconds >= device_authorization_ttl_seconds {
            bail!(
                "DEVICE_AUTHORIZATION_POLL_INTERVAL_SECONDS must be less than DEVICE_AUTHORIZATION_TTL_SECONDS"
            );
        }
        let ciba_auth_req_id_ttl_seconds = config.parse("CIBA_AUTH_REQ_ID_TTL_SECONDS", 600)?;
        if ciba_auth_req_id_ttl_seconds == 0 {
            bail!("CIBA_AUTH_REQ_ID_TTL_SECONDS must be positive");
        }
        let ciba_poll_interval_seconds = config.parse("CIBA_POLL_INTERVAL_SECONDS", 5)?;
        if ciba_poll_interval_seconds == 0 {
            bail!("CIBA_POLL_INTERVAL_SECONDS must be positive");
        }
        if ciba_poll_interval_seconds >= ciba_auth_req_id_ttl_seconds {
            bail!("CIBA_POLL_INTERVAL_SECONDS must be less than CIBA_AUTH_REQ_ID_TTL_SECONDS");
        }
        let ciba_automated_decision_token = config.optional_string("CIBA_AUTOMATED_DECISION_TOKEN");
        if let Some(token) = &ciba_automated_decision_token
            && token.len() < 32
        {
            bail!("CIBA_AUTOMATED_DECISION_TOKEN must be at least 32 bytes when set");
        }
        let enable_dynamic_client_registration =
            config.bool("ENABLE_DYNAMIC_CLIENT_REGISTRATION", false)?;
        let dynamic_client_registration_initial_access_token =
            config.optional_string("DYNAMIC_CLIENT_REGISTRATION_INITIAL_ACCESS_TOKEN");
        if enable_dynamic_client_registration
            && dynamic_client_registration_initial_access_token.is_none()
        {
            bail!(
                "DYNAMIC_CLIENT_REGISTRATION_INITIAL_ACCESS_TOKEN is required when ENABLE_DYNAMIC_CLIENT_REGISTRATION=true"
            );
        }
        let passkey = PasskeySettings::from_config(config, &issuer)?;
        let federation = FederationSettings::from_config(config)?;
        let signing_key_rotation_interval_seconds =
            config.parse("SIGNING_KEY_ROTATION_INTERVAL_SECONDS", 7_776_000)?;
        let signing_key_prepublish_seconds =
            config.parse("SIGNING_KEY_PREPUBLISH_SECONDS", 86_400)?;
        if signing_key_rotation_interval_seconds <= 0 {
            bail!("SIGNING_KEY_ROTATION_INTERVAL_SECONDS must be positive");
        }
        if signing_key_prepublish_seconds <= 0 {
            bail!("SIGNING_KEY_PREPUBLISH_SECONDS must be positive");
        }
        if signing_key_prepublish_seconds >= signing_key_rotation_interval_seconds {
            bail!(
                "SIGNING_KEY_PREPUBLISH_SECONDS must be less than SIGNING_KEY_ROTATION_INTERVAL_SECONDS"
            );
        }

        let data_dir = PathBuf::from(config.string("DATA_DIR", "runtime"));
        let avatar_storage_dir = config
            .optional_string("AVATAR_STORAGE_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| data_dir.join("avatars"));
        let jwk_keys_dir = config
            .optional_string("JWK_KEYS_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| data_dir.join("keys"));

        Ok(Self {
            issuer,
            mtls_endpoint_base_url,
            frontend_base_url,
            cors_allowed_origins,
            default_audience: config.string("DEFAULT_AUDIENCE", "resource://default"),
            protected_resource_identifier,
            authorization_server_profile,
            ciba_security_profile,
            dpop_nonce_policy,
            request_object_jti_policy,
            session_cookie_name: config.string("SESSION_COOKIE_NAME", "nazo_oauth_session"),
            csrf_cookie_name: config.string("CSRF_COOKIE_NAME", "nazo_oauth_csrf"),
            cookie_secure,
            session_ttl_seconds: positive_u64(
                config,
                "SESSION_TTL_SECONDS",
                28_800,
                "SESSION_TTL_SECONDS",
            )?,
            auth_code_ttl_seconds,
            access_token_ttl_seconds: positive_i64(
                config,
                "ACCESS_TOKEN_TTL_SECONDS",
                300,
                "ACCESS_TOKEN_TTL_SECONDS",
            )?,
            id_token_ttl_seconds: positive_i64(
                config,
                "ID_TOKEN_TTL_SECONDS",
                600,
                "ID_TOKEN_TTL_SECONDS",
            )?,
            refresh_token_ttl_seconds: positive_i64(
                config,
                "REFRESH_TOKEN_TTL_SECONDS",
                2_592_000,
                "REFRESH_TOKEN_TTL_SECONDS",
            )?,
            avatar_max_bytes: config.parse("AVATAR_MAX_BYTES", 2_097_152)?,
            client_delivery_ttl_seconds: positive_u64(
                config,
                "CLIENT_DELIVERY_TTL_SECONDS",
                86_400,
                "CLIENT_DELIVERY_TTL_SECONDS",
            )?,
            client_secret_pepper,
            rate_limit: RateLimitSettings::from_config(config)?,
            email: EmailSettings::from_config(config)?,
            email_code_dev_response_enabled: config
                .bool("EMAIL_CODE_DEV_RESPONSE_ENABLED", false)?,
            avatar_storage_dir,
            jwk_keys_dir,
            signing_external_command: parse_signing_external_command(
                config.optional_string("SIGNING_EXTERNAL_COMMAND"),
            ),
            signing_external_timeout_ms: config.parse("SIGNING_EXTERNAL_TIMEOUT_MS", 2_000)?,
            signing_key_rotation_interval_seconds,
            signing_key_prepublish_seconds,
            trusted_proxy_cidrs: parse_trusted_proxy_cidrs(config.get("TRUSTED_PROXY_CIDRS"))?,
            client_ip_header_mode: ClientIpHeaderMode::parse(
                &config.string("CLIENT_IP_HEADER_MODE", "none"),
            )?,
            subject_type,
            pairwise_subject_secret,
            par_ttl_seconds,
            require_pushed_authorization_requests,
            scim_bearer_token: config.optional_string("SCIM_BEARER_TOKEN"),
            passkey,
            federation,
            enable_request_object: config.bool("ENABLE_REQUEST_OBJECT", false)?,
            enable_request_uri_parameter: config.bool("ENABLE_REQUEST_URI_PARAMETER", false)?,
            enable_par_request_object: config.bool("ENABLE_PAR_REQUEST_OBJECT", false)?,
            enable_authorization_details: config.bool("ENABLE_AUTHORIZATION_DETAILS", false)?,
            enable_legacy_audience_param: config.bool("ENABLE_LEGACY_AUDIENCE_PARAM", false)?,
            enable_device_authorization_grant: config
                .bool("ENABLE_DEVICE_AUTHORIZATION_GRANT", false)?,
            enable_frontchannel_logout: config.bool("ENABLE_FRONTCHANNEL_LOGOUT", false)?,
            enable_session_management: config.bool("ENABLE_SESSION_MANAGEMENT", false)?,
            enable_ciba: config.bool("ENABLE_CIBA", false)?,
            enable_native_sso: config.bool("ENABLE_NATIVE_SSO", false)?,
            enable_dynamic_client_registration,
            dynamic_client_registration_initial_access_token,
            device_authorization_ttl_seconds,
            device_authorization_poll_interval_seconds,
            ciba_auth_req_id_ttl_seconds,
            ciba_poll_interval_seconds,
            ciba_automated_decision_token,
        })
    }
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

fn default_protected_resource_identifier(issuer: &str) -> String {
    format!("{}/fapi/resource", issuer.trim_end_matches('/'))
}

#[cfg(test)]
#[path = "../tests/in_source/src/settings/tests/settings.rs"]
mod tests;
