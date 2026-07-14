//! Runtime configuration loading.
// Configuration is read once at startup from defaults, .env.yaml, and whitelisted environment variables.

use std::{collections::HashMap, fs::File, path::Path};

use anyhow::{Context, bail};
use yaml_serde::Value as YamlValue;

const CONFIG_FILE: &str = ".env.yaml";
const UNSUPPORTED_DOTENV_FILE: &str = ".env";
const DEPRECATED_IGNORED_CONFIG_KEYS: &[&str] = &[
    // Retained so existing deployments can remove the obsolete OpenID
    // Federation gate on their own schedule. The incomplete endpoint was
    // removed and this key intentionally has no runtime effect.
    "ENABLE_OIDC_FEDERATION",
];
pub const DEFAULT_DATABASE_URL: &str = "postgresql://postgres:postgres@127.0.0.1:5432/oauth";
pub const DEFAULT_DATABASE_MAX_CONNECTIONS: usize = 32;
const ENV_CONFIG_KEYS: &[&str] = &[
    "ACCESS_TOKEN_TTL_SECONDS",
    "AUTH_CODE_TTL_SECONDS",
    "AUTH_RATE_LIMIT_MAX_REQUESTS",
    "AUTHORIZATION_SERVER_PROFILE",
    "AVATAR_MAX_BYTES",
    "AVATAR_STORAGE_DIR",
    "BIND",
    "CLIENT_DELIVERY_TTL_SECONDS",
    "CLIENT_IP_HEADER_MODE",
    "CLIENT_SECRET_PEPPER",
    "CIBA_AUTOMATED_DECISION_TOKEN",
    "CIBA_AUTH_REQ_ID_TTL_SECONDS",
    "CIBA_POLL_INTERVAL_SECONDS",
    "CIBA_SECURITY_PROFILE",
    "COOKIE_SECURE",
    "CORS_ALLOWED_ORIGINS",
    "CSRF_COOKIE_NAME",
    "DATABASE_URL",
    "DATABASE_MAX_CONNECTIONS",
    "DATA_DIR",
    "DEFAULT_AUDIENCE",
    "DEVICE_AUTHORIZATION_POLL_INTERVAL_SECONDS",
    "DEVICE_AUTHORIZATION_TTL_SECONDS",
    "DPOP_NONCE_POLICY",
    "DYNAMIC_CLIENT_REGISTRATION_INITIAL_ACCESS_TOKEN",
    "ENABLE_AUTHORIZATION_DETAILS",
    "ENABLE_CIBA",
    "ENABLE_DEVICE_AUTHORIZATION_GRANT",
    "ENABLE_DYNAMIC_CLIENT_REGISTRATION",
    "ENABLE_FRONTCHANNEL_LOGOUT",
    "ENABLE_FAPI_HTTP_SIGNATURES",
    "ENABLE_LEGACY_AUDIENCE_PARAM",
    "ENABLE_NATIVE_SSO",
    "ENABLE_PAR_REQUEST_OBJECT",
    "ENABLE_REQUEST_OBJECT",
    "ENABLE_REQUEST_URI_PARAMETER",
    "ENABLE_SESSION_MANAGEMENT",
    "EMAIL_CODE_DEV_RESPONSE_ENABLED",
    "EMAIL_CODE_PEER_COOLDOWN_SECONDS",
    "EMAIL_CODE_SEND_COOLDOWN_SECONDS",
    "EMAIL_CODE_TTL_SECONDS",
    "EMAIL_DELIVERY",
    "EMAIL_FROM",
    "EMAIL_SMTP_HOST",
    "EMAIL_SMTP_PASSWORD",
    "EMAIL_SMTP_PORT",
    "EMAIL_SMTP_TLS",
    "EMAIL_SMTP_USERNAME",
    "FRONTEND_BASE_URL",
    "FEDERATION_PROVIDER_CONFIGS",
    "FEDERATION_SAML_GATEWAY_AUDIENCE",
    "FEDERATION_SAML_GATEWAY_ENABLED",
    "FEDERATION_SAML_GATEWAY_ISSUER",
    "FEDERATION_SAML_GATEWAY_SECRET",
    "FAPI_HTTP_SIGNATURE_MAX_AGE_SECONDS",
    "ID_TOKEN_TTL_SECONDS",
    "ISSUER",
    "JWK_KEYS_DIR",
    "LOGIN_FAILURE_EMAIL_MAX_ATTEMPTS",
    "LOGIN_FAILURE_IP_EMAIL_MAX_ATTEMPTS",
    "LOGIN_FAILURE_WINDOW_SECONDS",
    "MTLS_ENDPOINT_BASE_URL",
    "SIGNING_EXTERNAL_COMMAND",
    "SIGNING_EXTERNAL_TIMEOUT_MS",
    "OTEL_ENABLED",
    "OTEL_EXPORTER_OTLP_ENDPOINT",
    "OTEL_EXPORTER_OTLP_PROTOCOL",
    "OTEL_EXPORTER_OTLP_TIMEOUT",
    "PAIRWISE_SUBJECT_SECRET",
    "PAR_TTL_SECONDS",
    "PASSKEY_RP_ID",
    "PASSKEY_RP_NAME",
    "PASSKEY_ORIGIN",
    "PASSKEY_REQUIRE_USER_VERIFICATION",
    "PASSKEY_REQUIRE_USER_HANDLE",
    "PASSKEY_STRICT_BASE64",
    "PASSWORD_HASH_MAX_CONCURRENCY",
    "PASSWORD_HASH_QUEUE_TIMEOUT_MS",
    "PERF_METRICS_ENABLED",
    "PUBLIC_BASE_URL",
    "PROTECTED_RESOURCE_IDENTIFIER",
    "RATE_LIMIT_WINDOW_SECONDS",
    "REFRESH_TOKEN_TTL_SECONDS",
    "REQUEST_OBJECT_JTI_POLICY",
    "REQUIRE_PUSHED_AUTHORIZATION_REQUESTS",
    "RUST_LOG",
    "SCIM_BEARER_TOKEN",
    "SESSION_COOKIE_NAME",
    "SESSION_TTL_SECONDS",
    "SIGNING_KEY_PREPUBLISH_SECONDS",
    "SIGNING_KEY_ROTATION_INTERVAL_SECONDS",
    "SUBJECT_TYPE",
    "TOKEN_MANAGEMENT_RATE_LIMIT_MAX_REQUESTS",
    "TOKEN_RATE_LIMIT_MAX_REQUESTS",
    "TRUSTED_PROXY_CIDRS",
    "VALKEY_COMMAND_TIMEOUT_MS",
    "VALKEY_URL",
];

#[derive(Clone, Debug, Default)]
pub struct ConfigSource {
    file_values: HashMap<String, String>,
    env_values: HashMap<String, String>,
}

impl ConfigSource {
    pub fn load() -> anyhow::Result<Self> {
        Self::load_from_dir_with_env(".", std::env::vars())
    }

    #[cfg(test)]
    pub(crate) fn from_pairs_for_test(
        values: impl IntoIterator<Item = (&'static str, &'static str)>,
    ) -> Self {
        Self {
            file_values: values
                .into_iter()
                .map(|(key, value)| (key.to_owned(), value.to_owned()))
                .collect(),
            env_values: HashMap::new(),
        }
    }

    #[cfg(test)]
    pub(crate) fn from_owned_pairs_for_test(
        values: impl IntoIterator<Item = (String, String)>,
    ) -> Self {
        // 动态端点测试需要在运行时生成配置值；生产加载仍只走文件和环境变量。
        Self {
            file_values: values.into_iter().collect(),
            env_values: HashMap::new(),
        }
    }

    #[cfg(test)]
    fn load_from_dir(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        Self::load_from_dir_with_env(path, std::iter::empty::<(String, String)>())
    }

    fn load_from_dir_with_env(
        path: impl AsRef<Path>,
        env: impl IntoIterator<Item = (String, String)>,
    ) -> anyhow::Result<Self> {
        let path = path.as_ref();
        let dotenv_path = path.join(UNSUPPORTED_DOTENV_FILE);
        if dotenv_path.exists() {
            bail!(".env is not supported; use .env.yaml");
        }

        let mut source = Self::default();
        let config_path = path.join(CONFIG_FILE);
        if config_path.exists() {
            source.merge_yaml_file(config_path)?;
        }
        source.merge_env(env)?;
        Ok(source)
    }

    pub fn required_string(&self, key: &str) -> anyhow::Result<String> {
        let Some(value) = self
            .get(key)
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
        else {
            bail!("{key} is required");
        };
        Ok(value)
    }

    pub fn optional_string(&self, key: &str) -> Option<String> {
        self.get(key)
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
    }

    pub fn get(&self, key: &str) -> Option<String> {
        self.env_values
            .get(key)
            .or_else(|| self.file_values.get(key))
            .cloned()
    }

    pub fn string(&self, key: &str, default: &str) -> String {
        self.get(key).unwrap_or_else(|| default.to_owned())
    }

    pub fn parse<T>(&self, key: &str, default: T) -> anyhow::Result<T>
    where
        T: std::str::FromStr,
    {
        let Some(value) = self.get(key) else {
            return Ok(default);
        };
        let Ok(parsed) = value.parse() else {
            bail!("{key} must be a valid {}", std::any::type_name::<T>());
        };
        Ok(parsed)
    }

    pub fn bool(&self, key: &str, default: bool) -> anyhow::Result<bool> {
        let Some(value) = self.get(key) else {
            return Ok(default);
        };
        let Some(parsed) = parse_bool(&value) else {
            bail!("{key} must be a boolean value");
        };
        Ok(parsed)
    }

    fn merge_yaml_file(&mut self, path: impl AsRef<Path>) -> anyhow::Result<()> {
        let path = path.as_ref();
        let file = File::open(path)
            .with_context(|| format!("failed to read required {}", path.display()))?;
        let value = yaml_serde::from_reader::<_, YamlValue>(file)
            .with_context(|| format!("failed to parse {}", path.display()))?;
        let YamlValue::Mapping(values) = value else {
            bail!("{} must be a top-level key/value mapping", path.display());
        };
        for (key, value) in values {
            let Some(key) = key.as_str().map(str::trim).filter(|key| !key.is_empty()) else {
                bail!("{} contains a non-string or empty key", path.display());
            };
            if DEPRECATED_IGNORED_CONFIG_KEYS.contains(&key) {
                let value = yaml_value_to_string(key, &value)?;
                if parse_bool(&value).is_none() {
                    bail!("{key} must be a boolean value");
                }
                continue;
            }
            if !ENV_CONFIG_KEYS.contains(&key) {
                bail!("{} contains unknown config key {key}", path.display());
            }
            let value = yaml_value_to_string(key, &value)?;
            self.file_values.insert(key.to_owned(), value);
        }
        Ok(())
    }

    fn merge_env(&mut self, env: impl IntoIterator<Item = (String, String)>) -> anyhow::Result<()> {
        for (key, value) in env {
            if !ENV_CONFIG_KEYS.contains(&key.as_str()) {
                continue;
            }
            if key.trim().is_empty() {
                bail!("environment config key must not be empty");
            }
            self.env_values.insert(key, value);
        }
        Ok(())
    }
}

fn yaml_value_to_string(key: &str, value: &YamlValue) -> anyhow::Result<String> {
    match value {
        YamlValue::String(value) => Ok(value.clone()),
        YamlValue::Bool(value) => Ok(value.to_string()),
        YamlValue::Number(value) => Ok(value.to_string()),
        YamlValue::Sequence(values) => {
            let values = values
                .iter()
                .map(|value| yaml_value_to_string(key, value))
                .collect::<anyhow::Result<Vec<_>>>()?;
            Ok(values.join(","))
        }
        _ => bail!("{key} must be a scalar or a sequence of scalars"),
    }
}

fn parse_bool(value: &str) -> Option<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

pub fn database_url(source: &ConfigSource) -> String {
    source.string("DATABASE_URL", DEFAULT_DATABASE_URL)
}

pub fn database_max_connections(source: &ConfigSource) -> anyhow::Result<usize> {
    let value = source.parse("DATABASE_MAX_CONNECTIONS", DEFAULT_DATABASE_MAX_CONNECTIONS)?;
    if value == 0 {
        bail!("DATABASE_MAX_CONNECTIONS must be greater than zero");
    }
    Ok(value)
}

#[cfg(test)]
#[path = "../tests/in_source/src/config/tests/config.rs"]
mod tests;
