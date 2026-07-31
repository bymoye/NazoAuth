//! Runtime configuration loading.
// Configuration is read once at startup from defaults, .env.yaml, and whitelisted environment variables.

use std::{
    collections::HashMap,
    fs::{File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use anyhow::{Context, bail};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use yaml_serde::Value as YamlValue;

const CONFIG_FILE: &str = ".env.yaml";
const UNSUPPORTED_DOTENV_FILE: &str = ".env";
const INITIAL_CONFIG: &str = r#"# Generated local NazoAuth configuration.
BIND: "0.0.0.0:8000"
PUBLIC_BASE_URL: "http://127.0.0.1:8000"
DATABASE_URL: "postgresql://postgres:postgres@127.0.0.1:5432/oauth"
DATABASE_MAX_CONNECTIONS: 32
VALKEY_URL: "redis://127.0.0.1:6379/0"
DATA_DIR: "runtime"
RUST_LOG: "info"
"#;
pub const DEFAULT_DATABASE_URL: &str = "postgresql://postgres:postgres@127.0.0.1:5432/oauth";
pub const DEFAULT_DATABASE_MAX_CONNECTIONS: usize = 32;
const GENERATED_SECRET_BYTES: usize = 48;
const GENERATED_SECRETS_DIR: &str = "secrets";
const SECRET_FILE_INPUTS: &[(&str, &str)] = &[
    ("CLIENT_SECRET_PEPPER", "CLIENT_SECRET_PEPPER_FILE"),
    ("DATABASE_URL", "DATABASE_URL_FILE"),
    (
        "DYNAMIC_CLIENT_REGISTRATION_INITIAL_ACCESS_TOKEN",
        "DYNAMIC_CLIENT_REGISTRATION_INITIAL_ACCESS_TOKEN_FILE",
    ),
    ("PAIRWISE_SUBJECT_SECRET", "PAIRWISE_SUBJECT_SECRET_FILE"),
    ("VALKEY_URL", "VALKEY_URL_FILE"),
];
const ENV_CONFIG_KEYS: &[&str] = &[
    "ACCESS_TOKEN_TTL_SECONDS",
    "AUTH_CODE_TTL_SECONDS",
    "AUTH_RATE_LIMIT_MAX_REQUESTS",
    "AUTHORIZATION_SERVER_PROFILE",
    "AVATAR_MAX_BYTES",
    "AVATAR_STORAGE_DIR",
    "BACKCHANNEL_LOGOUT_PRIVATE_ORIGINS",
    "BIND",
    "CLIENT_DELIVERY_TTL_SECONDS",
    "CLIENT_IP_HEADER_MODE",
    "CLIENT_SECRET_PEPPER",
    "CLIENT_SECRET_PEPPER_FILE",
    "CIBA_AUTOMATED_DECISION_TOKEN",
    "CIBA_AUTH_REQ_ID_TTL_SECONDS",
    "CIBA_NOTIFICATION_PRIVATE_ORIGINS",
    "CIBA_PING_TLS_TRUST_BUNDLE",
    "CIBA_POLL_INTERVAL_SECONDS",
    "CIBA_SECURITY_PROFILE",
    "COOKIE_SECURE",
    "CORS_ALLOWED_ORIGINS",
    "CSRF_COOKIE_NAME",
    "DATABASE_URL",
    "DATABASE_URL_FILE",
    "DATABASE_MAX_CONNECTIONS",
    "DATA_DIR",
    "DEFAULT_AUDIENCE",
    "DEVICE_AUTHORIZATION_POLL_INTERVAL_SECONDS",
    "DEVICE_AUTHORIZATION_TTL_SECONDS",
    "DPOP_NONCE_POLICY",
    "DYNAMIC_CLIENT_REGISTRATION_INITIAL_ACCESS_TOKEN",
    "DYNAMIC_CLIENT_REGISTRATION_INITIAL_ACCESS_TOKEN_FILE",
    "ENABLE_AUTHORIZATION_DETAILS",
    "ENABLE_CIBA",
    "ENABLE_DEVICE_AUTHORIZATION_GRANT",
    "ENABLE_DYNAMIC_CLIENT_REGISTRATION",
    "ENABLE_FRONTCHANNEL_LOGOUT",
    "ENABLE_FAPI_HTTP_SIGNATURES",
    "ENABLE_NATIVE_SSO",
    "ENABLE_OPENID4VCI_ISSUER",
    "ENABLE_OPENID4VP_VERIFIER",
    "ENABLE_PAR_REQUEST_OBJECT",
    "ENABLE_REQUEST_OBJECT",
    "ENABLE_SESSION_MANAGEMENT",
    "ENABLE_SCIM_SECURITY_EVENTS",
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
    "FAPI_RESOURCE_DPOP_NONCE_POLICY",
    "ID_TOKEN_TTL_SECONDS",
    "ISSUER",
    "JWK_KEYS_DIR",
    "LOGIN_FAILURE_IP_EMAIL_MAX_ATTEMPTS",
    "LOGIN_FAILURE_WINDOW_SECONDS",
    "MTLS_ENDPOINT_BASE_URL",
    "MTLS_CERTIFICATE_SOURCE",
    "OPENID4VC_DATA_ENCRYPTION_KEY",
    "OPENID4VC_CLIENT_ATTESTATION_JWKS_JSON",
    "OPENID4VC_CLIENT_ATTESTATION_ISSUER",
    "OPENID4VC_KEY_ATTESTATION_JWKS_JSON",
    "OPENID4VC_SIGNING_CERTIFICATE_CHAIN_FILE",
    "OPENID4VC_TRUST_ANCHORS_FILE",
    "OPENID4VC_TRANSACTION_TTL_SECONDS",
    "OPENID4VCI_CREDENTIAL_CONFIGURATIONS_JSON",
    "OPENID4VCI_DEFERRED_CREDENTIAL_CONFIGURATIONS",
    "OPENID4VCI_ISSUER_MANAGEMENT_TOKEN",
    "OPENID4VP_VERIFIER_MANAGEMENT_TOKEN",
    "OPENID4VP_WALLET_AUTHORIZATION_ORIGINS",
    "SIGNING_EXTERNAL_COMMAND",
    "SIGNING_EXTERNAL_TIMEOUT_MS",
    "OTEL_ENABLED",
    "OTEL_EXPORTER_OTLP_ENDPOINT",
    "OTEL_EXPORTER_OTLP_PROTOCOL",
    "OTEL_EXPORTER_OTLP_TIMEOUT",
    "PAIRWISE_SUBJECT_SECRET",
    "PAIRWISE_SUBJECT_SECRET_FILE",
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
    "REMOTE_CLIENT_DOCUMENT_PRIVATE_ORIGINS",
    "REQUIRE_PUSHED_AUTHORIZATION_REQUESTS",
    "RUST_LOG",
    "SCIM_EVENT_RETENTION_SECONDS",
    "SESSION_COOKIE_NAME",
    "SESSION_TTL_SECONDS",
    "SIGNING_KEY_PREPUBLISH_SECONDS",
    "SIGNING_KEY_ROTATION_INTERVAL_SECONDS",
    "SUBJECT_TYPE",
    "TOKEN_MANAGEMENT_RATE_LIMIT_MAX_REQUESTS",
    "TOKEN_RATE_LIMIT_MAX_REQUESTS",
    "TLS_BIND",
    "TLS_CERTIFICATE_FILE",
    "TLS_CLIENT_CA_FILE",
    "TLS_PRIVATE_KEY_FILE",
    "TRUSTED_PROXY_CIDRS",
    "VALKEY_COMMAND_TIMEOUT_MS",
    "VALKEY_URL",
    "VALKEY_URL_FILE",
];

#[derive(Clone, Debug, Default)]
pub struct ConfigSource {
    file_values: HashMap<String, String>,
    env_values: HashMap<String, String>,
    generated_values: HashMap<String, String>,
}

#[derive(Debug, Eq, PartialEq)]
pub enum ServerConfigPreparation {
    Ready,
    Created(PathBuf),
}

pub fn prepare_server_config() -> anyhow::Result<ServerConfigPreparation> {
    prepare_server_config_in(".")
}

fn prepare_server_config_in(path: impl AsRef<Path>) -> anyhow::Result<ServerConfigPreparation> {
    let config_path = path.as_ref().join(CONFIG_FILE);
    if config_path.exists() {
        return Ok(ServerConfigPreparation::Ready);
    }

    let mut file = match OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&config_path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            return Ok(ServerConfigPreparation::Ready);
        }
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to create initial {}", config_path.display()));
        }
    };
    file.write_all(INITIAL_CONFIG.as_bytes())
        .with_context(|| format!("failed to write initial {}", config_path.display()))?;
    file.sync_all()
        .with_context(|| format!("failed to persist initial {}", config_path.display()))?;

    Ok(ServerConfigPreparation::Created(config_path))
}

impl ConfigSource {
    pub fn load() -> anyhow::Result<Self> {
        Self::load_from_dir_with_env(".", std::env::vars())
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
        source.merge_secret_file_inputs(path)?;
        source.merge_generated_secrets(path)?;
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
            .or_else(|| self.generated_values.get(key))
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

    fn merge_secret_file_inputs(&mut self, config_dir: &Path) -> anyhow::Result<()> {
        for (target_key, file_key) in SECRET_FILE_INPUTS {
            if self.env_values.contains_key(*target_key) {
                continue;
            }
            if self.file_values.contains_key(*target_key) {
                continue;
            }
            if let Some(path) = self.env_values.get(*file_key) {
                let value = read_secret_input(config_dir, file_key, path)?;
                self.env_values.insert((*target_key).to_owned(), value);
                continue;
            }
            if let Some(path) = self.file_values.get(*file_key) {
                let value = read_secret_input(config_dir, file_key, path)?;
                self.file_values.insert((*target_key).to_owned(), value);
            }
        }
        Ok(())
    }

    fn merge_generated_secrets(&mut self, config_dir: &Path) -> anyhow::Result<()> {
        let data_dir =
            resolve_from_config_dir(config_dir, Path::new(&self.string("DATA_DIR", "runtime")));
        let secrets_dir = data_dir.join(GENERATED_SECRETS_DIR);
        let mut required = vec![
            ("CLIENT_SECRET_PEPPER", "client-secret-pepper"),
            (
                "DYNAMIC_CLIENT_REGISTRATION_INITIAL_ACCESS_TOKEN",
                "dynamic-client-registration-initial-access-token",
            ),
        ];
        if self
            .get("SUBJECT_TYPE")
            .is_some_and(|value| value.trim().eq_ignore_ascii_case("pairwise"))
        {
            required.push(("PAIRWISE_SUBJECT_SECRET", "pairwise-subject-secret"));
        }

        for (key, file_name) in required {
            if self.env_values.contains_key(key) || self.file_values.contains_key(key) {
                continue;
            }
            let value = read_or_create_generated_secret(&secrets_dir.join(file_name))?;
            self.generated_values.insert(key.to_owned(), value);
        }
        Ok(())
    }
}

fn read_secret_input(
    config_dir: &Path,
    key: &str,
    configured_path: &str,
) -> anyhow::Result<String> {
    let configured_path = configured_path.trim();
    if configured_path.is_empty() {
        bail!("{key} must not be empty");
    }
    let path = resolve_from_config_dir(config_dir, Path::new(configured_path));
    let value = std::fs::read_to_string(&path)
        .with_context(|| format!("failed to read {key} from {}", path.display()))?;
    let value = value.trim().to_owned();
    if value.is_empty() {
        bail!("{key} points to an empty secret file {}", path.display());
    }
    Ok(value)
}

fn resolve_from_config_dir(config_dir: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_owned()
    } else {
        config_dir.join(path)
    }
}

fn read_or_create_generated_secret(path: &Path) -> anyhow::Result<String> {
    if path.exists() {
        return read_generated_secret(path);
    }
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("generated secret path has no parent"))?;
    std::fs::create_dir_all(parent).with_context(|| {
        format!(
            "failed to create generated secret directory {}",
            parent.display()
        )
    })?;

    let value = URL_SAFE_NO_PAD.encode(rand::random::<[u8; GENERATED_SECRET_BYTES]>());
    let temporary_path = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("secret"),
        URL_SAFE_NO_PAD.encode(rand::random::<[u8; 12]>())
    ));
    let mut temporary = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary_path)
        .with_context(|| {
            format!(
                "failed to create generated secret temporary file {}",
                temporary_path.display()
            )
        })?;
    restrict_secret_permissions(&temporary_path)?;
    temporary.write_all(value.as_bytes()).with_context(|| {
        format!(
            "failed to write generated secret {}",
            temporary_path.display()
        )
    })?;
    temporary.sync_all().with_context(|| {
        format!(
            "failed to persist generated secret {}",
            temporary_path.display()
        )
    })?;
    drop(temporary);

    match std::fs::hard_link(&temporary_path, path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => {
            let _ = std::fs::remove_file(&temporary_path);
            return Err(error)
                .with_context(|| format!("failed to publish generated secret {}", path.display()));
        }
    }
    let _ = std::fs::remove_file(&temporary_path);
    read_generated_secret(path)
}

pub(crate) fn read_or_create_runtime_secret(
    data_dir: &Path,
    relative_path: impl AsRef<Path>,
) -> anyhow::Result<(PathBuf, String)> {
    let path = data_dir.join(relative_path);
    let value = read_or_create_generated_secret(&path)?;
    Ok((path, value))
}

fn read_generated_secret(path: &Path) -> anyhow::Result<String> {
    let value = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read generated secret {}", path.display()))?;
    let value = value.trim().to_owned();
    if value.len() < 32 {
        bail!(
            "generated secret {} is missing or malformed; restore it from backup instead of regenerating it",
            path.display()
        );
    }
    Ok(value)
}

#[cfg(unix)]
fn restrict_secret_permissions(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("failed to restrict generated secret {}", path.display()))
}

#[cfg(not(unix))]
fn restrict_secret_permissions(_path: &Path) -> anyhow::Result<()> {
    Ok(())
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
#[path = "../tests/unit/config.rs"]
mod tests;
