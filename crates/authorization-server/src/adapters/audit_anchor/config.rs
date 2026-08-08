use std::{
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::bail;
use url::Url;

use crate::config::ConfigSource;

pub(super) const MAX_BATCH_SIZE: i64 = 256;
const MAX_DEPLOYMENT_ID_BYTES: usize = 255;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AuditAnchorMode {
    Disabled,
    Optional,
    Required,
}

impl AuditAnchorMode {
    pub(crate) const fn is_required(self) -> bool {
        matches!(self, Self::Required)
    }

    pub(crate) const fn is_enabled(self) -> bool {
        !matches!(self, Self::Disabled)
    }

    pub(crate) fn parse(value: &str) -> anyhow::Result<Self> {
        match value {
            "disabled" => Ok(Self::Disabled),
            "optional" => Ok(Self::Optional),
            "required" => Ok(Self::Required),
            _ => bail!("AUDIT_ANCHOR_MODE must be disabled, optional, or required"),
        }
    }
}

/// Server-safe configuration. It has no exporter database URL or HMAC secret.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AuditAnchorPreflightConfig {
    pub(crate) mode: AuditAnchorMode,
    pub(crate) deployment_id: String,
    pub(crate) status_file: PathBuf,
    pub(crate) freshness: Duration,
    pub(crate) max_lag: Duration,
}

impl AuditAnchorPreflightConfig {
    pub(crate) fn validate(&self) -> anyhow::Result<()> {
        validate_deployment_id(&self.deployment_id)?;
        if self.status_file.as_os_str().is_empty() {
            bail!("AUDIT_ANCHOR_STATUS_FILE must not be empty");
        }
        if self.mode.is_enabled() && self.freshness.is_zero() {
            bail!("AUDIT_ANCHOR_FRESHNESS_SECONDS must be greater than zero");
        }
        if self.mode.is_enabled() && self.max_lag.is_zero() {
            bail!("AUDIT_ANCHOR_MAX_LAG_SECONDS must be greater than zero");
        }
        Ok(())
    }
}

/// Configuration used only by the independent exporter process.
pub(crate) struct AuditAnchorWorkerConfig {
    pub(crate) preflight: AuditAnchorPreflightConfig,
    pub(crate) endpoint: Url,
    pub(crate) auth_secret: Vec<u8>,
    pub(crate) poll_interval: Duration,
    pub(crate) request_timeout: Duration,
    pub(crate) batch_size: i64,
    pub(crate) lock_timeout_seconds: i32,
}

impl AuditAnchorWorkerConfig {
    pub(crate) fn validate(&self) -> anyhow::Result<()> {
        self.preflight.validate()?;
        if !self.preflight.mode.is_enabled() {
            bail!("audit anchor worker cannot run while AUDIT_ANCHOR_MODE=disabled");
        }
        if self.endpoint.scheme() != "https" {
            bail!("AUDIT_ANCHOR_URL must use HTTPS");
        }
        if !self.endpoint.username().is_empty()
            || self.endpoint.password().is_some()
            || self.endpoint.fragment().is_some()
            || self.endpoint.query().is_some()
        {
            bail!("AUDIT_ANCHOR_URL must not contain credentials, a query, or a fragment");
        }
        if self.auth_secret.len() < 16 {
            bail!("AUDIT_ANCHOR_TOKEN must contain at least 16 bytes");
        }
        if self.poll_interval.is_zero() {
            bail!("AUDIT_ANCHOR_POLL_INTERVAL_SECONDS must be greater than zero");
        }
        if self.request_timeout.is_zero() {
            bail!("AUDIT_ANCHOR_REQUEST_TIMEOUT_SECONDS must be greater than zero");
        }
        if !(1..=MAX_BATCH_SIZE).contains(&self.batch_size) {
            bail!("AUDIT_ANCHOR_BATCH_SIZE must be between 1 and {MAX_BATCH_SIZE}");
        }
        if !(1..=3_600).contains(&self.lock_timeout_seconds) {
            bail!("AUDIT_ANCHOR_LOCK_TIMEOUT_SECONDS must be between 1 and 3600");
        }
        Ok(())
    }
}

pub(crate) fn preflight_config_from_source(
    source: &ConfigSource,
    data_dir: &Path,
) -> anyhow::Result<AuditAnchorPreflightConfig> {
    let mode = AuditAnchorMode::parse(&source.string("AUDIT_ANCHOR_MODE", "disabled"))?;
    let deployment_id = if mode.is_enabled() {
        source.required_string("DEPLOYMENT_ID")?
    } else {
        source.string("DEPLOYMENT_ID", "audit-anchor-disabled")
    };
    let config = AuditAnchorPreflightConfig {
        mode,
        deployment_id,
        status_file: source
            .optional_string("AUDIT_ANCHOR_STATUS_FILE")
            .map(|_| source.persistent_path("AUDIT_ANCHOR_STATUS_FILE", None))
            .transpose()?
            .unwrap_or_else(|| data_dir.join("instance/audit-anchor-health.json")),
        freshness: Duration::from_secs(source.parse("AUDIT_ANCHOR_FRESHNESS_SECONDS", 120_u64)?),
        max_lag: Duration::from_secs(source.parse("AUDIT_ANCHOR_MAX_LAG_SECONDS", 300_u64)?),
    };
    config.validate()?;
    Ok(config)
}

pub(crate) fn worker_config_from_source(
    source: &ConfigSource,
) -> anyhow::Result<(String, usize, AuditAnchorWorkerConfig)> {
    let data_dir = source.persistent_path("DATA_DIR", Some(crate::config::DEFAULT_DATA_DIR))?;
    let preflight = preflight_config_from_source(source, &data_dir)?;
    let endpoint = Url::parse(&source.required_string("AUDIT_ANCHOR_URL")?)
        .map_err(|_| anyhow::anyhow!("AUDIT_ANCHOR_URL must be a valid absolute URL"))?;
    let config = AuditAnchorWorkerConfig {
        preflight,
        endpoint,
        auth_secret: source.required_string("AUDIT_ANCHOR_TOKEN")?.into_bytes(),
        poll_interval: Duration::from_secs(
            source.parse("AUDIT_ANCHOR_POLL_INTERVAL_SECONDS", 5_u64)?,
        ),
        request_timeout: Duration::from_secs(
            source.parse("AUDIT_ANCHOR_REQUEST_TIMEOUT_SECONDS", 10_u64)?,
        ),
        batch_size: source.parse("AUDIT_ANCHOR_BATCH_SIZE", 64_i64)?,
        lock_timeout_seconds: source.parse("AUDIT_ANCHOR_LOCK_TIMEOUT_SECONDS", 60_i32)?,
    };
    config.validate()?;
    let database_url = source.required_string("AUDIT_ANCHOR_DATABASE_URL")?;
    let database_max_connections =
        source.parse("AUDIT_ANCHOR_DATABASE_MAX_CONNECTIONS", 4_usize)?;
    if database_max_connections == 0 {
        bail!("AUDIT_ANCHOR_DATABASE_MAX_CONNECTIONS must be greater than zero");
    }
    Ok((database_url, database_max_connections, config))
}

pub(super) fn validate_deployment_id(value: &str) -> anyhow::Result<()> {
    if value.is_empty()
        || value.len() > MAX_DEPLOYMENT_ID_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    {
        bail!(
            "deployment identity must be 1..={MAX_DEPLOYMENT_ID_BYTES} ASCII letters, digits, dots, dashes, or underscores"
        );
    }
    Ok(())
}
