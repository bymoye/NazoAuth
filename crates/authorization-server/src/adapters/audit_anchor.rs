//! Exporter-side anchoring for the append-only security audit ledger.
//!
//! The HTTP exporter deliberately lives outside the authorization-server
//! request process.  It uses a separate database pool/role, claims the durable
//! ledger outbox in bounded batches, and only acknowledges a row after the
//! independent sink accepts the checkpoint.  The server process only reads the
//! small health file written by this worker for fail-closed preflight checks;
//! it never receives the exporter credential or exporter database handle.

use std::{
    path::{Path, PathBuf},
    sync::OnceLock,
    time::Duration,
};

use anyhow::{Context as _, bail};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use hmac::{Hmac, KeyInit, Mac};
use nazo_postgres::{AuditLedgerRepository, SecurityAuditOutboxDelivery};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use url::Url;

use crate::config::ConfigSource;

const HEALTH_SCHEMA_VERSION: &str = "nazo.audit.anchor.health.v1";
const CHECKPOINT_SCHEMA_VERSION: &str = "nazo.audit.anchor.v1";
const MAX_BATCH_SIZE: i64 = 256;
const MAX_RETRY_DELAY: Duration = Duration::from_secs(300);
const MAX_DEPLOYMENT_ID_BYTES: usize = 255;

type HmacSha256 = Hmac<Sha256>;

static PREFLIGHT_CONFIG: OnceLock<AuditAnchorPreflightConfig> = OnceLock::new();

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

/// Configuration that is safe to pass to the server process.
///
/// This contains no sink URL credential or database handle.  The status file
/// is an availability signal, not a trust root: a privileged local attacker
/// can forge it, so production still needs an independently protected sink.
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

/// Configuration used only by the independent exporter command/sidecar.
///
/// `auth_secret` must come from a secret environment/file input in the
/// exporter process.  Do not derive `Debug` or include it in diagnostics.
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
            .map(PathBuf::from)
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
    let data_dir = PathBuf::from(source.string("DATA_DIR", "runtime"));
    let preflight = preflight_config_from_source(source, &data_dir)?;
    let endpoint = Url::parse(&source.required_string("AUDIT_ANCHOR_URL")?)
        .context("AUDIT_ANCHOR_URL must be a valid absolute URL")?;
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

/// Register the server-side preflight configuration once at bootstrap.
pub(crate) fn configure_preflight(config: AuditAnchorPreflightConfig) -> anyhow::Result<()> {
    config.validate()?;
    if let Some(existing) = PREFLIGHT_CONFIG.get() {
        if existing == &config {
            return Ok(());
        }
        bail!("audit anchor preflight was configured more than once with different values");
    }
    let _ = PREFLIGHT_CONFIG.set(config);
    Ok(())
}

/// Check whether the independent exporter has observed and anchored the
/// current ledger head recently enough for a high-impact mutation.
pub(crate) async fn ensure_fresh(
    expected_head_sequence: i64,
    expected_head_hash: &[u8],
) -> anyhow::Result<()> {
    let Some(config) = PREFLIGHT_CONFIG.get() else {
        bail!("audit anchor preflight is not configured");
    };
    if !config.mode.is_required() {
        return Ok(());
    }

    let status = read_health(&config.status_file).await?;
    if status.schema_version != HEALTH_SCHEMA_VERSION {
        bail!("audit anchor health schema is unsupported");
    }
    if status.deployment_id != config.deployment_id {
        bail!("audit anchor health deployment identity does not match this runtime");
    }
    if status.head_sequence != expected_head_sequence
        || status.head_hash != encode_hash(expected_head_hash)
    {
        bail!("audit anchor status does not cover the current durable ledger head");
    }
    let now = Utc::now();
    let observed_age = age_seconds(now, status.observed_at)?;
    if observed_age > duration_seconds(config.freshness) {
        bail!(
            "audit anchor health is stale: observed {observed_age}s ago (limit {}s)",
            duration_seconds(config.freshness)
        );
    }
    if status.pending_count != 0 {
        let pending_lag = status
            .oldest_pending_occurred_at
            .map(|occurred_at| age_seconds(now, occurred_at))
            .transpose()?
            .unwrap_or_default();
        bail!(
            "audit anchor has {} pending ledger entries (oldest lag {pending_lag}s)",
            status.pending_count
        );
    }
    let Some(last_anchored_sequence) = status.last_anchored_sequence else {
        bail!("audit anchor has not completed its first checkpoint");
    };
    let Some(last_anchored_hash) = status.last_anchored_hash.as_deref() else {
        bail!("audit anchor status has no last checkpoint hash");
    };
    if status.head_sequence != last_anchored_sequence || status.head_hash != last_anchored_hash {
        bail!("audit anchor is behind the current ledger head");
    }
    let anchor_lag = status.anchor_lag_seconds.unwrap_or_default();
    if anchor_lag > duration_seconds(config.max_lag) {
        bail!(
            "audit anchor delivery lag is {anchor_lag}s (limit {}s)",
            duration_seconds(config.max_lag)
        );
    }
    Ok(())
}

/// Run the exporter until cancellation.  The caller must construct the
/// repository from an independent database URL/role and provide the sink
/// credential only in this worker process.
pub(crate) async fn run_worker(
    repository: AuditLedgerRepository,
    config: AuditAnchorWorkerConfig,
) -> anyhow::Result<()> {
    config.validate()?;
    repository
        .check_exporter_available()
        .await
        .map_err(|_| anyhow::anyhow!("audit anchor exporter capability preflight failed"))?;
    let client = reqwest::Client::builder()
        .timeout(config.request_timeout)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("failed to build audit anchor HTTP client")?;
    tracing::info!(
        target: "audit.anchor",
        endpoint_host = config.endpoint.host_str().unwrap_or("unknown"),
        deployment_id = %config.preflight.deployment_id,
        mode = ?config.preflight.mode,
        "starting independent audit anchor worker"
    );

    loop {
        let snapshot = match repository.anchor_health().await {
            Ok(snapshot) => snapshot,
            Err(error) => {
                tracing::warn!(
                    target: "audit.anchor",
                    error_kind = %error_kind(&error),
                    "audit anchor ledger health query failed"
                );
                tokio::time::sleep(retry_delay(1)).await;
                continue;
            }
        };
        let last_anchored =
            if snapshot.head_sequence == 0 && snapshot.last_exported_sequence.is_none() {
                match send_genesis_checkpoint(&client, &config, &snapshot).await {
                    Ok(checkpoint) => Some(checkpoint),
                    Err(error) => {
                        tracing::warn!(
                            target: "audit.anchor",
                            error_kind = error.code(),
                            "audit anchor genesis checkpoint failed"
                        );
                        tokio::time::sleep(retry_delay(1)).await;
                        continue;
                    }
                }
            } else {
                AnchorCheckpoint::from_snapshot(&snapshot)
            };
        if let Err(error) = write_health(
            &config.preflight,
            &snapshot,
            last_anchored.as_ref(),
            Utc::now(),
        )
        .await
        {
            tracing::error!(
                target: "audit.anchor",
                error_kind = %error_kind(&error),
                "failed to publish audit anchor health"
            );
        }

        let deliveries = match repository
            .claim_due(config.batch_size, config.lock_timeout_seconds)
            .await
        {
            Ok(deliveries) => deliveries,
            Err(error) => {
                tracing::warn!(
                    target: "audit.anchor",
                    error_kind = %error_kind(&error),
                    "audit anchor outbox claim failed"
                );
                tokio::time::sleep(retry_delay(1)).await;
                continue;
            }
        };
        if deliveries.is_empty() {
            tokio::time::sleep(config.poll_interval).await;
            continue;
        }

        for (index, delivery) in deliveries.iter().enumerate() {
            match send_checkpoint(&client, &config, delivery).await {
                Ok(()) => match repository
                    .mark_exported(delivery.event_id, delivery.attempts)
                    .await
                {
                    Ok(()) => {
                        tracing::info!(
                            target: "audit.anchor",
                            event_id = %delivery.event_id,
                            sequence = delivery.sequence,
                            anchor_lag_seconds = delivery_lag_seconds(delivery),
                            status = "anchored",
                            "audit ledger checkpoint accepted by independent sink"
                        );
                    }
                    Err(error) => {
                        let delay = retry_delay(delivery.attempts);
                        reschedule_claimed(
                            &repository,
                            &deliveries[index..],
                            delay,
                            "ack_database_error",
                        )
                        .await;
                        tracing::warn!(
                            target: "audit.anchor",
                            event_id = %delivery.event_id,
                            sequence = delivery.sequence,
                            error_kind = %error_kind(&error),
                            "audit anchor acknowledgement failed; retrying idempotently"
                        );
                        break;
                    }
                },
                Err(error) => {
                    let delay = retry_delay(delivery.attempts);
                    reschedule_claimed(&repository, &deliveries[index..], delay, error.code())
                        .await;
                    tracing::warn!(
                        target: "audit.anchor",
                        event_id = %delivery.event_id,
                        sequence = delivery.sequence,
                        error_kind = error.code(),
                        retry_after_seconds = delay.as_secs(),
                        "audit checkpoint push failed; durable retry scheduled"
                    );
                    break;
                }
            }
        }
    }
}

async fn reschedule_claimed(
    repository: &AuditLedgerRepository,
    deliveries: &[SecurityAuditOutboxDelivery],
    delay: Duration,
    reason: &str,
) {
    let available_at = Utc::now()
        + ChronoDuration::from_std(delay).unwrap_or_else(|_| ChronoDuration::seconds(300));
    for delivery in deliveries {
        if let Err(error) = repository
            .reschedule(delivery.event_id, delivery.attempts, available_at, reason)
            .await
        {
            tracing::error!(
                target: "audit.anchor",
                event_id = %delivery.event_id,
                sequence = delivery.sequence,
                error_kind = %error_kind(&error),
                "failed to reschedule audit anchor delivery"
            );
        }
    }
}

async fn send_checkpoint(
    client: &reqwest::Client,
    config: &AuditAnchorWorkerConfig,
    delivery: &SecurityAuditOutboxDelivery,
) -> Result<(), AnchorPushError> {
    let checkpoint = AnchorCheckpointEnvelope {
        schema_version: CHECKPOINT_SCHEMA_VERSION,
        event_id: delivery.event_id,
        deployment_id: &config.preflight.deployment_id,
        sequence: delivery.sequence,
        previous_hash: encode_hash(&delivery.previous_hash),
        event_hash: encode_hash(&delivery.event_hash),
        occurred_at: delivery.occurred_at,
        anchored_at: Utc::now(),
    };
    let body = serde_json::to_vec(&checkpoint).map_err(|_| AnchorPushError::Serialize)?;
    let signature = sign_body(&config.auth_secret, &body);
    let response = client
        .post(config.endpoint.clone())
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .header("Idempotency-Key", delivery.event_id.to_string())
        .header("X-Nazo-Audit-Schema", CHECKPOINT_SCHEMA_VERSION)
        .header("X-Nazo-Audit-Deployment", &config.preflight.deployment_id)
        .header("X-Nazo-Audit-Signature", format!("sha256={signature}"))
        .body(body)
        .send()
        .await
        .map_err(|_| AnchorPushError::Transport)?;
    let status = response.status();
    if status.is_success() {
        Ok(())
    } else {
        Err(AnchorPushError::Http(status.as_u16()))
    }
}

async fn send_genesis_checkpoint(
    client: &reqwest::Client,
    config: &AuditAnchorWorkerConfig,
    snapshot: &nazo_postgres::SecurityAuditAnchorHealth,
) -> Result<AnchorCheckpoint, AnchorPushError> {
    let anchored_at = Utc::now();
    let occurred_at = DateTime::<Utc>::UNIX_EPOCH;
    let hash = encode_hash(&snapshot.head_hash);
    let body = serde_json::to_vec(&serde_json::json!({
        "schema_version": CHECKPOINT_SCHEMA_VERSION,
        "event_id": uuid::Uuid::nil(),
        "deployment_id": &config.preflight.deployment_id,
        "sequence": 0,
        "previous_hash": &hash,
        "event_hash": &hash,
        "occurred_at": occurred_at,
        "anchored_at": anchored_at,
    }))
    .map_err(|_| AnchorPushError::Serialize)?;
    let signature = sign_body(&config.auth_secret, &body);
    let response = client
        .post(config.endpoint.clone())
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .header(
            "Idempotency-Key",
            format!("genesis:{}", config.preflight.deployment_id),
        )
        .header("X-Nazo-Audit-Schema", CHECKPOINT_SCHEMA_VERSION)
        .header("X-Nazo-Audit-Deployment", &config.preflight.deployment_id)
        .header("X-Nazo-Audit-Signature", format!("sha256={signature}"))
        .body(body)
        .send()
        .await
        .map_err(|_| AnchorPushError::Transport)?;
    if !response.status().is_success() {
        return Err(AnchorPushError::Http(response.status().as_u16()));
    }
    Ok(AnchorCheckpoint {
        sequence: 0,
        hash,
        occurred_at,
        anchored_at,
    })
}

#[derive(Debug)]
enum AnchorPushError {
    Transport,
    Serialize,
    Http(u16),
}

impl AnchorPushError {
    const fn code(&self) -> &'static str {
        match self {
            Self::Transport => "transport_error",
            Self::Serialize => "serialization_error",
            Self::Http(429) => "http_429",
            Self::Http(400..=499) => "http_4xx",
            Self::Http(500..=599) => "http_5xx",
            Self::Http(_) => "http_other",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct AnchorHealth {
    schema_version: String,
    deployment_id: String,
    observed_at: DateTime<Utc>,
    head_sequence: i64,
    head_hash: String,
    pending_count: i64,
    oldest_pending_occurred_at: Option<DateTime<Utc>>,
    last_anchored_sequence: Option<i64>,
    last_anchored_hash: Option<String>,
    last_anchored_occurred_at: Option<DateTime<Utc>>,
    last_anchored_at: Option<DateTime<Utc>>,
    anchor_lag_seconds: Option<i64>,
}

#[derive(Clone, Debug)]
struct AnchorCheckpoint {
    sequence: i64,
    hash: String,
    occurred_at: DateTime<Utc>,
    anchored_at: DateTime<Utc>,
}

impl AnchorCheckpoint {
    fn from_snapshot(snapshot: &nazo_postgres::SecurityAuditAnchorHealth) -> Option<Self> {
        Some(Self {
            sequence: snapshot.last_exported_sequence?,
            hash: encode_hash(snapshot.last_exported_hash.as_deref()?),
            occurred_at: snapshot.last_exported_occurred_at?,
            anchored_at: snapshot.last_exported_at?,
        })
    }
}

#[derive(Serialize)]
struct AnchorCheckpointEnvelope<'a> {
    schema_version: &'static str,
    event_id: uuid::Uuid,
    deployment_id: &'a str,
    sequence: i64,
    previous_hash: String,
    event_hash: String,
    occurred_at: DateTime<Utc>,
    anchored_at: DateTime<Utc>,
}

async fn write_health(
    config: &AuditAnchorPreflightConfig,
    snapshot: &nazo_postgres::SecurityAuditAnchorHealth,
    last_anchored: Option<&AnchorCheckpoint>,
    observed_at: DateTime<Utc>,
) -> anyhow::Result<()> {
    let health = AnchorHealth {
        schema_version: HEALTH_SCHEMA_VERSION.to_owned(),
        deployment_id: config.deployment_id.clone(),
        observed_at,
        head_sequence: snapshot.head_sequence,
        head_hash: encode_hash(&snapshot.head_hash),
        pending_count: snapshot.pending_count,
        oldest_pending_occurred_at: snapshot.oldest_pending_occurred_at,
        last_anchored_sequence: last_anchored.map(|value| value.sequence),
        last_anchored_hash: last_anchored.map(|value| value.hash.clone()),
        last_anchored_occurred_at: last_anchored.map(|value| value.occurred_at),
        last_anchored_at: last_anchored.map(|value| value.anchored_at),
        anchor_lag_seconds: last_anchored
            .map(|value| (value.anchored_at - value.occurred_at).num_seconds().max(0)),
    };
    let bytes = serde_json::to_vec(&health).context("failed to encode audit anchor health")?;
    write_atomic(&config.status_file, bytes).await
}

async fn read_health(path: &Path) -> anyhow::Result<AnchorHealth> {
    let bytes = tokio::fs::read(path)
        .await
        .with_context(|| format!("failed to read audit anchor health {}", path.display()))?;
    serde_json::from_slice(&bytes)
        .with_context(|| format!("failed to parse audit anchor health {}", path.display()))
}

async fn write_atomic(path: &Path, bytes: Vec<u8>) -> anyhow::Result<()> {
    let Some(parent) = path.parent() else {
        bail!("audit anchor health path has no parent directory");
    };
    tokio::fs::create_dir_all(parent).await.with_context(|| {
        format!(
            "failed to create audit anchor health directory {}",
            parent.display()
        )
    })?;
    let destination = path.to_owned();
    tokio::task::spawn_blocking(move || {
        use std::io::Write as _;
        atomicwrites::AtomicFile::new(&destination, atomicwrites::AllowOverwrite)
            .write(|file| file.write_all(&bytes))
            .map_err(std::io::Error::from)
    })
    .await
    .context("audit anchor health writer task failed")??;
    Ok(())
}

fn sign_body(secret: &[u8], body: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts arbitrary key lengths");
    mac.update(body);
    URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
}

fn encode_hash(hash: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(hash)
}

fn retry_delay(attempts: i32) -> Duration {
    let exponent = attempts.saturating_sub(1).clamp(0, 63) as u32;
    let seconds = 2_u64
        .saturating_pow(exponent)
        .min(MAX_RETRY_DELAY.as_secs());
    Duration::from_secs(seconds)
}

fn delivery_lag_seconds(delivery: &SecurityAuditOutboxDelivery) -> i64 {
    (Utc::now() - delivery.occurred_at).num_seconds().max(0)
}

fn validate_deployment_id(value: &str) -> anyhow::Result<()> {
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

fn age_seconds(now: DateTime<Utc>, timestamp: DateTime<Utc>) -> anyhow::Result<i64> {
    let age = (now - timestamp).num_seconds();
    if age < 0 {
        bail!("audit anchor health timestamp is in the future");
    }
    Ok(age)
}

fn duration_seconds(value: Duration) -> i64 {
    value.as_secs().min(i64::MAX as u64) as i64
}

fn error_kind<T>(_error: &T) -> &'static str {
    "external_error"
}

#[cfg(test)]
#[path = "../../tests/unit/adapters/audit_anchor.rs"]
mod tests;
