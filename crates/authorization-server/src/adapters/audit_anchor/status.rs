use std::{path::Path, time::Duration};

use anyhow::{Context as _, bail};
use chrono::{DateTime, Utc};
use nazo_postgres::{SecurityAuditAnchorHealth, SecurityAuditOutboxDelivery};
use serde::{Deserialize, Serialize};

use super::{AuditAnchorPreflightConfig, protocol::encode_hash};

pub(super) const HEALTH_SCHEMA_VERSION: &str = "nazo.audit.anchor.health.v1";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct AnchorHealth {
    pub(super) schema_version: String,
    pub(super) deployment_id: String,
    pub(super) observed_at: DateTime<Utc>,
    pub(super) head_sequence: i64,
    pub(super) head_hash: String,
    pub(super) pending_count: i64,
    pub(super) oldest_pending_occurred_at: Option<DateTime<Utc>>,
    pub(super) last_anchored_sequence: Option<i64>,
    pub(super) last_anchored_hash: Option<String>,
    pub(super) last_anchored_occurred_at: Option<DateTime<Utc>>,
    pub(super) last_anchored_at: Option<DateTime<Utc>>,
    pub(super) anchor_lag_seconds: Option<i64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct AnchorCheckpoint {
    pub(super) sequence: i64,
    pub(super) hash: String,
    pub(super) occurred_at: DateTime<Utc>,
    pub(super) anchored_at: DateTime<Utc>,
}

impl AnchorCheckpoint {
    pub(super) fn from_snapshot(snapshot: &SecurityAuditAnchorHealth) -> Option<Self> {
        Some(Self {
            sequence: snapshot.last_exported_sequence?,
            hash: encode_hash(snapshot.last_exported_hash.as_deref()?),
            occurred_at: snapshot.last_exported_occurred_at?,
            anchored_at: snapshot.last_exported_at?,
        })
    }

    pub(super) fn from_health(health: &AnchorHealth) -> Option<Self> {
        Some(Self {
            sequence: health.last_anchored_sequence?,
            hash: health.last_anchored_hash.clone()?,
            occurred_at: health.last_anchored_occurred_at?,
            anchored_at: health.last_anchored_at?,
        })
    }

    pub(super) fn from_delivery(delivery: &SecurityAuditOutboxDelivery) -> Self {
        Self {
            sequence: delivery.sequence,
            hash: encode_hash(&delivery.event_hash),
            occurred_at: delivery.occurred_at,
            anchored_at: Utc::now(),
        }
    }

    pub(super) fn genesis(hash: String) -> Self {
        let now = Utc::now();
        Self {
            sequence: 0,
            hash,
            occurred_at: DateTime::<Utc>::UNIX_EPOCH,
            anchored_at: now,
        }
    }
}

pub(super) async fn write_health(
    config: &AuditAnchorPreflightConfig,
    snapshot: &SecurityAuditAnchorHealth,
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
        anchor_lag_seconds: last_anchored.map(|value| {
            if value.sequence == 0 {
                0
            } else {
                (value.anchored_at - value.occurred_at).num_seconds().max(0)
            }
        }),
    };
    let bytes = serde_json::to_vec(&health).context("failed to encode audit anchor health")?;
    write_atomic(&config.status_file, bytes).await
}

pub(super) async fn read_health(path: &Path) -> anyhow::Result<AnchorHealth> {
    let bytes = tokio::fs::read(path)
        .await
        .with_context(|| format!("failed to read audit anchor health {}", path.display()))?;
    serde_json::from_slice(&bytes)
        .with_context(|| format!("failed to parse audit anchor health {}", path.display()))
}

pub(super) async fn read_health_optional(path: &Path) -> anyhow::Result<Option<AnchorHealth>> {
    match tokio::fs::read(path).await {
        Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes).with_context(|| {
            format!("failed to parse audit anchor health {}", path.display())
        })?)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error)
            .with_context(|| format!("failed to read audit anchor health {}", path.display())),
    }
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

pub(super) fn age_seconds(now: DateTime<Utc>, timestamp: DateTime<Utc>) -> anyhow::Result<i64> {
    if timestamp > now {
        bail!("audit anchor health timestamp is in the future");
    }
    Ok((now - timestamp).num_seconds())
}

pub(super) fn duration_seconds(value: Duration) -> i64 {
    value.as_secs().min(i64::MAX as u64) as i64
}
