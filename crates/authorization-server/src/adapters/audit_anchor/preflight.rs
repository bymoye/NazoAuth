use chrono::{DateTime, Utc};
use nazo_persistence::SecurityAuditAnchorHealth;

use super::{
    AuditAnchorPreflightConfig,
    status::{age_seconds, duration_seconds},
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AuditAnchorPreflight {
    config: AuditAnchorPreflightConfig,
}

impl AuditAnchorPreflight {
    pub(crate) fn new(config: AuditAnchorPreflightConfig) -> anyhow::Result<Self> {
        config.validate()?;
        Ok(Self { config })
    }

    pub(crate) fn ensure_fresh(&self, status: &SecurityAuditAnchorHealth) -> anyhow::Result<()> {
        if !self.config.mode.is_required() {
            return Ok(());
        }
        validate_health(&self.config, status, Utc::now())
    }
}

pub(super) fn validate_health(
    config: &AuditAnchorPreflightConfig,
    status: &SecurityAuditAnchorHealth,
    now: DateTime<Utc>,
) -> anyhow::Result<()> {
    if status.deployment_id.as_deref() != Some(config.deployment_id.as_str()) {
        anyhow::bail!("audit anchor deployment identity does not match this runtime");
    }
    let observed_at = status
        .observed_at
        .ok_or_else(|| anyhow::anyhow!("audit anchor has not been observed by a worker"))?;
    let observed_age = age_seconds(now, observed_at)?;
    if observed_age > duration_seconds(config.freshness) {
        anyhow::bail!(
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
        anyhow::bail!(
            "audit anchor has {} pending ledger entries (oldest lag {pending_lag}s)",
            status.pending_count
        );
    }
    let sequence = status
        .last_exported_sequence
        .ok_or_else(|| anyhow::anyhow!("audit anchor has not completed its first checkpoint"))?;
    let hash = status
        .last_exported_hash
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("audit anchor status has no last checkpoint hash"))?;
    if sequence != status.head_sequence || hash != status.head_hash {
        anyhow::bail!("audit anchor is behind the current ledger head");
    }
    let occurred_at = status.last_exported_occurred_at.ok_or_else(|| {
        anyhow::anyhow!("audit anchor status has no last checkpoint occurrence time")
    })?;
    let anchored_at = status.last_exported_at.ok_or_else(|| {
        anyhow::anyhow!("audit anchor status has no last checkpoint delivery time")
    })?;
    age_seconds(now, occurred_at)?;
    age_seconds(now, anchored_at)?;
    if anchored_at < occurred_at {
        anyhow::bail!("audit anchor checkpoint was delivered before it occurred");
    }
    let anchor_lag = if sequence == 0 {
        0
    } else {
        (anchored_at - occurred_at).num_seconds()
    };
    if anchor_lag > duration_seconds(config.max_lag) {
        anyhow::bail!(
            "audit anchor delivery lag is {anchor_lag}s (limit {}s)",
            duration_seconds(config.max_lag)
        );
    }
    Ok(())
}
