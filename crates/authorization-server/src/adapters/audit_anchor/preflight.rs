use chrono::{DateTime, Utc};

use super::{
    AuditAnchorPreflightConfig,
    protocol::encode_hash,
    status::{AnchorHealth, HEALTH_SCHEMA_VERSION, age_seconds, duration_seconds, read_health},
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

    pub(crate) async fn ensure_fresh(
        &self,
        expected_head_sequence: i64,
        expected_head_hash: &[u8],
    ) -> anyhow::Result<()> {
        if !self.config.mode.is_required() {
            return Ok(());
        }

        let status = read_health(&self.config.status_file).await?;
        validate_health(
            &self.config,
            &status,
            expected_head_sequence,
            expected_head_hash,
            Utc::now(),
        )
    }
}

pub(super) fn validate_health(
    config: &AuditAnchorPreflightConfig,
    status: &AnchorHealth,
    expected_head_sequence: i64,
    expected_head_hash: &[u8],
    now: DateTime<Utc>,
) -> anyhow::Result<()> {
    if status.schema_version != HEALTH_SCHEMA_VERSION {
        anyhow::bail!("audit anchor health schema is unsupported");
    }
    if status.deployment_id != config.deployment_id {
        anyhow::bail!("audit anchor health deployment identity does not match this runtime");
    }
    if status.head_sequence != expected_head_sequence
        || status.head_hash != encode_hash(expected_head_hash)
    {
        anyhow::bail!("audit anchor status does not cover the current durable ledger head");
    }

    let observed_age = age_seconds(now, status.observed_at)?;
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

    let Some(last_anchored_sequence) = status.last_anchored_sequence else {
        anyhow::bail!("audit anchor has not completed its first checkpoint");
    };
    let Some(last_anchored_hash) = status.last_anchored_hash.as_deref() else {
        anyhow::bail!("audit anchor status has no last checkpoint hash");
    };
    if status.head_sequence != last_anchored_sequence || status.head_hash != last_anchored_hash {
        anyhow::bail!("audit anchor is behind the current ledger head");
    }
    let Some(last_anchored_occurred_at) = status.last_anchored_occurred_at else {
        anyhow::bail!("audit anchor status has no last checkpoint occurrence time");
    };
    let Some(last_anchored_at) = status.last_anchored_at else {
        anyhow::bail!("audit anchor status has no last checkpoint delivery time");
    };
    age_seconds(now, last_anchored_occurred_at)?;
    age_seconds(now, last_anchored_at)?;
    if last_anchored_at < last_anchored_occurred_at {
        anyhow::bail!("audit anchor checkpoint was delivered before it occurred");
    }
    if status.observed_at < last_anchored_at {
        anyhow::bail!("audit anchor checkpoint was delivered after the health observation");
    }

    let Some(anchor_lag) = status.anchor_lag_seconds else {
        anyhow::bail!("audit anchor status has no delivery lag");
    };
    if anchor_lag < 0 {
        anyhow::bail!("audit anchor status has a negative delivery lag");
    }
    let computed_anchor_lag = if last_anchored_sequence == 0 {
        0
    } else {
        (last_anchored_at - last_anchored_occurred_at).num_seconds()
    };
    if anchor_lag != computed_anchor_lag {
        anyhow::bail!("audit anchor status delivery lag does not match its checkpoint timestamps");
    }
    if anchor_lag > duration_seconds(config.max_lag) {
        anyhow::bail!(
            "audit anchor delivery lag is {anchor_lag}s (limit {}s)",
            duration_seconds(config.max_lag)
        );
    }
    Ok(())
}
