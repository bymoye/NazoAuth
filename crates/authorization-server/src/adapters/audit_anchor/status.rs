use std::time::Duration;

use chrono::{DateTime, Utc};
use nazo_persistence::{SecurityAuditAnchorHealth, SecurityAuditOutboxDelivery};

use super::protocol::encode_hash;

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

pub(super) fn age_seconds(now: DateTime<Utc>, value: DateTime<Utc>) -> anyhow::Result<i64> {
    let age = (now - value).num_seconds();
    if age < 0 {
        anyhow::bail!("audit anchor timestamp is in the future");
    }
    Ok(age)
}

pub(super) fn duration_seconds(value: Duration) -> i64 {
    i64::try_from(value.as_secs()).unwrap_or(i64::MAX)
}
