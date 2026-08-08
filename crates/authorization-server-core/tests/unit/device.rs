use chrono::{Duration, TimeZone, Utc};

use super::device_approval_claim_is_stale;

#[test]
fn stale_approval_claims_are_reclaimable_but_bounded() {
    let started_at = Utc.timestamp_opt(1_700_000_000, 0).single().unwrap();
    assert!(!device_approval_claim_is_stale(
        started_at,
        started_at + Duration::seconds(29)
    ));
    assert!(device_approval_claim_is_stale(
        started_at,
        started_at + Duration::seconds(30)
    ));
    assert!(!device_approval_claim_is_stale(
        started_at,
        started_at - Duration::seconds(1)
    ));
}
