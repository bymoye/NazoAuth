use std::sync::Arc;

use chrono::{Duration, TimeZone, Utc};

use super::{DeviceStateStorePort, DeviceStateVersion, device_approval_claim_is_stale};

fn assert_arc_port<T>()
where
    T: DeviceStateStorePort + ?Sized,
    Arc<T>: DeviceStateStorePort<Version = T::Version>,
{
}

#[test]
fn state_version_exposes_the_opaque_comparison_token() {
    let version = DeviceStateVersion::new("opaque-snapshot".to_owned());

    assert_eq!(version.comparison_token(), "opaque-snapshot");
}

#[test]
fn arc_trait_objects_preserve_the_store_version_type() {
    assert_arc_port::<dyn DeviceStateStorePort<Version = DeviceStateVersion>>();
}

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
