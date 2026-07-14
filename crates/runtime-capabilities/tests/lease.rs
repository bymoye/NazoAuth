use std::collections::BTreeSet;
use std::sync::Arc;

use nazo_runtime_modules::{ActiveModuleSnapshot, ModuleId, ModuleRevision, RequestLeaseTracker};

fn snapshot(revision: u64, accepting: &[ModuleId]) -> ActiveModuleSnapshot {
    ActiveModuleSnapshot {
        revision: ModuleRevision::new(revision),
        accepting: accepting.iter().copied().collect(),
        draining: BTreeSet::new(),
    }
}

#[test]
fn lease_is_issued_only_for_admitted_module_and_generation() {
    let tracker = RequestLeaseTracker::default();
    let snapshot = Arc::new(snapshot(7, &[ModuleId::Ciba]));

    let lease = tracker
        .acquire(Arc::clone(&snapshot), ModuleId::Ciba)
        .unwrap();
    assert!(
        tracker
            .acquire(Arc::clone(&snapshot), ModuleId::Scim)
            .is_none()
    );
    assert_eq!(tracker.active(ModuleId::Ciba, ModuleRevision::new(7)), 1);
    drop(lease);
    assert_eq!(tracker.active(ModuleId::Ciba, ModuleRevision::new(7)), 0);
}

#[test]
fn metadata_capability_and_new_work_admission_are_the_same_snapshot_fact() {
    let active = snapshot(4, &[ModuleId::Jarm]);
    assert_eq!(
        active.admits(ModuleId::Jarm),
        active.advertises(ModuleId::Jarm)
    );
    assert_eq!(
        active.admits(ModuleId::Ciba),
        active.advertises(ModuleId::Ciba)
    );
}
