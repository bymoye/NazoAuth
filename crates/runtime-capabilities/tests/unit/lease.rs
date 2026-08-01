use std::collections::BTreeSet;

use super::*;

#[test]
fn closed_generation_rejects_a_delayed_stale_snapshot() {
    let tracker = RequestLeaseTracker::default();
    let snapshot = Arc::new(ActiveModuleSnapshot {
        revision: ModuleRevision::new(7),
        accepting: BTreeSet::from([ModuleId::Ciba]),
        draining: BTreeSet::new(),
    });

    tracker.close_generation(ModuleId::Ciba, snapshot.revision);

    assert!(tracker.acquire(snapshot, ModuleId::Ciba).is_none());
}

#[test]
fn closing_an_old_generation_does_not_reject_a_new_generation() {
    let tracker = RequestLeaseTracker::default();
    tracker.close_generation(ModuleId::Ciba, ModuleRevision::new(7));
    let snapshot = Arc::new(ActiveModuleSnapshot {
        revision: ModuleRevision::new(8),
        accepting: BTreeSet::from([ModuleId::Ciba]),
        draining: BTreeSet::new(),
    });

    assert!(tracker.acquire(snapshot, ModuleId::Ciba).is_some());
}
