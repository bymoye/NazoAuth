use std::collections::BTreeMap;
use std::sync::Arc;

use crate::{
    ActiveModuleSnapshot, ModuleCatalog, ModuleId, ModuleLifecycle, ModuleStateRepository,
    RequestLeaseTracker, SnapshotStore,
};

#[path = "registry/dependency.rs"]
mod dependency;
#[path = "registry/desired.rs"]
mod desired;
#[path = "registry/lease.rs"]
mod lease;
#[path = "registry/persistence.rs"]
mod persistence;
#[path = "registry/reconcile.rs"]
mod reconcile;
#[path = "registry/transition.rs"]
mod transition;

/// Coordinates durable desired state, one process instance's lifecycle, and
/// the lock-free admission snapshot used by request handlers.
pub struct RuntimeModuleRegistry<R, L> {
    repository: Arc<R>,
    lifecycle: Arc<L>,
    catalog: ModuleCatalog,
    instance_id: String,
    snapshots: Arc<SnapshotStore>,
    leases: RequestLeaseTracker,
    desired_policy_lock: futures_util::lock::Mutex<()>,
    transition_locks: BTreeMap<ModuleId, Arc<futures_util::lock::Mutex<()>>>,
}

impl<R, L> RuntimeModuleRegistry<R, L>
where
    R: ModuleStateRepository,
    L: ModuleLifecycle,
{
    #[must_use]
    pub fn new(
        repository: Arc<R>,
        lifecycle: Arc<L>,
        catalog: ModuleCatalog,
        instance_id: String,
        initial_snapshot: ActiveModuleSnapshot,
    ) -> Self {
        Self {
            repository,
            lifecycle,
            catalog,
            instance_id,
            snapshots: Arc::new(SnapshotStore::new(initial_snapshot)),
            leases: RequestLeaseTracker::default(),
            desired_policy_lock: futures_util::lock::Mutex::new(()),
            transition_locks: ModuleId::ALL
                .into_iter()
                .map(|module_id| (module_id, Arc::new(futures_util::lock::Mutex::new(()))))
                .collect(),
        }
    }
}
