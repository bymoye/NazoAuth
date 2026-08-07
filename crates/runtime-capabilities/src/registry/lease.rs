use std::collections::BTreeSet;
use std::sync::Arc;

use crate::{
    ActiveModuleSnapshot, ModuleId, ModuleLifecycle, ModuleRevision, ModuleStateRepository,
    RegistryError, RequestLease,
};

use super::RuntimeModuleRegistry;

impl<R, L> RuntimeModuleRegistry<R, L>
where
    R: ModuleStateRepository,
    L: ModuleLifecycle,
{
    #[must_use]
    pub fn snapshot(&self) -> Arc<ActiveModuleSnapshot> {
        self.snapshots.load_full()
    }

    #[must_use]
    pub fn lease(&self, module_id: ModuleId) -> Option<RequestLease> {
        self.leases.acquire(self.snapshot(), module_id)
    }

    /// Publishes a new admission generation and closes leases from the old
    /// generation whenever a module stops accepting requests.
    pub(super) fn publish(
        &self,
        module_id: ModuleId,
        accepting: bool,
        draining: bool,
    ) -> Result<(), RegistryError<R::Error>> {
        loop {
            let current = self.snapshots.load_full();
            let mut accepting_set = current.accepting.clone();
            let mut draining_set = current.draining.clone();
            set_membership(&mut accepting_set, module_id, accepting);
            set_membership(&mut draining_set, module_id, draining);
            let next_revision = current
                .revision
                .get()
                .checked_add(1)
                .ok_or(RegistryError::SnapshotRevisionExhausted)?;
            let next = ActiveModuleSnapshot {
                revision: ModuleRevision::new(next_revision),
                accepting: accepting_set,
                draining: draining_set,
            };
            if !accepting && current.admits(module_id) {
                self.leases.close_generation(module_id, current.revision);
            }
            if self
                .snapshots
                .compare_and_publish(current.revision, next)
                .is_ok()
            {
                return Ok(());
            }
        }
    }
}

fn set_membership(set: &mut BTreeSet<ModuleId>, module_id: ModuleId, present: bool) {
    if present {
        set.insert(module_id);
    } else {
        set.remove(&module_id);
    }
}
