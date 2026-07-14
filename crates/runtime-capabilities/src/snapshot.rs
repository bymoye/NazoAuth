use std::collections::BTreeSet;
use std::sync::Arc;

use arc_swap::{ArcSwap, Guard};

use crate::{ModuleId, ModuleRevision, StaleTransition};

/// Immutable request-facing generation of runtime module admission state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActiveModuleSnapshot {
    pub revision: ModuleRevision,
    pub accepting: BTreeSet<ModuleId>,
    pub draining: BTreeSet<ModuleId>,
}

impl ActiveModuleSnapshot {
    #[must_use]
    pub fn admits(&self, module_id: ModuleId) -> bool {
        self.accepting.contains(&module_id)
    }

    #[must_use]
    pub fn advertises(&self, module_id: ModuleId) -> bool {
        self.admits(module_id)
    }
}

/// Atomically publishes immutable request-facing module state.
pub struct SnapshotStore {
    current: ArcSwap<ActiveModuleSnapshot>,
}

impl SnapshotStore {
    #[must_use]
    pub fn new(initial: ActiveModuleSnapshot) -> Self {
        Self {
            current: ArcSwap::from_pointee(initial),
        }
    }

    #[must_use]
    pub fn load(&self) -> Guard<Arc<ActiveModuleSnapshot>> {
        self.current.load()
    }

    #[must_use]
    pub fn load_full(&self) -> Arc<ActiveModuleSnapshot> {
        self.current.load_full()
    }

    pub fn compare_and_publish(
        &self,
        expected: ModuleRevision,
        next: ActiveModuleSnapshot,
    ) -> Result<(), StaleTransition> {
        if next.revision <= expected {
            return Err(StaleTransition::NonMonotonicPublication {
                expected,
                attempted: next.revision,
            });
        }

        let current = self.current.load();
        if current.revision != expected {
            return Err(StaleTransition::RevisionChanged {
                expected,
                current: current.revision,
            });
        }

        let previous = self.current.compare_and_swap(&current, Arc::new(next));
        if Arc::ptr_eq(&previous, &current) {
            Ok(())
        } else {
            Err(StaleTransition::RevisionChanged {
                expected,
                current: previous.revision,
            })
        }
    }
}
