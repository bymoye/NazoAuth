use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

/// Monotonic revision binding desired, actual, and snapshot state.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ModuleRevision(u64);

impl ModuleRevision {
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// A revision-bound transition or publication can no longer proceed safely.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum StaleTransition {
    #[error(
        "stale module transition: expected revision {expected:?}, current revision {current:?}"
    )]
    RevisionChanged {
        expected: ModuleRevision,
        current: ModuleRevision,
    },
    #[error(
        "non-monotonic snapshot publication: expected a revision after {expected:?}, attempted {attempted:?}"
    )]
    NonMonotonicPublication {
        expected: ModuleRevision,
        attempted: ModuleRevision,
    },
}

/// Cheap revision token revalidated around transition side effects.
pub struct TransitionGuard {
    latest: Arc<AtomicU64>,
    bound: ModuleRevision,
}

impl TransitionGuard {
    #[must_use]
    pub fn bind(latest: Arc<AtomicU64>, bound: ModuleRevision) -> Self {
        Self { latest, bound }
    }

    pub fn ensure_current(&self) -> Result<(), StaleTransition> {
        let current = ModuleRevision::new(self.latest.load(Ordering::Acquire));
        if current == self.bound {
            Ok(())
        } else {
            Err(StaleTransition::RevisionChanged {
                expected: self.bound,
                current,
            })
        }
    }

    #[must_use]
    pub const fn revision(&self) -> ModuleRevision {
        self.bound
    }
}
