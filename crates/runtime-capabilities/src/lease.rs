use std::collections::BTreeMap;
use std::future::poll_fn;
use std::sync::{Arc, Mutex};
use std::task::{Poll, Waker};

use crate::{ActiveModuleSnapshot, ModuleId, ModuleRevision};

type GenerationKey = (ModuleId, ModuleRevision);

#[derive(Default)]
struct LeaseState {
    active: BTreeMap<GenerationKey, usize>,
    waiters: BTreeMap<GenerationKey, Vec<Waker>>,
}

#[derive(Clone, Default)]
pub struct RequestLeaseTracker {
    state: Arc<Mutex<LeaseState>>,
}

impl RequestLeaseTracker {
    #[must_use]
    pub fn acquire(
        &self,
        snapshot: Arc<ActiveModuleSnapshot>,
        module_id: ModuleId,
    ) -> Option<RequestLease> {
        if !snapshot.admits(module_id) {
            return None;
        }
        let key = (module_id, snapshot.revision);
        *self
            .state
            .lock()
            .expect("request lease lock poisoned")
            .active
            .entry(key)
            .or_default() += 1;
        Some(RequestLease {
            key,
            state: Arc::clone(&self.state),
            snapshot,
        })
    }

    #[must_use]
    pub fn active(&self, module_id: ModuleId, generation: ModuleRevision) -> usize {
        self.state
            .lock()
            .expect("request lease lock poisoned")
            .active
            .get(&(module_id, generation))
            .copied()
            .unwrap_or_default()
    }

    pub async fn wait_until_zero(&self, module_id: ModuleId, generation: ModuleRevision) {
        let key = (module_id, generation);
        poll_fn(|context| {
            let mut state = self.state.lock().expect("request lease lock poisoned");
            if state.active.get(&key).copied().unwrap_or_default() == 0 {
                return Poll::Ready(());
            }
            let waiters = state.waiters.entry(key).or_default();
            if !waiters.iter().any(|waker| waker.will_wake(context.waker())) {
                waiters.push(context.waker().clone());
            }
            Poll::Pending
        })
        .await;
    }
}

pub struct RequestLease {
    key: GenerationKey,
    state: Arc<Mutex<LeaseState>>,
    snapshot: Arc<ActiveModuleSnapshot>,
}

impl RequestLease {
    #[must_use]
    pub fn snapshot(&self) -> &ActiveModuleSnapshot {
        &self.snapshot
    }
}

impl Drop for RequestLease {
    fn drop(&mut self) {
        let mut state = self.state.lock().expect("request lease lock poisoned");
        let Some(active) = state.active.get_mut(&self.key) else {
            return;
        };
        *active -= 1;
        if *active == 0 {
            state.active.remove(&self.key);
            for waker in state.waiters.remove(&self.key).unwrap_or_default() {
                waker.wake();
            }
        }
    }
}
