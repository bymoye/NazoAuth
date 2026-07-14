use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use crate::{ModuleId, ModuleRevision};

pub type LifecycleFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[error("module lifecycle failed with {code}")]
pub struct LifecycleFailure {
    pub code: &'static str,
}

pub trait ModuleLifecycle: Send + Sync {
    fn initialize(&self, module_id: ModuleId) -> LifecycleFuture<'_, Result<(), LifecycleFailure>>;

    fn stop(&self, module_id: ModuleId) -> LifecycleFuture<'_, Result<(), LifecycleFailure>>;

    fn drain_stored_transactions(
        &self,
        module_id: ModuleId,
        revision: ModuleRevision,
        remaining_duration: Duration,
    ) -> LifecycleFuture<'_, Result<bool, LifecycleFailure>>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct NoopModuleLifecycle;

impl ModuleLifecycle for NoopModuleLifecycle {
    fn initialize(
        &self,
        _module_id: ModuleId,
    ) -> LifecycleFuture<'_, Result<(), LifecycleFailure>> {
        Box::pin(async { Ok(()) })
    }

    fn stop(&self, _module_id: ModuleId) -> LifecycleFuture<'_, Result<(), LifecycleFailure>> {
        Box::pin(async { Ok(()) })
    }

    fn drain_stored_transactions(
        &self,
        _module_id: ModuleId,
        _revision: ModuleRevision,
        _remaining_duration: Duration,
    ) -> LifecycleFuture<'_, Result<bool, LifecycleFailure>> {
        Box::pin(async { Ok(true) })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReconcileOutcome {
    NoChange,
    Enabled,
    Disabled,
    StaleDiscarded,
    Failed,
}

#[derive(Debug)]
pub enum RegistryError<E> {
    Repository(E),
    MissingDesiredState(ModuleId),
    MissingCatalogSpec(ModuleId),
    RuntimeDisableBlocked(ModuleId),
    ActiveDependent {
        module_id: ModuleId,
        dependent: ModuleId,
    },
    DependencyUnavailable {
        module_id: ModuleId,
        dependency: ModuleId,
    },
    RevisionExhausted(ModuleId),
    SnapshotRevisionExhausted,
}
