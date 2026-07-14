//! Infrastructure-free runtime-module state model.

mod catalog;
mod lease;
mod management;
mod model;
mod policy;
mod reconcile;
mod registry;
mod repository;
mod snapshot;
mod transition;

pub use catalog::{CatalogDurations, ModuleCatalog};
pub use lease::{RequestLease, RequestLeaseTracker};
pub use management::{
    DesiredStateUpdate, DesiredStateUpdateOutcome, RuntimeModuleManagement,
    RuntimeModuleManagementError, RuntimeModuleView,
};
pub use model::{DesiredMode, ModuleEventType, ModuleId, ModuleState};
pub use policy::{DisablePolicy, ModuleCatalogError, ModuleSpec, validate_module_specs};
pub use reconcile::{
    LifecycleFailure, LifecycleFuture, ModuleLifecycle, NoopModuleLifecycle, ReconcileOutcome,
    RegistryError,
};
pub use registry::RuntimeModuleRegistry;
pub use repository::{
    CasOutcome, DesiredRevisionGuard, DesiredStateChange, DesiredStateRecord, InstanceStateChange,
    InstanceStateMutation, InstanceStateRecord, ModuleEventPage, ModuleEventRecord,
    ModuleEventState, ModuleStateRepository,
};
pub use snapshot::{ActiveModuleSnapshot, SnapshotStore};
pub use transition::{ModuleRevision, StaleTransition, TransitionGuard};
