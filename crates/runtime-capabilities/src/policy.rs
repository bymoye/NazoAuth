use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use crate::ModuleId;

/// The close behavior that orchestration must apply when disabling a module.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DisablePolicy {
    Immediate,
    FinishExecutingRequests,
    DrainStoredTransactions { max_duration: Duration },
    NotRuntimeDisableable,
}

/// One caller-supplied entry in the concrete runtime-module catalog.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModuleSpec {
    pub id: ModuleId,
    pub dependencies: BTreeSet<ModuleId>,
    pub disable_policy: DisablePolicy,
}

/// Structural defects in a caller-supplied module catalog.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ModuleCatalogError {
    #[error("module catalog has no specification for {0:?}")]
    MissingSpec(ModuleId),
    #[error("module catalog has more than one specification for {0:?}")]
    DuplicateSpec(ModuleId),
    #[error("module {0:?} depends on itself")]
    SelfDependency(ModuleId),
    #[error("module {module:?} depends on missing module {dependency:?}")]
    MissingDependency {
        module: ModuleId,
        dependency: ModuleId,
    },
    #[error("module dependency graph contains a cycle through {0:?}")]
    DependencyCycle(ModuleId),
}

/// Validates completeness and acyclicity without assigning domain policy.
pub fn validate_module_specs(specs: &[ModuleSpec]) -> Result<(), ModuleCatalogError> {
    let mut by_id = BTreeMap::new();
    for spec in specs {
        if by_id.insert(spec.id, spec).is_some() {
            return Err(ModuleCatalogError::DuplicateSpec(spec.id));
        }
    }

    for id in ModuleId::ALL {
        if !by_id.contains_key(&id) {
            return Err(ModuleCatalogError::MissingSpec(id));
        }
    }

    for spec in specs {
        if spec.dependencies.contains(&spec.id) {
            return Err(ModuleCatalogError::SelfDependency(spec.id));
        }
        for dependency in &spec.dependencies {
            if !by_id.contains_key(dependency) {
                return Err(ModuleCatalogError::MissingDependency {
                    module: spec.id,
                    dependency: *dependency,
                });
            }
        }
    }

    let mut visiting = BTreeSet::new();
    let mut visited = BTreeSet::new();
    for id in ModuleId::ALL {
        visit(id, &by_id, &mut visiting, &mut visited)?;
    }
    Ok(())
}

fn visit(
    id: ModuleId,
    specs: &BTreeMap<ModuleId, &ModuleSpec>,
    visiting: &mut BTreeSet<ModuleId>,
    visited: &mut BTreeSet<ModuleId>,
) -> Result<(), ModuleCatalogError> {
    if visited.contains(&id) {
        return Ok(());
    }
    if !visiting.insert(id) {
        return Err(ModuleCatalogError::DependencyCycle(id));
    }

    let spec = specs.get(&id).ok_or(ModuleCatalogError::MissingSpec(id))?;
    for dependency in &spec.dependencies {
        visit(*dependency, specs, visiting, visited)?;
    }

    visiting.remove(&id);
    visited.insert(id);
    Ok(())
}
