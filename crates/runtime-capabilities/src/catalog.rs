use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use crate::{DisablePolicy, ModuleCatalogError, ModuleId, ModuleSpec, validate_module_specs};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CatalogDurations {
    pub device_authorization: Duration,
    pub ciba: Duration,
    pub authorization_code: Duration,
    pub refresh_token: Duration,
    pub session: Duration,
}

#[derive(Clone, Debug)]
pub struct ModuleCatalog {
    specs: BTreeMap<ModuleId, ModuleSpec>,
    inherited_enabled: BTreeSet<ModuleId>,
    runtime_disable_blocked: BTreeSet<ModuleId>,
}

impl ModuleCatalog {
    pub fn fixed(
        durations: CatalogDurations,
        inherited_enabled: BTreeSet<ModuleId>,
    ) -> Result<Self, ModuleCatalogError> {
        let finish = DisablePolicy::FinishExecutingRequests;
        let drain = |max_duration| DisablePolicy::DrainStoredTransactions { max_duration };
        let policies = [
            (
                ModuleId::DeviceAuthorization,
                drain(durations.device_authorization),
            ),
            (ModuleId::TokenExchange, finish),
            (ModuleId::JwtBearerGrant, finish),
            (ModuleId::Ciba, drain(durations.ciba)),
            (ModuleId::DynamicClientRegistration, finish),
            (ModuleId::RequestObjects, finish),
            (ModuleId::Jarm, drain(durations.authorization_code)),
            (
                ModuleId::AuthorizationDetails,
                drain(durations.refresh_token),
            ),
            (ModuleId::HttpMessageSignatures, finish),
            (ModuleId::Scim, finish),
            (ModuleId::NativeSso, drain(durations.refresh_token)),
            (ModuleId::FrontchannelLogout, finish),
            // Stop advertising and issuing new session_state values immediately,
            // while allowing check_session polling for OP browser sessions that
            // already exist. Their Valkey TTL is the bounded drain deadline.
            (ModuleId::SessionManagement, drain(durations.session)),
        ];
        let specs: Vec<_> = policies
            .into_iter()
            .map(|(id, disable_policy)| ModuleSpec {
                id,
                dependencies: BTreeSet::new(),
                disable_policy,
            })
            .collect();
        validate_module_specs(&specs)?;
        Ok(Self {
            specs: specs.into_iter().map(|spec| (spec.id, spec)).collect(),
            inherited_enabled,
            runtime_disable_blocked: BTreeSet::new(),
        })
    }

    #[must_use]
    pub fn with_runtime_disable_blocked(
        mut self,
        modules: impl IntoIterator<Item = ModuleId>,
    ) -> Self {
        self.runtime_disable_blocked.extend(modules);
        self
    }

    pub fn with_dependencies(
        mut self,
        module_id: ModuleId,
        dependencies: impl IntoIterator<Item = ModuleId>,
    ) -> Result<Self, ModuleCatalogError> {
        self.specs
            .get_mut(&module_id)
            .expect("the fixed catalog contains every closed module ID")
            .dependencies = dependencies.into_iter().collect();
        let specs = self.specs.values().cloned().collect::<Vec<_>>();
        validate_module_specs(&specs)?;
        Ok(self)
    }

    #[must_use]
    pub fn specs(&self) -> &BTreeMap<ModuleId, ModuleSpec> {
        &self.specs
    }

    #[must_use]
    pub fn spec(&self, module_id: ModuleId) -> Option<&ModuleSpec> {
        self.specs.get(&module_id)
    }

    #[must_use]
    pub fn inherited_enabled(&self, module_id: ModuleId) -> bool {
        self.inherited_enabled.contains(&module_id)
    }

    #[must_use]
    pub fn runtime_disable_blocked(&self, module_id: ModuleId) -> bool {
        self.runtime_disable_blocked.contains(&module_id)
    }

    #[must_use]
    pub fn effective_disable_policy(&self, module_id: ModuleId) -> Option<DisablePolicy> {
        if self.runtime_disable_blocked(module_id) {
            Some(DisablePolicy::NotRuntimeDisableable)
        } else {
            self.spec(module_id).map(|spec| spec.disable_policy)
        }
    }

    pub fn active_dependents(
        &self,
        module_id: ModuleId,
        active: &BTreeSet<ModuleId>,
    ) -> Vec<ModuleId> {
        self.specs
            .values()
            .filter(|spec| active.contains(&spec.id) && spec.dependencies.contains(&module_id))
            .map(|spec| spec.id)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn security_profile_block_is_reflected_only_in_effective_policy() {
        let durations = CatalogDurations {
            device_authorization: Duration::from_secs(1),
            ciba: Duration::from_secs(2),
            authorization_code: Duration::from_secs(3),
            refresh_token: Duration::from_secs(4),
            session: Duration::from_secs(5),
        };
        let base = ModuleCatalog::fixed(durations, BTreeSet::new()).unwrap();
        assert_eq!(
            base.effective_disable_policy(ModuleId::Jarm),
            Some(DisablePolicy::DrainStoredTransactions {
                max_duration: Duration::from_secs(3)
            })
        );

        let profiled = base.clone().with_runtime_disable_blocked([ModuleId::Jarm]);
        assert_eq!(
            profiled.spec(ModuleId::Jarm).unwrap().disable_policy,
            DisablePolicy::DrainStoredTransactions {
                max_duration: Duration::from_secs(3)
            }
        );
        assert_eq!(
            profiled.effective_disable_policy(ModuleId::Jarm),
            Some(DisablePolicy::NotRuntimeDisableable)
        );
    }
}
