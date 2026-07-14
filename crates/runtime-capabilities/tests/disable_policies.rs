use std::collections::BTreeSet;
use std::time::Duration;

use nazo_runtime_modules::{
    CatalogDurations, DisablePolicy, ModuleCatalog, ModuleId, ModuleRevision,
};

fn durations() -> CatalogDurations {
    CatalogDurations {
        device_authorization: Duration::from_secs(601),
        ciba: Duration::from_secs(602),
        authorization_code: Duration::from_secs(603),
        refresh_token: Duration::from_secs(604),
        session: Duration::from_secs(605),
    }
}

#[test]
fn fixed_catalog_assigns_every_reviewed_disable_policy() {
    let catalog = ModuleCatalog::fixed(durations(), BTreeSet::new()).unwrap();

    let expected = [
        (
            ModuleId::DeviceAuthorization,
            DisablePolicy::DrainStoredTransactions {
                max_duration: Duration::from_secs(601),
            },
        ),
        (
            ModuleId::TokenExchange,
            DisablePolicy::FinishExecutingRequests,
        ),
        (
            ModuleId::JwtBearerGrant,
            DisablePolicy::FinishExecutingRequests,
        ),
        (
            ModuleId::Ciba,
            DisablePolicy::DrainStoredTransactions {
                max_duration: Duration::from_secs(602),
            },
        ),
        (
            ModuleId::DynamicClientRegistration,
            DisablePolicy::FinishExecutingRequests,
        ),
        (
            ModuleId::RequestObjects,
            DisablePolicy::FinishExecutingRequests,
        ),
        (
            ModuleId::Jarm,
            DisablePolicy::DrainStoredTransactions {
                max_duration: Duration::from_secs(603),
            },
        ),
        (
            ModuleId::AuthorizationDetails,
            DisablePolicy::DrainStoredTransactions {
                max_duration: Duration::from_secs(604),
            },
        ),
        (
            ModuleId::HttpMessageSignatures,
            DisablePolicy::FinishExecutingRequests,
        ),
        (ModuleId::Scim, DisablePolicy::FinishExecutingRequests),
        (
            ModuleId::NativeSso,
            DisablePolicy::DrainStoredTransactions {
                max_duration: Duration::from_secs(604),
            },
        ),
        (
            ModuleId::FrontchannelLogout,
            DisablePolicy::FinishExecutingRequests,
        ),
        (
            ModuleId::SessionManagement,
            DisablePolicy::DrainStoredTransactions {
                max_duration: Duration::from_secs(605),
            },
        ),
    ];

    assert_eq!(catalog.specs().len(), ModuleId::ALL.len());
    for (module_id, policy) in expected {
        assert_eq!(catalog.spec(module_id).unwrap().disable_policy, policy);
    }
}

#[test]
fn catalog_retains_inherited_defaults_without_mutating_specs() {
    let enabled = BTreeSet::from([ModuleId::Ciba, ModuleId::Scim]);
    let catalog = ModuleCatalog::fixed(durations(), enabled).unwrap();

    assert!(catalog.inherited_enabled(ModuleId::Ciba));
    assert!(catalog.inherited_enabled(ModuleId::Scim));
    assert!(!catalog.inherited_enabled(ModuleId::Jarm));
    assert_eq!(ModuleRevision::new(0).get(), 0);
}
