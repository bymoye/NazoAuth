use std::time::Duration;

use nazo_runtime_modules::{CatalogDurations, DisablePolicy, ModuleCatalog, ModuleId};

fn durations() -> CatalogDurations {
    CatalogDurations {
        device_authorization: Duration::from_secs(601),
        ciba: Duration::from_secs(602),
        authorization_code: Duration::from_secs(603),
        refresh_token: Duration::from_secs(604),
        session: Duration::from_secs(605),
        scim_security_events: Duration::from_secs(606),
    }
}

#[test]
fn fixed_catalog_assigns_every_reviewed_disable_policy() {
    let catalog = ModuleCatalog::fixed(durations()).unwrap();

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
            ModuleId::ScimSecurityEvents,
            DisablePolicy::DrainStoredTransactions {
                max_duration: Duration::from_secs(606),
            },
        ),
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
