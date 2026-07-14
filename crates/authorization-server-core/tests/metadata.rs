use std::collections::BTreeSet;

use nazo_auth::{CapabilityAdmission, MetadataCapabilities, module_admissible};
use nazo_runtime_modules::{ActiveModuleSnapshot, ModuleId, ModuleRevision};

fn snapshot(accepting: &[ModuleId], draining: &[ModuleId]) -> ActiveModuleSnapshot {
    ActiveModuleSnapshot {
        revision: ModuleRevision::new(7),
        accepting: accepting.iter().copied().collect::<BTreeSet<_>>(),
        draining: draining.iter().copied().collect::<BTreeSet<_>>(),
    }
}

#[test]
fn metadata_exposes_only_capabilities_accepting_new_work() {
    let snapshot = snapshot(
        &[
            ModuleId::DeviceAuthorization,
            ModuleId::AuthorizationDetails,
            ModuleId::NativeSso,
            ModuleId::TokenExchange,
        ],
        &[ModuleId::Ciba],
    );

    let capabilities = MetadataCapabilities::from_snapshot(&snapshot);

    assert!(capabilities.device_authorization);
    assert!(capabilities.authorization_details);
    assert!(capabilities.native_sso);
    assert!(!capabilities.ciba);
    assert_eq!(
        capabilities.grant_types,
        vec![
            "authorization_code",
            "refresh_token",
            "client_credentials",
            "urn:ietf:params:oauth:grant-type:token-exchange",
            "urn:ietf:params:oauth:grant-type:device_code",
        ]
    );
}

#[test]
fn disabled_but_draining_ciba_is_hidden_while_existing_polling_remains_admissible() {
    let snapshot = snapshot(&[], &[ModuleId::Ciba]);

    assert!(!MetadataCapabilities::from_snapshot(&snapshot).ciba);
    assert!(!module_admissible(
        &snapshot,
        ModuleId::Ciba,
        CapabilityAdmission::NewRequest
    ));
    assert!(module_admissible(
        &snapshot,
        ModuleId::Ciba,
        CapabilityAdmission::ExistingTransaction
    ));
}
