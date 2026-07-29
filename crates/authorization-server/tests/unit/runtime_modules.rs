use super::*;
use crate::config::ConfigSource;

#[test]
fn instance_id_is_nonempty_and_storage_bounded() {
    let instance_id = runtime_instance_id().expect("default runtime instance id is valid");
    assert!(!instance_id.trim().is_empty());
    assert!(instance_id.len() <= 255);
}

#[test]
fn stable_dormant_capabilities_are_inherited_on() {
    let settings =
        Settings::from_config(&ConfigSource::default()).expect("default settings should load");
    let inherited = inherited_enabled(&settings);

    for module_id in [
        ModuleId::DeviceAuthorization,
        ModuleId::Ciba,
        ModuleId::RequestObjects,
        ModuleId::FrontchannelLogout,
        ModuleId::SessionManagement,
    ] {
        assert!(inherited.contains(&module_id), "{module_id:?}");
    }
}

#[test]
fn scim_security_events_are_default_closed_and_depend_on_scim() {
    let mut settings =
        Settings::from_config(&ConfigSource::default()).expect("default settings should load");
    assert!(!inherited_enabled(&settings).contains(&ModuleId::ScimSecurityEvents));

    settings.modules.enable_scim_security_events = true;
    let inherited = inherited_enabled(&settings);
    assert!(inherited.contains(&ModuleId::ScimSecurityEvents));
    let catalog = module_catalog(&settings, inherited).unwrap();
    assert_eq!(
        catalog
            .spec(ModuleId::ScimSecurityEvents)
            .unwrap()
            .dependencies,
        BTreeSet::from([ModuleId::Scim])
    );
    assert_eq!(
        catalog
            .spec(ModuleId::ScimSecurityEvents)
            .unwrap()
            .disable_policy,
        nazo_runtime_modules::DisablePolicy::DrainStoredTransactions {
            max_duration: Duration::from_secs(604_800)
        }
    );
}

#[test]
fn dynamic_registration_requires_a_provisioning_authority() {
    let mut settings =
        Settings::from_config(&ConfigSource::default()).expect("default settings should load");
    assert!(!inherited_enabled(&settings).contains(&ModuleId::DynamicClientRegistration));

    settings
        .modules
        .dynamic_client_registration_initial_access_token = Some("provisioning-token".to_owned());
    assert!(inherited_enabled(&settings).contains(&ModuleId::DynamicClientRegistration));
}

#[test]
fn native_sso_depends_on_token_exchange() {
    let settings =
        Settings::from_config(&ConfigSource::default()).expect("default settings should load");
    let inherited = inherited_enabled(&settings);
    let catalog = module_catalog(&settings, inherited).unwrap();

    assert_eq!(
        catalog.spec(ModuleId::NativeSso).unwrap().dependencies,
        BTreeSet::from([ModuleId::TokenExchange])
    );
}

#[test]
fn legacy_defaults_remain_available_for_upgrade_materialization() {
    let settings =
        Settings::from_config(&ConfigSource::default()).expect("default settings should load");
    let legacy = legacy_inherited_enabled(&settings);

    assert!(!legacy.contains(&ModuleId::DeviceAuthorization));
    assert!(!legacy.contains(&ModuleId::Ciba));
    assert!(!legacy.contains(&ModuleId::RequestObjects));
    assert!(!legacy.contains(&ModuleId::SessionManagement));
}
