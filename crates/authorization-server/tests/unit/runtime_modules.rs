use super::*;
use crate::config::ConfigSource;

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
fn migration_defaults_match_current_composable_defaults() {
    let settings =
        Settings::from_config(&ConfigSource::default()).expect("default settings should load");
    let inherited = inherited_enabled(&settings);

    assert!(inherited.contains(&ModuleId::DeviceAuthorization));
    assert!(inherited.contains(&ModuleId::Ciba));
    assert!(inherited.contains(&ModuleId::RequestObjects));
    assert!(inherited.contains(&ModuleId::SessionManagement));
}

#[tokio::test]
async fn initialization_reconciles_the_persisted_catalog_before_exposing_a_snapshot() {
    let Some(database_url) = std::env::var("DATABASE_URL").ok() else {
        return;
    };
    nazo_postgres::run_pending_migrations(&database_url)
        .await
        .expect("runtime module schema should be current");
    let pool = nazo_postgres::create_pool(database_url, 2).expect("database pool should build");
    let settings =
        Settings::from_config(&ConfigSource::default()).expect("default settings should load");

    let runtime = RuntimeModules::initialize(pool, &settings, "test-instance")
        .await
        .expect("persisted module policy should initialize");

    assert!(!runtime.instance_id.trim().is_empty());
    let snapshot = runtime.registry.snapshot();
    for module_id in inherited_enabled(&settings) {
        assert!(
            snapshot.accepting.contains(&module_id) || snapshot.draining.contains(&module_id),
            "{module_id:?} must be represented in the initialized snapshot"
        );
    }
}
