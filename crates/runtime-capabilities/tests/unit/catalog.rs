use super::*;

#[test]
fn security_profile_block_is_reflected_only_in_effective_policy() {
    let durations = CatalogDurations {
        device_authorization: Duration::from_secs(1),
        ciba: Duration::from_secs(2),
        authorization_code: Duration::from_secs(3),
        refresh_token: Duration::from_secs(4),
        session: Duration::from_secs(5),
        scim_security_events: Duration::from_secs(6),
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
