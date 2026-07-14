use nazo_identity::ports::AdminUserUpdate;
use nazo_identity::{
    AdminPolicyError, Principal, TenantContext, TenantId, UserId, UserRole, authorize_admin_update,
};
use uuid::Uuid;

fn principal(user: u128, tenant: u128, level: Option<u32>, active: bool) -> Principal {
    let mut context = TenantContext::default_system();
    context.tenant_id = TenantId::new(Uuid::from_u128(tenant)).unwrap();
    Principal {
        user_id: UserId::new(Uuid::from_u128(user)).unwrap(),
        tenant: context,
        role: level.map_or(UserRole::User, |level| UserRole::Admin { level }),
        active,
    }
}

fn update(role: Option<&str>, admin_level: Option<i32>, active: Option<bool>) -> AdminUserUpdate {
    AdminUserUpdate {
        role: role.map(str::to_owned),
        admin_level,
        active,
    }
}

#[test]
fn admin_cannot_elevate_or_demote_disable_self() {
    let actor = principal(10, 1, Some(3), true);
    assert_eq!(
        authorize_admin_update(&actor, &actor, &update(None, Some(4), None)),
        Err(AdminPolicyError::SelfElevation)
    );
    assert_eq!(
        authorize_admin_update(&actor, &actor, &update(Some("user"), Some(0), None)),
        Err(AdminPolicyError::SelfDemotionOrDisable)
    );
    assert_eq!(
        authorize_admin_update(&actor, &actor, &update(None, None, Some(false))),
        Err(AdminPolicyError::SelfDemotionOrDisable)
    );
}

#[test]
fn admin_cannot_modify_peer_superior_or_grant_own_level() {
    let actor = principal(10, 1, Some(3), true);
    for target_level in [3, 4] {
        let target = principal(11, 1, Some(target_level), true);
        assert_eq!(
            authorize_admin_update(&actor, &target, &update(None, None, Some(false))),
            Err(AdminPolicyError::TargetAtOrAboveActor)
        );
    }
    let user = principal(12, 1, None, true);
    assert_eq!(
        authorize_admin_update(&actor, &user, &update(Some("admin"), Some(3), None)),
        Err(AdminPolicyError::GrantAtOrAboveActor)
    );
}

#[test]
fn admin_policy_rejects_cross_tenant_and_resolves_safe_update() {
    let actor = principal(10, 1, Some(3), true);
    let foreign = principal(11, 2, None, true);
    assert_eq!(
        authorize_admin_update(&actor, &foreign, &update(None, None, Some(false))),
        Err(AdminPolicyError::CrossTenant)
    );
    let subordinate = principal(12, 1, Some(1), true);
    let resolved = authorize_admin_update(
        &actor,
        &subordinate,
        &update(Some("admin"), Some(2), Some(false)),
    )
    .unwrap();
    assert_eq!(resolved.role, "admin");
    assert_eq!(resolved.admin_level, 2);
    assert!(!resolved.active);
}
