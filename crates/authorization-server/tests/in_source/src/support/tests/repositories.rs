use super::*;

#[test]
fn default_repository_context_is_default_tenant() {
    let context = default_tenant_context();

    assert_eq!(context.tenant_id, DEFAULT_TENANT_ID);
    assert_eq!(context.realm_id, DEFAULT_REALM_ID);
    assert_eq!(context.organization_id, DEFAULT_ORGANIZATION_ID);
}
