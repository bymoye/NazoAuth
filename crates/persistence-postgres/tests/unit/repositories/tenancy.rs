use super::*;

fn active_row(context: TenantContext) -> ActiveTenantBoundaryRow {
    let tenant_id = context.tenant_id.as_uuid();
    ActiveTenantBoundaryRow {
        tenant_id: Some(tenant_id),
        tenant_status: Some("active".to_owned()),
        realm_id: Some(context.realm_id.as_uuid()),
        realm_tenant_id: Some(tenant_id),
        realm_status: Some("active".to_owned()),
        organization_id: Some(context.organization_id.as_uuid()),
        organization_tenant_id: Some(tenant_id),
        organization_status: Some("active".to_owned()),
    }
}

#[test]
fn active_boundary_is_accepted() {
    let context = TenantContext::default_system();

    assert_eq!(
        validate_active_boundary(context, active_row(context)),
        Ok(())
    );
}

#[test]
fn inactive_tenant_fails_closed_as_consistency_error() {
    let context = TenantContext::default_system();
    let mut row = active_row(context);
    row.tenant_status = Some("suspended".to_owned());

    assert!(matches!(
        validate_active_boundary(context, row),
        Err(RepositoryError::Consistency(message))
            if message == "tenant boundary row is not active"
    ));
}

#[test]
fn realm_from_another_tenant_fails_closed_as_consistency_error() {
    let context = TenantContext::default_system();
    let mut row = active_row(context);
    row.realm_tenant_id = Some(Uuid::now_v7());

    assert!(matches!(
        validate_active_boundary(context, row),
        Err(RepositoryError::Consistency(message))
            if message == "realm boundary row belongs to another tenant"
    ));
}

#[test]
fn organization_from_another_tenant_fails_closed_as_consistency_error() {
    let context = TenantContext::default_system();
    let mut row = active_row(context);
    row.organization_tenant_id = Some(Uuid::now_v7());

    assert!(matches!(
        validate_active_boundary(context, row),
        Err(RepositoryError::Consistency(message))
            if message == "organization boundary row belongs to another tenant"
    ));
}

#[test]
fn missing_boundary_row_is_not_found() {
    let context = TenantContext::default_system();
    let mut row = active_row(context);
    row.organization_id = None;
    row.organization_tenant_id = None;
    row.organization_status = None;

    assert_eq!(
        validate_active_boundary(context, row),
        Err(RepositoryError::NotFound)
    );
}
