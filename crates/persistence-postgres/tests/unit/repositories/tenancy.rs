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
fn directory_snapshot_maps_active_bindings_and_empty_directory() {
    let tenant = TenantContext::default_system();
    let snapshot = directory_snapshot(vec![TenantDirectoryRow {
        revision: 7,
        tenant_id: Some(tenant.tenant_id.as_uuid()),
        realm_id: Some(tenant.realm_id.as_uuid()),
        organization_id: Some(tenant.organization_id.as_uuid()),
        issuer: Some("https://auth.example".to_owned()),
        external_host: Some("auth.example".to_owned()),
    }])
    .expect("complete directory row should map");
    assert_eq!(snapshot.revision, 7);
    assert_eq!(snapshot.tenants.len(), 1);
    assert_eq!(snapshot.tenants[0].tenant, tenant);
    assert_eq!(snapshot.tenants[0].issuer, "https://auth.example");
    assert_eq!(snapshot.tenants[0].external_host, "auth.example");

    let empty = directory_snapshot(vec![TenantDirectoryRow {
        revision: 8,
        tenant_id: None,
        realm_id: None,
        organization_id: None,
        issuer: None,
        external_host: None,
    }])
    .expect("directory state without active bindings should map");
    assert_eq!(empty.revision, 8);
    assert!(empty.tenants.is_empty());
}

#[test]
fn directory_snapshot_rejects_incomplete_rows() {
    let error = directory_snapshot(vec![TenantDirectoryRow {
        revision: 1,
        tenant_id: Some(Uuid::now_v7()),
        realm_id: None,
        organization_id: None,
        issuer: Some("https://auth.example".to_owned()),
        external_host: Some("auth.example".to_owned()),
    }])
    .expect_err("partial binding must fail closed");
    assert!(matches!(error, RepositoryError::Consistency(_)));
}

#[test]
fn directory_revision_rejects_negative_storage_values() {
    assert_eq!(decode_directory_revision(0), Ok(0));
    assert!(matches!(
        decode_directory_revision(-1),
        Err(RepositoryError::Consistency(_))
    ));
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
fn inactive_realm_fails_closed_as_consistency_error() {
    let context = TenantContext::default_system();
    let mut row = active_row(context);
    row.realm_status = Some("suspended".to_owned());

    assert!(matches!(
        validate_active_boundary(context, row),
        Err(RepositoryError::Consistency(message))
            if message == "realm boundary row is not active"
    ));
}

#[test]
fn inactive_organization_fails_closed_as_consistency_error() {
    let context = TenantContext::default_system();
    let mut row = active_row(context);
    row.organization_status = Some("suspended".to_owned());

    assert!(matches!(
        validate_active_boundary(context, row),
        Err(RepositoryError::Consistency(message))
            if message == "organization boundary row is not active"
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

#[test]
fn missing_tenant_or_realm_row_is_not_found() {
    let context = TenantContext::default_system();
    let mut missing_tenant = active_row(context);
    missing_tenant.tenant_id = None;
    assert_eq!(
        validate_active_boundary(context, missing_tenant),
        Err(RepositoryError::NotFound)
    );

    let mut missing_realm = active_row(context);
    missing_realm.realm_id = None;
    missing_realm.realm_tenant_id = None;
    assert_eq!(
        validate_active_boundary(context, missing_realm),
        Err(RepositoryError::NotFound)
    );
}

#[test]
fn query_errors_preserve_not_found_and_unexpected_semantics() {
    assert_eq!(
        map_query_error(diesel::result::Error::NotFound),
        RepositoryError::NotFound
    );
    assert!(matches!(
        map_query_error(diesel::result::Error::RollbackTransaction),
        RepositoryError::Unexpected(message) if message.contains("rollback")
    ));
}
