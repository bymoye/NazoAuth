use super::*;

#[test]
fn authorization_repository_error_mapping_is_exhaustive() {
    let cases = [
        (
            RepositoryError::Unavailable,
            AuthorizationPortError::Unavailable,
        ),
        (RepositoryError::Conflict, AuthorizationPortError::Conflict),
        (
            RepositoryError::AlreadyProcessed,
            AuthorizationPortError::Conflict,
        ),
        (
            RepositoryError::Consistency("invalid row".to_owned()),
            AuthorizationPortError::CorruptData,
        ),
        (
            RepositoryError::NotFound,
            AuthorizationPortError::Unexpected,
        ),
        (
            RepositoryError::Unexpected("database".to_owned()),
            AuthorizationPortError::Unexpected,
        ),
    ];

    for (input, expected) in cases {
        assert_eq!(map_repository_error(input), expected);
    }
}

#[test]
fn device_grant_repository_error_mapping_is_exhaustive() {
    let cases = [
        (
            RepositoryError::Unavailable,
            DeviceGrantPortError::Unavailable,
        ),
        (RepositoryError::Conflict, DeviceGrantPortError::Conflict),
        (
            RepositoryError::AlreadyProcessed,
            DeviceGrantPortError::Conflict,
        ),
        (
            RepositoryError::Consistency("invalid row".to_owned()),
            DeviceGrantPortError::CorruptData,
        ),
        (RepositoryError::NotFound, DeviceGrantPortError::Unexpected),
        (
            RepositoryError::Unexpected("database".to_owned()),
            DeviceGrantPortError::Unexpected,
        ),
    ];

    for (input, expected) in cases {
        assert_eq!(map_device_repository_error(input), expected);
    }
}

#[tokio::test]
async fn fixed_tenant_adapter_rejects_cross_tenant_grant_writes_before_database_access() {
    let tenant_id = Uuid::now_v7();
    let repository = AuthorizationFlowRepository::new(
        crate::create_pool(
            "postgres://nazo_invalid:nazo_invalid@127.0.0.1:1/nazo".to_owned(),
            1,
        )
        .expect("pool construction must not connect"),
        tenant_id,
    );
    let scopes = vec!["openid".to_owned()];
    let resources = Vec::new();
    let details = serde_json::json!([]);
    let user_id = Uuid::now_v7();
    let client_id = Uuid::now_v7();

    assert_eq!(
        AuthorizationRepositoryPort::upsert_grant(
            &repository,
            GrantWrite {
                tenant_id: Uuid::now_v7(),
                user_id,
                client_id,
                scopes: &scopes,
                resource_indicators: &resources,
                authorization_details: &details,
            }
        )
        .await,
        Err(AuthorizationPortError::CorruptData)
    );
    assert_eq!(
        DeviceGrantRepositoryPort::upsert_grant(
            &repository,
            DeviceGrantWrite {
                tenant_id: Uuid::now_v7(),
                user_id,
                client_id,
                scopes: &scopes,
                resource_indicators: &resources,
                authorization_details: &details,
            }
        )
        .await,
        Err(DeviceGrantPortError::CorruptData)
    );
}
