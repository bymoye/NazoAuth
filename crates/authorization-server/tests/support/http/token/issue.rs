use crate::domain::tenancy::DEFAULT_TENANT_ID;
use crate::test_support::TestInfrastructure;

pub(crate) fn test_authorization_service(
    state: &TestInfrastructure,
) -> crate::http::authorization::ServerAuthorizationService {
    let connection = state.valkey_connection();
    crate::http::authorization::ServerAuthorizationService::new(
        nazo_postgres::AuthorizationFlowRepository::new(state.diesel_db.clone(), DEFAULT_TENANT_ID),
        nazo_valkey::AuthorizationStateAdapter::new(&connection),
        state.keyset.clone(),
    )
}
