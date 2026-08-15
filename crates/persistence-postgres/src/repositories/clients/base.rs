use nazo_identity::ports::RepositoryError;

use crate::DbPool;

#[derive(Clone)]
pub struct OAuthClientRepository {
    pool: DbPool,
}

pub(crate) fn conformance_lease_is_effective()
-> diesel::expression::SqlLiteral<diesel::sql_types::Bool> {
    diesel::dsl::sql(
        "nazo_oauth_conformance_lease_is_active(\
            oauth_clients.tenant_id, oauth_clients.conformance_lease_id\
        )",
    )
}

impl OAuthClientRepository {
    #[must_use]
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}

impl OAuthClientRepository {
    pub(super) async fn connection(&self) -> Result<crate::DbConnection, RepositoryError> {
        self.pool
            .get()
            .await
            .map_err(|_| RepositoryError::Unavailable)
    }
}
