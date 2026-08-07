use diesel::{ExpressionMethods, QueryDsl};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use nazo_identity::ports::RepositoryError;
use uuid::Uuid;

use crate::{DbPool, schema::oauth_client_conformance_bindings};

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

pub(crate) async fn bind_conformance_lease(
    connection: &mut AsyncPgConnection,
    client_id: Uuid,
    lease_id: Option<Uuid>,
) -> Result<(), diesel::result::Error> {
    let Some(lease_id) = lease_id else {
        return Ok(());
    };
    let updated = diesel::update(
        oauth_client_conformance_bindings::table
            .filter(oauth_client_conformance_bindings::id.eq(client_id)),
    )
    .set(oauth_client_conformance_bindings::conformance_lease_id.eq(Some(lease_id)))
    .execute(connection)
    .await?;
    if updated == 1 {
        Ok(())
    } else {
        Err(diesel::result::Error::NotFound)
    }
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
