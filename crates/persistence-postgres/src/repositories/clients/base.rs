use nazo_identity::ports::RepositoryError;

use crate::DbPool;

#[derive(Clone)]
pub struct OAuthClientRepository {
    pool: DbPool,
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
