use chrono::{DateTime, Utc};
use diesel::{
    ExpressionMethods, JoinOnDsl, OptionalExtension, QueryDsl, SelectableHelper,
    TextExpressionMethods,
};
use diesel_async::RunQueryDsl;
use nazo_auth::OAuthClient;
use nazo_identity::ports::RepositoryError;
use serde_json::Value;
use uuid::Uuid;

use crate::schema::{oauth_clients, user_client_grants};

use super::base::OAuthClientRepository;
use super::{OAuthClientRecord, conformance_lease_is_effective, map_error};

impl OAuthClientRepository {
    pub async fn by_client_id(
        &self,
        tenant_id: Uuid,
        client_id: &str,
    ) -> Result<Option<OAuthClient>, RepositoryError> {
        let mut connection = self.connection().await?;
        oauth_clients::table
            .filter(oauth_clients::tenant_id.eq(tenant_id))
            .filter(oauth_clients::client_id.eq(client_id))
            .filter(conformance_lease_is_effective())
            .select(OAuthClientRecord::as_select())
            .first::<OAuthClientRecord>(&mut connection)
            .await
            .optional()
            .map_err(map_error)?
            .map(OAuthClientRecord::into_domain)
            .transpose()
    }

    pub async fn by_id(&self, id: Uuid) -> Result<Option<OAuthClient>, RepositoryError> {
        let mut connection = self.connection().await?;
        oauth_clients::table
            .find(id)
            .filter(conformance_lease_is_effective())
            .select(OAuthClientRecord::as_select())
            .first::<OAuthClientRecord>(&mut connection)
            .await
            .optional()
            .map_err(map_error)?
            .map(OAuthClientRecord::into_domain)
            .transpose()
    }

    pub async fn active_mtls_candidates(
        &self,
        tenant_id: Uuid,
        limit: i64,
    ) -> Result<Vec<OAuthClient>, RepositoryError> {
        let mut connection = self.connection().await?;
        oauth_clients::table
            .filter(oauth_clients::tenant_id.eq(tenant_id))
            .filter(
                oauth_clients::token_endpoint_auth_method
                    .eq_any(["tls_client_auth", "self_signed_tls_client_auth"]),
            )
            .filter(oauth_clients::client_type.eq("confidential"))
            .filter(oauth_clients::is_active.eq(true))
            .filter(conformance_lease_is_effective())
            .select(OAuthClientRecord::as_select())
            .limit(limit)
            .load::<OAuthClientRecord>(&mut connection)
            .await
            .map_err(map_error)?
            .into_iter()
            .map(OAuthClientRecord::into_domain)
            .collect()
    }

    pub async fn page(
        &self,
        offset: i64,
        limit: i64,
    ) -> Result<(Vec<OAuthClient>, i64), RepositoryError> {
        let mut connection = self.connection().await?;
        let total = oauth_clients::table
            .count()
            .get_result::<i64>(&mut connection)
            .await
            .map_err(map_error)?;
        let clients = oauth_clients::table
            .select(OAuthClientRecord::as_select())
            .order(oauth_clients::created_at.desc())
            .limit(limit)
            .offset(offset)
            .load::<OAuthClientRecord>(&mut connection)
            .await
            .map_err(map_error)?
            .into_iter()
            .map(OAuthClientRecord::into_domain)
            .collect::<Result<Vec<_>, _>>()?;
        Ok((clients, total))
    }

    pub async fn by_registration_access_token(
        &self,
        tenant_id: Uuid,
        client_id: &str,
        access_token_hash: &str,
    ) -> Result<Option<OAuthClient>, RepositoryError> {
        let mut connection = self.connection().await?;
        oauth_clients::table
            .filter(oauth_clients::tenant_id.eq(tenant_id))
            .filter(oauth_clients::client_id.eq(client_id))
            .filter(oauth_clients::is_active.eq(true))
            .filter(conformance_lease_is_effective())
            .filter(oauth_clients::registration_access_token_blake3.eq(access_token_hash))
            .select(OAuthClientRecord::as_select())
            .first::<OAuthClientRecord>(&mut connection)
            .await
            .optional()
            .map_err(map_error)?
            .map(OAuthClientRecord::into_domain)
            .transpose()
    }

    pub async fn has_client_secret(&self, id: Uuid) -> Result<bool, RepositoryError> {
        let mut connection = self.connection().await?;
        diesel::select(diesel::dsl::exists(
            oauth_clients::table
                .filter(oauth_clients::id.eq(id))
                .filter(oauth_clients::is_active.eq(true))
                .filter(conformance_lease_is_effective())
                .filter(oauth_clients::client_secret_hash.is_not_null()),
        ))
        .get_result(&mut connection)
        .await
        .map_err(map_error)
    }

    pub async fn active_for_user(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<OAuthClient>, RepositoryError> {
        let mut connection = self.connection().await?;
        user_client_grants::table
            .inner_join(
                oauth_clients::table.on(oauth_clients::id.eq(user_client_grants::client_id)),
            )
            .filter(user_client_grants::user_id.eq(user_id))
            .filter(oauth_clients::is_active.eq(true))
            .filter(conformance_lease_is_effective())
            .select(OAuthClientRecord::as_select())
            .load::<OAuthClientRecord>(&mut connection)
            .await
            .map_err(map_error)?
            .into_iter()
            .map(OAuthClientRecord::into_domain)
            .collect()
    }

    pub async fn active_for_tenant_user(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<Vec<OAuthClient>, RepositoryError> {
        let mut connection = self.connection().await?;
        user_client_grants::table
            .inner_join(
                oauth_clients::table.on(oauth_clients::id.eq(user_client_grants::client_id)),
            )
            .filter(user_client_grants::tenant_id.eq(tenant_id))
            .filter(user_client_grants::user_id.eq(user_id))
            .filter(oauth_clients::tenant_id.eq(tenant_id))
            .filter(oauth_clients::is_active.eq(true))
            .filter(conformance_lease_is_effective())
            .select(OAuthClientRecord::as_select())
            .load::<OAuthClientRecord>(&mut connection)
            .await
            .map_err(map_error)?
            .into_iter()
            .map(OAuthClientRecord::into_domain)
            .collect()
    }

    pub async fn applications_for_user(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<nazo_identity::ports::AuthorizedApplication>, RepositoryError> {
        let mut connection = self.connection().await?;
        let rows = user_client_grants::table
            .inner_join(
                oauth_clients::table.on(oauth_clients::id.eq(user_client_grants::client_id)),
            )
            .filter(user_client_grants::user_id.eq(user_id))
            .select((
                oauth_clients::client_id,
                oauth_clients::client_name,
                user_client_grants::last_scopes,
                user_client_grants::last_authorized_at,
                user_client_grants::authorization_count,
            ))
            .order(user_client_grants::last_authorized_at.desc())
            .load::<(String, String, Value, DateTime<Utc>, i32)>(&mut connection)
            .await
            .map_err(map_error)?;
        Ok(rows
            .into_iter()
            .map(
                |(client_id, client_name, last_scopes, last_authorized_at, authorization_count)| {
                    nazo_identity::ports::AuthorizedApplication {
                        client_id,
                        client_name,
                        last_scopes,
                        last_authorized_at,
                        authorization_count,
                    }
                },
            )
            .collect())
    }

    /// Returns only the non-secret salt needed to derive a candidate digest.
    pub async fn client_secret_salt(&self, id: Uuid) -> Result<Option<String>, RepositoryError> {
        let mut connection = self.connection().await?;
        oauth_clients::table
            .find(id)
            .filter(oauth_clients::is_active.eq(true))
            .filter(conformance_lease_is_effective())
            .filter(oauth_clients::client_secret_hash.like("client-secret-v1:%:%"))
            .select(diesel::dsl::sql::<diesel::sql_types::Text>(
                "split_part(client_secret_hash, ':', 2)",
            ))
            .first::<String>(&mut connection)
            .await
            .optional()
            .map_err(map_error)
    }

    /// Compares an already-derived candidate digest without loading the stored digest.
    pub async fn client_secret_digest_matches(
        &self,
        id: Uuid,
        candidate_digest: &str,
    ) -> Result<bool, RepositoryError> {
        let mut connection = self.connection().await?;
        diesel::select(diesel::dsl::exists(
            oauth_clients::table
                .find(id)
                .filter(oauth_clients::is_active.eq(true))
                .filter(conformance_lease_is_effective())
                .filter(oauth_clients::client_secret_hash.eq(candidate_digest)),
        ))
        .get_result(&mut connection)
        .await
        .map_err(map_error)
    }
}

impl nazo_identity::ports::AuthorizedApplicationRepositoryPort for OAuthClientRepository {
    fn applications_for_user(
        &self,
        user_id: Uuid,
    ) -> nazo_identity::ports::RepositoryFuture<'_, Vec<nazo_identity::ports::AuthorizedApplication>>
    {
        Box::pin(async move { OAuthClientRepository::applications_for_user(self, user_id).await })
    }
}
