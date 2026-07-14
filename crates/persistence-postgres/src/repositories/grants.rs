use chrono::{DateTime, Utc};
use diesel::{
    AggregateExpressionMethods, BoolExpressionMethods, ExpressionMethods, JoinOnDsl, QueryDsl,
};
use diesel_async::{AsyncConnection, RunQueryDsl};
use nazo_auth::{
    AdminGrantPage, AdminGrantRepositoryPort, AdminGrantRevocation, AdminGrantRevokeError,
    AdminGrantView, AuthorizationPortError,
};
use nazo_identity::ports::RepositoryError;
use serde_json::Value;
use uuid::Uuid;

use crate::{
    DbPool,
    schema::{oauth_clients, oauth_tokens, user_client_grants, users},
};

use super::tokens::{lock_refresh_family, lock_refresh_grant_scope};

#[derive(Clone, Debug, PartialEq)]
pub struct GrantAuthorization {
    pub scopes: Value,
    pub resource_indicators: Value,
    pub authorization_details: Value,
    pub authorization_count: i32,
}

#[derive(diesel::Queryable)]
struct GrantRecord {
    user_id: Uuid,
    email: String,
    client_id: String,
    client_name: String,
    last_authorized_at: DateTime<Utc>,
    authorization_count: i32,
    last_scopes: Value,
    last_authorization_details: Value,
}

impl From<GrantRecord> for AdminGrantView {
    fn from(record: GrantRecord) -> Self {
        Self {
            user_id: record.user_id,
            email: record.email,
            client_id: record.client_id,
            client_name: record.client_name,
            last_authorized_at: record.last_authorized_at,
            authorization_count: record.authorization_count,
            last_scopes: record
                .last_scopes
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|value| value.as_str().map(ToOwned::to_owned))
                .collect(),
            last_authorization_details: record.last_authorization_details,
        }
    }
}

#[derive(Clone)]
pub struct GrantRepository {
    pool: DbPool,
}

impl GrantRepository {
    #[must_use]
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    async fn admin_page(
        &self,
        tenant_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<AdminGrantPage, AuthorizationPortError> {
        let mut connection = self
            .pool
            .get()
            .await
            .map_err(|_| AuthorizationPortError::Unavailable)?;
        let total = user_client_grants::table
            .filter(user_client_grants::tenant_id.eq(tenant_id))
            .select(diesel::dsl::count_star())
            .first::<i64>(&mut connection)
            .await
            .map_err(map_authorization_error)?;
        let records = user_client_grants::table
            .inner_join(
                users::table.on(users::id
                    .eq(user_client_grants::user_id)
                    .and(users::tenant_id.eq(user_client_grants::tenant_id))),
            )
            .inner_join(
                oauth_clients::table.on(oauth_clients::id
                    .eq(user_client_grants::client_id)
                    .and(oauth_clients::tenant_id.eq(user_client_grants::tenant_id))),
            )
            .filter(user_client_grants::tenant_id.eq(tenant_id))
            .select((
                user_client_grants::user_id,
                users::email,
                oauth_clients::client_id,
                oauth_clients::client_name,
                user_client_grants::last_authorized_at,
                user_client_grants::authorization_count,
                user_client_grants::last_scopes,
                user_client_grants::last_authorization_details,
            ))
            .order(user_client_grants::last_authorized_at.desc())
            .limit(limit)
            .offset(offset)
            .load::<GrantRecord>(&mut connection)
            .await
            .map_err(map_authorization_error)?;
        Ok(AdminGrantPage {
            total,
            grants: records.into_iter().map(Into::into).collect(),
        })
    }

    pub async fn upsert(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        client_id: Uuid,
        scopes: &[String],
        resource_indicators: &[String],
        authorization_details: &Value,
    ) -> Result<(), RepositoryError> {
        let mut connection = self.connection().await?;
        let now = Utc::now();
        diesel::insert_into(user_client_grants::table)
            .values((
                user_client_grants::tenant_id.eq(tenant_id),
                user_client_grants::user_id.eq(user_id),
                user_client_grants::client_id.eq(client_id),
                user_client_grants::first_authorized_at.eq(now),
                user_client_grants::last_authorized_at.eq(now),
                user_client_grants::last_scopes.eq(serde_json::json!(scopes)),
                user_client_grants::last_resource_indicators
                    .eq(serde_json::json!(resource_indicators)),
                user_client_grants::last_authorization_details.eq(authorization_details),
                user_client_grants::authorization_count.eq(1),
            ))
            .on_conflict((
                user_client_grants::tenant_id,
                user_client_grants::user_id,
                user_client_grants::client_id,
            ))
            .do_update()
            .set((
                user_client_grants::last_authorized_at.eq(now),
                user_client_grants::last_scopes.eq(serde_json::json!(scopes)),
                user_client_grants::last_resource_indicators
                    .eq(serde_json::json!(resource_indicators)),
                user_client_grants::last_authorization_details.eq(authorization_details),
                user_client_grants::authorization_count
                    .eq(user_client_grants::authorization_count + 1),
            ))
            .execute(&mut connection)
            .await
            .map_err(map_error)?;
        Ok(())
    }

    pub async fn authorization(
        &self,
        user_id: Uuid,
        client_id: Uuid,
    ) -> Result<Option<GrantAuthorization>, RepositoryError> {
        use diesel::OptionalExtension;

        let mut connection = self.connection().await?;
        user_client_grants::table
            .filter(user_client_grants::user_id.eq(user_id))
            .filter(user_client_grants::client_id.eq(client_id))
            .select((
                user_client_grants::last_scopes,
                user_client_grants::last_resource_indicators,
                user_client_grants::last_authorization_details,
                user_client_grants::authorization_count,
            ))
            .first::<(Value, Value, Value, i32)>(&mut connection)
            .await
            .optional()
            .map(|value| {
                value.map(
                    |(scopes, resource_indicators, authorization_details, authorization_count)| {
                        GrantAuthorization {
                            scopes,
                            resource_indicators,
                            authorization_details,
                            authorization_count,
                        }
                    },
                )
            })
            .map_err(map_error)
    }

    pub async fn authorized_client_count(&self, user_id: Uuid) -> Result<i64, RepositoryError> {
        let mut connection = self.connection().await?;
        user_client_grants::table
            .filter(user_client_grants::user_id.eq(user_id))
            .select(diesel::dsl::count(user_client_grants::client_id).aggregate_distinct())
            .first::<i64>(&mut connection)
            .await
            .map_err(map_error)
    }

    async fn revoke_admin_grant(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        client_id: &str,
    ) -> Result<AdminGrantRevocation, AdminGrantRevokeError> {
        let mut connection = self.pool.get().await.map_err(|_| {
            AdminGrantRevokeError::ClientLookup(AuthorizationPortError::Unavailable)
        })?;
        connection
            .transaction::<AdminGrantRevocation, GrantRevokeTransactionError, _>(
                async |connection| {
                    use diesel::OptionalExtension;

                    let client_pk = oauth_clients::table
                        .filter(oauth_clients::tenant_id.eq(tenant_id))
                        .filter(oauth_clients::client_id.eq(client_id))
                        .select(oauth_clients::id)
                        .first::<Uuid>(connection)
                        .await
                        .optional()
                        .map_err(GrantRevokeTransactionError::ClientLookup)?
                        .ok_or(GrantRevokeTransactionError::ClientNotFound)?;
                    lock_refresh_grant_scope(connection, tenant_id, Some(user_id), client_pk)
                        .await
                        .map_err(GrantRevokeTransactionError::Revoke)?;
                    let family_ids = oauth_tokens::table
                        .filter(oauth_tokens::tenant_id.eq(tenant_id))
                        .filter(oauth_tokens::user_id.eq(user_id))
                        .filter(oauth_tokens::client_id.eq(client_pk))
                        .select(oauth_tokens::token_family_id)
                        .distinct()
                        .order(oauth_tokens::token_family_id.asc())
                        .load::<Uuid>(connection)
                        .await
                        .map_err(GrantRevokeTransactionError::Revoke)?;
                    for family_id in family_ids {
                        lock_refresh_family(connection, family_id)
                            .await
                            .map_err(GrantRevokeTransactionError::Revoke)?;
                    }
                    let revoked_refresh_tokens = diesel::update(
                        oauth_tokens::table
                            .filter(oauth_tokens::tenant_id.eq(tenant_id))
                            .filter(oauth_tokens::user_id.eq(user_id))
                            .filter(oauth_tokens::client_id.eq(client_pk))
                            .filter(oauth_tokens::revoked_at.is_null()),
                    )
                    .set(oauth_tokens::revoked_at.eq(diesel::dsl::now))
                    .execute(connection)
                    .await
                    .map_err(GrantRevokeTransactionError::Revoke)?;
                    let removed_grants = diesel::delete(
                        user_client_grants::table
                            .filter(user_client_grants::tenant_id.eq(tenant_id))
                            .filter(user_client_grants::user_id.eq(user_id))
                            .filter(user_client_grants::client_id.eq(client_pk)),
                    )
                    .execute(connection)
                    .await
                    .map_err(GrantRevokeTransactionError::Revoke)?;
                    Ok(AdminGrantRevocation {
                        revoked_refresh_tokens,
                        removed_grants,
                    })
                },
            )
            .await
            .map_err(Into::into)
    }

    async fn connection(&self) -> Result<crate::DbConnection, RepositoryError> {
        self.pool
            .get()
            .await
            .map_err(|_| RepositoryError::Unavailable)
    }
}

impl AdminGrantRepositoryPort for GrantRepository {
    fn page(
        &self,
        tenant_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> nazo_auth::AdminGrantFuture<'_, AdminGrantPage> {
        Box::pin(async move { self.admin_page(tenant_id, limit, offset).await })
    }

    fn revoke_by_client_id<'a>(
        &'a self,
        tenant_id: Uuid,
        user_id: Uuid,
        client_id: &'a str,
    ) -> nazo_auth::AdminGrantRevokeFuture<'a> {
        Box::pin(async move { self.revoke_admin_grant(tenant_id, user_id, client_id).await })
    }
}

impl nazo_identity::ports::GrantSummaryRepositoryPort for GrantRepository {
    fn authorized_client_count(
        &self,
        user_id: Uuid,
    ) -> nazo_identity::ports::RepositoryFuture<'_, i64> {
        Box::pin(async move { GrantRepository::authorized_client_count(self, user_id).await })
    }
}

fn map_error(error: diesel::result::Error) -> RepositoryError {
    RepositoryError::Unexpected(error.to_string())
}

fn map_authorization_error(_error: diesel::result::Error) -> AuthorizationPortError {
    AuthorizationPortError::Unexpected
}

enum GrantRevokeTransactionError {
    ClientNotFound,
    ClientLookup(diesel::result::Error),
    Revoke(diesel::result::Error),
}

impl From<diesel::result::Error> for GrantRevokeTransactionError {
    fn from(error: diesel::result::Error) -> Self {
        Self::Revoke(error)
    }
}

impl From<GrantRevokeTransactionError> for AdminGrantRevokeError {
    fn from(error: GrantRevokeTransactionError) -> Self {
        match error {
            GrantRevokeTransactionError::ClientNotFound => Self::ClientNotFound,
            GrantRevokeTransactionError::ClientLookup(error) => {
                Self::ClientLookup(map_authorization_error(error))
            }
            GrantRevokeTransactionError::Revoke(error) => {
                Self::Revoke(map_authorization_error(error))
            }
        }
    }
}
