use crate::{
    DbPool,
    convert::identity,
    rows::identity::PublicAccountRow,
    schema::{oauth_tokens, user_client_grants, users},
};
use diesel::{
    BoolExpressionMethods, ExpressionMethods, OptionalExtension, QueryDsl, SelectableHelper,
    dsl::{count_star, now},
    result::{DatabaseErrorKind, Error},
};
use diesel_async::{AsyncConnection, RunQueryDsl};
use nazo_identity::{
    PublicAccount, TenantContext, UserId,
    ports::{
        NewScimUser, RepositoryError, RepositoryFuture, ScimListQuery, ScimRepositoryPort, UserPage,
    },
    scim::{NormalizedScimUser, ScimPatch},
};

#[derive(Clone)]
pub struct ScimRepository {
    pool: DbPool,
}
impl ScimRepository {
    #[must_use]
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    pub async fn list(&self, query: ScimListQuery) -> Result<UserPage, RepositoryError> {
        let mut connection = self
            .pool
            .get()
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        let mut count_query = users::table
            .filter(users::tenant_id.eq(query.tenant_id.as_uuid()))
            .into_boxed();
        if let Some(email) = &query.email {
            count_query = count_query.filter(users::email.eq(email));
        }
        let total = count_query
            .select(count_star())
            .first::<i64>(&mut connection)
            .await
            .map_err(map_error)?;
        if query.limit == 0 {
            return Ok(UserPage {
                total,
                users: Vec::new(),
            });
        }
        let mut rows_query = users::table
            .filter(users::tenant_id.eq(query.tenant_id.as_uuid()))
            .into_boxed();
        if let Some(email) = query.email {
            rows_query = rows_query.filter(users::email.eq(email));
        }
        if let Some((created_at, id)) = query.after {
            rows_query = rows_query.filter(
                users::created_at
                    .gt(created_at)
                    .or(users::created_at.eq(created_at).and(users::id.gt(id))),
            );
        }
        let rows = rows_query
            .select(PublicAccountRow::as_select())
            .order((users::created_at.asc(), users::id.asc()))
            .limit(query.limit)
            .offset(query.offset)
            .load::<PublicAccountRow>(&mut connection)
            .await
            .map_err(map_error)?;
        let users = rows
            .into_iter()
            .map(PublicAccount::try_from)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| RepositoryError::Consistency(error.0))?;
        Ok(UserPage { total, users })
    }

    pub async fn get(
        &self,
        tenant: TenantContext,
        user_id: UserId,
    ) -> Result<Option<PublicAccount>, RepositoryError> {
        let mut connection = self
            .pool
            .get()
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        users::table
            .find(user_id.as_uuid())
            .filter(users::tenant_id.eq(tenant.tenant_id.as_uuid()))
            .select(PublicAccountRow::as_select())
            .first::<PublicAccountRow>(&mut connection)
            .await
            .optional()
            .map_err(map_error)?
            .map(PublicAccount::try_from)
            .transpose()
            .map_err(|error| RepositoryError::Consistency(error.0))
    }

    pub async fn create(&self, new_user: NewScimUser) -> Result<PublicAccount, RepositoryError> {
        let mut connection = self
            .pool
            .get()
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        let input = new_user.input;
        let tenant = new_user.tenant;
        let row = diesel::insert_into(users::table)
            .values((
                users::tenant_id.eq(tenant.tenant_id.as_uuid()),
                users::realm_id.eq(tenant.realm_id.as_uuid()),
                users::organization_id.eq(tenant.organization_id.as_uuid()),
                users::username.eq(input.user_name),
                users::email.eq(input.email),
                users::password_hash.eq(new_user.password_hash.into_persistence_value()),
                users::email_verified.eq(true),
                users::is_active.eq(input.active),
                users::display_name.eq(input.display_name),
                users::given_name.eq(input.given_name),
                users::family_name.eq(input.family_name),
            ))
            .returning(PublicAccountRow::as_returning())
            .get_result(&mut connection)
            .await
            .map_err(map_error)?;
        row.try_into()
            .map_err(|error: identity::ConversionError| RepositoryError::Consistency(error.0))
    }

    pub async fn replace(
        &self,
        tenant: TenantContext,
        user_id: UserId,
        replacement: NormalizedScimUser,
    ) -> Result<PublicAccount, RepositoryError> {
        let mut connection = self
            .pool
            .get()
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        let row = connection
            .transaction::<PublicAccountRow, Error, _>(async move |connection| {
                let row = diesel::update(
                    users::table
                        .find(user_id.as_uuid())
                        .filter(users::tenant_id.eq(tenant.tenant_id.as_uuid())),
                )
                .set((
                    users::username.eq(replacement.user_name),
                    users::email.eq(replacement.email),
                    users::email_verified.eq(true),
                    users::is_active.eq(replacement.active),
                    users::display_name.eq(replacement.display_name),
                    users::given_name.eq(replacement.given_name),
                    users::family_name.eq(replacement.family_name),
                    users::updated_at.eq(now),
                ))
                .returning(PublicAccountRow::as_returning())
                .get_result(connection)
                .await?;
                if !row.is_active {
                    revoke(connection, tenant.tenant_id.as_uuid(), row.id).await?;
                }
                Ok(row)
            })
            .await
            .map_err(map_error)?;
        row.try_into()
            .map_err(|error: identity::ConversionError| RepositoryError::Consistency(error.0))
    }

    pub async fn patch(
        &self,
        tenant: TenantContext,
        user_id: UserId,
        patch: ScimPatch,
    ) -> Result<PublicAccount, RepositoryError> {
        let mut connection = self
            .pool
            .get()
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        let row = connection
            .transaction::<PublicAccountRow, Error, _>(async move |connection| {
                let current = users::table
                    .find(user_id.as_uuid())
                    .filter(users::tenant_id.eq(tenant.tenant_id.as_uuid()))
                    .for_update()
                    .select(PublicAccountRow::as_select())
                    .first::<PublicAccountRow>(connection)
                    .await?;
                let row = diesel::update(users::table.find(user_id.as_uuid()))
                    .set((
                        users::username.eq(patch.user_name.unwrap_or(current.username)),
                        users::email.eq(patch.email.unwrap_or(current.email)),
                        users::email_verified.eq(true),
                        users::is_active.eq(patch.active.unwrap_or(current.is_active)),
                        users::display_name.eq(patch.display_name.or(current.display_name)),
                        users::given_name.eq(patch.given_name.or(current.given_name)),
                        users::family_name.eq(patch.family_name.or(current.family_name)),
                        users::updated_at.eq(now),
                    ))
                    .returning(PublicAccountRow::as_returning())
                    .get_result(connection)
                    .await?;
                if !row.is_active {
                    revoke(connection, tenant.tenant_id.as_uuid(), row.id).await?;
                }
                Ok(row)
            })
            .await
            .map_err(map_error)?;
        row.try_into()
            .map_err(|error: identity::ConversionError| RepositoryError::Consistency(error.0))
    }

    pub async fn deactivate(
        &self,
        tenant: TenantContext,
        user_id: UserId,
    ) -> Result<bool, RepositoryError> {
        let mut connection = self
            .pool
            .get()
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        connection
            .transaction::<bool, Error, _>(async move |connection| {
                let changed = diesel::update(
                    users::table
                        .find(user_id.as_uuid())
                        .filter(users::tenant_id.eq(tenant.tenant_id.as_uuid())),
                )
                .set((users::is_active.eq(false), users::updated_at.eq(now)))
                .execute(connection)
                .await?;
                if changed > 0 {
                    revoke(connection, tenant.tenant_id.as_uuid(), user_id.as_uuid()).await?;
                }
                Ok(changed > 0)
            })
            .await
            .map_err(map_error)
    }
}

impl ScimRepositoryPort for ScimRepository {
    fn list<'a>(&'a self, query: ScimListQuery) -> RepositoryFuture<'a, UserPage> {
        Box::pin(async move { Self::list(self, query).await })
    }

    fn get<'a>(
        &'a self,
        tenant: TenantContext,
        user_id: UserId,
    ) -> RepositoryFuture<'a, Option<PublicAccount>> {
        Box::pin(async move { Self::get(self, tenant, user_id).await })
    }

    fn create<'a>(&'a self, new_user: NewScimUser) -> RepositoryFuture<'a, PublicAccount> {
        Box::pin(async move { Self::create(self, new_user).await })
    }

    fn replace<'a>(
        &'a self,
        tenant: TenantContext,
        user_id: UserId,
        replacement: NormalizedScimUser,
    ) -> RepositoryFuture<'a, PublicAccount> {
        Box::pin(async move { Self::replace(self, tenant, user_id, replacement).await })
    }

    fn patch<'a>(
        &'a self,
        tenant: TenantContext,
        user_id: UserId,
        patch: ScimPatch,
    ) -> RepositoryFuture<'a, PublicAccount> {
        Box::pin(async move { Self::patch(self, tenant, user_id, patch).await })
    }

    fn deactivate<'a>(
        &'a self,
        tenant: TenantContext,
        user_id: UserId,
    ) -> RepositoryFuture<'a, bool> {
        Box::pin(async move { Self::deactivate(self, tenant, user_id).await })
    }
}

async fn revoke(
    connection: &mut diesel_async::AsyncPgConnection,
    tenant_id: uuid::Uuid,
    user_id: uuid::Uuid,
) -> Result<(), Error> {
    diesel::update(
        oauth_tokens::table
            .filter(oauth_tokens::tenant_id.eq(tenant_id))
            .filter(oauth_tokens::user_id.eq(user_id))
            .filter(oauth_tokens::revoked_at.is_null()),
    )
    .set(oauth_tokens::revoked_at.eq(now))
    .execute(connection)
    .await?;
    diesel::delete(
        user_client_grants::table
            .filter(user_client_grants::tenant_id.eq(tenant_id))
            .filter(user_client_grants::user_id.eq(user_id)),
    )
    .execute(connection)
    .await?;
    Ok(())
}

fn map_error(error: Error) -> RepositoryError {
    match error {
        Error::NotFound => RepositoryError::NotFound,
        Error::DatabaseError(DatabaseErrorKind::UniqueViolation, _) => RepositoryError::Conflict,
        other => RepositoryError::Unexpected(other.to_string()),
    }
}
