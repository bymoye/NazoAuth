use crate::{
    DbPool,
    convert::identity,
    rows::identity::{ExternalIdentityLinkRow, PublicAccountRow},
    schema::{external_identity_links, users},
};
use diesel::{
    ExpressionMethods, OptionalExtension, QueryDsl, SelectableHelper,
    result::{DatabaseErrorKind, Error},
};
use diesel_async::{AsyncConnection, RunQueryDsl};
use nazo_identity::{
    PublicAccount, TenantId, UserId,
    ports::{
        FederationLink, FederationLogin, NewFederatedIdentity, NewFederationLink, RepositoryError,
    },
};

#[derive(Clone)]
pub struct FederationRepository {
    pool: DbPool,
}
impl FederationRepository {
    #[must_use]
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }
    pub async fn insert(&self, link: NewFederationLink) -> Result<FederationLink, RepositoryError> {
        let mut connection = self
            .pool
            .get()
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        let row = diesel::insert_into(external_identity_links::table)
            .values((
                external_identity_links::tenant_id.eq(link.tenant_id.as_uuid()),
                external_identity_links::user_id.eq(link.user_id.as_uuid()),
                external_identity_links::provider_type.eq(link.provider_type),
                external_identity_links::provider_id.eq(link.provider_id),
                external_identity_links::subject.eq(link.subject),
                external_identity_links::email.eq(link.email),
                external_identity_links::claims.eq(link.claims),
            ))
            .returning(ExternalIdentityLinkRow::as_returning())
            .get_result(&mut connection)
            .await
            .map_err(map_error)?;
        identity::federation_link(row).map_err(|error| RepositoryError::Consistency(error.0))
    }
    pub async fn list(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> Result<Vec<FederationLink>, RepositoryError> {
        let mut connection = self
            .pool
            .get()
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        external_identity_links::table
            .filter(external_identity_links::tenant_id.eq(tenant_id.as_uuid()))
            .filter(external_identity_links::user_id.eq(user_id.as_uuid()))
            .select(ExternalIdentityLinkRow::as_select())
            .load(&mut connection)
            .await
            .map_err(map_error)?
            .into_iter()
            .map(identity::federation_link)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| RepositoryError::Consistency(error.0))
    }
    pub async fn delete(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
        link_id: uuid::Uuid,
    ) -> Result<Option<FederationLink>, RepositoryError> {
        let mut connection = self
            .pool
            .get()
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        diesel::delete(
            external_identity_links::table
                .find(link_id)
                .filter(external_identity_links::tenant_id.eq(tenant_id.as_uuid()))
                .filter(external_identity_links::user_id.eq(user_id.as_uuid())),
        )
        .returning(ExternalIdentityLinkRow::as_returning())
        .get_result(&mut connection)
        .await
        .optional()
        .map_err(map_error)?
        .map(identity::federation_link)
        .transpose()
        .map_err(|error| RepositoryError::Consistency(error.0))
    }
    pub async fn resolve_existing(
        &self,
        login: FederationLogin,
    ) -> Result<Option<PublicAccount>, RepositoryError> {
        let mut connection = self
            .pool
            .get()
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        connection
            .transaction::<_, diesel::result::Error, _>(async move |connection| {
                let link = external_identity_links::table
                    .filter(external_identity_links::tenant_id.eq(login.tenant.tenant_id.as_uuid()))
                    .filter(external_identity_links::provider_type.eq(&login.provider_type))
                    .filter(external_identity_links::provider_id.eq(&login.provider_id))
                    .filter(external_identity_links::subject.eq(&login.subject))
                    .select(ExternalIdentityLinkRow::as_select())
                    .first::<ExternalIdentityLinkRow>(connection)
                    .await
                    .optional()?;
                let Some(link) = link else {
                    return Ok(None);
                };
                let user = users::table
                    .find(link.user_id)
                    .filter(users::tenant_id.eq(login.tenant.tenant_id.as_uuid()))
                    .select(PublicAccountRow::as_select())
                    .first::<PublicAccountRow>(connection)
                    .await?;
                let email = login.email.unwrap_or(link.email);
                diesel::update(external_identity_links::table.find(link.id))
                    .set((
                        external_identity_links::email.eq(email),
                        external_identity_links::claims.eq(login.claims),
                        external_identity_links::last_login_at.eq(diesel::dsl::now),
                        external_identity_links::updated_at.eq(diesel::dsl::now),
                    ))
                    .execute(connection)
                    .await?;
                Ok(Some(user))
            })
            .await
            .map_err(map_error)?
            .map(PublicAccount::try_from)
            .transpose()
            .map_err(|error| RepositoryError::Consistency(error.0))
    }
    pub async fn create_federated(
        &self,
        new_identity: NewFederatedIdentity,
    ) -> Result<PublicAccount, RepositoryError> {
        let retry_login = new_identity.login.clone();
        let mut connection = self
            .pool
            .get()
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        let result = connection
            .transaction::<_, diesel::result::Error, _>(async move |connection| {
                let tenant = new_identity.login.tenant;
                let user = diesel::insert_into(users::table)
                    .values((
                        users::tenant_id.eq(tenant.tenant_id.as_uuid()),
                        users::realm_id.eq(tenant.realm_id.as_uuid()),
                        users::organization_id.eq(tenant.organization_id.as_uuid()),
                        users::username.eq(&new_identity.email),
                        users::email.eq(&new_identity.email),
                        users::password_hash
                            .eq(new_identity.password_hash.into_persistence_value()),
                        users::email_verified.eq(true),
                        users::display_name.eq(new_identity.display_name),
                    ))
                    .returning(PublicAccountRow::as_returning())
                    .get_result::<PublicAccountRow>(connection)
                    .await?;
                diesel::insert_into(external_identity_links::table)
                    .values((
                        external_identity_links::tenant_id.eq(tenant.tenant_id.as_uuid()),
                        external_identity_links::user_id.eq(user.id),
                        external_identity_links::provider_type.eq(new_identity.login.provider_type),
                        external_identity_links::provider_id.eq(new_identity.login.provider_id),
                        external_identity_links::subject.eq(new_identity.login.subject),
                        external_identity_links::email.eq(new_identity.email),
                        external_identity_links::claims.eq(new_identity.login.claims),
                        external_identity_links::last_login_at.eq(diesel::dsl::now),
                    ))
                    .execute(connection)
                    .await?;
                Ok(user)
            })
            .await;
        match result {
            Ok(row) => row
                .try_into()
                .map_err(|error: identity::ConversionError| RepositoryError::Consistency(error.0)),
            Err(Error::DatabaseError(DatabaseErrorKind::UniqueViolation, _)) => self
                .resolve_existing(retry_login)
                .await?
                .ok_or(RepositoryError::Conflict),
            Err(error) => Err(map_error(error)),
        }
    }
}

impl nazo_identity::ports::FederationLinkRepositoryPort for FederationRepository {
    fn list(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> nazo_identity::ports::RepositoryFuture<'_, Vec<FederationLink>> {
        Box::pin(async move { FederationRepository::list(self, tenant_id, user_id).await })
    }

    fn delete(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
        link_id: uuid::Uuid,
    ) -> nazo_identity::ports::RepositoryFuture<'_, Option<FederationLink>> {
        Box::pin(
            async move { FederationRepository::delete(self, tenant_id, user_id, link_id).await },
        )
    }
}

impl nazo_identity::ports::FederationLoginRepositoryPort for FederationRepository {
    fn resolve_existing(
        &self,
        login: FederationLogin,
    ) -> nazo_identity::ports::RepositoryFuture<'_, Option<PublicAccount>> {
        Box::pin(async move { FederationRepository::resolve_existing(self, login).await })
    }

    fn account_by_email<'a>(
        &'a self,
        tenant_id: TenantId,
        email: &'a str,
    ) -> nazo_identity::ports::RepositoryFuture<'a, Option<PublicAccount>> {
        Box::pin(async move {
            super::UserRepository::new(self.pool.clone())
                .public_account_by_email(tenant_id, email)
                .await
        })
    }

    fn create_federated(
        &self,
        identity: NewFederatedIdentity,
    ) -> nazo_identity::ports::RepositoryFuture<'_, PublicAccount> {
        Box::pin(async move { FederationRepository::create_federated(self, identity).await })
    }
}
fn map_error(error: Error) -> RepositoryError {
    match error {
        Error::DatabaseError(DatabaseErrorKind::UniqueViolation, _) => RepositoryError::Conflict,
        other => RepositoryError::Unexpected(other.to_string()),
    }
}
