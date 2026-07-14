use crate::{
    DbPool,
    convert::identity,
    repositories::audit::insert_identity_security_event,
    rows::identity::{AuthenticationIdentityRow, PrincipalRow, PublicAccountRow, SubjectClaimsRow},
    schema::users,
};
use diesel::{
    ExpressionMethods, OptionalExtension, PgExpressionMethods, QueryDsl, SelectableHelper,
};
use diesel_async::RunQueryDsl;
use nazo_identity::{
    AdminPolicyError, AdminUserUpdateOutcome, AuthenticationIdentity, IdentitySecurityEvent,
    IdentitySecurityEventType, IdentitySecurityOutcome, IdentitySecurityReason, Principal,
    PublicAccount, SubjectClaims, TenantContext, TenantId, UserId, authorize_admin_update,
    ports::{
        AdminUserUpdate, NewUser, ProfileUpdate, RepositoryError, UserPage, UserRepositoryPort,
    },
};

#[derive(Clone)]
pub struct UserRepository {
    pool: DbPool,
}
impl UserRepository {
    #[must_use]
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }
    pub async fn principal_by_id(
        &self,
        tenant: TenantContext,
        user_id: UserId,
    ) -> Result<Option<Principal>, RepositoryError> {
        let mut connection = self
            .pool
            .get()
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        users::table
            .find(user_id.as_uuid())
            .filter(users::tenant_id.eq(tenant.tenant_id.as_uuid()))
            .filter(users::realm_id.eq(tenant.realm_id.as_uuid()))
            .filter(users::organization_id.eq(tenant.organization_id.as_uuid()))
            .select(PrincipalRow::as_select())
            .first(&mut connection)
            .await
            .optional()
            .map_err(|error| RepositoryError::Unexpected(error.to_string()))?
            .map(identity::principal_row)
            .transpose()
            .map_err(|error| RepositoryError::Consistency(error.0))
    }

    pub async fn public_account_by_id(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> Result<Option<PublicAccount>, RepositoryError> {
        let mut connection = self
            .pool
            .get()
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        users::table
            .find(user_id.as_uuid())
            .filter(users::tenant_id.eq(tenant_id.as_uuid()))
            .select(PublicAccountRow::as_select())
            .first(&mut connection)
            .await
            .optional()
            .map_err(|error| RepositoryError::Unexpected(error.to_string()))?
            .map(PublicAccount::try_from)
            .transpose()
            .map_err(|error| RepositoryError::Consistency(error.0))
    }

    pub async fn principal_by_tenant_id(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> Result<Option<Principal>, RepositoryError> {
        let mut connection = self
            .pool
            .get()
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        users::table
            .find(user_id.as_uuid())
            .filter(users::tenant_id.eq(tenant_id.as_uuid()))
            .select(PrincipalRow::as_select())
            .first(&mut connection)
            .await
            .optional()
            .map_err(|error| RepositoryError::Unexpected(error.to_string()))?
            .map(identity::principal_row)
            .transpose()
            .map_err(|error| RepositoryError::Consistency(error.0))
    }

    pub async fn active_subject_claims_by_tenant_id(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> Result<Option<SubjectClaims>, RepositoryError> {
        let mut connection = self
            .pool
            .get()
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        users::table
            .find(user_id.as_uuid())
            .filter(users::tenant_id.eq(tenant_id.as_uuid()))
            .filter(users::is_active.eq(true))
            .select(SubjectClaimsRow::as_select())
            .first(&mut connection)
            .await
            .optional()
            .map_err(|error| RepositoryError::Unexpected(error.to_string()))?
            .map(identity::active_subject_claims)
            .transpose()
            .map_err(|error| RepositoryError::Consistency(error.0))
    }

    pub async fn public_account_by_email(
        &self,
        tenant_id: TenantId,
        email: &str,
    ) -> Result<Option<PublicAccount>, RepositoryError> {
        let mut connection = self
            .pool
            .get()
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        users::table
            .filter(users::tenant_id.eq(tenant_id.as_uuid()))
            .filter(users::email.eq(email.trim()))
            .select(PublicAccountRow::as_select())
            .first(&mut connection)
            .await
            .optional()
            .map_err(|error| RepositoryError::Unexpected(error.to_string()))?
            .map(PublicAccount::try_from)
            .transpose()
            .map_err(|error| RepositoryError::Consistency(error.0))
    }
    pub async fn authentication_by_email(
        &self,
        tenant_id: TenantId,
        email: &str,
    ) -> Result<Option<AuthenticationIdentity>, RepositoryError> {
        let mut connection = self
            .pool
            .get()
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        users::table
            .filter(users::tenant_id.eq(tenant_id.as_uuid()))
            .filter(users::email.eq(email.trim()))
            .select(AuthenticationIdentityRow::as_select())
            .first(&mut connection)
            .await
            .optional()
            .map_err(|error| RepositoryError::Unexpected(error.to_string()))?
            .map(identity::authentication_identity)
            .transpose()
            .map_err(|error| RepositoryError::Consistency(error.0))
    }

    pub async fn create(&self, new_user: NewUser) -> Result<PublicAccount, RepositoryError> {
        let mut connection = self
            .pool
            .get()
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        let row = diesel::insert_into(users::table)
            .values((
                users::tenant_id.eq(new_user.tenant.tenant_id.as_uuid()),
                users::realm_id.eq(new_user.tenant.realm_id.as_uuid()),
                users::organization_id.eq(new_user.tenant.organization_id.as_uuid()),
                users::username.eq(new_user.username),
                users::email.eq(new_user.email),
                users::password_hash.eq(new_user.password_hash.into_persistence_value()),
                users::email_verified.eq(new_user.email_verified),
            ))
            .returning(PublicAccountRow::as_returning())
            .get_result(&mut connection)
            .await
            .map_err(map_error)?;
        row.try_into()
            .map_err(|error: identity::ConversionError| RepositoryError::Consistency(error.0))
    }
    pub async fn update_profile(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
        update: ProfileUpdate,
    ) -> Result<PublicAccount, RepositoryError> {
        let mut connection = self
            .pool
            .get()
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        let profile = update.profile;
        let row = diesel::update(
            users::table
                .find(user_id.as_uuid())
                .filter(users::tenant_id.eq(tenant_id.as_uuid()))
                .filter(users::is_active.eq(true)),
        )
        .set((
            users::display_name.eq(profile.display_name),
            users::given_name.eq(profile.given_name),
            users::family_name.eq(profile.family_name),
            users::middle_name.eq(profile.middle_name),
            users::nickname.eq(profile.nickname),
            users::profile_url.eq(profile.profile_url),
            users::website_url.eq(profile.website_url),
            users::gender.eq(profile.gender),
            users::birthdate.eq(profile.birthdate),
            users::zoneinfo.eq(profile.zoneinfo),
            users::locale.eq(profile.locale),
            users::address_formatted.eq(profile.address.formatted),
            users::address_street_address.eq(profile.address.street_address),
            users::address_locality.eq(profile.address.locality),
            users::address_region.eq(profile.address.region),
            users::address_postal_code.eq(profile.address.postal_code),
            users::address_country.eq(profile.address.country),
            users::phone_number.eq(profile.phone_number),
            users::phone_number_verified.eq(profile.phone_number_verified),
            users::updated_at.eq(diesel::dsl::now),
        ))
        .returning(PublicAccountRow::as_returning())
        .get_result(&mut connection)
        .await
        .optional()
        .map_err(map_error)?
        .ok_or(RepositoryError::NotFound)?;
        row.try_into()
            .map_err(|error: identity::ConversionError| RepositoryError::Consistency(error.0))
    }
    pub async fn compare_and_set_avatar(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
        expected_avatar_url: Option<&str>,
        avatar_url: Option<String>,
    ) -> Result<Option<PublicAccount>, RepositoryError> {
        let mut connection = self
            .pool
            .get()
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        let row = diesel::update(
            users::table
                .find(user_id.as_uuid())
                .filter(users::tenant_id.eq(tenant_id.as_uuid()))
                .filter(users::avatar_url.is_not_distinct_from(expected_avatar_url)),
        )
        .set((
            users::avatar_url.eq(avatar_url),
            users::updated_at.eq(diesel::dsl::now),
        ))
        .returning(PublicAccountRow::as_returning())
        .get_result(&mut connection)
        .await
        .optional()
        .map_err(map_error)?;
        row.map(PublicAccount::try_from)
            .transpose()
            .map_err(|error: identity::ConversionError| RepositoryError::Consistency(error.0))
    }
    pub async fn page(
        &self,
        tenant_id: TenantId,
        limit: i64,
        offset: i64,
    ) -> Result<UserPage, RepositoryError> {
        let mut connection = self
            .pool
            .get()
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        let total = users::table
            .filter(users::tenant_id.eq(tenant_id.as_uuid()))
            .select(diesel::dsl::count_star())
            .first::<i64>(&mut connection)
            .await
            .map_err(map_error)?;
        let rows = users::table
            .filter(users::tenant_id.eq(tenant_id.as_uuid()))
            .select(PublicAccountRow::as_select())
            .order(users::created_at.desc())
            .limit(limit)
            .offset(offset)
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
    pub async fn admin_update_authorized(
        &self,
        tenant_id: TenantId,
        actor_id: UserId,
        target_id: UserId,
        update: AdminUserUpdate,
    ) -> Result<AdminUserUpdateOutcome, RepositoryError> {
        let mut connection = self
            .pool
            .get()
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        diesel_async::AsyncConnection::transaction::<_, AdminAuthorizedUpdateError, _>(
            &mut connection,
            async move |connection| {
                // A stable lock order prevents two concurrent hierarchy updates from
                // deadlocking when their actor and target are reversed.
                let accounts = users::table
                    .filter(users::id.eq_any([actor_id.as_uuid(), target_id.as_uuid()]))
                    .order(users::id.asc())
                    .select(PublicAccountRow::as_select())
                    .for_update()
                    .load::<PublicAccountRow>(connection)
                    .await?;
                let mut accounts = accounts
                    .into_iter()
                    .map(PublicAccount::try_from)
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|error| AdminAuthorizedUpdateError::Consistency(error.0))?;
                let actor = accounts
                    .iter()
                    .find(|account| account.id() == actor_id.as_uuid())
                    .cloned();
                let target = accounts
                    .iter_mut()
                    .find(|account| account.id() == target_id.as_uuid())
                    .cloned();
                let Some(actor) = actor.filter(|actor| actor.tenant().tenant_id == tenant_id)
                else {
                    insert_identity_security_event(
                        connection,
                        &admin_event(
                            tenant_id,
                            None,
                            None,
                            IdentitySecurityOutcome::Denied,
                            IdentitySecurityReason::ActorNotAuthorized,
                        ),
                    )
                    .await
                    .map_err(AdminAuthorizedUpdateError::Repository)?;
                    return Ok(AdminUserUpdateOutcome::Denied(
                        AdminPolicyError::ActorNotAuthorized,
                    ));
                };
                let Some(target) = target else {
                    insert_identity_security_event(
                        connection,
                        &admin_event(
                            tenant_id,
                            Some(actor_id),
                            None,
                            IdentitySecurityOutcome::Denied,
                            IdentitySecurityReason::TargetNotFound,
                        ),
                    )
                    .await
                    .map_err(AdminAuthorizedUpdateError::Repository)?;
                    return Ok(AdminUserUpdateOutcome::TargetNotFound);
                };
                let decision = authorize_admin_update(&actor.principal, &target.principal, &update);
                let resolved = match decision {
                    Ok(resolved) => resolved,
                    Err(reason) => {
                        let same_tenant = target.tenant().tenant_id == tenant_id;
                        insert_identity_security_event(
                            connection,
                            &admin_event(
                                tenant_id,
                                Some(actor_id),
                                same_tenant.then_some(target_id),
                                IdentitySecurityOutcome::Denied,
                                admin_denial_reason(reason),
                            ),
                        )
                        .await
                        .map_err(AdminAuthorizedUpdateError::Repository)?;
                        return Ok(AdminUserUpdateOutcome::Denied(reason));
                    }
                };
                if update.role.is_none() && update.admin_level.is_none() && update.active.is_none()
                {
                    insert_identity_security_event(
                        connection,
                        &admin_event(
                            tenant_id,
                            Some(actor_id),
                            Some(target_id),
                            IdentitySecurityOutcome::Success,
                            IdentitySecurityReason::AdminUpdated,
                        ),
                    )
                    .await
                    .map_err(AdminAuthorizedUpdateError::Repository)?;
                    return Ok(AdminUserUpdateOutcome::Updated(Box::new(target)));
                }
                let updated = diesel::update(users::table.find(target_id.as_uuid()))
                    .set((
                        users::role.eq(resolved.role),
                        users::admin_level.eq(resolved.admin_level),
                        users::is_active.eq(resolved.active),
                        users::updated_at.eq(diesel::dsl::now),
                    ))
                    .returning(PublicAccountRow::as_returning())
                    .get_result::<PublicAccountRow>(connection)
                    .await?;
                insert_identity_security_event(
                    connection,
                    &admin_event(
                        tenant_id,
                        Some(actor_id),
                        Some(target_id),
                        IdentitySecurityOutcome::Success,
                        IdentitySecurityReason::AdminUpdated,
                    ),
                )
                .await
                .map_err(AdminAuthorizedUpdateError::Repository)?;
                let updated = PublicAccount::try_from(updated)
                    .map_err(|error| AdminAuthorizedUpdateError::Consistency(error.0))?;
                Ok(AdminUserUpdateOutcome::Updated(Box::new(updated)))
            },
        )
        .await
        .map_err(AdminAuthorizedUpdateError::into_repository)
    }
    pub async fn subject_claims_by_id(
        &self,
        tenant: TenantContext,
        user_id: UserId,
    ) -> Result<Option<SubjectClaims>, RepositoryError> {
        let mut connection = self
            .pool
            .get()
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        users::table
            .find(user_id.as_uuid())
            .filter(users::tenant_id.eq(tenant.tenant_id.as_uuid()))
            .filter(users::realm_id.eq(tenant.realm_id.as_uuid()))
            .filter(users::organization_id.eq(tenant.organization_id.as_uuid()))
            .filter(users::is_active.eq(true))
            .select(SubjectClaimsRow::as_select())
            .first(&mut connection)
            .await
            .optional()
            .map_err(|error| RepositoryError::Unexpected(error.to_string()))?
            .map(identity::active_subject_claims)
            .transpose()
            .map_err(|error| RepositoryError::Consistency(error.0))
    }
}

fn admin_event(
    tenant_id: TenantId,
    actor_id: Option<UserId>,
    target_user_id: Option<UserId>,
    outcome: IdentitySecurityOutcome,
    reason: IdentitySecurityReason,
) -> IdentitySecurityEvent {
    IdentitySecurityEvent {
        tenant_id,
        event_type: IdentitySecurityEventType::AdminUserUpdate,
        outcome,
        actor_id,
        target_user_id,
        reason,
        occurred_at: std::time::SystemTime::now(),
    }
}

const fn admin_denial_reason(error: AdminPolicyError) -> IdentitySecurityReason {
    match error {
        AdminPolicyError::ActorNotAuthorized => IdentitySecurityReason::ActorNotAuthorized,
        AdminPolicyError::CrossTenant => IdentitySecurityReason::CrossTenant,
        AdminPolicyError::SelfElevation => IdentitySecurityReason::SelfElevation,
        AdminPolicyError::SelfDemotionOrDisable => IdentitySecurityReason::SelfDemotionOrDisable,
        AdminPolicyError::TargetAtOrAboveActor => IdentitySecurityReason::TargetAtOrAboveActor,
        AdminPolicyError::GrantAtOrAboveActor => IdentitySecurityReason::GrantAtOrAboveActor,
        AdminPolicyError::InvalidRoleLevel => IdentitySecurityReason::InvalidRoleLevel,
    }
}

enum AdminAuthorizedUpdateError {
    Diesel(diesel::result::Error),
    Repository(RepositoryError),
    Consistency(String),
}

impl From<diesel::result::Error> for AdminAuthorizedUpdateError {
    fn from(error: diesel::result::Error) -> Self {
        Self::Diesel(error)
    }
}

impl AdminAuthorizedUpdateError {
    fn into_repository(self) -> RepositoryError {
        match self {
            Self::Diesel(error) => map_error(error),
            Self::Repository(error) => error,
            Self::Consistency(message) => RepositoryError::Consistency(message),
        }
    }
}

fn map_error(error: diesel::result::Error) -> RepositoryError {
    match error {
        diesel::result::Error::DatabaseError(
            diesel::result::DatabaseErrorKind::UniqueViolation,
            _,
        ) => RepositoryError::Conflict,
        other => RepositoryError::Unexpected(other.to_string()),
    }
}
impl UserRepositoryPort for UserRepository {
    fn principal_by_id<'a>(
        &'a self,
        tenant: TenantContext,
        user_id: UserId,
    ) -> nazo_identity::ports::RepositoryFuture<'a, Option<Principal>> {
        Box::pin(async move { self.principal_by_id(tenant, user_id).await })
    }
    fn subject_claims_by_id<'a>(
        &'a self,
        tenant: TenantContext,
        user_id: UserId,
    ) -> nazo_identity::ports::RepositoryFuture<'a, Option<SubjectClaims>> {
        Box::pin(async move { self.subject_claims_by_id(tenant, user_id).await })
    }
}

impl nazo_identity::ports::AdminUserRepositoryPort for UserRepository {
    fn page(
        &self,
        tenant_id: nazo_identity::TenantId,
        limit: i64,
        offset: i64,
    ) -> nazo_identity::ports::RepositoryFuture<'_, nazo_identity::ports::UserPage> {
        Box::pin(async move { UserRepository::page(self, tenant_id, limit, offset).await })
    }

    fn update_authorized(
        &self,
        tenant_id: nazo_identity::TenantId,
        actor_id: nazo_identity::UserId,
        target_id: nazo_identity::UserId,
        update: nazo_identity::ports::AdminUserUpdate,
    ) -> nazo_identity::ports::RepositoryFuture<'_, nazo_identity::AdminUserUpdateOutcome> {
        Box::pin(async move {
            UserRepository::admin_update_authorized(self, tenant_id, actor_id, target_id, update)
                .await
        })
    }
}

impl nazo_identity::ports::ProfileRepositoryPort for UserRepository {
    fn update_profile<'a>(
        &'a self,
        tenant_id: nazo_identity::TenantId,
        user_id: nazo_identity::UserId,
        update: nazo_identity::ports::ProfileUpdate,
    ) -> nazo_identity::ports::RepositoryFuture<'a, nazo_identity::PublicAccount> {
        Box::pin(
            async move { UserRepository::update_profile(self, tenant_id, user_id, update).await },
        )
    }
}

impl nazo_identity::ports::AvatarRepositoryPort for UserRepository {
    fn compare_and_set_avatar<'a>(
        &'a self,
        tenant_id: nazo_identity::TenantId,
        user_id: nazo_identity::UserId,
        expected_avatar_url: Option<&'a str>,
        avatar_url: Option<String>,
    ) -> nazo_identity::ports::RepositoryFuture<'a, Option<nazo_identity::PublicAccount>> {
        Box::pin(async move {
            UserRepository::compare_and_set_avatar(
                self,
                tenant_id,
                user_id,
                expected_avatar_url,
                avatar_url,
            )
            .await
        })
    }
}

impl nazo_identity::ports::RegistrationAccountRepositoryPort for UserRepository {
    fn account_by_email<'a>(
        &'a self,
        tenant_id: nazo_identity::TenantId,
        email: &'a str,
    ) -> nazo_identity::ports::RepositoryFuture<'a, Option<nazo_identity::PublicAccount>> {
        Box::pin(
            async move { UserRepository::public_account_by_email(self, tenant_id, email).await },
        )
    }

    fn create_user(
        &self,
        user: nazo_identity::ports::NewUser,
    ) -> nazo_identity::ports::RepositoryFuture<'_, nazo_identity::PublicAccount> {
        Box::pin(async move { UserRepository::create(self, user).await })
    }
}

impl nazo_identity::ports::LoginAccountRepositoryPort for UserRepository {
    fn authentication_by_email<'a>(
        &'a self,
        tenant_id: nazo_identity::TenantId,
        email: &'a str,
    ) -> nazo_identity::ports::RepositoryFuture<'a, Option<nazo_identity::AuthenticationIdentity>>
    {
        Box::pin(
            async move { UserRepository::authentication_by_email(self, tenant_id, email).await },
        )
    }

    fn public_account_by_id(
        &self,
        tenant_id: nazo_identity::TenantId,
        user_id: nazo_identity::UserId,
    ) -> nazo_identity::ports::RepositoryFuture<'_, Option<nazo_identity::PublicAccount>> {
        Box::pin(
            async move { UserRepository::public_account_by_id(self, tenant_id, user_id).await },
        )
    }
}

impl nazo_identity::ports::SessionAccountPort for UserRepository {
    fn public_account_by_id(
        &self,
        tenant_id: nazo_identity::TenantId,
        user_id: nazo_identity::UserId,
    ) -> nazo_identity::ports::RepositoryFuture<'_, Option<nazo_identity::PublicAccount>> {
        Box::pin(
            async move { UserRepository::public_account_by_id(self, tenant_id, user_id).await },
        )
    }
}

impl nazo_identity::ports::PasskeyAccountRepositoryPort for UserRepository {
    fn by_email<'a>(
        &'a self,
        tenant_id: nazo_identity::TenantId,
        email: &'a str,
    ) -> nazo_identity::ports::RepositoryFuture<'a, Option<nazo_identity::PublicAccount>> {
        Box::pin(
            async move { UserRepository::public_account_by_email(self, tenant_id, email).await },
        )
    }

    fn by_id(
        &self,
        tenant_id: nazo_identity::TenantId,
        user_id: nazo_identity::UserId,
    ) -> nazo_identity::ports::RepositoryFuture<'_, Option<nazo_identity::PublicAccount>> {
        Box::pin(
            async move { UserRepository::public_account_by_id(self, tenant_id, user_id).await },
        )
    }
}
