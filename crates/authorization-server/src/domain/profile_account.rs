use nazo_http_actix::{
    ProfileAccountError, ProfileAccountFuture, ProfileAccountOperations, ProfileMe,
};
use nazo_identity::{
    AccountProfileService, AccountProfileView, AuthorizedApplicationsView, ProfilePatch, SessionId,
    SessionResolution, SessionService, ports::AuthorizedApplicationRepositoryPort,
    ports::GrantSummaryRepositoryPort, ports::ProfileRepositoryPort,
};

#[derive(Clone)]
pub(crate) struct ServerProfileAccountOperations<P, G, A> {
    sessions: SessionService,
    profiles: AccountProfileService<P, G, A>,
}

impl<P, G, A> ServerProfileAccountOperations<P, G, A> {
    pub(crate) fn new(sessions: SessionService, profiles: AccountProfileService<P, G, A>) -> Self {
        Self { sessions, profiles }
    }
}

impl<P, G, A> ServerProfileAccountOperations<P, G, A>
where
    P: ProfileRepositoryPort,
    G: GrantSummaryRepositoryPort,
    A: AuthorizedApplicationRepositoryPort,
{
    async fn active_account(
        &self,
        session_id: &SessionId,
    ) -> Result<nazo_identity::PublicAccount, ProfileAccountError> {
        match self
            .sessions
            .current(session_id, chrono::Utc::now().timestamp())
            .await
        {
            Ok(SessionResolution::Present(session)) => Ok(session.into_user()),
            Ok(SessionResolution::Missing | SessionResolution::Invalidated) => {
                Err(ProfileAccountError::LoginRequired)
            }
            Err(error) => {
                tracing::warn!(%error, "failed to resolve current profile session");
                Err(ProfileAccountError::SessionLookupUnavailable)
            }
        }
    }

    async fn me(&self, session_id: SessionId) -> Result<ProfileMe, ProfileAccountError> {
        match self
            .sessions
            .current(&session_id, chrono::Utc::now().timestamp())
            .await
        {
            Ok(SessionResolution::Present(session)) => {
                let overview =
                    self.profiles
                        .overview(session.into_user())
                        .await
                        .map_err(|error| {
                            tracing::warn!(%error, "failed to build auth me response");
                            ProfileAccountError::OverviewUnavailable
                        })?;
                Ok(ProfileMe::Active(Box::new(overview.into())))
            }
            Ok(SessionResolution::Missing | SessionResolution::Invalidated) => {
                match self
                    .sessions
                    .pending_mfa(&session_id, chrono::Utc::now().timestamp())
                    .await
                {
                    Ok(SessionResolution::Present(session)) => {
                        Ok(ProfileMe::PendingMfa(session.into_user().into()))
                    }
                    Ok(SessionResolution::Missing | SessionResolution::Invalidated) => {
                        Err(ProfileAccountError::LoginRequired)
                    }
                    Err(error) => {
                        tracing::warn!(%error, "failed to resolve pending MFA session");
                        Err(ProfileAccountError::SessionLookupUnavailable)
                    }
                }
            }
            Err(error) => {
                tracing::warn!(%error, "failed to resolve current session");
                Err(ProfileAccountError::SessionLookupUnavailable)
            }
        }
    }

    async fn update(
        &self,
        session_id: SessionId,
        patch: ProfilePatch,
    ) -> Result<AccountProfileView, ProfileAccountError> {
        let account = self.active_account(&session_id).await?;
        self.profiles
            .update(&account, patch)
            .await
            .map(AccountProfileView::from)
            .map_err(|error| match error {
                nazo_identity::UpdateProfileError::Validation(error) => {
                    ProfileAccountError::Validation(error)
                }
                nazo_identity::UpdateProfileError::UpdateRepository(
                    nazo_identity::ports::RepositoryError::NotFound,
                ) => ProfileAccountError::LoginRequired,
                nazo_identity::UpdateProfileError::UpdateRepository(error) => {
                    tracing::warn!(%error, "failed to update profile");
                    ProfileAccountError::UpdateUnavailable
                }
                nazo_identity::UpdateProfileError::OverviewRepository(error) => {
                    tracing::warn!(%error, "failed to build updated auth me response");
                    ProfileAccountError::UpdatedOverviewUnavailable
                }
            })
    }

    async fn applications(
        &self,
        session_id: SessionId,
    ) -> Result<AuthorizedApplicationsView, ProfileAccountError> {
        let account = self.active_account(&session_id).await?;
        self.profiles
            .applications(&account)
            .await
            .map(AuthorizedApplicationsView::from)
            .map_err(|error| {
                tracing::warn!(%error, "failed to load user applications");
                ProfileAccountError::ApplicationsUnavailable
            })
    }
}

impl<P, G, A> ProfileAccountOperations for ServerProfileAccountOperations<P, G, A>
where
    P: ProfileRepositoryPort + 'static,
    G: GrantSummaryRepositoryPort + 'static,
    A: AuthorizedApplicationRepositoryPort + 'static,
{
    fn me(&self, session_id: SessionId) -> ProfileAccountFuture<'_, ProfileMe> {
        Box::pin(async move { Self::me(self, session_id).await })
    }

    fn update(
        &self,
        session_id: SessionId,
        patch: ProfilePatch,
    ) -> ProfileAccountFuture<'_, AccountProfileView> {
        Box::pin(async move { Self::update(self, session_id, patch).await })
    }

    fn applications(
        &self,
        session_id: SessionId,
    ) -> ProfileAccountFuture<'_, AuthorizedApplicationsView> {
        Box::pin(async move { Self::applications(self, session_id).await })
    }
}

#[cfg(test)]
#[path = "../../tests/in_source/src/domain/tests/profile_account.rs"]
mod tests;
