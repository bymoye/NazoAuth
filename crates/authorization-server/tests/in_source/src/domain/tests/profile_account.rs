use std::sync::Arc;

use chrono::{TimeZone as _, Utc};
use nazo_http_actix::{ProfileAccountError, ProfileMe};
use nazo_identity::{
    AccountIdentity, AccountProfileService, Principal, ProfilePatch, PublicAccount, SessionId,
    SessionService, TenantContext, TenantId, UserId, UserProfile, UserRole,
    ports::{
        AuthorizedApplication, AuthorizedApplicationRepositoryPort, GrantSummaryRepositoryPort,
        ProfileRepositoryPort, ProfileUpdate, RepositoryError, RepositoryFuture,
        SessionAccountPort, SessionStorePort,
    },
    session::{SessionRecord, SessionRotationOutcome, SessionSnapshot, SessionVersion},
};
use serde_json::json;
use uuid::Uuid;

use super::ServerProfileAccountOperations;

#[derive(Clone)]
struct FixedSessionStore {
    load: Result<Option<SessionSnapshot>, RepositoryError>,
}

impl SessionStorePort for FixedSessionStore {
    fn load<'a>(
        &'a self,
        _session_id: &'a SessionId,
    ) -> RepositoryFuture<'a, Option<SessionSnapshot>> {
        let load = self.load.clone();
        Box::pin(async move { load })
    }

    fn delete<'a>(&'a self, _session_id: &'a SessionId) -> RepositoryFuture<'a, bool> {
        Box::pin(async { Ok(true) })
    }

    fn rotate<'a>(
        &'a self,
        _old_session_id: &'a SessionId,
        _expected: &'a SessionSnapshot,
        _new_session_id: &'a SessionId,
        _replacement: &'a SessionRecord,
        _ttl_seconds: u64,
    ) -> RepositoryFuture<'a, SessionRotationOutcome> {
        Box::pin(async { Ok(SessionRotationOutcome::Applied) })
    }
}

#[derive(Clone)]
struct FixedSessionAccounts(Option<PublicAccount>);

impl SessionAccountPort for FixedSessionAccounts {
    fn public_account_by_id(
        &self,
        _tenant_id: TenantId,
        _user_id: UserId,
    ) -> RepositoryFuture<'_, Option<PublicAccount>> {
        let account = self.0.clone();
        Box::pin(async move { Ok(account) })
    }
}

#[derive(Clone)]
struct StoredProfile(PublicAccount);

impl ProfileRepositoryPort for StoredProfile {
    fn update_profile<'a>(
        &'a self,
        _tenant_id: TenantId,
        _user_id: UserId,
        update: ProfileUpdate,
    ) -> RepositoryFuture<'a, PublicAccount> {
        let mut account = self.0.clone();
        account.profile = update.profile;
        Box::pin(async move { Ok(account) })
    }
}

#[derive(Clone, Copy)]
struct FixedGrantSummary(i64);

impl GrantSummaryRepositoryPort for FixedGrantSummary {
    fn authorized_client_count(&self, _user_id: Uuid) -> RepositoryFuture<'_, i64> {
        let count = self.0;
        Box::pin(async move { Ok(count) })
    }
}

#[derive(Clone)]
struct FixedApplications(Vec<AuthorizedApplication>);

impl AuthorizedApplicationRepositoryPort for FixedApplications {
    fn applications_for_user(
        &self,
        _user_id: Uuid,
    ) -> RepositoryFuture<'_, Vec<AuthorizedApplication>> {
        let applications = self.0.clone();
        Box::pin(async move { Ok(applications) })
    }
}

type Operations =
    ServerProfileAccountOperations<StoredProfile, FixedGrantSummary, FixedApplications>;

fn account() -> PublicAccount {
    let now = Utc::now();
    PublicAccount {
        principal: Principal {
            user_id: UserId::new(Uuid::from_u128(10)).unwrap(),
            tenant: TenantContext::default_system(),
            role: UserRole::User,
            active: true,
        },
        account: AccountIdentity {
            username: "alice".to_owned(),
            email: "alice@example.test".to_owned(),
            email_verified: true,
            mfa_enabled: true,
        },
        profile: UserProfile {
            display_name: Some("Alice".to_owned()),
            phone_number: Some("+15550000001".to_owned()),
            phone_number_verified: true,
            ..UserProfile::default()
        },
        created_at: now,
        updated_at: now,
    }
}

fn snapshot(pending_mfa: bool) -> SessionSnapshot {
    SessionSnapshot::new(
        SessionRecord::new(
            account().user_id(),
            Utc::now().timestamp(),
            vec!["pwd".to_owned()],
            pending_mfa,
            Some("oidc-session".to_owned()),
        ),
        SessionVersion::from_storage(b"version-1".to_vec().into_boxed_slice()),
    )
}

fn operations(
    load: Result<Option<SessionSnapshot>, RepositoryError>,
    applications: Vec<AuthorizedApplication>,
) -> Operations {
    let account = account();
    ServerProfileAccountOperations::new(
        SessionService::new(
            Arc::new(FixedSessionStore { load }),
            Arc::new(FixedSessionAccounts(Some(account.clone()))),
            account.tenant().tenant_id,
        ),
        AccountProfileService::new(
            StoredProfile(account),
            FixedGrantSummary(2),
            FixedApplications(applications),
        ),
    )
}

#[tokio::test]
async fn active_and_pending_sessions_expose_their_distinct_profile_shapes() {
    let active = operations(Ok(Some(snapshot(false))), Vec::new())
        .me(SessionId::new("active"))
        .await
        .unwrap();
    let ProfileMe::Active(active) = active else {
        panic!("active session must produce the full profile")
    };
    assert_eq!(active.email, "alice@example.test");
    assert_eq!(active.display_name.as_deref(), Some("Alice"));
    assert_eq!(active.authorized_app_count, 2);

    let pending = operations(Ok(Some(snapshot(true))), Vec::new())
        .me(SessionId::new("pending"))
        .await
        .unwrap();
    let ProfileMe::PendingMfa(pending) = pending else {
        panic!("pending MFA session must produce the reduced profile")
    };
    assert_eq!(pending.email, "alice@example.test");
    assert_eq!(pending.id, account().id());
}

#[tokio::test]
async fn missing_and_unavailable_sessions_remain_distinct_errors() {
    let missing = operations(Ok(None), Vec::new())
        .me(SessionId::new("missing"))
        .await;
    assert_eq!(missing, Err(ProfileAccountError::LoginRequired));

    let unavailable = operations(Err(RepositoryError::Unavailable), Vec::new())
        .me(SessionId::new("unavailable"))
        .await;
    assert_eq!(
        unavailable,
        Err(ProfileAccountError::SessionLookupUnavailable)
    );
}

#[tokio::test]
async fn update_validation_and_application_projection_stay_in_focused_services() {
    let application = AuthorizedApplication {
        client_id: "client-1".to_owned(),
        client_name: "Example Client".to_owned(),
        last_scopes: json!(["openid", 42, null, "profile"]),
        last_authorized_at: Utc.timestamp_opt(1_700_000_000, 0).unwrap(),
        authorization_count: 3,
    };
    let operations = operations(Ok(Some(snapshot(false))), vec![application]);

    let update = operations
        .update(
            SessionId::new("active"),
            ProfilePatch {
                profile_url: Some("javascript:alert(1)".to_owned()),
                ..ProfilePatch::default()
            },
        )
        .await;
    assert_eq!(
        update,
        Err(ProfileAccountError::Validation(
            nazo_identity::ProfileValidationError::InvalidHttpUrl("profile_url")
        ))
    );

    let applications = operations
        .applications(SessionId::new("active"))
        .await
        .unwrap();
    assert_eq!(applications.total, 1);
    assert_eq!(applications.items[0].last_scopes, vec!["openid", "profile"]);
    assert_eq!(applications.items[0].authorization_count, 3);
}
