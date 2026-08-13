use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

use chrono::Utc;
use nazo_identity::{
    AccountIdentity, AuthenticatePasswordError, AuthenticatePasswordInput, AuthenticationIdentity,
    AuthenticationService, AuthenticationServiceConfig, LoginIdentity, PasswordHash, Principal,
    PublicAccount, TenantContext, TenantId, UserId, UserRole,
    ports::{
        AuthenticationAuditEvent, AuthenticationAuditPort, LoginAccountRepositoryPort,
        LoginSessionCreate, LoginSessionPort, LoginThrottlePort, RememberedMfaDevicePort,
        RepositoryFuture, SecretVerifyFuture, SecretVerifyPort,
    },
    session::SessionRecord,
};
use uuid::Uuid;

#[derive(Clone)]
struct Accounts(Option<AuthenticationIdentity>);

impl LoginAccountRepositoryPort for Accounts {
    fn authentication_by_email<'a>(
        &'a self,
        _tenant_id: TenantId,
        _email: &'a str,
    ) -> RepositoryFuture<'a, Option<AuthenticationIdentity>> {
        let identity = self.0.clone();
        Box::pin(async move { Ok(identity) })
    }

    fn public_account_by_id(
        &self,
        _tenant_id: TenantId,
        _user_id: UserId,
    ) -> RepositoryFuture<'_, Option<PublicAccount>> {
        Box::pin(async { panic!("non-authenticatable accounts must not load a public account") })
    }
}

#[derive(Clone, Default)]
struct Throttles(Arc<AtomicUsize>);

impl LoginThrottlePort for Throttles {
    fn failure_count<'a>(
        &'a self,
        _email: &'a str,
        _source_ip: &'a str,
    ) -> RepositoryFuture<'a, u64> {
        Box::pin(async { Ok(0) })
    }

    fn record_failure<'a>(
        &'a self,
        _email: &'a str,
        _source_ip: &'a str,
        _window_seconds: u64,
    ) -> RepositoryFuture<'a, ()> {
        self.0.fetch_add(1, Ordering::Relaxed);
        Box::pin(async { Ok(()) })
    }

    fn clear_failure<'a>(
        &'a self,
        _email: &'a str,
        _source_ip: &'a str,
    ) -> RepositoryFuture<'a, ()> {
        Box::pin(async { Ok(()) })
    }
}

#[derive(Clone)]
struct Verifier(Arc<Mutex<Vec<PasswordHash>>>);

impl SecretVerifyPort for Verifier {
    fn verify_secret(
        &self,
        _secret: String,
        password_hash: PasswordHash,
    ) -> SecretVerifyFuture<'_> {
        self.0.lock().unwrap().push(password_hash);
        Box::pin(async { Ok(false) })
    }
}

#[derive(Clone, Copy)]
struct RememberedMfa;

impl RememberedMfaDevicePort for RememberedMfa {
    fn is_valid<'a>(
        &'a self,
        _account: &'a PublicAccount,
        _token_hash: &'a str,
        _user_agent_hash: Option<&'a str>,
        _now: chrono::DateTime<Utc>,
    ) -> RepositoryFuture<'a, bool> {
        Box::pin(async { Ok(false) })
    }
}

#[derive(Clone, Copy)]
struct Sessions;

impl LoginSessionPort for Sessions {
    fn create<'a>(
        &'a self,
        _session_id: &'a str,
        _record: &'a SessionRecord,
        _ttl_seconds: u64,
    ) -> RepositoryFuture<'a, LoginSessionCreate> {
        panic!("invalid credentials must not create a session")
    }

    fn create_replacing<'a>(
        &'a self,
        _previous_session_id: Option<&'a str>,
        _session_id: &'a str,
        _record: &'a SessionRecord,
        _ttl_seconds: u64,
    ) -> RepositoryFuture<'a, LoginSessionCreate> {
        panic!("invalid credentials must not replace a session")
    }
}

#[derive(Clone, Default)]
struct RecordingSessions(Arc<Mutex<Vec<u64>>>);

impl LoginSessionPort for RecordingSessions {
    fn create<'a>(
        &'a self,
        _session_id: &'a str,
        _record: &'a SessionRecord,
        ttl_seconds: u64,
    ) -> RepositoryFuture<'a, LoginSessionCreate> {
        self.0.lock().unwrap().push(ttl_seconds);
        Box::pin(async { Ok(LoginSessionCreate::Created) })
    }

    fn create_replacing<'a>(
        &'a self,
        _previous_session_id: Option<&'a str>,
        _session_id: &'a str,
        _record: &'a SessionRecord,
        ttl_seconds: u64,
    ) -> RepositoryFuture<'a, LoginSessionCreate> {
        self.0.lock().unwrap().push(ttl_seconds);
        Box::pin(async { Ok(LoginSessionCreate::Created) })
    }
}

#[derive(Clone, Copy)]
struct AlwaysValidVerifier;

impl SecretVerifyPort for AlwaysValidVerifier {
    fn verify_secret(
        &self,
        _secret: String,
        _password_hash: PasswordHash,
    ) -> SecretVerifyFuture<'_> {
        Box::pin(async { Ok(true) })
    }
}

#[derive(Clone)]
struct ActiveAccounts {
    authentication: AuthenticationIdentity,
    public: PublicAccount,
}

impl LoginAccountRepositoryPort for ActiveAccounts {
    fn authentication_by_email<'a>(
        &'a self,
        _tenant_id: TenantId,
        _email: &'a str,
    ) -> RepositoryFuture<'a, Option<AuthenticationIdentity>> {
        let authentication = self.authentication.clone();
        Box::pin(async move { Ok(Some(authentication)) })
    }

    fn public_account_by_id(
        &self,
        _tenant_id: TenantId,
        _user_id: UserId,
    ) -> RepositoryFuture<'_, Option<PublicAccount>> {
        let public = self.public.clone();
        Box::pin(async move { Ok(Some(public)) })
    }
}

#[derive(Clone, Default)]
struct Audit(Arc<Mutex<Vec<AuthenticationAuditEvent>>>);

impl AuthenticationAuditPort for Audit {
    fn record(&self, event: AuthenticationAuditEvent) {
        self.0.lock().unwrap().push(event);
    }
}

fn inactive_identity() -> AuthenticationIdentity {
    AuthenticationIdentity {
        principal: Principal {
            user_id: UserId::new(Uuid::now_v7()).unwrap(),
            tenant: TenantContext::default_system(),
            role: UserRole::User,
            active: false,
        },
        login: LoginIdentity {
            account: AccountIdentity {
                username: "inactive".to_owned(),
                email: "inactive@example.com".to_owned(),
                email_verified: true,
                mfa_enabled: false,
            },
            password_hash: PasswordHash::new("persisted-password-hash").unwrap(),
        },
    }
}

fn active_mfa_identity() -> AuthenticationIdentity {
    AuthenticationIdentity {
        principal: Principal {
            user_id: UserId::new(Uuid::now_v7()).unwrap(),
            tenant: TenantContext::default_system(),
            role: UserRole::User,
            active: true,
        },
        login: LoginIdentity {
            account: AccountIdentity {
                username: "active".to_owned(),
                email: "active@example.com".to_owned(),
                email_verified: true,
                mfa_enabled: true,
            },
            password_hash: PasswordHash::new("persisted-password-hash").unwrap(),
        },
    }
}

#[tokio::test]
async fn missing_and_inactive_accounts_share_dummy_verification_and_failure_behavior() {
    for authentication in [None, Some(inactive_identity())] {
        let dummy_hash = PasswordHash::new("dummy-password-hash").unwrap();
        let verified_hashes = Arc::new(Mutex::new(Vec::new()));
        let throttles = Throttles::default();
        let audit = Audit::default();
        let service = AuthenticationService::new(
            Accounts(authentication.clone()),
            throttles.clone(),
            Verifier(verified_hashes.clone()),
            RememberedMfa,
            Sessions,
            audit.clone(),
            AuthenticationServiceConfig {
                tenant_id: TenantContext::default_system().tenant_id,
                dummy_password_hash: dummy_hash.clone(),
                failure_window_seconds: 60,
                failure_ip_email_max_attempts: 5,
                session_ttl_seconds: 300,
                pending_mfa_session_ttl_seconds: 120,
            },
        );

        let result = service
            .authenticate_password(AuthenticatePasswordInput {
                email: "account@example.com".to_owned(),
                password: "candidate".to_owned(),
                source_ip: "192.0.2.1".to_owned(),
                remembered_mfa: None,
                previous_session_id: Some("old-session".to_owned()),
                now: Utc::now(),
            })
            .await;

        assert_eq!(result, Err(AuthenticatePasswordError::InvalidCredentials));
        assert_eq!(*verified_hashes.lock().unwrap(), vec![dummy_hash]);
        assert_eq!(throttles.0.load(Ordering::Relaxed), 1);
        let events = audit.0.lock().unwrap();
        assert_eq!(events.len(), 1);
        assert!(matches!(
            &events[0],
            AuthenticationAuditEvent::Failure { user_id, .. }
                if *user_id == authentication.as_ref().map(|identity| identity.principal.user_id)
        ));
    }
}

#[tokio::test]
async fn pending_mfa_login_uses_a_short_session_ttl() {
    let authentication = active_mfa_identity();
    let public = PublicAccount {
        principal: authentication.principal.clone(),
        account: authentication.login.account.clone(),
        profile: Default::default(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    let sessions = RecordingSessions::default();
    let service = AuthenticationService::new(
        ActiveAccounts {
            authentication,
            public,
        },
        Throttles::default(),
        AlwaysValidVerifier,
        RememberedMfa,
        sessions.clone(),
        Audit::default(),
        AuthenticationServiceConfig {
            tenant_id: TenantContext::default_system().tenant_id,
            dummy_password_hash: PasswordHash::new("dummy-password-hash").unwrap(),
            failure_window_seconds: 60,
            failure_ip_email_max_attempts: 5,
            session_ttl_seconds: 300,
            pending_mfa_session_ttl_seconds: 120,
        },
    );

    let result = service
        .authenticate_password(AuthenticatePasswordInput {
            email: "active@example.com".to_owned(),
            password: "candidate".to_owned(),
            source_ip: "192.0.2.1".to_owned(),
            remembered_mfa: None,
            previous_session_id: None,
            now: Utc::now(),
        })
        .await
        .unwrap();

    assert!(result.session.pending_mfa());
    assert_eq!(*sessions.0.lock().unwrap(), vec![120]);
}
