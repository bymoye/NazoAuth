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
        LoginFailureCounts, LoginSessionCreate, LoginSessionPort, LoginThrottlePort,
        RememberedMfaDevicePort, RepositoryFuture, SecretVerifyFuture, SecretVerifyPort,
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
    fn failure_counts<'a>(
        &'a self,
        _email: &'a str,
        _source_ip: &'a str,
    ) -> RepositoryFuture<'a, LoginFailureCounts> {
        Box::pin(async {
            Ok(LoginFailureCounts {
                email: 0,
                ip_email: 0,
            })
        })
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

    fn clear_failures<'a>(
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
                failure_email_max_attempts: 5,
                failure_ip_email_max_attempts: 5,
                session_ttl_seconds: 300,
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
