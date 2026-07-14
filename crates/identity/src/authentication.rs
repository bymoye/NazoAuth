use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};

use crate::{
    PasswordHash, TenantId,
    ports::{
        AuthenticationAuditEvent, AuthenticationAuditPort, LoginAccountRepositoryPort,
        LoginSessionCreate, LoginSessionPort, LoginThrottlePort, RememberedMfaDevicePort,
        RepositoryError, SecretVerifyError, SecretVerifyPort,
    },
    session::SessionRecord,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticationServiceConfig {
    pub tenant_id: TenantId,
    pub dummy_password_hash: PasswordHash,
    pub failure_window_seconds: u64,
    pub failure_email_max_attempts: u64,
    pub failure_ip_email_max_attempts: u64,
    pub session_ttl_seconds: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RememberedMfaProof {
    pub token_hash: String,
    pub user_agent_hash: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatePasswordInput {
    pub email: String,
    pub password: String,
    pub source_ip: String,
    pub remembered_mfa: Option<RememberedMfaProof>,
    pub previous_session_id: Option<String>,
    pub now: DateTime<Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoginSuccess {
    pub session_id: String,
    pub csrf_token: String,
    pub session: SessionRecord,
}

/// Minimal password-login projection exposed to the HTTP transport.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PasswordLoginResult {
    pub session_id: String,
    pub csrf_token: String,
    pub mfa_required: bool,
}

impl From<LoginSuccess> for PasswordLoginResult {
    fn from(success: LoginSuccess) -> Self {
        Self {
            session_id: success.session_id,
            csrf_token: success.csrf_token,
            mfa_required: success.session.pending_mfa(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthenticatePasswordError {
    ThrottleUnavailable(RepositoryError),
    Throttled { retry_after_seconds: u64 },
    AccountLookup(RepositoryError),
    SecretBusy,
    SecretUnavailable,
    FailureRecord(RepositoryError),
    InvalidCredentials,
    InactiveAccount,
    RememberedMfa(RepositoryError),
    Session(RepositoryError),
    SessionCollision,
}

#[derive(Clone)]
pub struct AuthenticationService<A, T, V, M, S, U> {
    accounts: A,
    throttles: T,
    verifier: V,
    remembered_mfa: M,
    sessions: S,
    audit: U,
    config: AuthenticationServiceConfig,
}

impl<A, T, V, M, S, U> AuthenticationService<A, T, V, M, S, U>
where
    A: LoginAccountRepositoryPort,
    T: LoginThrottlePort,
    V: SecretVerifyPort,
    M: RememberedMfaDevicePort,
    S: LoginSessionPort,
    U: AuthenticationAuditPort,
{
    pub fn new(
        accounts: A,
        throttles: T,
        verifier: V,
        remembered_mfa: M,
        sessions: S,
        audit: U,
        config: AuthenticationServiceConfig,
    ) -> Self {
        Self {
            accounts,
            throttles,
            verifier,
            remembered_mfa,
            sessions,
            audit,
            config,
        }
    }

    pub async fn authenticate_password(
        &self,
        input: AuthenticatePasswordInput,
    ) -> Result<LoginSuccess, AuthenticatePasswordError> {
        let counts = self
            .throttles
            .failure_counts(&input.email, &input.source_ip)
            .await
            .map_err(AuthenticatePasswordError::ThrottleUnavailable)?;
        if counts.email >= self.config.failure_email_max_attempts
            || counts.ip_email >= self.config.failure_ip_email_max_attempts
        {
            return Err(AuthenticatePasswordError::Throttled {
                retry_after_seconds: self.config.failure_window_seconds,
            });
        }

        let authentication = self
            .accounts
            .authentication_by_email(self.config.tenant_id, &input.email)
            .await
            .map_err(AuthenticatePasswordError::AccountLookup)?;
        let authenticatable = authentication
            .as_ref()
            .is_some_and(|identity| identity.principal.active);
        let password_hash = authentication
            .as_ref()
            .filter(|_| authenticatable)
            .map(|identity| identity.login.password_hash.clone())
            .unwrap_or_else(|| self.config.dummy_password_hash.clone());
        let password_valid = self
            .verifier
            .verify_secret(input.password, password_hash)
            .await
            .map_err(|error| match error {
                SecretVerifyError::Busy => AuthenticatePasswordError::SecretBusy,
                SecretVerifyError::Failed => AuthenticatePasswordError::SecretUnavailable,
            })?;
        if !authenticatable || !password_valid {
            self.throttles
                .record_failure(
                    &input.email,
                    &input.source_ip,
                    self.config.failure_window_seconds,
                )
                .await
                .map_err(AuthenticatePasswordError::FailureRecord)?;
            self.audit.record(AuthenticationAuditEvent::Failure {
                email: input.email,
                source_ip: input.source_ip,
                user_id: authentication.as_ref().map(|value| value.principal.user_id),
            });
            return Err(AuthenticatePasswordError::InvalidCredentials);
        }
        let authenticated = authentication.expect("active authenticated identity must exist");
        let account = self
            .accounts
            .public_account_by_id(
                authenticated.principal.tenant.tenant_id,
                authenticated.principal.user_id,
            )
            .await
            .map_err(AuthenticatePasswordError::AccountLookup)?
            .ok_or(AuthenticatePasswordError::InvalidCredentials)?;
        let _ = self
            .throttles
            .clear_failures(&input.email, &input.source_ip)
            .await;
        if !account.principal.active {
            return Err(AuthenticatePasswordError::InactiveAccount);
        }

        let remembered_mfa = if account.account.mfa_enabled {
            if let Some(proof) = input.remembered_mfa.as_ref() {
                self.remembered_mfa
                    .is_valid(
                        &account,
                        &proof.token_hash,
                        proof.user_agent_hash.as_deref(),
                        input.now,
                    )
                    .await
                    .map_err(AuthenticatePasswordError::RememberedMfa)?
            } else {
                false
            }
        } else {
            false
        };
        let mut amr = vec!["password".to_owned()];
        if remembered_mfa {
            amr.push("remembered_mfa".to_owned());
            amr.push("mfa".to_owned());
        }
        let session = SessionRecord::new(
            account.user_id(),
            input.now.timestamp(),
            amr,
            account.account.mfa_enabled && !remembered_mfa,
            Some(random_urlsafe_token()),
        );
        let session_id = random_urlsafe_token();
        let csrf_token = random_urlsafe_token();
        match self
            .sessions
            .create_replacing(
                input.previous_session_id.as_deref(),
                &session_id,
                &session,
                self.config.session_ttl_seconds,
            )
            .await
            .map_err(AuthenticatePasswordError::Session)?
        {
            LoginSessionCreate::Created => {}
            LoginSessionCreate::Collision => {
                return Err(AuthenticatePasswordError::SessionCollision);
            }
        }
        self.audit.record(AuthenticationAuditEvent::Success {
            user_id: account.user_id(),
            source_ip: input.source_ip,
            amr: session.amr().to_vec(),
        });
        Ok(LoginSuccess {
            session_id,
            csrf_token,
            session,
        })
    }
}

fn random_urlsafe_token() -> String {
    let bytes: [u8; 32] = rand::random();
    URL_SAFE_NO_PAD.encode(bytes)
}
