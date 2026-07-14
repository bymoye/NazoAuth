use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    LoginSuccess, PublicAccount, TenantContext,
    ports::{
        FederationAuditPort, FederationLogin, FederationLoginRepositoryPort,
        FederationPasswordHasherPort, FederationStatePort, LoginSessionCreate, LoginSessionPort,
        NewFederatedIdentity, RepositoryError,
    },
    session::SessionRecord,
};

#[must_use]
pub fn normalize_federation_token(value: &str) -> Option<String> {
    let value = value.trim();
    (value.len() >= 32
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'))
    .then_some(value.to_owned())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OidcFederationState {
    /// Absent only on callback state written by a pre-binding server during a rolling deploy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_id: Option<String>,
    pub nonce: String,
    pub pkce_verifier: String,
    pub created_at: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SocialFederationState {
    pub provider_id: String,
    pub pkce_verifier: String,
    pub created_at: i64,
}

#[derive(Clone, Debug)]
pub struct OidcFederationStart {
    pub state: String,
    pub nonce: String,
    pub pkce_verifier: String,
}

#[derive(Clone, Debug)]
pub struct SocialFederationStart {
    pub state: String,
    pub pkce_verifier: String,
}

#[derive(Clone, Debug)]
pub struct VerifiedExternalIdentity {
    pub provider_type: String,
    pub provider_id: String,
    pub subject: String,
    pub email: Option<String>,
    pub display_name: Option<String>,
    pub claims: Value,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FederationAuditEvent {
    RelinkDenied {
        provider_type: String,
        provider_id: String,
        email: String,
    },
    IdentityLinked {
        user_id: crate::UserId,
        provider_type: String,
        provider_id: String,
    },
    LoginSuccess {
        user_id: crate::UserId,
        method: String,
        source_ip: String,
    },
    ProviderMismatchRejected {
        expected_provider_id: String,
        actual_provider_id: String,
    },
    SamlReplayRejected,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FederationError {
    InvalidState,
    StateExpired,
    State(RepositoryError),
    ProviderMismatch,
    VerifiedEmailRequired,
    LoginFailed,
    InactiveExistingLink,
    Account(RepositoryError),
    Password(RepositoryError),
    Session(RepositoryError),
    SessionCollision,
    SamlReplay,
}

#[derive(Clone, Copy, Debug)]
pub struct FederationServiceConfig {
    pub tenant: TenantContext,
    pub state_ttl_seconds: u64,
    pub saml_replay_ttl_seconds: u64,
    pub session_ttl_seconds: u64,
}

pub struct FederationService<R, T, H, S, A> {
    accounts: R,
    states: T,
    password_hasher: H,
    sessions: S,
    audit: A,
    config: FederationServiceConfig,
}

impl<R, T, H, S, A> FederationService<R, T, H, S, A>
where
    R: FederationLoginRepositoryPort,
    T: FederationStatePort,
    H: FederationPasswordHasherPort,
    S: LoginSessionPort,
    A: FederationAuditPort,
{
    pub fn new(
        accounts: R,
        states: T,
        password_hasher: H,
        sessions: S,
        audit: A,
        config: FederationServiceConfig,
    ) -> Self {
        Self {
            accounts,
            states,
            password_hasher,
            sessions,
            audit,
            config,
        }
    }

    pub async fn start_oidc(
        &self,
        provider_id: String,
        now: DateTime<Utc>,
    ) -> Result<OidcFederationStart, FederationError> {
        let start = OidcFederationStart {
            state: random_urlsafe_token(),
            nonce: random_urlsafe_token(),
            pkce_verifier: random_urlsafe_token(),
        };
        self.states
            .store_oidc(
                &start.state,
                &OidcFederationState {
                    provider_id: Some(provider_id),
                    nonce: start.nonce.clone(),
                    pkce_verifier: start.pkce_verifier.clone(),
                    created_at: now.timestamp(),
                },
                self.config.state_ttl_seconds,
            )
            .await
            .map_err(FederationError::State)?;
        Ok(start)
    }

    pub async fn consume_oidc(
        &self,
        state: &str,
        expected_provider_id: &str,
        now: DateTime<Utc>,
    ) -> Result<OidcFederationState, FederationError> {
        let state = normalize_federation_token(state).ok_or(FederationError::InvalidState)?;
        let stored = self
            .states
            .take_oidc(&state)
            .await
            .map_err(ceremony_error)?
            .ok_or(FederationError::StateExpired)?;
        if let Some(actual_provider_id) = &stored.provider_id
            && actual_provider_id != expected_provider_id
        {
            self.audit
                .record(FederationAuditEvent::ProviderMismatchRejected {
                    expected_provider_id: expected_provider_id.to_owned(),
                    actual_provider_id: actual_provider_id.clone(),
                });
            return Err(FederationError::ProviderMismatch);
        }
        self.ensure_fresh(stored.created_at, now)?;
        Ok(stored)
    }

    pub async fn start_social(
        &self,
        provider_id: String,
        now: DateTime<Utc>,
    ) -> Result<SocialFederationStart, FederationError> {
        let start = SocialFederationStart {
            state: random_urlsafe_token(),
            pkce_verifier: random_urlsafe_token(),
        };
        self.states
            .store_social(
                &start.state,
                &SocialFederationState {
                    provider_id,
                    pkce_verifier: start.pkce_verifier.clone(),
                    created_at: now.timestamp(),
                },
                self.config.state_ttl_seconds,
            )
            .await
            .map_err(FederationError::State)?;
        Ok(start)
    }

    pub async fn consume_social(
        &self,
        state: &str,
        expected_provider_id: &str,
        now: DateTime<Utc>,
    ) -> Result<SocialFederationState, FederationError> {
        let state = normalize_federation_token(state).ok_or(FederationError::InvalidState)?;
        let stored = self
            .states
            .take_social(&state)
            .await
            .map_err(ceremony_error)?
            .ok_or(FederationError::StateExpired)?;
        if stored.provider_id != expected_provider_id {
            self.audit
                .record(FederationAuditEvent::ProviderMismatchRejected {
                    expected_provider_id: expected_provider_id.to_owned(),
                    actual_provider_id: stored.provider_id,
                });
            return Err(FederationError::ProviderMismatch);
        }
        self.ensure_fresh(stored.created_at, now)?;
        Ok(stored)
    }

    pub async fn consume_saml_assertion(
        &self,
        signature: &str,
        expires_at: i64,
        now: DateTime<Utc>,
    ) -> Result<(), FederationError> {
        let ttl = expires_at
            .saturating_sub(now.timestamp())
            .clamp(1, self.config.saml_replay_ttl_seconds as i64) as u64;
        if self
            .states
            .reserve_saml_replay(signature, ttl)
            .await
            .map_err(FederationError::State)?
        {
            Ok(())
        } else {
            self.audit.record(FederationAuditEvent::SamlReplayRejected);
            Err(FederationError::SamlReplay)
        }
    }

    pub async fn complete_verified(
        &self,
        identity: VerifiedExternalIdentity,
        method: String,
        source_ip: String,
    ) -> Result<LoginSuccess, FederationError> {
        let account = self.resolve(identity, false).await?;
        self.create_session(account, method, source_ip).await
    }

    pub async fn complete_existing_only(
        &self,
        identity: VerifiedExternalIdentity,
        method: String,
        source_ip: String,
    ) -> Result<LoginSuccess, FederationError> {
        let account = self.resolve(identity, true).await?;
        if !account.principal.active {
            return Err(FederationError::InactiveExistingLink);
        }
        self.create_session(account, method, source_ip).await
    }

    async fn resolve(
        &self,
        identity: VerifiedExternalIdentity,
        existing_only: bool,
    ) -> Result<PublicAccount, FederationError> {
        if identity.provider_type.is_empty()
            || identity.provider_type.len() > 64
            || identity.provider_id.trim().is_empty()
            || identity.subject.trim().is_empty()
            || identity.subject.len() > 1024
            || identity
                .email
                .as_ref()
                .is_some_and(|email| email.len() > 320 || email.trim() != email)
        {
            return Err(FederationError::LoginFailed);
        }
        let login = FederationLogin {
            tenant: self.config.tenant,
            provider_type: identity.provider_type.clone(),
            provider_id: identity.provider_id.clone(),
            subject: identity.subject.clone(),
            email: identity.email.clone(),
            claims: identity.claims.clone(),
        };
        if let Some(account) = self
            .accounts
            .resolve_existing(login.clone())
            .await
            .map_err(FederationError::Account)?
        {
            if !existing_only && !account.principal.active {
                return Err(FederationError::LoginFailed);
            }
            return Ok(account);
        }
        if existing_only {
            return Err(FederationError::VerifiedEmailRequired);
        }
        let email = identity
            .email
            .clone()
            .ok_or(FederationError::VerifiedEmailRequired)?;
        if self
            .accounts
            .account_by_email(self.config.tenant.tenant_id, &email)
            .await
            .map_err(FederationError::Account)?
            .is_some()
        {
            self.audit.record(FederationAuditEvent::RelinkDenied {
                provider_type: identity.provider_type,
                provider_id: identity.provider_id,
                email,
            });
            return Err(FederationError::LoginFailed);
        }
        let password_hash = self
            .password_hasher
            .hash_bootstrap_secret()
            .await
            .map_err(FederationError::Password)?;
        let account = self
            .accounts
            .create_federated(NewFederatedIdentity {
                login,
                email,
                display_name: identity.display_name,
                password_hash,
            })
            .await
            .map_err(FederationError::Account)?;
        self.audit.record(FederationAuditEvent::IdentityLinked {
            user_id: account.user_id(),
            provider_type: identity.provider_type,
            provider_id: identity.provider_id,
        });
        Ok(account)
    }

    async fn create_session(
        &self,
        account: PublicAccount,
        method: String,
        source_ip: String,
    ) -> Result<LoginSuccess, FederationError> {
        let now = Utc::now();
        let session = SessionRecord::new(
            account.user_id(),
            now.timestamp(),
            vec![method.clone(), "federated".to_owned()],
            false,
            Some(random_urlsafe_token()),
        );
        let session_id = random_urlsafe_token();
        let csrf_token = random_urlsafe_token();
        match self
            .sessions
            .create(&session_id, &session, self.config.session_ttl_seconds)
            .await
            .map_err(FederationError::Session)?
        {
            LoginSessionCreate::Created => {}
            LoginSessionCreate::Collision => return Err(FederationError::SessionCollision),
        }
        self.audit.record(FederationAuditEvent::LoginSuccess {
            user_id: account.user_id(),
            method,
            source_ip,
        });
        Ok(LoginSuccess {
            session_id,
            csrf_token,
            session,
        })
    }

    fn ensure_fresh(&self, created_at: i64, now: DateTime<Utc>) -> Result<(), FederationError> {
        if now.timestamp().saturating_sub(created_at) > self.config.state_ttl_seconds as i64 {
            Err(FederationError::StateExpired)
        } else {
            Ok(())
        }
    }
}

fn random_urlsafe_token() -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>())
}

fn ceremony_error(error: RepositoryError) -> FederationError {
    match error {
        RepositoryError::Consistency(_) => FederationError::StateExpired,
        error => FederationError::State(error),
    }
}
