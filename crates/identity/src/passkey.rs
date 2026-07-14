use std::{error::Error, fmt};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use passkey_auth::{
    AuthenticationChallenge, AuthenticationResponse, AuthenticationState, CosePublicKey,
    PasskeyCredential as WebauthnCredential, RegistrationChallenge, RegistrationResponse,
    RegistrationState, Webauthn,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    LoginSuccess, PublicAccount, TenantId, UserId,
    ports::{
        LoginSessionCreate, LoginSessionPort, PasskeyAccountRepositoryPort, PasskeyAuditPort,
        PasskeyCeremonyPort, PasskeyCredential, PasskeyRepositoryPort, RememberedMfaDevicePort,
        RepositoryError,
    },
    session::SessionRecord,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PasskeyPolicyError {
    LabelTooLong,
    InvalidCeremonyId,
    InvalidCredentialId,
}

impl fmt::Display for PasskeyPolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::LabelTooLong => "passkey label is too long",
            Self::InvalidCeremonyId => "invalid ceremony ID",
            Self::InvalidCredentialId => "invalid passkey credential ID",
        })
    }
}

impl Error for PasskeyPolicyError {}

#[must_use]
pub fn passkey_user_handle(tenant_id: TenantId, user_id: UserId) -> Vec<u8> {
    let mut handle = Vec::with_capacity(32);
    handle.extend_from_slice(tenant_id.as_uuid().as_bytes());
    handle.extend_from_slice(user_id.as_uuid().as_bytes());
    handle
}

pub fn normalize_passkey_label(value: Option<&str>) -> Result<String, PasskeyPolicyError> {
    let label = value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("Passkey");
    if label.len() > 120 {
        return Err(PasskeyPolicyError::LabelTooLong);
    }
    Ok(label.to_owned())
}

pub fn normalize_ceremony_id(value: &str) -> Result<String, PasskeyPolicyError> {
    let value = value.trim();
    if value.len() < 32
        || value.len() > 256
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(PasskeyPolicyError::InvalidCeremonyId);
    }
    Ok(value.to_owned())
}

pub fn credential_id_from_response(id: &str) -> Result<Vec<u8>, PasskeyPolicyError> {
    URL_SAFE_NO_PAD
        .decode(id)
        .map_err(|_| PasskeyPolicyError::InvalidCredentialId)
}

#[derive(Clone, Debug)]
pub struct PasskeyServiceConfig {
    pub tenant_id: TenantId,
    pub rp_id: String,
    pub rp_name: String,
    pub origin: String,
    pub require_user_verification: bool,
    pub require_user_handle: bool,
    pub strict_base64: bool,
    pub ceremony_ttl_seconds: u64,
    pub session_ttl_seconds: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredPasskeyRegistration {
    pub user_id: UserId,
    pub tenant_id: TenantId,
    pub label: String,
    pub state: RegistrationState,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredPasskeyAuthentication {
    pub user_id: UserId,
    pub tenant_id: TenantId,
    pub state: AuthenticationState,
    #[serde(default)]
    pub dummy: bool,
}

#[derive(Debug)]
pub struct PasskeyLoginBegin {
    pub ceremony_id: String,
    pub challenge: AuthenticationChallenge,
}

#[derive(Debug)]
pub struct PasskeyRegistrationBegin {
    pub ceremony_id: String,
    pub challenge: RegistrationChallenge,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PasskeyAuditEvent {
    LoginFailureEmail {
        email: String,
        reason: PasskeyAuditReason,
    },
    LoginFailureUser {
        user_id: UserId,
        reason: PasskeyAuditReason,
    },
    LoginSuccess {
        user_id: UserId,
        source_ip: String,
    },
    RegistrationRejected {
        user_id: UserId,
        reason: PasskeyAuditReason,
    },
    Registered {
        user_id: UserId,
        credential_id: Uuid,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PasskeyAuditReason {
    AccountUnavailable,
    NoCredentials,
    InvalidAssertion,
    CounterConflict,
    CeremonyUserMismatch,
    InvalidAttestation,
}

impl PasskeyAuditReason {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AccountUnavailable => "account_unavailable",
            Self::NoCredentials => "no_credentials",
            Self::InvalidAssertion => "invalid_assertion",
            Self::CounterConflict => "counter_conflict",
            Self::CeremonyUserMismatch => "ceremony_user_mismatch",
            Self::InvalidAttestation => "invalid_attestation",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PasskeyError {
    InvalidLabel,
    InvalidCeremonyId,
    InvalidCredentialId,
    LoginFailed,
    CeremonyExpired,
    CeremonyMismatch,
    RegistrationFailed,
    AlreadyRegistered,
    NotFound,
    Account(RepositoryError),
    CeremonyState(RepositoryError),
    State(RepositoryError),
    Mfa(RepositoryError),
    Session(RepositoryError),
    SessionCollision,
}

#[derive(Clone)]
pub struct PasskeyService<A, R, C, M, S, U> {
    accounts: A,
    credentials: R,
    ceremonies: C,
    remembered_mfa: M,
    sessions: S,
    audit: U,
    webauthn: Webauthn,
    config: PasskeyServiceConfig,
}

impl<A, R, C, M, S, U> PasskeyService<A, R, C, M, S, U>
where
    A: PasskeyAccountRepositoryPort,
    R: PasskeyRepositoryPort,
    C: PasskeyCeremonyPort,
    M: RememberedMfaDevicePort,
    S: LoginSessionPort,
    U: PasskeyAuditPort,
{
    pub fn new(
        accounts: A,
        credentials: R,
        ceremonies: C,
        remembered_mfa: M,
        sessions: S,
        audit: U,
        config: PasskeyServiceConfig,
    ) -> Self {
        let webauthn = Webauthn::new(&config.rp_id, &config.rp_name, &config.origin)
            .require_user_verification(config.require_user_verification)
            .require_user_handle(config.require_user_handle)
            .strict_base64(config.strict_base64);
        Self {
            accounts,
            credentials,
            ceremonies,
            remembered_mfa,
            sessions,
            audit,
            webauthn,
            config,
        }
    }

    pub async fn login_begin(&self, email: String) -> Result<PasskeyLoginBegin, PasskeyError> {
        let account = self
            .accounts
            .by_email(self.config.tenant_id, &email)
            .await
            .map_err(PasskeyError::Account)?
            .filter(|account| account.principal.active);
        let Some(account) = account else {
            self.audit.record(PasskeyAuditEvent::LoginFailureEmail {
                email,
                reason: PasskeyAuditReason::AccountUnavailable,
            });
            // Keep the storage access pattern close to a real username-first ceremony.
            // The random user cannot match an account, and the resulting ceremony is
            // explicitly marked as dummy before it is persisted.
            let dummy_user_id = random_user_id();
            self.credentials
                .list(self.config.tenant_id, dummy_user_id)
                .await
                .map_err(PasskeyError::State)?;
            return self.dummy_login_begin(dummy_user_id).await;
        };
        let rows = self
            .credentials
            .list(account.tenant().tenant_id, account.user_id())
            .await
            .map_err(PasskeyError::State)?;
        if rows.is_empty() {
            self.audit.record(PasskeyAuditEvent::LoginFailureUser {
                user_id: account.user_id(),
                reason: PasskeyAuditReason::NoCredentials,
            });
            return self.dummy_login_begin(account.user_id()).await;
        }
        let credentials = rows
            .iter()
            .map(decode_credential)
            .collect::<Result<Vec<_>, _>>()?;
        let user_handle = passkey_user_handle(account.tenant().tenant_id, account.user_id());
        let (mut challenge, state) = self
            .webauthn
            .start_authentication_with_creds_for_user(&user_handle, &credentials);
        remove_authentication_transport_hints(&mut challenge);
        let ceremony_id = random_urlsafe_token();
        self.ceremonies
            .store_authentication(
                &ceremony_id,
                &StoredPasskeyAuthentication {
                    user_id: account.user_id(),
                    tenant_id: account.tenant().tenant_id,
                    state,
                    dummy: false,
                },
                self.config.ceremony_ttl_seconds,
            )
            .await
            .map_err(PasskeyError::CeremonyState)?;
        Ok(PasskeyLoginBegin {
            ceremony_id,
            challenge,
        })
    }

    pub async fn login_finish(
        &self,
        ceremony_id: &str,
        response: AuthenticationResponse,
        source_ip: String,
        remembered_mfa: Option<crate::RememberedMfaProof>,
        previous_session_id: Option<String>,
        now: DateTime<Utc>,
    ) -> Result<LoginSuccess, PasskeyError> {
        let ceremony_id =
            normalize_ceremony_id(ceremony_id).map_err(|_| PasskeyError::InvalidCeremonyId)?;
        let stored = self
            .ceremonies
            .take_authentication(&ceremony_id)
            .await
            .map_err(ceremony_read_error)?
            .ok_or(PasskeyError::CeremonyExpired)?;
        if stored.dummy {
            return Err(PasskeyError::LoginFailed);
        }
        let account = self
            .accounts
            .by_id(stored.tenant_id, stored.user_id)
            .await
            .map_err(PasskeyError::Account)?
            .filter(|account| {
                account.principal.active
                    && account.tenant().tenant_id == stored.tenant_id
                    && account.user_id() == stored.user_id
            })
            .ok_or(PasskeyError::LoginFailed)?;
        let credential_id = passkey_auth::CredentialId(
            credential_id_from_response(&response.id)
                .map_err(|_| PasskeyError::InvalidCredentialId)?,
        )
        .to_b64url();
        let row = self
            .credentials
            .by_credential_id(stored.tenant_id, stored.user_id, &credential_id)
            .await
            .map_err(PasskeyError::State)?
            .ok_or(PasskeyError::LoginFailed)?;
        let mut credential = decode_credential(&row)?;
        if i64::from(credential.counter) != row.sign_count {
            return Err(PasskeyError::State(RepositoryError::Consistency(
                "passkey counter columns disagree".to_owned(),
            )));
        }
        let outcome = self
            .webauthn
            .finish_authentication(&stored.state, &response, &credential)
            .map_err(|error| {
                tracing::debug!(
                    error = ?error,
                    user_id = %account.user_id().as_uuid(),
                    "passkey assertion verification failed"
                );
                self.audit.record(PasskeyAuditEvent::LoginFailureUser {
                    user_id: account.user_id(),
                    reason: PasskeyAuditReason::InvalidAssertion,
                });
                PasskeyError::LoginFailed
            })?;
        credential.counter = outcome.new_counter;
        let credential_json = serde_json::to_value(&credential).map_err(|_| {
            PasskeyError::State(RepositoryError::Consistency(
                "passkey credential serialization failed".to_owned(),
            ))
        })?;
        self.credentials
            .update_counter(
                stored.tenant_id,
                stored.user_id,
                &row.credential_id,
                row.sign_count,
                i64::from(outcome.new_counter),
                credential_json,
            )
            .await
            .map_err(|error| match error {
                RepositoryError::Conflict => {
                    self.audit.record(PasskeyAuditEvent::LoginFailureUser {
                        user_id: account.user_id(),
                        reason: PasskeyAuditReason::CounterConflict,
                    });
                    PasskeyError::LoginFailed
                }
                error => PasskeyError::State(error),
            })?;
        self.create_session(account, source_ip, remembered_mfa, previous_session_id, now)
            .await
    }

    pub async fn registration_begin(
        &self,
        account: &PublicAccount,
        label: Option<String>,
    ) -> Result<PasskeyRegistrationBegin, PasskeyError> {
        let label =
            normalize_passkey_label(label.as_deref()).map_err(|_| PasskeyError::InvalidLabel)?;
        let rows = self
            .credentials
            .list(account.tenant().tenant_id, account.user_id())
            .await
            .map_err(PasskeyError::State)?;
        let existing_ids = rows
            .iter()
            .map(decode_credential)
            .map(|result| result.map(|credential| credential.id))
            .collect::<Result<Vec<_>, _>>()?;
        let user_handle = passkey_user_handle(account.tenant().tenant_id, account.user_id());
        let (challenge, state) = self.webauthn.start_registration(
            &user_handle,
            &account.account.email,
            account
                .profile
                .display_name
                .as_deref()
                .unwrap_or(&account.account.email),
            &existing_ids,
        );
        let ceremony_id = random_urlsafe_token();
        self.ceremonies
            .store_registration(
                &ceremony_id,
                &StoredPasskeyRegistration {
                    user_id: account.user_id(),
                    tenant_id: account.tenant().tenant_id,
                    label,
                    state,
                },
                self.config.ceremony_ttl_seconds,
            )
            .await
            .map_err(PasskeyError::CeremonyState)?;
        Ok(PasskeyRegistrationBegin {
            ceremony_id,
            challenge,
        })
    }

    pub async fn registration_finish(
        &self,
        account: &PublicAccount,
        ceremony_id: &str,
        response: RegistrationResponse,
    ) -> Result<PasskeyCredential, PasskeyError> {
        let ceremony_id =
            normalize_ceremony_id(ceremony_id).map_err(|_| PasskeyError::InvalidCeremonyId)?;
        let stored = self
            .ceremonies
            .take_registration(&ceremony_id)
            .await
            .map_err(ceremony_read_error)?
            .ok_or(PasskeyError::CeremonyExpired)?;
        if stored.user_id != account.user_id() || stored.tenant_id != account.tenant().tenant_id {
            self.audit.record(PasskeyAuditEvent::RegistrationRejected {
                user_id: account.user_id(),
                reason: PasskeyAuditReason::CeremonyUserMismatch,
            });
            return Err(PasskeyError::CeremonyMismatch);
        }
        let credential = self
            .webauthn
            .finish_registration(&stored.state, &response)
            .map_err(|error| {
                tracing::debug!(
                    error = ?error,
                    user_id = %account.user_id().as_uuid(),
                    "passkey attestation verification failed"
                );
                self.audit.record(PasskeyAuditEvent::RegistrationRejected {
                    user_id: account.user_id(),
                    reason: PasskeyAuditReason::InvalidAttestation,
                });
                PasskeyError::RegistrationFailed
            })?;
        let credential_id = credential.id.to_b64url();
        let sign_count = i64::from(credential.counter);
        let credential_json = serde_json::to_value(credential).map_err(|_| {
            PasskeyError::State(RepositoryError::Consistency(
                "passkey credential serialization failed".to_owned(),
            ))
        })?;
        let row = self
            .credentials
            .insert(
                stored.tenant_id,
                stored.user_id,
                credential_id,
                credential_json,
                stored.label,
                sign_count,
            )
            .await
            .map_err(|error| match error {
                RepositoryError::Conflict => PasskeyError::AlreadyRegistered,
                error => PasskeyError::State(error),
            })?;
        self.audit.record(PasskeyAuditEvent::Registered {
            user_id: account.user_id(),
            credential_id: row.id,
        });
        Ok(row)
    }

    pub async fn list(
        &self,
        account: &PublicAccount,
    ) -> Result<Vec<PasskeyCredential>, PasskeyError> {
        self.credentials
            .list(account.tenant().tenant_id, account.user_id())
            .await
            .map_err(PasskeyError::State)
    }

    pub async fn delete(&self, account: &PublicAccount, id: Uuid) -> Result<(), PasskeyError> {
        if self
            .credentials
            .delete(account.tenant().tenant_id, account.user_id(), id)
            .await
            .map_err(PasskeyError::State)?
        {
            Ok(())
        } else {
            Err(PasskeyError::NotFound)
        }
    }

    async fn create_session(
        &self,
        account: PublicAccount,
        source_ip: String,
        remembered_mfa: Option<crate::RememberedMfaProof>,
        previous_session_id: Option<String>,
        now: DateTime<Utc>,
    ) -> Result<LoginSuccess, PasskeyError> {
        let remembered = if account.account.mfa_enabled {
            if let Some(proof) = remembered_mfa.as_ref() {
                self.remembered_mfa
                    .is_valid(
                        &account,
                        &proof.token_hash,
                        proof.user_agent_hash.as_deref(),
                        now,
                    )
                    .await
                    .map_err(PasskeyError::Mfa)?
            } else {
                false
            }
        } else {
            false
        };
        let mut amr = vec!["passkey".to_owned()];
        if remembered {
            amr.push("remembered_mfa".to_owned());
            amr.push("mfa".to_owned());
        }
        let session = SessionRecord::new(
            account.user_id(),
            now.timestamp(),
            amr,
            account.account.mfa_enabled && !remembered,
            Some(random_urlsafe_token()),
        );
        let session_id = random_urlsafe_token();
        let csrf_token = random_urlsafe_token();
        match self
            .sessions
            .create_replacing(
                previous_session_id.as_deref(),
                &session_id,
                &session,
                self.config.session_ttl_seconds,
            )
            .await
            .map_err(PasskeyError::Session)?
        {
            LoginSessionCreate::Created => {}
            LoginSessionCreate::Collision => return Err(PasskeyError::SessionCollision),
        }
        self.audit.record(PasskeyAuditEvent::LoginSuccess {
            user_id: account.user_id(),
            source_ip,
        });
        Ok(LoginSuccess {
            session_id,
            csrf_token,
            session,
        })
    }

    async fn dummy_login_begin(
        &self,
        dummy_user_id: UserId,
    ) -> Result<PasskeyLoginBegin, PasskeyError> {
        let user_handle = passkey_user_handle(self.config.tenant_id, dummy_user_id);
        let dummy_credential_id = rand::random::<[u8; 32]>().to_vec();
        let dummy_credential = WebauthnCredential {
            id: passkey_auth::CredentialId(dummy_credential_id),
            public_key_cose: CosePublicKey(Vec::new()),
            counter: 0,
            transports: vec!["internal".to_owned()],
            aaguid: [0; 16],
        };
        let (mut challenge, state) = self
            .webauthn
            .start_authentication_with_creds_for_user(&user_handle, &[dummy_credential]);
        remove_authentication_transport_hints(&mut challenge);

        let ceremony_id = random_urlsafe_token();
        self.ceremonies
            .store_authentication(
                &ceremony_id,
                &StoredPasskeyAuthentication {
                    user_id: dummy_user_id,
                    tenant_id: self.config.tenant_id,
                    state,
                    dummy: true,
                },
                self.config.ceremony_ttl_seconds,
            )
            .await
            .map_err(PasskeyError::CeremonyState)?;
        Ok(PasskeyLoginBegin {
            ceremony_id,
            challenge,
        })
    }
}

fn decode_credential(row: &PasskeyCredential) -> Result<WebauthnCredential, PasskeyError> {
    serde_json::from_value(row.credential.clone()).map_err(|_| {
        PasskeyError::State(RepositoryError::Consistency(
            "stored passkey credential is malformed".to_owned(),
        ))
    })
}

fn remove_authentication_transport_hints(challenge: &mut AuthenticationChallenge) {
    // Username-first responses are unauthenticated. Transport hints are optional
    // and can otherwise disclose account-specific authenticator characteristics.
    for descriptor in &mut challenge.allow_credentials {
        descriptor.transports.clear();
    }
}

fn random_urlsafe_token() -> String {
    URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>())
}

fn random_user_id() -> UserId {
    UserId::new(Uuid::now_v7()).expect("UUIDv7 is never nil")
}

fn ceremony_read_error(error: RepositoryError) -> PasskeyError {
    match error {
        RepositoryError::Consistency(_) => PasskeyError::CeremonyExpired,
        error => PasskeyError::CeremonyState(error),
    }
}
