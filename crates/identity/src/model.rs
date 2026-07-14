use std::{error::Error, fmt};

use argon2::{Argon2, PasswordHash as EncodedPasswordHash, PasswordVerifier};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{TenantContext, UserId};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentityModelError {
    EmptyId,
    EmptyPasswordHash,
    InvalidAuthenticationTime,
    FutureAuthenticationTime,
    EmptyAuthenticationMethods,
    EmptyOidcSid,
}

impl fmt::Display for IdentityModelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::EmptyId => "identity ID must not be nil",
            Self::EmptyPasswordHash => "password hash must not be blank",
            Self::InvalidAuthenticationTime => "authentication time must be positive",
            Self::FutureAuthenticationTime => "authentication time exceeds allowed clock skew",
            Self::EmptyAuthenticationMethods => "authentication methods must not be empty",
            Self::EmptyOidcSid => "OIDC session ID must not be blank",
        })
    }
}

impl Error for IdentityModelError {}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum UserRole {
    User,
    Admin { level: u32 },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Principal {
    pub user_id: UserId,
    pub tenant: TenantContext,
    pub role: UserRole,
    pub active: bool,
}

impl Principal {
    #[must_use]
    pub const fn admin_level(&self) -> Option<u32> {
        match self.role {
            UserRole::User => None,
            UserRole::Admin { level } => Some(level),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum AuthMethod {
    Password,
    Passkey,
    Totp,
    BackupCode,
    RememberedMfa,
    Federated(String),
}

impl AuthMethod {
    fn append_amr(&self, values: &mut Vec<String>) {
        match self {
            Self::Password => push_unique(values, "password"),
            Self::Passkey => push_unique(values, "passkey"),
            Self::Totp => push_unique(values, "otp"),
            Self::BackupCode => push_unique(values, "recovery_code"),
            Self::RememberedMfa => {
                push_unique(values, "remembered_mfa");
                push_unique(values, "mfa");
            }
            Self::Federated(provider) => {
                push_unique(values, provider);
                push_unique(values, "federated");
            }
        }
    }
}

/// Validated authentication state. It is intentionally not deserializable;
/// persisted AMR data must enter through [`AuthenticationContext::from_amr`].
///
/// ```compile_fail
/// let _: nazo_identity::AuthenticationContext =
///     serde_json::from_str(r#"{"auth_time":0,"methods":[],"oidc_sid":"","amr":["tampered"]}"#)
///         .unwrap();
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AuthenticationContext {
    pub auth_time: i64,
    pub methods: Vec<AuthMethod>,
    pub oidc_sid: String,
    amr: Vec<String>,
}

impl AuthenticationContext {
    pub fn new(
        auth_time: i64,
        methods: impl IntoIterator<Item = AuthMethod>,
    ) -> Result<Self, IdentityModelError> {
        let methods = deduplicate_methods(methods);
        if auth_time <= 0 {
            return Err(IdentityModelError::InvalidAuthenticationTime);
        }
        if methods.is_empty() {
            return Err(IdentityModelError::EmptyAuthenticationMethods);
        }
        let mut amr = Vec::new();
        for method in &methods {
            method.append_amr(&mut amr);
        }
        Ok(Self {
            auth_time,
            methods,
            oidc_sid: uuid::Uuid::now_v7().to_string(),
            amr,
        })
    }

    pub fn from_amr<'a>(
        auth_time: i64,
        amr: impl IntoIterator<Item = &'a str>,
        oidc_sid: &str,
        now: i64,
    ) -> Result<Self, IdentityModelError> {
        if auth_time <= 0 {
            return Err(IdentityModelError::InvalidAuthenticationTime);
        }
        if auth_time > now.saturating_add(30) {
            return Err(IdentityModelError::FutureAuthenticationTime);
        }
        let mut normalized_amr = Vec::new();
        for value in amr {
            push_unique(&mut normalized_amr, value);
        }
        if normalized_amr.is_empty() {
            return Err(IdentityModelError::EmptyAuthenticationMethods);
        }
        let oidc_sid = oidc_sid.trim();
        if oidc_sid.is_empty() {
            return Err(IdentityModelError::EmptyOidcSid);
        }
        let methods = normalized_amr
            .iter()
            .map(|value| method_from_amr(value))
            .collect();
        Ok(Self {
            auth_time,
            methods,
            oidc_sid: oidc_sid.to_owned(),
            amr: normalized_amr,
        })
    }

    #[must_use]
    pub fn has_mfa(&self) -> bool {
        self.amr.iter().any(|value| {
            matches!(
                value.as_str(),
                "mfa" | "otp" | "recovery_code" | "remembered_mfa"
            )
        })
    }

    #[must_use]
    pub fn amr(&self) -> &[String] {
        &self.amr
    }
}

fn deduplicate_methods(methods: impl IntoIterator<Item = AuthMethod>) -> Vec<AuthMethod> {
    let mut result = Vec::new();
    for method in methods {
        if !result.contains(&method) {
            result.push(method);
        }
    }
    result
}

fn push_unique(values: &mut Vec<String>, value: &str) {
    if !value.trim().is_empty() && !values.iter().any(|existing| existing == value) {
        values.push(value.to_owned());
    }
}

fn method_from_amr(value: &str) -> AuthMethod {
    match value {
        "password" | "pwd" => AuthMethod::Password,
        "passkey" => AuthMethod::Passkey,
        "otp" => AuthMethod::Totp,
        "recovery_code" => AuthMethod::BackupCode,
        "remembered_mfa" => AuthMethod::RememberedMfa,
        other => AuthMethod::Federated(other.to_owned()),
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct PostalAddress {
    pub formatted: Option<String>,
    pub street_address: Option<String>,
    pub locality: Option<String>,
    pub region: Option<String>,
    pub postal_code: Option<String>,
    pub country: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubjectClaims {
    pub subject: UserId,
    pub preferred_username: String,
    pub name: Option<String>,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    pub middle_name: Option<String>,
    pub nickname: Option<String>,
    pub profile: Option<String>,
    pub picture: Option<String>,
    pub website: Option<String>,
    pub gender: Option<String>,
    pub birthdate: Option<String>,
    pub zoneinfo: Option<String>,
    pub locale: Option<String>,
    pub email: String,
    pub email_verified: bool,
    pub address: Option<PostalAddress>,
    pub phone_number: Option<String>,
    pub phone_number_verified: bool,
    pub updated_at: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccountIdentity {
    pub username: String,
    pub email: String,
    pub email_verified: bool,
    pub mfa_enabled: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoginIdentity {
    pub account: AccountIdentity,
    pub password_hash: PasswordHash,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticationIdentity {
    pub principal: Principal,
    pub login: LoginIdentity,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct UserProfile {
    pub display_name: Option<String>,
    pub avatar_url: Option<String>,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    pub middle_name: Option<String>,
    pub nickname: Option<String>,
    pub profile_url: Option<String>,
    pub website_url: Option<String>,
    pub gender: Option<String>,
    pub birthdate: Option<String>,
    pub zoneinfo: Option<String>,
    pub locale: Option<String>,
    pub address: PostalAddress,
    pub phone_number: Option<String>,
    pub phone_number_verified: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicAccount {
    pub principal: Principal,
    pub account: AccountIdentity,
    pub profile: UserProfile,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// A password verifier owned by the identity domain.
///
/// The inner verifier is deliberately unavailable to serializers and callers.
/// Candidate verification is completed inside this type and returns only a
/// boolean result.
///
/// ```compile_fail
/// fn assert_serialize<T: serde::Serialize>() {}
/// assert_serialize::<nazo_identity::PasswordHash>();
/// ```
///
/// ```compile_fail
/// fn assert_deserialize<T: serde::de::DeserializeOwned>() {}
/// assert_deserialize::<nazo_identity::PasswordHash>();
/// ```
///
/// Authentication-facing callers cannot extract the persisted verifier.
///
/// ```compile_fail
/// let hash = nazo_identity::PasswordHash::new("$argon2id$test").unwrap();
/// let _: String = hash.into_inner();
/// ```
///
/// ```compile_fail
/// let hash = nazo_identity::PasswordHash::new("$argon2id$test").unwrap();
/// let _: &str = hash.expose_for_verification();
/// ```
#[derive(Clone, Eq, PartialEq)]
pub struct PasswordHash(String);

impl PasswordHash {
    pub fn new(value: impl Into<String>) -> Result<Self, IdentityModelError> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(IdentityModelError::EmptyPasswordHash);
        }
        Ok(Self(value))
    }

    /// Verifies a password candidate without releasing the persisted verifier.
    #[must_use]
    pub fn verify_password(&self, candidate: &str) -> bool {
        let Ok(encoded) = EncodedPasswordHash::new(&self.0) else {
            return false;
        };
        Argon2::default()
            .verify_password(candidate.as_bytes(), &encoded)
            .is_ok()
    }
}

impl fmt::Debug for PasswordHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PasswordHash([REDACTED])")
    }
}

impl PublicAccount {
    #[must_use]
    pub const fn id(&self) -> uuid::Uuid {
        self.principal.user_id.as_uuid()
    }
    #[must_use]
    pub const fn user_id(&self) -> UserId {
        self.principal.user_id
    }
    #[must_use]
    pub const fn tenant(&self) -> TenantContext {
        self.principal.tenant
    }
    #[must_use]
    pub const fn tenant_id(&self) -> uuid::Uuid {
        self.principal.tenant.tenant_id.as_uuid()
    }
    #[must_use]
    pub const fn realm_id(&self) -> uuid::Uuid {
        self.principal.tenant.realm_id.as_uuid()
    }
    #[must_use]
    pub const fn organization_id(&self) -> uuid::Uuid {
        self.principal.tenant.organization_id.as_uuid()
    }
    #[must_use]
    pub fn display_name(&self) -> &str {
        self.profile
            .display_name
            .as_deref()
            .unwrap_or(&self.account.username)
    }
    #[must_use]
    pub const fn role_name(&self) -> &'static str {
        match self.principal.role {
            UserRole::User => "user",
            UserRole::Admin { .. } => "admin",
        }
    }
    #[must_use]
    pub const fn admin_level(&self) -> u32 {
        match self.principal.role {
            UserRole::User => 0,
            UserRole::Admin { level } => level,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use argon2::{Argon2, PasswordHasher, password_hash::SaltString};

    #[test]
    fn login_identity_debug_never_exposes_password_hash() {
        let secret = "$argon2id$v=19$m=19456,t=2,p=1$secret-salt$secret-digest";
        let login = LoginIdentity {
            account: AccountIdentity {
                username: "alice".to_owned(),
                email: "alice@example.test".to_owned(),
                email_verified: true,
                mfa_enabled: false,
            },
            password_hash: PasswordHash::new(secret).unwrap(),
        };

        assert!(!format!("{login:?}").contains(secret));
    }

    #[test]
    fn password_hash_verifies_candidates_without_exposing_the_verifier() {
        let encoded = Argon2::default()
            .hash_password(
                b"correct horse battery staple",
                &SaltString::from_b64("c2FsdHNhbHQ").unwrap(),
            )
            .unwrap()
            .to_string();
        let hash = PasswordHash::new(encoded).unwrap();

        assert!(hash.verify_password("correct horse battery staple"));
        assert!(!hash.verify_password("wrong password"));
    }
}
