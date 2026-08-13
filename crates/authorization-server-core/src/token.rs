use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::OidcClaimRequest;

/// Versioned authentication and claim contract carried by a refresh family.
///
/// OIDC Core 12.2 requires a refreshed ID Token to retain the original
/// authentication context (notably `auth_time`) and the original claim
/// contract.  This state is optional on the domain model so rows written
/// before the migration remain readable; callers must not synthesize a
/// replacement context when it is absent.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct RefreshTokenAuthenticationContext {
    pub version: u16,
    pub issuer: String,
    pub audience: String,
    pub auth_time: i64,
    pub amr: Vec<String>,
    pub oidc_sid: Option<String>,
    pub id_token_sid: Option<String>,
    pub acr: Option<String>,
    /// The original authorization nonce is retained for audit/contract
    /// fidelity.  OIDC Core 12.2 says a refreshed ID Token SHOULD omit it.
    pub nonce: Option<String>,
    pub userinfo_claims: Vec<String>,
    pub userinfo_claim_requests: Vec<OidcClaimRequest>,
    pub id_token_claims: Vec<String>,
    pub id_token_claim_requests: Vec<OidcClaimRequest>,
}

impl RefreshTokenAuthenticationContext {
    pub const CURRENT_VERSION: u16 = 1;

    #[must_use]
    pub const fn is_supported_version(&self) -> bool {
        self.version == Self::CURRENT_VERSION
    }

    #[must_use]
    pub fn is_well_formed(&self) -> bool {
        self.is_supported_version()
            && !self.issuer.trim().is_empty()
            && !self.audience.trim().is_empty()
            && self.auth_time > 0
            && !self.amr.is_empty()
            && self.amr.iter().all(|method| !method.trim().is_empty())
            && self
                .oidc_sid
                .as_deref()
                .is_none_or(|sid| !sid.trim().is_empty())
            && self
                .id_token_sid
                .as_deref()
                .is_none_or(|sid| !sid.trim().is_empty())
            && self.acr.as_deref().is_none_or(|acr| !acr.trim().is_empty())
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct RefreshToken {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub token_family_id: Uuid,
    pub client_id: Uuid,
    pub user_id: Option<Uuid>,
    pub scopes: Value,
    pub audience: Value,
    pub authorization_details: Value,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub subject: String,
    pub dpop_jkt: Option<String>,
    pub mtls_x5t_s256: Option<String>,
    pub client_attestation_jkt: Option<String>,
    pub authentication_context: Option<RefreshTokenAuthenticationContext>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LostResponseRetry {
    pub original_id: Uuid,
    pub retry_started_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct NewRefreshToken {
    pub raw_token: String,
    pub tenant_id: Uuid,
    pub family_id: Uuid,
    pub rotated_from_id: Option<Uuid>,
    pub lost_response_retry: Option<LostResponseRetry>,
    pub client_id: Uuid,
    pub user_id: Option<Uuid>,
    pub scopes: Vec<String>,
    pub audiences: Vec<String>,
    pub authorization_details: Value,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub subject: String,
    pub dpop_jkt: Option<String>,
    pub mtls_x5t_s256: Option<String>,
    pub client_attestation_jkt: Option<String>,
    pub authentication_context: Option<RefreshTokenAuthenticationContext>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RefreshTokenPersistResult {
    Inserted,
    RotationConflict,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackchannelLogoutDelivery {
    pub id: Uuid,
    pub logout_uri: String,
    pub logout_token: String,
    pub attempts: i32,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingBackchannelLogoutDelivery {
    pub tenant_id: Uuid,
    pub client_id: Uuid,
    pub client_public_id: String,
    pub logout_uri: String,
    pub logout_token: String,
    pub expires_at: DateTime<Utc>,
}

#[cfg(test)]
#[path = "../tests/unit/token.rs"]
mod tests;
