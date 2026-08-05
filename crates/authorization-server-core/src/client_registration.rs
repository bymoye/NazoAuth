use serde_json::Value;
use std::ops::{Deref, DerefMut};
use uuid::Uuid;

const CLIENT_SECURITY_POLICY_VERSION: u16 = 1;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientAssuranceLevel {
    #[default]
    Baseline,
    Fapi2,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClientSecurityPolicy {
    pub version: u16,
    #[serde(default)]
    pub assurance: ClientAssuranceLevel,
    #[serde(default)]
    pub require_signed_authorization_request: bool,
    #[serde(default)]
    pub require_signed_authorization_response: bool,
    #[serde(default)]
    pub require_signed_introspection_response: bool,
    #[serde(default)]
    pub session_management: bool,
    #[serde(default)]
    pub allow_cross_device_flows: bool,
    /// Explicit compatibility exception for confidential OIDC clients.
    /// New and legacy clients default to PKCE-required; callers must constrain
    /// this exception to a separately controlled compatibility boundary.
    #[serde(default)]
    pub allow_confidential_oidc_without_pkce: bool,
}

impl Default for ClientSecurityPolicy {
    fn default() -> Self {
        Self {
            version: CLIENT_SECURITY_POLICY_VERSION,
            assurance: ClientAssuranceLevel::Baseline,
            require_signed_authorization_request: false,
            require_signed_authorization_response: false,
            require_signed_introspection_response: false,
            session_management: false,
            allow_cross_device_flows: false,
            allow_confidential_oidc_without_pkce: false,
        }
    }
}

impl ClientSecurityPolicy {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.version != CLIENT_SECURITY_POLICY_VERSION {
            return Err("unsupported client security policy version");
        }
        Ok(())
    }

    #[must_use]
    pub fn fapi2() -> Self {
        Self {
            assurance: ClientAssuranceLevel::Fapi2,
            ..Self::default()
        }
    }

    #[must_use]
    pub fn requires_fapi2_security(&self) -> bool {
        self.assurance == ClientAssuranceLevel::Fapi2
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, serde::Serialize)]
pub struct ClientPresentationMetadata {
    pub logo_uri: Option<String>,
    pub policy_uri: Option<String>,
    pub tos_uri: Option<String>,
}

/// Validated protocol metadata for an OAuth client registration.
///
/// Tenant placement, credential digests, issued plaintext credentials, and
/// database command shape belong to the coordinating service and adapters.
#[derive(Clone, Debug)]
pub struct ValidatedClientRegistration {
    pub client_id: String,
    pub client_name: String,
    pub client_type: String,
    pub redirect_uris: Vec<String>,
    pub post_logout_redirect_uris: Vec<String>,
    pub scopes: Vec<String>,
    pub allowed_audiences: Vec<String>,
    pub grant_types: Vec<String>,
    pub token_endpoint_auth_method: String,
    pub subject_type: String,
    pub sector_identifier_uri: Option<String>,
    pub sector_identifier_host: Option<String>,
    pub require_dpop_bound_tokens: bool,
    pub allow_client_assertion_audience_array: bool,
    pub allow_client_assertion_endpoint_audience: bool,
    pub require_par_request_object: bool,
    /// CIBA token delivery mode registered for this client. Only `poll` and
    /// `ping` are supported; FAPI-CIBA deliberately excludes `push`.
    pub backchannel_token_delivery_mode: String,
    /// HTTPS callback used only by CIBA ping-mode clients.
    pub backchannel_client_notification_endpoint: Option<String>,
    /// Signing algorithm registered for CIBA Authentication Request objects.
    pub backchannel_authentication_request_signing_alg: Option<String>,
    /// NazoAuth does not support the optional CIBA user-code parameter.
    pub backchannel_user_code_parameter: bool,
    pub backchannel_logout_uri: Option<String>,
    pub backchannel_logout_session_required: bool,
    pub frontchannel_logout_uri: Option<String>,
    pub frontchannel_logout_session_required: bool,
    pub tls_client_auth_subject_dn: Option<String>,
    pub tls_client_auth_cert_sha256: Option<String>,
    pub tls_client_auth_san_dns: Vec<String>,
    pub tls_client_auth_san_uri: Vec<String>,
    pub tls_client_auth_san_ip: Vec<String>,
    pub tls_client_auth_san_email: Vec<String>,
    /// HTTPS URI registered by a dynamic client for retrieving its public JWK Set.
    /// `jwks` contains the last validated snapshot used by protocol verification.
    pub jwks_uri: Option<String>,
    pub jwks: Option<Value>,
    /// Exact, pre-registered HTTPS locations from which OIDC Request Objects may be loaded.
    pub request_uris: Vec<String>,
    /// RP endpoint used by OpenID Connect Third-Party Initiated Login.
    pub initiate_login_uri: Option<String>,
    /// Dynamically registered, display-only RP metadata. These URIs are never
    /// dereferenced by the authorization server.
    pub presentation: ClientPresentationMetadata,
    pub id_token_signed_response_alg: Option<String>,
    pub id_token_encrypted_response_alg: Option<String>,
    pub id_token_encrypted_response_enc: Option<String>,
    pub request_object_signing_alg: Option<String>,
    pub request_object_encryption_alg: Option<String>,
    pub request_object_encryption_enc: Option<String>,
    pub token_endpoint_auth_signing_alg: Option<String>,
    pub introspection_signed_response_alg: Option<String>,
    pub introspection_encrypted_response_alg: Option<String>,
    pub introspection_encrypted_response_enc: Option<String>,
    pub userinfo_signed_response_alg: Option<String>,
    pub userinfo_encrypted_response_alg: Option<String>,
    pub userinfo_encrypted_response_enc: Option<String>,
    pub authorization_signed_response_alg: Option<String>,
    pub authorization_encrypted_response_alg: Option<String>,
    pub authorization_encrypted_response_enc: Option<String>,
    /// Explicit per-client policy. `None` is reserved for clients created
    /// before composable policy and delegates to the legacy deployment profile.
    pub security_policy: Option<ClientSecurityPolicy>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApprovedClient {
    pub id: Uuid,
    pub client_id: String,
}

/// Runtime OAuth client policy independent of any persistence adapter.
///
/// The validated registration metadata is composed rather than copied into a
/// second flat persistence-shaped DTO. Credential digests deliberately do not
/// cross this boundary.
#[derive(Clone, Debug)]
pub struct OAuthClient {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub realm_id: Uuid,
    pub organization_id: Uuid,
    pub registration: ValidatedClientRegistration,
    pub require_mtls_bound_tokens: bool,
    pub is_active: bool,
}

impl Deref for OAuthClient {
    type Target = ValidatedClientRegistration;

    fn deref(&self) -> &Self::Target {
        &self.registration
    }
}

impl DerefMut for OAuthClient {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.registration
    }
}

#[cfg(test)]
#[path = "../tests/unit/client_registration.rs"]
mod tests;
