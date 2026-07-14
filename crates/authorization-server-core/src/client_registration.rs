use serde_json::Value;
use std::ops::{Deref, DerefMut};
use uuid::Uuid;

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
    pub allow_authorization_code_without_pkce: bool,
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
    pub jwks: Option<Value>,
    pub introspection_encrypted_response_alg: Option<String>,
    pub introspection_encrypted_response_enc: Option<String>,
    pub userinfo_signed_response_alg: Option<String>,
    pub userinfo_encrypted_response_alg: Option<String>,
    pub userinfo_encrypted_response_enc: Option<String>,
    pub authorization_signed_response_alg: Option<String>,
    pub authorization_encrypted_response_alg: Option<String>,
    pub authorization_encrypted_response_enc: Option<String>,
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
