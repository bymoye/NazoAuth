use serde::Deserialize;
use serde_json::Value;
use uuid::Uuid;

use crate::{ClientPresentationMetadata, ClientSecurityPolicy};

#[derive(Clone, Debug, Deserialize, serde::Serialize)]
pub struct CreateClientRequest {
    /// Optional ownership boundary for short-lived conformance clients.
    ///
    /// The persistence adapter validates the lease in the same database statement that creates
    /// the client. The field contains no key material or client secret.
    #[serde(default)]
    pub conformance_lease_id: Option<Uuid>,
    pub client_name: String,
    pub client_type: String,
    pub redirect_uris: Vec<String>,
    #[serde(default)]
    pub post_logout_redirect_uris: Vec<String>,
    pub scopes: Vec<String>,
    pub allowed_audiences: Vec<String>,
    pub grant_types: Vec<String>,
    pub token_endpoint_auth_method: String,
    #[serde(default)]
    pub subject_type: Option<String>,
    #[serde(default)]
    pub sector_identifier_uri: Option<String>,
    #[serde(default)]
    pub require_dpop_bound_tokens: bool,
    #[serde(default)]
    pub require_mtls_bound_tokens: bool,
    #[serde(default)]
    pub allow_client_assertion_audience_array: bool,
    #[serde(default)]
    pub allow_client_assertion_endpoint_audience: bool,
    #[serde(default)]
    pub require_par_request_object: bool,
    #[serde(default = "default_ciba_delivery_mode")]
    pub backchannel_token_delivery_mode: String,
    #[serde(default)]
    pub backchannel_client_notification_endpoint: Option<String>,
    #[serde(default)]
    pub backchannel_authentication_request_signing_alg: Option<String>,
    #[serde(default)]
    pub backchannel_user_code_parameter: bool,
    #[serde(default)]
    pub backchannel_logout_uri: Option<String>,
    #[serde(default)]
    pub backchannel_logout_session_required: bool,
    #[serde(default)]
    pub frontchannel_logout_uri: Option<String>,
    #[serde(default)]
    pub frontchannel_logout_session_required: bool,
    #[serde(default)]
    pub tls_client_auth_subject_dn: Option<String>,
    #[serde(default)]
    pub tls_client_auth_cert_sha256: Option<String>,
    #[serde(default)]
    pub tls_client_auth_san_dns: Vec<String>,
    #[serde(default)]
    pub tls_client_auth_san_uri: Vec<String>,
    #[serde(default)]
    pub tls_client_auth_san_ip: Vec<String>,
    #[serde(default)]
    pub tls_client_auth_san_email: Vec<String>,
    #[serde(default, skip_deserializing)]
    pub jwks_uri: Option<String>,
    pub jwks: Option<Value>,
    #[serde(default, skip_deserializing)]
    pub request_uris: Vec<String>,
    #[serde(default, skip_deserializing)]
    pub initiate_login_uri: Option<String>,
    #[serde(default, skip_deserializing)]
    pub presentation: ClientPresentationMetadata,
    #[serde(default)]
    pub id_token_signed_response_alg: Option<String>,
    #[serde(default)]
    pub id_token_encrypted_response_alg: Option<String>,
    #[serde(default)]
    pub id_token_encrypted_response_enc: Option<String>,
    #[serde(default)]
    pub request_object_signing_alg: Option<String>,
    #[serde(default)]
    pub request_object_encryption_alg: Option<String>,
    #[serde(default)]
    pub request_object_encryption_enc: Option<String>,
    #[serde(default)]
    pub token_endpoint_auth_signing_alg: Option<String>,
    #[serde(default)]
    pub introspection_signed_response_alg: Option<String>,
    #[serde(default)]
    pub introspection_encrypted_response_alg: Option<String>,
    #[serde(default)]
    pub introspection_encrypted_response_enc: Option<String>,
    #[serde(default)]
    pub userinfo_signed_response_alg: Option<String>,
    #[serde(default)]
    pub userinfo_encrypted_response_alg: Option<String>,
    #[serde(default)]
    pub userinfo_encrypted_response_enc: Option<String>,
    #[serde(default)]
    pub authorization_signed_response_alg: Option<String>,
    #[serde(default)]
    pub authorization_encrypted_response_alg: Option<String>,
    #[serde(default)]
    pub authorization_encrypted_response_enc: Option<String>,
    #[serde(default)]
    pub security_policy: ClientSecurityPolicy,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct PatchClientRequest {
    pub client_name: Option<String>,
    pub redirect_uris: Option<Vec<String>>,
    pub post_logout_redirect_uris: Option<Vec<String>>,
    pub scopes: Option<Vec<String>>,
    pub allowed_audiences: Option<Vec<String>>,
    pub grant_types: Option<Vec<String>>,
    pub require_dpop_bound_tokens: Option<bool>,
    pub require_mtls_bound_tokens: Option<bool>,
    pub allow_client_assertion_audience_array: Option<bool>,
    pub allow_client_assertion_endpoint_audience: Option<bool>,
    pub require_par_request_object: Option<bool>,
    pub backchannel_token_delivery_mode: Option<String>,
    pub backchannel_client_notification_endpoint: Option<String>,
    pub backchannel_authentication_request_signing_alg: Option<String>,
    pub backchannel_user_code_parameter: Option<bool>,
    pub subject_type: Option<String>,
    pub sector_identifier_uri: Option<String>,
    pub backchannel_logout_uri: Option<String>,
    pub backchannel_logout_session_required: Option<bool>,
    pub frontchannel_logout_uri: Option<String>,
    pub frontchannel_logout_session_required: Option<bool>,
    pub tls_client_auth_subject_dn: Option<String>,
    pub tls_client_auth_cert_sha256: Option<String>,
    pub tls_client_auth_san_dns: Option<Vec<String>>,
    pub tls_client_auth_san_uri: Option<Vec<String>>,
    pub tls_client_auth_san_ip: Option<Vec<String>>,
    pub tls_client_auth_san_email: Option<Vec<String>>,
    pub jwks: Option<Value>,
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
    pub security_policy: Option<ClientSecurityPolicy>,
    pub is_active: Option<bool>,
}

fn default_ciba_delivery_mode() -> String {
    "poll".to_owned()
}
