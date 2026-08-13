//! Wire request models and conversion into the core client-create request.

use serde::Deserialize;
use serde_json::Value;

use crate::{ClientPresentationMetadata, ClientSecurityPolicy, CreateClientRequest};

#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
pub struct DynamicClientRegistrationRequest {
    #[serde(default)]
    pub redirect_uris: Option<Vec<String>>,
    #[serde(default)]
    pub response_types: Option<Vec<String>>,
    #[serde(default)]
    pub grant_types: Option<Vec<String>>,
    #[serde(default)]
    pub application_type: Option<String>,
    #[serde(default)]
    pub client_name: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub token_endpoint_auth_method: Option<String>,
    #[serde(default)]
    pub token_endpoint_auth_methods_supported: Option<Vec<String>>,
    #[serde(default)]
    pub subject_type: Option<String>,
    #[serde(default)]
    pub subject_types_supported: Option<Vec<String>>,
    #[serde(default)]
    pub sector_identifier_uri: Option<String>,
    #[serde(default)]
    pub post_logout_redirect_uris: Vec<String>,
    #[serde(default)]
    pub backchannel_logout_uri: Option<String>,
    #[serde(default)]
    pub backchannel_logout_session_required: Option<bool>,
    #[serde(default)]
    pub backchannel_token_delivery_mode: Option<String>,
    #[serde(default)]
    pub backchannel_client_notification_endpoint: Option<String>,
    #[serde(default)]
    pub backchannel_authentication_request_signing_alg: Option<String>,
    #[serde(default)]
    pub backchannel_authentication_request_signing_alg_values_supported: Option<Vec<String>>,
    #[serde(default)]
    pub backchannel_user_code_parameter: Option<bool>,
    #[serde(default)]
    pub frontchannel_logout_uri: Option<String>,
    #[serde(default)]
    pub frontchannel_logout_session_required: Option<bool>,
    #[serde(default)]
    pub dpop_bound_access_tokens: bool,
    #[serde(default)]
    pub tls_client_certificate_bound_access_tokens: bool,
    #[serde(default)]
    pub tls_client_auth_subject_dn: Option<String>,
    #[serde(default)]
    pub tls_client_auth_san_dns: Option<String>,
    #[serde(default)]
    pub tls_client_auth_san_uri: Option<String>,
    #[serde(default)]
    pub tls_client_auth_san_ip: Option<String>,
    #[serde(default)]
    pub tls_client_auth_san_email: Option<String>,
    #[serde(default)]
    pub jwks_uri: Option<String>,
    #[serde(default)]
    pub jwks: Option<Value>,
    #[serde(default)]
    pub id_token_signed_response_alg: Option<String>,
    #[serde(default)]
    pub id_token_signing_alg_values_supported: Option<Vec<String>>,
    #[serde(default)]
    pub id_token_encrypted_response_alg: Option<String>,
    #[serde(default)]
    pub id_token_encryption_alg_values_supported: Option<Vec<String>>,
    #[serde(default)]
    pub id_token_encrypted_response_enc: Option<String>,
    #[serde(default)]
    pub id_token_encryption_enc_values_supported: Option<Vec<String>>,
    #[serde(default)]
    pub request_object_signing_alg: Option<String>,
    #[serde(default)]
    pub request_object_signing_alg_values_supported: Option<Vec<String>>,
    #[serde(default)]
    pub request_object_encryption_alg: Option<String>,
    #[serde(default)]
    pub request_object_encryption_alg_values_supported: Option<Vec<String>>,
    #[serde(default)]
    pub request_object_encryption_enc: Option<String>,
    #[serde(default)]
    pub request_object_encryption_enc_values_supported: Option<Vec<String>>,
    #[serde(default)]
    pub token_endpoint_auth_signing_alg: Option<String>,
    #[serde(default)]
    pub token_endpoint_auth_signing_alg_values_supported: Option<Vec<String>>,
    #[serde(default)]
    pub userinfo_signed_response_alg: Option<String>,
    #[serde(default)]
    pub userinfo_signing_alg_values_supported: Option<Vec<String>>,
    #[serde(default)]
    pub userinfo_encrypted_response_alg: Option<String>,
    #[serde(default)]
    pub userinfo_encryption_alg_values_supported: Option<Vec<String>>,
    #[serde(default)]
    pub userinfo_encrypted_response_enc: Option<String>,
    #[serde(default)]
    pub userinfo_encryption_enc_values_supported: Option<Vec<String>>,
    #[serde(default)]
    pub authorization_signed_response_alg: Option<String>,
    #[serde(default)]
    pub authorization_signing_alg_values_supported: Option<Vec<String>>,
    #[serde(default)]
    pub authorization_encrypted_response_alg: Option<String>,
    #[serde(default)]
    pub authorization_encryption_alg_values_supported: Option<Vec<String>>,
    #[serde(default)]
    pub authorization_encrypted_response_enc: Option<String>,
    #[serde(default)]
    pub authorization_encryption_enc_values_supported: Option<Vec<String>>,
    #[serde(default)]
    pub introspection_encrypted_response_alg: Option<String>,
    #[serde(default)]
    pub introspection_encryption_alg_values_supported: Option<Vec<String>>,
    #[serde(default)]
    pub introspection_encrypted_response_enc: Option<String>,
    #[serde(default)]
    pub introspection_encryption_enc_values_supported: Option<Vec<String>>,
    #[serde(default)]
    pub introspection_signed_response_alg: Option<String>,
    #[serde(default)]
    pub introspection_signing_alg_values_supported: Option<Vec<String>>,
    #[serde(default)]
    pub request_uris: Option<Vec<String>>,
    #[serde(default)]
    pub initiate_login_uri: Option<String>,
    #[serde(default)]
    pub logo_uri: Option<String>,
    #[serde(default)]
    pub policy_uri: Option<String>,
    #[serde(default)]
    pub tos_uri: Option<String>,
    #[serde(default)]
    pub software_statement: Option<String>,
}
#[derive(Clone, Debug, PartialEq)]
pub struct PreparedDynamicClientRegistration {
    pub client_name: String,
    pub client_type: String,
    pub redirect_uris: Vec<String>,
    pub post_logout_redirect_uris: Vec<String>,
    pub scopes: Vec<String>,
    pub allowed_audiences: Vec<String>,
    pub grant_types: Vec<String>,
    pub response_types: Vec<String>,
    pub token_endpoint_auth_method: String,
    pub subject_type: Option<String>,
    pub sector_identifier_uri: Option<String>,
    pub require_dpop_bound_tokens: bool,
    pub require_mtls_bound_tokens: bool,
    pub backchannel_token_delivery_mode: String,
    pub backchannel_client_notification_endpoint: Option<String>,
    pub backchannel_authentication_request_signing_alg: Option<String>,
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
    pub jwks_uri: Option<String>,
    pub jwks: Option<Value>,
    pub request_uris: Vec<String>,
    pub initiate_login_uri: Option<String>,
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
}
impl PreparedDynamicClientRegistration {
    #[must_use]
    pub fn into_create_client_request(self) -> CreateClientRequest {
        // OIDC Core section 9 defines the token endpoint URL as the audience for
        // private_key_jwt client assertions. FAPI clients are provisioned through the
        // profile-aware admin paths, which keep this baseline OIDC policy disabled.
        let allow_client_assertion_endpoint_audience =
            self.token_endpoint_auth_method == "private_key_jwt";
        CreateClientRequest {
            conformance_lease_id: None,
            client_name: self.client_name,
            client_type: self.client_type,
            redirect_uris: self.redirect_uris,
            post_logout_redirect_uris: self.post_logout_redirect_uris,
            scopes: self.scopes,
            allowed_audiences: self.allowed_audiences,
            grant_types: self.grant_types,
            token_endpoint_auth_method: self.token_endpoint_auth_method,
            subject_type: self.subject_type,
            sector_identifier_uri: self.sector_identifier_uri,
            require_dpop_bound_tokens: self.require_dpop_bound_tokens,
            require_mtls_bound_tokens: self.require_mtls_bound_tokens,
            allow_client_assertion_audience_array: false,
            allow_client_assertion_endpoint_audience,
            require_par_request_object: false,
            backchannel_token_delivery_mode: self.backchannel_token_delivery_mode,
            backchannel_client_notification_endpoint: self.backchannel_client_notification_endpoint,
            backchannel_authentication_request_signing_alg: self
                .backchannel_authentication_request_signing_alg,
            backchannel_user_code_parameter: self.backchannel_user_code_parameter,
            backchannel_logout_uri: self.backchannel_logout_uri,
            backchannel_logout_session_required: self.backchannel_logout_session_required,
            frontchannel_logout_uri: self.frontchannel_logout_uri,
            frontchannel_logout_session_required: self.frontchannel_logout_session_required,
            tls_client_auth_subject_dn: self.tls_client_auth_subject_dn,
            tls_client_auth_cert_sha256: self.tls_client_auth_cert_sha256,
            tls_client_auth_san_dns: self.tls_client_auth_san_dns,
            tls_client_auth_san_uri: self.tls_client_auth_san_uri,
            tls_client_auth_san_ip: self.tls_client_auth_san_ip,
            tls_client_auth_san_email: self.tls_client_auth_san_email,
            jwks_uri: self.jwks_uri,
            jwks: self.jwks,
            request_uris: self.request_uris,
            initiate_login_uri: self.initiate_login_uri,
            presentation: self.presentation,
            id_token_signed_response_alg: self.id_token_signed_response_alg,
            id_token_encrypted_response_alg: self.id_token_encrypted_response_alg,
            id_token_encrypted_response_enc: self.id_token_encrypted_response_enc,
            request_object_signing_alg: self.request_object_signing_alg,
            request_object_encryption_alg: self.request_object_encryption_alg,
            request_object_encryption_enc: self.request_object_encryption_enc,
            token_endpoint_auth_signing_alg: self.token_endpoint_auth_signing_alg,
            introspection_signed_response_alg: self.introspection_signed_response_alg,
            introspection_encrypted_response_alg: self.introspection_encrypted_response_alg,
            introspection_encrypted_response_enc: self.introspection_encrypted_response_enc,
            userinfo_signed_response_alg: self.userinfo_signed_response_alg,
            userinfo_encrypted_response_alg: self.userinfo_encrypted_response_alg,
            userinfo_encrypted_response_enc: self.userinfo_encrypted_response_enc,
            authorization_signed_response_alg: self.authorization_signed_response_alg,
            authorization_encrypted_response_alg: self.authorization_encrypted_response_alg,
            authorization_encrypted_response_enc: self.authorization_encrypted_response_enc,
            security_policy: ClientSecurityPolicy::default(),
        }
    }
}
