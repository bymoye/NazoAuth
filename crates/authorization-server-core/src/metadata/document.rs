use serde_json::{Value, json};

use super::MetadataCapabilities;
use crate::SUPPORTED_AUTHORIZATION_DETAILS_TYPES;
use nazo_runtime_modules::ActiveModuleSnapshot;

const CLIENT_JWT_SIGNING_ALGS: [&str; 4] = ["EdDSA", "RS256", "ES256", "PS256"];
const DPOP_SIGNING_ALGS: [&str; 2] = ["EdDSA", "ES256"];
const FAPI_CIBA_REQUEST_OBJECT_SIGNING_ALGS: [&str; 3] = ["EdDSA", "ES256", "PS256"];
const REQUEST_OBJECT_SIGNING_ALGS: [&str; 4] = ["EdDSA", "RS256", "ES256", "PS256"];
const BASELINE_REQUEST_OBJECT_SIGNING_ALGS: [&str; 5] =
    ["none", "EdDSA", "RS256", "ES256", "PS256"];
const PROMPT_VALUES_SUPPORTED: [&str; 4] = ["login", "consent", "select_account", "none"];
const CLAIMS_SUPPORTED: [&str; 24] = [
    "sub",
    "auth_time",
    "amr",
    "nonce",
    "acr",
    "preferred_username",
    "name",
    "given_name",
    "family_name",
    "middle_name",
    "nickname",
    "profile",
    "picture",
    "website",
    "gender",
    "birthdate",
    "zoneinfo",
    "locale",
    "email",
    "email_verified",
    "address",
    "phone_number",
    "phone_number_verified",
    "updated_at",
];
const CLIENT_AUTH_METHODS: [&str; 6] = [
    "client_secret_basic",
    "client_secret_post",
    "private_key_jwt",
    "tls_client_auth",
    "self_signed_tls_client_auth",
    "none",
];
const FAPI2_CLIENT_AUTH_METHODS: [&str; 3] = [
    "private_key_jwt",
    "tls_client_auth",
    "self_signed_tls_client_auth",
];
const SCOPES_SUPPORTED: [&str; 6] = [
    "openid",
    "profile",
    "email",
    "address",
    "phone",
    "offline_access",
];
const SUPPORTED_CLIENT_JWE_KEY_MANAGEMENT_ALGS: [&str; 1] = ["RSA-OAEP-256"];
const SUPPORTED_CLIENT_JWE_CONTENT_ENC_ALGS: [&str; 1] = ["A256GCM"];
const BASELINE_ACR_VALUE: &str = "1";

/// Authorization-server profile choices that affect standard metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MetadataAuthorizationServerProfile {
    Oauth2Baseline,
    Fapi2Security,
    Fapi2MessageSigningAuthorizationRequest,
    Fapi2MessageSigningJarm,
    Fapi2MessageSigningIntrospection,
}

impl MetadataAuthorizationServerProfile {
    const fn requires_fapi2_security(self) -> bool {
        !matches!(self, Self::Oauth2Baseline)
    }

    const fn requires_signed_authorization_request(self) -> bool {
        matches!(self, Self::Fapi2MessageSigningAuthorizationRequest)
    }

    const fn requires_signed_authorization_response(self) -> bool {
        matches!(self, Self::Fapi2MessageSigningJarm)
    }

    const fn requires_signed_introspection(self) -> bool {
        matches!(self, Self::Fapi2MessageSigningIntrospection)
    }
}

/// CIBA policy choices that affect client-authentication metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CibaMetadataProfile {
    FapiCiba,
    Fapi2Ciba,
}

impl CibaMetadataProfile {
    const fn requires_fapi2_hardening(self) -> bool {
        matches!(self, Self::Fapi2Ciba)
    }
}

/// OIDC subject identifier mode selected by configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MetadataSubjectType {
    Public,
    Pairwise,
}

/// Signing algorithms made available by the current key snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MetadataSigningAlgorithms<'a> {
    /// Algorithms backed by the active signing key.
    pub active: &'a [&'a str],
    /// Algorithms backed by keys eligible to sign ID Tokens.
    pub id_token: &'a [&'a str],
    /// Algorithms backed by all keys eligible for protocol responses.
    pub response: &'a [&'a str],
}

/// Framework- and infrastructure-free input for OAuth AS and OIDC discovery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorizationServerMetadataInput<'a> {
    pub issuer: &'a str,
    pub mtls_endpoint_base_url: &'a str,
    pub mtls_enabled: bool,
    pub profile: MetadataAuthorizationServerProfile,
    pub ciba_profile: CibaMetadataProfile,
    pub subject_type: MetadataSubjectType,
    pub pairwise_subject_enabled: bool,
    pub protected_resource_identifier: &'a str,
    pub require_pushed_authorization_requests: bool,
    pub request_uri_parameter_enabled: bool,
    pub signing_algorithms: MetadataSigningAlgorithms<'a>,
}

/// Framework- and infrastructure-free input for RFC 9728 metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProtectedResourceMetadataInput<'a> {
    pub issuer: &'a str,
    pub protected_resource_identifier: &'a str,
    pub mtls_enabled: bool,
}

/// Builds a single immutable OAuth AS/OIDC metadata document from typed inputs.
#[must_use]
pub fn authorization_server_metadata(
    input: AuthorizationServerMetadataInput<'_>,
    snapshot: &ActiveModuleSnapshot,
) -> Value {
    let capabilities = MetadataCapabilities::from_snapshot(snapshot);
    let issuer = input.issuer;
    let response_signing_algs = input.signing_algorithms.response;
    let active_signing_algs = input.signing_algorithms.active;
    let id_token_signing_algs =
        id_token_signing_alg_values_supported(input.signing_algorithms.id_token);
    let token_auth_methods = token_endpoint_auth_methods_supported(
        input.profile,
        input.ciba_profile,
        input.mtls_enabled,
    );
    let token_auth_signing_algs =
        token_endpoint_auth_signing_alg_values_supported(input.ciba_profile);
    let request_object_signing_algs =
        request_object_signing_alg_values_supported(input.profile, active_signing_algs);
    let mut response_modes = response_modes_supported(input.profile);
    if !capabilities.jarm {
        response_modes.retain(|mode| *mode != "jwt");
    }
    let mut scopes_supported = SCOPES_SUPPORTED.to_vec();
    if capabilities.native_sso {
        scopes_supported.push("device_sso");
    }
    let mut metadata = json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}/authorize"),
        "token_endpoint": format!("{issuer}/token"),
        "end_session_endpoint": format!("{issuer}/logout"),
        "pushed_authorization_request_endpoint": format!("{issuer}/par"),
        "revocation_endpoint": format!("{issuer}/revoke"),
        "introspection_endpoint": format!("{issuer}/introspect"),
        "userinfo_endpoint": format!("{issuer}/userinfo"),
        "jwks_uri": format!("{issuer}/jwks.json"),
        "response_types_supported": ["code"],
        "response_modes_supported": response_modes,
        "subject_types_supported": subject_types_supported(input),
        "id_token_signing_alg_values_supported": id_token_signing_algs,
        "userinfo_signing_alg_values_supported": response_signing_algs,
        "userinfo_encryption_alg_values_supported": SUPPORTED_CLIENT_JWE_KEY_MANAGEMENT_ALGS,
        "userinfo_encryption_enc_values_supported": SUPPORTED_CLIENT_JWE_CONTENT_ENC_ALGS,
        "authorization_signing_alg_values_supported": response_signing_algs,
        "authorization_encryption_alg_values_supported": SUPPORTED_CLIENT_JWE_KEY_MANAGEMENT_ALGS,
        "authorization_encryption_enc_values_supported": SUPPORTED_CLIENT_JWE_CONTENT_ENC_ALGS,
        "token_endpoint_auth_methods_supported": token_auth_methods,
        "token_endpoint_auth_signing_alg_values_supported": token_auth_signing_algs,
        "revocation_endpoint_auth_methods_supported": token_auth_methods,
        "revocation_endpoint_auth_signing_alg_values_supported": CLIENT_JWT_SIGNING_ALGS,
        "introspection_endpoint_auth_methods_supported": token_auth_methods,
        "introspection_endpoint_auth_signing_alg_values_supported": CLIENT_JWT_SIGNING_ALGS,
        "scopes_supported": scopes_supported,
        "claims_supported": CLAIMS_SUPPORTED,
        "acr_values_supported": [BASELINE_ACR_VALUE],
        "prompt_values_supported": PROMPT_VALUES_SUPPORTED,
        "grant_types_supported": capabilities.grant_types,
        "protected_resources": [input.protected_resource_identifier],
        "authorization_response_iss_parameter_supported": true,
        "claims_parameter_supported": true,
        "backchannel_logout_supported": true,
        "backchannel_logout_session_supported": true,
        "require_pushed_authorization_requests": input.require_pushed_authorization_requests,
        "code_challenge_methods_supported": ["S256"],
        "dpop_signing_alg_values_supported": DPOP_SIGNING_ALGS,
        "request_object_signing_alg_values_supported": request_object_signing_algs
    });

    if capabilities.authorization_details {
        metadata["authorization_details_types_supported"] =
            json!(SUPPORTED_AUTHORIZATION_DETAILS_TYPES);
    }
    if capabilities.device_authorization {
        metadata["device_authorization_endpoint"] = json!(format!("{issuer}/device_authorization"));
    }
    if capabilities.dynamic_client_registration {
        metadata["registration_endpoint"] = json!(format!("{issuer}/register"));
    }
    if capabilities.frontchannel_logout {
        metadata["frontchannel_logout_supported"] = json!(true);
        metadata["frontchannel_logout_session_supported"] = json!(true);
    }
    if capabilities.session_management {
        metadata["check_session_iframe"] = json!(format!("{issuer}/check_session"));
    }
    if capabilities.ciba {
        metadata["backchannel_authentication_endpoint"] = json!(format!("{issuer}/bc-authorize"));
        metadata["backchannel_token_delivery_modes_supported"] = json!(["poll"]);
        metadata["backchannel_user_code_parameter_supported"] = json!(false);
        metadata["backchannel_authentication_request_signing_alg_values_supported"] =
            json!(FAPI_CIBA_REQUEST_OBJECT_SIGNING_ALGS);
    }
    if capabilities.native_sso {
        metadata["native_sso_supported"] = json!(true);
    }
    if input.profile.requires_signed_introspection() {
        metadata["introspection_signing_alg_values_supported"] = json!(active_signing_algs);
        metadata["introspection_encryption_alg_values_supported"] =
            json!(SUPPORTED_CLIENT_JWE_KEY_MANAGEMENT_ALGS);
        metadata["introspection_encryption_enc_values_supported"] =
            json!(SUPPORTED_CLIENT_JWE_CONTENT_ENC_ALGS);
    }
    if capabilities.request_objects {
        metadata["request_parameter_supported"] = json!(true);
    }
    if input.request_uri_parameter_enabled {
        metadata["request_uri_parameter_supported"] = json!(true);
        metadata["require_request_uri_registration"] = json!(true);
    } else {
        metadata["request_uri_parameter_supported"] = json!(false);
    }
    if input.mtls_enabled {
        let mtls_base = input.mtls_endpoint_base_url;
        metadata["tls_client_certificate_bound_access_tokens"] = json!(true);
        metadata["mtls_endpoint_aliases"] = json!({
            "token_endpoint": format!("{mtls_base}/token"),
            "pushed_authorization_request_endpoint": format!("{mtls_base}/par"),
            "revocation_endpoint": format!("{mtls_base}/revoke"),
            "introspection_endpoint": format!("{mtls_base}/introspect"),
            "userinfo_endpoint": format!("{mtls_base}/userinfo")
        });
    }

    metadata
}

/// Builds RFC 9728 protected-resource metadata from the same capability snapshot.
#[must_use]
pub fn protected_resource_metadata(
    input: ProtectedResourceMetadataInput<'_>,
    snapshot: &ActiveModuleSnapshot,
) -> Value {
    let capabilities = MetadataCapabilities::from_snapshot(snapshot);
    let mut metadata = json!({
        "resource": input.protected_resource_identifier,
        "authorization_servers": [input.issuer],
        "resource_name": "Nazo OAuth Protected Resource",
        "bearer_methods_supported": ["header", "body"],
        "scopes_supported": SCOPES_SUPPORTED,
        "dpop_signing_alg_values_supported": DPOP_SIGNING_ALGS
    });
    if input.mtls_enabled {
        metadata["tls_client_certificate_bound_access_tokens"] = json!(true);
    }
    if capabilities.authorization_details {
        metadata["authorization_details_types_supported"] =
            json!(SUPPORTED_AUTHORIZATION_DETAILS_TYPES);
    }
    metadata
}

fn subject_types_supported(input: AuthorizationServerMetadataInput<'_>) -> Vec<&'static str> {
    match (input.pairwise_subject_enabled, input.subject_type) {
        (false, _) => vec!["public"],
        (true, MetadataSubjectType::Pairwise) => vec!["pairwise"],
        (true, MetadataSubjectType::Public) => vec!["public", "pairwise"],
    }
}

fn token_endpoint_auth_methods_supported(
    profile: MetadataAuthorizationServerProfile,
    ciba_profile: CibaMetadataProfile,
    mtls_enabled: bool,
) -> Vec<&'static str> {
    let methods = if profile.requires_fapi2_security() || ciba_profile.requires_fapi2_hardening() {
        FAPI2_CLIENT_AUTH_METHODS.as_slice()
    } else {
        CLIENT_AUTH_METHODS.as_slice()
    };
    methods
        .iter()
        .copied()
        .filter(|method| {
            mtls_enabled || !matches!(*method, "tls_client_auth" | "self_signed_tls_client_auth")
        })
        .collect()
}

fn token_endpoint_auth_signing_alg_values_supported(
    ciba_profile: CibaMetadataProfile,
) -> Vec<&'static str> {
    if ciba_profile.requires_fapi2_hardening() {
        return FAPI_CIBA_REQUEST_OBJECT_SIGNING_ALGS.to_vec();
    }
    CLIENT_JWT_SIGNING_ALGS.to_vec()
}

fn request_object_signing_alg_values_supported<'a>(
    profile: MetadataAuthorizationServerProfile,
    active_signing_algs: &'a [&'a str],
) -> Vec<&'a str> {
    if profile.requires_signed_authorization_request() {
        return active_signing_algs.to_vec();
    }
    if profile.requires_fapi2_security() {
        return REQUEST_OBJECT_SIGNING_ALGS.to_vec();
    }
    BASELINE_REQUEST_OBJECT_SIGNING_ALGS.to_vec()
}

fn response_modes_supported(profile: MetadataAuthorizationServerProfile) -> Vec<&'static str> {
    if profile.requires_signed_authorization_response() {
        return vec!["jwt"];
    }
    vec!["query", "jwt"]
}

fn id_token_signing_alg_values_supported<'a>(active: &'a [&'a str]) -> Vec<&'a str> {
    let mut values = active.to_vec();
    values.push("RS256");
    values.sort_unstable();
    values.dedup();
    values
}

#[cfg(test)]
#[path = "document_tests.rs"]
mod tests;
