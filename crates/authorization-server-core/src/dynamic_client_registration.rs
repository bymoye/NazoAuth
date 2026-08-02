use std::{future::Future, pin::Pin};

use serde::Deserialize;
use serde_json::Value;
use uuid::Uuid;

use crate::{
    ClientPresentationMetadata, ClientSecurityPolicy, CreateClientRequest, OAuthClient,
    PreparedClientRegistration, SUPPORTED_CLIENT_JWE_CONTENT_ENC_ALGS,
    SUPPORTED_CLIENT_JWE_KEY_MANAGEMENT_ALGS, SUPPORTED_CLIENT_JWT_SIGNING_ALGS, parse_scope,
};

pub type DynamicRegistrationFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, DynamicRegistrationDependencyError>> + Send + 'a>>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DynamicRegistrationDependencyError {
    Unavailable,
    StaleCredentials,
}

/// Persistence boundary for RFC 7591 registration and RFC 7592 client management.
pub trait DynamicRegistrationClientStore: Send + Sync {
    fn insert<'a>(
        &'a self,
        prepared: &'a PreparedClientRegistration,
    ) -> DynamicRegistrationFuture<'a, OAuthClient>;

    fn by_registration_access_token<'a>(
        &'a self,
        tenant_id: Uuid,
        client_id: &'a str,
        token_hash: &'a str,
    ) -> DynamicRegistrationFuture<'a, Option<OAuthClient>>;

    fn has_client_secret(&self, client_id: Uuid) -> DynamicRegistrationFuture<'_, bool>;

    fn client_secret_salt(&self, client_id: Uuid) -> DynamicRegistrationFuture<'_, Option<String>>;

    fn client_secret_digest_matches<'a>(
        &'a self,
        client_id: Uuid,
        candidate_digest: &'a str,
    ) -> DynamicRegistrationFuture<'a, bool>;

    fn rotate_credentials<'a>(
        &'a self,
        tenant_id: Uuid,
        client_id: Uuid,
        client_secret_hash: Option<&'a str>,
        expected_registration_access_token_hash: &'a str,
        new_registration_access_token_hash: &'a str,
    ) -> DynamicRegistrationFuture<'a, OAuthClient>;

    fn replace_registration<'a>(
        &'a self,
        client: &'a OAuthClient,
        client_secret_hash: Option<&'a str>,
        expected_registration_access_token_hash: &'a str,
        new_registration_access_token_hash: Option<&'a str>,
    ) -> DynamicRegistrationFuture<'a, OAuthClient>;

    fn deactivate<'a>(
        &'a self,
        tenant_id: Uuid,
        client_id: Uuid,
        expected_registration_access_token_hash: &'a str,
    ) -> DynamicRegistrationFuture<'a, bool>;
}

/// Secret-material operations kept outside protocol and transport code.
pub trait DynamicRegistrationSecretPort: Send + Sync {
    fn random_token(&self) -> String;
    fn token_hash(&self, token: &str) -> String;
    fn constant_time_eq(&self, left: &[u8], right: &[u8]) -> bool;
}

pub trait ClientSecretDigesterPort: Send + Sync {
    fn client_secret_digest(&self, secret: &str, pepper: &str, salt: &str) -> String;
}

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

#[derive(Clone, Copy, Debug)]
pub struct DynamicRegistrationPolicy<'a> {
    pub default_audience: &'a str,
    pub pairwise_subject_supported: bool,
    pub id_token_signing_algs: &'a [&'a str],
    pub response_signing_algs: &'a [&'a str],
    pub request_object_encryption_algs: &'a [&'a str],
    pub request_object_encryption_encs: &'a [&'a str],
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DynamicRegistrationError {
    pub error: &'static str,
    pub description: String,
}

impl DynamicRegistrationError {
    #[must_use]
    pub fn new(error: &'static str, description: impl Into<String>) -> Self {
        Self {
            error,
            description: description.into(),
        }
    }

    #[must_use]
    pub fn invalid_client_metadata(description: impl Into<String>) -> Self {
        Self::new("invalid_client_metadata", description)
    }
}

pub fn prepare_dynamic_client_registration(
    mut request: DynamicClientRegistrationRequest,
    policy: DynamicRegistrationPolicy<'_>,
) -> Result<PreparedDynamicClientRegistration, DynamicRegistrationError> {
    let subject_types = if policy.pairwise_subject_supported {
        &["public", "pairwise"][..]
    } else {
        &["public"][..]
    };
    request.subject_type = negotiate_metadata_choice(
        "subject_type",
        request.subject_type,
        request.subject_types_supported,
        subject_types,
    )?;
    request.token_endpoint_auth_method = negotiate_metadata_choice(
        "token_endpoint_auth_method",
        request.token_endpoint_auth_method,
        request.token_endpoint_auth_methods_supported,
        &[
            "private_key_jwt",
            "tls_client_auth",
            "self_signed_tls_client_auth",
            "client_secret_basic",
            "client_secret_post",
            "none",
        ],
    )?;
    request.id_token_signed_response_alg = negotiate_metadata_choice(
        "id_token_signed_response_alg",
        request.id_token_signed_response_alg,
        request.id_token_signing_alg_values_supported,
        policy.id_token_signing_algs,
    )?;
    request.id_token_encrypted_response_alg = negotiate_metadata_choice(
        "id_token_encrypted_response_alg",
        request.id_token_encrypted_response_alg,
        request.id_token_encryption_alg_values_supported,
        SUPPORTED_CLIENT_JWE_KEY_MANAGEMENT_ALGS,
    )?;
    request.id_token_encrypted_response_enc = negotiate_metadata_choice(
        "id_token_encrypted_response_enc",
        request.id_token_encrypted_response_enc,
        request.id_token_encryption_enc_values_supported,
        SUPPORTED_CLIENT_JWE_CONTENT_ENC_ALGS,
    )?;
    request.request_object_signing_alg = negotiate_metadata_choice(
        "request_object_signing_alg",
        request.request_object_signing_alg,
        request.request_object_signing_alg_values_supported,
        SUPPORTED_CLIENT_JWT_SIGNING_ALGS,
    )?;
    request.request_object_encryption_alg = negotiate_metadata_choice(
        "request_object_encryption_alg",
        request.request_object_encryption_alg,
        request.request_object_encryption_alg_values_supported,
        policy.request_object_encryption_algs,
    )?;
    request.request_object_encryption_enc = negotiate_metadata_choice(
        "request_object_encryption_enc",
        request.request_object_encryption_enc,
        request.request_object_encryption_enc_values_supported,
        policy.request_object_encryption_encs,
    )?;
    request.token_endpoint_auth_signing_alg = negotiate_metadata_choice(
        "token_endpoint_auth_signing_alg",
        request.token_endpoint_auth_signing_alg,
        request.token_endpoint_auth_signing_alg_values_supported,
        SUPPORTED_CLIENT_JWT_SIGNING_ALGS,
    )?;
    request.backchannel_authentication_request_signing_alg = negotiate_metadata_choice(
        "backchannel_authentication_request_signing_alg",
        request.backchannel_authentication_request_signing_alg,
        request.backchannel_authentication_request_signing_alg_values_supported,
        &["EdDSA", "ES256", "PS256"],
    )?;
    request.userinfo_signed_response_alg = negotiate_metadata_choice(
        "userinfo_signed_response_alg",
        request.userinfo_signed_response_alg,
        request.userinfo_signing_alg_values_supported,
        &["EdDSA", "RS256", "ES256", "PS256"],
    )?;
    request.userinfo_encrypted_response_alg = negotiate_metadata_choice(
        "userinfo_encrypted_response_alg",
        request.userinfo_encrypted_response_alg,
        request.userinfo_encryption_alg_values_supported,
        SUPPORTED_CLIENT_JWE_KEY_MANAGEMENT_ALGS,
    )?;
    request.userinfo_encrypted_response_enc = negotiate_metadata_choice(
        "userinfo_encrypted_response_enc",
        request.userinfo_encrypted_response_enc,
        request.userinfo_encryption_enc_values_supported,
        SUPPORTED_CLIENT_JWE_CONTENT_ENC_ALGS,
    )?;
    request.authorization_signed_response_alg = negotiate_metadata_choice(
        "authorization_signed_response_alg",
        request.authorization_signed_response_alg,
        request.authorization_signing_alg_values_supported,
        &["EdDSA", "RS256", "ES256", "PS256"],
    )?;
    request.authorization_encrypted_response_alg = negotiate_metadata_choice(
        "authorization_encrypted_response_alg",
        request.authorization_encrypted_response_alg,
        request.authorization_encryption_alg_values_supported,
        SUPPORTED_CLIENT_JWE_KEY_MANAGEMENT_ALGS,
    )?;
    request.authorization_encrypted_response_enc = negotiate_metadata_choice(
        "authorization_encrypted_response_enc",
        request.authorization_encrypted_response_enc,
        request.authorization_encryption_enc_values_supported,
        SUPPORTED_CLIENT_JWE_CONTENT_ENC_ALGS,
    )?;
    request.introspection_encrypted_response_alg = negotiate_metadata_choice(
        "introspection_encrypted_response_alg",
        request.introspection_encrypted_response_alg,
        request.introspection_encryption_alg_values_supported,
        SUPPORTED_CLIENT_JWE_KEY_MANAGEMENT_ALGS,
    )?;
    request.introspection_encrypted_response_enc = negotiate_metadata_choice(
        "introspection_encrypted_response_enc",
        request.introspection_encrypted_response_enc,
        request.introspection_encryption_enc_values_supported,
        SUPPORTED_CLIENT_JWE_CONTENT_ENC_ALGS,
    )?;
    request.introspection_signed_response_alg = negotiate_metadata_choice(
        "introspection_signed_response_alg",
        request.introspection_signed_response_alg,
        request.introspection_signing_alg_values_supported,
        policy.response_signing_algs,
    )?;
    if request.software_statement.is_some() {
        return Err(DynamicRegistrationError::new(
            "invalid_software_statement",
            "software_statement is not supported by this registration endpoint.",
        ));
    }
    if request.jwks_uri.is_some() && request.jwks.is_some() {
        return Err(DynamicRegistrationError::invalid_client_metadata(
            "jwks_uri and jwks must not both be present.",
        ));
    }
    let jwks_uri = request
        .jwks_uri
        .map(|uri| validate_https_metadata_uri("jwks_uri", uri, false))
        .transpose()?;
    let request_uris = validate_request_uris(request.request_uris.unwrap_or_default())?;
    let initiate_login_uri = request
        .initiate_login_uri
        .map(|uri| validate_https_metadata_uri("initiate_login_uri", uri, false))
        .transpose()?;
    let presentation = ClientPresentationMetadata {
        logo_uri: request
            .logo_uri
            .map(|uri| validate_https_metadata_uri("logo_uri", uri, false))
            .transpose()?,
        policy_uri: request
            .policy_uri
            .map(|uri| validate_https_metadata_uri("policy_uri", uri, false))
            .transpose()?,
        tos_uri: request
            .tos_uri
            .map(|uri| validate_https_metadata_uri("tos_uri", uri, false))
            .transpose()?,
    };
    let backchannel_token_delivery_mode = request
        .backchannel_token_delivery_mode
        .unwrap_or_else(|| "poll".to_owned());
    if !matches!(backchannel_token_delivery_mode.as_str(), "poll" | "ping") {
        return Err(DynamicRegistrationError::invalid_client_metadata(
            "backchannel_token_delivery_mode must be poll or ping; push is not supported.",
        ));
    }
    let backchannel_client_notification_endpoint = request
        .backchannel_client_notification_endpoint
        .map(|uri| {
            validate_https_metadata_uri("backchannel_client_notification_endpoint", uri, false)
        })
        .transpose()?;
    match (
        backchannel_token_delivery_mode.as_str(),
        backchannel_client_notification_endpoint.as_ref(),
    ) {
        ("ping", None) => {
            return Err(DynamicRegistrationError::invalid_client_metadata(
                "ping mode requires backchannel_client_notification_endpoint.",
            ));
        }
        ("poll", Some(_)) => {
            return Err(DynamicRegistrationError::invalid_client_metadata(
                "poll mode must not register backchannel_client_notification_endpoint.",
            ));
        }
        _ => {}
    }
    if request.backchannel_user_code_parameter.unwrap_or(false) {
        return Err(DynamicRegistrationError::invalid_client_metadata(
            "backchannel_user_code_parameter=true is not supported.",
        ));
    }
    if request
        .backchannel_authentication_request_signing_alg
        .as_deref()
        .is_some_and(|algorithm| !matches!(algorithm, "EdDSA" | "ES256" | "PS256"))
    {
        return Err(DynamicRegistrationError::invalid_client_metadata(
            "backchannel_authentication_request_signing_alg must be EdDSA, ES256, or PS256.",
        ));
    }
    if request
        .application_type
        .as_deref()
        .is_some_and(|value| !matches!(value, "web" | "native"))
    {
        return Err(DynamicRegistrationError::invalid_client_metadata(
            "application_type must be web or native.",
        ));
    }

    let grant_types = request
        .grant_types
        .unwrap_or_else(default_dynamic_client_grant_types);
    let ciba_enabled = grant_types
        .iter()
        .any(|grant| grant == "urn:openid:params:grant-type:ciba");
    if backchannel_token_delivery_mode == "ping" && !ciba_enabled {
        return Err(DynamicRegistrationError::invalid_client_metadata(
            "ping delivery mode requires the CIBA grant type.",
        ));
    }
    if !ciba_enabled
        && request
            .backchannel_authentication_request_signing_alg
            .is_some()
    {
        return Err(DynamicRegistrationError::invalid_client_metadata(
            "backchannel_authentication_request_signing_alg requires the CIBA grant type.",
        ));
    }
    let response_types = match request.response_types {
        Some(values) if values.is_empty() => {
            return Err(DynamicRegistrationError::invalid_client_metadata(
                "response_types must not be empty.",
            ));
        }
        Some(values) => values,
        None if grant_types
            .iter()
            .any(|grant| grant == "authorization_code") =>
        {
            vec!["code".to_owned()]
        }
        None => Vec::new(),
    };
    validate_response_type_relationship(&grant_types, &response_types)?;

    let token_endpoint_auth_method = request
        .token_endpoint_auth_method
        .unwrap_or_else(|| "client_secret_basic".to_owned());
    let client_type = if token_endpoint_auth_method == "none" {
        "public".to_owned()
    } else {
        "confidential".to_owned()
    };
    let scopes = request
        .scope
        .as_deref()
        .map(parse_scope)
        .unwrap_or_else(|| default_dynamic_client_scopes(&grant_types));
    let client_name = request
        .client_name
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "Dynamic OAuth Client".to_owned());

    Ok(PreparedDynamicClientRegistration {
        client_name,
        client_type,
        redirect_uris: request.redirect_uris.unwrap_or_default(),
        post_logout_redirect_uris: request.post_logout_redirect_uris,
        scopes,
        allowed_audiences: vec![policy.default_audience.to_owned()],
        grant_types,
        response_types,
        token_endpoint_auth_method,
        subject_type: request.subject_type,
        sector_identifier_uri: request.sector_identifier_uri,
        require_dpop_bound_tokens: request.dpop_bound_access_tokens,
        require_mtls_bound_tokens: request.tls_client_certificate_bound_access_tokens,
        backchannel_token_delivery_mode,
        backchannel_client_notification_endpoint,
        backchannel_authentication_request_signing_alg: request
            .backchannel_authentication_request_signing_alg,
        backchannel_user_code_parameter: false,
        backchannel_logout_uri: request.backchannel_logout_uri,
        backchannel_logout_session_required: request
            .backchannel_logout_session_required
            .unwrap_or(false),
        frontchannel_logout_uri: request.frontchannel_logout_uri,
        frontchannel_logout_session_required: request
            .frontchannel_logout_session_required
            .unwrap_or(false),
        tls_client_auth_subject_dn: request.tls_client_auth_subject_dn,
        // RFC 8705 defines each PKI subject selector as a single string and
        // requires exactly one selector for tls_client_auth. The internal
        // client model stores selectors as vectors, but RFC 8705 dynamic
        // registration accepts exactly one value for each selector.
        tls_client_auth_cert_sha256: None,
        tls_client_auth_san_dns: request.tls_client_auth_san_dns.into_iter().collect(),
        tls_client_auth_san_uri: request.tls_client_auth_san_uri.into_iter().collect(),
        tls_client_auth_san_ip: request.tls_client_auth_san_ip.into_iter().collect(),
        tls_client_auth_san_email: request.tls_client_auth_san_email.into_iter().collect(),
        jwks_uri,
        jwks: request.jwks,
        request_uris,
        initiate_login_uri,
        presentation,
        id_token_signed_response_alg: request.id_token_signed_response_alg,
        id_token_encrypted_response_alg: request.id_token_encrypted_response_alg,
        id_token_encrypted_response_enc: request.id_token_encrypted_response_enc,
        request_object_signing_alg: request.request_object_signing_alg,
        request_object_encryption_alg: request.request_object_encryption_alg,
        request_object_encryption_enc: request.request_object_encryption_enc,
        token_endpoint_auth_signing_alg: request.token_endpoint_auth_signing_alg,
        introspection_signed_response_alg: request.introspection_signed_response_alg,
        introspection_encrypted_response_alg: request.introspection_encrypted_response_alg,
        introspection_encrypted_response_enc: request.introspection_encrypted_response_enc,
        userinfo_signed_response_alg: request.userinfo_signed_response_alg,
        userinfo_encrypted_response_alg: request.userinfo_encrypted_response_alg,
        userinfo_encrypted_response_enc: request.userinfo_encrypted_response_enc,
        authorization_signed_response_alg: request.authorization_signed_response_alg,
        authorization_encrypted_response_alg: request.authorization_encrypted_response_alg,
        authorization_encrypted_response_enc: request.authorization_encrypted_response_enc,
    })
}

pub fn parse_client_configuration_update(
    mut payload: Value,
    current: &OAuthClient,
    current_has_secret: bool,
    submitted_secret_matches: bool,
) -> Result<DynamicClientRegistrationRequest, DynamicRegistrationError> {
    let Some(object) = payload.as_object_mut() else {
        return Err(DynamicRegistrationError::new(
            "invalid_request",
            "Client configuration update body must be a JSON object.",
        ));
    };
    for field in [
        "registration_access_token",
        "registration_client_uri",
        "client_secret_expires_at",
        "client_id_issued_at",
    ] {
        if object.contains_key(field) {
            return Err(DynamicRegistrationError::new(
                "invalid_request",
                format!("{field} is managed by the authorization server."),
            ));
        }
    }
    let client_id = object
        .remove("client_id")
        .and_then(|value| value.as_str().map(ToOwned::to_owned))
        .ok_or_else(|| {
            DynamicRegistrationError::invalid_client_metadata(
                "client_id must be present in a client configuration update.",
            )
        })?;
    if client_id != current.client_id {
        return Err(DynamicRegistrationError::invalid_client_metadata(
            "client_id must match the client configuration endpoint.",
        ));
    }
    let client_secret = object.remove("client_secret");
    match (current_has_secret, client_secret) {
        (true, Some(Value::String(_))) if submitted_secret_matches => {}
        (true, _) => {
            return Err(DynamicRegistrationError::invalid_client_metadata(
                "client_secret must match the current client secret.",
            ));
        }
        (false, Some(_)) => {
            return Err(DynamicRegistrationError::invalid_client_metadata(
                "public or assertion-based clients must not submit client_secret.",
            ));
        }
        (false, None) => {}
    }
    serde_json::from_value(payload).map_err(|error| {
        DynamicRegistrationError::invalid_client_metadata(format!(
            "Invalid client metadata: {error}"
        ))
    })
}

#[must_use]
pub fn response_types_from_client(client: &OAuthClient) -> Vec<String> {
    if client
        .grant_types
        .iter()
        .any(|grant| grant == "authorization_code")
    {
        vec!["code".to_owned()]
    } else {
        Vec::new()
    }
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

fn negotiate_metadata_choice(
    single_field: &str,
    single: Option<String>,
    choices: Option<Vec<String>>,
    server_supported: &[&str],
) -> Result<Option<String>, DynamicRegistrationError> {
    let Some(choices) = choices else {
        return Ok(single);
    };
    if choices.is_empty() || choices.iter().any(|value| value.trim().is_empty()) {
        return Err(DynamicRegistrationError::invalid_client_metadata(format!(
            "{single_field} choices must contain at least one non-empty value."
        )));
    }
    if let Some(single) = single.as_deref()
        && !choices.iter().any(|choice| choice == single)
    {
        return Err(DynamicRegistrationError::invalid_client_metadata(format!(
            "{single_field} must be included in its values-supported choices."
        )));
    }
    choices
        .into_iter()
        .find(|choice| server_supported.contains(&choice.as_str()))
        .map(Some)
        .ok_or_else(|| {
            DynamicRegistrationError::invalid_client_metadata(format!(
                "No supported {single_field} choice was provided."
            ))
        })
}

fn validate_https_metadata_uri(
    field: &str,
    value: String,
    allow_fragment: bool,
) -> Result<String, DynamicRegistrationError> {
    const MAX_URI_LENGTH: usize = 2048;
    if value.len() > MAX_URI_LENGTH {
        return Err(DynamicRegistrationError::invalid_client_metadata(format!(
            "{field} exceeds {MAX_URI_LENGTH} bytes."
        )));
    }
    let parsed = url::Url::parse(&value).map_err(|_| {
        DynamicRegistrationError::invalid_client_metadata(format!(
            "{field} must be an absolute HTTPS URI."
        ))
    })?;
    if parsed.scheme() != "https"
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || (!allow_fragment && parsed.fragment().is_some())
    {
        return Err(DynamicRegistrationError::invalid_client_metadata(format!(
            "{field} must be an absolute HTTPS URI without userinfo{}.",
            if allow_fragment { "" } else { " or fragment" }
        )));
    }
    Ok(value)
}

fn validate_request_uris(values: Vec<String>) -> Result<Vec<String>, DynamicRegistrationError> {
    const MAX_REQUEST_URIS: usize = 10;
    const MAX_REQUEST_URI_LENGTH: usize = 512;
    if values.len() > MAX_REQUEST_URIS {
        return Err(DynamicRegistrationError::invalid_client_metadata(format!(
            "request_uris must contain at most {MAX_REQUEST_URIS} entries."
        )));
    }
    let mut unique = std::collections::BTreeSet::new();
    for value in &values {
        if value.len() > MAX_REQUEST_URI_LENGTH {
            return Err(DynamicRegistrationError::invalid_client_metadata(format!(
                "request_uris entries must not exceed {MAX_REQUEST_URI_LENGTH} bytes."
            )));
        }
        validate_https_metadata_uri("request_uris entry", value.clone(), true)?;
        if !unique.insert(value) {
            return Err(DynamicRegistrationError::invalid_client_metadata(
                "request_uris must not contain duplicates.",
            ));
        }
    }
    Ok(values)
}

fn validate_response_type_relationship(
    grant_types: &[String],
    response_types: &[String],
) -> Result<(), DynamicRegistrationError> {
    if response_types
        .iter()
        .any(|response_type| response_type != "code")
    {
        return Err(DynamicRegistrationError::invalid_client_metadata(
            "only code response type is supported.",
        ));
    }
    let has_code_grant = grant_types
        .iter()
        .any(|grant| grant == "authorization_code");
    let has_code_response = response_types.iter().any(|response| response == "code");
    if has_code_grant != has_code_response {
        return Err(DynamicRegistrationError::invalid_client_metadata(
            "authorization_code grant requires code response type.",
        ));
    }
    Ok(())
}

fn default_dynamic_client_scopes(grant_types: &[String]) -> Vec<String> {
    if !grant_types
        .iter()
        .any(|grant| grant == "authorization_code")
    {
        return Vec::new();
    }
    let mut scopes = ["openid", "profile", "email", "address", "phone"]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if grant_types.iter().any(|grant| grant == "refresh_token") {
        scopes.push("offline_access".to_owned());
    }
    scopes
}

fn default_dynamic_client_grant_types() -> Vec<String> {
    ["authorization_code", "refresh_token"]
        .into_iter()
        .map(str::to_owned)
        .collect()
}

#[cfg(test)]
#[path = "../tests/unit/dynamic_client_registration.rs"]
mod tests;
