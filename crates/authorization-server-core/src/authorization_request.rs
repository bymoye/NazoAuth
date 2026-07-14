use std::collections::HashMap;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Validation, decode, decode_header};
use serde::Deserialize;
use serde_json::Value;

use crate::{
    AuthorizationPortError, RedirectUriError, is_subset, parse_resource_indicator_parameter,
    resolve_registered_redirect_uri,
};
use crate::{
    OAuthClient,
    client_assertion::{client_jwt_decoding_key, supported_client_jwt_algorithm_name},
};

pub const REQUEST_OBJECT_MAX_TTL_SECONDS: i64 = 300;
pub const REQUEST_OBJECT_CLOCK_SKEW_SECONDS: i64 = 30;

const AUTHORIZATION_REQUEST_PARAMETERS: &[&str] = &[
    "response_type",
    "client_id",
    "redirect_uri",
    "scope",
    "resource",
    "authorization_details",
    "state",
    "code_challenge",
    "code_challenge_method",
    "nonce",
    "claims",
    "acr_values",
    "prompt",
    "max_age",
    "dpop_jkt",
    "response_mode",
    "request_uri",
    "request",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestObjectMode {
    BasicOidc,
    SignedJar,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestObjectJtiPolicy {
    Optional,
    RequiredForSignedJar,
}

/// Claims obtained after the protocol core has decoded and, for signed
/// request objects, cryptographically verified the compact JWT.
#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct RequestObjectClaims {
    pub client_id: String,
    pub iss: Option<String>,
    pub sub: Option<String>,
    pub aud: Option<Value>,
    pub exp: Option<i64>,
    pub nbf: Option<i64>,
    pub iat: Option<i64>,
    pub jti: Option<String>,
    #[serde(flatten)]
    pub parameters: HashMap<String, Value>,
}

#[derive(Clone, Copy, Debug)]
pub struct RequestObjectPolicy<'a> {
    pub issuer: &'a str,
    pub client_id: &'a str,
    pub mode: RequestObjectMode,
    pub jti_policy: RequestObjectJtiPolicy,
    pub unsigned_request_object_allowed: bool,
    pub require_integrity_protected_parameters: bool,
    pub now: i64,
}

#[derive(Clone, Copy)]
pub struct RequestObjectVerificationInput<'a> {
    pub request_object: &'a str,
    pub client: &'a OAuthClient,
    pub profile_disallows_unsigned_request_object: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct VerifiedRequestObject {
    pub claims: RequestObjectClaims,
    pub mode: RequestObjectMode,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestObjectVerificationError {
    InvalidCompact,
    InvalidHeader,
    InvalidClaims,
    InvalidAlgorithm,
    MissingKeyId,
    InvalidKey,
    InvalidSignature,
    SigningPolicy,
}

#[derive(Deserialize)]
struct RequestObjectHeader {
    alg: String,
}

/// Parses and verifies a compact authorization Request Object.
///
/// All protocol cryptography and JWK policy live here. The caller supplies an
/// already loaded client and remains responsible for runtime-module admission
/// and committing the replay marker through [`crate::AuthorizationService`].
pub fn verify_request_object(
    input: RequestObjectVerificationInput<'_>,
) -> Result<VerifiedRequestObject, RequestObjectVerificationError> {
    let (header_part, payload_part, signature_part) = split_compact_jwt(input.request_object)
        .ok_or(RequestObjectVerificationError::InvalidCompact)?;
    let decoded_header = decode_request_object_header(header_part)?;
    let (claims, mode) = if decoded_header.alg == "none" {
        if payload_part.is_empty() || !signature_part.is_empty() {
            return Err(RequestObjectVerificationError::InvalidAlgorithm);
        }
        (
            decode_request_object_claims(payload_part)?,
            RequestObjectMode::BasicOidc,
        )
    } else {
        if signature_part.is_empty() {
            return Err(RequestObjectVerificationError::InvalidAlgorithm);
        }
        let header = decode_header(input.request_object)
            .map_err(|_| RequestObjectVerificationError::InvalidAlgorithm)?;
        if supported_client_jwt_algorithm_name(header.alg).is_none() {
            return Err(RequestObjectVerificationError::InvalidAlgorithm);
        }
        let kid = header
            .kid
            .as_deref()
            .ok_or(RequestObjectVerificationError::MissingKeyId)?;
        if kid.trim().is_empty() || kid.trim() != kid {
            return Err(RequestObjectVerificationError::InvalidKey);
        }
        let decoding_key = client_jwt_decoding_key(input.client, kid, header.alg)
            .ok_or(RequestObjectVerificationError::InvalidKey)?;
        let mut validation = Validation::new(header.alg);
        validation.validate_aud = false;
        validation.validate_exp = false;
        validation.validate_nbf = false;
        validation.set_required_spec_claims::<&str>(&[]);
        let claims =
            decode::<RequestObjectClaims>(input.request_object, &decoding_key, &validation)
                .map_err(|_| RequestObjectVerificationError::InvalidSignature)?
                .claims;
        (claims, RequestObjectMode::SignedJar)
    };
    if !request_object_mode_allowed(
        input.client,
        mode,
        input.profile_disallows_unsigned_request_object,
    ) {
        return Err(RequestObjectVerificationError::SigningPolicy);
    }
    Ok(VerifiedRequestObject { claims, mode })
}

#[must_use]
pub fn request_object_uses_unsigned_algorithm(request_object: &str) -> bool {
    let Some((header, _payload, signature)) = split_compact_jwt(request_object) else {
        return false;
    };
    let Ok(header) = decode_request_object_header(header) else {
        return false;
    };
    header.alg == "none" && signature.is_empty()
}

#[must_use]
pub fn unverified_signed_request_object_client_id(request_object: &str) -> Option<String> {
    let (header, payload, signature) = split_compact_jwt(request_object)?;
    let header = decode_request_object_header(header).ok()?;
    if header.alg == "none" || signature.is_empty() {
        return None;
    }
    let claims = decode_request_object_claims(payload).ok()?;
    let issuer_matches = claims
        .iss
        .as_deref()
        .is_none_or(|issuer| issuer == claims.client_id);
    let subject_matches = claims
        .sub
        .as_deref()
        .is_none_or(|subject| subject == claims.client_id);
    (issuer_matches && subject_matches && !claims.client_id.trim().is_empty())
        .then_some(claims.client_id)
}

fn split_compact_jwt(token: &str) -> Option<(&str, &str, &str)> {
    let mut parts = token.split('.');
    let header = parts.next()?;
    let payload = parts.next()?;
    let signature = parts.next()?;
    parts
        .next()
        .is_none()
        .then_some((header, payload, signature))
}

fn decode_request_object_header(
    header: &str,
) -> Result<RequestObjectHeader, RequestObjectVerificationError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(header)
        .map_err(|_| RequestObjectVerificationError::InvalidHeader)?;
    serde_json::from_slice(&bytes).map_err(|_| RequestObjectVerificationError::InvalidHeader)
}

fn decode_request_object_claims(
    payload: &str,
) -> Result<RequestObjectClaims, RequestObjectVerificationError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| RequestObjectVerificationError::InvalidClaims)?;
    serde_json::from_slice(&bytes).map_err(|_| RequestObjectVerificationError::InvalidClaims)
}

fn request_object_mode_allowed(
    client: &OAuthClient,
    mode: RequestObjectMode,
    profile_disallows_unsigned_request_object: bool,
) -> bool {
    !((client.require_dpop_bound_tokens
        || client.require_par_request_object
        || profile_disallows_unsigned_request_object)
        && mode == RequestObjectMode::BasicOidc)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestObjectReplay {
    pub client_id: String,
    pub jti: String,
    pub ttl_seconds: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedRequestObject {
    pub parameters: HashMap<String, String>,
    pub replay: Option<RequestObjectReplay>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorizationRequestError {
    InvalidRequest,
    InvalidRequestObject,
    RequestObjectSigningPolicy,
    RequestObjectClaims,
    RequestObjectContainsRequestUri,
    RequestObjectParameterType,
    OuterClientIdConflict,
    SignedRequestObjectMissingRedirectUri,
    OuterAuthorizationParametersConflict,
    InvalidRequestObjectReplay,
    InvalidTarget,
    UnsupportedResponseType,
    UnauthorizedClient,
    InvalidClient,
    Dependency(AuthorizationPortError),
}

impl AuthorizationRequestError {
    #[must_use]
    pub const fn oauth_error(self) -> &'static str {
        match self {
            Self::InvalidRequest | Self::OuterClientIdConflict => "invalid_request",
            Self::InvalidRequestObject
            | Self::RequestObjectSigningPolicy
            | Self::RequestObjectClaims
            | Self::RequestObjectContainsRequestUri
            | Self::RequestObjectParameterType
            | Self::SignedRequestObjectMissingRedirectUri
            | Self::OuterAuthorizationParametersConflict
            | Self::InvalidRequestObjectReplay => "invalid_request_object",
            Self::InvalidTarget => "invalid_target",
            Self::UnsupportedResponseType => "unsupported_response_type",
            Self::UnauthorizedClient => "unauthorized_client",
            Self::InvalidClient => "invalid_client",
            Self::Dependency(_) => "server_error",
        }
    }
}

/// Applies request-object claim and parameter policy after signature handling.
/// No replay state is mutated until all pure validation has succeeded.
pub fn normalize_request_object(
    outer: &HashMap<String, String>,
    claims: &RequestObjectClaims,
    policy: RequestObjectPolicy<'_>,
) -> Result<NormalizedRequestObject, AuthorizationRequestError> {
    if policy.mode == RequestObjectMode::BasicOidc && !policy.unsigned_request_object_allowed {
        return Err(AuthorizationRequestError::RequestObjectSigningPolicy);
    }
    if claims.client_id != policy.client_id
        || !request_object_party_claims_valid(claims, policy)
        || !request_object_audience_valid(claims, policy)
        || !request_object_times_valid(claims, policy)
        || !request_object_jti_valid(claims, policy)
    {
        return Err(AuthorizationRequestError::RequestObjectClaims);
    }

    let mut request_parameters = request_object_parameters(claims)?;
    request_parameters.insert("client_id".to_owned(), claims.client_id.clone());
    if outer
        .get("client_id")
        .is_some_and(|outer_client_id| outer_client_id != &claims.client_id)
    {
        return Err(AuthorizationRequestError::OuterClientIdConflict);
    }
    if policy.mode == RequestObjectMode::SignedJar
        && !request_parameters.contains_key("redirect_uri")
    {
        return Err(AuthorizationRequestError::SignedRequestObjectMissingRedirectUri);
    }
    if policy.require_integrity_protected_parameters
        && outer_authorization_parameters_conflict(outer, &request_parameters)
    {
        return Err(AuthorizationRequestError::OuterAuthorizationParametersConflict);
    }

    let replay = request_object_replay(claims, policy)?;
    let mut parameters = outer.clone();
    if policy.require_integrity_protected_parameters {
        parameters.retain(|key, _| matches!(key.as_str(), "request" | "client_id"));
    } else {
        parameters.retain(|key, _| key == "request" || !request_parameters.contains_key(key));
    }
    parameters.extend(request_parameters);
    Ok(NormalizedRequestObject { parameters, replay })
}

fn request_object_party_claims_valid(
    claims: &RequestObjectClaims,
    policy: RequestObjectPolicy<'_>,
) -> bool {
    match policy.mode {
        RequestObjectMode::BasicOidc => {
            claims
                .iss
                .as_deref()
                .is_none_or(|issuer| issuer == policy.client_id)
                && claims
                    .sub
                    .as_deref()
                    .is_none_or(|subject| subject == policy.client_id)
        }
        RequestObjectMode::SignedJar => {
            claims.iss.as_deref() == Some(policy.client_id)
                && claims
                    .sub
                    .as_deref()
                    .is_none_or(|subject| subject == policy.client_id)
        }
    }
}

fn request_object_audience_valid(
    claims: &RequestObjectClaims,
    policy: RequestObjectPolicy<'_>,
) -> bool {
    match (&claims.aud, policy.mode) {
        (Some(Value::String(audience)), _) => {
            audience == policy.issuer || audience == &format!("{}/authorize", policy.issuer)
        }
        (Some(Value::Array(audiences)), _) => audiences.iter().any(|audience| {
            audience.as_str().is_some_and(|audience| {
                audience == policy.issuer || audience == format!("{}/authorize", policy.issuer)
            })
        }),
        (None, RequestObjectMode::BasicOidc) => true,
        _ => false,
    }
}

fn request_object_times_valid(
    claims: &RequestObjectClaims,
    policy: RequestObjectPolicy<'_>,
) -> bool {
    let now = policy.now;
    let expiry = match claims.exp {
        Some(expiry) if expiry <= now => return false,
        Some(expiry) => expiry,
        None if policy.mode == RequestObjectMode::SignedJar => return false,
        None => now.saturating_add(REQUEST_OBJECT_MAX_TTL_SECONDS),
    };
    let not_before = match claims.nbf {
        Some(not_before) => not_before,
        None if policy.mode == RequestObjectMode::SignedJar => return false,
        None => now,
    };
    if not_before > now.saturating_add(REQUEST_OBJECT_CLOCK_SKEW_SECONDS) {
        return false;
    }
    if policy.mode == RequestObjectMode::SignedJar {
        if now.saturating_sub(not_before) > REQUEST_OBJECT_MAX_TTL_SECONDS
            || expiry <= not_before
            || expiry.saturating_sub(not_before)
                > REQUEST_OBJECT_MAX_TTL_SECONDS.saturating_add(REQUEST_OBJECT_CLOCK_SKEW_SECONDS)
        {
            return false;
        }
    } else if expiry > now.saturating_add(REQUEST_OBJECT_MAX_TTL_SECONDS) {
        return false;
    }
    !claims.iat.is_some_and(|issued_at| {
        issued_at > now.saturating_add(REQUEST_OBJECT_CLOCK_SKEW_SECONDS)
            || now.saturating_sub(issued_at) > REQUEST_OBJECT_MAX_TTL_SECONDS
    })
}

fn request_object_jti_valid(claims: &RequestObjectClaims, policy: RequestObjectPolicy<'_>) -> bool {
    match (&claims.jti, policy.mode) {
        (Some(jti), _) => {
            let jti = jti.trim();
            !jti.is_empty() && jti.len() <= 128
        }
        (None, RequestObjectMode::SignedJar)
            if policy.jti_policy == RequestObjectJtiPolicy::RequiredForSignedJar =>
        {
            false
        }
        (None, _) => true,
    }
}

fn request_object_replay(
    claims: &RequestObjectClaims,
    policy: RequestObjectPolicy<'_>,
) -> Result<Option<RequestObjectReplay>, AuthorizationRequestError> {
    let Some(jti) = claims.jti.as_ref() else {
        return Ok(None);
    };
    let ttl_seconds = match claims.exp {
        Some(expiry) => expiry
            .saturating_sub(policy.now)
            .clamp(1, REQUEST_OBJECT_MAX_TTL_SECONDS) as u64,
        None if policy.mode == RequestObjectMode::BasicOidc => {
            REQUEST_OBJECT_MAX_TTL_SECONDS as u64
        }
        None => return Err(AuthorizationRequestError::RequestObjectClaims),
    };
    Ok(Some(RequestObjectReplay {
        client_id: claims.client_id.clone(),
        jti: jti.clone(),
        ttl_seconds,
    }))
}

fn request_object_parameters(
    claims: &RequestObjectClaims,
) -> Result<HashMap<String, String>, AuthorizationRequestError> {
    if claims.parameters.contains_key("request_uri") {
        return Err(AuthorizationRequestError::RequestObjectContainsRequestUri);
    }
    let mut parameters = HashMap::new();
    for key in AUTHORIZATION_REQUEST_PARAMETERS {
        if matches!(*key, "request" | "request_uri" | "client_id") {
            continue;
        }
        let Some(value) = claims.parameters.get(*key) else {
            continue;
        };
        let value = match value {
            Value::String(value) => value.clone(),
            Value::Number(value) => value.to_string(),
            Value::Object(_) if *key == "claims" => value.to_string(),
            Value::Array(_) if matches!(*key, "authorization_details" | "resource") => {
                value.to_string()
            }
            _ => return Err(AuthorizationRequestError::RequestObjectParameterType),
        };
        parameters.insert((*key).to_owned(), value);
    }
    Ok(parameters)
}

fn outer_authorization_parameters_conflict(
    outer: &HashMap<String, String>,
    request: &HashMap<String, String>,
) -> bool {
    AUTHORIZATION_REQUEST_PARAMETERS.iter().any(|key| {
        if matches!(*key, "request" | "request_uri" | "client_id") {
            return false;
        }
        let (Some(outer), Some(request)) = (outer.get(*key), request.get(*key)) else {
            return false;
        };
        if *key == "resource" {
            parse_resource_indicator_parameter(Some(outer)).ok()
                != parse_resource_indicator_parameter(Some(request)).ok()
        } else {
            outer != request
        }
    })
}

#[derive(Clone, Copy, Debug)]
pub struct RawParAdmissionPolicy<'a> {
    pub client_is_confidential: bool,
    pub client_authentication_method: &'a str,
    pub require_dpop_bound_tokens: bool,
    pub require_mtls_bound_tokens: bool,
    pub require_request_object: bool,
    pub fapi2_security: bool,
}

#[derive(Clone, Copy, Debug)]
pub struct ExpandedParAdmissionPolicy<'a> {
    pub client_type: &'a str,
    pub redirect_uris: &'a [String],
    pub allowed_audiences: &'a [String],
    pub fapi2_requires_explicit_redirect_uri: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParAdmission {
    pub redirect_uri: String,
    pub resources: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParAdmissionError {
    RequestUriNotAllowed,
    UnsupportedResponseType,
    RequestObjectRequired,
    ConfidentialClientRequired,
    StrongClientAuthenticationRequired,
    SenderConstraintRequired,
    ExplicitRedirectUriRequired,
    RedirectUriRequired,
    RedirectUriNotRegistered,
    InvalidResource,
    ResourceNotAllowed,
}

impl ParAdmissionError {
    #[must_use]
    pub const fn oauth_error(self) -> &'static str {
        match self {
            Self::RequestUriNotAllowed => "invalid_request_object",
            Self::UnsupportedResponseType => "unsupported_response_type",
            Self::ConfidentialClientRequired => "unauthorized_client",
            Self::StrongClientAuthenticationRequired => "invalid_client",
            Self::RequestObjectRequired
            | Self::SenderConstraintRequired
            | Self::ExplicitRedirectUriRequired
            | Self::RedirectUriRequired
            | Self::RedirectUriNotRegistered => "invalid_request",
            Self::InvalidResource | Self::ResourceNotAllowed => "invalid_target",
        }
    }
}

/// Validates client and raw-form policy after client authentication, before a
/// signed Request Object is expanded. Authentication parameters remain a
/// transport concern and are not accepted by this policy function.
pub fn validate_raw_par_admission(
    parameters: &HashMap<String, String>,
    policy: RawParAdmissionPolicy<'_>,
) -> Result<(), ParAdmissionError> {
    if policy.fapi2_security {
        if !policy.client_is_confidential {
            return Err(ParAdmissionError::ConfidentialClientRequired);
        }
        if !matches!(
            policy.client_authentication_method,
            "private_key_jwt" | "tls_client_auth" | "self_signed_tls_client_auth"
        ) {
            return Err(ParAdmissionError::StrongClientAuthenticationRequired);
        }
        if !(policy.require_dpop_bound_tokens || policy.require_mtls_bound_tokens) {
            return Err(ParAdmissionError::SenderConstraintRequired);
        }
    }
    if policy.require_request_object && !parameters.contains_key("request") {
        return Err(ParAdmissionError::RequestObjectRequired);
    }
    Ok(())
}

/// Validates the authorization parameters after any signed Request Object has
/// been expanded, but before DPoP verification or PAR state persistence.
pub fn validate_expanded_par_admission(
    parameters: &HashMap<String, String>,
    policy: ExpandedParAdmissionPolicy<'_>,
) -> Result<ParAdmission, ParAdmissionError> {
    if parameters.contains_key("request_uri") {
        return Err(ParAdmissionError::RequestUriNotAllowed);
    }
    if parameters
        .get("response_type")
        .is_some_and(|response_type| response_type != "code")
    {
        return Err(ParAdmissionError::UnsupportedResponseType);
    }
    if policy.fapi2_requires_explicit_redirect_uri && !parameters.contains_key("redirect_uri") {
        return Err(ParAdmissionError::ExplicitRedirectUriRequired);
    }
    let redirect_uri = resolve_registered_redirect_uri(
        policy.client_type,
        policy.redirect_uris,
        parameters.get("redirect_uri").map(String::as_str),
    )
    .map_err(|error| match error {
        RedirectUriError::Missing => ParAdmissionError::RedirectUriRequired,
        RedirectUriError::Invalid => ParAdmissionError::RedirectUriNotRegistered,
    })?;
    let resources =
        parse_resource_indicator_parameter(parameters.get("resource").map(String::as_str))
            .map_err(|_| ParAdmissionError::InvalidResource)?;
    if !resources.is_empty() && !is_subset(&resources, policy.allowed_audiences) {
        return Err(ParAdmissionError::ResourceNotAllowed);
    }
    Ok(ParAdmission {
        redirect_uri,
        resources,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PushedAuthorizationRequestConsumeError {
    Missing,
    Malformed,
    Dependency(AuthorizationPortError),
}

pub(crate) fn classify_request_object_replay(
    result: Result<bool, AuthorizationPortError>,
) -> Result<(), AuthorizationRequestError> {
    match result {
        Ok(true) => Ok(()),
        Ok(false) => Err(AuthorizationRequestError::InvalidRequestObjectReplay),
        Err(error) => Err(AuthorizationRequestError::Dependency(error)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer as _, SigningKey};
    use proptest::prelude::*;
    use serde_json::json;
    use uuid::Uuid;

    use crate::ValidatedClientRegistration;

    const JAR_SIGNING_KEY: [u8; 32] = [29; 32];

    fn request_object_client(jwks: Value) -> OAuthClient {
        OAuthClient {
            id: Uuid::from_u128(1),
            tenant_id: Uuid::from_u128(2),
            realm_id: Uuid::from_u128(3),
            organization_id: Uuid::from_u128(4),
            registration: ValidatedClientRegistration {
                client_id: "client".to_owned(),
                client_name: "Client".to_owned(),
                client_type: "confidential".to_owned(),
                redirect_uris: vec!["https://client.example/cb".to_owned()],
                post_logout_redirect_uris: Vec::new(),
                scopes: vec!["openid".to_owned()],
                allowed_audiences: Vec::new(),
                grant_types: vec!["authorization_code".to_owned()],
                token_endpoint_auth_method: "private_key_jwt".to_owned(),
                subject_type: "public".to_owned(),
                sector_identifier_uri: None,
                sector_identifier_host: None,
                require_dpop_bound_tokens: false,
                allow_client_assertion_audience_array: false,
                allow_client_assertion_endpoint_audience: false,
                require_par_request_object: false,
                allow_authorization_code_without_pkce: false,
                backchannel_logout_uri: None,
                backchannel_logout_session_required: true,
                frontchannel_logout_uri: None,
                frontchannel_logout_session_required: true,
                tls_client_auth_subject_dn: None,
                tls_client_auth_cert_sha256: None,
                tls_client_auth_san_dns: Vec::new(),
                tls_client_auth_san_uri: Vec::new(),
                tls_client_auth_san_ip: Vec::new(),
                tls_client_auth_san_email: Vec::new(),
                jwks: Some(jwks),
                introspection_encrypted_response_alg: None,
                introspection_encrypted_response_enc: None,
                userinfo_signed_response_alg: None,
                userinfo_encrypted_response_alg: None,
                userinfo_encrypted_response_enc: None,
                authorization_signed_response_alg: None,
                authorization_encrypted_response_alg: None,
                authorization_encrypted_response_enc: None,
            },
            require_mtls_bound_tokens: false,
            is_active: true,
        }
    }

    fn request_object_public_jwk() -> Value {
        let verifying_key = SigningKey::from_bytes(&JAR_SIGNING_KEY).verifying_key();
        json!({
            "kid": "jar-key",
            "kty": "OKP",
            "crv": "Ed25519",
            "alg": "EdDSA",
            "use": "sig",
            "key_ops": ["verify"],
            "x": URL_SAFE_NO_PAD.encode(verifying_key.as_bytes()),
        })
    }

    fn signed_request_object(claims: &Value, header: Value) -> String {
        let header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).unwrap());
        let signing_input = format!("{header}.{payload}");
        let signature = SigningKey::from_bytes(&JAR_SIGNING_KEY).sign(signing_input.as_bytes());
        format!(
            "{signing_input}.{}",
            URL_SAFE_NO_PAD.encode(signature.to_bytes())
        )
    }

    fn signed_request_object_json(now: i64) -> Value {
        json!({
            "client_id": "client",
            "iss": "client",
            "sub": "client",
            "aud": "https://issuer.example",
            "exp": now + 120,
            "nbf": now,
            "iat": now,
            "jti": "unique",
            "response_type": "code",
            "redirect_uri": "https://client.example/cb",
            "scope": "openid"
        })
    }

    fn signed_policy(now: i64) -> RequestObjectPolicy<'static> {
        RequestObjectPolicy {
            issuer: "https://issuer.example",
            client_id: "client",
            mode: RequestObjectMode::SignedJar,
            jti_policy: RequestObjectJtiPolicy::RequiredForSignedJar,
            unsigned_request_object_allowed: false,
            require_integrity_protected_parameters: true,
            now,
        }
    }

    fn signed_claims(now: i64) -> RequestObjectClaims {
        RequestObjectClaims {
            client_id: "client".to_owned(),
            iss: Some("client".to_owned()),
            sub: Some("client".to_owned()),
            aud: Some(json!(["unrelated", "https://issuer.example/authorize"])),
            exp: Some(now + 120),
            nbf: Some(now - 1),
            iat: Some(now - 1),
            jti: Some("unique".to_owned()),
            parameters: HashMap::from([
                (
                    "redirect_uri".to_owned(),
                    json!("https://client.example/cb"),
                ),
                ("scope".to_owned(), json!("openid")),
            ]),
        }
    }

    #[test]
    fn signed_request_object_is_normalized_only_after_all_claim_checks() {
        let now = 1_700_000_000;
        let outer = HashMap::from([
            ("client_id".to_owned(), "client".to_owned()),
            ("request".to_owned(), "jwt".to_owned()),
            ("scope".to_owned(), "openid".to_owned()),
            ("state".to_owned(), "unprotected".to_owned()),
        ]);
        let normalized = normalize_request_object(&outer, &signed_claims(now), signed_policy(now))
            .expect("valid signed request object");
        assert_eq!(
            normalized.parameters.get("scope").map(String::as_str),
            Some("openid")
        );
        assert!(!normalized.parameters.contains_key("state"));
        assert_eq!(
            normalized.replay.expect("replay instruction").ttl_seconds,
            120
        );
    }

    #[test]
    fn signed_request_object_crypto_uses_strict_shared_client_jwk_policy() {
        let now = 1_700_000_000;
        let token = signed_request_object(
            &signed_request_object_json(now),
            json!({"alg": "EdDSA", "kid": "jar-key"}),
        );
        let client = request_object_client(json!({"keys": [request_object_public_jwk()]}));
        let verified = verify_request_object(RequestObjectVerificationInput {
            request_object: &token,
            client: &client,
            profile_disallows_unsigned_request_object: true,
        })
        .expect("valid signed Request Object");
        assert_eq!(verified.mode, RequestObjectMode::SignedJar);
        assert_eq!(verified.claims.client_id, "client");

        let duplicate = request_object_client(json!({
            "keys": [request_object_public_jwk(), request_object_public_jwk()]
        }));
        assert_eq!(
            verify_request_object(RequestObjectVerificationInput {
                request_object: &token,
                client: &duplicate,
                profile_disallows_unsigned_request_object: true,
            }),
            Err(RequestObjectVerificationError::InvalidKey)
        );

        for (member, value) in [
            ("d", json!("private")),
            ("k", json!("symmetric")),
            ("key_ops", json!(["sign", "verify"])),
            ("use", json!("enc")),
        ] {
            let mut key = request_object_public_jwk();
            key[member] = value;
            let client = request_object_client(json!({"keys": [key]}));
            assert_eq!(
                verify_request_object(RequestObjectVerificationInput {
                    request_object: &token,
                    client: &client,
                    profile_disallows_unsigned_request_object: true,
                }),
                Err(RequestObjectVerificationError::InvalidKey),
                "accepted invalid JWK member {member}"
            );
        }
    }

    #[test]
    fn signed_request_object_crypto_defers_time_policy_to_injected_clock() {
        let now = 1_700_000_000;
        let token = signed_request_object(
            &signed_request_object_json(now),
            json!({"alg": "EdDSA", "kid": "jar-key"}),
        );
        let client = request_object_client(json!({"keys": [request_object_public_jwk()]}));
        let verified = verify_request_object(RequestObjectVerificationInput {
            request_object: &token,
            client: &client,
            profile_disallows_unsigned_request_object: true,
        })
        .expect("signature verification must not use the process wall clock");
        assert!(
            normalize_request_object(&HashMap::new(), &verified.claims, signed_policy(now)).is_ok()
        );
        assert_eq!(
            normalize_request_object(&HashMap::new(), &verified.claims, signed_policy(now + 121)),
            Err(AuthorizationRequestError::RequestObjectClaims)
        );
    }

    #[test]
    fn compact_shape_algorithm_key_and_signature_errors_remain_distinct() {
        let now = 1_700_000_000;
        let claims = signed_request_object_json(now);
        let client = request_object_client(json!({"keys": [request_object_public_jwk()]}));
        for (request_object, expected) in [
            ("one.two", RequestObjectVerificationError::InvalidCompact),
            ("!.payload.", RequestObjectVerificationError::InvalidHeader),
            (
                &signed_request_object(&claims, json!({"alg": "HS256", "kid": "jar-key"})),
                RequestObjectVerificationError::InvalidAlgorithm,
            ),
            (
                &signed_request_object(&claims, json!({"alg": "EdDSA"})),
                RequestObjectVerificationError::MissingKeyId,
            ),
            (
                &signed_request_object(&claims, json!({"alg": "EdDSA", "kid": " "})),
                RequestObjectVerificationError::InvalidKey,
            ),
        ] {
            assert_eq!(
                verify_request_object(RequestObjectVerificationInput {
                    request_object,
                    client: &client,
                    profile_disallows_unsigned_request_object: false,
                }),
                Err(expected)
            );
        }
        let valid = signed_request_object(&claims, json!({"alg": "EdDSA", "kid": "jar-key"}));
        let signing_input = valid.rsplit_once('.').unwrap().0;
        let invalid_signature = format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode([0; 64]));
        assert_eq!(
            verify_request_object(RequestObjectVerificationInput {
                request_object: &invalid_signature,
                client: &client,
                profile_disallows_unsigned_request_object: false,
            }),
            Err(RequestObjectVerificationError::InvalidSignature)
        );
    }

    #[test]
    fn unsigned_request_objects_preserve_mode_policy_and_client_id_discovery() {
        let claims = signed_request_object_json(1_700_000_000);
        let unsigned = format!(
            "{}.{}.",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&json!({"alg": "none"})).unwrap()),
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap())
        );
        let client = request_object_client(json!({"keys": [request_object_public_jwk()]}));
        assert!(request_object_uses_unsigned_algorithm(&unsigned));
        assert_eq!(
            verify_request_object(RequestObjectVerificationInput {
                request_object: &unsigned,
                client: &client,
                profile_disallows_unsigned_request_object: true,
            }),
            Err(RequestObjectVerificationError::SigningPolicy)
        );
        let mut sender_constrained = client.clone();
        sender_constrained.require_dpop_bound_tokens = true;
        assert_eq!(
            verify_request_object(RequestObjectVerificationInput {
                request_object: &unsigned,
                client: &sender_constrained,
                profile_disallows_unsigned_request_object: false,
            }),
            Err(RequestObjectVerificationError::SigningPolicy)
        );
        let mut par_required = client.clone();
        par_required.require_par_request_object = true;
        assert_eq!(
            verify_request_object(RequestObjectVerificationInput {
                request_object: &unsigned,
                client: &par_required,
                profile_disallows_unsigned_request_object: false,
            }),
            Err(RequestObjectVerificationError::SigningPolicy)
        );
        let signed = signed_request_object(&claims, json!({"alg": "EdDSA", "kid": "jar-key"}));
        assert_eq!(
            unverified_signed_request_object_client_id(&signed).as_deref(),
            Some("client")
        );
        let unsupported = signed_request_object(&claims, json!({"alg": "HS256", "kid": "jar-key"}));
        assert_eq!(
            unverified_signed_request_object_client_id(&unsupported).as_deref(),
            Some("client")
        );
        assert_eq!(unverified_signed_request_object_client_id(&unsigned), None);
    }

    #[test]
    fn signed_request_object_rejects_conflicts_and_reserved_request_uri() {
        let now = 1_700_000_000;
        let claims = signed_claims(now);
        let conflicting = HashMap::from([
            ("client_id".to_owned(), "client".to_owned()),
            ("scope".to_owned(), "email".to_owned()),
        ]);
        assert_eq!(
            normalize_request_object(&conflicting, &claims, signed_policy(now)),
            Err(AuthorizationRequestError::OuterAuthorizationParametersConflict)
        );
        let mut claims = claims;
        claims
            .parameters
            .insert("request_uri".to_owned(), json!("urn:forbidden"));
        assert_eq!(
            normalize_request_object(&HashMap::new(), &claims, signed_policy(now)),
            Err(AuthorizationRequestError::RequestObjectContainsRequestUri)
        );
    }

    #[test]
    fn replay_and_dependency_failures_are_fail_closed_and_keep_error_categories() {
        assert_eq!(classify_request_object_replay(Ok(true)), Ok(()));
        assert_eq!(
            classify_request_object_replay(Ok(false)),
            Err(AuthorizationRequestError::InvalidRequestObjectReplay)
        );
        assert_eq!(
            classify_request_object_replay(Err(AuthorizationPortError::Unavailable)),
            Err(AuthorizationRequestError::Dependency(
                AuthorizationPortError::Unavailable
            ))
        );
    }

    #[test]
    fn par_fapi_policy_requires_confidential_strong_auth_and_sender_constraint() {
        let redirect_uris = vec!["https://client.example/cb".to_owned()];
        let audiences = vec!["https://api.example".to_owned()];
        let parameters = HashMap::from([
            ("response_type".to_owned(), "code".to_owned()),
            ("redirect_uri".to_owned(), redirect_uris[0].clone()),
            ("request".to_owned(), "signed.jwt".to_owned()),
            (
                "resource".to_owned(),
                "[\"https://api.example\"]".to_owned(),
            ),
        ]);
        let raw = RawParAdmissionPolicy {
            client_is_confidential: true,
            client_authentication_method: "private_key_jwt",
            require_dpop_bound_tokens: true,
            require_mtls_bound_tokens: false,
            require_request_object: true,
            fapi2_security: true,
        };
        let expanded = ExpandedParAdmissionPolicy {
            client_type: "confidential",
            redirect_uris: &redirect_uris,
            allowed_audiences: &audiences,
            fapi2_requires_explicit_redirect_uri: true,
        };
        assert!(validate_raw_par_admission(&parameters, raw).is_ok());
        assert!(validate_expanded_par_admission(&parameters, expanded).is_ok());
        assert_eq!(
            validate_raw_par_admission(
                &parameters,
                RawParAdmissionPolicy {
                    client_is_confidential: false,
                    ..raw
                }
            ),
            Err(ParAdmissionError::ConfidentialClientRequired)
        );
        assert_eq!(
            validate_raw_par_admission(
                &parameters,
                RawParAdmissionPolicy {
                    require_dpop_bound_tokens: false,
                    ..raw
                }
            ),
            Err(ParAdmissionError::SenderConstraintRequired)
        );
        let mut nested = parameters;
        nested.insert("request_uri".to_owned(), "urn:forbidden".to_owned());
        assert_eq!(
            validate_expanded_par_admission(&nested, expanded),
            Err(ParAdmissionError::RequestUriNotAllowed)
        );
    }

    proptest! {
        #[test]
        fn signed_request_object_time_window_is_bounded(
            age in 0_i64..1_000,
            lifetime in 1_i64..1_000,
        ) {
            let now = 1_700_000_000;
            let mut claims = signed_claims(now);
            claims.nbf = Some(now - age);
            claims.iat = Some(now - age);
            claims.exp = Some(now - age + lifetime);
            let accepted = normalize_request_object(&HashMap::new(), &claims, signed_policy(now)).is_ok();
            let expected = age <= REQUEST_OBJECT_MAX_TTL_SECONDS
                && lifetime <= REQUEST_OBJECT_MAX_TTL_SECONDS + REQUEST_OBJECT_CLOCK_SKEW_SECONDS
                && lifetime > age;
            prop_assert_eq!(accepted, expected);
        }
    }
}
