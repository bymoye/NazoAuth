use std::collections::HashMap;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Validation, decode, decode_header};
use serde::Deserialize;
use serde_json::Value;

use crate::{
    AuthorizationPortError, RedirectUriError, is_subset, is_valid_pkce_value,
    parse_resource_indicator_parameter, resolve_registered_redirect_uri,
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
    "issuer_state",
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
    pub jti_policy: RequestObjectJtiPolicy,
    pub require_integrity_protected_parameters: bool,
    pub now: i64,
}

#[derive(Clone, Copy)]
pub struct RequestObjectVerificationInput<'a> {
    pub request_object: &'a str,
    pub client: &'a OAuthClient,
    pub expected_signing_algorithm: Option<&'a str>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct VerifiedRequestObject {
    pub claims: RequestObjectClaims,
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
    if decoded_header.alg == "none" || payload_part.is_empty() || signature_part.is_empty() {
        return Err(RequestObjectVerificationError::InvalidAlgorithm);
    }
    let header = decode_header(input.request_object)
        .map_err(|_| RequestObjectVerificationError::InvalidAlgorithm)?;
    let Some(algorithm_name) = supported_client_jwt_algorithm_name(header.alg) else {
        return Err(RequestObjectVerificationError::InvalidAlgorithm);
    };
    if input
        .expected_signing_algorithm
        .is_some_and(|expected| expected != algorithm_name)
    {
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
    let claims = decode::<RequestObjectClaims>(input.request_object, &decoding_key, &validation)
        .map_err(|_| RequestObjectVerificationError::InvalidSignature)?
        .claims;
    Ok(VerifiedRequestObject { claims })
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
    let mut outer = outer.clone();
    normalize_request_object_owned(&mut outer, claims, policy)
}

/// Applies request-object policy while reusing the caller's parameter map.
///
/// The map is moved only after all validation (including replay metadata
/// derivation) succeeds, so policy failures leave the caller's outer
/// parameters untouched.
pub fn normalize_request_object_owned(
    outer: &mut HashMap<String, String>,
    claims: &RequestObjectClaims,
    policy: RequestObjectPolicy<'_>,
) -> Result<NormalizedRequestObject, AuthorizationRequestError> {
    let plan = prepare_request_object(outer, claims, policy)?;
    Ok(apply_request_object_plan(outer, plan))
}

pub(crate) struct RequestObjectNormalizationPlan {
    request_parameters: HashMap<String, String>,
    replay: Option<RequestObjectReplay>,
    require_integrity_protected_parameters: bool,
}

impl RequestObjectNormalizationPlan {
    pub(crate) fn replay(&self) -> Option<&RequestObjectReplay> {
        self.replay.as_ref()
    }
}

pub(crate) fn prepare_request_object(
    outer: &HashMap<String, String>,
    claims: &RequestObjectClaims,
    policy: RequestObjectPolicy<'_>,
) -> Result<RequestObjectNormalizationPlan, AuthorizationRequestError> {
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
    if !request_parameters.contains_key("redirect_uri") {
        return Err(AuthorizationRequestError::SignedRequestObjectMissingRedirectUri);
    }
    if policy.require_integrity_protected_parameters
        && outer_authorization_parameters_conflict(outer, &request_parameters)
    {
        return Err(AuthorizationRequestError::OuterAuthorizationParametersConflict);
    }

    let replay = request_object_replay(claims, policy)?;
    Ok(RequestObjectNormalizationPlan {
        request_parameters,
        replay,
        require_integrity_protected_parameters: policy.require_integrity_protected_parameters,
    })
}

pub(crate) fn apply_request_object_plan(
    outer: &mut HashMap<String, String>,
    plan: RequestObjectNormalizationPlan,
) -> NormalizedRequestObject {
    let mut parameters = std::mem::take(outer);
    if plan.require_integrity_protected_parameters {
        parameters.retain(|key, _| matches!(key.as_str(), "request" | "client_id"));
    } else {
        parameters.retain(|key, _| key == "request" || !plan.request_parameters.contains_key(key));
    }
    parameters.extend(plan.request_parameters);
    NormalizedRequestObject {
        parameters,
        replay: plan.replay,
    }
}

fn request_object_party_claims_valid(
    claims: &RequestObjectClaims,
    policy: RequestObjectPolicy<'_>,
) -> bool {
    claims.iss.as_deref() == Some(policy.client_id)
        && claims
            .sub
            .as_deref()
            .is_none_or(|subject| subject == policy.client_id)
}

fn request_object_audience_valid(
    claims: &RequestObjectClaims,
    policy: RequestObjectPolicy<'_>,
) -> bool {
    match &claims.aud {
        Some(Value::String(audience)) => {
            audience == policy.issuer || audience == &format!("{}/authorize", policy.issuer)
        }
        Some(Value::Array(audiences)) => audiences.iter().any(|audience| {
            audience.as_str().is_some_and(|audience| {
                audience == policy.issuer || audience == format!("{}/authorize", policy.issuer)
            })
        }),
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
        None => return false,
    };
    let not_before = match claims.nbf {
        Some(not_before) => not_before,
        None => return false,
    };
    if not_before > now.saturating_add(REQUEST_OBJECT_CLOCK_SKEW_SECONDS) {
        return false;
    }
    if now.saturating_sub(not_before) > REQUEST_OBJECT_MAX_TTL_SECONDS
        || expiry <= not_before
        || expiry.saturating_sub(not_before)
            > REQUEST_OBJECT_MAX_TTL_SECONDS.saturating_add(REQUEST_OBJECT_CLOCK_SKEW_SECONDS)
    {
        return false;
    }
    !claims.iat.is_some_and(|issued_at| {
        issued_at > now.saturating_add(REQUEST_OBJECT_CLOCK_SKEW_SECONDS)
            || now.saturating_sub(issued_at) > REQUEST_OBJECT_MAX_TTL_SECONDS
    })
}

fn request_object_jti_valid(claims: &RequestObjectClaims, policy: RequestObjectPolicy<'_>) -> bool {
    match &claims.jti {
        Some(jti) => {
            let jti = jti.trim();
            !jti.is_empty() && jti.len() <= 128
        }
        None if policy.jti_policy == RequestObjectJtiPolicy::RequiredForSignedJar => false,
        None => true,
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
        let value = if *key == "resource" {
            let values = match value {
                Value::String(value) => vec![value.clone()],
                Value::Array(values) => values
                    .iter()
                    .map(|value| value.as_str().map(ToOwned::to_owned))
                    .collect::<Option<Vec<_>>>()
                    .ok_or(AuthorizationRequestError::RequestObjectParameterType)?,
                _ => return Err(AuthorizationRequestError::RequestObjectParameterType),
            };
            crate::encode_resource_indicators(&values)
                .ok_or(AuthorizationRequestError::RequestObjectParameterType)?
        } else {
            match value {
                Value::String(value) => value.clone(),
                Value::Number(value) => value.to_string(),
                Value::Object(_) if *key == "claims" => value.to_string(),
                Value::Array(_) if *key == "authorization_details" => value.to_string(),
                _ => return Err(AuthorizationRequestError::RequestObjectParameterType),
            }
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
    PkceRequired,
    InvalidPkce,
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
            | Self::PkceRequired
            | Self::InvalidPkce
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
            "private_key_jwt"
                | "tls_client_auth"
                | "self_signed_tls_client_auth"
                | "attest_jwt_client_auth"
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
    match (
        parameters.get("code_challenge").map(String::as_str),
        parameters.get("code_challenge_method").map(String::as_str),
    ) {
        (None, None) => return Err(ParAdmissionError::PkceRequired),
        (Some(challenge), Some("S256")) if is_valid_pkce_value(challenge) => {}
        _ => return Err(ParAdmissionError::InvalidPkce),
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
#[path = "../tests/unit/authorization_request.rs"]
mod tests;
