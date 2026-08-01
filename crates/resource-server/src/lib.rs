//! Resource-server JWT access-token verifier.
//!
//! This module is intentionally independent from the authorization server
//! runtime state. Resource servers should validate issuer, audience, token
//! type, algorithm, key id, expiry, scopes, and sender constraints locally
//! before falling back to introspection or application policy hooks.

use chrono::Utc;
use jsonwebtoken::{Algorithm, Validation};
use serde::{Deserialize, Serialize};

mod dpop;
mod jwk;
mod presentation;
mod service;
pub use dpop::{DpopProofVerifier, DpopProofVerifierConfig, DpopProofVerifierError};
use presentation::{
    PresentedAccessTokenScheme, http_authorization_headers, http_dpop_headers,
    presented_authorization_token, query_has_access_token, single_dpop_header,
    validate_presented_sender_constraint,
};
use serde_json::Value;
pub use service::{
    AccessTokenRevocationLookup, AccessTokenScheme, DpopNoncePolicy, DpopNonceStorage,
    DpopNonceValidationResult, DpopReplayConsumption, DpopReplayConsumptionResult, DpopReplayKey,
    ProtectedResourceAuthorizationContext, ProtectedResourceAuthorizationError,
    ProtectedResourceAuthorizationRequest, ProtectedResourceAuthorizationResult,
    ProtectedResourceAuthorizationService, ProtectedResourceDependencyError,
    ResourceServerPortFuture, RevocationLookupKey,
};

const DEFAULT_CLOCK_SKEW_SECONDS: i64 = 60;
const DEFAULT_DPOP_MAX_AGE_SECONDS: i64 = 300;

#[derive(Clone, Debug)]
pub struct ResourceServerVerifier {
    config: ResourceServerVerifierConfig,
}

#[derive(Clone, Debug)]
pub struct ResourceServerVerifierConfig {
    pub issuer: String,
    pub audiences: Vec<String>,
    pub jwks: Value,
    pub required_scopes: Vec<String>,
    pub confirmation: ConfirmationPolicy,
    pub allowed_algs: Vec<Algorithm>,
    pub clock_skew_seconds: i64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum ConfirmationPolicy {
    #[default]
    Optional,
    RequireDpop,
    RequireDpopJkt(String),
    RequireMtls,
    RequireMtlsThumbprint(String),
    RequireAnySenderConstraint,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedAccessToken {
    pub issuer: String,
    pub subject: String,
    pub tenant_id: Option<String>,
    pub client_id: String,
    pub audiences: Vec<String>,
    pub scopes: Vec<String>,
    pub jti: String,
    pub exp: i64,
    pub cnf: Option<ConfirmationClaims>,
    pub authorization_details: Value,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct ConfirmationClaims {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jkt: Option<String>,
    #[serde(rename = "x5t#S256", default, skip_serializing_if = "Option::is_none")]
    pub x5t_s256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResourceServerVerifierError {
    MissingIssuer,
    MissingAudience,
    MissingJwks,
    UnsupportedAlgorithm,
    MissingKeyId,
    UnknownKeyId,
    InvalidKey,
    InvalidToken,
    WrongTokenType,
    IssuerMismatch,
    AudienceMismatch,
    Expired,
    NotYetValid,
    MissingScope(String),
    MissingSenderConstraint,
    DpopBindingMismatch,
    MtlsBindingMismatch,
}

/// Sender-constraint material that has already been verified by the resource
/// server's DPoP proof verifier or mTLS certificate boundary.
///
/// This type intentionally does not represent a raw DPoP proof JWT. A caller
/// must validate DPoP `typ`, proof signature, `htu`, `htm`, `ath`, `jti`, and
/// nonce policy before filling `dpop_jkt`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VerifiedSenderConstraintProof {
    pub dpop_jkt: Option<String>,
    pub mtls_x5t_s256: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResourceServerRequestError {
    MissingToken,
    InvalidRequest,
    InvalidToken(ResourceServerVerifierError),
    InvalidDpopProof(DpopProofVerifierError),
    MissingSenderConstraint,
    DpopBindingMismatch,
    MtlsBindingMismatch,
}

#[derive(Debug, Deserialize)]
struct AccessTokenClaims {
    iss: String,
    sub: String,
    #[serde(default)]
    tenant_id: Option<String>,
    aud: Value,
    client_id: String,
    #[serde(default)]
    scope: String,
    #[serde(default)]
    authorization_details: Value,
    token_use: String,
    jti: String,
    #[serde(default)]
    nbf: Option<i64>,
    exp: i64,
    #[serde(default)]
    cnf: Option<ConfirmationClaims>,
}

impl ResourceServerVerifier {
    pub fn new(config: ResourceServerVerifierConfig) -> Result<Self, ResourceServerVerifierError> {
        if config.issuer.trim().is_empty() {
            return Err(ResourceServerVerifierError::MissingIssuer);
        }
        if config.audiences.is_empty() {
            return Err(ResourceServerVerifierError::MissingAudience);
        }
        if config.jwks.get("keys").and_then(Value::as_array).is_none() {
            return Err(ResourceServerVerifierError::MissingJwks);
        }
        Ok(Self { config })
    }

    pub fn verify(&self, token: &str) -> Result<VerifiedAccessToken, ResourceServerVerifierError> {
        self.verify_at(token, Utc::now().timestamp())
    }

    fn verify_at(
        &self,
        token: &str,
        now: i64,
    ) -> Result<VerifiedAccessToken, ResourceServerVerifierError> {
        let header = jsonwebtoken::decode_header(token)
            .map_err(|_| ResourceServerVerifierError::InvalidToken)?;
        if header.typ.as_deref() != Some("at+jwt") {
            return Err(ResourceServerVerifierError::WrongTokenType);
        }
        if !self.config.allowed_algs.contains(&header.alg) {
            return Err(ResourceServerVerifierError::UnsupportedAlgorithm);
        }
        let kid = header
            .kid
            .as_deref()
            .ok_or(ResourceServerVerifierError::MissingKeyId)?;
        let key = self
            .jwk_for_kid(kid)
            .ok_or(ResourceServerVerifierError::UnknownKeyId)?;
        let decoding_key =
            jwk::decoding_key(key, header.alg).ok_or(ResourceServerVerifierError::InvalidKey)?;
        let mut validation = Validation::new(header.alg);
        validation.validate_aud = false;
        validation.validate_exp = false;
        validation.validate_nbf = false;
        let decoded = jsonwebtoken::decode::<AccessTokenClaims>(token, &decoding_key, &validation)
            .map_err(|_| ResourceServerVerifierError::InvalidToken)?;
        self.validate_claims(decoded.claims, now)
    }

    fn validate_claims(
        &self,
        claims: AccessTokenClaims,
        now: i64,
    ) -> Result<VerifiedAccessToken, ResourceServerVerifierError> {
        if claims.token_use != "access" {
            return Err(ResourceServerVerifierError::WrongTokenType);
        }
        if claims.iss != self.config.issuer {
            return Err(ResourceServerVerifierError::IssuerMismatch);
        }
        let audiences = audience_values(&claims.aud);
        if !audiences
            .iter()
            .any(|aud| self.config.audiences.iter().any(|expected| expected == aud))
        {
            return Err(ResourceServerVerifierError::AudienceMismatch);
        }
        let skew = self.config.clock_skew_seconds.max(0);
        if claims.exp <= now.saturating_sub(skew) {
            return Err(ResourceServerVerifierError::Expired);
        }
        if claims.nbf.is_some_and(|nbf| nbf > now.saturating_add(skew)) {
            return Err(ResourceServerVerifierError::NotYetValid);
        }
        let scopes = scope_values(&claims.scope);
        for required in &self.config.required_scopes {
            if !scopes.iter().any(|scope| scope == required) {
                return Err(ResourceServerVerifierError::MissingScope(required.clone()));
            }
        }
        validate_confirmation_policy(&self.config.confirmation, claims.cnf.as_ref())?;
        Ok(VerifiedAccessToken {
            issuer: claims.iss,
            subject: claims.sub,
            tenant_id: claims.tenant_id,
            client_id: claims.client_id,
            audiences,
            scopes,
            jti: claims.jti,
            exp: claims.exp,
            cnf: claims.cnf,
            authorization_details: claims.authorization_details,
        })
    }

    fn jwk_for_kid(&self, kid: &str) -> Option<&Value> {
        self.config
            .jwks
            .get("keys")?
            .as_array()?
            .iter()
            .find(|key| key.get("kid").and_then(Value::as_str) == Some(kid))
    }
}

impl ResourceServerVerifierConfig {
    pub fn new(issuer: impl Into<String>, audience: impl Into<String>, jwks: Value) -> Self {
        Self {
            issuer: issuer.into(),
            audiences: vec![audience.into()],
            jwks,
            required_scopes: Vec::new(),
            confirmation: ConfirmationPolicy::Optional,
            allowed_algs: vec![
                Algorithm::EdDSA,
                Algorithm::RS256,
                Algorithm::ES256,
                Algorithm::PS256,
            ],
            clock_skew_seconds: DEFAULT_CLOCK_SKEW_SECONDS,
        }
    }
}

pub fn authorize_resource_request(
    verifier: &ResourceServerVerifier,
    authorization_headers: &[&str],
    query: Option<&str>,
    proof: &VerifiedSenderConstraintProof,
) -> Result<VerifiedAccessToken, ResourceServerRequestError> {
    if query_has_access_token(query) {
        return Err(ResourceServerRequestError::InvalidRequest);
    }
    let (scheme, token) = presented_authorization_token(authorization_headers)?;
    let verified = verifier
        .verify(token)
        .map_err(ResourceServerRequestError::InvalidToken)?;
    validate_presented_sender_constraint(scheme, &verified, proof)?;
    Ok(verified)
}

pub fn authorize_dpop_resource_request(
    verifier: &ResourceServerVerifier,
    dpop_verifier: &DpopProofVerifier,
    authorization_headers: &[&str],
    dpop_proof_jwt: &str,
    query: Option<&str>,
    method: &str,
    htu: &str,
) -> Result<(VerifiedAccessToken, VerifiedSenderConstraintProof), ResourceServerRequestError> {
    if query_has_access_token(query) {
        return Err(ResourceServerRequestError::InvalidRequest);
    }
    let (scheme, access_token) = presented_authorization_token(authorization_headers)?;
    if scheme != PresentedAccessTokenScheme::Dpop {
        return Err(ResourceServerRequestError::MissingSenderConstraint);
    }
    let verified = verifier
        .verify(access_token)
        .map_err(ResourceServerRequestError::InvalidToken)?;
    let proof = dpop_verifier
        .verify(dpop_proof_jwt, method, htu, access_token)
        .map_err(ResourceServerRequestError::InvalidDpopProof)?;
    validate_presented_sender_constraint(scheme, &verified, &proof)?;
    Ok((verified, proof))
}

pub fn authorize_http_request<B>(
    verifier: &ResourceServerVerifier,
    request: &mut http::Request<B>,
) -> Result<VerifiedAccessToken, ResourceServerRequestError> {
    let headers = http_authorization_headers(request.headers())?;
    let proof = request
        .extensions()
        .get::<VerifiedSenderConstraintProof>()
        .cloned()
        .unwrap_or_default();
    let verified = authorize_resource_request(verifier, &headers, request.uri().query(), &proof)?;
    request.extensions_mut().insert(verified.clone());
    Ok(verified)
}

pub fn authorize_dpop_http_request<B>(
    verifier: &ResourceServerVerifier,
    dpop_verifier: &DpopProofVerifier,
    request: &mut http::Request<B>,
    htu: &str,
) -> Result<VerifiedAccessToken, ResourceServerRequestError> {
    let authorization_headers = http_authorization_headers(request.headers())?;
    let dpop_headers = http_dpop_headers(request.headers())?;
    let dpop_proof_jwt = single_dpop_header(&dpop_headers)?;
    let (verified, proof) = authorize_dpop_resource_request(
        verifier,
        dpop_verifier,
        &authorization_headers,
        dpop_proof_jwt,
        request.uri().query(),
        request.method().as_str(),
        htu,
    )?;
    request.extensions_mut().insert(proof);
    request.extensions_mut().insert(verified.clone());
    Ok(verified)
}

fn validate_confirmation_policy(
    policy: &ConfirmationPolicy,
    cnf: Option<&ConfirmationClaims>,
) -> Result<(), ResourceServerVerifierError> {
    match policy {
        ConfirmationPolicy::Optional => Ok(()),
        ConfirmationPolicy::RequireAnySenderConstraint => {
            let Some(cnf) = cnf else {
                return Err(ResourceServerVerifierError::MissingSenderConstraint);
            };
            if cnf.jkt.is_some() || cnf.x5t_s256.is_some() {
                Ok(())
            } else {
                Err(ResourceServerVerifierError::MissingSenderConstraint)
            }
        }
        ConfirmationPolicy::RequireDpop => {
            if cnf.and_then(|claims| claims.jkt.as_ref()).is_some() {
                Ok(())
            } else {
                Err(ResourceServerVerifierError::MissingSenderConstraint)
            }
        }
        ConfirmationPolicy::RequireDpopJkt(expected) => {
            match cnf.and_then(|claims| claims.jkt.as_ref()) {
                Some(actual) if actual == expected => Ok(()),
                Some(_) => Err(ResourceServerVerifierError::DpopBindingMismatch),
                None => Err(ResourceServerVerifierError::MissingSenderConstraint),
            }
        }
        ConfirmationPolicy::RequireMtls => {
            if cnf.and_then(|claims| claims.x5t_s256.as_ref()).is_some() {
                Ok(())
            } else {
                Err(ResourceServerVerifierError::MissingSenderConstraint)
            }
        }
        ConfirmationPolicy::RequireMtlsThumbprint(expected) => {
            match cnf.and_then(|claims| claims.x5t_s256.as_ref()) {
                Some(actual) if actual == expected => Ok(()),
                Some(_) => Err(ResourceServerVerifierError::MtlsBindingMismatch),
                None => Err(ResourceServerVerifierError::MissingSenderConstraint),
            }
        }
    }
}

fn audience_values(value: &Value) -> Vec<String> {
    match value {
        Value::String(value) => vec![value.clone()],
        Value::Array(values) => values
            .iter()
            .filter_map(|value| value.as_str().map(ToOwned::to_owned))
            .collect(),
        _ => Vec::new(),
    }
}

fn scope_values(value: &str) -> Vec<String> {
    value
        .split_whitespace()
        .map(ToOwned::to_owned)
        .filter(|scope| !scope.is_empty())
        .collect()
}

#[cfg(test)]
#[path = "../tests/unit/lib.rs"]
mod tests;
