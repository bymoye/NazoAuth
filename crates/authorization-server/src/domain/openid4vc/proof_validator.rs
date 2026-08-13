use super::crypto_helpers::{algorithm_name, decoding_key};

use std::{future::Future, pin::Pin, sync::Arc};

use chrono::{Duration, Utc};
use jsonwebtoken::{Algorithm, Validation, decode, decode_header};
use nazo_digital_credentials::decode_compact_jwt;
use nazo_openid4vci::{ProofError, ProofValidatorPort, Proofs, ValidatedProof};
use nazo_operator_protocol::Openid4vcConformanceTrust;
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Clone)]
pub(crate) struct Openid4vcProofValidator {
    pub(super) key_attestation_jwks: Arc<Value>,
    conformance: Option<(nazo_postgres::ConformanceLeaseRepository, uuid::Uuid)>,
}

#[derive(Clone, Copy)]
pub(crate) enum KeyAttestationContext {
    AttestationProof,
    JwtProof,
}

impl Openid4vcProofValidator {
    pub(crate) fn new(key_attestation_jwks: Value) -> anyhow::Result<Self> {
        if key_attestation_jwks
            .get("keys")
            .and_then(Value::as_array)
            .is_none()
        {
            anyhow::bail!("OpenID4VC key-attestation trust configuration must be a JWK Set");
        }
        Ok(Self {
            key_attestation_jwks: Arc::new(key_attestation_jwks),
            conformance: None,
        })
    }

    pub(crate) fn with_conformance_leases(
        mut self,
        repository: nazo_postgres::ConformanceLeaseRepository,
        tenant_id: uuid::Uuid,
    ) -> Self {
        self.conformance = Some((repository, tenant_id));
        self
    }

    async fn effective_key_attestation_jwks(
        &self,
        client_id: &str,
    ) -> Result<Arc<Value>, ProofError> {
        if let Some((repository, tenant_id)) = &self.conformance {
            let material = repository
                .active_public_material_for_client(*tenant_id, client_id)
                .await
                .map_err(|_| ProofError::InvalidKeyAttestation)?;
            if let Some(material) = material {
                let material: Openid4vcConformanceTrust = serde_json::from_value(material)
                    .map_err(|_| ProofError::InvalidKeyAttestation)?;
                return Ok(Arc::new(material.key_attestation_jwks));
            }
        }
        Ok(self.key_attestation_jwks.clone())
    }
}

impl ProofValidatorPort for Openid4vcProofValidator {
    fn validate<'a>(
        &'a self,
        proofs: &'a Proofs,
        client_id: &'a str,
        expected_audience: &'a str,
        expected_nonce: &'a str,
        metadata: &'a nazo_openid4vci::ProofTypeMetadata,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<ValidatedProof>, ProofError>> + Send + 'a>> {
        Box::pin(async move {
            let trust_jwks = self.effective_key_attestation_jwks(client_id).await?;
            if proofs.0.len() != 1 {
                return Err(ProofError::UnsupportedType);
            }
            let now = Utc::now();
            if let Some(attestations) = proofs.0.get("attestation") {
                let mut validated = Vec::new();
                for encoded in attestations {
                    let encoded = encoded.as_str().ok_or(ProofError::InvalidKeyAttestation)?;
                    let claims = self.validate_key_attestation_with(
                        &trust_jwks,
                        encoded,
                        expected_nonce,
                        metadata,
                        now,
                        KeyAttestationContext::AttestationProof,
                    )?;
                    let keys = claims
                        .get("attested_keys")
                        .and_then(Value::as_array)
                        .ok_or(ProofError::InvalidKeyAttestation)?;
                    for key in keys {
                        validated.push(ValidatedProof {
                            proof_type: "attestation".to_owned(),
                            holder_binding: json!({"jwk": key}),
                            nonce: expected_nonce.to_owned(),
                            key_attestation: Some(claims.clone()),
                        });
                    }
                }
                return (!validated.is_empty())
                    .then_some(validated)
                    .ok_or(ProofError::InvalidKeyAttestation);
            }
            let jwt_proofs = proofs.0.get("jwt").ok_or(ProofError::UnsupportedType)?;
            if jwt_proofs.is_empty() {
                return Err(ProofError::UnsupportedType);
            }
            let mut validated = Vec::with_capacity(jwt_proofs.len());
            for encoded in jwt_proofs {
                let encoded = encoded.as_str().ok_or(ProofError::InvalidSignature)?;
                let header = decode_header(encoded).map_err(|_| ProofError::InvalidSignature)?;
                let alg = algorithm_name(header.alg).ok_or(ProofError::UnsupportedType)?;
                if !metadata
                    .proof_signing_alg_values_supported
                    .iter()
                    .any(|candidate| candidate == alg)
                    || header.typ.as_deref() != Some("openid4vci-proof+jwt")
                {
                    return Err(ProofError::UnsupportedType);
                }
                let jwk = header.jwk.as_ref().ok_or(ProofError::InvalidSignature)?;
                let jwk = serde_json::to_value(jwk).map_err(|_| ProofError::InvalidSignature)?;
                let key = decoding_key(&jwk, header.alg)?;
                let mut validation = Validation::new(header.alg);
                validation.validate_exp = false;
                validation.required_spec_claims.clear();
                validation.set_audience(&[expected_audience]);
                let decoded = decode::<ProofClaims>(encoded, &key, &validation)
                    .map_err(|_| ProofError::InvalidSignature)?;
                if decoded.claims.nonce != expected_nonce
                    || decoded.claims.iat < (now - Duration::minutes(5)).timestamp()
                    || decoded.claims.iat > (now + Duration::seconds(60)).timestamp()
                {
                    return Err(ProofError::InvalidNonce);
                }
                let compact =
                    decode_compact_jwt(encoded).map_err(|_| ProofError::InvalidSignature)?;
                let key_attestation = compact
                    .header
                    .extensions
                    .get("key_attestation")
                    .and_then(Value::as_str)
                    .map(|encoded| {
                        self.validate_key_attestation_with(
                            &trust_jwks,
                            encoded,
                            expected_nonce,
                            metadata,
                            now,
                            KeyAttestationContext::JwtProof,
                        )
                    })
                    .transpose()?;
                if metadata.key_attestations_required.is_some() {
                    let claims = key_attestation
                        .as_ref()
                        .ok_or(ProofError::InvalidKeyAttestation)?;
                    let matches = claims
                        .get("attested_keys")
                        .and_then(Value::as_array)
                        .is_some_and(|keys| keys.iter().any(|key| jwk_public_eq(key, &jwk)));
                    if !matches {
                        return Err(ProofError::InvalidKeyAttestation);
                    }
                }
                validated.push(ValidatedProof {
                    proof_type: "jwt".to_owned(),
                    holder_binding: json!({"jwk": jwk}),
                    nonce: expected_nonce.to_owned(),
                    key_attestation,
                });
            }
            Ok(validated)
        })
    }
}

impl Openid4vcProofValidator {
    pub(super) fn validate_key_attestation_with(
        &self,
        trust_jwks: &Value,
        encoded: &str,
        expected_nonce: &str,
        metadata: &nazo_openid4vci::ProofTypeMetadata,
        now: chrono::DateTime<Utc>,
        context: KeyAttestationContext,
    ) -> Result<Value, ProofError> {
        let compact = decode_compact_jwt(encoded).map_err(|_| ProofError::InvalidKeyAttestation)?;
        if compact.header.typ.as_deref() != Some("key-attestation+jwt") {
            return Err(ProofError::InvalidKeyAttestation);
        }
        let kid = compact
            .header
            .kid
            .as_deref()
            .ok_or(ProofError::InvalidKeyAttestation)?;
        let key = trust_jwks
            .get("keys")
            .and_then(Value::as_array)
            .and_then(|keys| {
                keys.iter()
                    .find(|key| key.get("kid").and_then(Value::as_str) == Some(kid))
            })
            .ok_or(ProofError::InvalidKeyAttestation)?;
        let algorithm = match compact.header.alg.as_str() {
            "ES256" => Algorithm::ES256,
            "EdDSA" => Algorithm::EdDSA,
            _ => return Err(ProofError::InvalidKeyAttestation),
        };
        let mut validation = Validation::new(algorithm);
        validation.validate_aud = false;
        validation.required_spec_claims.clear();
        validation.validate_exp = false;
        let claims = decode::<Value>(encoded, &decoding_key(key, algorithm)?, &validation)
            .map_err(|_| ProofError::InvalidKeyAttestation)?
            .claims;
        let issued_at = claims
            .get("iat")
            .and_then(Value::as_i64)
            .ok_or(ProofError::InvalidKeyAttestation)?;
        if issued_at < (now - Duration::minutes(5)).timestamp()
            || issued_at > (now + Duration::seconds(60)).timestamp()
        {
            return Err(ProofError::InvalidKeyAttestation);
        }
        let expires_at = claims
            .get("exp")
            .map(|value| value.as_i64().ok_or(ProofError::InvalidKeyAttestation))
            .transpose()?;
        if expires_at.is_some_and(|exp| exp <= now.timestamp()) {
            return Err(ProofError::InvalidKeyAttestation);
        }
        let nonce = claims
            .get("nonce")
            .map(|value| value.as_str().ok_or(ProofError::InvalidKeyAttestation))
            .transpose()?;
        match context {
            KeyAttestationContext::AttestationProof => {
                if nonce != Some(expected_nonce) {
                    return Err(ProofError::InvalidKeyAttestation);
                }
            }
            KeyAttestationContext::JwtProof => {
                if expires_at.is_none() || nonce.is_some_and(|nonce| nonce != expected_nonce) {
                    return Err(ProofError::InvalidKeyAttestation);
                }
            }
        }
        if claims
            .get("attested_keys")
            .and_then(Value::as_array)
            .is_none_or(Vec::is_empty)
        {
            return Err(ProofError::InvalidKeyAttestation);
        }
        if let Some(required) = &metadata.key_attestations_required {
            for (component, allowed) in required {
                let asserted = claims
                    .get(component)
                    .and_then(Value::as_array)
                    .ok_or(ProofError::InvalidKeyAttestation)?;
                if !asserted
                    .iter()
                    .filter_map(Value::as_str)
                    .any(|value| allowed.iter().any(|allowed| allowed == value))
                {
                    return Err(ProofError::InvalidKeyAttestation);
                }
            }
        }
        Ok(claims)
    }
}

fn jwk_public_eq(left: &Value, right: &Value) -> bool {
    left.get("kty") == right.get("kty")
        && left.get("crv") == right.get("crv")
        && left.get("x") == right.get("x")
        && left.get("y") == right.get("y")
}

#[derive(Deserialize)]
struct ProofClaims {
    nonce: String,
    iat: i64,
}
