use super::crypto_helpers::decoding_key;

use std::sync::Arc;

use jsonwebtoken::{Algorithm, Validation, decode};
use nazo_digital_credentials::decode_compact_jwt;
use nazo_operator_protocol::Openid4vcConformanceTrust;
use serde_json::Value;

#[derive(Clone)]
pub(crate) struct Openid4vcClientAttestationValidator {
    static_trust: Option<(Arc<str>, Arc<Value>)>,
    conformance: Option<(nazo_postgres::ConformanceLeaseRepository, uuid::Uuid)>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ValidatedClientAttestation {
    pub(crate) client_id: String,
    pub(crate) client_instance_key_thumbprint: String,
    pub(crate) replay_id: String,
    pub(crate) replay_ttl_seconds: u64,
}

const CLIENT_ATTESTATION_CLOCK_SKEW_SECONDS: i64 = 60;
const CLIENT_ATTESTATION_POP_MAX_AGE_SECONDS: i64 = 300;
const CLIENT_ATTESTATION_POP_MAX_JTI_BYTES: usize = 128;

pub(crate) fn client_instance_key_thumbprint(instance_key: &Value) -> anyhow::Result<String> {
    if instance_key.get("d").is_some()
        || instance_key.get("kty").and_then(Value::as_str) != Some("EC")
        || instance_key.get("crv").and_then(Value::as_str) != Some("P-256")
    {
        anyhow::bail!("client instance key must be a public P-256 key");
    }
    nazo_auth::jwk_thumbprint(instance_key)
        .map_err(|_| anyhow::anyhow!("invalid client instance key"))
}

impl Openid4vcClientAttestationValidator {
    pub(crate) fn new(
        attester_issuer: impl Into<String>,
        trust_jwks: Value,
    ) -> anyhow::Result<Self> {
        let attester_issuer = attester_issuer.into();
        if attester_issuer.trim().is_empty()
            || trust_jwks
                .get("keys")
                .and_then(Value::as_array)
                .is_none_or(Vec::is_empty)
        {
            anyhow::bail!("client attestation requires an issuer and a non-empty trust JWK Set");
        }
        Ok(Self {
            static_trust: Some((attester_issuer.into(), Arc::new(trust_jwks))),
            conformance: None,
        })
    }

    pub(crate) fn with_conformance_leases(
        static_trust: Option<(String, Value)>,
        repository: nazo_postgres::ConformanceLeaseRepository,
        tenant_id: uuid::Uuid,
    ) -> anyhow::Result<Self> {
        let mut validator = if let Some((issuer, jwks)) = static_trust {
            Self::new(issuer, jwks)?
        } else {
            Self {
                static_trust: None,
                conformance: None,
            }
        };
        validator.conformance = Some((repository, tenant_id));
        Ok(validator)
    }

    pub(crate) fn unverified_client_id(attestation: &str) -> Option<String> {
        decode_compact_jwt(attestation)
            .ok()?
            .claims
            .get("sub")?
            .as_str()
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
    }

    pub(crate) fn validate(
        &self,
        attestation: &str,
        proof: &str,
        audience: &str,
        now: i64,
    ) -> anyhow::Result<ValidatedClientAttestation> {
        let (attester_issuer, trust_jwks) = self
            .static_trust
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("client attestation is not statically configured"))?;
        let parsed_attestation = decode_compact_jwt(attestation)?;
        if parsed_attestation.header.typ.as_deref() != Some("oauth-client-attestation+jwt")
            || parsed_attestation.header.alg != "ES256"
        {
            anyhow::bail!("invalid client attestation protected header");
        }
        let trust_key = select_jwk(
            trust_jwks,
            parsed_attestation.header.kid.as_deref(),
            "ES256",
        )?;
        let mut attestation_validation = Validation::new(Algorithm::ES256);
        attestation_validation.set_issuer(&[attester_issuer.as_ref()]);
        // OpenID4VCI 1.0 fixes Attestation-Based Client Authentication at
        // draft-07: iat and nbf are optional in the Client Attestation JWT.
        attestation_validation.set_required_spec_claims(&["iss", "sub", "exp"]);
        attestation_validation.validate_aud = false;
        attestation_validation.validate_nbf = true;
        attestation_validation.leeway = CLIENT_ATTESTATION_CLOCK_SKEW_SECONDS as u64;
        let claims = decode::<Value>(
            attestation,
            &decoding_key(trust_key, Algorithm::ES256)
                .map_err(|_| anyhow::anyhow!("invalid attester key"))?,
            &attestation_validation,
        )?
        .claims;
        let client_id = claims
            .get("sub")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| anyhow::anyhow!("client attestation subject is missing"))?;
        let instance_key = claims
            .pointer("/cnf/jwk")
            .ok_or_else(|| anyhow::anyhow!("client attestation cnf.jwk is missing"))?;
        let client_instance_key_thumbprint = client_instance_key_thumbprint(instance_key)?;
        if claims.get("iat").is_some_and(|iat| {
            iat.as_i64()
                .is_none_or(|iat| iat > now.saturating_add(CLIENT_ATTESTATION_CLOCK_SKEW_SECONDS))
        }) {
            anyhow::bail!("client attestation iat is invalid");
        }

        let parsed_proof = decode_compact_jwt(proof)?;
        if parsed_proof.header.typ.as_deref() != Some("oauth-client-attestation-pop+jwt")
            || parsed_proof.header.alg != "ES256"
        {
            anyhow::bail!("invalid client attestation proof protected header");
        }
        let mut proof_validation = Validation::new(Algorithm::ES256);
        proof_validation.set_audience(&[audience]);
        // draft-07 requires iat but does not define exp for the PoP JWT.
        proof_validation.set_required_spec_claims(&["iss", "aud", "iat", "jti"]);
        proof_validation.validate_nbf = true;
        proof_validation.leeway = CLIENT_ATTESTATION_CLOCK_SKEW_SECONDS as u64;
        let proof_claims = decode::<Value>(
            proof,
            &decoding_key(instance_key, Algorithm::ES256)
                .map_err(|_| anyhow::anyhow!("invalid instance key"))?,
            &proof_validation,
        )?
        .claims;
        if proof_claims.get("iss").and_then(Value::as_str) != Some(client_id) {
            anyhow::bail!("client attestation proof issuer does not match the subject");
        }
        let replay_id = proof_claims
            .get("jti")
            .and_then(Value::as_str)
            .filter(|value| {
                !value.is_empty() && value.len() <= CLIENT_ATTESTATION_POP_MAX_JTI_BYTES
            })
            .ok_or_else(|| anyhow::anyhow!("client attestation proof jti is missing"))?;
        let iat = proof_claims
            .get("iat")
            .and_then(Value::as_i64)
            .ok_or_else(|| anyhow::anyhow!("client attestation proof iat is missing"))?;
        let age = now.saturating_sub(iat);
        if iat > now.saturating_add(CLIENT_ATTESTATION_CLOCK_SKEW_SECONDS)
            || age > CLIENT_ATTESTATION_POP_MAX_AGE_SECONDS
        {
            anyhow::bail!("client attestation proof iat is outside the replay window");
        }
        Ok(ValidatedClientAttestation {
            client_id: client_id.to_owned(),
            client_instance_key_thumbprint,
            replay_id: replay_id.to_owned(),
            replay_ttl_seconds: CLIENT_ATTESTATION_POP_MAX_AGE_SECONDS
                .saturating_sub(age.max(0))
                .max(1) as u64,
        })
    }

    pub(crate) async fn validate_for_client(
        &self,
        attestation: &str,
        proof: &str,
        audience: &str,
        now: i64,
    ) -> anyhow::Result<ValidatedClientAttestation> {
        let client_id = Self::unverified_client_id(attestation)
            .ok_or_else(|| anyhow::anyhow!("client attestation subject is missing"))?;
        if let Some((repository, tenant_id)) = &self.conformance
            && let Some(material) = repository
                .active_public_material_for_client(*tenant_id, &client_id)
                .await?
        {
            let material: Openid4vcConformanceTrust = serde_json::from_value(material)?;
            return Self::new(
                material.client_attestation_issuer,
                material.client_attestation_jwks,
            )?
            .validate(attestation, proof, audience, now);
        }
        self.validate(attestation, proof, audience, now)
    }
}

fn select_jwk<'a>(jwks: &'a Value, kid: Option<&str>, alg: &str) -> anyhow::Result<&'a Value> {
    let matches = jwks
        .get("keys")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|key| {
            key.get("alg")
                .and_then(Value::as_str)
                .is_none_or(|value| value == alg)
                && kid.is_none_or(|kid| key.get("kid").and_then(Value::as_str) == Some(kid))
        })
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [key] => Ok(*key),
        _ => anyhow::bail!("client attestation signing key is ambiguous or unavailable"),
    }
}
