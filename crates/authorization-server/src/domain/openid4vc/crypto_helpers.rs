use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use coset::{CoseKeyBuilder, iana};
use jsonwebtoken::{Algorithm, DecodingKey};
use nazo_digital_credentials::CredentialTrustError;
use nazo_openid4vci::ProofError;
use p256::PublicKey;
use rustls::pki_types::{CertificateDer, pem::PemObject as _};
use serde_json::{Map, Value, json};

pub(super) fn decoding_key(jwk: &Value, algorithm: Algorithm) -> Result<DecodingKey, ProofError> {
    match algorithm {
        Algorithm::ES256 => DecodingKey::from_ec_components(
            jwk.get("x")
                .and_then(Value::as_str)
                .ok_or(ProofError::InvalidSignature)?,
            jwk.get("y")
                .and_then(Value::as_str)
                .ok_or(ProofError::InvalidSignature)?,
        )
        .map_err(|_| ProofError::InvalidSignature),
        Algorithm::EdDSA => DecodingKey::from_ed_components(
            jwk.get("x")
                .and_then(Value::as_str)
                .ok_or(ProofError::InvalidSignature)?,
        )
        .map_err(|_| ProofError::InvalidSignature),
        _ => Err(ProofError::UnsupportedType),
    }
}

pub(super) fn decoding_key_trust(
    jwk: &Value,
    algorithm: Algorithm,
) -> Result<DecodingKey, CredentialTrustError> {
    match algorithm {
        Algorithm::ES256 => DecodingKey::from_ec_components(
            jwk.get("x")
                .and_then(Value::as_str)
                .ok_or(CredentialTrustError::InvalidHolderBinding)?,
            jwk.get("y")
                .and_then(Value::as_str)
                .ok_or(CredentialTrustError::InvalidHolderBinding)?,
        )
        .map_err(|_| CredentialTrustError::InvalidHolderBinding),
        Algorithm::EdDSA => DecodingKey::from_ed_components(
            jwk.get("x")
                .and_then(Value::as_str)
                .ok_or(CredentialTrustError::InvalidHolderBinding)?,
        )
        .map_err(|_| CredentialTrustError::InvalidHolderBinding),
        _ => Err(CredentialTrustError::InvalidHolderBinding),
    }
}

pub(super) fn timestamp_claim(value: &Value, name: &str) -> Option<chrono::DateTime<Utc>> {
    chrono::DateTime::from_timestamp(value.get(name)?.as_i64()?, 0)
}

pub(crate) fn jwk_to_cose_key(jwk: &Value) -> Result<coset::CoseKey, CredentialTrustError> {
    match jwk.get("kty").and_then(Value::as_str) {
        Some("EC") if jwk.get("crv").and_then(Value::as_str) == Some("P-256") => {
            jwk_to_ec2_cose_key(jwk)
        }
        _ => Err(CredentialTrustError::InvalidHolderBinding),
    }
}

pub(super) fn jwk_to_ec2_cose_key(jwk: &Value) -> Result<coset::CoseKey, CredentialTrustError> {
    let x = URL_SAFE_NO_PAD
        .decode(
            jwk.get("x")
                .and_then(Value::as_str)
                .ok_or(CredentialTrustError::InvalidHolderBinding)?,
        )
        .map_err(|_| CredentialTrustError::InvalidHolderBinding)?;
    let y = URL_SAFE_NO_PAD
        .decode(
            jwk.get("y")
                .and_then(Value::as_str)
                .ok_or(CredentialTrustError::InvalidHolderBinding)?,
        )
        .map_err(|_| CredentialTrustError::InvalidHolderBinding)?;
    Ok(CoseKeyBuilder::new_ec2_pub_key(iana::EllipticCurve::P_256, x, y).build())
}

pub(super) fn json_to_cbor(value: &Value) -> Result<ciborium::Value, CredentialTrustError> {
    match value {
        Value::Null => Ok(ciborium::Value::Null),
        Value::Bool(value) => Ok(ciborium::Value::Bool(*value)),
        Value::Number(value) => value
            .as_i64()
            .map(|value| ciborium::Value::Integer(value.into()))
            .or_else(|| {
                value
                    .as_u64()
                    .map(|value| ciborium::Value::Integer(value.into()))
            })
            .or_else(|| value.as_f64().map(ciborium::Value::Float))
            .ok_or(CredentialTrustError::InvalidEncoding),
        Value::String(value) => Ok(ciborium::Value::Text(value.clone())),
        Value::Array(values) => values
            .iter()
            .map(json_to_cbor)
            .collect::<Result<Vec<_>, _>>()
            .map(ciborium::Value::Array),
        Value::Object(values) => values
            .iter()
            .map(|(key, value)| Ok((ciborium::Value::Text(key.clone()), json_to_cbor(value)?)))
            .collect::<Result<Vec<_>, _>>()
            .map(ciborium::Value::Map),
    }
}

pub(super) fn cbor_to_json(value: &ciborium::Value) -> Result<Value, CredentialTrustError> {
    match value {
        ciborium::Value::Null => Ok(Value::Null),
        ciborium::Value::Bool(value) => Ok(Value::Bool(*value)),
        ciborium::Value::Integer(value) => {
            let value: i128 = (*value).into();
            i64::try_from(value)
                .map(|value| json!(value))
                .or_else(|_| u64::try_from(value).map(|value| json!(value)))
                .map_err(|_| CredentialTrustError::InvalidEncoding)
        }
        ciborium::Value::Float(value) => serde_json::Number::from_f64(*value)
            .map(Value::Number)
            .ok_or(CredentialTrustError::InvalidEncoding),
        ciborium::Value::Bytes(value) => Ok(Value::String(URL_SAFE_NO_PAD.encode(value))),
        ciborium::Value::Text(value) => Ok(Value::String(value.clone())),
        ciborium::Value::Array(values) => values
            .iter()
            .map(cbor_to_json)
            .collect::<Result<Vec<_>, _>>()
            .map(Value::Array),
        ciborium::Value::Map(values) => values
            .iter()
            .map(|(key, value)| {
                let key = key.as_text().ok_or(CredentialTrustError::InvalidEncoding)?;
                Ok((key.to_owned(), cbor_to_json(value)?))
            })
            .collect::<Result<Map<_, _>, _>>()
            .map(Value::Object),
        ciborium::Value::Tag(_, value) => cbor_to_json(value),
        _ => Err(CredentialTrustError::InvalidEncoding),
    }
}

pub(super) fn algorithm_name(algorithm: Algorithm) -> Option<&'static str> {
    match algorithm {
        Algorithm::ES256 => Some("ES256"),
        Algorithm::EdDSA => Some("EdDSA"),
        _ => None,
    }
}

pub(super) fn p256_public_key_from_jwk(jwk: &Value) -> anyhow::Result<PublicKey> {
    let x = URL_SAFE_NO_PAD.decode(
        jwk.get("x")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("missing x"))?,
    )?;
    let y = URL_SAFE_NO_PAD.decode(
        jwk.get("y")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("missing y"))?,
    )?;
    if x.len() != 32 || y.len() != 32 {
        anyhow::bail!("invalid P-256 coordinate length");
    }
    let mut point = [0_u8; 65];
    point[0] = 4;
    point[1..33].copy_from_slice(&x);
    point[33..].copy_from_slice(&y);
    PublicKey::from_sec1_bytes(&point).map_err(Into::into)
}

pub(super) fn parse_pem_certificates(pem: &[u8]) -> anyhow::Result<Vec<Vec<u8>>> {
    CertificateDer::pem_slice_iter(pem)
        .map(|certificate| certificate.map(|certificate| certificate.as_ref().to_vec()))
        .collect::<Result<_, _>>()
        .map_err(Into::into)
}

pub(super) fn parse_x509<'a>(
    der: &'a [u8],
    description: &str,
) -> anyhow::Result<(&'a [u8], x509_parser::certificate::X509Certificate<'a>)> {
    let (remainder, certificate) = x509_parser::parse_x509_certificate(der)
        .map_err(|error| anyhow::anyhow!("failed to parse {description}: {error}"))?;
    if !remainder.is_empty() {
        anyhow::bail!("{description} contains trailing DER data");
    }
    Ok((remainder, certificate))
}

pub(super) fn verify_openid4vc_chain(
    certificates: &[Vec<u8>],
    anchors: &[Vec<u8>],
) -> anyhow::Result<()> {
    let (_, mut current) = parse_x509(&certificates[0], "OpenID4VC signing leaf")?;
    if current.is_ca() || !current.validity().is_valid() {
        anyhow::bail!("OpenID4VC signing leaf must be a currently valid end-entity certificate");
    }
    for intermediate in certificates
        .iter()
        .skip(1)
        .filter(|der| !anchors.contains(der))
    {
        let (_, issuer) = parse_x509(intermediate, "OpenID4VC intermediate certificate")?;
        if !issuer.is_ca()
            || !issuer.validity().is_valid()
            || current.issuer() != issuer.subject()
            || current.verify_signature(Some(issuer.public_key())).is_err()
        {
            anyhow::bail!("OpenID4VC signing certificate chain is invalid");
        }
        current = issuer;
    }
    let anchored = anchors.iter().any(|anchor| {
        parse_x509(anchor, "OpenID4VC trust anchor").is_ok_and(|(_, anchor)| {
            anchor.is_ca()
                && anchor.validity().is_valid()
                && current.issuer() == anchor.subject()
                && current.verify_signature(Some(anchor.public_key())).is_ok()
        })
    });
    if !anchored {
        anyhow::bail!(
            "OpenID4VC signing certificate is not anchored by the configured trust store"
        );
    }
    Ok(())
}
