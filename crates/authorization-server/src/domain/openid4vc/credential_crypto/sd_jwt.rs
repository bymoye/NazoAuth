use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use chrono::{Duration, Utc};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use nazo_digital_credentials::{
    CredentialFormat, CredentialSignInput, CredentialTrustError, HolderBinding,
    PresentedCredential, VerifiedCredential,
};
use rand::Rng;
use serde::Deserialize;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use super::super::crypto_helpers::{decoding_key_trust, timestamp_claim};
use super::Openid4vcCredentialCrypto;

pub(super) struct ValidatedSdJwtChain {
    pub(super) decoding_key: DecodingKey,
    pub(super) certificates: Vec<Vec<u8>>,
    pub(super) leaf_der: Vec<u8>,
}

pub(super) async fn sign(
    crypto: &Openid4vcCredentialCrypto,
    input: &CredentialSignInput,
) -> Result<String, CredentialTrustError> {
    let claims = input
        .payload
        .subject_claims
        .as_object()
        .ok_or(CredentialTrustError::InvalidEncoding)?;
    let mut disclosures = Vec::with_capacity(claims.len());
    let mut digests = Vec::with_capacity(claims.len());
    for (name, value) in claims {
        let mut salt = [0_u8; 16];
        rand::rng().fill_bytes(&mut salt);
        let disclosure = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&json!([URL_SAFE_NO_PAD.encode(salt), name, value]))
                .map_err(|_| CredentialTrustError::InvalidEncoding)?,
        );
        digests.push(URL_SAFE_NO_PAD.encode(Sha256::digest(disclosure.as_bytes())));
        disclosures.push(disclosure);
    }
    let mut credential = Map::from_iter([
        ("iss".to_owned(), json!(input.payload.issuer)),
        ("iat".to_owned(), json!(input.issued_at.timestamp())),
        ("nbf".to_owned(), json!(input.issued_at.timestamp())),
        ("exp".to_owned(), json!(input.expires_at.timestamp())),
        ("vct".to_owned(), json!(input.payload.credential_type)),
        ("_sd_alg".to_owned(), json!("sha-256")),
        ("_sd".to_owned(), json!(digests)),
    ]);
    if let Some(HolderBinding::Jwk { jwk }) = &input.payload.holder_binding {
        credential.insert("cnf".to_owned(), json!({"jwk": jwk}));
    }
    if let Some(status) = &input.status {
        credential.insert("status".to_owned(), status.clone());
    }
    let mut header = jsonwebtoken::Header::new(Algorithm::ES256);
    header.typ = Some("dc+sd-jwt".to_owned());
    header.x5c = Some(crypto.x5c.as_ref().clone());
    let jwt = crypto
        .keyset
        .encode_jwt(nazo_auth::SigningPurpose::Credential, &header, &credential)
        .await
        .map_err(|_| CredentialTrustError::Unavailable)?;
    Ok(format!("{jwt}~{}~", disclosures.join("~")))
}

pub(super) fn verify(
    crypto: &Openid4vcCredentialCrypto,
    presentation: &PresentedCredential,
) -> Result<VerifiedCredential, CredentialTrustError> {
    let parts = presentation.encoded.split('~').collect::<Vec<_>>();
    if parts.len() < 2 || parts[0].is_empty() || parts.last().is_some_and(|part| part.is_empty()) {
        return Err(CredentialTrustError::InvalidEncoding);
    }
    let credential_jwt = parts[0];
    let kb_jwt = parts.last().ok_or(CredentialTrustError::InvalidEncoding)?;
    let disclosures = &parts[1..parts.len() - 1];
    let header =
        decode_header(credential_jwt).map_err(|_| CredentialTrustError::InvalidEncoding)?;
    if header.typ.as_deref() != Some("dc+sd-jwt") || header.alg != Algorithm::ES256 {
        return Err(CredentialTrustError::InvalidEncoding);
    }
    let ValidatedSdJwtChain {
        decoding_key: key,
        certificates,
        leaf_der,
    } = validate_sd_jwt_chain(
        crypto,
        header
            .x5c
            .as_deref()
            .ok_or(CredentialTrustError::UntrustedIssuer)?,
        &presentation.additional_trust_anchors,
    )?;
    let mut validation = Validation::new(header.alg);
    validation.required_spec_claims = ["exp", "iss"].into_iter().map(str::to_owned).collect();
    validation.validate_aud = false;
    let credential = decode::<Value>(credential_jwt, &key, &validation)
        .map_err(|_| CredentialTrustError::InvalidSignature)?
        .claims;
    let issuer = credential
        .get("iss")
        .and_then(Value::as_str)
        .ok_or(CredentialTrustError::InvalidEncoding)?;
    crypto
        .issuer_trust_policy
        .validate(issuer, &leaf_der)
        .map_err(|_| CredentialTrustError::UntrustedIssuer)?;
    crypto
        .revocation_policy
        .check_chain_with_conformance_trust(
            Some(issuer),
            &certificates,
            Utc::now(),
            &presentation.additional_trust_anchors,
        )?;
    if credential
        .get("_sd_alg")
        .and_then(Value::as_str)
        .is_some_and(|algorithm| algorithm != "sha-256")
    {
        return Err(CredentialTrustError::InvalidEncoding);
    }
    let expected_digests = credential
        .get("_sd")
        .and_then(Value::as_array)
        .ok_or(CredentialTrustError::InvalidEncoding)?;
    let mut disclosed = Map::new();
    for disclosure in disclosures {
        let digest = Value::String(URL_SAFE_NO_PAD.encode(Sha256::digest(disclosure.as_bytes())));
        if !expected_digests.contains(&digest) {
            return Err(CredentialTrustError::InvalidSignature);
        }
        let decoded: Value = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(disclosure)
                .map_err(|_| CredentialTrustError::InvalidEncoding)?,
        )
        .map_err(|_| CredentialTrustError::InvalidEncoding)?;
        let array = decoded
            .as_array()
            .filter(|value| value.len() == 3)
            .ok_or(CredentialTrustError::InvalidEncoding)?;
        let name = array[1]
            .as_str()
            .ok_or(CredentialTrustError::InvalidEncoding)?;
        if disclosed
            .insert(name.to_owned(), array[2].clone())
            .is_some()
        {
            return Err(CredentialTrustError::InvalidEncoding);
        }
    }
    let holder_jwk = credential
        .pointer("/cnf/jwk")
        .ok_or(CredentialTrustError::InvalidHolderBinding)?;
    let kb_header =
        decode_header(kb_jwt).map_err(|_| CredentialTrustError::InvalidHolderBinding)?;
    if kb_header.typ.as_deref() != Some("kb+jwt") {
        return Err(CredentialTrustError::InvalidHolderBinding);
    }
    let holder_key = decoding_key_trust(holder_jwk, kb_header.alg)?;
    let mut kb_validation = Validation::new(kb_header.alg);
    kb_validation.validate_exp = false;
    kb_validation.required_spec_claims.clear();
    kb_validation.set_audience(&[presentation.expected_audience.as_str()]);
    let binding = decode::<KeyBindingClaims>(kb_jwt, &holder_key, &kb_validation)
        .map_err(|_| CredentialTrustError::InvalidHolderBinding)?
        .claims;
    let now = Utc::now();
    if binding.nonce != presentation.expected_nonce
        || binding.iat < (now - Duration::minutes(5)).timestamp()
        || binding.iat > (now + Duration::seconds(60)).timestamp()
    {
        return Err(CredentialTrustError::InvalidHolderBinding);
    }
    let sd_input = if disclosures.is_empty() {
        format!("{credential_jwt}~")
    } else {
        format!("{}~{}~", credential_jwt, disclosures.join("~"))
    };
    if binding.sd_hash != URL_SAFE_NO_PAD.encode(Sha256::digest(sd_input.as_bytes())) {
        return Err(CredentialTrustError::InvalidHolderBinding);
    }
    Ok(VerifiedCredential {
        format: CredentialFormat::SdJwtVc,
        issuer: issuer.to_owned(),
        credential_type: credential
            .get("vct")
            .and_then(Value::as_str)
            .ok_or(CredentialTrustError::InvalidEncoding)?
            .to_owned(),
        claims: Value::Object(disclosed),
        holder_key: Some(holder_jwk.clone()),
        issued_at: timestamp_claim(&credential, "iat"),
        expires_at: timestamp_claim(&credential, "exp"),
        status: credential.get("status").cloned(),
    })
}

pub(super) fn validate_sd_jwt_chain(
    crypto: &Openid4vcCredentialCrypto,
    x5c: &[String],
    additional_trust_anchors: &[Vec<u8>],
) -> Result<ValidatedSdJwtChain, CredentialTrustError> {
    let certificates = x5c
        .iter()
        .map(|value| {
            STANDARD
                .decode(value)
                .map_err(|_| CredentialTrustError::InvalidEncoding)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let leaf_der = certificates
        .first()
        .ok_or(CredentialTrustError::UntrustedIssuer)?
        .clone();
    let anchors = crypto.combined_trust_anchors(additional_trust_anchors)?;
    super::super::crypto_helpers::verify_openid4vc_chain(&certificates, &anchors)
        .map_err(|_| CredentialTrustError::UntrustedIssuer)?;
    let (_, leaf) = x509_parser::parse_x509_certificate(&leaf_der)
        .map_err(|_| CredentialTrustError::InvalidEncoding)?;
    Ok(ValidatedSdJwtChain {
        decoding_key: DecodingKey::from_ec_der(leaf.public_key().subject_public_key.data.as_ref()),
        certificates,
        leaf_der,
    })
}

#[derive(Deserialize)]
struct KeyBindingClaims {
    nonce: String,
    iat: i64,
    sd_hash: String,
}
