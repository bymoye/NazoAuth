use std::sync::Arc;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use coset::CborSerializable;
use mdoc_rs::{
    builder::{CoseSigner, DocumentBuilder},
    cbor::data_item::{encode_cbor_canonical, wrap_tag24},
    model::types::ValidityInfo,
};
use nazo_auth::{SignRequest, Signer, SigningPurpose};
use nazo_digital_credentials::{
    CredentialFormat, CredentialSignInput, CredentialTrustError, HolderBinding,
    PresentedCredential, VerifiedCredential,
};
use nazo_key_management::KeyManager;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use super::super::crypto_helpers::{cbor_to_json, json_to_cbor, jwk_to_cose_key};
use super::Openid4vcCredentialCrypto;

pub(super) async fn sign(
    crypto: &Openid4vcCredentialCrypto,
    input: &CredentialSignInput,
) -> Result<String, CredentialTrustError> {
    let Some(HolderBinding::Jwk { jwk }) = input.payload.holder_binding.as_ref() else {
        return Err(CredentialTrustError::InvalidHolderBinding);
    };
    let namespaces = input
        .payload
        .subject_claims
        .as_object()
        .ok_or(CredentialTrustError::InvalidEncoding)?;
    let mut builder = DocumentBuilder::new(&input.payload.credential_type)
        .device_key(jwk_to_cose_key(jwk)?)
        .validity(ValidityInfo {
            signed: input.issued_at,
            valid_from: input.issued_at,
            valid_until: input.expires_at,
            expected_update: None,
        });
    for (namespace, values) in namespaces {
        let object = values
            .as_object()
            .ok_or(CredentialTrustError::InvalidEncoding)?;
        let entries = object
            .iter()
            .map(|(name, value)| Ok((name.as_str(), json_to_cbor(value)?)))
            .collect::<Result<Vec<_>, CredentialTrustError>>()?;
        builder = builder.add_namespace(namespace, entries);
    }
    let signer = AsyncCoseSigner {
        keyset: crypto.keyset.clone(),
        certificate_der: crypto.leaf_der.clone(),
        runtime: tokio::runtime::Handle::current(),
    };
    let document = tokio::task::spawn_blocking(move || builder.sign(&signer))
        .await
        .map_err(|_| CredentialTrustError::Unavailable)?
        .map_err(|_| CredentialTrustError::Unavailable)?;
    let mut namespace_entries = Vec::new();
    for (namespace, items) in &document.issuer_signed.name_spaces {
        namespace_entries.push((
            ciborium::Value::Text(namespace.clone()),
            ciborium::Value::Array(items.iter().map(|item| wrap_tag24(&item.encoded)).collect()),
        ));
    }
    let cose_bytes = document
        .issuer_signed
        .issuer_auth
        .cose_sign1
        .clone()
        .to_vec()
        .map_err(|_| CredentialTrustError::InvalidEncoding)?;
    let cose = ciborium::from_reader(cose_bytes.as_slice())
        .map_err(|_| CredentialTrustError::InvalidEncoding)?;
    let issuer_signed = ciborium::Value::Map(vec![
        (
            ciborium::Value::Text("nameSpaces".to_owned()),
            ciborium::Value::Map(namespace_entries),
        ),
        (ciborium::Value::Text("issuerAuth".to_owned()), cose),
    ]);
    Ok(URL_SAFE_NO_PAD.encode(
        encode_cbor_canonical(&issuer_signed).map_err(|_| CredentialTrustError::InvalidEncoding)?,
    ))
}

pub(super) fn verify(
    crypto: &Openid4vcCredentialCrypto,
    presentation: &PresentedCredential,
) -> Result<VerifiedCredential, CredentialTrustError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(&presentation.encoded)
        .map_err(|_| CredentialTrustError::InvalidEncoding)?;
    let session_transcript = presentation
        .mdoc_session_transcript
        .as_ref()
        .ok_or(CredentialTrustError::InvalidHolderBinding)?;
    let trust_anchors = crypto.combined_trust_anchors(&presentation.additional_trust_anchors)?;
    let verifier = mdoc_rs::Verifier::new(trust_anchors.clone());
    let verified = verifier
        .verify(
            &bytes,
            &mdoc_rs::VerifyOptions {
                session_transcript: Some(mdoc_rs::session::SessionTranscript::Raw(
                    session_transcript.clone(),
                )),
                ..Default::default()
            },
        )
        .map_err(|error| {
            tracing::warn!(%error, "OpenID4VP mdoc verifier could not process a credential");
            CredentialTrustError::InvalidEncoding
        })?;
    let standard_device_authentication_valid =
        verify_standard_mdoc_device_signatures(&verified, session_transcript)?;
    let issuer_chain_valid = verify_mdoc_issuer_certificate_chains(
        &verified,
        &trust_anchors,
        &presentation.additional_trust_anchors,
        &crypto.revocation_policy,
    )?;
    if !mdoc_assessments_accepted(
        &verified,
        standard_device_authentication_valid,
        issuer_chain_valid,
    ) || verified.mdoc.documents.len() != 1
    {
        let assessments = verified
            .assessments
            .iter()
            .map(|assessment| {
                format!(
                    "{}: {:?}: {}",
                    assessment.check,
                    assessment.status,
                    assessment.reason.as_deref().unwrap_or("")
                )
            })
            .collect::<Vec<_>>();
        let session_transcript_sha256 = URL_SAFE_NO_PAD.encode(Sha256::digest(session_transcript));
        tracing::warn!(
            document_count = verified.mdoc.documents.len(),
            %session_transcript_sha256,
            ?assessments,
            "OpenID4VP mdoc credential failed verification"
        );
        return Err(CredentialTrustError::InvalidSignature);
    }
    let document = &verified.mdoc.documents[0];
    let mso = document
        .issuer_signed
        .issuer_auth
        .mso()
        .map_err(|_| CredentialTrustError::InvalidEncoding)?;
    let holder_key = mdoc_holder_key(
        mso.device_key_info
            .as_ref()
            .map(|device_key_info| &device_key_info.device_key),
    )?;
    let mut namespaces = Map::new();
    for (namespace, items) in &document.issuer_signed.name_spaces {
        let mut claims = Map::new();
        for item in items {
            claims.insert(
                item.element_identifier.clone(),
                cbor_to_json(&item.element_value)?,
            );
        }
        namespaces.insert(namespace.clone(), Value::Object(claims));
    }
    Ok(VerifiedCredential {
        format: CredentialFormat::MsoMdoc,
        issuer: document
            .issuer_signed
            .issuer_auth
            .certificate_der()
            .map(|certificate| URL_SAFE_NO_PAD.encode(Sha256::digest(certificate)))
            .map_err(|_| CredentialTrustError::InvalidEncoding)?,
        credential_type: mso.doc_type,
        claims: Value::Object(namespaces),
        holder_key: Some(holder_key),
        issued_at: Some(mso.validity_info.signed),
        expires_at: Some(mso.validity_info.valid_until),
        status: mso
            .status
            .map(|status| cbor_to_json(&status.raw))
            .transpose()?,
    })
}

pub(crate) fn standard_device_authentication_bytes(
    session_transcript: &[u8],
    doc_type: &str,
    device_name_spaces: &[u8],
) -> Result<Vec<u8>, mdoc_rs::MdocError> {
    let device_authentication = mdoc_rs::session::build_device_authentication_bytes(
        session_transcript,
        doc_type,
        device_name_spaces,
    )?;
    encode_cbor_canonical(&wrap_tag24(&device_authentication))
}

fn verify_standard_mdoc_device_signatures(
    verified: &mdoc_rs::verifier::VerifiedMDoc,
    session_transcript: &[u8],
) -> Result<bool, CredentialTrustError> {
    if verified.mdoc.documents.is_empty() {
        return Ok(false);
    }

    let mut verified_signatures = 0usize;
    for document in &verified.mdoc.documents {
        let Some(device_signed) = document.device_signed.as_ref() else {
            return Ok(false);
        };
        if !matches!(
            device_signed.device_auth,
            mdoc_rs::model::types::DeviceAuth::Signature(_)
        ) {
            return Ok(false);
        }
        let mso = document
            .issuer_signed
            .issuer_auth
            .mso()
            .map_err(|_| CredentialTrustError::InvalidEncoding)?;
        let device_key = mso
            .device_key_info
            .as_ref()
            .map(|device_key_info| &device_key_info.device_key)
            .ok_or(CredentialTrustError::InvalidHolderBinding)?;
        let device_key_bytes = device_key
            .clone()
            .to_vec()
            .map_err(|_| CredentialTrustError::InvalidEncoding)?;
        let device_authentication = standard_device_authentication_bytes(
            session_transcript,
            &document.doc_type,
            &device_signed.name_spaces_bytes,
        )
        .map_err(|_| CredentialTrustError::InvalidEncoding)?;
        let result = mdoc_rs::device_auth::verify_device_auth(
            &device_signed.device_auth,
            &device_authentication,
            &device_key_bytes,
            None,
        )
        .map_err(|_| CredentialTrustError::InvalidSignature)?;
        if !result.is_valid {
            return Ok(false);
        }
        verified_signatures += 1;
    }

    Ok(verified_signatures == verified.mdoc.documents.len())
}

fn verify_mdoc_issuer_certificate_chains(
    verified: &mdoc_rs::verifier::VerifiedMDoc,
    trust_anchors: &[Vec<u8>],
    conformance_trust_anchors: &[Vec<u8>],
    revocation_policy: &nazo_digital_credentials::CertificateRevocationPolicy,
) -> Result<bool, CredentialTrustError> {
    // mdoc-rs fails this assessment closed without its optional TSP backend.
    // Avoid an unrelated RSA implementation in this ES256 mdoc path and perform
    // path, CA, signature, and signing-time validation with the AWS-LC-backed
    // X.509 verifier.
    if verified.mdoc.documents.is_empty() {
        return Ok(false);
    }
    for document in &verified.mdoc.documents {
        let certificates = document
            .issuer_signed
            .issuer_auth
            .certificate_chain_der()
            .map_err(|_| CredentialTrustError::InvalidEncoding)?
            .into_iter()
            .collect::<Vec<_>>();
        if certificates.is_empty() {
            return Err(CredentialTrustError::UntrustedIssuer);
        }
        let signed_at = document
            .issuer_signed
            .issuer_auth
            .mso()
            .map_err(|_| CredentialTrustError::InvalidEncoding)?
            .validity_info
            .signed
            .timestamp();
        if !verify_certificate_chain_at(&certificates, trust_anchors, signed_at)? {
            return Ok(false);
        }
        revocation_policy.check_chain_with_conformance_trust(
            None,
            &certificates,
            Utc::now(),
            conformance_trust_anchors,
        )?;
    }
    Ok(true)
}

pub(super) fn verify_certificate_chain_at(
    certificates: &[Vec<u8>],
    anchors: &[Vec<u8>],
    unix_time: i64,
) -> Result<bool, CredentialTrustError> {
    let at = x509_parser::time::ASN1Time::from_timestamp(unix_time)
        .map_err(|_| CredentialTrustError::InvalidEncoding)?;
    let (_, mut current) = x509_parser::parse_x509_certificate(&certificates[0])
        .map_err(|_| CredentialTrustError::InvalidEncoding)?;
    if current.is_ca() || !current.validity().is_valid_at(at) {
        return Ok(false);
    }
    for intermediate in certificates
        .iter()
        .skip(1)
        .filter(|der| !anchors.contains(der))
    {
        let (_, issuer) = x509_parser::parse_x509_certificate(intermediate)
            .map_err(|_| CredentialTrustError::InvalidEncoding)?;
        if !issuer.is_ca()
            || !issuer.validity().is_valid_at(at)
            || current.issuer() != issuer.subject()
            || current.verify_signature(Some(issuer.public_key())).is_err()
        {
            return Ok(false);
        }
        current = issuer;
    }
    Ok(anchors.iter().any(|anchor| {
        x509_parser::parse_x509_certificate(anchor).is_ok_and(|(_, anchor)| {
            anchor.is_ca()
                && anchor.validity().is_valid_at(at)
                && current.issuer() == anchor.subject()
                && current.verify_signature(Some(anchor.public_key())).is_ok()
        })
    }))
}

pub(super) fn mdoc_assessments_accepted(
    verified: &mdoc_rs::verifier::VerifiedMDoc,
    standard_device_authentication_valid: bool,
    issuer_chain_valid: bool,
) -> bool {
    if !standard_device_authentication_valid || !issuer_chain_valid {
        return false;
    }
    if verified.is_valid {
        return true;
    }

    mdoc_failed_assessments_accepted(
        verified.assessments.iter(),
        standard_device_authentication_valid,
        issuer_chain_valid,
    )
}

pub(crate) fn mdoc_failed_assessments_accepted<'a>(
    assessments: impl Iterator<Item = &'a mdoc_rs::verifier::VerificationAssessment>,
    standard_device_authentication_valid: bool,
    issuer_chain_valid: bool,
) -> bool {
    // Only library checks that were independently re-run against the normative
    // bytes or trust store may be replaced. Every other warning/failure remains
    // fatal, including future checks added by mdoc-rs.
    let mut failed = 0usize;
    for assessment in assessments
        .filter(|assessment| assessment.status != mdoc_rs::verifier::VerificationStatus::Passed)
    {
        failed += 1;
        let accepted = match assessment.id {
            mdoc_rs::verifier::CheckId::DeviceSignatureValidity => {
                standard_device_authentication_valid
            }
            mdoc_rs::verifier::CheckId::IssuerCertificateValidity => issuer_chain_valid,
            _ => false,
        };
        if !accepted {
            return false;
        }
    }
    failed > 0
}

pub(crate) fn mdoc_holder_key(
    device_key: Option<&coset::CoseKey>,
) -> Result<Value, CredentialTrustError> {
    let encoded = device_key
        .ok_or(CredentialTrustError::InvalidHolderBinding)?
        .clone()
        .to_vec()
        .map_err(|_| CredentialTrustError::InvalidEncoding)?;
    Ok(json!({"cose_key": URL_SAFE_NO_PAD.encode(encoded)}))
}

pub(super) struct AsyncCoseSigner {
    pub(super) keyset: KeyManager,
    pub(super) certificate_der: Arc<Vec<u8>>,
    pub(super) runtime: tokio::runtime::Handle,
}

impl CoseSigner for AsyncCoseSigner {
    fn sign(&self, tbs: &[u8]) -> Result<Vec<u8>, mdoc_rs::MdocError> {
        self.runtime
            .block_on(self.keyset.sign(SignRequest {
                purpose: SigningPurpose::Credential,
                algorithm: "ES256",
                signing_input: tbs,
            }))
            .map(nazo_auth::Signature::into_bytes)
            .map_err(|error| mdoc_rs::MdocError::Issuance(error.to_string()))
    }

    fn algorithm(&self) -> i64 {
        -7
    }
    fn certificate_der(&self) -> &[u8] {
        &self.certificate_der
    }
}
