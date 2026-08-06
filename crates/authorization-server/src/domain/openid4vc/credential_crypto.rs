use super::crypto_helpers::*;

use std::sync::Arc;

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use chrono::{Duration, Utc};
use coset::CborSerializable;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use mdoc_rs::{
    builder::{CoseSigner, DocumentBuilder},
    cbor::data_item::{encode_cbor_canonical, wrap_tag24},
    model::types::ValidityInfo,
};
use nazo_auth::{SignRequest, Signer, SigningPurpose};
use nazo_digital_credentials::{
    CertificateRevocationPolicy, CredentialFormat, CredentialFuture, CredentialSignInput,
    CredentialSignerPort, CredentialTrustError, CredentialVerifierPort, HolderBinding,
    PresentedCredential, VcIssuerTrustPolicy, VerifiedCredential,
};
use nazo_key_management::KeyManager;
use p256::PublicKey;
use rand::Rng;
use serde::Deserialize;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

#[derive(Clone)]
pub(crate) struct Openid4vcCredentialCrypto {
    keyset: KeyManager,
    x5c: Arc<Vec<String>>,
    leaf_der: Arc<Vec<u8>>,
    trust_anchors: Arc<Vec<Vec<u8>>>,
    issuer_trust_policy: VcIssuerTrustPolicy,
    revocation_policy: CertificateRevocationPolicy,
}

struct ValidatedSdJwtChain {
    decoding_key: DecodingKey,
    certificates: Vec<Vec<u8>>,
    leaf_der: Vec<u8>,
}

pub(crate) fn parse_conformance_credential_trust_anchor(pem: &str) -> anyhow::Result<Vec<u8>> {
    let certificates = parse_pem_certificates(pem.as_bytes())?;
    if certificates.len() != 1 {
        anyhow::bail!(
            "OpenID4VC conformance credential trust must contain exactly one certificate"
        );
    }
    let der = certificates[0].clone();
    let (remainder, parsed) = x509_parser::parse_x509_certificate(&der).map_err(|error| {
        anyhow::anyhow!("failed to parse OpenID4VC conformance credential trust anchor: {error}")
    })?;
    if !remainder.is_empty() || !parsed.is_ca() || !parsed.validity().is_valid() {
        anyhow::bail!(
            "OpenID4VC conformance credential trust anchor must be a currently valid CA certificate"
        );
    }
    Ok(der)
}

impl Openid4vcCredentialCrypto {
    pub(crate) fn new_with_policies(
        keyset: KeyManager,
        certificate_chain_pem: &[u8],
        trust_anchors_pem: &[u8],
        issuer_trust_policy: VcIssuerTrustPolicy,
        revocation_policy: CertificateRevocationPolicy,
    ) -> anyhow::Result<Self> {
        let certificates = parse_pem_certificates(certificate_chain_pem)?;
        let leaf_der = certificates
            .first()
            .ok_or_else(|| anyhow::anyhow!("OpenID4VC signing certificate chain is empty"))?;
        let (_, leaf) = parse_x509(leaf_der, "OpenID4VC signing leaf")?;
        let mut trust_anchors = Vec::new();
        for der in parse_pem_certificates(trust_anchors_pem)? {
            let (_, parsed) = parse_x509(&der, "OpenID4VC trust certificate")?;
            if parsed.is_ca() {
                trust_anchors.push(der);
            }
        }
        if trust_anchors.is_empty() {
            anyhow::bail!("OpenID4VC trust anchor set must not be empty");
        }
        let x5c_der = certificates
            .iter()
            .filter(|certificate| !trust_anchors.contains(certificate))
            .cloned()
            .collect::<Vec<_>>();
        if x5c_der.is_empty() {
            anyhow::bail!("OpenID4VC x5c chain must contain a non-anchor leaf certificate");
        }
        let x5c = x5c_der
            .into_iter()
            .map(|certificate| STANDARD.encode(certificate))
            .collect();
        verify_openid4vc_chain(&certificates, &trust_anchors)?;
        let snapshot = keyset.snapshot();
        let leaf_key =
            PublicKey::from_sec1_bytes(leaf.public_key().subject_public_key.data.as_ref())?;
        let credential_key =
            snapshot.signing_verification_key(SigningPurpose::Credential, Algorithm::ES256);
        let presentation_key = snapshot
            .signing_verification_key(SigningPurpose::PresentationRequest, Algorithm::ES256);
        let key_matches = credential_key.zip(presentation_key).is_some_and(
            |(credential_key, presentation_key)| {
                credential_key.kid == presentation_key.kid
                    && p256_public_key_from_jwk(&credential_key.public_jwk)
                        .is_ok_and(|candidate| candidate == leaf_key)
            },
        );
        if !key_matches {
            anyhow::bail!(
                "OpenID4VC signing certificate does not match a credential and presentation-request scoped ES256 managed key"
            );
        }
        Ok(Self {
            keyset,
            x5c: Arc::new(x5c),
            leaf_der: Arc::new(leaf_der.clone()),
            trust_anchors: Arc::new(trust_anchors),
            issuer_trust_policy,
            revocation_policy,
        })
    }

    pub(crate) async fn sign_request_object(&self, claims: &Value) -> anyhow::Result<String> {
        let mut header = jsonwebtoken::Header::new(Algorithm::ES256);
        header.typ = Some("oauth-authz-req+jwt".to_owned());
        header.x5c = Some(self.x5c.as_ref().clone());
        self.keyset
            .encode_jwt(SigningPurpose::PresentationRequest, &header, claims)
            .await
            .map_err(Into::into)
    }

    pub(crate) async fn sign_issuer_metadata(&self, claims: &Value) -> anyhow::Result<String> {
        let mut header = jsonwebtoken::Header::new(Algorithm::ES256);
        header.typ = Some("openidvci-issuer-metadata+jwt".to_owned());
        header.x5c = Some(self.x5c.as_ref().clone());
        self.keyset
            .encode_jwt(SigningPurpose::Credential, &header, claims)
            .await
            .map_err(Into::into)
    }

    pub(crate) fn x509_hash_client_id(&self) -> String {
        format!(
            "x509_hash:{}",
            URL_SAFE_NO_PAD.encode(Sha256::digest(self.leaf_der.as_slice()))
        )
    }

    pub(crate) fn x509_san_dns_client_id(&self) -> anyhow::Result<String> {
        let (_, certificate) = parse_x509(self.leaf_der.as_slice(), "OpenID4VC signing leaf")?;
        let dns_name = certificate
            .subject_alternative_name()?
            .into_iter()
            .flat_map(|extension| extension.value.general_names.iter())
            .find_map(|name| match name {
                x509_parser::extensions::GeneralName::DNSName(name) => Some((*name).to_owned()),
                _ => None,
            })
            .filter(|name| !name.is_empty())
            .ok_or_else(|| anyhow::anyhow!("OpenID4VP signing certificate has no DNS SAN"))?;
        Ok(format!("x509_san_dns:{dns_name}"))
    }

    async fn sign_sd_jwt(
        &self,
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
        header.x5c = Some(self.x5c.as_ref().clone());
        let jwt = self
            .keyset
            .encode_jwt(SigningPurpose::Credential, &header, &credential)
            .await
            .map_err(|_| CredentialTrustError::Unavailable)?;
        Ok(format!("{jwt}~{}~", disclosures.join("~")))
    }

    async fn sign_mdoc(&self, input: &CredentialSignInput) -> Result<String, CredentialTrustError> {
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
            keyset: self.keyset.clone(),
            certificate_der: self.leaf_der.clone(),
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
                ciborium::Value::Array(
                    items.iter().map(|item| wrap_tag24(&item.encoded)).collect(),
                ),
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
            encode_cbor_canonical(&issuer_signed)
                .map_err(|_| CredentialTrustError::InvalidEncoding)?,
        ))
    }
}

impl CredentialSignerPort for Openid4vcCredentialCrypto {
    fn sign<'a>(
        &'a self,
        input: &'a CredentialSignInput,
    ) -> CredentialFuture<'a, Result<String, CredentialTrustError>> {
        Box::pin(async move {
            match input.payload.format {
                CredentialFormat::SdJwtVc => self.sign_sd_jwt(input).await,
                CredentialFormat::MsoMdoc => self.sign_mdoc(input).await,
            }
        })
    }
}

impl CredentialVerifierPort for Openid4vcCredentialCrypto {
    fn verify<'a>(
        &'a self,
        presentation: &'a PresentedCredential,
    ) -> CredentialFuture<'a, Result<VerifiedCredential, CredentialTrustError>> {
        Box::pin(async move {
            match presentation.format {
                CredentialFormat::SdJwtVc => self.verify_sd_jwt(presentation),
                CredentialFormat::MsoMdoc => self.verify_mdoc(presentation),
            }
        })
    }
}

impl Openid4vcCredentialCrypto {
    fn verify_sd_jwt(
        &self,
        presentation: &PresentedCredential,
    ) -> Result<VerifiedCredential, CredentialTrustError> {
        let parts = presentation.encoded.split('~').collect::<Vec<_>>();
        if parts.len() < 2
            || parts[0].is_empty()
            || parts.last().is_some_and(|part| part.is_empty())
        {
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
        } = self.validate_sd_jwt_chain(
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
        self.issuer_trust_policy
            .validate(issuer, &leaf_der)
            .map_err(|_| CredentialTrustError::UntrustedIssuer)?;
        self.revocation_policy
            .check_chain(Some(issuer), &certificates, Utc::now())?;
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
            let digest =
                Value::String(URL_SAFE_NO_PAD.encode(Sha256::digest(disclosure.as_bytes())));
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

    fn validate_sd_jwt_chain(
        &self,
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
        let anchors = self.combined_trust_anchors(additional_trust_anchors)?;
        verify_openid4vc_chain(&certificates, &anchors)
            .map_err(|_| CredentialTrustError::UntrustedIssuer)?;
        let (_, leaf) = x509_parser::parse_x509_certificate(&leaf_der)
            .map_err(|_| CredentialTrustError::InvalidEncoding)?;
        Ok(ValidatedSdJwtChain {
            decoding_key: DecodingKey::from_ec_der(
                leaf.public_key().subject_public_key.data.as_ref(),
            ),
            certificates,
            leaf_der,
        })
    }

    fn verify_mdoc(
        &self,
        presentation: &PresentedCredential,
    ) -> Result<VerifiedCredential, CredentialTrustError> {
        let bytes = URL_SAFE_NO_PAD
            .decode(&presentation.encoded)
            .map_err(|_| CredentialTrustError::InvalidEncoding)?;
        let session_transcript = presentation
            .mdoc_session_transcript
            .as_ref()
            .ok_or(CredentialTrustError::InvalidHolderBinding)?;
        let trust_anchors = self.combined_trust_anchors(&presentation.additional_trust_anchors)?;
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
            &self.revocation_policy,
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
            let session_transcript_sha256 =
                URL_SAFE_NO_PAD.encode(Sha256::digest(session_transcript));
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

    fn combined_trust_anchors(
        &self,
        additional: &[Vec<u8>],
    ) -> Result<Vec<Vec<u8>>, CredentialTrustError> {
        let mut anchors = self.trust_anchors.as_ref().clone();
        for anchor in additional {
            let (_, certificate) = x509_parser::parse_x509_certificate(anchor)
                .map_err(|_| CredentialTrustError::InvalidEncoding)?;
            if !certificate.is_ca() {
                return Err(CredentialTrustError::UntrustedIssuer);
            }
            if !anchors.contains(anchor) {
                anchors.push(anchor.clone());
            }
        }
        Ok(anchors)
    }
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
    revocation_policy: &CertificateRevocationPolicy,
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
        revocation_policy.check_chain(None, &certificates, Utc::now())?;
    }
    Ok(true)
}

fn verify_certificate_chain_at(
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

fn mdoc_assessments_accepted(
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

#[derive(Deserialize)]
struct KeyBindingClaims {
    nonce: String,
    iat: i64,
    sd_hash: String,
}

struct AsyncCoseSigner {
    keyset: KeyManager,
    certificate_der: Arc<Vec<u8>>,
    runtime: tokio::runtime::Handle,
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
