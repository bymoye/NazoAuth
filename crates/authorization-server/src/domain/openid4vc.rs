use std::{future::Future, pin::Pin, sync::Arc};

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use chrono::{Duration, Utc};
use coset::{CborSerializable, CoseKeyBuilder, iana};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use mdoc_rs::{
    builder::{CoseSigner, DocumentBuilder},
    cbor::data_item::{encode_cbor_canonical, wrap_tag24},
    model::types::ValidityInfo,
};
use nazo_auth::{SignRequest, Signer, SigningPurpose};
use nazo_digital_credentials::{
    CredentialFormat, CredentialFuture, CredentialSignInput, CredentialSignerPort,
    CredentialTrustError, CredentialVerifierPort, HolderBinding, PresentedCredential,
    VerifiedCredential, decode_compact_jwt,
};
use nazo_key_management::KeyManager;
use nazo_openid4vci::{ProofError, ProofValidatorPort, Proofs, ValidatedProof};
use openssl::{
    bn::{BigNum, BigNumContext},
    ec::{EcGroup, EcKey, EcPoint},
    nid::Nid,
    pkey::PKey,
    stack::Stack,
    x509::{X509, X509StoreContext, store::X509StoreBuilder},
};
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
}

impl Openid4vcCredentialCrypto {
    pub(crate) fn new(
        keyset: KeyManager,
        certificate_chain_pem: &[u8],
        trust_anchors_pem: &[u8],
    ) -> anyhow::Result<Self> {
        let certificates = X509::stack_from_pem(certificate_chain_pem)?;
        let leaf = certificates
            .first()
            .ok_or_else(|| anyhow::anyhow!("OpenID4VC signing certificate chain is empty"))?;
        let leaf_der = leaf.to_der()?;
        let trust_anchors = X509::stack_from_pem(trust_anchors_pem)?
            .into_iter()
            .map(|certificate| certificate.to_der())
            .collect::<Result<Vec<_>, _>>()?;
        if trust_anchors.is_empty() {
            anyhow::bail!("OpenID4VC trust anchor set must not be empty");
        }
        let x5c_der = certificates
            .iter()
            .map(|certificate| certificate.to_der())
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .filter(|certificate| !trust_anchors.contains(certificate))
            .collect::<Vec<_>>();
        if x5c_der.is_empty() {
            anyhow::bail!("OpenID4VC x5c chain must contain a non-anchor leaf certificate");
        }
        let x5c = x5c_der
            .into_iter()
            .map(|certificate| STANDARD.encode(certificate))
            .collect();
        let mut store = X509StoreBuilder::new()?;
        for anchor in &trust_anchors {
            store.add_cert(X509::from_der(anchor)?)?;
        }
        let store = store.build();
        let mut untrusted = Stack::new()?;
        for certificate in certificates.iter().skip(1) {
            let der = certificate.to_der()?;
            if !trust_anchors.contains(&der) {
                untrusted.push(certificate.clone())?;
            }
        }
        let mut context = X509StoreContext::new()?;
        if !context.init(&store, leaf, &untrusted, |context| context.verify_cert())? {
            anyhow::bail!(
                "OpenID4VC signing certificate is not anchored by the configured trust store"
            );
        }
        let snapshot = keyset.snapshot();
        let leaf_key = leaf.public_key()?;
        let credential_key =
            snapshot.signing_verification_key(SigningPurpose::Credential, Algorithm::ES256);
        let presentation_key = snapshot
            .signing_verification_key(SigningPurpose::PresentationRequest, Algorithm::ES256);
        let key_matches = credential_key.zip(presentation_key).is_some_and(
            |(credential_key, presentation_key)| {
                credential_key.kid == presentation_key.kid
                    && p256_pkey_from_jwk(&credential_key.public_jwk)
                        .is_ok_and(|candidate| candidate.public_eq(&leaf_key))
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
            leaf_der: Arc::new(leaf_der),
            trust_anchors: Arc::new(trust_anchors),
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
        let certificate = X509::from_der(self.leaf_der.as_slice())?;
        let dns_name = certificate
            .subject_alt_names()
            .into_iter()
            .flatten()
            .find_map(|name| name.dnsname().map(ToOwned::to_owned))
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
        let key = self.validate_sd_jwt_chain(
            header
                .x5c
                .as_deref()
                .ok_or(CredentialTrustError::UntrustedIssuer)?,
        )?;
        let mut validation = Validation::new(header.alg);
        validation.required_spec_claims = ["exp", "iss"].into_iter().map(str::to_owned).collect();
        validation.validate_aud = false;
        let credential = decode::<Value>(credential_jwt, &key, &validation)
            .map_err(|_| CredentialTrustError::InvalidSignature)?
            .claims;
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
            issuer: credential
                .get("iss")
                .and_then(Value::as_str)
                .ok_or(CredentialTrustError::InvalidEncoding)?
                .to_owned(),
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

    fn validate_sd_jwt_chain(&self, x5c: &[String]) -> Result<DecodingKey, CredentialTrustError> {
        let certificates = x5c
            .iter()
            .map(|value| {
                STANDARD
                    .decode(value)
                    .map_err(|_| CredentialTrustError::InvalidEncoding)
            })
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .map(|value| X509::from_der(&value).map_err(|_| CredentialTrustError::InvalidEncoding))
            .collect::<Result<Vec<_>, _>>()?;
        let leaf = certificates
            .first()
            .ok_or(CredentialTrustError::UntrustedIssuer)?;
        let mut store = X509StoreBuilder::new().map_err(|_| CredentialTrustError::Unavailable)?;
        for anchor in self.trust_anchors.iter() {
            store
                .add_cert(X509::from_der(anchor).map_err(|_| CredentialTrustError::Unavailable)?)
                .map_err(|_| CredentialTrustError::Unavailable)?;
        }
        let store = store.build();
        let mut chain = Stack::new().map_err(|_| CredentialTrustError::Unavailable)?;
        for intermediate in certificates.iter().skip(1) {
            chain
                .push(intermediate.clone())
                .map_err(|_| CredentialTrustError::Unavailable)?;
        }
        let mut context = X509StoreContext::new().map_err(|_| CredentialTrustError::Unavailable)?;
        let trusted = context
            .init(&store, leaf, &chain, |context| context.verify_cert())
            .map_err(|_| CredentialTrustError::UntrustedIssuer)?;
        if !trusted {
            return Err(CredentialTrustError::UntrustedIssuer);
        }
        let public_key = leaf
            .public_key()
            .and_then(|key| key.public_key_to_pem())
            .map_err(|_| CredentialTrustError::InvalidEncoding)?;
        DecodingKey::from_ec_pem(&public_key).map_err(|_| CredentialTrustError::InvalidEncoding)
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
        let verifier = mdoc_rs::Verifier::new(self.trust_anchors.as_ref().clone());
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
        let issuer_chain_valid =
            verify_mdoc_issuer_certificate_chains(&verified, self.trust_anchors.as_ref())?;
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
            tracing::warn!(
                document_count = verified.mdoc.documents.len(),
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
}

fn standard_device_authentication_bytes(
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
) -> Result<bool, CredentialTrustError> {
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
            .map(|value| X509::from_der(&value).map_err(|_| CredentialTrustError::InvalidEncoding))
            .collect::<Result<Vec<_>, _>>()?;
        let leaf = certificates
            .first()
            .ok_or(CredentialTrustError::UntrustedIssuer)?;
        let mut store = X509StoreBuilder::new().map_err(|_| CredentialTrustError::Unavailable)?;
        for anchor in trust_anchors {
            store
                .add_cert(X509::from_der(anchor).map_err(|_| CredentialTrustError::Unavailable)?)
                .map_err(|_| CredentialTrustError::Unavailable)?;
        }
        let store = store.build();
        let mut chain = Stack::new().map_err(|_| CredentialTrustError::Unavailable)?;
        for intermediate in certificates.iter().skip(1) {
            if trust_anchors
                .iter()
                .any(|anchor| intermediate.to_der().is_ok_and(|der| der == *anchor))
            {
                continue;
            }
            chain
                .push(intermediate.clone())
                .map_err(|_| CredentialTrustError::Unavailable)?;
        }
        let mut context = X509StoreContext::new().map_err(|_| CredentialTrustError::Unavailable)?;
        let trusted = context
            .init(&store, leaf, &chain, |context| context.verify_cert())
            .map_err(|_| CredentialTrustError::UntrustedIssuer)?;
        if !trusted {
            return Ok(false);
        }
    }
    Ok(true)
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

fn mdoc_failed_assessments_accepted<'a>(
    assessments: impl Iterator<Item = &'a mdoc_rs::verifier::VerificationAssessment>,
    standard_device_authentication_valid: bool,
    issuer_chain_valid: bool,
) -> bool {
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

fn mdoc_holder_key(device_key: Option<&coset::CoseKey>) -> Result<Value, CredentialTrustError> {
    let encoded = device_key
        .ok_or(CredentialTrustError::InvalidHolderBinding)?
        .clone()
        .to_vec()
        .map_err(|_| CredentialTrustError::InvalidEncoding)?;
    Ok(json!({"cose_key": URL_SAFE_NO_PAD.encode(encoded)}))
}

#[cfg(test)]
#[path = "../../tests/unit/domain/openid4vc.rs"]
mod tests;

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

#[derive(Clone)]
pub(crate) struct Openid4vcProofValidator {
    key_attestation_jwks: Arc<Value>,
}

#[derive(Clone, Copy)]
enum KeyAttestationContext {
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
        })
    }
}

impl ProofValidatorPort for Openid4vcProofValidator {
    fn validate<'a>(
        &'a self,
        proofs: &'a Proofs,
        expected_audience: &'a str,
        expected_nonce: &'a str,
        metadata: &'a nazo_openid4vci::ProofTypeMetadata,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<ValidatedProof>, ProofError>> + Send + 'a>> {
        Box::pin(async move {
            if proofs.0.len() != 1 {
                return Err(ProofError::UnsupportedType);
            }
            let now = Utc::now();
            if let Some(attestations) = proofs.0.get("attestation") {
                let mut validated = Vec::new();
                for encoded in attestations {
                    let encoded = encoded.as_str().ok_or(ProofError::InvalidKeyAttestation)?;
                    let claims = self.validate_key_attestation(
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
                        self.validate_key_attestation(
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
    fn validate_key_attestation(
        &self,
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
        let key = self
            .key_attestation_jwks
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

#[derive(Clone)]
pub(crate) struct Openid4vcClientAttestationValidator {
    attester_issuer: Arc<str>,
    trust_jwks: Arc<Value>,
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

fn client_instance_key_thumbprint(instance_key: &Value) -> anyhow::Result<String> {
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
            attester_issuer: attester_issuer.into(),
            trust_jwks: Arc::new(trust_jwks),
        })
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
        let parsed_attestation = decode_compact_jwt(attestation)?;
        if parsed_attestation.header.typ.as_deref() != Some("oauth-client-attestation+jwt")
            || parsed_attestation.header.alg != "ES256"
        {
            anyhow::bail!("invalid client attestation protected header");
        }
        let trust_key = select_jwk(
            &self.trust_jwks,
            parsed_attestation.header.kid.as_deref(),
            "ES256",
        )?;
        let mut attestation_validation = Validation::new(Algorithm::ES256);
        attestation_validation.set_issuer(&[self.attester_issuer.as_ref()]);
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

fn decoding_key(jwk: &Value, algorithm: Algorithm) -> Result<DecodingKey, ProofError> {
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

fn decoding_key_trust(
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

fn timestamp_claim(value: &Value, name: &str) -> Option<chrono::DateTime<Utc>> {
    chrono::DateTime::from_timestamp(value.get(name)?.as_i64()?, 0)
}

fn jwk_to_cose_key(jwk: &Value) -> Result<coset::CoseKey, CredentialTrustError> {
    match jwk.get("kty").and_then(Value::as_str) {
        Some("EC") if jwk.get("crv").and_then(Value::as_str) == Some("P-256") => {
            jwk_to_ec2_cose_key(jwk)
        }
        _ => Err(CredentialTrustError::InvalidHolderBinding),
    }
}

fn jwk_to_ec2_cose_key(jwk: &Value) -> Result<coset::CoseKey, CredentialTrustError> {
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

fn json_to_cbor(value: &Value) -> Result<ciborium::Value, CredentialTrustError> {
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

fn cbor_to_json(value: &ciborium::Value) -> Result<Value, CredentialTrustError> {
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

fn algorithm_name(algorithm: Algorithm) -> Option<&'static str> {
    match algorithm {
        Algorithm::ES256 => Some("ES256"),
        Algorithm::EdDSA => Some("EdDSA"),
        _ => None,
    }
}

fn p256_pkey_from_jwk(jwk: &Value) -> anyhow::Result<PKey<openssl::pkey::Public>> {
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
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
    let mut context = BigNumContext::new()?;
    let mut point = EcPoint::new(&group)?;
    let x = BigNum::from_slice(&x)?;
    let y = BigNum::from_slice(&y)?;
    point.set_affine_coordinates_gfp(&group, &x, &y, &mut context)?;
    Ok(PKey::from_ec_key(EcKey::from_public_key(&group, &point)?)?)
}
