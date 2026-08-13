use chrono::{DateTime, Utc};
use nazo_digital_credentials::{
    CredentialFormat, CredentialVerifierPort, PresentedCredential, VerifiedCredential,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{
    AuthorizationResponse, PresentationError, PresentationResult, PresentationStoreError,
    PresentationStorePort, PresentationTransaction, ResponseMode,
};

#[derive(Clone, Debug, PartialEq)]
pub struct VerifiedPresentation {
    pub credentials: Vec<VerifiedCredential>,
}

pub struct PresentationService<S, V> {
    store: S,
    verifier: V,
}

impl<S, V> PresentationService<S, V>
where
    S: PresentationStorePort,
    V: CredentialVerifierPort,
{
    pub const fn new(store: S, verifier: V) -> Self {
        Self { store, verifier }
    }

    pub async fn verify_response(
        &self,
        transaction: &PresentationTransaction,
        response: &AuthorizationResponse,
        additional_trust_anchors: &[Vec<u8>],
        now: DateTime<Utc>,
    ) -> Result<PresentationResult, PresentationServiceError> {
        if now >= transaction.expires_at
            || response.state.as_deref() != Some(transaction.request.state.as_str())
            || response.error.is_some()
            || transaction.request.transaction_data.is_some()
        {
            return Err(PresentationError::InvalidState.into());
        }
        let vp_token = response
            .vp_token
            .as_ref()
            .ok_or(PresentationError::InvalidResponse)?;
        let object = vp_token
            .as_object()
            .ok_or(PresentationError::InvalidResponse)?;
        let mdoc_session_transcript = mdoc_session_transcript(transaction)?;
        let mut verified = Vec::new();
        let mut satisfied = std::collections::BTreeSet::new();
        for query in &transaction.request.dcql_query.credentials {
            let Some(values) = object.get(&query.id).and_then(Value::as_array) else {
                continue;
            };
            if values.is_empty() {
                return Err(PresentationError::DcqlUnsatisfied.into());
            }
            for value in values {
                let encoded = value.as_str().ok_or(PresentationError::InvalidResponse)?;
                let credential = self
                    .verifier
                    .verify(&PresentedCredential {
                        format: query.format,
                        encoded: encoded.to_owned(),
                        expected_nonce: transaction.request.nonce.clone(),
                        expected_audience: transaction.request.client_id.clone(),
                        response_uri: transaction.request.response_uri.clone(),
                        mdoc_session_transcript: (query.format == CredentialFormat::MsoMdoc)
                            .then(|| mdoc_session_transcript.clone())
                            .flatten(),
                        additional_trust_anchors: additional_trust_anchors.to_vec(),
                    })
                    .await
                    .map_err(|_| PresentationError::UntrustedPresentation)?;
                if credential.format != query.format {
                    return Err(PresentationError::DcqlUnsatisfied.into());
                }
                if !credential_matches_query(&credential, query) {
                    return Err(PresentationError::DcqlUnsatisfied.into());
                }
                verified.push(credential);
            }
            satisfied.insert(query.id.as_str());
        }
        if let Some(sets) = &transaction.request.dcql_query.credential_sets {
            for set in sets.iter().filter(|set| set.required) {
                if !set
                    .options
                    .iter()
                    .any(|option| option.iter().all(|id| satisfied.contains(id.as_str())))
                {
                    return Err(PresentationError::DcqlUnsatisfied.into());
                }
            }
        } else if satisfied.len() != transaction.request.dcql_query.credentials.len() {
            return Err(PresentationError::DcqlUnsatisfied.into());
        }
        let result = PresentationResult {
            transaction_id: transaction.id,
            credentials: verified,
            completed_at: now,
        };
        let state_hash = blake3::hash(transaction.request.state.as_bytes())
            .to_hex()
            .to_string();
        if !self
            .store
            .complete(transaction.id, &state_hash, &result, now)
            .await?
        {
            return Err(PresentationError::InvalidState.into());
        }
        Ok(result)
    }
}

fn mdoc_session_transcript(
    transaction: &PresentationTransaction,
) -> Result<Option<Vec<u8>>, PresentationServiceError> {
    if !transaction
        .request
        .dcql_query
        .credentials
        .iter()
        .any(|query| query.format == CredentialFormat::MsoMdoc)
    {
        return Ok(None);
    }
    let verifier_key_thumbprint = if transaction.response_mode == ResponseMode::DirectPostJwt {
        transaction
            .request
            .client_metadata
            .as_ref()
            .and_then(|metadata| metadata.jwks.as_ref())
            .map(jwk_set_thumbprint)
            .transpose()?
    } else {
        None
    };
    let handover_info = ciborium::Value::Array(vec![
        ciborium::Value::Text(transaction.request.client_id.clone()),
        ciborium::Value::Text(transaction.request.nonce.clone()),
        verifier_key_thumbprint
            .map(ciborium::Value::Bytes)
            .unwrap_or(ciborium::Value::Null),
        ciborium::Value::Text(transaction.request.response_uri.clone()),
    ]);
    let mut encoded_handover_info = Vec::new();
    ciborium::into_writer(&handover_info, &mut encoded_handover_info)
        .map_err(|_| PresentationError::InvalidRequest)?;
    let transcript = ciborium::Value::Array(vec![
        ciborium::Value::Null,
        ciborium::Value::Null,
        ciborium::Value::Array(vec![
            ciborium::Value::Text("OpenID4VPHandover".to_owned()),
            ciborium::Value::Bytes(Sha256::digest(encoded_handover_info).to_vec()),
        ]),
    ]);
    let mut encoded = Vec::new();
    ciborium::into_writer(&transcript, &mut encoded)
        .map_err(|_| PresentationError::InvalidRequest)?;
    Ok(Some(encoded))
}

fn jwk_set_thumbprint(jwks: &Value) -> Result<Vec<u8>, PresentationServiceError> {
    let keys = jwks
        .get("keys")
        .and_then(Value::as_array)
        .filter(|keys| keys.len() == 1)
        .ok_or(PresentationError::InvalidRequest)?;
    let key = &keys[0];
    let kty = key.get("kty").and_then(Value::as_str);
    let canonical = match kty {
        Some("EC") => serde_json::json!({
            "crv": key.get("crv").and_then(Value::as_str).ok_or(PresentationError::InvalidRequest)?,
            "kty": "EC",
            "x": key.get("x").and_then(Value::as_str).ok_or(PresentationError::InvalidRequest)?,
            "y": key.get("y").and_then(Value::as_str).ok_or(PresentationError::InvalidRequest)?,
        }),
        _ => return Err(PresentationError::InvalidRequest.into()),
    };
    let encoded = serde_json::to_vec(&canonical).map_err(|_| PresentationError::InvalidRequest)?;
    Ok(Sha256::digest(encoded).to_vec())
}

fn credential_matches_query(
    credential: &VerifiedCredential,
    query: &nazo_digital_credentials::CredentialQuery,
) -> bool {
    if query.require_cryptographic_holder_binding.unwrap_or(true) && credential.holder_key.is_none()
    {
        return false;
    }
    if let Some(meta) = query.meta.as_ref() {
        match query.format {
            nazo_digital_credentials::CredentialFormat::SdJwtVc => {
                let values = meta.get("vct_values").and_then(Value::as_array);
                if values.is_some_and(|values| {
                    !values
                        .iter()
                        .any(|value| value.as_str() == Some(&credential.credential_type))
                }) {
                    return false;
                }
            }
            nazo_digital_credentials::CredentialFormat::MsoMdoc => {
                if meta
                    .get("doctype_value")
                    .and_then(Value::as_str)
                    .is_some_and(|value| value != credential.credential_type)
                {
                    return false;
                }
            }
        }
    }
    if query
        .trusted_authorities
        .as_ref()
        .is_some_and(|authorities| {
            !authorities.iter().any(|authority| {
                matches!(authority.authority_type.as_str(), "issuer" | "aki")
                    && authority
                        .values
                        .iter()
                        .any(|value| value == &credential.issuer)
            })
        })
    {
        return false;
    }
    let Some(claims) = query.claims.as_ref() else {
        return true;
    };
    let available = claims
        .iter()
        .filter(|claim| {
            claim_values(&credential.claims, &claim.path).is_some_and(|values| {
                claim
                    .values
                    .as_ref()
                    .is_none_or(|allowed| values.iter().any(|value| allowed.contains(value)))
            })
        })
        .filter_map(|claim| claim.id.as_deref())
        .collect::<std::collections::BTreeSet<_>>();
    let all_available = claims.iter().all(|claim| {
        claim_values(&credential.claims, &claim.path).is_some_and(|values| {
            claim
                .values
                .as_ref()
                .is_none_or(|allowed| values.iter().any(|value| allowed.contains(value)))
        })
    });
    query.claim_sets.as_ref().map_or(all_available, |sets| {
        sets.iter()
            .any(|set| set.iter().all(|id| available.contains(id.as_str())))
    })
}

fn claim_values<'a>(
    value: &'a Value,
    path: &[nazo_digital_credentials::ClaimPathSegment],
) -> Option<Vec<&'a Value>> {
    let mut current = vec![value];
    for segment in path {
        let mut next = Vec::new();
        for value in current {
            match segment {
                nazo_digital_credentials::ClaimPathSegment::Name(name) => {
                    next.extend(value.get(name))
                }
                nazo_digital_credentials::ClaimPathSegment::Index(index) => {
                    next.extend(value.get(*index as usize))
                }
                nazo_digital_credentials::ClaimPathSegment::Wildcard(_) => {
                    next.extend(value.as_array()?.iter())
                }
            }
        }
        if next.is_empty() {
            return None;
        }
        current = next;
    }
    Some(current)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PresentationServiceError {
    #[error(transparent)]
    Presentation(#[from] PresentationError),
    #[error(transparent)]
    Store(#[from] PresentationStoreError),
}
