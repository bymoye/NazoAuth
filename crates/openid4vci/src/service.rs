use std::{future::Future, pin::Pin};

use chrono::{DateTime, Utc};
use nazo_digital_credentials::{CredentialPayload, CredentialSignInput, CredentialSignerPort};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::{
    CredentialAccess, CredentialConfiguration, CredentialError, CredentialRequest,
    CredentialResponse, CredentialStorePort, IssuedCredential, ProofError, ProofValidatorPort,
};

pub trait CredentialDatasetPort: Send + Sync {
    fn dataset<'a>(
        &'a self,
        access: &'a CredentialAccess,
        configuration_id: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Value, CredentialIssuanceError>> + Send + 'a>>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IssuanceDisposition {
    Immediate,
    Deferred { ready_at: DateTime<Utc> },
}

#[derive(Clone, Debug, PartialEq)]
pub struct CredentialIssuance {
    pub configuration_id: String,
    pub configuration: CredentialConfiguration,
    pub disposition: IssuanceDisposition,
    pub status: Option<Value>,
    pub expires_at: DateTime<Utc>,
}

pub struct CredentialIssuerService<S, P, D, K> {
    store: S,
    proofs: P,
    datasets: D,
    signer: K,
    issuer: String,
    max_batch_size: usize,
}

impl<S, P, D, K> CredentialIssuerService<S, P, D, K>
where
    S: CredentialStorePort,
    P: ProofValidatorPort,
    D: CredentialDatasetPort,
    K: CredentialSignerPort,
{
    pub fn new(
        store: S,
        proofs: P,
        datasets: D,
        signer: K,
        issuer: String,
        max_batch_size: usize,
    ) -> Self {
        Self {
            store,
            proofs,
            datasets,
            signer,
            issuer,
            max_batch_size: max_batch_size.max(1),
        }
    }

    pub async fn issue(
        &self,
        access: &CredentialAccess,
        request: &CredentialRequest,
        issuance: &CredentialIssuance,
        expected_nonce: &str,
        now: DateTime<Utc>,
    ) -> Result<CredentialResponse, CredentialIssuanceError> {
        request.validate_identifier()?;
        if now >= access.expires_at
            || !access
                .configuration_ids
                .contains(&issuance.configuration_id)
        {
            return Err(CredentialIssuanceError::Unauthorized);
        }
        let holder_bindings = if issuance.configuration.proof_types_supported.is_empty() {
            if request
                .proofs
                .as_ref()
                .is_some_and(|proofs| proofs.count() != 0)
                || !issuance
                    .configuration
                    .cryptographic_binding_methods_supported
                    .is_empty()
            {
                return Err(CredentialIssuanceError::Credential(
                    CredentialError::InvalidProof,
                ));
            }
            vec![Value::Null]
        } else {
            let proofs = request
                .proofs
                .as_ref()
                .ok_or(CredentialIssuanceError::Credential(
                    CredentialError::InvalidProof,
                ))?;
            if proofs.count() == 0 || proofs.count() > self.max_batch_size || proofs.0.len() != 1 {
                return Err(CredentialIssuanceError::Credential(
                    CredentialError::InvalidProof,
                ));
            }
            let proof_type = proofs
                .0
                .first_key_value()
                .map(|(proof_type, _)| proof_type)
                .ok_or(CredentialIssuanceError::Credential(
                    CredentialError::InvalidProof,
                ))?;
            let proof_metadata = issuance
                .configuration
                .proof_types_supported
                .get(proof_type)
                .ok_or(CredentialIssuanceError::Credential(
                    CredentialError::InvalidProof,
                ))?;
            let validated = self
                .proofs
                .validate(
                    proofs,
                    &access.client_id,
                    &self.issuer,
                    expected_nonce,
                    proof_metadata,
                )
                .await?;
            if validated.is_empty()
                || !self
                    .store
                    .consume_nonce(&blake3::hash(expected_nonce.as_bytes()).to_hex(), now)
                    .await?
            {
                return Err(CredentialIssuanceError::Credential(
                    CredentialError::InvalidNonce,
                ));
            }
            validated
                .into_iter()
                .map(|proof| proof.holder_binding)
                .collect()
        };
        let dataset = self
            .datasets
            .dataset(access, &issuance.configuration_id)
            .await?;
        match issuance.disposition {
            IssuanceDisposition::Immediate => {
                let mut credentials = Vec::with_capacity(holder_bindings.len());
                let issued_at = batch_privacy_claim_time(now);
                let expires_at = batch_privacy_claim_time(issuance.expires_at);
                for holder_binding in holder_bindings {
                    let credential = self
                        .signer
                        .sign(&CredentialSignInput {
                            payload: CredentialPayload {
                                issuer: self.issuer.clone(),
                                format: issuance.configuration.format,
                                configuration_id: issuance.configuration_id.clone(),
                                credential_type: issuance
                                    .configuration
                                    .vct
                                    .clone()
                                    .or_else(|| issuance.configuration.doctype.clone())
                                    .ok_or(CredentialIssuanceError::InvalidConfiguration)?,
                                subject_claims: dataset.clone(),
                                holder_binding: serde_json::from_value(holder_binding).ok(),
                                selectively_disclosable_claims: Vec::new(),
                            },
                            issued_at,
                            expires_at,
                            status: issuance.status.clone(),
                        })
                        .await?;
                    credentials.push(IssuedCredential {
                        credential: Value::String(credential),
                    });
                }
                let notification_id = Uuid::now_v7().to_string();
                self.store
                    .issue_notification_handle(&crate::NotificationHandle {
                        notification_id: notification_id.clone(),
                        token_id: access.token_id,
                        expires_at: access.expires_at.min(issuance.expires_at),
                    })
                    .await?;
                Ok(CredentialResponse {
                    credentials: Some(credentials),
                    transaction_id: None,
                    notification_id: Some(notification_id),
                    interval: None,
                })
            }
            IssuanceDisposition::Deferred { ready_at } => {
                let transaction_id = Uuid::now_v7().to_string();
                let protected = DeferredPayload {
                    dataset,
                    status: issuance.status.clone(),
                    issued_at: now,
                    expires_at: issuance.expires_at,
                };
                self.store
                    .store_deferred(&crate::DeferredCredential {
                        id: Uuid::now_v7(),
                        transaction_hash: blake3::hash(transaction_id.as_bytes())
                            .to_hex()
                            .to_string(),
                        access: access.clone(),
                        configuration_id: issuance.configuration_id.clone(),
                        format: issuance.configuration.format,
                        holder_bindings,
                        payload_ciphertext: serde_json::to_vec(&protected)
                            .map_err(|_| CredentialIssuanceError::InvalidConfiguration)?,
                        ready_at,
                        expires_at: access.expires_at.min(issuance.expires_at),
                    })
                    .await?;
                Ok(CredentialResponse {
                    credentials: None,
                    transaction_id: Some(transaction_id),
                    notification_id: None,
                    interval: Some(5),
                })
            }
        }
    }
}

fn batch_privacy_claim_time(value: DateTime<Utc>) -> DateTime<Utc> {
    let timestamp = value.timestamp();
    let rounded = timestamp - timestamp.rem_euclid(86_400);
    DateTime::<Utc>::from_timestamp(rounded, 0).unwrap_or(value)
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DeferredPayload {
    pub dataset: Value,
    pub status: Option<Value>,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum CredentialIssuanceError {
    #[error(transparent)]
    Credential(#[from] CredentialError),
    #[error(transparent)]
    Proof(#[from] ProofError),
    #[error(transparent)]
    Store(#[from] crate::CredentialStoreError),
    #[error("credential access is unauthorized")]
    Unauthorized,
    #[error("credential configuration is invalid")]
    InvalidConfiguration,
    #[error("credential dataset is unavailable")]
    DatasetUnavailable,
    #[error("credential signing failed")]
    SigningFailed,
    #[error("credential holder binding is invalid")]
    InvalidHolderBinding,
}

impl From<nazo_digital_credentials::CredentialTrustError> for CredentialIssuanceError {
    fn from(error: nazo_digital_credentials::CredentialTrustError) -> Self {
        match error {
            nazo_digital_credentials::CredentialTrustError::InvalidHolderBinding => {
                Self::InvalidHolderBinding
            }
            _ => Self::SigningFailed,
        }
    }
}
