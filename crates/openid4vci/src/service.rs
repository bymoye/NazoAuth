use std::{future::Future, pin::Pin};

use chrono::{DateTime, Utc};
use nazo_digital_credentials::{CredentialPayload, CredentialSignInput, CredentialSignerPort};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::{
    CredentialAccess, CredentialConfiguration, CredentialError, CredentialRequest,
    CredentialResponse, CredentialStorePort, IssuedCredential, ProofError, ProofValidatorPort,
    StoredCredentialResponse,
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssuanceClaim {
    nonce_hash: String,
    claim_id: String,
}

#[derive(Clone, Debug, PartialEq)]
pub enum IssuanceCommit {
    Immediate {
        notification_handle: crate::NotificationHandle,
        nonce_claim: Option<IssuanceClaim>,
    },
    Deferred {
        credential: Box<crate::DeferredCredential>,
        nonce_claim: Option<IssuanceClaim>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssuanceIdentity {
    pub issuance_id: Uuid,
    pub request_digest: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct PendingCredentialIssuance {
    pub response: CredentialResponse,
    pub commit: IssuanceCommit,
    pub issuance_id: Uuid,
    pub request_digest: String,
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
        let pending = self
            .issue_pending(access, request, issuance, expected_nonce, now)
            .await?;
        if let Err(error) = self.commit_pending(&pending, now).await {
            let _ = self.rollback_pending(&pending, now).await;
            return Err(error);
        }
        Ok(pending.response)
    }

    /// Prepare a credential response without committing single-use state.
    ///
    /// The HTTP adapter must call [`Self::commit_pending`] only after it has
    /// completely encoded/encrypted the response. This keeps malformed client
    /// response-encryption parameters from permanently consuming a proof nonce.
    pub async fn issue_pending(
        &self,
        access: &CredentialAccess,
        request: &CredentialRequest,
        issuance: &CredentialIssuance,
        expected_nonce: &str,
        now: DateTime<Utc>,
    ) -> Result<PendingCredentialIssuance, CredentialIssuanceError> {
        self.issue_pending_with_identity(
            access,
            request,
            issuance,
            expected_nonce,
            IssuanceIdentity {
                issuance_id: Uuid::now_v7(),
                request_digest: "legacy".to_owned(),
            },
            now,
        )
        .await
    }

    pub async fn issue_pending_with_identity(
        &self,
        access: &CredentialAccess,
        request: &CredentialRequest,
        issuance: &CredentialIssuance,
        expected_nonce: &str,
        identity: IssuanceIdentity,
        now: DateTime<Utc>,
    ) -> Result<PendingCredentialIssuance, CredentialIssuanceError> {
        request.validate_identifier()?;
        if now >= access.expires_at
            || !access
                .configuration_ids
                .contains(&issuance.configuration_id)
        {
            return Err(CredentialIssuanceError::Unauthorized);
        }
        let mut nonce_claim = None;
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
            if validated.is_empty() {
                return Err(CredentialIssuanceError::Credential(
                    CredentialError::InvalidNonce,
                ));
            }
            let nonce_hash = blake3::hash(expected_nonce.as_bytes()).to_hex().to_string();
            let claim_id = Uuid::now_v7().to_string();
            // Proof validation is asynchronous; use a fresh clock value for
            // the expiry check rather than the request-start timestamp.
            let claim_now = std::cmp::max(now, Utc::now());
            if claim_now >= access.expires_at {
                return Err(CredentialIssuanceError::Unauthorized);
            }
            if !self
                .store
                .claim_nonce(&nonce_hash, &claim_id, claim_now)
                .await?
            {
                return Err(CredentialIssuanceError::Credential(
                    CredentialError::InvalidNonce,
                ));
            }
            nonce_claim = Some(IssuanceClaim {
                nonce_hash,
                claim_id,
            });
            validated
                .into_iter()
                .map(|proof| proof.holder_binding)
                .collect()
        };
        let claim_for_rollback = nonce_claim.clone();
        let result = self
            .prepare_after_nonce_claim(
                access,
                issuance,
                holder_bindings,
                nonce_claim,
                identity,
                now,
            )
            .await;
        match result {
            Ok(pending) => Ok(pending),
            Err(error) => {
                if let Some(claim) = claim_for_rollback {
                    let _ = self
                        .store
                        .release_nonce(&claim.nonce_hash, &claim.claim_id, now)
                        .await;
                }
                Err(error)
            }
        }
    }

    pub async fn commit_pending(
        &self,
        pending: &PendingCredentialIssuance,
        now: DateTime<Utc>,
    ) -> Result<(), CredentialIssuanceError> {
        self.commit_pending_internal(pending, None, now).await
    }

    pub async fn commit_pending_with_response(
        &self,
        pending: &PendingCredentialIssuance,
        response: &StoredCredentialResponse,
        now: DateTime<Utc>,
    ) -> Result<(), CredentialIssuanceError> {
        let expected_token_id = match &pending.commit {
            IssuanceCommit::Immediate {
                notification_handle,
                ..
            } => notification_handle.token_id,
            IssuanceCommit::Deferred { credential, .. } => credential.access.token_id,
        };
        if response.issuance_id != pending.issuance_id
            || response.request_digest != pending.request_digest
            || response.token_id != expected_token_id
        {
            return Err(CredentialIssuanceError::Store(
                crate::CredentialStoreError::InvalidTransition,
            ));
        }
        self.commit_pending_internal(pending, Some(response), now)
            .await
    }

    async fn commit_pending_internal(
        &self,
        pending: &PendingCredentialIssuance,
        response: Option<&StoredCredentialResponse>,
        now: DateTime<Utc>,
    ) -> Result<(), CredentialIssuanceError> {
        match &pending.commit {
            IssuanceCommit::Immediate {
                notification_handle,
                nonce_claim,
            } => {
                if let Some(claim) = nonce_claim {
                    let committed = if let Some(response) = response {
                        self.store
                            .finalize_nonce_with_notification_and_response(
                                &claim.nonce_hash,
                                &claim.claim_id,
                                notification_handle,
                                response,
                                now,
                            )
                            .await?
                    } else {
                        self.store
                            .finalize_nonce_with_notification(
                                &claim.nonce_hash,
                                &claim.claim_id,
                                notification_handle,
                                now,
                            )
                            .await?
                    };
                    if !committed {
                        return Err(CredentialIssuanceError::Store(
                            crate::CredentialStoreError::InvalidTransition,
                        ));
                    }
                } else {
                    if let Some(response) = response {
                        self.store
                            .store_response_with_notification(notification_handle, response, now)
                            .await?;
                    } else {
                        self.store
                            .issue_notification_handle(notification_handle)
                            .await?;
                    }
                }
            }
            IssuanceCommit::Deferred {
                credential,
                nonce_claim,
            } => {
                if let Some(claim) = nonce_claim {
                    if let Some(response) = response {
                        self.store
                            .store_deferred_and_finalize_nonce_with_response(
                                credential,
                                &claim.nonce_hash,
                                &claim.claim_id,
                                response,
                                now,
                            )
                            .await?;
                    } else {
                        self.store
                            .store_deferred_and_finalize_nonce(
                                credential,
                                &claim.nonce_hash,
                                &claim.claim_id,
                                now,
                            )
                            .await?;
                    }
                } else {
                    if let Some(response) = response {
                        self.store
                            .store_deferred_with_response(credential, response, now)
                            .await?;
                    } else {
                        self.store.store_deferred(credential).await?;
                    }
                }
            }
        }
        Ok(())
    }

    pub async fn rollback_pending(
        &self,
        pending: &PendingCredentialIssuance,
        now: DateTime<Utc>,
    ) -> Result<(), CredentialIssuanceError> {
        let claim = match &pending.commit {
            IssuanceCommit::Immediate { nonce_claim, .. }
            | IssuanceCommit::Deferred { nonce_claim, .. } => nonce_claim.as_ref(),
        };
        if let Some(claim) = claim {
            self.store
                .release_nonce(&claim.nonce_hash, &claim.claim_id, now)
                .await?;
        }
        Ok(())
    }

    async fn prepare_after_nonce_claim(
        &self,
        access: &CredentialAccess,
        issuance: &CredentialIssuance,
        holder_bindings: Vec<Value>,
        nonce_claim: Option<IssuanceClaim>,
        identity: IssuanceIdentity,
        now: DateTime<Utc>,
    ) -> Result<PendingCredentialIssuance, CredentialIssuanceError> {
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
                let notification_handle = crate::NotificationHandle {
                    notification_id: notification_id.clone(),
                    token_id: access.token_id,
                    expires_at: access.expires_at.min(issuance.expires_at),
                };
                Ok(PendingCredentialIssuance {
                    response: CredentialResponse {
                        credentials: Some(credentials),
                        transaction_id: None,
                        notification_id: Some(notification_id),
                        interval: None,
                    },
                    commit: IssuanceCommit::Immediate {
                        notification_handle,
                        nonce_claim,
                    },
                    issuance_id: identity.issuance_id,
                    request_digest: identity.request_digest,
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
                let deferred = crate::DeferredCredential {
                    id: Uuid::now_v7(),
                    transaction_hash: blake3::hash(transaction_id.as_bytes()).to_hex().to_string(),
                    access: access.clone(),
                    configuration_id: issuance.configuration_id.clone(),
                    format: issuance.configuration.format,
                    holder_bindings,
                    payload_ciphertext: serde_json::to_vec(&protected)
                        .map_err(|_| CredentialIssuanceError::InvalidConfiguration)?,
                    ready_at,
                    expires_at: access.expires_at.min(issuance.expires_at),
                };
                Ok(PendingCredentialIssuance {
                    response: CredentialResponse {
                        credentials: None,
                        transaction_id: Some(transaction_id),
                        notification_id: None,
                        interval: Some(5),
                    },
                    commit: IssuanceCommit::Deferred {
                        credential: Box::new(deferred),
                        nonce_claim,
                    },
                    issuance_id: identity.issuance_id,
                    request_digest: identity.request_digest,
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
