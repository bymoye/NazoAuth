use std::{future::Future, pin::Pin};

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::{PresentationResult, PresentationTransaction};

pub type PresentationStoreFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[derive(Clone, Debug, PartialEq)]
pub struct StoredPresentation {
    pub transaction: PresentationTransaction,
    pub completed: Option<PresentationResult>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PresentationCompletionBinding<'a> {
    pub context_sha256: &'a str,
    pub intent_jws: &'a str,
    pub presentation_request_sha256: &'a str,
    pub trust_policy_binding_id: Option<Uuid>,
    pub trust_policy_resource_id: Option<&'a str>,
    pub trust_policy_digest: Option<&'a str>,
}

pub trait PresentationStorePort: Send + Sync {
    fn create<'a>(
        &'a self,
        transaction: &'a PresentationTransaction,
    ) -> PresentationStoreFuture<'a, Result<(), PresentationStoreError>>;

    fn request<'a>(
        &'a self,
        transaction_id: Uuid,
        now: DateTime<Utc>,
    ) -> PresentationStoreFuture<'a, Result<Option<PresentationTransaction>, PresentationStoreError>>;

    fn bind_wallet_nonce<'a>(
        &'a self,
        transaction_id: Uuid,
        wallet_nonce: &'a str,
        now: DateTime<Utc>,
    ) -> PresentationStoreFuture<'a, Result<Option<PresentationTransaction>, PresentationStoreError>>;

    fn complete<'a>(
        &'a self,
        transaction_id: Uuid,
        state_hash: &'a str,
        result: &'a PresentationResult,
        verification_binding: Option<PresentationCompletionBinding<'a>>,
        now: DateTime<Utc>,
    ) -> PresentationStoreFuture<'a, Result<bool, PresentationStoreError>>;

    fn result<'a>(
        &'a self,
        transaction_id: Uuid,
        now: DateTime<Utc>,
    ) -> PresentationStoreFuture<'a, Result<Option<StoredPresentation>, PresentationStoreError>>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PresentationStoreError {
    #[error("presentation store is unavailable")]
    Unavailable,
    #[error("presentation state transition is invalid")]
    InvalidTransition,
}
