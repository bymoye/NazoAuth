use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

use chrono::{Duration, Utc};
use nazo_digital_credentials::{
    CredentialFormat, CredentialFuture, CredentialSignInput, CredentialSignerPort,
    CredentialTrustError,
};
use nazo_openid4vci::{
    CredentialAccess, CredentialConfiguration, CredentialDatasetPort, CredentialError,
    CredentialIdentifier, CredentialIssuance, CredentialIssuanceError, CredentialIssuerService,
    CredentialRequest, CredentialStoreError, CredentialStoreFuture, CredentialStorePort,
    DeferredCredential, DeferredCredentialClaim, IssuanceCommit, IssuanceDisposition,
    IssuanceIdentity, IssuanceNotification, NonceRecord, NotificationHandle, ProofError,
    ProofTypeMetadata, ProofValidatorPort, Proofs, StoredCredentialOffer, StoredCredentialResponse,
    ValidatedProof,
};
use serde_json::{Value, json};
use uuid::Uuid;

#[derive(Clone, Default)]
struct RecordingStore {
    nonce_consumed: Arc<Mutex<bool>>,
    nonce_finalized: Arc<Mutex<usize>>,
    nonce_released: Arc<Mutex<usize>>,
    notifications: Arc<Mutex<Vec<NotificationHandle>>>,
    deferred: Arc<Mutex<Vec<DeferredCredential>>>,
    responses: Arc<Mutex<Vec<StoredCredentialResponse>>>,
    commit_success: Arc<Mutex<Option<bool>>>,
}

impl RecordingStore {
    fn commit_is_allowed(&self) -> bool {
        self.commit_success.lock().unwrap().unwrap_or(true)
    }

    fn notification_exists(&self, handle: &NotificationHandle) -> bool {
        self.notifications.lock().unwrap().iter().any(|stored| {
            stored.notification_id == handle.notification_id && stored.token_id == handle.token_id
        })
    }

    fn response_exists(&self, response: &StoredCredentialResponse) -> bool {
        self.responses.lock().unwrap().iter().any(|stored| {
            stored.token_id == response.token_id && stored.request_digest == response.request_digest
        })
    }

    fn deferred_exists(&self, credential: &DeferredCredential) -> bool {
        self.deferred.lock().unwrap().iter().any(|stored| {
            stored.transaction_hash == credential.transaction_hash
                && stored.access.token_id == credential.access.token_id
        })
    }
}

impl CredentialStorePort for RecordingStore {
    fn upsert_access<'a>(
        &'a self,
        _: &'a str,
        _: &'a CredentialAccess,
    ) -> CredentialStoreFuture<'a, Result<(), CredentialStoreError>> {
        Box::pin(async { Ok(()) })
    }
    fn offer<'a>(
        &'a self,
        _: Uuid,
        _: Uuid,
        _: chrono::DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<Option<StoredCredentialOffer>, CredentialStoreError>>
    {
        Box::pin(async { Ok(None) })
    }
    fn consume_pre_authorized_offer<'a>(
        &'a self,
        _: Uuid,
        _: &'a str,
        _: Option<&'a str>,
        _: &'a str,
        _: chrono::DateTime<Utc>,
    ) -> CredentialStoreFuture<
        'a,
        Result<Option<nazo_openid4vci::CredentialAuthorization>, CredentialStoreError>,
    > {
        Box::pin(async { Ok(None) })
    }
    fn issue_nonce<'a>(
        &'a self,
        _: &'a NonceRecord,
    ) -> CredentialStoreFuture<'a, Result<(), CredentialStoreError>> {
        Box::pin(async { Ok(()) })
    }
    fn consume_nonce<'a>(
        &'a self,
        _: &'a str,
        _: chrono::DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>> {
        Box::pin(async move {
            let mut consumed = self.nonce_consumed.lock().unwrap();
            if *consumed {
                Ok(false)
            } else {
                *consumed = true;
                Ok(true)
            }
        })
    }
    fn claim_nonce<'a>(
        &'a self,
        nonce_hash: &'a str,
        _: &'a str,
        now: chrono::DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>> {
        self.consume_nonce(nonce_hash, now)
    }
    fn finalize_nonce<'a>(
        &'a self,
        _: &'a str,
        _: &'a str,
        _: chrono::DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>> {
        Box::pin(async move {
            *self.nonce_finalized.lock().unwrap() += 1;
            Ok(true)
        })
    }
    fn finalize_nonce_with_notification<'a>(
        &'a self,
        _: &'a str,
        _: &'a str,
        handle: &'a NotificationHandle,
        _: chrono::DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>> {
        Box::pin(async move {
            if !self.commit_is_allowed() || self.notification_exists(handle) {
                return Ok(false);
            }
            *self.nonce_finalized.lock().unwrap() += 1;
            self.notifications.lock().unwrap().push(handle.clone());
            Ok(true)
        })
    }
    fn find_response<'a>(
        &'a self,
        _: Uuid,
        _: Uuid,
        _: &'a str,
        _: chrono::DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<Option<StoredCredentialResponse>, CredentialStoreError>>
    {
        Box::pin(async { Ok(None) })
    }
    fn release_nonce<'a>(
        &'a self,
        _: &'a str,
        _: &'a str,
        _: chrono::DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>> {
        Box::pin(async move {
            *self.nonce_consumed.lock().unwrap() = false;
            *self.nonce_released.lock().unwrap() += 1;
            Ok(true)
        })
    }

    fn finalize_nonce_with_notification_and_response<'a>(
        &'a self,
        _: &'a str,
        _: &'a str,
        handle: &'a NotificationHandle,
        response: &'a StoredCredentialResponse,
        _: chrono::DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>> {
        Box::pin(async move {
            if !self.commit_is_allowed()
                || self.notification_exists(handle)
                || self.response_exists(response)
            {
                return Ok(false);
            }
            *self.nonce_finalized.lock().unwrap() += 1;
            self.notifications.lock().unwrap().push(handle.clone());
            self.responses.lock().unwrap().push(response.clone());
            Ok(true)
        })
    }

    fn store_response_with_notification<'a>(
        &'a self,
        handle: &'a NotificationHandle,
        response: &'a StoredCredentialResponse,
        _: chrono::DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<(), CredentialStoreError>> {
        Box::pin(async move {
            if !self.commit_is_allowed()
                || self.notification_exists(handle)
                || self.response_exists(response)
            {
                return Err(CredentialStoreError::InvalidTransition);
            }
            self.notifications.lock().unwrap().push(handle.clone());
            self.responses.lock().unwrap().push(response.clone());
            Ok(())
        })
    }
    fn resolve_access<'a>(
        &'a self,
        _: &'a str,
        _: chrono::DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<Option<CredentialAccess>, CredentialStoreError>> {
        Box::pin(async { Ok(None) })
    }
    fn store_deferred<'a>(
        &'a self,
        credential: &'a DeferredCredential,
    ) -> CredentialStoreFuture<'a, Result<(), CredentialStoreError>> {
        Box::pin(async move {
            if !self.commit_is_allowed() || self.deferred_exists(credential) {
                return Err(CredentialStoreError::InvalidTransition);
            }
            self.deferred.lock().unwrap().push(credential.clone());
            Ok(())
        })
    }
    fn store_deferred_and_finalize_nonce<'a>(
        &'a self,
        credential: &'a DeferredCredential,
        _: &'a str,
        _: &'a str,
        _: chrono::DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<(), CredentialStoreError>> {
        Box::pin(async move {
            if !self.commit_is_allowed() || self.deferred_exists(credential) {
                return Err(CredentialStoreError::InvalidTransition);
            }
            self.deferred.lock().unwrap().push(credential.clone());
            *self.nonce_finalized.lock().unwrap() += 1;
            Ok(())
        })
    }

    fn store_deferred_and_finalize_nonce_with_response<'a>(
        &'a self,
        credential: &'a DeferredCredential,
        _: &'a str,
        _: &'a str,
        response: &'a StoredCredentialResponse,
        _: chrono::DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<(), CredentialStoreError>> {
        Box::pin(async move {
            if !self.commit_is_allowed()
                || self.deferred_exists(credential)
                || self.response_exists(response)
            {
                return Err(CredentialStoreError::InvalidTransition);
            }
            self.deferred.lock().unwrap().push(credential.clone());
            self.responses.lock().unwrap().push(response.clone());
            *self.nonce_finalized.lock().unwrap() += 1;
            Ok(())
        })
    }

    fn store_deferred_with_response<'a>(
        &'a self,
        credential: &'a DeferredCredential,
        response: &'a StoredCredentialResponse,
        _: chrono::DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<(), CredentialStoreError>> {
        Box::pin(async move {
            if !self.commit_is_allowed()
                || self.deferred_exists(credential)
                || self.response_exists(response)
            {
                return Err(CredentialStoreError::InvalidTransition);
            }
            self.deferred.lock().unwrap().push(credential.clone());
            self.responses.lock().unwrap().push(response.clone());
            Ok(())
        })
    }
    fn consume_ready_deferred<'a>(
        &'a self,
        _: &'a str,
        _: Uuid,
        _: chrono::DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<Option<DeferredCredential>, CredentialStoreError>> {
        Box::pin(async { Ok(None) })
    }
    fn claim_ready_deferred<'a>(
        &'a self,
        _: &'a str,
        _: Uuid,
        _: &'a str,
        _: chrono::DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<Option<DeferredCredentialClaim>, CredentialStoreError>>
    {
        Box::pin(async { Ok(None) })
    }
    fn finalize_deferred<'a>(
        &'a self,
        _: &'a str,
        _: Uuid,
        _: &'a str,
        _: chrono::DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>> {
        Box::pin(async { Ok(true) })
    }
    fn release_deferred<'a>(
        &'a self,
        _: &'a str,
        _: Uuid,
        _: &'a str,
        _: chrono::DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>> {
        Box::pin(async { Ok(true) })
    }
    fn finalize_deferred_with_notification<'a>(
        &'a self,
        _: &'a str,
        _: Uuid,
        _: &'a str,
        handle: &'a NotificationHandle,
        _: chrono::DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>> {
        Box::pin(async move {
            if !self.commit_is_allowed() || self.notification_exists(handle) {
                return Ok(false);
            }
            self.notifications.lock().unwrap().push(handle.clone());
            Ok(true)
        })
    }

    fn finalize_deferred_with_notification_and_response<'a>(
        &'a self,
        _: &'a str,
        _: Uuid,
        _: &'a str,
        handle: &'a NotificationHandle,
        response: &'a StoredCredentialResponse,
        _: chrono::DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>> {
        Box::pin(async move {
            if !self.commit_is_allowed()
                || self.notification_exists(handle)
                || self.response_exists(response)
            {
                return Ok(false);
            }
            self.notifications.lock().unwrap().push(handle.clone());
            self.responses.lock().unwrap().push(response.clone());
            Ok(true)
        })
    }
    fn record_notification<'a>(
        &'a self,
        _: &'a IssuanceNotification,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>> {
        Box::pin(async { Ok(true) })
    }
    fn issue_notification_handle<'a>(
        &'a self,
        handle: &'a NotificationHandle,
    ) -> CredentialStoreFuture<'a, Result<(), CredentialStoreError>> {
        Box::pin(async move {
            if !self.commit_is_allowed() || self.notification_exists(handle) {
                return Err(CredentialStoreError::InvalidTransition);
            }
            self.notifications.lock().unwrap().push(handle.clone());
            Ok(())
        })
    }
}

#[derive(Clone)]
struct FixedProofs(Vec<ValidatedProof>);

impl ProofValidatorPort for FixedProofs {
    fn validate<'a>(
        &'a self,
        _: &'a Proofs,
        _: &'a str,
        _: &'a str,
        _: &'a str,
        _: &'a ProofTypeMetadata,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Vec<ValidatedProof>, ProofError>> + Send + 'a>,
    > {
        Box::pin(async move { Ok(self.0.clone()) })
    }
}

struct Dataset;

impl CredentialDatasetPort for Dataset {
    fn dataset<'a>(
        &'a self,
        _: &'a CredentialAccess,
        _: &'a str,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Value, CredentialIssuanceError>> + Send + 'a>,
    > {
        Box::pin(async { Ok(json!({"given_name":"Ada"})) })
    }
}

#[derive(Clone, Default)]
struct RecordingSigner(Arc<Mutex<Vec<CredentialSignInput>>>);

impl CredentialSignerPort for RecordingSigner {
    fn sign<'a>(
        &'a self,
        input: &'a CredentialSignInput,
    ) -> CredentialFuture<'a, Result<String, CredentialTrustError>> {
        Box::pin(async move {
            self.0.lock().unwrap().push(input.clone());
            Ok(format!("credential-{}", self.0.lock().unwrap().len()))
        })
    }
}

#[derive(Clone)]
struct InvalidHolderBindingSigner;

impl CredentialSignerPort for InvalidHolderBindingSigner {
    fn sign<'a>(
        &'a self,
        _: &'a CredentialSignInput,
    ) -> CredentialFuture<'a, Result<String, CredentialTrustError>> {
        Box::pin(async { Err(CredentialTrustError::InvalidHolderBinding) })
    }
}

#[derive(Clone, Copy)]
struct ErrorProofs(ProofError);

impl ProofValidatorPort for ErrorProofs {
    fn validate<'a>(
        &'a self,
        _: &'a Proofs,
        _: &'a str,
        _: &'a str,
        _: &'a str,
        _: &'a ProofTypeMetadata,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Vec<ValidatedProof>, ProofError>> + Send + 'a>,
    > {
        let error = self.0;
        Box::pin(async move { Err(error) })
    }
}

#[derive(Clone, Copy)]
struct ErrorDataset(CredentialIssuanceError);

impl CredentialDatasetPort for ErrorDataset {
    fn dataset<'a>(
        &'a self,
        _: &'a CredentialAccess,
        _: &'a str,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Value, CredentialIssuanceError>> + Send + 'a>,
    > {
        let error = self.0;
        Box::pin(async move { Err(error) })
    }
}

#[derive(Clone, Copy)]
struct ErrorSigner(CredentialTrustError);

impl CredentialSignerPort for ErrorSigner {
    fn sign<'a>(
        &'a self,
        _: &'a CredentialSignInput,
    ) -> CredentialFuture<'a, Result<String, CredentialTrustError>> {
        let error = self.0;
        Box::pin(async move { Err(error) })
    }
}

fn fixture(
    now: chrono::DateTime<Utc>,
) -> (CredentialAccess, CredentialIssuance, CredentialRequest) {
    let configuration = CredentialConfiguration {
        format: CredentialFormat::SdJwtVc,
        scope: Some("pid".to_owned()),
        cryptographic_binding_methods_supported: vec!["jwk".to_owned()],
        credential_signing_alg_values_supported: vec!["ES256".to_owned()],
        proof_types_supported: BTreeMap::from([(
            "jwt".to_owned(),
            ProofTypeMetadata {
                proof_signing_alg_values_supported: vec!["ES256".to_owned()],
                key_attestations_required: None,
            },
        )]),
        vct: Some("urn:example:pid".to_owned()),
        doctype: None,
        credential_metadata: None,
    };
    (
        CredentialAccess {
            token_id: Uuid::now_v7(),
            tenant_id: Uuid::now_v7(),
            subject_id: Uuid::now_v7(),
            client_id: "wallet".to_owned(),
            configuration_ids: vec!["pid".to_owned()],
            credential_identifiers: vec![CredentialIdentifier("pid-1".to_owned())],
            dpop_jkt: None,
            expires_at: now + Duration::minutes(5),
        },
        CredentialIssuance {
            configuration_id: "pid".to_owned(),
            configuration,
            disposition: IssuanceDisposition::Immediate,
            status: None,
            expires_at: now + Duration::days(30),
        },
        CredentialRequest {
            credential_identifier: None,
            credential_configuration_id: Some("pid".to_owned()),
            proofs: Some(Proofs(BTreeMap::from([(
                "jwt".to_owned(),
                vec![json!("one"), json!("two")],
            )]))),
            credential_response_encryption: None,
            extensions: BTreeMap::new(),
        },
    )
}

fn non_bound_fixture(
    now: chrono::DateTime<Utc>,
) -> (CredentialAccess, CredentialIssuance, CredentialRequest) {
    let (access, mut issuance, mut request) = fixture(now);
    issuance.configuration.proof_types_supported.clear();
    issuance
        .configuration
        .cryptographic_binding_methods_supported
        .clear();
    request.proofs = None;
    (access, issuance, request)
}

fn response_for_pending(
    pending: &nazo_openid4vci::PendingCredentialIssuance,
    now: chrono::DateTime<Utc>,
) -> StoredCredentialResponse {
    let token_id = match &pending.commit {
        IssuanceCommit::Immediate {
            notification_handle,
            ..
        } => notification_handle.token_id,
        IssuanceCommit::Deferred { credential, .. } => credential.access.token_id,
    };
    StoredCredentialResponse {
        issuance_id: pending.issuance_id,
        token_id,
        request_digest: pending.request_digest.clone(),
        body: br#"{"credentials":[]}"#.to_vec(),
        encoding: nazo_openid4vci::CredentialResponseEncoding::Json,
        status: 200,
        dpop_nonce: None,
        expires_at: now + Duration::minutes(10),
    }
}

#[tokio::test]
async fn batch_issuance_consumes_nonce_once_and_binds_each_credential() {
    let now = Utc::now();
    let store = RecordingStore::default();
    let signer = RecordingSigner::default();
    let proofs = FixedProofs(vec![
        ValidatedProof {
            proof_type: "jwt".to_owned(),
            holder_binding: json!({"jwk":{"kid":"holder-1"}}),
            nonce: "nonce".to_owned(),
            key_attestation: None,
        },
        ValidatedProof {
            proof_type: "jwt".to_owned(),
            holder_binding: json!({"jwk":{"kid":"holder-2"}}),
            nonce: "nonce".to_owned(),
            key_attestation: None,
        },
    ]);
    let service = CredentialIssuerService::new(
        store.clone(),
        proofs,
        Dataset,
        signer.clone(),
        "https://issuer.example".to_owned(),
        4,
    );
    let (access, issuance, request) = fixture(now);

    let pending = service
        .issue_pending(&access, &request, &issuance, "nonce", now)
        .await
        .unwrap();
    assert_eq!(*store.nonce_finalized.lock().unwrap(), 0);
    service.commit_pending(&pending, now).await.unwrap();
    let response = pending.response;
    assert_eq!(*store.nonce_finalized.lock().unwrap(), 1);
    assert_eq!(response.credentials.as_ref().map(Vec::len), Some(2));
    {
        let signed = signer.0.lock().unwrap();
        assert_ne!(
            signed[0].payload.holder_binding,
            signed[1].payload.holder_binding
        );
        assert_eq!(signed[0].issued_at.timestamp() % 86_400, 0);
        assert_eq!(signed[0].expires_at.timestamp() % 86_400, 0);
        assert_eq!(signed[0].issued_at, signed[1].issued_at);
        assert_eq!(signed[0].expires_at, signed[1].expires_at);
    }
    assert_eq!(store.notifications.lock().unwrap().len(), 1);

    assert_eq!(
        service
            .issue(&access, &request, &issuance, "nonce", now)
            .await,
        Err(CredentialIssuanceError::Credential(
            CredentialError::InvalidNonce
        ))
    );
}

#[tokio::test]
async fn invalid_holder_binding_remains_a_protocol_error_not_a_generic_signing_failure() {
    let now = Utc::now();
    let store = RecordingStore::default();
    let service = CredentialIssuerService::new(
        store.clone(),
        FixedProofs(vec![ValidatedProof {
            proof_type: "jwt".to_owned(),
            holder_binding: json!({"jwk":{"kty":"unsupported"}}),
            nonce: "nonce".to_owned(),
            key_attestation: None,
        }]),
        Dataset,
        InvalidHolderBindingSigner,
        "https://issuer.example".to_owned(),
        4,
    );
    let (access, issuance, request) = fixture(now);

    assert_eq!(
        service
            .issue(&access, &request, &issuance, "nonce", now)
            .await,
        Err(CredentialIssuanceError::InvalidHolderBinding)
    );
    assert_eq!(*store.nonce_released.lock().unwrap(), 1);
}

#[tokio::test]
async fn request_and_access_validation_rejects_ambiguous_or_unsupported_inputs() {
    let now = Utc::now();
    let service = CredentialIssuerService::new(
        RecordingStore::default(),
        FixedProofs(vec![]),
        Dataset,
        RecordingSigner::default(),
        "https://issuer.example".to_owned(),
        4,
    );
    let (access, issuance, request) = fixture(now);

    let mut ambiguous = request.clone();
    ambiguous.credential_identifier = Some(CredentialIdentifier("pid-1".to_owned()));
    assert_eq!(
        service
            .issue_pending(&access, &ambiguous, &issuance, "nonce", now)
            .await,
        Err(CredentialIssuanceError::Credential(
            CredentialError::InvalidCredentialRequest
        ))
    );

    let mut expired_access = access.clone();
    expired_access.expires_at = now - Duration::seconds(1);
    assert_eq!(
        service
            .issue_pending(&expired_access, &request, &issuance, "nonce", now)
            .await,
        Err(CredentialIssuanceError::Unauthorized)
    );

    let mut wrong_configuration = access.clone();
    wrong_configuration.configuration_ids.clear();
    assert_eq!(
        service
            .issue_pending(&wrong_configuration, &request, &issuance, "nonce", now)
            .await,
        Err(CredentialIssuanceError::Unauthorized)
    );

    let mut missing_proofs = request.clone();
    missing_proofs.proofs = None;
    assert_eq!(
        service
            .issue_pending(&access, &missing_proofs, &issuance, "nonce", now)
            .await,
        Err(CredentialIssuanceError::Credential(
            CredentialError::InvalidProof
        ))
    );

    let mut empty_proofs = request.clone();
    empty_proofs.proofs = Some(Proofs(BTreeMap::new()));
    assert_eq!(
        service
            .issue_pending(&access, &empty_proofs, &issuance, "nonce", now)
            .await,
        Err(CredentialIssuanceError::Credential(
            CredentialError::InvalidProof
        ))
    );

    let mut unsupported_type = request.clone();
    unsupported_type.proofs = Some(Proofs(BTreeMap::from([(
        "cose_key".to_owned(),
        vec![json!("proof")],
    )])));
    assert_eq!(
        service
            .issue_pending(&access, &unsupported_type, &issuance, "nonce", now)
            .await,
        Err(CredentialIssuanceError::Credential(
            CredentialError::InvalidProof
        ))
    );

    let mut multiple_types = request.clone();
    multiple_types.proofs = Some(Proofs(BTreeMap::from([
        ("jwt".to_owned(), vec![json!("proof")]),
        ("cose_key".to_owned(), vec![json!("proof")]),
    ])));
    assert_eq!(
        service
            .issue_pending(&access, &multiple_types, &issuance, "nonce", now)
            .await,
        Err(CredentialIssuanceError::Credential(
            CredentialError::InvalidProof
        ))
    );

    let mut too_many = request;
    too_many.proofs = Some(Proofs(BTreeMap::from([(
        "jwt".to_owned(),
        vec![json!("a"), json!("b"), json!("c"), json!("d"), json!("e")],
    )])));
    assert_eq!(
        service
            .issue_pending(&access, &too_many, &issuance, "nonce", now)
            .await,
        Err(CredentialIssuanceError::Credential(
            CredentialError::InvalidProof
        ))
    );
}

#[tokio::test]
async fn unbound_issuance_requires_a_proof_free_configuration() {
    let now = Utc::now();
    let service = CredentialIssuerService::new(
        RecordingStore::default(),
        FixedProofs(vec![]),
        Dataset,
        RecordingSigner::default(),
        "https://issuer.example".to_owned(),
        4,
    );
    let (access, issuance, request) = non_bound_fixture(now);

    let pending = service
        .issue_pending(&access, &request, &issuance, "unused", now)
        .await
        .unwrap();
    assert!(pending.response.credentials.is_some());

    let mut supplied_proof = request.clone();
    supplied_proof.proofs = Some(Proofs(BTreeMap::from([(
        "jwt".to_owned(),
        vec![json!("proof")],
    )])));
    assert_eq!(
        service
            .issue_pending(&access, &supplied_proof, &issuance, "unused", now)
            .await,
        Err(CredentialIssuanceError::Credential(
            CredentialError::InvalidProof
        ))
    );

    let mut binding_required = issuance.clone();
    binding_required
        .configuration
        .cryptographic_binding_methods_supported
        .push("jwk".to_owned());
    assert_eq!(
        service
            .issue_pending(&access, &request, &binding_required, "unused", now)
            .await,
        Err(CredentialIssuanceError::Credential(
            CredentialError::InvalidProof
        ))
    );
}

#[tokio::test]
async fn proof_dataset_claim_and_signing_failures_are_classified_and_released() {
    let now = Utc::now();
    let (access, issuance, request) = fixture(now);

    let proof_error_service = CredentialIssuerService::new(
        RecordingStore::default(),
        ErrorProofs(ProofError::Unavailable),
        Dataset,
        RecordingSigner::default(),
        "https://issuer.example".to_owned(),
        4,
    );
    assert_eq!(
        proof_error_service
            .issue_pending(&access, &request, &issuance, "nonce", now)
            .await,
        Err(CredentialIssuanceError::Proof(ProofError::Unavailable))
    );

    let empty_validation_service = CredentialIssuerService::new(
        RecordingStore::default(),
        FixedProofs(vec![]),
        Dataset,
        RecordingSigner::default(),
        "https://issuer.example".to_owned(),
        4,
    );
    assert_eq!(
        empty_validation_service
            .issue_pending(&access, &request, &issuance, "nonce", now)
            .await,
        Err(CredentialIssuanceError::Credential(
            CredentialError::InvalidNonce
        ))
    );

    let claim_rejected_store = RecordingStore::default();
    *claim_rejected_store.nonce_consumed.lock().unwrap() = true;
    let claim_rejected_service = CredentialIssuerService::new(
        claim_rejected_store,
        FixedProofs(vec![ValidatedProof {
            proof_type: "jwt".to_owned(),
            holder_binding: json!({"jwk":{"kid":"holder"}}),
            nonce: "nonce".to_owned(),
            key_attestation: None,
        }]),
        Dataset,
        RecordingSigner::default(),
        "https://issuer.example".to_owned(),
        4,
    );
    assert_eq!(
        claim_rejected_service
            .issue_pending(&access, &request, &issuance, "nonce", now)
            .await,
        Err(CredentialIssuanceError::Credential(
            CredentialError::InvalidNonce
        ))
    );

    let dataset_store = RecordingStore::default();
    let dataset_service = CredentialIssuerService::new(
        dataset_store.clone(),
        FixedProofs(vec![ValidatedProof {
            proof_type: "jwt".to_owned(),
            holder_binding: json!({"jwk":{"kid":"holder"}}),
            nonce: "nonce".to_owned(),
            key_attestation: None,
        }]),
        ErrorDataset(CredentialIssuanceError::DatasetUnavailable),
        RecordingSigner::default(),
        "https://issuer.example".to_owned(),
        4,
    );
    assert_eq!(
        dataset_service
            .issue_pending(&access, &request, &issuance, "nonce", now)
            .await,
        Err(CredentialIssuanceError::DatasetUnavailable)
    );
    assert_eq!(*dataset_store.nonce_released.lock().unwrap(), 1);

    let signer_store = RecordingStore::default();
    let signer_service = CredentialIssuerService::new(
        signer_store.clone(),
        FixedProofs(vec![ValidatedProof {
            proof_type: "jwt".to_owned(),
            holder_binding: json!({"jwk":{"kid":"holder"}}),
            nonce: "nonce".to_owned(),
            key_attestation: None,
        }]),
        Dataset,
        ErrorSigner(CredentialTrustError::Unavailable),
        "https://issuer.example".to_owned(),
        4,
    );
    assert_eq!(
        signer_service
            .issue_pending(&access, &request, &issuance, "nonce", now)
            .await,
        Err(CredentialIssuanceError::SigningFailed)
    );
    assert_eq!(*signer_store.nonce_released.lock().unwrap(), 1);

    let invalid_configuration_store = RecordingStore::default();
    let invalid_configuration_service = CredentialIssuerService::new(
        invalid_configuration_store.clone(),
        FixedProofs(vec![ValidatedProof {
            proof_type: "jwt".to_owned(),
            holder_binding: json!({"jwk":{"kid":"holder"}}),
            nonce: "nonce".to_owned(),
            key_attestation: None,
        }]),
        Dataset,
        RecordingSigner::default(),
        "https://issuer.example".to_owned(),
        4,
    );
    let mut missing_type = issuance.clone();
    missing_type.configuration.vct = None;
    missing_type.configuration.doctype = None;
    assert_eq!(
        invalid_configuration_service
            .issue_pending(&access, &request, &missing_type, "nonce", now)
            .await,
        Err(CredentialIssuanceError::InvalidConfiguration)
    );
    assert_eq!(
        *invalid_configuration_store.nonce_released.lock().unwrap(),
        1
    );

    let mut late_access = access;
    late_access.expires_at = Utc::now() - Duration::seconds(1);
    let late_service = CredentialIssuerService::new(
        RecordingStore::default(),
        FixedProofs(vec![ValidatedProof {
            proof_type: "jwt".to_owned(),
            holder_binding: json!({"jwk":{"kid":"holder"}}),
            nonce: "nonce".to_owned(),
            key_attestation: None,
        }]),
        Dataset,
        RecordingSigner::default(),
        "https://issuer.example".to_owned(),
        4,
    );
    assert_eq!(
        late_service
            .issue_pending(
                &late_access,
                &request,
                &issuance,
                "nonce",
                Utc::now() - Duration::minutes(10),
            )
            .await,
        Err(CredentialIssuanceError::Unauthorized)
    );
}

#[tokio::test]
async fn immediate_and_deferred_commit_variants_preserve_identity_and_rollback() {
    let now = Utc::now();
    let identity = IssuanceIdentity {
        issuance_id: Uuid::now_v7(),
        request_digest: "digest-1".to_owned(),
    };
    let (access, issuance, request) = fixture(now);

    let immediate_store = RecordingStore::default();
    let immediate_service = CredentialIssuerService::new(
        immediate_store.clone(),
        FixedProofs(vec![ValidatedProof {
            proof_type: "jwt".to_owned(),
            holder_binding: json!({"jwk":{"kid":"holder"}}),
            nonce: "nonce".to_owned(),
            key_attestation: None,
        }]),
        Dataset,
        RecordingSigner::default(),
        "https://issuer.example".to_owned(),
        4,
    );
    let immediate_pending = immediate_service
        .issue_pending_with_identity(&access, &request, &issuance, "nonce", identity, now)
        .await
        .unwrap();
    let immediate_response = response_for_pending(&immediate_pending, now);
    immediate_service
        .commit_pending_with_response(&immediate_pending, &immediate_response, now)
        .await
        .unwrap();
    assert_eq!(*immediate_store.nonce_finalized.lock().unwrap(), 1);
    assert_eq!(
        immediate_store.responses.lock().unwrap()[0].clone(),
        immediate_response
    );

    let mut wrong_response = immediate_response.clone();
    wrong_response.request_digest = "wrong".to_owned();
    assert_eq!(
        immediate_service
            .commit_pending_with_response(&immediate_pending, &wrong_response, now)
            .await,
        Err(CredentialIssuanceError::Store(
            CredentialStoreError::InvalidTransition
        ))
    );
    assert_eq!(
        immediate_service
            .commit_pending_with_response(&immediate_pending, &immediate_response, now)
            .await,
        Err(CredentialIssuanceError::Store(
            CredentialStoreError::InvalidTransition
        ))
    );

    let (unbound_access, unbound_issuance, unbound_request) = non_bound_fixture(now);
    let unbound_store = RecordingStore::default();
    let unbound_service = CredentialIssuerService::new(
        unbound_store.clone(),
        FixedProofs(vec![]),
        Dataset,
        RecordingSigner::default(),
        "https://issuer.example".to_owned(),
        4,
    );
    let unbound_pending = unbound_service
        .issue_pending_with_identity(
            &unbound_access,
            &unbound_request,
            &unbound_issuance,
            "unused",
            IssuanceIdentity {
                issuance_id: Uuid::now_v7(),
                request_digest: "digest-2".to_owned(),
            },
            now,
        )
        .await
        .unwrap();
    unbound_service
        .commit_pending(&unbound_pending, now)
        .await
        .unwrap();
    assert_eq!(
        unbound_service.commit_pending(&unbound_pending, now).await,
        Err(CredentialIssuanceError::Store(
            CredentialStoreError::InvalidTransition
        ))
    );
    let unbound_response_pending = unbound_service
        .issue_pending_with_identity(
            &unbound_access,
            &unbound_request,
            &unbound_issuance,
            "unused",
            IssuanceIdentity {
                issuance_id: Uuid::now_v7(),
                request_digest: "digest-2-response".to_owned(),
            },
            now,
        )
        .await
        .unwrap();
    let unbound_response = response_for_pending(&unbound_response_pending, now);
    unbound_service
        .commit_pending_with_response(&unbound_response_pending, &unbound_response, now)
        .await
        .unwrap();
    assert_eq!(unbound_store.responses.lock().unwrap().len(), 1);

    let mut deferred_issuance = issuance.clone();
    deferred_issuance.disposition = IssuanceDisposition::Deferred {
        ready_at: now + Duration::minutes(2),
    };
    let deferred_store = RecordingStore::default();
    let deferred_service = CredentialIssuerService::new(
        deferred_store.clone(),
        FixedProofs(vec![ValidatedProof {
            proof_type: "jwt".to_owned(),
            holder_binding: json!({"jwk":{"kid":"holder"}}),
            nonce: "nonce".to_owned(),
            key_attestation: None,
        }]),
        Dataset,
        RecordingSigner::default(),
        "https://issuer.example".to_owned(),
        4,
    );
    let deferred_pending = deferred_service
        .issue_pending(&access, &request, &deferred_issuance, "nonce", now)
        .await
        .unwrap();
    deferred_service
        .commit_pending(&deferred_pending, now)
        .await
        .unwrap();
    assert_eq!(deferred_store.deferred.lock().unwrap().len(), 1);
    assert_eq!(
        deferred_store.deferred.lock().unwrap()[0]
            .transaction_hash
            .clone(),
        match &deferred_pending.commit {
            IssuanceCommit::Deferred { credential, .. } => credential.transaction_hash.clone(),
            IssuanceCommit::Immediate { .. } => unreachable!(),
        }
    );

    let deferred_response_store = RecordingStore::default();
    let deferred_response_service = CredentialIssuerService::new(
        deferred_response_store.clone(),
        FixedProofs(vec![ValidatedProof {
            proof_type: "jwt".to_owned(),
            holder_binding: json!({"jwk":{"kid":"holder"}}),
            nonce: "nonce-2".to_owned(),
            key_attestation: None,
        }]),
        Dataset,
        RecordingSigner::default(),
        "https://issuer.example".to_owned(),
        4,
    );
    let deferred_response_pending = deferred_response_service
        .issue_pending(&access, &request, &deferred_issuance, "nonce-2", now)
        .await
        .unwrap();
    let deferred_response = response_for_pending(&deferred_response_pending, now);
    deferred_response_service
        .commit_pending_with_response(&deferred_response_pending, &deferred_response, now)
        .await
        .unwrap();
    assert_eq!(deferred_response_store.deferred.lock().unwrap().len(), 1);
    assert_eq!(deferred_response_store.responses.lock().unwrap().len(), 1);
    assert_eq!(
        deferred_response_store.responses.lock().unwrap()[0].clone(),
        deferred_response
    );

    let (unbound_deferred_access, mut unbound_deferred_issuance, unbound_deferred_request) =
        non_bound_fixture(now);
    unbound_deferred_issuance.disposition = IssuanceDisposition::Deferred {
        ready_at: now + Duration::minutes(2),
    };
    let unbound_deferred_store = RecordingStore::default();
    let unbound_deferred_service = CredentialIssuerService::new(
        unbound_deferred_store.clone(),
        FixedProofs(vec![]),
        Dataset,
        RecordingSigner::default(),
        "https://issuer.example".to_owned(),
        4,
    );
    let unbound_deferred_pending = unbound_deferred_service
        .issue_pending(
            &unbound_deferred_access,
            &unbound_deferred_request,
            &unbound_deferred_issuance,
            "unused",
            now,
        )
        .await
        .unwrap();
    unbound_deferred_service
        .commit_pending(&unbound_deferred_pending, now)
        .await
        .unwrap();
    assert_eq!(
        unbound_deferred_service
            .commit_pending(&unbound_deferred_pending, now)
            .await,
        Err(CredentialIssuanceError::Store(
            CredentialStoreError::InvalidTransition
        ))
    );
    let unbound_deferred_response_pending = unbound_deferred_service
        .issue_pending(
            &unbound_deferred_access,
            &unbound_deferred_request,
            &unbound_deferred_issuance,
            "unused",
            now,
        )
        .await
        .unwrap();
    let unbound_deferred_response = response_for_pending(&unbound_deferred_response_pending, now);
    unbound_deferred_service
        .commit_pending_with_response(
            &unbound_deferred_response_pending,
            &unbound_deferred_response,
            now,
        )
        .await
        .unwrap();
    assert_eq!(unbound_deferred_store.deferred.lock().unwrap().len(), 2);
    assert_eq!(unbound_deferred_store.responses.lock().unwrap().len(), 1);
    assert_eq!(
        unbound_deferred_store.responses.lock().unwrap()[0].clone(),
        unbound_deferred_response
    );

    let rollback_store = RecordingStore::default();
    let rollback_service = CredentialIssuerService::new(
        rollback_store.clone(),
        FixedProofs(vec![ValidatedProof {
            proof_type: "jwt".to_owned(),
            holder_binding: json!({"jwk":{"kid":"holder"}}),
            nonce: "nonce".to_owned(),
            key_attestation: None,
        }]),
        Dataset,
        RecordingSigner::default(),
        "https://issuer.example".to_owned(),
        4,
    );
    let rollback_pending = rollback_service
        .issue_pending(&access, &request, &issuance, "nonce", now)
        .await
        .unwrap();
    rollback_service
        .rollback_pending(&rollback_pending, now)
        .await
        .unwrap();
    assert_eq!(*rollback_store.nonce_released.lock().unwrap(), 1);

    let failing_commit_store = RecordingStore::default();
    *failing_commit_store.commit_success.lock().unwrap() = Some(false);
    let failing_commit_service = CredentialIssuerService::new(
        failing_commit_store.clone(),
        FixedProofs(vec![ValidatedProof {
            proof_type: "jwt".to_owned(),
            holder_binding: json!({"jwk":{"kid":"holder"}}),
            nonce: "nonce".to_owned(),
            key_attestation: None,
        }]),
        Dataset,
        RecordingSigner::default(),
        "https://issuer.example".to_owned(),
        4,
    );
    assert_eq!(
        failing_commit_service
            .issue(&access, &request, &issuance, "nonce", now)
            .await,
        Err(CredentialIssuanceError::Store(
            CredentialStoreError::InvalidTransition
        ))
    );
    assert_eq!(*failing_commit_store.nonce_released.lock().unwrap(), 1);
    assert_eq!(*failing_commit_store.nonce_finalized.lock().unwrap(), 0);
    assert!(
        failing_commit_store
            .notifications
            .lock()
            .unwrap()
            .is_empty()
    );

    *failing_commit_store.commit_success.lock().unwrap() = None;
    failing_commit_service
        .issue(&access, &request, &issuance, "nonce", now)
        .await
        .unwrap();
    assert_eq!(*failing_commit_store.nonce_finalized.lock().unwrap(), 1);
    assert_eq!(failing_commit_store.notifications.lock().unwrap().len(), 1);

    let deferred_failure_store = RecordingStore::default();
    *deferred_failure_store.commit_success.lock().unwrap() = Some(false);
    let deferred_failure_service = CredentialIssuerService::new(
        deferred_failure_store.clone(),
        FixedProofs(vec![ValidatedProof {
            proof_type: "jwt".to_owned(),
            holder_binding: json!({"jwk":{"kid":"holder"}}),
            nonce: "deferred-failure".to_owned(),
            key_attestation: None,
        }]),
        Dataset,
        RecordingSigner::default(),
        "https://issuer.example".to_owned(),
        4,
    );
    let mut deferred_failure_issuance = issuance.clone();
    deferred_failure_issuance.disposition = IssuanceDisposition::Deferred {
        ready_at: now + Duration::minutes(2),
    };
    let deferred_failure_pending = deferred_failure_service
        .issue_pending(
            &access,
            &request,
            &deferred_failure_issuance,
            "deferred-failure",
            now,
        )
        .await
        .unwrap();
    assert_eq!(
        deferred_failure_service
            .commit_pending(&deferred_failure_pending, now)
            .await,
        Err(CredentialIssuanceError::Store(
            CredentialStoreError::InvalidTransition
        ))
    );
    assert!(deferred_failure_store.deferred.lock().unwrap().is_empty());
    assert_eq!(*deferred_failure_store.nonce_finalized.lock().unwrap(), 0);
    *deferred_failure_store.commit_success.lock().unwrap() = None;
    deferred_failure_service
        .commit_pending(&deferred_failure_pending, now)
        .await
        .unwrap();
    assert_eq!(deferred_failure_store.deferred.lock().unwrap().len(), 1);
    assert_eq!(*deferred_failure_store.nonce_finalized.lock().unwrap(), 1);
}

#[tokio::test]
async fn doctype_is_used_when_vct_is_absent() {
    let now = Utc::now();
    let (access, mut issuance, request) = fixture(now);
    issuance.configuration.vct = None;
    issuance.configuration.doctype = Some("org.example.pid".to_owned());
    let service = CredentialIssuerService::new(
        RecordingStore::default(),
        FixedProofs(vec![ValidatedProof {
            proof_type: "jwt".to_owned(),
            holder_binding: json!({"jwk":{"kid":"holder"}}),
            nonce: "nonce".to_owned(),
            key_attestation: None,
        }]),
        Dataset,
        RecordingSigner::default(),
        "https://issuer.example".to_owned(),
        4,
    );
    let pending = service
        .issue_pending(&access, &request, &issuance, "nonce", now)
        .await
        .unwrap();
    assert_eq!(pending.response.credentials.as_ref().unwrap().len(), 1);
}
