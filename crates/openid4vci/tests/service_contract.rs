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
    DeferredCredential, DeferredCredentialClaim, IssuanceDisposition, IssuanceNotification,
    NonceRecord, NotificationHandle, ProofError, ProofTypeMetadata, ProofValidatorPort, Proofs,
    StoredCredentialOffer, StoredCredentialResponse, ValidatedProof,
};
use serde_json::{Value, json};
use uuid::Uuid;

#[derive(Clone, Default)]
struct RecordingStore {
    nonce_consumed: Arc<Mutex<bool>>,
    nonce_finalized: Arc<Mutex<usize>>,
    nonce_released: Arc<Mutex<usize>>,
    notifications: Arc<Mutex<Vec<NotificationHandle>>>,
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
        _: chrono::DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<Option<StoredCredentialOffer>, CredentialStoreError>>
    {
        Box::pin(async { Ok(None) })
    }
    fn consume_pre_authorized_offer<'a>(
        &'a self,
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
            *self.nonce_released.lock().unwrap() += 1;
            Ok(true)
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
        _: &'a DeferredCredential,
    ) -> CredentialStoreFuture<'a, Result<(), CredentialStoreError>> {
        Box::pin(async { Ok(()) })
    }
    fn store_deferred_and_finalize_nonce<'a>(
        &'a self,
        _: &'a DeferredCredential,
        _: &'a str,
        _: &'a str,
        _: chrono::DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<(), CredentialStoreError>> {
        Box::pin(async { Ok(()) })
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
            self.notifications.lock().unwrap().push(handle.clone());
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
