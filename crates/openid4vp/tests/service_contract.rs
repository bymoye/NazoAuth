use std::sync::{Arc, Mutex};

use chrono::{Duration, Utc};
use nazo_digital_credentials::{
    CredentialFormat, CredentialFuture, CredentialQuery, CredentialTrustError,
    CredentialVerifierPort, DcqlQuery, PresentedCredential, VerifiedCredential,
};
use nazo_openid4vp::{
    AuthorizationRequest, AuthorizationResponse, ClientIdPrefix, ClientMetadata, PresentationError,
    PresentationResult, PresentationService, PresentationServiceError, PresentationStoreError,
    PresentationStoreFuture, PresentationStorePort, PresentationTransaction, RequestMethod,
    ResponseMode, StoredPresentation,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use uuid::Uuid;

#[derive(Clone, Default)]
struct RecordingStore;

impl PresentationStorePort for RecordingStore {
    fn create<'a>(
        &'a self,
        _transaction: &'a PresentationTransaction,
    ) -> PresentationStoreFuture<'a, Result<(), PresentationStoreError>> {
        Box::pin(async { Ok(()) })
    }

    fn request<'a>(
        &'a self,
        _transaction_id: Uuid,
        _now: chrono::DateTime<Utc>,
    ) -> PresentationStoreFuture<'a, Result<Option<PresentationTransaction>, PresentationStoreError>>
    {
        Box::pin(async { Ok(None) })
    }

    fn bind_wallet_nonce<'a>(
        &'a self,
        _transaction_id: Uuid,
        _wallet_nonce: &'a str,
        _now: chrono::DateTime<Utc>,
    ) -> PresentationStoreFuture<'a, Result<Option<PresentationTransaction>, PresentationStoreError>>
    {
        Box::pin(async { Ok(None) })
    }

    fn complete<'a>(
        &'a self,
        _transaction_id: Uuid,
        _state_hash: &'a str,
        _result: &'a PresentationResult,
        _now: chrono::DateTime<Utc>,
    ) -> PresentationStoreFuture<'a, Result<bool, PresentationStoreError>> {
        Box::pin(async { Ok(true) })
    }

    fn result<'a>(
        &'a self,
        _transaction_id: Uuid,
        _now: chrono::DateTime<Utc>,
    ) -> PresentationStoreFuture<'a, Result<Option<StoredPresentation>, PresentationStoreError>>
    {
        Box::pin(async { Ok(None) })
    }
}

#[derive(Clone)]
struct RecordingVerifier {
    transcript: Arc<Mutex<Option<Vec<u8>>>>,
    trust_anchors: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl CredentialVerifierPort for RecordingVerifier {
    fn verify<'a>(
        &'a self,
        presentation: &'a PresentedCredential,
    ) -> CredentialFuture<'a, Result<VerifiedCredential, CredentialTrustError>> {
        let transcript = presentation.mdoc_session_transcript.clone();
        let trust_anchors = presentation.additional_trust_anchors.clone();
        let output = self.transcript.clone();
        let trust_output = self.trust_anchors.clone();
        Box::pin(async move {
            *output.lock().expect("recording verifier lock") = transcript;
            *trust_output.lock().expect("recording trust lock") = trust_anchors;
            Ok(VerifiedCredential {
                format: CredentialFormat::MsoMdoc,
                issuer: "trusted-issuer".to_owned(),
                credential_type: "org.iso.18013.5.1.mDL".to_owned(),
                claims: json!({"org.iso.18013.5.1":{"family_name":"Doe"}}),
                holder_key: Some(json!({"kty":"EC"})),
                issued_at: None,
                expires_at: None,
                status: None,
            })
        })
    }
}

#[derive(Clone)]
struct MissingHolderVerifier;

impl CredentialVerifierPort for MissingHolderVerifier {
    fn verify<'a>(
        &'a self,
        _presentation: &'a PresentedCredential,
    ) -> CredentialFuture<'a, Result<VerifiedCredential, CredentialTrustError>> {
        Box::pin(async {
            Ok(VerifiedCredential {
                format: CredentialFormat::MsoMdoc,
                issuer: "trusted-issuer".to_owned(),
                credential_type: "org.iso.18013.5.1.mDL".to_owned(),
                claims: json!({"org.iso.18013.5.1":{"family_name":"Doe"}}),
                holder_key: None,
                issued_at: None,
                expires_at: None,
                status: None,
            })
        })
    }
}

#[tokio::test]
async fn final_mdoc_handover_binds_verifier_key_and_request_context() {
    let transaction_id = Uuid::now_v7();
    let now = Utc::now();
    let request = AuthorizationRequest {
        client_id: "x509_san_dns:example.com".to_owned(),
        response_type: "vp_token".to_owned(),
        response_mode: "direct_post.jwt".to_owned(),
        response_uri: "https://example.com/response".to_owned(),
        nonce: "exc7gBkxjx1rdc9udRrveKvSsJIq80avlXeLHhGwqtA".to_owned(),
        state: "state".to_owned(),
        dcql_query: DcqlQuery {
            credentials: vec![CredentialQuery {
                id: "mdl".to_owned(),
                format: CredentialFormat::MsoMdoc,
                meta: Some(json!({"doctype_value":"org.iso.18013.5.1.mDL"})),
                claims: None,
                claim_sets: None,
                trusted_authorities: None,
                require_cryptographic_holder_binding: None,
            }],
            credential_sets: None,
        },
        client_metadata: Some(ClientMetadata {
            vp_formats_supported: json!({"mso_mdoc":{"issuerauth_alg_values":[-7]}}),
            jwks: Some(json!({"keys":[{
                "kty":"EC",
                "crv":"P-256",
                "x":"DxiH5Q4Yx3UrukE2lWCErq8N8bqC9CHLLrAwLz5BmE0",
                "y":"XtLM4-3h5o3HUH0MHVJV0kyq0iBlrBwlh8qEDMZ4-Pc"
            }]})),
            encrypted_response_enc_values_supported: Some(vec![
                "A128GCM".to_owned(),
                "A256GCM".to_owned(),
            ]),
        }),
        verifier_info: None,
        transaction_data: None,
        wallet_nonce: None,
    };
    let mut unsupported_transaction_data = request.clone();
    unsupported_transaction_data.transaction_data =
        Some(vec!["eyJ0eXBlIjoiZXhhbXBsZSJ9".to_owned()]);
    assert_eq!(
        unsupported_transaction_data.validate(),
        Err(PresentationError::InvalidRequest)
    );
    let transaction = PresentationTransaction {
        id: transaction_id,
        client_id_prefix: ClientIdPrefix::X509SanDns,
        request_method: RequestMethod::RequestUriSignedPost,
        response_mode: ResponseMode::DirectPostJwt,
        wallet_authorization_endpoint: "https://wallet.example/authorize".to_owned(),
        request,
        request_object: None,
        request_uri: None,
        conformance_lease_id: None,
        response_encryption_private_key: None,
        created_at: now,
        expires_at: now + Duration::minutes(5),
    };
    let recorded = Arc::new(Mutex::new(None));
    let recorded_trust = Arc::new(Mutex::new(Vec::new()));
    let service = PresentationService::new(
        RecordingStore,
        RecordingVerifier {
            transcript: recorded.clone(),
            trust_anchors: recorded_trust.clone(),
        },
    );

    service
        .verify_response(
            &transaction,
            &AuthorizationResponse {
                vp_token: Some(json!({"mdl":["base64url-mdoc"]})),
                state: Some("state".to_owned()),
                error: None,
                error_description: None,
            },
            &[vec![1, 2, 3]],
            now,
        )
        .await
        .expect("valid mdoc presentation");

    let transcript = recorded
        .lock()
        .expect("recording verifier lock")
        .clone()
        .expect("mdoc transcript");
    let decoded: ciborium::Value =
        ciborium::from_reader(transcript.as_slice()).expect("decode session transcript");
    let values = decoded.as_array().expect("session transcript array");
    assert_eq!(values.len(), 3);
    assert!(values[0].is_null() && values[1].is_null());
    let handover = values[2].as_array().expect("OpenID4VPHandover");
    assert_eq!(handover[0].as_text(), Some("OpenID4VPHandover"));
    assert_eq!(handover[1].as_bytes().map(Vec::len), Some(32));
    assert_eq!(
        transcript,
        vec![
            0x83, 0xf6, 0xf6, 0x82, 0x71, 0x4f, 0x70, 0x65, 0x6e, 0x49, 0x44, 0x34, 0x56, 0x50,
            0x48, 0x61, 0x6e, 0x64, 0x6f, 0x76, 0x65, 0x72, 0x58, 0x20, 0x04, 0x8b, 0xc0, 0x53,
            0xc0, 0x04, 0x42, 0xaf, 0x9b, 0x8e, 0xed, 0x49, 0x4c, 0xef, 0xdd, 0x9d, 0x95, 0x24,
            0x0d, 0x25, 0x4b, 0x04, 0x6b, 0x11, 0xb6, 0x80, 0x13, 0x72, 0x2a, 0xad, 0x38, 0xac,
        ],
        "OpenID4VP 1.0 Appendix B.2.6.2 encrypted-response vector"
    );
    assert_eq!(
        *recorded_trust.lock().expect("recording trust lock"),
        vec![vec![1, 2, 3]],
        "transaction-bound trust reaches credential verification"
    );

    let mut unencrypted_transaction = transaction.clone();
    unencrypted_transaction.response_mode = ResponseMode::DirectPost;
    unencrypted_transaction.request.response_mode = "direct_post".to_owned();
    let unencrypted_recorded = Arc::new(Mutex::new(None));
    let unencrypted_trust = Arc::new(Mutex::new(Vec::new()));
    PresentationService::new(
        RecordingStore,
        RecordingVerifier {
            transcript: unencrypted_recorded.clone(),
            trust_anchors: unencrypted_trust,
        },
    )
    .verify_response(
        &unencrypted_transaction,
        &AuthorizationResponse {
            vp_token: Some(json!({"mdl":["base64url-mdoc"]})),
            state: Some("state".to_owned()),
            error: None,
            error_description: None,
        },
        &[],
        now,
    )
    .await
    .expect("valid unencrypted mdoc presentation");
    let unencrypted_transcript = unencrypted_recorded
        .lock()
        .expect("recording verifier lock")
        .clone()
        .expect("unencrypted mdoc transcript");
    let unencrypted_decoded: ciborium::Value =
        ciborium::from_reader(unencrypted_transcript.as_slice())
            .expect("decode unencrypted session transcript");
    let unencrypted_handover = unencrypted_decoded
        .as_array()
        .and_then(|values| values.get(2))
        .and_then(ciborium::Value::as_array)
        .expect("unencrypted OpenID4VPHandover");
    let unencrypted_handover_info = ciborium::Value::Array(vec![
        ciborium::Value::Text(unencrypted_transaction.request.client_id.clone()),
        ciborium::Value::Text(unencrypted_transaction.request.nonce.clone()),
        ciborium::Value::Null,
        ciborium::Value::Text(unencrypted_transaction.request.response_uri.clone()),
    ]);
    let mut encoded_unencrypted_handover_info = Vec::new();
    ciborium::into_writer(
        &unencrypted_handover_info,
        &mut encoded_unencrypted_handover_info,
    )
    .expect("encode unencrypted handover info");
    let expected_unencrypted_hash = Sha256::digest(encoded_unencrypted_handover_info).to_vec();
    assert_eq!(
        unencrypted_handover[1].as_bytes().map(Vec::as_slice),
        Some(expected_unencrypted_hash.as_slice()),
        "direct_post uses a null JWK thumbprint even when client_metadata contains JWKS"
    );

    let error = PresentationService::new(RecordingStore, MissingHolderVerifier)
        .verify_response(
            &transaction,
            &AuthorizationResponse {
                vp_token: Some(json!({"mdl":["base64url-mdoc"]})),
                state: Some("state".to_owned()),
                error: None,
                error_description: None,
            },
            &[],
            now,
        )
        .await
        .expect_err("holder binding is required when the query omits the flag");
    assert_eq!(
        error,
        PresentationServiceError::Presentation(PresentationError::DcqlUnsatisfied)
    );
}
