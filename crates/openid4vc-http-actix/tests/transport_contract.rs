use std::sync::{Arc, Mutex};

use actix_web::{App, http::StatusCode, test, web};
use nazo_openid4vc_http_actix::{
    AccessTokenScheme, CreateCredentialOfferRequest, CreateCredentialOfferResponse,
    CreatePresentationRequest, CreatePresentationResponse, CredentialEndpointResponse,
    CredentialHttpError, CredentialIssuerEndpoint, CredentialIssuerFuture,
    CredentialIssuerOperations, CredentialRequestBody, CredentialRequestContext,
    CredentialResponseBody, PreAuthorizedTokenRequest, PreAuthorizedTokenResponse,
    PresentationEndpoint, PresentationFuture, PresentationHttpError, PresentationOperations,
    PresentationResponseBody, PresentationResponseInput, PresentationVerificationProjection,
    PresentationVerificationResponse, attach_presentation_verification_evidence,
    create_credential_offer, create_presentation, credential, credential_issuer_metadata,
    deferred_credential, issue_presentation_verification_receipt, notification,
    presentation_response, presentation_verification_receipt,
};
use nazo_openid4vci::{
    CredentialIssuerMetadata, CredentialOffer, CredentialRequest, CredentialResponse,
    DeferredCredentialRequest, NotificationRequest,
};
use nazo_openid4vp::{PresentationResult, PresentationTransaction};
use serde_json::json;
use uuid::Uuid;

#[actix_web::test]
async fn public_verification_receipt_requires_only_the_fixed_receipt_header() {
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(PresentationEndpoint::new(
                Arc::new(Verifier),
                b"management-secret".to_vec(),
            )))
            .route(
                "/openid4vp/verification-receipts",
                web::get().to(presentation_verification_receipt),
            ),
    )
    .await;

    for authorization in [
        None,
        Some("Bearer management-secret"),
        Some("Receipt short"),
    ] {
        let mut request = test::TestRequest::get().uri("/openid4vp/verification-receipts");
        if let Some(value) = authorization {
            request = request.insert_header(("Authorization", value));
        }
        let response = test::call_service(&app, request.to_request()).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(response.headers().get("Cache-Control").unwrap(), "no-store");
        assert_eq!(
            response.headers().get("Referrer-Policy").unwrap(),
            "no-referrer"
        );
    }

    let response = test::call_service(
        &app,
        test::TestRequest::get()
            .uri("/openid4vp/verification-receipts")
            .insert_header((
                "Authorization",
                "Receipt aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ))
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers().get("Cache-Control").unwrap(), "no-store");
    assert_eq!(
        response.headers().get("Referrer-Policy").unwrap(),
        "no-referrer"
    );
    let body = test::read_body(response).await;
    let body = std::str::from_utf8(&body).unwrap();
    for forbidden in ["credential", "nonce", "receipt_jws", "capability", "ui_url"] {
        assert!(
            !body.contains(forbidden),
            "public projection leaked {forbidden}"
        );
    }
    assert!(body.contains("\"status\":\"verified\""));

    let lower_scheme = test::call_service(
        &app,
        test::TestRequest::get()
            .uri("/openid4vp/verification-receipts")
            .insert_header((
                "Authorization",
                "receipt aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ))
            .to_request(),
    )
    .await;
    assert_eq!(lower_scheme.status(), StatusCode::OK);

    let duplicate = test::call_service(
        &app,
        test::TestRequest::get()
            .uri("/openid4vp/verification-receipts")
            .append_header((
                "Authorization",
                "Receipt aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ))
            .append_header((
                "Authorization",
                "Receipt aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ))
            .to_request(),
    )
    .await;
    assert_eq!(duplicate.status(), StatusCode::NOT_FOUND);
}

#[actix_web::test]
async fn management_verification_requires_bearer_and_returns_signed_projection() {
    let transaction_id = Uuid::parse_str("019c8ca2-30a6-7000-8000-000000000002").unwrap();
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(PresentationEndpoint::new(
                Arc::new(Verifier),
                b"management-secret".to_vec(),
            )))
            .route(
                "/openid4vp/verification/{transaction_id}/receipt-capability",
                web::post().to(issue_presentation_verification_receipt),
            ),
    )
    .await;
    let unauthorized = test::call_service(
        &app,
        test::TestRequest::post()
            .uri(&format!(
                "/openid4vp/verification/{transaction_id}/receipt-capability"
            ))
            .to_request(),
    )
    .await;
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

    let nonempty = test::call_service(
        &app,
        test::TestRequest::post()
            .uri(&format!(
                "/openid4vp/verification/{transaction_id}/receipt-capability"
            ))
            .insert_header(("Authorization", "Bearer management-secret"))
            .set_payload("unexpected")
            .to_request(),
    )
    .await;
    assert_eq!(nonempty.status(), StatusCode::BAD_REQUEST);

    let response = test::call_service(
        &app,
        test::TestRequest::post()
            .uri(&format!(
                "/openid4vp/verification/{transaction_id}/receipt-capability"
            ))
            .insert_header(("Authorization", "Bearer management-secret"))
            .set_json(json!({
                "schema": 1,
                "issuance_request_jti": "019c8ca2-30a6-7000-8000-000000000006"
            }))
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body: serde_json::Value = test::read_body_json(response).await;
    assert_eq!(body["transaction_id"], transaction_id.to_string());
    assert_eq!(body["status"], "verified");
    assert_eq!(body["receipt_jws"], "signed.receipt.value");
    assert_eq!(
        body["verification_ui_url"],
        "https://auth.example/ui/verification-result#receipt=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    );
    assert_eq!(body["verification_ttl_seconds"], 300);
}

#[actix_web::test]
async fn management_attach_returns_the_signed_non_secret_binding_projection() {
    let transaction_id = Uuid::parse_str("019c8ca2-30a6-7000-8000-000000000002").unwrap();
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(PresentationEndpoint::new(
                Arc::new(Verifier),
                b"management-secret".to_vec(),
            )))
            .route(
                "/openid4vp/verification/{transaction_id}/evidence-context",
                web::post().to(attach_presentation_verification_evidence),
            ),
    )
    .await;
    let response = test::call_service(
        &app,
        test::TestRequest::post()
            .uri(&format!(
                "/openid4vp/verification/{transaction_id}/evidence-context"
            ))
            .insert_header(("Authorization", "Bearer management-secret"))
            .set_json(json!({
                "schema": 1,
                "evidence_context": {
                    "run_jti": "run-jti-1",
                    "artifact_sha256": "a".repeat(64),
                    "matrix_sha256": "b".repeat(64),
                    "suite_plan_id": "019c8ca2-30a6-7000-8000-000000000003",
                    "suite_module_id": "019c8ca2-30a6-7000-8000-000000000004",
                    "test_name": "openid4vp-test",
                    "variant_sha256": "c".repeat(64)
                }
            }))
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body: serde_json::Value = test::read_body_json(response).await;
    assert_eq!(body["transaction_id"], transaction_id.to_string());
    assert_eq!(body["status"], "attached");
    assert_eq!(
        body["presentation_binding"]["presentation_request_sha256"],
        "e".repeat(64)
    );
    assert_eq!(body["intent_jws"], "signed.intent.value");
    assert_eq!(body["intent_sha256"].as_str().unwrap().len(), 64);
    assert_eq!(
        body["presentation_binding_sha256"].as_str().unwrap().len(),
        64
    );

    let duplicate_auth = test::call_service(
        &app,
        test::TestRequest::post()
            .uri(&format!(
                "/openid4vp/verification/{transaction_id}/evidence-context"
            ))
            .append_header(("Authorization", "Bearer management-secret"))
            .append_header(("Authorization", "Bearer management-secret"))
            .set_json(json!({"schema": 1, "evidence_context": {}}))
            .to_request(),
    )
    .await;
    assert_eq!(duplicate_auth.status(), StatusCode::UNAUTHORIZED);
}

#[test]
fn presentation_request_accepts_only_the_generic_trust_policy_fence() {
    let request_json = || {
        json!({
            "create_request_jti": Uuid::now_v7().to_string(),
            "wallet_authorization_endpoint": "https://wallet.example/authorize",
            "dcql_query": {"credentials": []},
            "openid4vc_trust_policy_resource_id": "trust:run-1",
            "openid4vc_trust_policy_digest": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        })
    };
    let request: CreatePresentationRequest =
        serde_json::from_value(request_json()).expect("ordinary trust policy request");
    assert_eq!(
        request.openid4vc_trust_policy_resource_id.as_deref(),
        Some("trust:run-1")
    );
    assert_eq!(
        request.openid4vc_trust_policy_digest.as_deref(),
        Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    );

    let mut missing_jti = request_json();
    missing_jti
        .as_object_mut()
        .unwrap()
        .remove("create_request_jti");
    assert!(serde_json::from_value::<CreatePresentationRequest>(missing_jti).is_err());
    let mut malformed_jti = request_json();
    malformed_jti["create_request_jti"] = json!("NOT-A-CANONICAL-UUID");
    let malformed: CreatePresentationRequest = serde_json::from_value(malformed_jti)
        .expect("shape parsing is separate from policy validation");
    assert!(
        nazo_operator_protocol::validate_openid4vp_create_request_jti(
            &malformed.create_request_jti
        )
        .is_err()
    );

    let mut legacy = request_json();
    legacy["conformance_lease_id"] = json!(Uuid::nil());
    assert!(serde_json::from_value::<CreatePresentationRequest>(legacy).is_err());

    let mut legacy = request_json();
    legacy["conformance_task_jti"] = json!("request-deadbeef");
    assert!(serde_json::from_value::<CreatePresentationRequest>(legacy).is_err());

    let mut ambiguous = request_json();
    ambiguous["evidence_context"] = json!({});
    assert!(
        serde_json::from_value::<CreatePresentationRequest>(ambiguous).is_err(),
        "evidence context must be attached to the selected pending transaction"
    );
}

#[derive(Default)]
struct Issuer {
    credential_contexts: Mutex<Vec<CredentialRequestContext>>,
}

impl CredentialIssuerOperations for Issuer {
    fn metadata(
        &self,
    ) -> CredentialIssuerFuture<'_, Result<CredentialIssuerMetadata, CredentialHttpError>> {
        Box::pin(async { unreachable!() })
    }
    fn offer<'a>(
        &'a self,
        _: &'a str,
    ) -> CredentialIssuerFuture<'a, Result<CredentialOffer, CredentialHttpError>> {
        Box::pin(async { unreachable!() })
    }
    fn nonce(
        &self,
        _: Option<&str>,
    ) -> CredentialIssuerFuture<'_, Result<String, CredentialHttpError>> {
        Box::pin(async { unreachable!() })
    }
    fn credential<'a>(
        &'a self,
        context: CredentialRequestContext,
        _: CredentialRequestBody<CredentialRequest>,
    ) -> CredentialIssuerFuture<
        'a,
        Result<CredentialEndpointResponse<CredentialResponseBody>, CredentialHttpError>,
    > {
        self.credential_contexts.lock().unwrap().push(context);
        Box::pin(async move {
            Err(CredentialHttpError {
                status: 409,
                error: "captured",
                description: "captured",
                dpop_nonce: None,
            })
        })
    }
    fn deferred<'a>(
        &'a self,
        _: CredentialRequestContext,
        _: CredentialRequestBody<DeferredCredentialRequest>,
    ) -> CredentialIssuerFuture<
        'a,
        Result<CredentialEndpointResponse<CredentialResponseBody>, CredentialHttpError>,
    > {
        Box::pin(async { unreachable!() })
    }
    fn notify<'a>(
        &'a self,
        _: CredentialRequestContext,
        _: NotificationRequest,
    ) -> CredentialIssuerFuture<'a, Result<CredentialEndpointResponse<()>, CredentialHttpError>>
    {
        Box::pin(async { unreachable!() })
    }
    fn pre_authorized_token<'a>(
        &'a self,
        _: PreAuthorizedTokenRequest,
    ) -> CredentialIssuerFuture<'a, Result<PreAuthorizedTokenResponse, CredentialHttpError>> {
        Box::pin(async { unreachable!() })
    }
    fn create_offer<'a>(
        &'a self,
        _: CreateCredentialOfferRequest,
    ) -> CredentialIssuerFuture<'a, Result<CreateCredentialOfferResponse, CredentialHttpError>>
    {
        Box::pin(async { unreachable!() })
    }
}

struct Verifier;

fn verification_projection() -> PresentationVerificationProjection {
    PresentationVerificationProjection {
        schema: 1,
        issuer: "https://auth.example".to_owned(),
        deployment_id: "deployment-1".to_owned(),
        runtime_instance_id: "runtime-1".to_owned(),
        instance_key_id: "instance-key".to_owned(),
        tenant_id: "019c8ca2-30a6-7000-8000-000000000005".to_owned(),
        receipt_id: "019c8ca2-30a6-7000-8000-000000000001".to_owned(),
        transaction_id: Uuid::parse_str("019c8ca2-30a6-7000-8000-000000000002").unwrap(),
        issuance_request_jti: "019c8ca2-30a6-7000-8000-000000000006".to_owned(),
        status: nazo_operator_protocol::Openid4vpVerificationStatus::Verified,
        evidence_context: nazo_operator_protocol::Openid4vpEvidenceContext {
            run_jti: "run-jti-1".to_owned(),
            artifact_sha256: "a".repeat(64),
            matrix_sha256: "b".repeat(64),
            suite_plan_id: "019c8ca2-30a6-7000-8000-000000000003".to_owned(),
            suite_module_id: "019c8ca2-30a6-7000-8000-000000000004".to_owned(),
            test_name: "openid4vp-test".to_owned(),
            variant_sha256: "c".repeat(64),
        },
        presentation_binding: nazo_operator_protocol::Openid4vpPresentationBinding {
            presentation_request_sha256: "e".repeat(64),
            trust_policy: nazo_operator_protocol::Openid4vpTrustPolicyBinding {
                binding_id: None,
                resource_id: None,
                resource_digest: None,
            },
        },
        intent_sha256: "f".repeat(64),
        completed_at: "2026-08-22T03:00:00Z".to_owned(),
        expires_at: "2026-08-22T03:05:00Z".to_owned(),
        receipt_sha256: "d".repeat(64),
    }
}

impl PresentationOperations for Verifier {
    fn create<'a>(
        &'a self,
        request: CreatePresentationRequest,
    ) -> PresentationFuture<'a, Result<CreatePresentationResponse, PresentationHttpError>> {
        Box::pin(async move {
            Ok(CreatePresentationResponse {
                idempotency: nazo_operator_protocol::Openid4vpCreateIdempotencyBinding {
                    create_request_jti: request.create_request_jti,
                    create_request_sha256: "a".repeat(64),
                },
                transaction_id: Uuid::now_v7(),
                authorization_url: "https://wallet.example/authorize".to_owned(),
                expires_in: 60,
            })
        })
    }
    fn request<'a>(
        &'a self,
        _: Uuid,
        _: Option<&'a str>,
    ) -> PresentationFuture<'a, Result<PresentationResponseBody, PresentationHttpError>> {
        Box::pin(async { unreachable!() })
    }
    fn respond<'a>(
        &'a self,
        _: Uuid,
        _: PresentationResponseInput,
    ) -> PresentationFuture<'a, Result<Option<String>, PresentationHttpError>> {
        Box::pin(async { Ok(None) })
    }
    fn result<'a>(
        &'a self,
        _: Uuid,
    ) -> PresentationFuture<'a, Result<PresentationResult, PresentationHttpError>> {
        Box::pin(async { unreachable!() })
    }
    fn issue_verification_receipt<'a>(
        &'a self,
        _: Uuid,
        _: nazo_operator_protocol::Openid4vpIssueVerificationReceiptRequest,
    ) -> PresentationFuture<
        'a,
        Result<nazo_openid4vc_http_actix::PresentationVerificationResponse, PresentationHttpError>,
    > {
        Box::pin(async {
            Ok(PresentationVerificationResponse {
                projection: verification_projection(),
                receipt_jws: "signed.receipt.value".to_owned(),
                receipt_api_url: "https://auth.example/openid4vp/verification-receipts".to_owned(),
                verification_ui_url: "https://auth.example/ui/verification-result#receipt=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
                verification_ttl_seconds: 300,
            })
        })
    }
    fn attach_verification_evidence<'a>(
        &'a self,
        transaction_id: Uuid,
        request: nazo_operator_protocol::Openid4vpAttachEvidenceRequest,
    ) -> PresentationFuture<
        'a,
        Result<nazo_operator_protocol::Openid4vpAttachEvidenceResponse, PresentationHttpError>,
    > {
        Box::pin(async move {
            let binding = nazo_operator_protocol::Openid4vpPresentationBinding {
                presentation_request_sha256: "e".repeat(64),
                trust_policy: nazo_operator_protocol::Openid4vpTrustPolicyBinding {
                    binding_id: None,
                    resource_id: None,
                    resource_digest: None,
                },
            };
            Ok(nazo_operator_protocol::Openid4vpAttachEvidenceResponse {
                schema: 1,
                transaction_id: transaction_id.to_string(),
                status: nazo_operator_protocol::Openid4vpEvidenceAttachmentStatus::Attached,
                evidence_context_sha256:
                    nazo_operator_protocol::canonical_openid4vp_evidence_context_sha256(
                        &request.evidence_context,
                    )
                    .unwrap(),
                presentation_binding_sha256:
                    nazo_operator_protocol::canonical_openid4vp_presentation_binding_sha256(
                        &binding,
                    )
                    .unwrap(),
                presentation_binding: binding,
                intent_jws: "signed.intent.value".to_owned(),
                intent_sha256: nazo_operator_protocol::compact_sha256("signed.intent.value"),
            })
        })
    }
    fn verification_receipt<'a>(
        &'a self,
        capability: &'a str,
    ) -> PresentationFuture<
        'a,
        Result<
            nazo_openid4vc_http_actix::PresentationVerificationProjection,
            PresentationHttpError,
        >,
    > {
        Box::pin(async move {
            if capability == "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
                Ok(verification_projection())
            } else {
                Err(PresentationHttpError {
                    status: 404,
                    error: "not_found",
                    description: "Verification receipt is not available.",
                })
            }
        })
    }
}

struct CapturingVerifier {
    responses: Mutex<Vec<PresentationResponseInput>>,
}

impl PresentationOperations for CapturingVerifier {
    fn create<'a>(
        &'a self,
        _: CreatePresentationRequest,
    ) -> PresentationFuture<'a, Result<CreatePresentationResponse, PresentationHttpError>> {
        Box::pin(async { unreachable!() })
    }

    fn request<'a>(
        &'a self,
        _: Uuid,
        _: Option<&'a str>,
    ) -> PresentationFuture<'a, Result<PresentationResponseBody, PresentationHttpError>> {
        Box::pin(async { unreachable!() })
    }

    fn respond<'a>(
        &'a self,
        _: Uuid,
        response: PresentationResponseInput,
    ) -> PresentationFuture<'a, Result<Option<String>, PresentationHttpError>> {
        self.responses.lock().unwrap().push(response);
        Box::pin(async { Ok(None) })
    }

    fn result<'a>(
        &'a self,
        _: Uuid,
    ) -> PresentationFuture<'a, Result<PresentationResult, PresentationHttpError>> {
        Box::pin(async { unreachable!() })
    }
    fn issue_verification_receipt<'a>(
        &'a self,
        _: Uuid,
        _: nazo_operator_protocol::Openid4vpIssueVerificationReceiptRequest,
    ) -> PresentationFuture<
        'a,
        Result<nazo_openid4vc_http_actix::PresentationVerificationResponse, PresentationHttpError>,
    > {
        Box::pin(async { unreachable!() })
    }
    fn attach_verification_evidence<'a>(
        &'a self,
        _: Uuid,
        _: nazo_operator_protocol::Openid4vpAttachEvidenceRequest,
    ) -> PresentationFuture<
        'a,
        Result<nazo_operator_protocol::Openid4vpAttachEvidenceResponse, PresentationHttpError>,
    > {
        Box::pin(async { unreachable!() })
    }
    fn verification_receipt<'a>(
        &'a self,
        _: &'a str,
    ) -> PresentationFuture<
        'a,
        Result<
            nazo_openid4vc_http_actix::PresentationVerificationProjection,
            PresentationHttpError,
        >,
    > {
        Box::pin(async { unreachable!() })
    }
}

struct DpopNonceIssuer;

impl CredentialIssuerOperations for DpopNonceIssuer {
    fn metadata(
        &self,
    ) -> CredentialIssuerFuture<'_, Result<CredentialIssuerMetadata, CredentialHttpError>> {
        Box::pin(async { unreachable!() })
    }
    fn offer<'a>(
        &'a self,
        _: &'a str,
    ) -> CredentialIssuerFuture<'a, Result<CredentialOffer, CredentialHttpError>> {
        Box::pin(async { unreachable!() })
    }
    fn nonce(
        &self,
        _: Option<&str>,
    ) -> CredentialIssuerFuture<'_, Result<String, CredentialHttpError>> {
        Box::pin(async { unreachable!() })
    }
    fn credential<'a>(
        &'a self,
        _: CredentialRequestContext,
        _: CredentialRequestBody<CredentialRequest>,
    ) -> CredentialIssuerFuture<
        'a,
        Result<CredentialEndpointResponse<CredentialResponseBody>, CredentialHttpError>,
    > {
        Box::pin(async {
            Err(CredentialHttpError {
                status: 401,
                error: "use_dpop_nonce",
                description: "Credential issuer requires nonce in DPoP proof.",
                dpop_nonce: Some("resource-nonce".to_owned()),
            })
        })
    }
    fn deferred<'a>(
        &'a self,
        _: CredentialRequestContext,
        _: CredentialRequestBody<DeferredCredentialRequest>,
    ) -> CredentialIssuerFuture<
        'a,
        Result<CredentialEndpointResponse<CredentialResponseBody>, CredentialHttpError>,
    > {
        Box::pin(async { unreachable!() })
    }
    fn notify<'a>(
        &'a self,
        _: CredentialRequestContext,
        _: NotificationRequest,
    ) -> CredentialIssuerFuture<'a, Result<CredentialEndpointResponse<()>, CredentialHttpError>>
    {
        Box::pin(async { unreachable!() })
    }
    fn pre_authorized_token<'a>(
        &'a self,
        _: PreAuthorizedTokenRequest,
    ) -> CredentialIssuerFuture<'a, Result<PreAuthorizedTokenResponse, CredentialHttpError>> {
        Box::pin(async { unreachable!() })
    }
    fn create_offer<'a>(
        &'a self,
        _: CreateCredentialOfferRequest,
    ) -> CredentialIssuerFuture<'a, Result<CreateCredentialOfferResponse, CredentialHttpError>>
    {
        Box::pin(async { unreachable!() })
    }
}

struct MetadataIssuer;

impl CredentialIssuerOperations for MetadataIssuer {
    fn metadata(
        &self,
    ) -> CredentialIssuerFuture<'_, Result<CredentialIssuerMetadata, CredentialHttpError>> {
        Box::pin(async {
            Ok(CredentialIssuerMetadata {
                credential_issuer: "https://issuer.example".to_owned(),
                authorization_servers: Vec::new(),
                credential_endpoint: "https://issuer.example/credential".to_owned(),
                nonce_endpoint: None,
                deferred_credential_endpoint: None,
                notification_endpoint: None,
                credential_request_encryption: None,
                credential_response_encryption: None,
                batch_credential_issuance: None,
                display: Vec::new(),
                credential_configurations_supported: Default::default(),
                signed_metadata: Some("signed.metadata.jwt".to_owned()),
            })
        })
    }
    fn offer<'a>(
        &'a self,
        _: &'a str,
    ) -> CredentialIssuerFuture<'a, Result<CredentialOffer, CredentialHttpError>> {
        Box::pin(async { unreachable!() })
    }
    fn nonce(
        &self,
        _: Option<&str>,
    ) -> CredentialIssuerFuture<'_, Result<String, CredentialHttpError>> {
        Box::pin(async { unreachable!() })
    }
    fn credential<'a>(
        &'a self,
        _: CredentialRequestContext,
        _: CredentialRequestBody<CredentialRequest>,
    ) -> CredentialIssuerFuture<
        'a,
        Result<CredentialEndpointResponse<CredentialResponseBody>, CredentialHttpError>,
    > {
        Box::pin(async { unreachable!() })
    }
    fn deferred<'a>(
        &'a self,
        _: CredentialRequestContext,
        _: CredentialRequestBody<DeferredCredentialRequest>,
    ) -> CredentialIssuerFuture<
        'a,
        Result<CredentialEndpointResponse<CredentialResponseBody>, CredentialHttpError>,
    > {
        Box::pin(async { unreachable!() })
    }
    fn notify<'a>(
        &'a self,
        _: CredentialRequestContext,
        _: NotificationRequest,
    ) -> CredentialIssuerFuture<'a, Result<CredentialEndpointResponse<()>, CredentialHttpError>>
    {
        Box::pin(async { unreachable!() })
    }
    fn pre_authorized_token<'a>(
        &'a self,
        _: PreAuthorizedTokenRequest,
    ) -> CredentialIssuerFuture<'a, Result<PreAuthorizedTokenResponse, CredentialHttpError>> {
        Box::pin(async { unreachable!() })
    }
    fn create_offer<'a>(
        &'a self,
        _: CreateCredentialOfferRequest,
    ) -> CredentialIssuerFuture<'a, Result<CreateCredentialOfferResponse, CredentialHttpError>>
    {
        Box::pin(async { unreachable!() })
    }
}

#[derive(Default)]
struct NotificationIssuer {
    notifications: Mutex<Vec<NotificationRequest>>,
}

struct SuccessfulIssuer {
    response: CredentialResponseBody,
    dpop_nonce: Option<String>,
}

impl SuccessfulIssuer {
    fn response(&self) -> CredentialEndpointResponse<CredentialResponseBody> {
        CredentialEndpointResponse {
            body: self.response.clone(),
            dpop_nonce: self.dpop_nonce.clone(),
        }
    }
}

impl CredentialIssuerOperations for SuccessfulIssuer {
    fn metadata(
        &self,
    ) -> CredentialIssuerFuture<'_, Result<CredentialIssuerMetadata, CredentialHttpError>> {
        Box::pin(async { unreachable!() })
    }
    fn offer<'a>(
        &'a self,
        _: &'a str,
    ) -> CredentialIssuerFuture<'a, Result<CredentialOffer, CredentialHttpError>> {
        Box::pin(async { unreachable!() })
    }
    fn nonce(
        &self,
        _: Option<&str>,
    ) -> CredentialIssuerFuture<'_, Result<String, CredentialHttpError>> {
        Box::pin(async { unreachable!() })
    }
    fn credential<'a>(
        &'a self,
        _: CredentialRequestContext,
        _: CredentialRequestBody<CredentialRequest>,
    ) -> CredentialIssuerFuture<
        'a,
        Result<CredentialEndpointResponse<CredentialResponseBody>, CredentialHttpError>,
    > {
        let response = self.response();
        Box::pin(async move { Ok(response) })
    }
    fn deferred<'a>(
        &'a self,
        _: CredentialRequestContext,
        _: CredentialRequestBody<DeferredCredentialRequest>,
    ) -> CredentialIssuerFuture<
        'a,
        Result<CredentialEndpointResponse<CredentialResponseBody>, CredentialHttpError>,
    > {
        let response = self.response();
        Box::pin(async move { Ok(response) })
    }
    fn notify<'a>(
        &'a self,
        _: CredentialRequestContext,
        _: NotificationRequest,
    ) -> CredentialIssuerFuture<'a, Result<CredentialEndpointResponse<()>, CredentialHttpError>>
    {
        let dpop_nonce = self.dpop_nonce.clone();
        Box::pin(async move {
            Ok(CredentialEndpointResponse {
                body: (),
                dpop_nonce,
            })
        })
    }
    fn pre_authorized_token<'a>(
        &'a self,
        _: PreAuthorizedTokenRequest,
    ) -> CredentialIssuerFuture<'a, Result<PreAuthorizedTokenResponse, CredentialHttpError>> {
        Box::pin(async { unreachable!() })
    }
    fn create_offer<'a>(
        &'a self,
        _: CreateCredentialOfferRequest,
    ) -> CredentialIssuerFuture<'a, Result<CreateCredentialOfferResponse, CredentialHttpError>>
    {
        Box::pin(async { unreachable!() })
    }
}

fn immediate_response() -> CredentialResponseBody {
    CredentialResponseBody::Json(CredentialResponse {
        credentials: Some(Vec::new()),
        transaction_id: None,
        notification_id: None,
        interval: None,
    })
}

impl CredentialIssuerOperations for NotificationIssuer {
    fn metadata(
        &self,
    ) -> CredentialIssuerFuture<'_, Result<CredentialIssuerMetadata, CredentialHttpError>> {
        Box::pin(async { unreachable!() })
    }
    fn offer<'a>(
        &'a self,
        _: &'a str,
    ) -> CredentialIssuerFuture<'a, Result<CredentialOffer, CredentialHttpError>> {
        Box::pin(async { unreachable!() })
    }
    fn nonce(
        &self,
        _: Option<&str>,
    ) -> CredentialIssuerFuture<'_, Result<String, CredentialHttpError>> {
        Box::pin(async { unreachable!() })
    }
    fn credential<'a>(
        &'a self,
        _: CredentialRequestContext,
        _: CredentialRequestBody<CredentialRequest>,
    ) -> CredentialIssuerFuture<
        'a,
        Result<CredentialEndpointResponse<CredentialResponseBody>, CredentialHttpError>,
    > {
        Box::pin(async { unreachable!() })
    }
    fn deferred<'a>(
        &'a self,
        _: CredentialRequestContext,
        _: CredentialRequestBody<DeferredCredentialRequest>,
    ) -> CredentialIssuerFuture<
        'a,
        Result<CredentialEndpointResponse<CredentialResponseBody>, CredentialHttpError>,
    > {
        Box::pin(async { unreachable!() })
    }
    fn notify<'a>(
        &'a self,
        _: CredentialRequestContext,
        request: NotificationRequest,
    ) -> CredentialIssuerFuture<'a, Result<CredentialEndpointResponse<()>, CredentialHttpError>>
    {
        self.notifications.lock().unwrap().push(request);
        Box::pin(async {
            Ok(CredentialEndpointResponse {
                body: (),
                dpop_nonce: None,
            })
        })
    }
    fn pre_authorized_token<'a>(
        &'a self,
        _: PreAuthorizedTokenRequest,
    ) -> CredentialIssuerFuture<'a, Result<PreAuthorizedTokenResponse, CredentialHttpError>> {
        Box::pin(async { unreachable!() })
    }
    fn create_offer<'a>(
        &'a self,
        _: CreateCredentialOfferRequest,
    ) -> CredentialIssuerFuture<'a, Result<CreateCredentialOfferResponse, CredentialHttpError>>
    {
        Box::pin(async { unreachable!() })
    }
}

#[actix_web::test]
async fn metadata_endpoint_returns_signed_jwt_when_requested() {
    let endpoint = web::Data::new(CredentialIssuerEndpoint::new(
        Arc::new(MetadataIssuer),
        b"management-token".to_vec(),
    ));
    let app = test::init_service(
        App::new()
            .app_data(endpoint)
            .route("/metadata", web::get().to(credential_issuer_metadata)),
    )
    .await;

    let response = test::call_service(
        &app,
        test::TestRequest::get()
            .uri("/metadata")
            .insert_header(("accept", "application/jwt"))
            .to_request(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get("content-type").unwrap(),
        "application/jwt"
    );
    let body = test::read_body(response).await;
    assert_eq!(body, "signed.metadata.jwt");
}

#[actix_web::test]
async fn management_endpoints_fail_closed_without_exact_bearer_token() {
    let issuer = web::Data::new(CredentialIssuerEndpoint::new(
        Arc::new(Issuer::default()),
        b"management-token".to_vec(),
    ));
    let verifier = web::Data::new(PresentationEndpoint::new(
        Arc::new(Verifier),
        b"management-token".to_vec(),
    ));
    let app = test::init_service(
        App::new()
            .app_data(issuer)
            .app_data(verifier)
            .route("/offers", web::post().to(create_credential_offer))
            .route("/presentations", web::post().to(create_presentation)),
    )
    .await;

    for (path, body) in [
        (
            "/offers",
            serde_json::json!({"subject_id":Uuid::now_v7(),"credential_configuration_ids":["pid"],"grant_types":["authorization_code"]}),
        ),
        (
            "/presentations",
            serde_json::json!({"create_request_jti":Uuid::now_v7(),"wallet_authorization_endpoint":"https://wallet.example/authorize","dcql_query":{"credentials":[]}}),
        ),
    ] {
        let response = test::call_service(
            &app,
            test::TestRequest::post()
                .uri(path)
                .set_json(body)
                .to_request(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(response.headers().get("cache-control").unwrap(), "no-store");
        assert_eq!(
            response.headers().get("www-authenticate").unwrap(),
            "Bearer"
        );
    }
}

#[actix_web::test]
async fn presentation_create_echoes_the_typed_idempotency_binding() {
    let endpoint = web::Data::new(PresentationEndpoint::new(
        Arc::new(Verifier),
        b"management-token".to_vec(),
    ));
    let app = test::init_service(
        App::new()
            .app_data(endpoint)
            .route("/presentations", web::post().to(create_presentation)),
    )
    .await;
    let create_request_jti = Uuid::now_v7().to_string();
    let response = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/presentations")
            .insert_header(("authorization", "Bearer management-token"))
            .set_json(json!({
                "create_request_jti": create_request_jti,
                "wallet_authorization_endpoint": "https://wallet.example/authorize",
                "dcql_query": {"credentials": []}
            }))
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body: serde_json::Value = test::read_body_json(response).await;
    assert_eq!(body["create_request_jti"], create_request_jti);
    assert_eq!(body["create_request_sha256"], "a".repeat(64));
}

#[actix_web::test]
async fn presentation_management_requires_nonempty_exact_bearer_token() {
    let cases = [
        (Vec::<u8>::new(), Some("Bearer "), StatusCode::UNAUTHORIZED),
        (
            b"management-token".to_vec(),
            Some("Bearer "),
            StatusCode::UNAUTHORIZED,
        ),
        (
            b"management-token".to_vec(),
            Some("Bearer  management-token"),
            StatusCode::UNAUTHORIZED,
        ),
        (
            b"management-token".to_vec(),
            Some(" Bearer management-token"),
            StatusCode::UNAUTHORIZED,
        ),
        (
            b"management-token".to_vec(),
            Some("Bearer management-token "),
            StatusCode::UNAUTHORIZED,
        ),
        (
            b"management-token".to_vec(),
            Some("Basic management-token"),
            StatusCode::UNAUTHORIZED,
        ),
        (
            b"management-token".to_vec(),
            Some("bearer management-token"),
            StatusCode::OK,
        ),
        (b"management-token".to_vec(), None, StatusCode::UNAUTHORIZED),
        (
            b"management-token".to_vec(),
            Some("Bearer management-token"),
            StatusCode::OK,
        ),
    ];

    for (configured_token, authorization, expected_status) in cases {
        let endpoint = web::Data::new(PresentationEndpoint::new(
            Arc::new(Verifier),
            configured_token,
        ));
        let app = test::init_service(
            App::new()
                .app_data(endpoint)
                .route("/presentations", web::post().to(create_presentation)),
        )
        .await;

        let request = test::TestRequest::post()
            .uri("/presentations")
            .set_json(json!({
                "create_request_jti": Uuid::now_v7(),
                "wallet_authorization_endpoint": "https://wallet.example/authorize",
                "dcql_query": {"credentials": []}
            }));
        let request = if let Some(authorization) = authorization {
            request.insert_header(("authorization", authorization))
        } else {
            request
        };
        let response = test::call_service(&app, request.to_request()).await;

        assert_eq!(response.status(), expected_status);
        assert_eq!(response.headers().get("cache-control").unwrap(), "no-store");
    }
}

#[actix_web::test]
async fn credential_endpoint_preserves_dpop_nonce_challenge_error() {
    let endpoint = web::Data::new(CredentialIssuerEndpoint::new(
        Arc::new(DpopNonceIssuer),
        b"management-token".to_vec(),
    ));
    let app = test::init_service(
        App::new()
            .app_data(endpoint)
            .route("/credential", web::post().to(credential)),
    )
    .await;

    let response = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/credential")
            .insert_header(("authorization", "DPoP access-token"))
            .insert_header(("DPoP", "proof.jwt"))
            .set_json(json!({"credential_configuration_id":"pid","proof":{"proof_type":"jwt","jwt":"proof"}}))
            .to_request(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response.headers().get("www-authenticate").unwrap(),
        r#"DPoP error="use_dpop_nonce""#
    );
    assert_eq!(
        response.headers().get("dpop-nonce").unwrap(),
        "resource-nonce"
    );
}

#[actix_web::test]
async fn credential_success_returns_next_dpop_nonce_for_json_and_jwt_responses() {
    for (response_body, content_type) in [
        (immediate_response(), "application/json"),
        (
            CredentialResponseBody::Jwt("encrypted.credential.response".to_owned()),
            "application/jwt",
        ),
    ] {
        let endpoint = web::Data::new(CredentialIssuerEndpoint::new(
            Arc::new(SuccessfulIssuer {
                response: response_body,
                dpop_nonce: Some("next-resource-nonce".to_owned()),
            }),
            b"management-token".to_vec(),
        ));
        let app = test::init_service(
            App::new()
                .app_data(endpoint)
                .route("/credential", web::post().to(credential)),
        )
        .await;

        let response = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/credential")
                .insert_header(("authorization", "DPoP access-token"))
                .insert_header(("dpop", "proof.jwt"))
                .set_json(json!({"credential_configuration_id":"pid"}))
                .to_request(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get("content-type").unwrap(),
            content_type
        );
        assert_eq!(
            response.headers().get("dpop-nonce").unwrap(),
            "next-resource-nonce"
        );
        assert_eq!(response.headers().get("cache-control").unwrap(), "no-store");
    }
}

#[actix_web::test]
async fn deferred_and_notification_success_return_next_dpop_nonce() {
    let endpoint = web::Data::new(CredentialIssuerEndpoint::new(
        Arc::new(SuccessfulIssuer {
            response: immediate_response(),
            dpop_nonce: Some("next-resource-nonce".to_owned()),
        }),
        b"management-token".to_vec(),
    ));
    let app = test::init_service(
        App::new()
            .app_data(endpoint)
            .route("/deferred", web::post().to(deferred_credential))
            .route("/notification", web::post().to(notification)),
    )
    .await;

    let deferred = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/deferred")
            .insert_header(("authorization", "DPoP access-token"))
            .insert_header(("dpop", "proof.jwt"))
            .set_json(json!({"transaction_id":"transaction-1"}))
            .to_request(),
    )
    .await;
    assert_eq!(deferred.status(), StatusCode::OK);
    assert_eq!(
        deferred.headers().get("dpop-nonce").unwrap(),
        "next-resource-nonce"
    );

    let notification_response = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/notification")
            .insert_header(("authorization", "DPoP access-token"))
            .insert_header(("dpop", "proof.jwt"))
            .set_json(json!({
                "notification_id":"notification-1",
                "event":"credential_accepted"
            }))
            .to_request(),
    )
    .await;
    assert_eq!(notification_response.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        notification_response.headers().get("dpop-nonce").unwrap(),
        "next-resource-nonce"
    );
    assert_eq!(
        notification_response
            .headers()
            .get("cache-control")
            .unwrap(),
        "no-store"
    );
}

#[actix_web::test]
async fn bearer_success_does_not_emit_a_dpop_nonce() {
    let endpoint = web::Data::new(CredentialIssuerEndpoint::new(
        Arc::new(SuccessfulIssuer {
            response: immediate_response(),
            dpop_nonce: None,
        }),
        b"management-token".to_vec(),
    ));
    let app = test::init_service(
        App::new()
            .app_data(endpoint)
            .route("/credential", web::post().to(credential)),
    )
    .await;

    let response = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/credential")
            .insert_header(("authorization", "Bearer access-token"))
            .set_json(json!({"credential_configuration_id":"pid"}))
            .to_request(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().get("dpop-nonce").is_none());
}

#[actix_web::test]
async fn notification_endpoint_accepts_extension_members_without_relaxing_authentication() {
    let issuer = Arc::new(NotificationIssuer::default());
    let endpoint = web::Data::new(CredentialIssuerEndpoint::new(
        issuer.clone(),
        b"management-token".to_vec(),
    ));
    let app = test::init_service(
        App::new()
            .app_data(endpoint)
            .route("/notification", web::post().to(notification)),
    )
    .await;

    let response = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/notification")
            .insert_header(("authorization", "DPoP access-token"))
            .insert_header(("dpop", "proof.jwt"))
            .set_json(json!({
                "notification_id": "notification-1",
                "event": "credential_accepted",
                "suite_extension": "ignored"
            }))
            .to_request(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let notifications = issuer.notifications.lock().unwrap();
    assert_eq!(notifications.len(), 1);
    assert_eq!(notifications[0].notification_id, "notification-1");
}

#[actix_web::test]
async fn credential_endpoint_rejects_query_tokens_and_non_json_or_jwt_bodies() {
    let endpoint = web::Data::new(CredentialIssuerEndpoint::new(
        Arc::new(Issuer::default()),
        b"management-token".to_vec(),
    ));
    let app = test::init_service(
        App::new()
            .app_data(endpoint)
            .route("/credential", web::post().to(credential)),
    )
    .await;

    let query_token = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/credential?access_token=leak")
            .insert_header(("content-type", "application/json"))
            .set_payload("{}")
            .to_request(),
    )
    .await;
    assert_eq!(query_token.status(), StatusCode::UNAUTHORIZED);

    let unsupported = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/credential")
            .insert_header(("authorization", "Bearer token"))
            .insert_header(("content-type", "text/plain"))
            .set_payload("{}")
            .to_request(),
    )
    .await;
    assert_eq!(unsupported.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

#[actix_web::test]
async fn credential_endpoint_rejects_multiple_dpop_proof_headers() {
    let issuer = Arc::new(Issuer::default());
    let endpoint = web::Data::new(CredentialIssuerEndpoint::new(
        issuer.clone(),
        b"management-token".to_vec(),
    ));
    let app = test::init_service(
        App::new()
            .app_data(endpoint)
            .route("/credential", web::post().to(credential)),
    )
    .await;

    let response = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/credential")
            .insert_header(("authorization", "DPoP access-token"))
            .append_header(("dpop", "proof-one.jwt"))
            .append_header(("dpop", "proof-two.jwt"))
            .set_json(json!({
                "credential_configuration_id": "pid",
                "proofs": {"jwt": ["proof.jwt"]}
            }))
            .to_request(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let contexts = issuer.credential_contexts.lock().unwrap();
    assert!(
        contexts.is_empty(),
        "duplicate DPoP proofs must be rejected before credential issuance"
    );
}

#[actix_web::test]
async fn credential_endpoint_preserves_dpop_authorization_scheme_and_proof() {
    let issuer = Arc::new(Issuer::default());
    let endpoint = web::Data::new(CredentialIssuerEndpoint::new(
        issuer.clone(),
        b"management-token".to_vec(),
    ));
    let app = test::init_service(
        App::new()
            .app_data(endpoint)
            .route("/credential", web::post().to(credential)),
    )
    .await;

    let response = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/credential")
            .insert_header(("authorization", "DPoP access-token"))
            .insert_header(("dpop", "proof.jwt"))
            .insert_header(("x-forwarded-tls-client-cert-sha256", "attacker-header"))
            .set_json(json!({
                "credential_configuration_id": "pid",
                "proofs": {"jwt": ["proof.jwt"]}
            }))
            .to_request(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::CONFLICT);
    let contexts = issuer.credential_contexts.lock().unwrap();
    assert_eq!(contexts.len(), 1);
    assert_eq!(contexts[0].bearer_token, "access-token");
    assert_eq!(contexts[0].access_token_scheme, AccessTokenScheme::Dpop);
    assert_eq!(contexts[0].dpop_proof.as_deref(), Some("proof.jwt"));
    assert_eq!(contexts[0].mtls_x5t_s256, None);
}

#[actix_web::test]
async fn credential_endpoint_passes_injected_verified_certificate_thumbprint() {
    let issuer = Arc::new(Issuer::default());
    let endpoint = web::Data::new(
        CredentialIssuerEndpoint::new(issuer.clone(), b"management-token".to_vec())
            .with_client_certificate_extractor(|_| Some("verified-thumbprint".to_owned())),
    );
    let app = test::init_service(
        App::new()
            .app_data(endpoint)
            .route("/credential", web::post().to(credential)),
    )
    .await;

    let response = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/credential")
            .insert_header(("authorization", "Bearer access-token"))
            .set_json(json!({
                "credential_configuration_id": "pid",
                "proofs": {"jwt": ["proof.jwt"]}
            }))
            .to_request(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::CONFLICT);
    let contexts = issuer.credential_contexts.lock().unwrap();
    assert_eq!(contexts.len(), 1);
    assert_eq!(
        contexts[0].mtls_x5t_s256.as_deref(),
        Some("verified-thumbprint")
    );
}

#[actix_web::test]
async fn direct_post_rejects_duplicate_and_mixed_response_parameters() {
    let endpoint = web::Data::new(PresentationEndpoint::new(
        Arc::new(Verifier),
        b"management-token".to_vec(),
    ));
    let id = Uuid::now_v7();
    let app = test::init_service(
        App::new()
            .app_data(endpoint)
            .route("/response/{id}", web::post().to(presentation_response)),
    )
    .await;

    for body in ["state=one&state=two", "response=jwt&state=unexpected"] {
        let response = test::call_service(
            &app,
            test::TestRequest::post()
                .uri(&format!("/response/{id}"))
                .insert_header(("content-type", "application/x-www-form-urlencoded"))
                .set_payload(body)
                .to_request(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(response.headers().get("cache-control").unwrap(), "no-store");
    }
}

#[actix_web::test]
async fn direct_post_preserves_json_vp_token_and_jwt_response_shapes() {
    let verifier = Arc::new(CapturingVerifier {
        responses: Mutex::new(Vec::new()),
    });
    let endpoint = web::Data::new(PresentationEndpoint::new(
        verifier.clone(),
        b"management-token".to_vec(),
    ));
    let id = Uuid::now_v7();
    let app = test::init_service(
        App::new()
            .app_data(endpoint)
            .route("/response/{id}", web::post().to(presentation_response)),
    )
    .await;

    let response = test::call_service(
        &app,
        test::TestRequest::post()
            .uri(&format!("/response/{id}"))
            .insert_header(("content-type", "application/x-www-form-urlencoded"))
            .set_payload("vp_token=%7B%22credential%22%3A%5B%22encoded%22%5D%7D&state=state")
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);

    let response = test::call_service(
        &app,
        test::TestRequest::post()
            .uri(&format!("/response/{id}"))
            .insert_header(("content-type", "application/x-www-form-urlencoded"))
            .set_payload("response=signed.jwt")
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);

    let responses = verifier.responses.lock().unwrap();
    assert!(matches!(
        &responses[0],
        PresentationResponseInput::DirectPost(response)
            if response.vp_token == Some(json!({"credential": ["encoded"]}))
                && response.state.as_deref() == Some("state")
    ));
    assert_eq!(
        responses[1],
        PresentationResponseInput::DirectPostJwt("signed.jwt".to_owned())
    );
}

fn _assert_transaction_type(_: &PresentationTransaction) {}
