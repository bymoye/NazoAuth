use super::*;

use std::collections::{BTreeMap, BTreeSet};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use nazo_digital_credentials::{CertificateRevocationPolicy, VcIssuerTrustPolicy};
use nazo_key_management::{KeyManager, KeySettings};
use nazo_openid4vci::CredentialResponse;
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair, KeyUsagePurpose,
    PKCS_ECDSA_P256_SHA256,
};

use crate::{
    config::ConfigSource,
    domain::tenancy::DEFAULT_TENANT_ID,
    http::{authorization::ServerAuthorizationService, token::ServerTokenService},
    runtime_modules::test_support::runtime_module_registry_for_test,
    settings::Settings,
};

fn invalid_pool() -> nazo_postgres::DbPool {
    nazo_postgres::create_pool(
        "postgres://nazo_openid4vci_unit:nazo_openid4vci_unit@127.0.0.1:1/nazo".to_owned(),
        1,
    )
    .expect("pool construction must not connect")
}

async fn fixture_crypto() -> Openid4vcCredentialCrypto {
    let root = std::env::temp_dir().join(format!(
        "nazo-openid4vci-endpoint-{}",
        Uuid::now_v7().simple()
    ));
    std::fs::create_dir_all(&root).expect("endpoint key fixture directory");
    let signing_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("endpoint signing key");
    let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("endpoint CA key");
    let now = time::OffsetDateTime::now_utc();
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    ca_params.not_before = now - time::Duration::minutes(1);
    ca_params.not_after = now + time::Duration::hours(1);
    let ca = CertifiedIssuer::self_signed(ca_params, ca_key).expect("endpoint CA certificate");

    let mut leaf_params =
        CertificateParams::new(vec!["issuer.example".to_owned()]).expect("endpoint leaf SAN");
    leaf_params.is_ca = IsCa::NoCa;
    leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf_params.not_before = now - time::Duration::minutes(1);
    leaf_params.not_after = now + time::Duration::hours(1);
    let leaf = leaf_params
        .signed_by(&signing_key, &ca)
        .expect("endpoint leaf certificate");

    std::fs::write(
        root.join("openid4vci-signing.pem"),
        signing_key.serialize_pem(),
    )
    .expect("endpoint signing key");
    std::fs::write(
        root.join("keyset.json"),
        serde_json::to_vec(&json!({
            "active_kid": "openid4vci-test",
            "keys": [{
                "kid": "openid4vci-test",
                "alg": "ES256",
                "file": "openid4vci-signing.pem",
                "created_at": chrono::Utc::now().to_rfc3339(),
                "retire_at": null,
                "purposes": ["credential", "presentation_request"]
            }]
        }))
        .expect("endpoint keyset JSON"),
    )
    .expect("endpoint keyset");
    let keyset = KeyManager::load_or_create(KeySettings {
        keys_dir: root.clone(),
        external_command: Vec::new(),
        external_timeout: std::time::Duration::from_secs(1),
        rotation_interval: chrono::Duration::days(30),
        prepublish_window: chrono::Duration::days(1),
        verification_grace: chrono::Duration::hours(1),
    })
    .await
    .expect("endpoint key manager");
    let chain = format!("{}{}", leaf.pem(), ca.pem());
    let crypto = Openid4vcCredentialCrypto::new_with_policies(
        keyset,
        chain.as_bytes(),
        ca.pem().as_bytes(),
        VcIssuerTrustPolicy::san_bound(),
        CertificateRevocationPolicy::disabled(),
    )
    .expect("endpoint credential crypto");
    std::fs::remove_dir_all(root).expect("endpoint key fixture cleanup");
    crypto
}

async fn operations(enabled: bool) -> ServerCredentialIssuerOperations {
    let mut settings =
        Settings::from_config(&ConfigSource::default()).expect("unit settings should load");
    settings.endpoint.issuer = "https://issuer.example".to_owned();
    settings.modules.enable_openid4vci_issuer = enabled;

    let pool = invalid_pool();
    let valkey = fred::prelude::Builder::default_centralized()
        .build()
        .expect("valkey fixture should build without connecting");
    let valkey_connection = nazo_valkey::ValkeyConnection::from_existing_client(valkey);
    let keyset = KeyManager::for_test(jsonwebtoken::Algorithm::EdDSA);
    let token_service = Arc::new(ServerTokenService::new(
        nazo_postgres::TokenIssuanceRepository::new_with_response_key_ring(
            pool.clone(),
            nazo_postgres::TokenIssuanceResponseKeyRing::new("unit-current", [0x42; 32], None)
                .expect("response key ring fixture should be valid"),
        ),
        nazo_valkey::TokenIssuanceStateAdapter::new(&valkey_connection),
        keyset.clone(),
    ));
    let authorization = Arc::new(ServerAuthorizationService::new(
        nazo_postgres::AuthorizationFlowRepository::new(pool.clone(), DEFAULT_TENANT_ID),
        nazo_valkey::AuthorizationStateAdapter::new(&valkey_connection),
        keyset.clone(),
    ));
    let runtime = runtime_module_registry_for_test(pool.clone(), &settings)
        .expect("runtime module fixture should build");
    let proof_validator = Openid4vcProofValidator::new(json!({ "keys": [] }))
        .expect("proof validator fixture should build");
    let crypto = fixture_crypto().await;
    let configuration = CredentialConfiguration {
        format: nazo_digital_credentials::CredentialFormat::SdJwtVc,
        scope: Some("unit-credential".to_owned()),
        cryptographic_binding_methods_supported: Vec::new(),
        credential_signing_alg_values_supported: vec!["ES256".to_owned()],
        proof_types_supported: Default::default(),
        vct: Some("https://issuer.example/unit".to_owned()),
        doctype: None,
        credential_metadata: None,
    };
    ServerCredentialIssuerOperations::new(
        pool,
        DEFAULT_TENANT_ID,
        [0x51; 32],
        token_service,
        authorization,
        runtime,
        crypto,
        proof_validator,
        None,
        settings.endpoint.issuer,
        BTreeMap::from([("unit-config".to_owned(), configuration)]),
        BTreeSet::new(),
        nazo_auth::DpopNoncePolicy::Optional,
    )
    .expect("credential issuer fixture should build")
}

fn credential_request() -> CredentialRequest {
    CredentialRequest {
        credential_identifier: None,
        credential_configuration_id: Some("unit-config".to_owned()),
        proofs: None,
        credential_response_encryption: None,
        extensions: BTreeMap::new(),
    }
}

fn request_context() -> CredentialRequestContext {
    CredentialRequestContext {
        bearer_token: "not-a-token".to_owned(),
        access_token_scheme: AccessTokenScheme::Bearer,
        dpop_proof: None,
        request_url: "/openid4vci/credential".to_owned(),
        method: "POST",
    }
}

fn assert_error(
    error: CredentialHttpError,
    status: u16,
    code: &'static str,
    description: &'static str,
) {
    assert_eq!(error.status, status);
    assert_eq!(error.error, code);
    assert_eq!(error.description, description);
    assert!(error.dpop_nonce.is_none());
}

#[tokio::test]
async fn request_json_accepts_json_and_rejects_invalid_encrypted_request() {
    let issuer = operations(false).await;
    let request = credential_request();
    assert_eq!(
        issuer
            .request_json(CredentialRequestBody::Json(request.clone()))
            .await
            .expect("JSON request should pass through"),
        request
    );

    let error = issuer
        .request_json::<CredentialRequest>(CredentialRequestBody::Jwt("not-a-jwe".to_owned()))
        .await
        .expect_err("malformed encrypted request must fail closed");
    assert_eq!(error.status, 400);
    assert_eq!(error.error, "invalid_encryption_parameters");
}

#[tokio::test]
async fn finish_response_supports_json_ecdh_and_deflate_and_rejects_unsupported_parameters() {
    let issuer = operations(false).await;
    let response = CredentialResponse {
        credentials: Some(vec![nazo_openid4vci::IssuedCredential {
            credential: json!("unit-credential"),
        }]),
        transaction_id: None,
        notification_id: None,
        interval: None,
    };

    assert!(matches!(
        issuer
            .finish_response(response.clone(), None)
            .await
            .expect("unencrypted response should be JSON"),
        CredentialResponseBody::Json(_)
    ));

    let mut jwk = issuer.request_encryption.public_jwk();
    jwk["alg"] = json!("ECDH-ES");
    jwk["kid"] = json!("openid4vci-request-encryption");
    for zip in [None, Some("DEF".to_owned())] {
        let encrypted = issuer
            .finish_response(
                response.clone(),
                Some(&CredentialResponseEncryption {
                    jwk: jwk.clone(),
                    enc: "A256GCM".to_owned(),
                    zip: zip.clone(),
                }),
            )
            .await
            .expect("supported ECDH response encryption should succeed");
        let compact = match encrypted {
            CredentialResponseBody::Jwt(value) => value,
            CredentialResponseBody::Json(_) => {
                panic!("encrypted response must use compact JWE")
            }
        };
        let parts = compact.split('.').collect::<Vec<_>>();
        assert_eq!(parts.len(), 5);
        assert!(parts[1].is_empty(), "ECDH-ES uses direct key agreement");
        let protected: Value = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(parts[0])
                .expect("protected header should be base64url"),
        )
        .expect("protected header should be JSON");
        assert_eq!(protected["alg"], "ECDH-ES");
        assert_eq!(protected["enc"], "A256GCM");
        assert_eq!(protected["kid"], "openid4vci-request-encryption");
        assert_eq!(protected["cty"], "application/json");
        assert_eq!(protected.get("zip").and_then(Value::as_str), zip.as_deref());

        let plaintext = issuer
            .request_encryption
            .decrypt_credential_request(&compact, "openid4vci-request-encryption")
            .expect("recipient private key should decrypt the response");
        assert_eq!(
            plaintext,
            serde_json::to_vec(&response).expect("credential response should serialize")
        );

        // The protected header is authenticated as the JWE AAD.  Changing it
        // while retaining ciphertext must therefore invalidate decryption.
        let mut changed_protected = protected;
        changed_protected["aad-test"] = json!("tampered");
        let changed_header = URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&changed_protected).expect("header should serialize"));
        let tampered = format!(
            "{changed_header}.{}.{}.{}.{}",
            parts[1], parts[2], parts[3], parts[4]
        );
        assert!(
            issuer
                .request_encryption
                .decrypt_credential_request(&tampered, "openid4vci-request-encryption")
                .is_err()
        );
    }

    for (jwk, enc, zip) in [
        (json!({"alg":"RSA-OAEP"}), "A256GCM", None),
        (json!({"alg":"ECDH-ES"}), "A128GCM", None),
        (json!({"alg":"ECDH-ES"}), "A256GCM", Some("GZIP".to_owned())),
    ] {
        let error = issuer
            .finish_response(
                response.clone(),
                Some(&CredentialResponseEncryption {
                    jwk,
                    enc: enc.to_owned(),
                    zip,
                }),
            )
            .await
            .expect_err("unsupported response encryption must fail closed");
        assert_eq!(error.status, 400);
        assert_eq!(error.error, "invalid_encryption_parameters");
    }
}

#[tokio::test]
async fn disabled_issuer_rejects_every_mutating_endpoint_before_state_access() {
    let issuer = operations(false).await;
    assert_error(
        issuer.metadata().await.expect_err("metadata disabled"),
        404,
        "invalid_request",
        "Credential issuer is disabled.",
    );
    assert_error(
        issuer
            .offer("not-a-uuid")
            .await
            .expect_err("offer disabled"),
        404,
        "invalid_request",
        "Credential issuer is disabled.",
    );
    assert_error(
        issuer.nonce(None).await.expect_err("nonce disabled"),
        404,
        "invalid_request",
        "Credential issuer is disabled.",
    );
    assert_error(
        issuer
            .credential(
                request_context(),
                CredentialRequestBody::Json(credential_request()),
            )
            .await
            .expect_err("credential disabled"),
        503,
        "temporarily_unavailable",
        "Credential issuer is not accepting new requests.",
    );
    assert_error(
        issuer
            .deferred(
                request_context(),
                CredentialRequestBody::Json(DeferredCredentialRequest {
                    transaction_id: "unit-transaction".to_owned(),
                    credential_response_encryption: None,
                }),
            )
            .await
            .expect_err("deferred disabled"),
        503,
        "temporarily_unavailable",
        "Credential issuer is unavailable.",
    );
    assert_error(
        issuer
            .pre_authorized_token(PreAuthorizedTokenRequest {
                pre_authorized_code: "unit-code".to_owned(),
                tx_code: None,
                client_id: None,
                dpop_proof: None,
                client_attestation: None,
                client_attestation_pop: None,
                request_url: "https://issuer.example/token".to_owned(),
            })
            .await
            .expect_err("pre-authorized token disabled"),
        503,
        "temporarily_unavailable",
        "Credential issuer is unavailable.",
    );
    assert_error(
        issuer
            .create_offer(CreateCredentialOfferRequest {
                subject_id: Uuid::nil(),
                credential_configuration_ids: vec!["unit-config".to_owned()],
                grant_types: vec![nazo_openid4vci::PRE_AUTHORIZED_CODE_GRANT.to_owned()],
                tx_code: None,
                expires_in: 300,
            })
            .await
            .expect_err("offer creation disabled"),
        503,
        "temporarily_unavailable",
        "Credential issuer is unavailable.",
    );
}

#[tokio::test]
async fn enabled_issuer_validates_request_shape_before_database_state() {
    let issuer = operations(true).await;
    assert_eq!(
        issuer
            .offer("not-a-uuid")
            .await
            .expect_err("malformed offer identifier")
            .status,
        404
    );
    assert_eq!(
        issuer
            .credential(
                request_context(),
                CredentialRequestBody::Jwt("not-a-jwe".to_owned()),
            )
            .await
            .expect_err("malformed credential JWE")
            .status,
        400
    );
    assert_eq!(
        issuer
            .deferred(
                request_context(),
                CredentialRequestBody::Jwt("not-a-jwe".to_owned()),
            )
            .await
            .expect_err("malformed deferred JWE")
            .status,
        400
    );
    assert_eq!(
        issuer
            .create_offer(CreateCredentialOfferRequest {
                subject_id: Uuid::nil(),
                credential_configuration_ids: vec!["unknown".to_owned()],
                grant_types: vec!["authorization_code".to_owned()],
                tx_code: None,
                expires_in: 300,
            })
            .await
            .expect_err("unknown configuration")
            .status,
        400
    );
}

#[tokio::test]
async fn access_and_notification_fail_closed_for_invalid_bearer() {
    let issuer = operations(true).await;
    let context = request_context();
    let access_error = issuer
        .access(&context)
        .await
        .expect_err("invalid bearer must not reach credential state");
    assert_error(
        access_error,
        401,
        "invalid_token",
        "Access token is invalid.",
    );

    let notify_error = issuer
        .notify(
            context,
            NotificationRequest {
                notification_id: "unit-notification".to_owned(),
                event: nazo_openid4vci::NotificationEvent::CredentialFailure,
                event_description: Some("unit".to_owned()),
            },
        )
        .await
        .expect_err("notification requires a valid access token");
    assert_error(
        notify_error,
        401,
        "invalid_token",
        "Access token is invalid.",
    );
}

#[tokio::test]
async fn access_rejects_signed_token_for_different_tenant_before_revocation_lookup() {
    let issuer = operations(true).await;
    let other_tenant = Uuid::from_u128(0x2222);
    assert_ne!(other_tenant, issuer.tenant_id);
    let subject = Uuid::from_u128(0x3333);
    let subject_string = subject.to_string();
    let audiences = [issuer.issuer.clone()];
    let authorization_details = Value::Array(Vec::new());
    let issued = issuer
        .token_service
        .sign_access_token(nazo_auth::AccessTokenSignInput {
            issuer: &issuer.issuer,
            tenant_id: other_tenant,
            subject: &subject_string,
            user_id: Some(subject),
            subject_type: "user",
            client_id: "unit-client",
            audiences: &audiences,
            scopes: &[],
            authorization_details: &authorization_details,
            userinfo_claims: &[],
            userinfo_claim_requests: &[],
            ttl_seconds: 300,
            dpop_jkt: None,
            mtls_x5t_s256: None,
            actor: None,
        })
        .await
        .expect("test key manager should sign the access token");

    let mut context = request_context();
    context.bearer_token = issued.token;
    let error = issuer
        .access(&context)
        .await
        .expect_err("a token from another tenant must be rejected before state access");
    assert_error(
        error,
        401,
        "invalid_token",
        "Access token tenant does not match this credential issuer.",
    );
}
