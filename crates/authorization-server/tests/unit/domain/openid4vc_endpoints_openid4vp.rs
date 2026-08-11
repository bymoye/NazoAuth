use super::*;

use std::path::Path;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use diesel::sql_query;
use diesel_async::RunQueryDsl;
use nazo_digital_credentials::{
    CertificateRevocationPolicy, CredentialFormat, CredentialSignInput, CredentialSignerPort,
    DcqlQuery, EphemeralEncryptionKey, HolderBinding, VcIssuerTrustPolicy, encrypt_ecdh_es,
};
use nazo_key_management::{KeyManager, KeySettings};
use nazo_openid4vc_http_actix::{
    CreatePresentationRequest, PresentationOperations, PresentationResponseBody,
    PresentationResponseInput,
};
use nazo_openid4vp::PresentationStorePort;
use p256::{ecdsa::SigningKey, pkcs8::EncodePrivateKey};
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair, KeyUsagePurpose,
    PKCS_ECDSA_P256_SHA256,
};
use serde_json::json;
use sha2::Digest as _;

fn invalid_pool() -> nazo_postgres::DbPool {
    nazo_postgres::create_pool(
        "postgres://openid4vp_unit_test:openid4vp_unit_test@127.0.0.1:1/oauth".to_owned(),
        1,
    )
    .expect("pool construction should not connect")
}

async fn fixture_crypto(root: &Path) -> Openid4vcCredentialCrypto {
    fixture_crypto_with_dns(root, true).await
}

async fn fixture_crypto_without_dns(root: &Path) -> Openid4vcCredentialCrypto {
    fixture_crypto_with_dns(root, false).await
}

async fn fixture_crypto_with_dns(root: &Path, include_dns: bool) -> Openid4vcCredentialCrypto {
    tokio::fs::create_dir_all(root)
        .await
        .expect("fixture key directory should be created");
    let signing_key =
        KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("fixture P-256 signing key");
    let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("fixture CA key");
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    ca_params.not_before = time::OffsetDateTime::now_utc() - time::Duration::minutes(1);
    ca_params.not_after = time::OffsetDateTime::now_utc() + time::Duration::hours(1);
    let ca = CertifiedIssuer::self_signed(ca_params, ca_key).expect("fixture CA certificate");

    let mut leaf_params = if include_dns {
        CertificateParams::new(vec!["issuer.example".to_owned()]).expect("fixture leaf parameters")
    } else {
        CertificateParams::default()
    };
    leaf_params.is_ca = IsCa::NoCa;
    leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf_params.not_before = time::OffsetDateTime::now_utc() - time::Duration::minutes(1);
    leaf_params.not_after = time::OffsetDateTime::now_utc() + time::Duration::hours(1);
    let leaf = leaf_params
        .signed_by(&signing_key, &ca)
        .expect("fixture leaf certificate");

    let key_file = root.join("openid4vp-signing.pem");
    tokio::fs::write(&key_file, signing_key.serialize_pem())
        .await
        .expect("fixture signing key should be written");
    let keyset = json!({
        "active_kid": "openid4vp-test",
        "keys": [{
            "kid": "openid4vp-test",
            "alg": "ES256",
            "file": "openid4vp-signing.pem",
            "created_at": chrono::Utc::now().to_rfc3339(),
            "retire_at": null,
            "purposes": ["credential", "presentation_request"]
        }]
    });
    tokio::fs::write(
        root.join("keyset.json"),
        serde_json::to_vec(&keyset).expect("fixture keyset JSON"),
    )
    .await
    .expect("fixture keyset should be written");
    let key_manager = KeyManager::load_or_create(KeySettings {
        keys_dir: root.to_owned(),
        external_command: Vec::new(),
        external_timeout: std::time::Duration::from_secs(1),
        rotation_interval: chrono::Duration::days(30),
        prepublish_window: chrono::Duration::days(1),
        verification_grace: chrono::Duration::hours(1),
    })
    .await
    .expect("fixture key manager should load");
    let chain = format!("{}{}", leaf.pem(), ca.pem());
    Openid4vcCredentialCrypto::new_with_policies(
        key_manager,
        chain.as_bytes(),
        ca.pem().as_bytes(),
        VcIssuerTrustPolicy::san_bound(),
        CertificateRevocationPolicy::disabled(),
    )
    .expect("fixture OpenID4VC crypto should load")
}

async fn operations(
    pool: nazo_postgres::DbPool,
    root: &Path,
    enabled: bool,
) -> ServerPresentationOperations {
    let crypto = fixture_crypto(root).await;
    operations_with_crypto(pool, crypto, enabled).await
}

async fn operations_with_crypto(
    pool: nazo_postgres::DbPool,
    crypto: Openid4vcCredentialCrypto,
    enabled: bool,
) -> ServerPresentationOperations {
    let mut settings =
        crate::settings::Settings::from_config(&crate::config::ConfigSource::default())
            .expect("fixture settings should load");
    settings.modules.enable_openid4vp_verifier = enabled;
    let runtime = crate::runtime_modules::test_support::runtime_module_registry_for_test(
        pool.clone(),
        &settings,
    )
    .expect("fixture runtime module registry should load");
    ServerPresentationOperations::new(
        pool,
        crate::domain::tenancy::DEFAULT_TENANT_ID,
        [0x42; 32],
        crypto,
        runtime,
        PresentationVerifierConfig {
            issuer: "https://issuer.example".to_owned(),
            wallet_origins: vec!["https://wallet.example".to_owned()],
            // Keep the live fixture comfortably above the minimum clamp:
            // certificate generation and a serialized DB round-trip can
            // exceed thirty seconds on a cold CI worker.
            transaction_ttl_seconds: 300,
        },
    )
}

fn valid_dcql() -> DcqlQuery {
    DcqlQuery {
        credentials: vec![nazo_digital_credentials::CredentialQuery {
            id: "pid".to_owned(),
            format: CredentialFormat::SdJwtVc,
            meta: None,
            claims: None,
            claim_sets: None,
            trusted_authorities: None,
            require_cryptographic_holder_binding: None,
        }],
        credential_sets: None,
    }
}

fn create_input(
    request_method: Option<&str>,
    response_mode: Option<&str>,
    client_id_prefix: Option<&str>,
    haip: bool,
) -> CreatePresentationRequest {
    CreatePresentationRequest {
        wallet_authorization_endpoint: "https://wallet.example/authorize".to_owned(),
        dcql_query: valid_dcql(),
        haip,
        client_id_prefix: client_id_prefix.map(str::to_owned),
        request_method: request_method.map(str::to_owned),
        response_mode: response_mode.map(str::to_owned),
        transaction_data: None,
        conformance_lease_id: None,
        conformance_task_jti: None,
    }
}

fn conformance_material(issuer: &str, credential_trust_anchor_pem: &str) -> serde_json::Value {
    serde_json::to_value(nazo_operator_protocol::Openid4vcConformanceTrust {
        schema: 1,
        client_attestation_issuer: issuer.to_owned(),
        client_attestation_jwks: json!({"keys": []}),
        key_attestation_jwks: json!({"keys": []}),
        credential_trust_anchor_pem: credential_trust_anchor_pem.to_owned(),
    })
    .expect("conformance material should serialize")
}

fn valid_ca_pem() -> String {
    let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("conformance CA key");
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    ca_params.not_before = time::OffsetDateTime::now_utc() - time::Duration::minutes(1);
    ca_params.not_after = time::OffsetDateTime::now_utc() + time::Duration::hours(1);
    CertifiedIssuer::self_signed(ca_params, ca_key)
        .expect("conformance CA certificate")
        .pem()
}

async fn bind_suite_origin(
    pool: &nazo_postgres::DbPool,
    lease_id: Uuid,
    origin: &str,
    task_jti: &str,
) {
    let mut connection = nazo_postgres::get_conn(pool)
        .await
        .expect("suite-origin fixture connection should be available");
    sql_query(
        "UPDATE conformance_leases
         SET profile = 'nazoauth-full', suite_origin = $1, task_jti = $2
         WHERE tenant_id = $3 AND id = $4",
    )
    .bind::<diesel::sql_types::Text, _>(origin)
    .bind::<diesel::sql_types::Text, _>(task_jti)
    .bind::<diesel::sql_types::Uuid, _>(crate::domain::tenancy::DEFAULT_TENANT_ID)
    .bind::<diesel::sql_types::Uuid, _>(lease_id)
    .execute(&mut connection)
    .await
    .expect("suite-origin fixture should be bound");
}

async fn expire_lease(pool: &nazo_postgres::DbPool, lease_id: Uuid) {
    let mut connection = nazo_postgres::get_conn(pool)
        .await
        .expect("expiry fixture connection should be available");
    sql_query(
        "UPDATE conformance_leases
         SET expires_at = CURRENT_TIMESTAMP - INTERVAL '1 second'
         WHERE tenant_id = $1 AND id = $2",
    )
    .bind::<diesel::sql_types::Uuid, _>(crate::domain::tenancy::DEFAULT_TENANT_ID)
    .bind::<diesel::sql_types::Uuid, _>(lease_id)
    .execute(&mut connection)
    .await
    .expect("expiry fixture should be updated");
}

#[tokio::test]
async fn create_rejects_disabled_verifier_and_untrusted_wallet_before_storage() {
    let root = std::env::temp_dir().join(format!("nazo-openid4vp-disabled-{}", Uuid::now_v7()));
    let disabled = operations(invalid_pool(), &root, false).await;
    let disabled_error = disabled
        .create(create_input(None, None, None, false))
        .await
        .expect_err("disabled verifier must fail closed");
    assert_eq!(
        (disabled_error.status, disabled_error.error),
        (503, "temporarily_unavailable")
    );

    let enabled = operations(invalid_pool(), &root.join("enabled"), true).await;
    let wallet_error = enabled
        .create(CreatePresentationRequest {
            wallet_authorization_endpoint: "http://wallet.example/authorize".to_owned(),
            ..create_input(None, None, None, false)
        })
        .await
        .expect_err("non-HTTPS wallet endpoint must fail closed");
    assert_eq!(
        (wallet_error.status, wallet_error.error),
        (400, "invalid_request")
    );

    let no_dns = operations_with_crypto(
        invalid_pool(),
        fixture_crypto_without_dns(&root.join("without-dns")).await,
        true,
    )
    .await;
    let no_dns_error = no_dns
        .create(create_input(
            Some("request_uri_signed_get"),
            Some("direct_post"),
            Some("x509_san_dns"),
            false,
        ))
        .await
        .expect_err("x509_san_dns must fail when the certificate has no DNS SAN");
    assert_eq!(
        (no_dns_error.status, no_dns_error.error),
        (500, "server_error")
    );

    let invalid_wallet_url = disabled
        .conformance_lease_for_wallet("not a url")
        .await
        .expect_err("invalid conformance wallet URL must fail closed");
    assert_eq!(
        (invalid_wallet_url.status, invalid_wallet_url.error),
        (400, "invalid_request")
    );
    let unavailable_lease = disabled
        .conformance_lease_for_wallet("https://wallet.example/authorize")
        .await
        .expect_err("conformance lease lookup must report unavailable storage");
    assert_eq!(
        (unavailable_lease.status, unavailable_lease.error),
        (503, "server_error")
    );
    assert!(
        disabled
            .conformance_credential_trust_anchors(None)
            .await
            .expect("missing lease has no additional anchors")
            .is_empty()
    );
    let unavailable_anchors = disabled
        .conformance_credential_trust_anchors(Some(Uuid::now_v7()))
        .await
        .expect_err("conformance anchor lookup must report unavailable storage");
    assert_eq!(
        (unavailable_anchors.status, unavailable_anchors.error),
        (503, "server_error")
    );
    let unavailable_request = disabled
        .request(Uuid::now_v7(), None)
        .await
        .expect_err("request lookup must report unavailable storage");
    assert_eq!(
        (unavailable_request.status, unavailable_request.error),
        (503, "server_error")
    );
    let unavailable_response = disabled
        .respond(
            Uuid::now_v7(),
            PresentationResponseInput::DirectPost(AuthorizationResponse {
                vp_token: None,
                state: None,
                error: None,
                error_description: None,
            }),
        )
        .await
        .expect_err("response lookup must report unavailable storage");
    assert_eq!(
        (unavailable_response.status, unavailable_response.error),
        (503, "server_error")
    );
    let unavailable_result = disabled
        .result(Uuid::now_v7())
        .await
        .expect_err("result lookup must report unavailable storage");
    assert_eq!(
        (unavailable_result.status, unavailable_result.error),
        (503, "server_error")
    );
}

#[tokio::test]
async fn create_and_request_cover_url_query_signed_get_and_signed_post_modes() {
    let Some(database_url) = std::env::var("DATABASE_URL").ok() else {
        return;
    };
    let root = std::env::temp_dir().join(format!("nazo-openid4vp-live-{}", Uuid::now_v7()));
    let pool = nazo_postgres::create_pool(database_url, 2).expect("live pool should build");
    let leases = nazo_postgres::ConformanceLeaseRepository::new(pool.clone());
    let operations = operations(pool.clone(), &root, true).await;

    let url_query = operations
        .create(create_input(
            Some("url_query"),
            Some("direct_post"),
            Some("redirect_uri"),
            false,
        ))
        .await
        .expect("url query presentation should be stored");
    assert!(
        url_query
            .authorization_url
            .contains("client_id=redirect_uri%3A")
    );
    assert_eq!(url_query.expires_in, 300);
    assert_eq!(
        operations
            .request(url_query.transaction_id, None)
            .await
            .expect_err("URL query transactions have no request object")
            .error,
        "invalid_request_uri"
    );

    let signed_get = operations
        .create(create_input(
            Some("request_uri_signed_get"),
            Some("direct_post"),
            Some("x509_san_dns"),
            false,
        ))
        .await
        .expect("signed GET presentation should be stored");
    assert!(signed_get.authorization_url.contains("request_uri="));
    assert!(matches!(
        operations
            .request(signed_get.transaction_id, None)
            .await
            .expect("signed GET request object should be returned"),
        PresentationResponseBody::RequestObject(value) if value.split('.').count() == 3
    ));

    let signed_post = operations
        .create(create_input(
            None,
            Some("direct_post.jwt"),
            Some("x509_hash"),
            true,
        ))
        .await
        .expect("signed POST presentation should be stored");
    let nonce_error = operations
        .request(signed_post.transaction_id, None)
        .await
        .expect_err("signed POST requires wallet_nonce");
    assert_eq!(
        (nonce_error.status, nonce_error.error),
        (400, "invalid_request")
    );
    assert!(matches!(
        operations
            .request(signed_post.transaction_id, Some("wallet-nonce"))
            .await
            .expect("wallet nonce should bind the signed POST request"),
        PresentationResponseBody::RequestObject(value) if value.split('.').count() == 3
    ));

    let mode_error = operations
        .respond(
            signed_post.transaction_id,
            PresentationResponseInput::DirectPost(AuthorizationResponse {
                vp_token: None,
                state: None,
                error: None,
                error_description: None,
            }),
        )
        .await
        .expect_err("plaintext response must not be accepted for direct_post.jwt");
    assert_eq!(
        (mode_error.status, mode_error.error),
        (400, "invalid_request")
    );
    let decrypt_error = operations
        .respond(
            signed_post.transaction_id,
            PresentationResponseInput::DirectPostJwt("not-encrypted".to_owned()),
        )
        .await
        .expect_err("invalid encrypted response must be rejected");
    assert_eq!(
        (decrypt_error.status, decrypt_error.error),
        (400, "invalid_request")
    );

    let direct_post_error = operations
        .respond(
            signed_get.transaction_id,
            PresentationResponseInput::DirectPost(AuthorizationResponse {
                vp_token: None,
                state: None,
                error: None,
                error_description: None,
            }),
        )
        .await
        .expect_err("invalid presentation response must be rejected");
    assert_eq!(
        (direct_post_error.status, direct_post_error.error),
        (400, "invalid_request")
    );
    let result_error = operations
        .result(signed_get.transaction_id)
        .await
        .expect_err("incomplete presentation has no result");
    assert_eq!(
        (result_error.status, result_error.error),
        (404, "not_found")
    );

    let signed_get_transaction = operations
        .store
        .request(signed_get.transaction_id, chrono::Utc::now())
        .await
        .expect("signed GET transaction should be readable")
        .expect("signed GET transaction should exist");
    let holder_signing_key = SigningKey::from_slice(&[17; 32]).expect("holder P-256 key");
    let holder_point = holder_signing_key.verifying_key().to_sec1_point(false);
    let holder_jwk = json!({
        "kty": "EC",
        "crv": "P-256",
        "x": URL_SAFE_NO_PAD.encode(holder_point.x().expect("holder x")),
        "y": URL_SAFE_NO_PAD.encode(holder_point.y().expect("holder y")),
    });
    let issued_at = chrono::Utc::now() - chrono::Duration::minutes(1);
    let signed_credential = operations
        .crypto
        .sign(&CredentialSignInput {
            payload: nazo_digital_credentials::CredentialPayload {
                issuer: "https://issuer.example".to_owned(),
                format: CredentialFormat::SdJwtVc,
                configuration_id: "openid4vp-fixture".to_owned(),
                credential_type: "ExampleCredential".to_owned(),
                subject_claims: json!({}),
                holder_binding: Some(HolderBinding::Jwk {
                    jwk: holder_jwk.clone(),
                }),
                selectively_disclosable_claims: Vec::new(),
            },
            issued_at,
            expires_at: issued_at + chrono::Duration::hours(1),
            status: None,
        })
        .await
        .expect("fixture credential should be signed");
    let credential_jwt = signed_credential
        .split('~')
        .next()
        .expect("signed credential should contain a JWT");
    let sd_input = format!("{credential_jwt}~");
    let kb_claims = json!({
        "nonce": signed_get_transaction.request.nonce.clone(),
        "iat": chrono::Utc::now().timestamp(),
        "sd_hash": URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(sd_input.as_bytes())),
        "aud": signed_get_transaction.request.client_id.clone(),
    });
    let mut kb_header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
    kb_header.typ = Some("kb+jwt".to_owned());
    let holder_key_der = holder_signing_key
        .to_pkcs8_der()
        .expect("holder key PKCS#8");
    let kb_jwt = jsonwebtoken::encode(
        &kb_header,
        &kb_claims,
        &jsonwebtoken::EncodingKey::from_ec_der(holder_key_der.as_bytes()),
    )
    .expect("holder binding JWT should be signed");
    let presented_credential = format!("{credential_jwt}~{kb_jwt}");
    let completion = operations
        .respond(
            signed_get.transaction_id,
            PresentationResponseInput::DirectPost(AuthorizationResponse {
                vp_token: Some(json!({"pid": [presented_credential]})),
                state: Some(signed_get_transaction.request.state.clone()),
                error: None,
                error_description: None,
            }),
        )
        .await
        .expect("valid SD-JWT presentation should complete")
        .expect("completed presentation should return a redirect");
    assert_eq!(
        completion,
        format!(
            "https://issuer.example/openid4vp/complete/{}",
            signed_get.transaction_id
        )
    );
    let completed_result = operations
        .result(signed_get.transaction_id)
        .await
        .expect("completed presentation result should be readable");
    assert_eq!(completed_result.transaction_id, signed_get.transaction_id);
    assert_eq!(completed_result.credentials.len(), 1);

    let missing_request = operations
        .request(Uuid::now_v7(), None)
        .await
        .expect_err("unknown request URI must be rejected");
    assert_eq!(
        (missing_request.status, missing_request.error),
        (404, "invalid_request_uri")
    );
    let missing_response = operations
        .respond(
            Uuid::now_v7(),
            PresentationResponseInput::DirectPost(AuthorizationResponse {
                vp_token: None,
                state: None,
                error: None,
                error_description: None,
            }),
        )
        .await
        .expect_err("unknown presentation transaction must be rejected");
    assert_eq!(
        (missing_response.status, missing_response.error),
        (400, "invalid_request")
    );

    let stored_signed_post = operations
        .store
        .request(signed_post.transaction_id, chrono::Utc::now())
        .await
        .expect("signed POST transaction should be readable")
        .expect("signed POST transaction should exist");
    let response_key: [u8; 32] = stored_signed_post
        .response_encryption_private_key
        .as_deref()
        .expect("signed POST must have a response key")
        .try_into()
        .expect("response key must be 32 bytes");
    let response_key = EphemeralEncryptionKey::from_secret_bytes(&response_key)
        .expect("stored response key should be valid");
    let malformed_plaintext = encrypt_ecdh_es(
        b"not-json",
        &response_key.public_jwk(),
        Some("application/json"),
    )
    .expect("malformed plaintext should still be encrypted");
    let malformed_response = operations
        .respond(
            signed_post.transaction_id,
            PresentationResponseInput::DirectPostJwt(malformed_plaintext),
        )
        .await
        .expect_err("decrypted non-JSON response must be rejected");
    assert_eq!(
        (malformed_response.status, malformed_response.error),
        (400, "invalid_request")
    );

    let mut missing_response_key = stored_signed_post;
    missing_response_key.id = Uuid::now_v7();
    missing_response_key.request.state = format!("missing-response-key-{}", Uuid::now_v7());
    missing_response_key.response_encryption_private_key = None;
    operations
        .store
        .create(&missing_response_key)
        .await
        .expect("transaction without response key should be insertable for the error test");
    let unavailable_response_key = operations
        .respond(
            missing_response_key.id,
            PresentationResponseInput::DirectPostJwt("ignored".to_owned()),
        )
        .await
        .expect_err("missing response key must fail closed");
    assert_eq!(
        (
            unavailable_response_key.status,
            unavailable_response_key.error
        ),
        (503, "server_error")
    );

    let policy_error = operations
        .create(create_input(
            Some("request_uri_signed_get"),
            Some("direct_post"),
            Some("redirect_uri"),
            false,
        ))
        .await
        .expect_err("redirect URI identifiers must not sign request objects");
    assert_eq!(
        (policy_error.status, policy_error.error),
        (400, "invalid_request")
    );
    let transaction_data_error = operations
        .create(CreatePresentationRequest {
            transaction_data: Some(vec![json!({"type": "fixture"})]),
            ..create_input(
                Some("request_uri_signed_get"),
                Some("direct_post"),
                Some("x509_hash"),
                false,
            )
        })
        .await
        .expect_err("transaction data must be rejected until proof binding exists");
    assert_eq!(
        (transaction_data_error.status, transaction_data_error.error),
        (400, "invalid_request")
    );

    let broken_store = nazo_postgres::Openid4vpRepository::new(
        invalid_pool(),
        crate::domain::tenancy::DEFAULT_TENANT_ID,
        [0x42; 32],
    );
    let store_error_operations = ServerPresentationOperations {
        store: broken_store.clone(),
        conformance: operations.conformance.clone(),
        service: nazo_openid4vp::PresentationService::new(broken_store, operations.crypto.clone()),
        crypto: operations.crypto.clone(),
        runtime: operations.runtime.clone(),
        issuer: operations.issuer.clone(),
        wallet_origins: operations.wallet_origins.clone(),
        transaction_ttl_seconds: operations.transaction_ttl_seconds,
        tenant_id: operations.tenant_id,
    };
    let store_error = store_error_operations
        .create(create_input(
            Some("request_uri_signed_get"),
            Some("direct_post"),
            Some("x509_hash"),
            false,
        ))
        .await
        .expect_err("presentation store failure must fail closed");
    assert_eq!(
        (store_error.status, store_error.error),
        (503, "server_error")
    );

    let invalid_prefix = operations
        .create(create_input(None, None, Some("unknown"), false))
        .await
        .expect_err("unknown client id prefix must be rejected");
    assert_eq!(
        (invalid_prefix.status, invalid_prefix.error),
        (400, "invalid_request")
    );
    let invalid_method = operations
        .create(create_input(Some("unknown"), None, None, false))
        .await
        .expect_err("unknown request method must be rejected");
    assert_eq!(
        (invalid_method.status, invalid_method.error),
        (400, "invalid_request")
    );
    let invalid_mode = operations
        .create(create_input(None, Some("unknown"), None, false))
        .await
        .expect_err("unknown response mode must be rejected");
    assert_eq!(
        (invalid_mode.status, invalid_mode.error),
        (400, "invalid_request")
    );
    let invalid_dcql = operations
        .create(CreatePresentationRequest {
            dcql_query: DcqlQuery {
                credentials: Vec::new(),
                credential_sets: None,
            },
            ..create_input(None, None, None, false)
        })
        .await
        .expect_err("empty DCQL query must be rejected");
    assert_eq!(
        (invalid_dcql.status, invalid_dcql.error),
        (400, "invalid_request")
    );

    let conformance_origin = format!(
        "https://wallet-conformance-{}.example",
        Uuid::now_v7().simple()
    );
    let conformance_endpoint = format!("{conformance_origin}/authorize");
    let valid_task_jti = format!("request-{:032x}", Uuid::now_v7().as_u128());
    let anchor_pem = format!("{}{}", valid_ca_pem(), valid_ca_pem());
    let valid_lease = leases
        .create(
            crate::domain::tenancy::DEFAULT_TENANT_ID,
            "nazoauth-full",
            &valid_task_jti,
            nazo_postgres::ConformanceLeaseTokenDigests::default(),
            Some(conformance_material(&conformance_origin, &anchor_pem)),
            60,
        )
        .await
        .expect("valid OpenID4VC conformance lease should be created");
    bind_suite_origin(&pool, valid_lease.id, &conformance_origin, &valid_task_jti).await;
    assert_eq!(
        operations
            .conformance_lease_for_wallet(&conformance_endpoint)
            .await
            .expect("wallet should resolve to its sole conformance lease"),
        Some(valid_lease.id)
    );
    let partial_lease_binding = operations
        .create(CreatePresentationRequest {
            conformance_lease_id: Some(valid_lease.id),
            ..create_input(None, None, None, false)
        })
        .await
        .expect_err("a partial conformance lease binding must be rejected");
    assert_eq!(
        (partial_lease_binding.status, partial_lease_binding.error),
        (400, "invalid_request")
    );
    let partial_task_binding = operations
        .create(CreatePresentationRequest {
            conformance_task_jti: Some(valid_task_jti.clone()),
            ..create_input(None, None, None, false)
        })
        .await
        .expect_err("a partial conformance task binding must be rejected");
    assert_eq!(
        (partial_task_binding.status, partial_task_binding.error),
        (400, "invalid_request")
    );

    let legacy_static_presentation = operations
        .create(create_input(None, None, None, false))
        .await
        .expect("static origins without a binding should retain legacy behavior");
    let legacy_static_transaction = operations
        .store
        .request(
            legacy_static_presentation.transaction_id,
            chrono::Utc::now(),
        )
        .await
        .expect("legacy static transaction should be readable")
        .expect("legacy static transaction should exist");
    assert_eq!(legacy_static_transaction.conformance_lease_id, None);

    let static_task_jti = format!("request-{:032x}", Uuid::now_v7().as_u128());
    let static_lease = leases
        .create(
            crate::domain::tenancy::DEFAULT_TENANT_ID,
            "nazoauth-full",
            &static_task_jti,
            nazo_postgres::ConformanceLeaseTokenDigests::default(),
            Some(conformance_material("https://wallet.example", &anchor_pem)),
            60,
        )
        .await
        .expect("static-origin conformance lease should be created");
    bind_suite_origin(
        &pool,
        static_lease.id,
        "https://wallet.example",
        &static_task_jti,
    )
    .await;
    let static_presentation = operations
        .create(CreatePresentationRequest {
            conformance_lease_id: Some(static_lease.id),
            conformance_task_jti: Some(static_task_jti.clone()),
            ..create_input(None, None, None, false)
        })
        .await
        .expect("static origins with an exact binding should be accepted");
    let static_transaction = operations
        .store
        .request(static_presentation.transaction_id, chrono::Utc::now())
        .await
        .expect("static-bound transaction should be readable")
        .expect("static-bound transaction should exist");
    assert_eq!(
        static_transaction.conformance_lease_id,
        Some(static_lease.id),
        "a complete binding must be stored even for a static Suite origin"
    );
    let static_binding = operations
        .create(CreatePresentationRequest {
            conformance_lease_id: Some(valid_lease.id),
            conformance_task_jti: Some(valid_task_jti.clone()),
            ..create_input(None, None, None, false)
        })
        .await
        .expect_err("static wallet origins must reject a cross-origin lease binding");
    assert_eq!(
        (static_binding.status, static_binding.error),
        (400, "invalid_request")
    );
    let missing_dynamic_binding = operations
        .create(CreatePresentationRequest {
            wallet_authorization_endpoint: conformance_endpoint.clone(),
            ..create_input(None, None, None, false)
        })
        .await
        .expect_err("dynamic Suite origins must require an exact binding");
    assert_eq!(
        (
            missing_dynamic_binding.status,
            missing_dynamic_binding.error
        ),
        (400, "invalid_request")
    );
    let dynamic_presentation = operations
        .create(CreatePresentationRequest {
            wallet_authorization_endpoint: conformance_endpoint.clone(),
            conformance_lease_id: Some(valid_lease.id),
            conformance_task_jti: Some(valid_task_jti.clone()),
            ..create_input(None, None, None, false)
        })
        .await
        .expect("dynamic Suite origin should be accepted");
    let dynamic_transaction = operations
        .store
        .request(dynamic_presentation.transaction_id, chrono::Utc::now())
        .await
        .expect("dynamic presentation transaction should be readable")
        .expect("dynamic presentation transaction should exist");
    assert_eq!(
        dynamic_transaction.conformance_lease_id,
        Some(valid_lease.id),
        "dynamic Suite origins must bind the presentation transaction to the matching lease"
    );
    let anchors = operations
        .conformance_credential_trust_anchors(Some(valid_lease.id))
        .await
        .expect("valid conformance lease should provide a trust anchor");
    assert_eq!(anchors.len(), 2);
    assert!(anchors.iter().all(|anchor| !anchor.is_empty()));

    assert_eq!(
        operations
            .conformance_lease_for_wallet("https://different-suite.example/authorize")
            .await
            .expect("a cross-origin wallet must not match the lease"),
        None
    );
    let cross_origin_binding = operations
        .create(CreatePresentationRequest {
            wallet_authorization_endpoint: "https://different-suite.example/authorize".to_owned(),
            conformance_lease_id: Some(valid_lease.id),
            conformance_task_jti: Some(valid_task_jti.clone()),
            ..create_input(None, None, None, false)
        })
        .await
        .expect_err("a lease binding must not cross Suite origins");
    assert_eq!(
        (cross_origin_binding.status, cross_origin_binding.error),
        (400, "invalid_request")
    );

    let duplicate_task_jti = format!("request-{:032x}", Uuid::now_v7().as_u128());
    let duplicate_lease = leases
        .create(
            crate::domain::tenancy::DEFAULT_TENANT_ID,
            "nazoauth-full",
            &duplicate_task_jti,
            nazo_postgres::ConformanceLeaseTokenDigests::default(),
            Some(conformance_material(&conformance_origin, &anchor_pem)),
            60,
        )
        .await
        .expect("duplicate-origin conformance lease should be created");
    bind_suite_origin(
        &pool,
        duplicate_lease.id,
        &conformance_origin,
        &duplicate_task_jti,
    )
    .await;
    let cross_run_binding = operations
        .create(CreatePresentationRequest {
            wallet_authorization_endpoint: conformance_endpoint.clone(),
            conformance_lease_id: Some(valid_lease.id),
            conformance_task_jti: Some(duplicate_task_jti.clone()),
            ..create_input(None, None, None, false)
        })
        .await
        .expect_err("a lease and JTI from different runs must not be mixed");
    assert_eq!(
        (cross_run_binding.status, cross_run_binding.error),
        (400, "invalid_request")
    );
    let duplicate_presentation = operations
        .create(CreatePresentationRequest {
            wallet_authorization_endpoint: conformance_endpoint.clone(),
            conformance_lease_id: Some(duplicate_lease.id),
            conformance_task_jti: Some(duplicate_task_jti.clone()),
            ..create_input(None, None, None, false)
        })
        .await
        .expect("exact binding must select the requested lease despite same-origin concurrency");
    let duplicate_transaction = operations
        .store
        .request(duplicate_presentation.transaction_id, chrono::Utc::now())
        .await
        .expect("duplicate-bound transaction should be readable")
        .expect("duplicate-bound transaction should exist");
    assert_eq!(
        duplicate_transaction.conformance_lease_id,
        Some(duplicate_lease.id)
    );
    let ambiguous = operations
        .conformance_lease_for_wallet(&conformance_endpoint)
        .await
        .expect_err("duplicate wallet trust must fail closed");
    assert_eq!((ambiguous.status, ambiguous.error), (503, "server_error"));

    leases
        .revoke(
            crate::domain::tenancy::DEFAULT_TENANT_ID,
            duplicate_lease.id,
        )
        .await
        .expect("duplicate lease should be revocable");
    assert_eq!(
        operations
            .conformance_lease_for_wallet(&conformance_endpoint)
            .await
            .expect("revoked duplicate must no longer make the origin ambiguous"),
        Some(valid_lease.id)
    );
    let revoked_binding = operations
        .create(CreatePresentationRequest {
            wallet_authorization_endpoint: conformance_endpoint.clone(),
            conformance_lease_id: Some(duplicate_lease.id),
            conformance_task_jti: Some(duplicate_task_jti),
            ..create_input(None, None, None, false)
        })
        .await
        .expect_err("a revoked lease must not be selectable");
    assert_eq!(
        (revoked_binding.status, revoked_binding.error),
        (400, "invalid_request")
    );

    leases
        .revoke(crate::domain::tenancy::DEFAULT_TENANT_ID, valid_lease.id)
        .await
        .expect("valid lease should be revocable");
    assert_eq!(
        operations
            .conformance_lease_for_wallet(&conformance_endpoint)
            .await
            .expect("revoked lease lookup should succeed"),
        None
    );

    let expired_origin = format!("https://wallet-expired-{}.example", Uuid::now_v7().simple());
    let expired_task_jti = format!("request-{:032x}", Uuid::now_v7().as_u128());
    let expired_lease = leases
        .create(
            crate::domain::tenancy::DEFAULT_TENANT_ID,
            "nazoauth-full",
            &expired_task_jti,
            nazo_postgres::ConformanceLeaseTokenDigests::default(),
            Some(conformance_material(&expired_origin, &anchor_pem)),
            60,
        )
        .await
        .expect("expired-origin conformance lease should be created");
    bind_suite_origin(&pool, expired_lease.id, &expired_origin, &expired_task_jti).await;
    expire_lease(&pool, expired_lease.id).await;
    assert_eq!(
        operations
            .conformance_lease_for_wallet(&format!("{expired_origin}/authorize"))
            .await
            .expect("expired lease lookup should succeed"),
        None
    );
    let expired_binding = operations
        .create(CreatePresentationRequest {
            wallet_authorization_endpoint: format!("{expired_origin}/authorize"),
            conformance_lease_id: Some(expired_lease.id),
            conformance_task_jti: Some(expired_task_jti),
            ..create_input(None, None, None, false)
        })
        .await
        .expect_err("an expired lease must not be selectable");
    assert_eq!(
        (expired_binding.status, expired_binding.error),
        (400, "invalid_request")
    );

    let malformed_material_lease = leases
        .create(
            crate::domain::tenancy::DEFAULT_TENANT_ID,
            "openid4vc",
            &format!("{:064x}", Uuid::now_v7().as_u128()),
            nazo_postgres::ConformanceLeaseTokenDigests::default(),
            Some(json!({})),
            60,
        )
        .await
        .expect("malformed conformance lease should be created for the error test");
    let malformed_material = operations
        .conformance_credential_trust_anchors(Some(malformed_material_lease.id))
        .await
        .expect_err("malformed conformance material must fail closed");
    assert_eq!(
        (malformed_material.status, malformed_material.error),
        (503, "server_error")
    );

    let invalid_anchor_lease = leases
        .create(
            crate::domain::tenancy::DEFAULT_TENANT_ID,
            "openid4vc",
            &format!("{:064x}", Uuid::now_v7().as_u128()),
            nazo_postgres::ConformanceLeaseTokenDigests::default(),
            Some(conformance_material(
                &format!("https://wallet-invalid-anchor-{}.example", Uuid::now_v7()),
                "not-pem",
            )),
            60,
        )
        .await
        .expect("invalid-anchor lease should be created for the error test");
    let invalid_anchor = operations
        .conformance_credential_trust_anchors(Some(invalid_anchor_lease.id))
        .await
        .expect_err("invalid conformance trust anchor must fail closed");
    assert_eq!(
        (invalid_anchor.status, invalid_anchor.error),
        (503, "server_error")
    );
}
