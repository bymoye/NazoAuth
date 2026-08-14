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
        openid4vc_trust_policy_resource_id: None,
        openid4vc_trust_policy_digest: None,
    }
}

fn ordinary_trust_policy_material() -> serde_json::Value {
    let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("trust anchor key");
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    ca_params.not_before = time::OffsetDateTime::now_utc() - time::Duration::minutes(1);
    ca_params.not_after = time::OffsetDateTime::now_utc() + time::Duration::hours(1);
    let anchor = CertifiedIssuer::self_signed(ca_params, ca_key)
        .expect("trust anchor certificate")
        .pem();
    let key = |kid: &str| {
        json!({
            "kty": "EC",
            "crv": "P-256",
            "x": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "y": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "kid": kid
        })
    };
    serde_json::to_value(nazo_operator_protocol::Openid4vcTrustPolicy {
        schema: 1,
        client_attestation_issuer: "https://attester.example".to_owned(),
        client_attestation_jwks: json!({"keys": [key("client")]}),
        key_attestation_jwks: json!({"keys": [key("holder")]}),
        credential_trust_anchor_pem: anchor,
        wallet_authorization_origins: vec!["https://dynamic-wallet.example".to_owned()],
    })
    .expect("ordinary trust policy should serialize")
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
        trust_policies: operations.trust_policies.clone(),
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

    let partial_resource_binding = operations
        .create(CreatePresentationRequest {
            openid4vc_trust_policy_resource_id: Some("trust:run-1".to_owned()),
            ..create_input(None, None, None, false)
        })
        .await
        .expect_err("a partial ordinary trust policy binding must be rejected");
    assert_eq!(
        (
            partial_resource_binding.status,
            partial_resource_binding.error
        ),
        (400, "invalid_request")
    );
    let partial_digest_binding = operations
        .create(CreatePresentationRequest {
            openid4vc_trust_policy_digest: Some("a".repeat(64)),
            ..create_input(None, None, None, false)
        })
        .await
        .expect_err("a partial ordinary trust policy digest fence must be rejected");
    assert_eq!(
        (partial_digest_binding.status, partial_digest_binding.error),
        (400, "invalid_request")
    );
    let missing_dynamic_binding = operations
        .create(CreatePresentationRequest {
            wallet_authorization_endpoint: "https://dynamic-wallet.example/authorize".to_owned(),
            ..create_input(None, None, None, false)
        })
        .await
        .expect_err("a non-static wallet must select an active ordinary trust policy");
    assert_eq!(
        (
            missing_dynamic_binding.status,
            missing_dynamic_binding.error
        ),
        (400, "invalid_request")
    );

    let policy_id = Uuid::now_v7();
    let policy_resource_id = format!("trust:{}", Uuid::now_v7());
    let policy_digest = "b".repeat(64);
    let mut connection = nazo_postgres::get_conn(&pool)
        .await
        .expect("trust policy fixture connection");
    sql_query(
        "INSERT INTO openid4vc_trust_policies
         (id, tenant_id, resource_id, resource_digest, public_material, wallet_origins)
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind::<diesel::sql_types::Uuid, _>(policy_id)
    .bind::<diesel::sql_types::Uuid, _>(crate::domain::tenancy::DEFAULT_TENANT_ID)
    .bind::<diesel::sql_types::Varchar, _>(&policy_resource_id)
    .bind::<diesel::sql_types::Varchar, _>(&policy_digest)
    .bind::<diesel::sql_types::Jsonb, _>(ordinary_trust_policy_material())
    .bind::<diesel::sql_types::Jsonb, _>(json!(["https://dynamic-wallet.example"]))
    .execute(&mut connection)
    .await
    .expect("ordinary trust policy should be inserted");

    let dynamic = operations
        .create(CreatePresentationRequest {
            wallet_authorization_endpoint: "https://dynamic-wallet.example/authorize".to_owned(),
            openid4vc_trust_policy_resource_id: Some(policy_resource_id.clone()),
            openid4vc_trust_policy_digest: Some(policy_digest.clone()),
            ..create_input(None, None, None, false)
        })
        .await
        .expect("an active ordinary trust policy should authorize the dynamic wallet");
    let frozen = operations
        .store
        .request(dynamic.transaction_id, Utc::now())
        .await
        .expect("frozen transaction lookup")
        .expect("frozen transaction");
    assert_eq!(frozen.openid4vc_trust_policy_binding_id, Some(policy_id));
    assert_eq!(
        frozen.openid4vc_trust_policy_resource_id.as_deref(),
        Some(policy_resource_id.as_str())
    );
    assert_eq!(
        frozen.openid4vc_trust_policy_digest.as_deref(),
        Some(policy_digest.as_str())
    );

    let digest_mismatch = operations
        .create(CreatePresentationRequest {
            wallet_authorization_endpoint: "https://dynamic-wallet.example/authorize".to_owned(),
            openid4vc_trust_policy_resource_id: Some(policy_resource_id.clone()),
            openid4vc_trust_policy_digest: Some("c".repeat(64)),
            ..create_input(None, None, None, false)
        })
        .await
        .expect_err("a mismatched policy digest must fail closed");
    assert_eq!(
        (digest_mismatch.status, digest_mismatch.error),
        (400, "invalid_request")
    );

    let other_tenant = Uuid::now_v7();
    sql_query("INSERT INTO tenants (id, slug, display_name) VALUES ($1, $2, $3)")
        .bind::<diesel::sql_types::Uuid, _>(other_tenant)
        .bind::<diesel::sql_types::Varchar, _>(format!("vp-test-{other_tenant}"))
        .bind::<diesel::sql_types::Varchar, _>("VP cross-tenant test")
        .execute(&mut connection)
        .await
        .expect("cross-tenant fixture should be inserted");
    let cross_tenant = ServerPresentationOperations::new(
        pool.clone(),
        other_tenant,
        [0x43; 32],
        operations.crypto.clone(),
        operations.runtime.clone(),
        PresentationVerifierConfig {
            issuer: operations.issuer.clone(),
            wallet_origins: operations.wallet_origins.clone(),
            transaction_ttl_seconds: operations.transaction_ttl_seconds,
        },
    )
    .create(CreatePresentationRequest {
        wallet_authorization_endpoint: "https://dynamic-wallet.example/authorize".to_owned(),
        openid4vc_trust_policy_resource_id: Some(policy_resource_id.clone()),
        openid4vc_trust_policy_digest: Some(policy_digest.clone()),
        ..create_input(None, None, None, false)
    })
    .await
    .expect_err("a trust policy must not cross tenant boundaries");
    assert_eq!(
        (cross_tenant.status, cross_tenant.error),
        (400, "invalid_request")
    );

    sql_query(
        "UPDATE openid4vc_trust_policies
         SET active = FALSE, revoked_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
         WHERE id = $1",
    )
    .bind::<diesel::sql_types::Uuid, _>(policy_id)
    .execute(&mut connection)
    .await
    .expect("trust policy should be revoked");
    assert!(
        operations
            .store
            .request(dynamic.transaction_id, Utc::now())
            .await
            .expect("revoked transaction lookup")
            .is_none(),
        "revocation must invalidate the frozen transaction"
    );
    let revoked = operations
        .create(CreatePresentationRequest {
            wallet_authorization_endpoint: "https://dynamic-wallet.example/authorize".to_owned(),
            openid4vc_trust_policy_resource_id: Some(policy_resource_id),
            openid4vc_trust_policy_digest: Some(policy_digest),
            ..create_input(None, None, None, false)
        })
        .await
        .expect_err("a revoked trust policy must not be selectable");
    assert_eq!((revoked.status, revoked.error), (400, "invalid_request"));
}
