use super::*;

use std::path::Path;

use nazo_digital_credentials::{
    CertificateRevocationPolicy, CredentialFormat, DcqlQuery, VcIssuerTrustPolicy,
};
use nazo_key_management::{KeyManager, KeySettings};
use nazo_openid4vc_http_actix::{
    CreatePresentationRequest, PresentationOperations, PresentationResponseBody,
    PresentationResponseInput,
};
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair, KeyUsagePurpose,
    PKCS_ECDSA_P256_SHA256,
};
use serde_json::json;

fn invalid_pool() -> nazo_postgres::DbPool {
    nazo_postgres::create_pool(
        "postgres://openid4vp_unit_test:openid4vp_unit_test@127.0.0.1:1/oauth".to_owned(),
        1,
    )
    .expect("pool construction should not connect")
}

async fn fixture_crypto(root: &Path) -> Openid4vcCredentialCrypto {
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

    let mut leaf_params =
        CertificateParams::new(vec!["issuer.example".to_owned()]).expect("fixture leaf parameters");
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
    }
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
}

#[tokio::test]
async fn create_and_request_cover_url_query_signed_get_and_signed_post_modes() {
    let Some(database_url) = std::env::var("DATABASE_URL").ok() else {
        return;
    };
    let root = std::env::temp_dir().join(format!("nazo-openid4vp-live-{}", Uuid::now_v7()));
    let pool = nazo_postgres::create_pool(database_url, 2).expect("live pool should build");
    let operations = operations(pool, &root, true).await;

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
            Some("x509_hash"),
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
            Some("x509_san_dns"),
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
}
