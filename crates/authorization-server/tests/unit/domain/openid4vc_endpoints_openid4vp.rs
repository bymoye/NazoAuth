use super::*;

use std::{path::Path, sync::Arc};

use diesel::sql_query;
use diesel_async::RunQueryDsl;
use nazo_auth::SigningPurpose;
use nazo_digital_credentials::{CredentialFormat, DcqlQuery, VcIssuerTrustPolicy};
use nazo_key_management::{
    KeyManager, KeySettings, LocalKeyRegistration, Openid4vcMaterial, Openid4vcPublicMaterial,
};
use nazo_openid4vc_http_actix::{
    CreatePresentationRequest, PresentationOperations, PresentationResponseBody,
    PresentationResponseInput,
};
use nazo_openid4vp::PresentationStorePort;
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
    fixture_crypto_with_dns(root, true).await.0
}

async fn fixture_crypto_without_dns(root: &Path) -> Openid4vcCredentialCrypto {
    fixture_crypto_with_dns(root, false).await.0
}

async fn fixture_crypto_with_dns(
    root: &Path,
    include_dns: bool,
) -> (Openid4vcCredentialCrypto, KeyManager) {
    tokio::fs::create_dir_all(root)
        .await
        .expect("fixture key directory should be created");
    let settings = KeySettings {
        keys_dir: root.to_owned(),
        external_command: Vec::new(),
        external_timeout: std::time::Duration::from_secs(1),
        rotation_interval: chrono::Duration::days(30),
        prepublish_window: chrono::Duration::days(1),
        verification_grace: chrono::Duration::hours(1),
    };
    KeyManager::load_or_create(settings.clone())
        .await
        .expect("fixture key store should initialize");
    let signing_kid = KeyManager::register_local(
        &settings,
        LocalKeyRegistration {
            algorithm: jsonwebtoken::Algorithm::ES256,
            purposes: [
                SigningPurpose::Credential,
                SigningPurpose::PresentationRequest,
            ]
            .into_iter()
            .collect(),
        },
    )
    .await
    .expect("fixture signing key should register");
    let signing_record = KeyManager::list_keys(&settings)
        .await
        .expect("fixture keys should list")
        .into_iter()
        .find(|record| record.kid == signing_kid)
        .expect("registered fixture signing key should exist");
    let signing_key_pem = tokio::fs::read_to_string(root.join(signing_record.locator))
        .await
        .expect("registered fixture signing key PEM should load");
    let signing_key =
        KeyPair::from_pem(&signing_key_pem).expect("registered fixture P-256 signing key");
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

    let key_manager = KeyManager::load_or_create(settings)
        .await
        .expect("fixture key manager should load");
    key_manager.set_openid4vc_material_for_test(Openid4vcMaterial {
        public: Openid4vcPublicMaterial {
            signing_kid,
            certificate_chain_pem: format!("{}{}", leaf.pem(), ca.pem()),
            trust_anchors_pem: ca.pem(),
            revocation_snapshot: None,
        },
        iaca_private_materials: Default::default(),
    });
    let crypto = Openid4vcCredentialCrypto::new_with_policies(
        key_manager.clone(),
        VcIssuerTrustPolicy::san_bound(),
        crate::settings::Openid4vcRevocationPolicy::Disabled,
    )
    .expect("fixture OpenID4VC crypto should load");
    (crypto, key_manager)
}

fn rotated_material(current: &Openid4vcPublicMaterial) -> Openid4vcMaterial {
    let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("rotated CA key");
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    ca_params.not_before = time::OffsetDateTime::now_utc() - time::Duration::minutes(1);
    ca_params.not_after = time::OffsetDateTime::now_utc() + time::Duration::hours(1);
    let ca = CertifiedIssuer::self_signed(ca_params, ca_key).expect("rotated CA certificate");
    let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("rotated leaf key");
    let mut leaf_params =
        CertificateParams::new(vec!["issuer.example".to_owned()]).expect("rotated leaf params");
    leaf_params.is_ca = IsCa::NoCa;
    leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf_params.not_before = time::OffsetDateTime::now_utc() - time::Duration::minutes(1);
    leaf_params.not_after = time::OffsetDateTime::now_utc() + time::Duration::hours(1);
    let leaf = leaf_params
        .signed_by(&leaf_key, &ca)
        .expect("rotated leaf certificate");
    Openid4vcMaterial {
        public: Openid4vcPublicMaterial {
            signing_kid: current.signing_kid.clone(),
            certificate_chain_pem: format!("{}{}", leaf.pem(), ca.pem()),
            trust_anchors_pem: ca.pem(),
            revocation_snapshot: current.revocation_snapshot.clone(),
        },
        iaca_private_materials: Default::default(),
    }
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
    let mut active_modules = crate::test_support::persisted_runtime_modules_fixture();
    if enabled {
        active_modules.insert(nazo_runtime_modules::ModuleId::Openid4vpVerifier);
    }
    let runtime =
        crate::runtime_modules::test_support::runtime_module_registry_with_modules_for_test(
            pool.clone(),
            &settings,
            active_modules,
        )
        .expect("fixture runtime module registry should load");
    let store: Arc<dyn nazo_persistence::Openid4vpStore> =
        Arc::new(nazo_postgres::Openid4vpRepository::new(
            pool.clone(),
            crate::domain::tenancy::DEFAULT_TENANT_ID,
            [0x42; 32],
        ));
    ServerPresentationOperations::new(
        store,
        crate::domain::tenancy::DEFAULT_TENANT_ID,
        crypto,
        runtime,
        Arc::new(nazo_postgres::TenantResourceRepository::new(pool)),
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
        create_request_jti: Uuid::now_v7().to_string(),
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
    let policy = nazo_operator_protocol::Openid4vcTrustPolicy {
        schema: 1,
        client_attestation_issuer: "https://attester.example".to_owned(),
        client_attestation_jwks: json!({"keys": [key("client")]}),
        key_attestation_jwks: json!({"keys": [key("holder")]}),
        credential_trust_anchor_pem: anchor,
        wallet_authorization_origins: vec!["https://dynamic-wallet.example".to_owned()],
    };
    nazo_operator_protocol::validate_openid4vc_trust_policy(&policy)
        .expect("ordinary trust policy fixture should be valid");
    serde_json::to_value(policy).expect("ordinary trust policy should serialize")
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
        (
            disabled_error.status,
            disabled_error.error,
            disabled_error.description
        ),
        (
            503,
            "temporarily_unavailable",
            "Presentation verifier is unavailable."
        )
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
        (
            wallet_error.status,
            wallet_error.error,
            wallet_error.description
        ),
        (
            400,
            "invalid_request",
            "Wallet authorization endpoint is invalid."
        )
    );

    let untrusted_wallet_error = enabled
        .create(CreatePresentationRequest {
            wallet_authorization_endpoint: "https://untrusted-wallet.example/authorize".to_owned(),
            ..create_input(None, None, None, false)
        })
        .await
        .expect_err("untrusted HTTPS wallet without a policy must fail before storage");
    assert_eq!(
        (
            untrusted_wallet_error.status,
            untrusted_wallet_error.error,
            untrusted_wallet_error.description
        ),
        (
            400,
            "invalid_request",
            "The wallet origin is not statically trusted and no OpenID4VC trust policy was selected."
        )
    );

    let oversized_error = enabled
        .create(CreatePresentationRequest {
            transaction_data: Some(vec![json!({
                "payload": "x".repeat(
                    nazo_operator_protocol::MAX_OPENID4VP_NORMALIZED_CREATE_REQUEST_BYTES
                )
            })]),
            ..create_input(None, None, None, false)
        })
        .await
        .expect_err("oversized normalized create request must fail before storage");
    assert_eq!(
        (
            oversized_error.status,
            oversized_error.error,
            oversized_error.description
        ),
        (
            413,
            "invalid_request",
            "Presentation create request is too large."
        )
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
        (
            no_dns_error.status,
            no_dns_error.error,
            no_dns_error.description
        ),
        (
            400,
            "invalid_request",
            "x509_san_dns is unavailable for the verifier certificate."
        )
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
async fn create_and_request_cover_standard_modes_and_tenant_bound_trust() {
    let Some(database_url) = std::env::var("DATABASE_URL").ok() else {
        return;
    };
    let root = std::env::temp_dir().join(format!("nazo-openid4vp-live-{}", Uuid::now_v7()));
    let pool = nazo_postgres::create_pool(database_url, 2).expect("live pool should build");
    let (crypto, keyset) = fixture_crypto_with_dns(&root, true).await;
    let operations = operations_with_crypto(pool.clone(), crypto, true).await;

    let url_query_input = create_input(
        Some("url_query"),
        Some("direct_post"),
        Some("redirect_uri"),
        false,
    );
    let url_query = operations
        .create(url_query_input.clone())
        .await
        .expect("URL query presentation should be stored");
    assert_eq!(
        operations
            .create(url_query_input.clone())
            .await
            .expect("an exact retry must return the stored transaction"),
        url_query
    );
    let mut conflicting = url_query_input;
    conflicting.transaction_data = Some(vec![json!({"changed": true})]);
    assert_eq!(
        operations
            .create(conflicting)
            .await
            .expect_err("the same request JTI cannot identify different input")
            .status,
        409
    );
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
    assert_eq!(
        operations
            .request(signed_post.transaction_id, None)
            .await
            .expect_err("signed POST requires a wallet nonce")
            .status,
        400
    );
    assert!(matches!(
        operations
            .request(signed_post.transaction_id, Some("wallet-nonce"))
            .await
            .expect("wallet nonce should bind the signed request"),
        PresentationResponseBody::RequestObject(value) if value.split('.').count() == 3
    ));

    let rotated_signed_post = operations
        .create(create_input(
            None,
            Some("direct_post.jwt"),
            Some("x509_hash"),
            true,
        ))
        .await
        .expect("rotated signed POST presentation should be stored");
    let current = keyset
        .openid4vc_public_material()
        .expect("managed test material");
    keyset.set_openid4vc_material_for_test(rotated_material(&current));
    let rotation_error = operations
        .request(
            rotated_signed_post.transaction_id,
            Some("rotated-wallet-nonce"),
        )
        .await
        .expect_err("certificate rotation must not emit an x509_hash-mismatched JWT");
    assert_eq!(
        (rotation_error.status, rotation_error.error),
        (400, "invalid_request_uri")
    );

    for request in [
        create_input(None, None, Some("unknown"), false),
        create_input(Some("unknown"), None, None, false),
        create_input(None, Some("unknown"), None, false),
    ] {
        assert_eq!(
            operations
                .create(request)
                .await
                .expect_err("unknown protocol selector must be rejected")
                .status,
            400
        );
    }

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
        .expect("active ordinary trust policy should authorize its wallet");
    let frozen = operations
        .store
        .request(dynamic.transaction_id, chrono::Utc::now())
        .await
        .expect("frozen transaction lookup")
        .expect("frozen transaction should exist");
    assert_eq!(frozen.openid4vc_trust_policy_binding_id, Some(policy_id));

    let other_tenant = Uuid::now_v7();
    sql_query("INSERT INTO tenants (id, slug, display_name) VALUES ($1, $2, $3)")
        .bind::<diesel::sql_types::Uuid, _>(other_tenant)
        .bind::<diesel::sql_types::Varchar, _>(format!("vp-test-{other_tenant}"))
        .bind::<diesel::sql_types::Varchar, _>("VP cross-tenant test")
        .execute(&mut connection)
        .await
        .expect("cross-tenant fixture should be inserted");
    drop(connection);

    let cross_tenant = ServerPresentationOperations::new(
        Arc::new(nazo_postgres::Openid4vpRepository::new(
            pool.clone(),
            other_tenant,
            [0x43; 32],
        )),
        other_tenant,
        operations.crypto.clone(),
        operations.runtime.clone(),
        Arc::new(nazo_postgres::TenantResourceRepository::new(pool.clone())),
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
    .expect_err("trust policy must not cross tenant boundaries");
    assert_eq!(cross_tenant.status, 400);

    let mut connection = nazo_postgres::get_conn(&pool).await.unwrap();
    sql_query(
        "UPDATE openid4vc_trust_policies
         SET active = FALSE, revoked_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
         WHERE id = $1",
    )
    .bind::<diesel::sql_types::Uuid, _>(policy_id)
    .execute(&mut connection)
    .await
    .expect("trust policy should be revoked");
    drop(connection);
    assert!(
        operations
            .store
            .request(dynamic.transaction_id, chrono::Utc::now())
            .await
            .expect("revoked transaction lookup")
            .is_none(),
        "revocation must invalidate the frozen transaction"
    );
}
