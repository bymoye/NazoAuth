use super::dataset::openid4vci_credential_identifier;
use super::*;

use std::collections::{BTreeMap, BTreeSet};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use diesel::sql_query;
use diesel::sql_types::{Integer, Text, Uuid as SqlUuid};
use diesel_async::RunQueryDsl;
use fred::interfaces::ClientLike;
use nazo_digital_credentials::{CertificateRevocationPolicy, VcIssuerTrustPolicy, encrypt_ecdh_es};
use nazo_key_management::{KeyManager, KeySettings};
use nazo_openid4vci::{CredentialResponse, ProofTypeMetadata};
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair, KeyUsagePurpose,
    PKCS_ECDSA_P256_SHA256,
};

use crate::{
    config::ConfigSource,
    domain::tenancy::{DEFAULT_ORGANIZATION_ID, DEFAULT_REALM_ID, DEFAULT_TENANT_ID},
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
    let pool = invalid_pool();
    let mut valkey_builder = fred::prelude::Builder::default_centralized();
    valkey_builder.with_performance_config(|performance: &mut fred::prelude::PerformanceConfig| {
        performance.default_command_timeout = std::time::Duration::from_millis(100);
    });
    valkey_builder.with_connection_config(|connection: &mut fred::prelude::ConnectionConfig| {
        connection.connection_timeout = std::time::Duration::from_millis(100);
        connection.internal_command_timeout = std::time::Duration::from_millis(100);
        connection.max_command_attempts = 1;
    });
    let valkey = valkey_builder
        .build()
        .expect("valkey fixture should build without connecting");
    let valkey_connection = nazo_valkey::ValkeyConnection::from_existing_client(valkey);
    operations_with_inputs(
        pool,
        valkey_connection,
        enabled,
        BTreeMap::from([("unit-config".to_owned(), unit_configuration())]),
        BTreeSet::new(),
    )
    .await
}

fn unit_configuration() -> CredentialConfiguration {
    CredentialConfiguration {
        format: nazo_digital_credentials::CredentialFormat::SdJwtVc,
        scope: Some("unit-credential".to_owned()),
        cryptographic_binding_methods_supported: Vec::new(),
        credential_signing_alg_values_supported: vec!["ES256".to_owned()],
        proof_types_supported: Default::default(),
        vct: Some("https://issuer.example/unit".to_owned()),
        doctype: None,
        credential_metadata: None,
    }
}

async fn operations_with_inputs(
    pool: nazo_postgres::DbPool,
    valkey_connection: nazo_valkey::ValkeyConnection,
    enabled: bool,
    configurations: BTreeMap<String, CredentialConfiguration>,
    deferred_configurations: BTreeSet<String>,
) -> ServerCredentialIssuerOperations {
    let mut settings =
        Settings::from_config(&ConfigSource::default()).expect("unit settings should load");
    settings.endpoint.issuer = "https://issuer.example".to_owned();
    settings.modules.enable_openid4vci_issuer = enabled;
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
        configurations,
        deferred_configurations,
        nazo_auth::DpopNoncePolicy::Optional,
    )
    .expect("credential issuer fixture should build")
}

fn live_configuration(configuration_id: &str) -> (String, CredentialConfiguration) {
    (
        configuration_id.to_owned(),
        CredentialConfiguration {
            format: nazo_digital_credentials::CredentialFormat::SdJwtVc,
            scope: Some(format!("{configuration_id}-scope")),
            cryptographic_binding_methods_supported: vec!["jwk".to_owned()],
            credential_signing_alg_values_supported: vec!["ES256".to_owned()],
            proof_types_supported: BTreeMap::from([(
                "jwt".to_owned(),
                ProofTypeMetadata {
                    proof_signing_alg_values_supported: vec!["ES256".to_owned()],
                    key_attestations_required: None,
                },
            )]),
            vct: Some(format!("https://issuer.example/{configuration_id}")),
            doctype: None,
            credential_metadata: None,
        },
    )
}

struct LiveEndpointFixture {
    issuer: ServerCredentialIssuerOperations,
    pool: nazo_postgres::DbPool,
    admin_id: Uuid,
    subject_id: Uuid,
}

impl LiveEndpointFixture {
    async fn new(configuration_id: &str, deferred: bool) -> Option<Self> {
        let database_url = std::env::var("NAZO_TEST_DATABASE_URL")
            .or_else(|_| std::env::var("DATABASE_URL"))
            .ok()?;
        let valkey_url = std::env::var("VALKEY_URL").ok()?;
        nazo_postgres::run_pending_migrations(&database_url)
            .await
            .expect("OpenID4VC endpoint fixture migrations should succeed");
        let pool = nazo_postgres::create_pool(database_url, 4)
            .expect("OpenID4VC endpoint fixture pool should build");
        let mut valkey_builder = fred::prelude::Builder::from_config(
            fred::prelude::Config::from_url(&valkey_url)
                .expect("OpenID4VC endpoint fixture VALKEY_URL should parse"),
        );
        valkey_builder.with_performance_config(
            |performance: &mut fred::prelude::PerformanceConfig| {
                performance.default_command_timeout = std::time::Duration::from_secs(2);
            },
        );
        valkey_builder.with_connection_config(
            |connection: &mut fred::prelude::ConnectionConfig| {
                connection.connection_timeout = std::time::Duration::from_secs(2);
                connection.internal_command_timeout = std::time::Duration::from_secs(2);
                connection.max_command_attempts = 1;
            },
        );
        let valkey = valkey_builder
            .build()
            .expect("OpenID4VC endpoint fixture Valkey client should build");
        valkey
            .init()
            .await
            .expect("OpenID4VC endpoint fixture Valkey should connect");
        let valkey_connection = nazo_valkey::ValkeyConnection::from_existing_client(valkey);
        let (configuration_key, configuration) = live_configuration(configuration_id);
        let issuer = operations_with_inputs(
            pool.clone(),
            valkey_connection,
            true,
            BTreeMap::from([(configuration_key, configuration)]),
            if deferred {
                BTreeSet::from([configuration_id.to_owned()])
            } else {
                BTreeSet::new()
            },
        )
        .await;

        let admin_id = Uuid::now_v7();
        let subject_id = Uuid::now_v7();
        let mut connection = nazo_postgres::get_conn(&pool)
            .await
            .expect("OpenID4VC endpoint fixture database connection");
        for (id, role, admin_level) in [(admin_id, "admin", 1_i32), (subject_id, "user", 0_i32)] {
            sql_query(
                "INSERT INTO users
                    (id,tenant_id,realm_id,organization_id,username,email,password_hash,role,admin_level)
                 VALUES ($1,$2,$3,$4,$5,$6,'openid4vci-live-fixture',$7,$8)",
            )
            .bind::<SqlUuid, _>(id)
            .bind::<SqlUuid, _>(DEFAULT_TENANT_ID)
            .bind::<SqlUuid, _>(DEFAULT_REALM_ID)
            .bind::<SqlUuid, _>(DEFAULT_ORGANIZATION_ID)
            .bind::<Text, _>(format!("openid4vci-live-{id}"))
            .bind::<Text, _>(format!("openid4vci-live-{id}@example.test"))
            .bind::<Text, _>(role)
            .bind::<Integer, _>(admin_level)
            .execute(&mut connection)
            .await
            .expect("OpenID4VC endpoint fixture user insert");
        }
        drop(connection);
        let claims = json!({"given_name":"OpenID4VC Live Fixture", "sub": subject_id});
        let inserted = issuer
            .datasets
            .upsert_managed_dataset(nazo_postgres::ManagedCredentialDatasetWrite {
                tenant_id: DEFAULT_TENANT_ID,
                actor_user_id: admin_id,
                subject_id,
                credential_configuration_id: configuration_id,
                claims: &claims,
                valid_from: None,
                valid_until: None,
            })
            .await
            .expect("OpenID4VC endpoint fixture dataset upsert");
        assert!(
            inserted,
            "OpenID4VC endpoint fixture dataset must be inserted"
        );
        Some(Self {
            issuer,
            pool,
            admin_id,
            subject_id,
        })
    }

    async fn cleanup(self) {
        let mut connection = nazo_postgres::get_conn(&self.pool)
            .await
            .expect("OpenID4VC endpoint fixture cleanup connection");
        for query in [
            "DELETE FROM openid4vci_notifications WHERE token_id IN (SELECT token_id FROM openid4vci_access_grants WHERE subject_id = $1)",
            "DELETE FROM openid4vci_issuance_responses WHERE token_id IN (SELECT token_id FROM openid4vci_access_grants WHERE subject_id = $1)",
            "DELETE FROM openid4vci_deferred_transactions WHERE token_id IN (SELECT token_id FROM openid4vci_access_grants WHERE subject_id = $1)",
            "DELETE FROM openid4vci_access_grants WHERE subject_id = $1",
            "DELETE FROM openid4vci_offers WHERE subject_id = $1",
            "DELETE FROM openid4vci_credential_dataset_events WHERE subject_id = $1",
            "DELETE FROM openid4vci_credential_datasets WHERE subject_id = $1",
            "DELETE FROM users WHERE id IN ($1,$2)",
        ] {
            if query.contains("users WHERE") {
                sql_query(query)
                    .bind::<SqlUuid, _>(self.subject_id)
                    .bind::<SqlUuid, _>(self.admin_id)
                    .execute(&mut connection)
                    .await
                    .expect("OpenID4VC endpoint fixture cleanup query");
            } else {
                sql_query(query)
                    .bind::<SqlUuid, _>(self.subject_id)
                    .execute(&mut connection)
                    .await
                    .expect("OpenID4VC endpoint fixture cleanup query");
            }
        }
    }
}

fn pre_authorized_code(offer: &CreateCredentialOfferResponse) -> String {
    let grants = offer
        .credential_offer
        .grants
        .as_ref()
        .expect("pre-authorized offer grants");
    let value = grants
        .0
        .get(nazo_openid4vci::PRE_AUTHORIZED_CODE_GRANT)
        .expect("pre-authorized grant");
    serde_json::from_value::<nazo_openid4vci::PreAuthorizedCodeGrant>(value.clone())
        .expect("pre-authorized grant JSON")
        .pre_authorized_code
}

fn jwt_credential_request(configuration_id: &str, issuer: &str, nonce: &str) -> CredentialRequest {
    let fixture = crate::test_support::client_signing_fixture(jsonwebtoken::Algorithm::ES256);
    let jwk = serde_json::from_value(fixture.public_jwk("openid4vci-proof"))
        .expect("credential proof JWK");
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
    header.typ = Some("openid4vci-proof+jwt".to_owned());
    header.jwk = Some(jwk);
    let jwt = fixture.encode_jwt(
        &header,
        &json!({
            "aud": issuer,
            "nonce": nonce,
            "iat": chrono::Utc::now().timestamp(),
        }),
    );
    CredentialRequest {
        credential_identifier: Some(openid4vci_credential_identifier(configuration_id)),
        credential_configuration_id: None,
        proofs: Some(nazo_openid4vci::Proofs(BTreeMap::from([(
            "jwt".to_owned(),
            vec![json!(jwt)],
        )]))),
        credential_response_encryption: None,
        extensions: BTreeMap::new(),
    }
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
        mtls_x5t_s256: None,
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

    let mut jwk = issuer.request_encryption.public_jwk();
    jwk["alg"] = json!("ECDH-ES");
    jwk["kid"] = json!("openid4vci-request-encryption");
    let malformed = encrypt_ecdh_es(b"not-json", &jwk, Some("application/json"))
        .expect("fixture request JWE should encrypt");
    let error = issuer
        .request_json::<CredentialRequest>(CredentialRequestBody::Jwt(malformed))
        .await
        .expect_err("encrypted non-JSON request must fail closed");
    assert_error(
        error,
        400,
        "invalid_credential_request",
        "Encrypted credential request is malformed.",
    );
}

#[tokio::test]
async fn enabled_metadata_is_signed_and_advertises_request_and_response_encryption() {
    let issuer = operations(true).await;
    let metadata = issuer
        .metadata()
        .await
        .expect("enabled issuer metadata should be available");
    assert_eq!(metadata.credential_issuer, issuer.issuer);
    assert_eq!(metadata.authorization_servers, vec![issuer.issuer.clone()]);
    assert_eq!(
        metadata.credential_endpoint,
        "https://issuer.example/openid4vci/credential"
    );
    assert_eq!(
        metadata.deferred_credential_endpoint.as_deref(),
        Some("https://issuer.example/openid4vci/deferred_credential")
    );
    assert_eq!(
        metadata.notification_endpoint.as_deref(),
        Some("https://issuer.example/openid4vci/notification")
    );
    assert!(
        !metadata
            .credential_request_encryption
            .as_ref()
            .expect("request encryption metadata")
            .encryption_required
    );
    assert_eq!(
        metadata
            .credential_response_encryption
            .as_ref()
            .expect("response encryption metadata")
            .alg_values_supported,
        vec!["ECDH-ES".to_owned()]
    );
    assert_eq!(
        metadata
            .credential_response_encryption
            .as_ref()
            .expect("response encryption metadata")
            .zip_values_supported,
        vec!["DEF".to_owned()]
    );
    assert_eq!(
        metadata
            .batch_credential_issuance
            .as_ref()
            .expect("batch metadata")
            .batch_size,
        10
    );
    assert!(metadata.signed_metadata.is_some());
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

    let error = issuer
        .finish_response(
            response,
            Some(&CredentialResponseEncryption {
                jwk: json!({"alg":"ECDH-ES"}),
                enc: "A256GCM".to_owned(),
                zip: None,
            }),
        )
        .await
        .expect_err("an incomplete ECDH key must fail during encryption");
    assert_error(
        error,
        400,
        "invalid_encryption_parameters",
        "Credential response encryption key is invalid.",
    );
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
            .notify(
                request_context(),
                NotificationRequest {
                    notification_id: "unit-notification".to_owned(),
                    event: nazo_openid4vci::NotificationEvent::CredentialFailure,
                    event_description: None,
                },
            )
            .await
            .expect_err("notification disabled"),
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

    let error = issuer
        .offer(&Uuid::now_v7().to_string())
        .await
        .expect_err("valid offer identifier should reach the state store");
    assert_error(
        error,
        503,
        "server_error",
        "Credential offer state is unavailable.",
    );

    let error = issuer
        .nonce(None)
        .await
        .expect_err("nonce issuance should reach the state store");
    assert_error(
        error,
        503,
        "server_error",
        "Credential nonce state is unavailable.",
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

#[tokio::test]
async fn access_rejects_signed_token_with_another_audience_before_state_access() {
    let issuer = operations(true).await;
    let subject = Uuid::from_u128(0x4444);
    let subject_string = subject.to_string();
    let issued = issuer
        .token_service
        .sign_access_token(nazo_auth::AccessTokenSignInput {
            issuer: &issuer.issuer,
            tenant_id: issuer.tenant_id,
            subject: &subject_string,
            user_id: Some(subject),
            subject_type: "user",
            client_id: "unit-client",
            audiences: &["https://another.example".to_owned()],
            scopes: &[],
            authorization_details: &Value::Array(Vec::new()),
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
        .expect_err("token for another audience must be rejected");
    assert_error(
        error,
        401,
        "invalid_token",
        "Access token is not intended for this credential issuer.",
    );
}

#[tokio::test]
async fn access_fails_closed_when_revocation_state_is_unavailable() {
    let issuer = operations(true).await;
    let subject = Uuid::from_u128(0x5555);
    let subject_string = subject.to_string();
    let issued = issuer
        .token_service
        .sign_access_token(nazo_auth::AccessTokenSignInput {
            issuer: &issuer.issuer,
            tenant_id: issuer.tenant_id,
            subject: &subject_string,
            user_id: Some(subject),
            subject_type: "user",
            client_id: "unit-client",
            audiences: std::slice::from_ref(&issuer.issuer),
            scopes: &[],
            authorization_details: &Value::Array(Vec::new()),
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
        .expect_err("unavailable revocation state must fail closed");
    assert_error(error, 401, "invalid_token", "Access token is revoked.");
}

#[tokio::test]
async fn pre_authorized_token_rejects_partial_client_attestation_before_offer_lookup() {
    let issuer = operations(true).await;
    let request = |client_attestation: Option<&str>, client_attestation_pop: Option<&str>| {
        PreAuthorizedTokenRequest {
            pre_authorized_code: "unit-code".to_owned(),
            tx_code: None,
            client_id: None,
            dpop_proof: None,
            client_attestation: client_attestation.map(str::to_owned),
            client_attestation_pop: client_attestation_pop.map(str::to_owned),
            request_url: "https://issuer.example/token".to_owned(),
        }
    };

    let error = issuer
        .pre_authorized_token(request(Some("attestation"), None))
        .await
        .expect_err("partial attestation must be rejected");
    assert_error(
        error,
        400,
        "invalid_request",
        "Both client attestation headers are required.",
    );

    let error = issuer
        .pre_authorized_token(request(Some("attestation"), Some("proof")))
        .await
        .expect_err("attestation without a configured validator must be rejected");
    assert_error(
        error,
        401,
        "invalid_client_attestation",
        "Client attestation is not configured.",
    );
}

#[tokio::test]
async fn pre_authorized_token_reaches_offer_state_after_optional_dpop_validation() {
    let issuer = operations(true).await;
    let error = issuer
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
        .expect_err("missing offer state should fail at the persistence boundary");
    assert_error(
        error,
        503,
        "server_error",
        "Credential offer state is unavailable.",
    );
}

#[tokio::test]
async fn create_offer_rejects_invalid_grant_shapes_and_subject_before_database_state() {
    let issuer = operations(true).await;
    let base = |grant_types: Vec<String>, tx_code: Option<&str>, subject_id| {
        CreateCredentialOfferRequest {
            subject_id,
            credential_configuration_ids: vec!["unit-config".to_owned()],
            grant_types,
            tx_code: tx_code.map(str::to_owned),
            expires_in: 300,
        }
    };

    for request in [
        base(Vec::new(), None, Uuid::nil()),
        base(vec!["unsupported".to_owned()], None, Uuid::nil()),
        base(
            vec![
                "authorization_code".to_owned(),
                "authorization_code".to_owned(),
            ],
            None,
            Uuid::nil(),
        ),
        base(
            vec!["authorization_code".to_owned()],
            Some("1234"),
            Uuid::nil(),
        ),
    ] {
        let error = issuer
            .create_offer(request)
            .await
            .expect_err("invalid grant shape must be rejected");
        assert_error(
            error,
            400,
            "invalid_request",
            "Credential offer grant types are invalid.",
        );
    }

    let error = issuer
        .create_offer(base(
            vec![nazo_openid4vci::PRE_AUTHORIZED_CODE_GRANT.to_owned()],
            None,
            Uuid::nil(),
        ))
        .await
        .expect_err("nil subject must be rejected");
    assert_error(
        error,
        400,
        "invalid_request",
        "Credential subject is invalid.",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires NAZO_TEST_DATABASE_URL/DATABASE_URL and VALKEY_URL; run explicitly with --ignored"]
async fn live_immediate_offer_pre_authorized_credential_replay_and_notification() {
    let Some(fixture) = LiveEndpointFixture::new("unit-live-immediate", false).await else {
        return;
    };
    let offer = fixture
        .issuer
        .create_offer(CreateCredentialOfferRequest {
            subject_id: fixture.subject_id,
            credential_configuration_ids: vec!["unit-live-immediate".to_owned()],
            grant_types: vec![nazo_openid4vci::PRE_AUTHORIZED_CODE_GRANT.to_owned()],
            tx_code: None,
            expires_in: 300,
        })
        .await
        .expect("live immediate offer should persist");
    let access = fixture
        .issuer
        .pre_authorized_token(PreAuthorizedTokenRequest {
            pre_authorized_code: pre_authorized_code(&offer),
            tx_code: None,
            client_id: Some("live-wallet".to_owned()),
            dpop_proof: None,
            client_attestation: None,
            client_attestation_pop: None,
            request_url: "https://issuer.example/token".to_owned(),
        })
        .await
        .expect("live pre-authorized token should be issued");
    assert_eq!(access.token_type, "Bearer");
    assert_eq!(access.authorization_details.len(), 1);

    let nonce = fixture
        .issuer
        .nonce(None)
        .await
        .expect("live credential nonce should be issued");
    let request = jwt_credential_request("unit-live-immediate", &fixture.issuer.issuer, &nonce);
    let mut context = request_context();
    context.bearer_token = access.access_token;
    let response = fixture
        .issuer
        .credential(
            context.clone(),
            CredentialRequestBody::Json(request.clone()),
        )
        .await
        .expect("live immediate credential should be issued");
    let notification_id = match &response.body {
        CredentialResponseBody::Json(body) => body
            .notification_id
            .clone()
            .expect("immediate response notification id"),
        CredentialResponseBody::Jwt(_) => panic!("live fixture requests JSON response"),
    };
    assert!(matches!(
        &response.body,
        CredentialResponseBody::Json(CredentialResponse {
            credentials: Some(_),
            transaction_id: None,
            ..
        })
    ));

    let replay = fixture
        .issuer
        .credential(context.clone(), CredentialRequestBody::Json(request))
        .await
        .expect("identical immediate credential request should replay");
    assert_eq!(replay.body, response.body);
    assert_eq!(replay.dpop_nonce, response.dpop_nonce);

    fixture
        .issuer
        .notify(
            CredentialRequestContext {
                request_url: "/openid4vci/notification".to_owned(),
                ..context.clone()
            },
            NotificationRequest {
                notification_id: notification_id.clone(),
                event: nazo_openid4vci::NotificationEvent::CredentialAccepted,
                event_description: Some("live immediate completed".to_owned()),
            },
        )
        .await
        .expect("live immediate notification should be recorded");

    let error = fixture
        .issuer
        .notify(
            CredentialRequestContext {
                request_url: "/openid4vci/notification".to_owned(),
                ..context
            },
            NotificationRequest {
                notification_id,
                event: nazo_openid4vci::NotificationEvent::CredentialAccepted,
                event_description: Some("live immediate replay".to_owned()),
            },
        )
        .await
        .expect_err("terminal notification must not be replayed");
    assert_error(
        error,
        400,
        "invalid_notification_id",
        "Notification identifier is invalid or already terminal.",
    );
    fixture.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires NAZO_TEST_DATABASE_URL/DATABASE_URL and VALKEY_URL; run explicitly with --ignored"]
async fn live_deferred_credential_claim_response_replay_and_notification() {
    let Some(fixture) = LiveEndpointFixture::new("unit-live-deferred", true).await else {
        return;
    };
    let offer = fixture
        .issuer
        .create_offer(CreateCredentialOfferRequest {
            subject_id: fixture.subject_id,
            credential_configuration_ids: vec!["unit-live-deferred".to_owned()],
            grant_types: vec![nazo_openid4vci::PRE_AUTHORIZED_CODE_GRANT.to_owned()],
            tx_code: None,
            expires_in: 300,
        })
        .await
        .expect("live deferred offer should persist");
    let access = fixture
        .issuer
        .pre_authorized_token(PreAuthorizedTokenRequest {
            pre_authorized_code: pre_authorized_code(&offer),
            tx_code: None,
            client_id: Some("live-wallet".to_owned()),
            dpop_proof: None,
            client_attestation: None,
            client_attestation_pop: None,
            request_url: "https://issuer.example/token".to_owned(),
        })
        .await
        .expect("live deferred pre-authorized token should be issued");
    let nonce = fixture
        .issuer
        .nonce(None)
        .await
        .expect("live deferred credential nonce should be issued");
    let request = jwt_credential_request("unit-live-deferred", &fixture.issuer.issuer, &nonce);
    let mut context = request_context();
    context.bearer_token = access.access_token;
    let pending = fixture
        .issuer
        .credential(context.clone(), CredentialRequestBody::Json(request))
        .await
        .expect("live deferred credential should return a transaction");
    let transaction_id = match pending.body {
        CredentialResponseBody::Json(CredentialResponse {
            transaction_id: Some(transaction_id),
            credentials: None,
            ..
        }) => transaction_id,
        _ => panic!("live deferred response should contain a transaction id"),
    };

    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    let deferred_request = DeferredCredentialRequest {
        transaction_id,
        credential_response_encryption: None,
    };
    let deferred_context = CredentialRequestContext {
        request_url: "/openid4vci/deferred_credential".to_owned(),
        ..context
    };
    let response = fixture
        .issuer
        .deferred(
            deferred_context.clone(),
            CredentialRequestBody::Json(deferred_request.clone()),
        )
        .await
        .expect("live deferred credential should be released");
    let notification_id = match &response.body {
        CredentialResponseBody::Json(body) => body
            .notification_id
            .clone()
            .expect("deferred response notification id"),
        CredentialResponseBody::Jwt(_) => panic!("live fixture requests JSON response"),
    };
    assert!(matches!(
        &response.body,
        CredentialResponseBody::Json(CredentialResponse {
            credentials: Some(_),
            transaction_id: None,
            ..
        })
    ));

    let replay = fixture
        .issuer
        .deferred(
            deferred_context.clone(),
            CredentialRequestBody::Json(deferred_request),
        )
        .await
        .expect("identical deferred request should replay");
    assert_eq!(replay.body, response.body);
    assert_eq!(replay.dpop_nonce, response.dpop_nonce);

    fixture
        .issuer
        .notify(
            CredentialRequestContext {
                request_url: "/openid4vci/notification".to_owned(),
                ..deferred_context
            },
            NotificationRequest {
                notification_id,
                event: nazo_openid4vci::NotificationEvent::CredentialAccepted,
                event_description: Some("live deferred completed".to_owned()),
            },
        )
        .await
        .expect("live deferred notification should be recorded");
    fixture.cleanup().await;
}

#[path = "openid4vci_endpoint_operations_policy.rs"]
mod policy;
