pub(crate) mod valkey;

#[path = "domain/database_user_fixture.rs"]
mod database_user_fixture;
pub(crate) use database_user_fixture::{
    DatabaseExternalIdentityFixture, DatabasePasskeyFixture, DatabaseUserFixture,
};

use std::{
    collections::BTreeSet,
    sync::{Arc, OnceLock},
};

use aws_lc_rs::{
    encoding::{AsDer, Pkcs8V1Der},
    rsa::{
        KeyPair, KeySize, OAEP_SHA256_MGF1SHA256, OaepPrivateDecryptingKey, PrivateDecryptingKey,
    },
    signature::KeyPair as _,
};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use ed25519_dalek::SigningKey;
use jsonwebtoken::jwk::Jwk;
use p256::elliptic_curve::{Generate, pkcs8::EncodePrivateKey as _};
use serde_json::{Value, json};

pub(crate) fn persisted_runtime_modules_fixture() -> BTreeSet<nazo_runtime_modules::ModuleId> {
    use nazo_runtime_modules::ModuleId;

    BTreeSet::from([
        ModuleId::DeviceAuthorization,
        ModuleId::TokenExchange,
        ModuleId::JwtBearerGrant,
        ModuleId::Ciba,
        ModuleId::RequestObjects,
        ModuleId::Jarm,
        ModuleId::Scim,
        ModuleId::FrontchannelLogout,
        ModuleId::SessionManagement,
    ])
}

pub(crate) struct Rfc9440CertificateFixture {
    pub(crate) header: String,
    pub(crate) thumbprint: String,
}

pub(crate) fn rfc9440_certificate_fixture(common_name: &str) -> Rfc9440CertificateFixture {
    use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, PKCS_ECDSA_P256_SHA256};
    use sha2::{Digest as _, Sha256};

    let mut params = CertificateParams::default();
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, common_name);
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::minutes(1);
    params.not_after = now + time::Duration::hours(1);
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("test P-256 key");
    let der = params
        .self_signed(&key)
        .expect("test certificate")
        .der()
        .to_vec();
    Rfc9440CertificateFixture {
        header: format!(":{}:", STANDARD.encode(&der)),
        thumbprint: URL_SAFE_NO_PAD.encode(Sha256::digest(&der)),
    }
}

pub(crate) fn hash_client_secret_fixture(secret: &str, pepper: &str) -> String {
    use nazo_auth::ClientSecretDigesterPort as _;

    nazo_key_management::ClientRegistrationCrypto::new(test_key_manager()).client_secret_digest(
        secret,
        pepper,
        &uuid::Uuid::now_v7().simple().to_string(),
    )
}

pub(crate) struct TestRsaKey {
    private_pkcs8_der: Vec<u8>,
    pub(crate) modulus: Vec<u8>,
    pub(crate) exponent: Vec<u8>,
}

impl TestRsaKey {
    pub(crate) fn generate() -> Self {
        let key = KeyPair::generate(KeySize::Rsa2048).expect("AWS-LC RSA fixture key");
        let private_pkcs8_der = AsDer::<Pkcs8V1Der<'static>>::as_der(&key)
            .expect("RSA fixture PKCS#8")
            .as_ref()
            .to_vec();
        Self {
            private_pkcs8_der,
            modulus: key
                .public_key()
                .modulus()
                .big_endian_without_leading_zero()
                .to_vec(),
            exponent: key
                .public_key()
                .exponent()
                .big_endian_without_leading_zero()
                .to_vec(),
        }
    }

    pub(crate) fn decrypt_oaep_sha256(&self, ciphertext: &[u8]) -> anyhow::Result<Vec<u8>> {
        let private = PrivateDecryptingKey::from_pkcs8(&self.private_pkcs8_der)
            .map_err(|_| anyhow::anyhow!("invalid RSA fixture private key"))?;
        let private = OaepPrivateDecryptingKey::new(private)
            .map_err(|_| anyhow::anyhow!("invalid RSA-OAEP fixture key"))?;
        let mut plaintext = vec![0; private.min_output_size()];
        Ok(private
            .decrypt(&OAEP_SHA256_MGF1SHA256, ciphertext, &mut plaintext, None)
            .map_err(|_| anyhow::anyhow!("RSA-OAEP fixture decryption failed"))?
            .to_vec())
    }
}

/// Shared infrastructure used to compose focused endpoint handles in tests.
#[derive(Clone)]
pub(crate) struct TestInfrastructure {
    pub(crate) diesel_db: nazo_postgres::DbPool,
    pub(crate) valkey: nazo_valkey::test_support::Client,
    pub(crate) settings: Arc<crate::settings::Settings>,
    pub(crate) keyset: nazo_key_management::KeyManager,
}

pub(crate) fn token_issuance_repository(
    pool: nazo_postgres::DbPool,
) -> nazo_postgres::TokenIssuanceRepository {
    initialize_audit_dependencies(&pool);
    nazo_postgres::TokenIssuanceRepository::new_with_response_key_ring(
        pool,
        nazo_postgres::TokenIssuanceResponseKeyRing::new("test-current", [0x11; 32], None)
            .expect("test response key ring is valid"),
    )
}

pub(crate) fn initialize_audit_dependencies(_pool: &nazo_postgres::DbPool) {
    static PROCESS_AUDIT_POOL: OnceLock<nazo_postgres::DbPool> = OnceLock::new();

    // The production audit sink is process-lifetime state.  Some endpoint tests
    // intentionally use a pool whose search_path points at a small isolated
    // schema, so allowing the first such test to install that pool makes all
    // later required-audit calls depend on tables the isolated fixture does not
    // own.  Keep the process-lifetime test sink on the canonical public test
    // database; focused repositories continue to use their caller-provided
    // pool below.
    let audit_pool = PROCESS_AUDIT_POOL.get_or_init(|| {
        let database_url = std::env::var("NAZO_TEST_DATABASE_URL")
            .or_else(|_| std::env::var("DATABASE_URL"))
            .expect("database-backed tests require NAZO_TEST_DATABASE_URL or DATABASE_URL");
        nazo_postgres::create_pool(database_url, 4)
            .expect("test durable audit database pool should build")
    });
    let preflight = crate::adapters::audit_anchor::AuditAnchorPreflight::new(
        crate::adapters::audit_anchor::AuditAnchorPreflightConfig {
            mode: crate::adapters::audit_anchor::config::AuditAnchorMode::Disabled,
            deployment_id: "unit-test".to_owned(),
            status_file: std::path::PathBuf::from("runtime/test/audit-anchor-health.json"),
            freshness: std::time::Duration::from_secs(1),
            max_lag: std::time::Duration::from_secs(1),
        },
    )
    .expect("test audit anchor preflight config is valid");
    crate::adapters::audit::install_persistent_audit_sink(
        nazo_postgres::AuditLedgerRepository::new(audit_pool.clone()),
        false,
        preflight,
    )
    .expect("test durable audit repository should install");
}

impl TestInfrastructure {
    pub(crate) fn active_module_snapshot(&self) -> nazo_runtime_modules::ActiveModuleSnapshot {
        nazo_runtime_modules::ActiveModuleSnapshot {
            revision: nazo_runtime_modules::ModuleRevision::new(0),
            accepting: persisted_runtime_modules_fixture(),
            draining: std::collections::BTreeSet::new(),
        }
    }

    pub(crate) fn valkey_connection(&self) -> nazo_valkey::ValkeyConnection {
        nazo_valkey::test_support::scoped_connection(self.valkey.clone())
    }
}

pub(crate) fn profile_sessions(
    state: &TestInfrastructure,
) -> actix_web::web::Data<crate::http::sessions::SessionProfileHandles> {
    actix_web::web::Data::new(crate::http::sessions::test_support::profile_session_handles(state))
}

pub(crate) fn avatar_profiles(
    state: &TestInfrastructure,
) -> actix_web::web::Data<crate::bootstrap::AvatarProfileService> {
    actix_web::web::Data::new(crate::bootstrap::AvatarProfileService::new(
        nazo_postgres::UserRepository::new(state.diesel_db.clone()),
        nazo_postgres::GrantRepository::new(state.diesel_db.clone()),
        crate::adapters::avatar_files::LocalAvatarStorage::new(
            state.settings.storage.avatar_storage_dir.clone(),
        ),
        state.settings.storage.avatar_max_bytes,
    ))
}

pub(crate) fn access_request_profiles(
    state: &TestInfrastructure,
) -> actix_web::web::Data<crate::bootstrap::ClientAccessProfileService> {
    actix_web::web::Data::new(crate::bootstrap::ClientAccessProfileService::new(
        nazo_postgres::AccessRequestRepository::new(state.diesel_db.clone()),
        nazo_valkey::DeliveryStore::new(&state.valkey_connection()),
        &state.settings.protocol.client_secret_pepper,
    ))
}

pub(crate) fn delivery_profiles(
    state: &TestInfrastructure,
) -> actix_web::web::Data<crate::bootstrap::ClientAccessProfileService> {
    access_request_profiles(state)
}

pub(crate) fn registration_service(
    state: &TestInfrastructure,
) -> actix_web::web::Data<crate::bootstrap::LocalRegistrationService> {
    let identity = &state.settings.identity;
    actix_web::web::Data::new(crate::bootstrap::LocalRegistrationService::new(
        nazo_postgres::UserRepository::new(state.diesel_db.clone()),
        nazo_valkey::AuthenticationStore::new(&state.valkey_connection()),
        crate::bootstrap::RegistrationSecretHasher,
        crate::adapters::email::SmtpVerificationEmailDelivery::from_delivery(
            &identity.email.delivery,
        ),
        state.settings.tenant.context,
        nazo_identity::RegistrationServiceConfig {
            delivery_enabled: crate::adapters::email::email_delivery_configured(&state.settings),
            send_peer_cooldown_seconds: identity.email.send_peer_cooldown_seconds,
            send_cooldown_seconds: identity.email.send_cooldown_seconds,
            code_ttl_seconds: identity.email.code_ttl_seconds,
        },
    ))
}

pub(crate) fn passkey_service(
    state: &TestInfrastructure,
) -> actix_web::web::Data<crate::bootstrap::LocalPasskeyService> {
    let passkey = &state.settings.identity.passkey;
    let session = &state.settings.session;
    actix_web::web::Data::new(crate::bootstrap::LocalPasskeyService::new(
        nazo_postgres::UserRepository::new(state.diesel_db.clone()),
        nazo_postgres::PasskeyRepository::new(state.diesel_db.clone()),
        nazo_valkey::AuthenticationStore::new(&state.valkey_connection()),
        nazo_postgres::MfaRepository::new(state.diesel_db.clone()),
        nazo_valkey::SessionStore::new(&state.valkey_connection()),
        crate::bootstrap::TracingPasskeyAudit,
        nazo_identity::PasskeyServiceConfig {
            tenant_id: state.settings.tenant.context.tenant_id,
            rp_id: passkey.rp_id.to_owned(),
            rp_name: passkey.rp_name.to_owned(),
            origin: passkey.origin.to_owned(),
            require_user_verification: passkey.require_user_verification,
            require_user_handle: passkey.require_user_handle,
            strict_base64: passkey.strict_base64,
            ceremony_ttl_seconds: crate::bootstrap::PASSKEY_CEREMONY_TTL_SECONDS,
            session_ttl_seconds: session.session_ttl_seconds,
        },
    ))
}

pub(crate) fn federation_service(
    state: &TestInfrastructure,
) -> actix_web::web::Data<crate::bootstrap::LocalFederationService> {
    actix_web::web::Data::new(crate::bootstrap::LocalFederationService::new(
        nazo_postgres::FederationRepository::new(state.diesel_db.clone()),
        nazo_valkey::AuthenticationStore::new(&state.valkey_connection()),
        crate::bootstrap::FederationBootstrapPasswordHasher,
        nazo_valkey::SessionStore::new(&state.valkey_connection()),
        crate::bootstrap::TracingFederationAudit,
        nazo_identity::FederationServiceConfig {
            tenant: state.settings.tenant.context,
            state_ttl_seconds: crate::http::auth::federation::FEDERATION_STATE_TTL_SECONDS,
            saml_replay_ttl_seconds: crate::http::auth::federation::SAML_REPLAY_TTL_SECONDS,
            session_ttl_seconds: state.settings.session.session_ttl_seconds,
        },
    ))
}

pub(crate) fn federation_http_config(
    state: &TestInfrastructure,
) -> actix_web::web::Data<crate::http::auth::federation::FederationHttpConfig> {
    let session = &state.settings.session;
    let federation = &state.settings.identity.federation;
    actix_web::web::Data::new(crate::http::auth::federation::FederationHttpConfig::new(
        federation.providers.clone(),
        federation.saml_gateway.clone(),
        session.session_cookie_name.as_str(),
        session.csrf_cookie_name.as_str(),
        session.session_ttl_seconds,
        session.cookie_secure,
    ))
}

pub(crate) fn auth_request_limiter(
    state: &TestInfrastructure,
) -> actix_web::web::Data<crate::http::rate_limit::AuthRequestLimiter> {
    let rate_limit = &state.settings.identity.rate_limit;
    actix_web::web::Data::new(crate::http::rate_limit::AuthRequestLimiter::new(
        nazo_valkey::RateLimitStore::new(&state.valkey_connection()),
        rate_limit.window_seconds,
        rate_limit.auth_max_requests,
        client_ip_config(state).get_ref().clone(),
    ))
}

pub(crate) fn client_ip_config(
    state: &TestInfrastructure,
) -> actix_web::web::Data<nazo_http_actix::ClientIpConfig> {
    let endpoint = &state.settings.endpoint;
    actix_web::web::Data::new(nazo_http_actix::ClientIpConfig::new(
        &endpoint.trusted_proxy_cidrs,
        endpoint.client_ip_header_mode,
    ))
}

pub(crate) struct ClientSigningFixture {
    algorithm: jsonwebtoken::Algorithm,
    private_pkcs8_der: Vec<u8>,
}

impl ClientSigningFixture {
    pub(crate) fn generate(algorithm: jsonwebtoken::Algorithm) -> anyhow::Result<Self> {
        let private_pkcs8_der = match algorithm {
            jsonwebtoken::Algorithm::EdDSA => {
                let seed: [u8; 32] = rand::random();
                let mut der = vec![
                    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04,
                    0x22, 0x04, 0x20,
                ];
                der.extend_from_slice(&seed);
                der
            }
            jsonwebtoken::Algorithm::RS256 | jsonwebtoken::Algorithm::PS256 => {
                let key = KeyPair::generate(KeySize::Rsa2048)
                    .map_err(|_| anyhow::anyhow!("AWS-LC RSA fixture generation failed"))?;
                let pkcs8 = AsDer::<Pkcs8V1Der<'static>>::as_der(&key)
                    .map_err(|_| anyhow::anyhow!("AWS-LC RSA fixture encoding failed"))?
                    .as_ref()
                    .to_vec();
                pkcs8::PrivateKeyInfoRef::try_from(pkcs8.as_slice())?
                    .private_key
                    .as_bytes()
                    .to_vec()
            }
            jsonwebtoken::Algorithm::ES256 => p256::SecretKey::try_generate()?
                .to_pkcs8_der()?
                .as_bytes()
                .to_vec(),
            _ => anyhow::bail!("unsupported test signing algorithm"),
        };
        Ok(Self {
            algorithm,
            private_pkcs8_der,
        })
    }

    pub(crate) fn public_jwk(&self, kid: &str) -> Value {
        let mut value = match self.algorithm {
            jsonwebtoken::Algorithm::EdDSA => {
                const PREFIX: &[u8] = &[
                    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04,
                    0x22, 0x04, 0x20,
                ];
                let mut seed = [0u8; 32];
                seed.copy_from_slice(&self.private_pkcs8_der[PREFIX.len()..]);
                let public = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
                json!({"kty":"OKP", "crv":"Ed25519", "x":URL_SAFE_NO_PAD.encode(public)})
            }
            jsonwebtoken::Algorithm::RS256 | jsonwebtoken::Algorithm::PS256 => {
                serde_json::to_value(
                    Jwk::from_encoding_key(
                        &jsonwebtoken::EncodingKey::from_rsa_der(&self.private_pkcs8_der),
                        self.algorithm,
                    )
                    .expect("generated RSA fixture must derive a public JWK"),
                )
                .expect("public JWK must serialize")
            }
            jsonwebtoken::Algorithm::ES256 => serde_json::to_value(
                Jwk::from_encoding_key(
                    &jsonwebtoken::EncodingKey::from_ec_der(&self.private_pkcs8_der),
                    self.algorithm,
                )
                .expect("generated EC fixture must derive a public JWK"),
            )
            .expect("public JWK must serialize"),
            _ => panic!("unsupported client signing fixture algorithm"),
        };
        value["kid"] = json!(kid);
        value["alg"] = json!(match self.algorithm {
            jsonwebtoken::Algorithm::EdDSA => "EdDSA",
            jsonwebtoken::Algorithm::RS256 => "RS256",
            jsonwebtoken::Algorithm::PS256 => "PS256",
            jsonwebtoken::Algorithm::ES256 => "ES256",
            _ => unreachable!(),
        });
        value["use"] = json!("sig");
        value
    }

    pub(crate) fn encode_jwt<T: serde::Serialize>(
        &self,
        header: &jsonwebtoken::Header,
        claims: &T,
    ) -> String {
        let encoding_key = match self.algorithm {
            jsonwebtoken::Algorithm::EdDSA => {
                jsonwebtoken::EncodingKey::from_ed_der(&self.private_pkcs8_der)
            }
            jsonwebtoken::Algorithm::RS256 | jsonwebtoken::Algorithm::PS256 => {
                jsonwebtoken::EncodingKey::from_rsa_der(&self.private_pkcs8_der)
            }
            jsonwebtoken::Algorithm::ES256 => {
                jsonwebtoken::EncodingKey::from_ec_der(&self.private_pkcs8_der)
            }
            _ => panic!("unsupported client signing fixture algorithm"),
        };
        jsonwebtoken::encode(header, claims, &encoding_key).expect("client fixture JWT should sign")
    }
}

pub(crate) fn client_signing_fixture(algorithm: jsonwebtoken::Algorithm) -> ClientSigningFixture {
    ClientSigningFixture::generate(algorithm).expect("client signing fixture should generate")
}

pub(crate) fn test_key_manager() -> nazo_key_management::KeyManager {
    nazo_key_management::KeyManager::for_test(jsonwebtoken::Algorithm::EdDSA)
}

pub(crate) fn test_key_manager_with_algorithm(
    algorithm: jsonwebtoken::Algorithm,
) -> nazo_key_management::KeyManager {
    nazo_key_management::KeyManager::for_test(algorithm)
}

pub(crate) fn failing_key_manager() -> nazo_key_management::KeyManager {
    nazo_key_management::KeyManager::for_test_behavior(
        jsonwebtoken::Algorithm::EdDSA,
        nazo_key_management::TestSigningBehavior::Failing,
    )
}

pub(crate) fn test_key_manager_with_auxiliary(
    algorithm: jsonwebtoken::Algorithm,
) -> nazo_key_management::KeyManager {
    nazo_key_management::KeyManager::for_test_with_auxiliary(algorithm)
}
