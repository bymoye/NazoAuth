use super::{
    AdminClientConfig, ServerAdminClientCrypto, ServerAdminClientService,
    ServerSectorIdentifierResolver, admin_client_policy,
};
use crate::adapters::security::random_urlsafe_token;
use crate::settings::Settings;
use crate::test_support::hash_client_secret_fixture as hash_client_secret;
use nazo_auth::AdminClientCryptoPort;
use nazo_key_management::{
    client_jwks_contains_signing_key, client_jwks_matching_encryption_key_count,
    validate_client_jwks, validate_self_signed_mtls_jwks,
};
use serde_json::Value;

pub(crate) use nazo_auth::{
    AdminClientError as InsertClientError, CreateClientRequest, PreparedClientRegistration,
};

pub(crate) fn admin_session_handles(
    database: nazo_postgres::DbPool,
    valkey: nazo_valkey::ValkeyConnection,
    settings: &Settings,
) -> actix_web::web::Data<crate::http::sessions::AdminSessionHandles> {
    let session = &settings.session;
    actix_web::web::Data::new(crate::http::sessions::AdminSessionHandles::new(
        nazo_valkey::SessionStore::new(&valkey),
        nazo_postgres::UserRepository::new(database),
        crate::http::sessions::SessionHttpConfig::new(
            &session.session_cookie_name,
            &session.csrf_cookie_name,
            session.cookie_secure,
        ),
    ))
}

pub(crate) fn admin_client_service(
    database: nazo_postgres::DbPool,
    keyset: nazo_key_management::KeyManager,
    settings: &Settings,
) -> actix_web::web::Data<ServerAdminClientService> {
    actix_web::web::Data::new(ServerAdminClientService::new(
        nazo_postgres::OAuthClientRepository::new(database),
        ServerSectorIdentifierResolver,
        ServerAdminClientCrypto::new(keyset),
        admin_client_policy(settings),
    ))
}

pub(crate) fn admin_client_config(settings: &Settings) -> actix_web::web::Data<AdminClientConfig> {
    actix_web::web::Data::new(AdminClientConfig::from_settings(settings))
}

pub(crate) async fn prepare_client_insert_with_secret_pepper(
    payload: CreateClientRequest,
    pairwise_subject_secret: Option<&str>,
    client_secret_pepper: &str,
    _issuer: &str,
    response_signing_algorithms: &[&'static str],
) -> Result<PreparedClientRegistration, InsertClientError> {
    let crypto = TestAdminClientCrypto {
        response_signing_algorithms,
    };
    nazo_auth::prepare_client_registration(
        payload,
        &nazo_auth::AdminClientPolicy {
            tenant: nazo_identity::TenantContext::default_system(),
            pairwise_subject_secret: pairwise_subject_secret.map(ToOwned::to_owned),
            client_secret_pepper: client_secret_pepper.to_owned(),
        },
        &ServerSectorIdentifierResolver,
        &crypto,
    )
    .await
}

struct TestAdminClientCrypto<'a> {
    response_signing_algorithms: &'a [&'static str],
}

impl AdminClientCryptoPort for TestAdminClientCrypto<'_> {
    fn response_signing_algorithms(&self) -> Vec<String> {
        self.response_signing_algorithms
            .iter()
            .map(|algorithm| (*algorithm).to_owned())
            .collect()
    }

    fn issue_client_secret(&self, pepper: &str) -> (String, String) {
        let secret = random_urlsafe_token();
        let digest = hash_client_secret(&secret, pepper);
        (secret, digest)
    }

    fn validate_jwks(&self, jwks: &Value) -> Result<(), String> {
        validate_client_jwks(jwks).map_err(|error| error.to_string())
    }

    fn validate_rfc4514_dn(&self, value: &str) -> Result<(), String> {
        nazo_key_management::validate_rfc4514_dn(value)
    }

    fn matching_encryption_key_count(&self, jwks: &Value, algorithm: &str) -> usize {
        client_jwks_matching_encryption_key_count(jwks, algorithm)
    }

    fn contains_signing_key(&self, jwks: &Value) -> bool {
        client_jwks_contains_signing_key(jwks)
    }

    fn valid_self_signed_mtls_jwks(&self, jwks: &Value) -> bool {
        validate_self_signed_mtls_jwks(jwks)
    }
}

pub(crate) async fn insert_prepared_client(
    repository: &nazo_postgres::OAuthClientRepository,
    prepared: &PreparedClientRegistration,
) -> Result<nazo_auth::OAuthClient, InsertClientError> {
    nazo_auth::insert_prepared_client(repository, prepared).await
}

pub(crate) async fn prepare_client_patch(
    current: &nazo_auth::OAuthClient,
    payload: nazo_auth::PatchClientRequest,
    pairwise_subject_secret: Option<&str>,
    _issuer: &str,
    response_signing_algorithms: &[&'static str],
) -> Result<nazo_auth::OAuthClient, InsertClientError> {
    let crypto = TestAdminClientCrypto {
        response_signing_algorithms,
    };
    nazo_auth::prepare_client_patch(
        current.clone(),
        payload,
        &nazo_auth::AdminClientPolicy {
            tenant: nazo_identity::TenantContext::default_system(),
            pairwise_subject_secret: pairwise_subject_secret.map(ToOwned::to_owned),
            client_secret_pepper: crate::adapters::security::LOCAL_DEVELOPMENT_CLIENT_SECRET_PEPPER
                .to_owned(),
        },
        &ServerSectorIdentifierResolver,
        &crypto,
    )
    .await
}
