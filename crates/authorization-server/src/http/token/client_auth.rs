//! token 管理端点复用的客户端认证。
use crate::adapters::security::ClientAssertionError;
use crate::adapters::security::ClientCredentials;
use crate::adapters::security::ValidatedClientAssertion;
use crate::adapters::security::blake3_hex;
use crate::adapters::security::client_secret_digest;
#[cfg(test)]
use crate::adapters::security::consume_private_key_jwt;
use crate::adapters::security::verify_private_key_jwt_claims_for_issuer;
use crate::domain::ClientRow;
#[cfg(test)]
use crate::domain::TestAppState;
#[cfg(test)]
use crate::domain::tenancy::DEFAULT_ORGANIZATION_ID;
#[cfg(test)]
use crate::domain::tenancy::DEFAULT_REALM_ID;
#[cfg(test)]
use crate::domain::tenancy::DEFAULT_TENANT_ID;
use crate::http::mtls::MtlsClientCertificate;
use crate::http::mtls::client_mtls_certificate_matches;
#[cfg(test)]
use crate::settings::Settings;
#[cfg(test)]
use chrono::Utc;
use nazo_auth::{
    ClientAuthenticationContext, ClientAuthenticationPolicyError, ClientAuthenticationRequirement,
    client_authentication_requirement,
};
#[cfg(test)]
use serde_json::json;
#[cfg(test)]
use uuid::Uuid;

pub(crate) enum TokenManagementClientAuthError {
    InvalidClient,
    PublicClientCredentialsForbidden,
    StoreUnavailable,
}

#[derive(Clone, Debug)]
pub(crate) struct ClientAuthRequestFacts {
    endpoint_path: String,
    client_certificate: Option<MtlsClientCertificate>,
}

impl ClientAuthRequestFacts {
    pub(crate) fn new(
        endpoint_path: impl Into<String>,
        client_certificate: Option<MtlsClientCertificate>,
    ) -> Self {
        Self {
            endpoint_path: endpoint_path.into(),
            client_certificate,
        }
    }

    pub(crate) fn endpoint_path(&self) -> &str {
        &self.endpoint_path
    }
}

#[derive(Clone, Copy)]
pub(crate) struct ClientAuthConfig<'a> {
    issuer: &'a str,
    client_secret_pepper: &'a str,
}

impl<'a> ClientAuthConfig<'a> {
    pub(crate) fn new(issuer: &'a str, client_secret_pepper: &'a str) -> Self {
        Self {
            issuer,
            client_secret_pepper,
        }
    }
}

fn dummy_client_secret_salt(client_id: Option<&str>) -> String {
    blake3_hex(client_id.unwrap_or(""))
}

/// Equalizes the CPU work for an unknown secret-authenticated client without touching storage.
/// The result is deliberately consumed so release optimization cannot remove the calculation.
pub(crate) fn perform_dummy_client_secret_verification(
    credentials: &ClientCredentials,
    client_secret_pepper: &str,
) {
    if matches!(
        credentials.method.as_str(),
        "client_secret_basic" | "client_secret_post"
    ) && let Some(secret) = credentials.client_secret.as_deref()
    {
        let dummy_salt = dummy_client_secret_salt(credentials.client_id.as_deref());
        drop(std::hint::black_box(client_secret_digest(
            secret,
            client_secret_pepper,
            &dummy_salt,
        )));
    }
}

#[cfg(not(test))]
pub(crate) async fn authenticate_introspection_client_with_dependencies(
    service: &crate::http::authorization::ServerAuthorizationService,
    config: ClientAuthConfig<'_>,
    request: &ClientAuthRequestFacts,
    client: &ClientRow,
    credentials: &ClientCredentials,
) -> Result<(), TokenManagementClientAuthError> {
    let assertion = authenticate_client_with_dependencies(
        service,
        config,
        request,
        client,
        credentials,
        ClientAuthenticationContext::ConfidentialOnly,
    )
    .await?;
    consume_token_management_client_assertion_with_authorization_service(
        service,
        client,
        assertion.as_ref(),
    )
    .await
    .map_err(|error| match error {
        TokenManagementClientAuthError::PublicClientCredentialsForbidden => {
            TokenManagementClientAuthError::InvalidClient
        }
        other => other,
    })
}

#[cfg(not(test))]
pub(crate) async fn authenticate_revocation_client_with_dependencies(
    service: &crate::http::authorization::ServerAuthorizationService,
    config: ClientAuthConfig<'_>,
    request: &ClientAuthRequestFacts,
    client: &ClientRow,
    credentials: &ClientCredentials,
) -> Result<(), TokenManagementClientAuthError> {
    let assertion = authenticate_client_with_dependencies(
        service,
        config,
        request,
        client,
        credentials,
        ClientAuthenticationContext::AllowPublicNone,
    )
    .await?;
    consume_token_management_client_assertion_with_authorization_service(
        service,
        client,
        assertion.as_ref(),
    )
    .await
}

#[cfg(test)]
pub(crate) async fn verify_confidential_client(
    state: &TestAppState,
    request: &ClientAuthRequestFacts,
    client: &ClientRow,
    credentials: &ClientCredentials,
) -> Result<Option<ValidatedClientAssertion>, TokenManagementClientAuthError> {
    let connection = state.valkey_connection();
    let service = crate::http::authorization::ServerAuthorizationService::new(
        nazo_postgres::AuthorizationFlowRepository::new(
            state.diesel_db.clone(),
            crate::domain::tenancy::DEFAULT_TENANT_ID,
        ),
        nazo_valkey::AuthorizationStateAdapter::new(&connection),
        state.keyset.clone(),
    );
    let result = authenticate_client_with_dependencies(
        &service,
        ClientAuthConfig::new(
            &state.settings.endpoint.issuer,
            &state.settings.protocol.client_secret_pepper,
        ),
        request,
        client,
        credentials,
        ClientAuthenticationContext::ConfidentialOnly,
    )
    .await;
    result.map_err(|error| match error {
        TokenManagementClientAuthError::PublicClientCredentialsForbidden => {
            TokenManagementClientAuthError::InvalidClient
        }
        other => other,
    })
}

#[cfg(test)]
fn revocation_public_client_allows_credentials(credentials: &ClientCredentials) -> bool {
    credentials.method == "none"
        && credentials.client_secret.is_none()
        && credentials.client_assertion.is_none()
}

pub(crate) async fn authenticate_client_with_dependencies(
    service: &crate::http::authorization::ServerAuthorizationService,
    config: ClientAuthConfig<'_>,
    request: &ClientAuthRequestFacts,
    client: &ClientRow,
    credentials: &ClientCredentials,
    context: ClientAuthenticationContext,
) -> Result<Option<ValidatedClientAssertion>, TokenManagementClientAuthError> {
    let requirement =
        client_authentication_requirement(client, credentials, context).map_err(|error| {
            log_client_auth_rejection(request, client, credentials, "policy");
            match error {
                ClientAuthenticationPolicyError::InvalidClient => {
                    TokenManagementClientAuthError::InvalidClient
                }
                ClientAuthenticationPolicyError::PublicClientCredentialsForbidden => {
                    TokenManagementClientAuthError::PublicClientCredentialsForbidden
                }
            }
        })?;

    match requirement {
        ClientAuthenticationRequirement::PublicClient => Ok(None),
        ClientAuthenticationRequirement::PrivateKeyJwt { assertion } => {
            verify_private_key_jwt_claims_for_issuer(
                config.issuer,
                request.endpoint_path(),
                client,
                assertion,
            )
            .map(Some)
            .map_err(|error| {
                log_client_auth_rejection(
                    request,
                    client,
                    credentials,
                    client_assertion_error_reason(&error),
                );
                token_management_client_assertion_error(error)
            })
        }
        ClientAuthenticationRequirement::ClientSecret { secret, .. } => {
            let secret_match = match service.client_secret_salt(client.id).await {
                Ok(Some(salt)) => {
                    let candidate_digest =
                        client_secret_digest(secret, config.client_secret_pepper, &salt);
                    service
                        .client_secret_digest_matches(client.id, &candidate_digest)
                        .await
                }
                Ok(None) => {
                    perform_dummy_client_secret_verification(
                        credentials,
                        config.client_secret_pepper,
                    );
                    Ok(false)
                }
                Err(error) => Err(error),
            };
            if client_secret_auth_result(secret_match)? {
                Ok(None)
            } else {
                log_client_auth_rejection(request, client, credentials, "client_secret");
                Err(TokenManagementClientAuthError::InvalidClient)
            }
        }
        ClientAuthenticationRequirement::MutualTls { .. } => {
            let Some(certificate) = request.client_certificate.as_ref() else {
                log_client_auth_rejection(request, client, credentials, "missing_mtls_certificate");
                return Err(TokenManagementClientAuthError::InvalidClient);
            };
            if client_mtls_certificate_matches(client, certificate) {
                Ok(None)
            } else {
                log_client_auth_rejection(request, client, credentials, "mtls_certificate");
                Err(TokenManagementClientAuthError::InvalidClient)
            }
        }
    }
}

fn client_secret_auth_result<E: std::fmt::Display>(
    result: Result<bool, E>,
) -> Result<bool, TokenManagementClientAuthError> {
    result.map_err(|error| {
        tracing::warn!(%error, "failed to verify management client secret");
        TokenManagementClientAuthError::StoreUnavailable
    })
}

fn client_assertion_error_reason(error: &ClientAssertionError) -> &'static str {
    match error {
        ClientAssertionError::Invalid => "client_assertion",
        ClientAssertionError::ReplayDetected => "client_assertion_replay",
        ClientAssertionError::StoreUnavailable => "client_assertion_store",
    }
}

fn log_client_auth_rejection(
    request: &ClientAuthRequestFacts,
    client: &ClientRow,
    credentials: &ClientCredentials,
    reason: &'static str,
) {
    tracing::warn!(
        target: "client_auth",
        "client_auth_rejected reason={} path={} client_id_hash={} expected_method={} presented_method={}",
        reason,
        request.endpoint_path(),
        blake3_hex(&client.client_id),
        client.token_endpoint_auth_method,
        credentials.method
    );
}

pub(crate) async fn consume_token_management_client_assertion_with_authorization_service(
    service: &crate::http::authorization::ServerAuthorizationService,
    client: &ClientRow,
    assertion: Option<&ValidatedClientAssertion>,
) -> Result<(), TokenManagementClientAuthError> {
    let Some(assertion) = assertion else {
        return Ok(());
    };
    crate::adapters::security::consume_private_key_jwt_with_authorization_service(
        service, client, assertion,
    )
    .await
    .map_err(token_management_client_assertion_error)
}

fn token_management_client_assertion_error(
    error: ClientAssertionError,
) -> TokenManagementClientAuthError {
    match error {
        ClientAssertionError::StoreUnavailable => TokenManagementClientAuthError::StoreUnavailable,
        ClientAssertionError::Invalid | ClientAssertionError::ReplayDetected => {
            TokenManagementClientAuthError::InvalidClient
        }
    }
}

pub(crate) async fn consume_token_client_assertion_with_authorization_service(
    service: &crate::http::authorization::ServerAuthorizationService,
    client: &ClientRow,
    assertion: Option<&ValidatedClientAssertion>,
) -> Result<(), TokenManagementClientAuthError> {
    let Some(assertion) = assertion else {
        return Ok(());
    };
    crate::adapters::security::consume_private_key_jwt_with_authorization_service(
        service, client, assertion,
    )
    .await
    .map_err(token_management_client_assertion_error)
}

#[cfg(test)]
pub(crate) async fn consume_token_client_assertion(
    state: &TestAppState,
    client: &ClientRow,
    assertion: Option<&ValidatedClientAssertion>,
) -> Result<(), TokenManagementClientAuthError> {
    let Some(assertion) = assertion else {
        return Ok(());
    };
    consume_private_key_jwt(state, client, assertion)
        .await
        .map_err(token_management_client_assertion_error)
}

#[cfg(test)]
#[path = "../../../tests/in_source/src/http/token/tests/client_auth.rs"]
mod tests;
