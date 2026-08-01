//! token 管理端点复用的客户端认证。
use crate::adapters::security::ClientAssertionError;
use crate::adapters::security::ClientCredentials;
use crate::adapters::security::ValidatedClientAssertion;
use crate::adapters::security::blake3_hex;
use crate::adapters::security::client_secret_digest;
use crate::adapters::security::verify_private_key_jwt_claims_for_issuer;
use crate::domain::ClientRow;

use crate::http::mtls::MtlsClientCertificate;
use crate::http::mtls::client_mtls_certificate_matches;

use nazo_auth::{
    ClientAuthenticationContext, ClientAuthenticationPolicyError, ClientAuthenticationRequirement,
    client_authentication_requirement,
};

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
    remote_jwks: Option<&'a crate::domain::remote_client_documents::RemoteClientDocumentResolver>,
}

impl<'a> ClientAuthConfig<'a> {
    pub(crate) fn new(issuer: &'a str, client_secret_pepper: &'a str) -> Self {
        Self {
            issuer,
            client_secret_pepper,
            remote_jwks: None,
        }
    }

    pub(crate) fn with_remote_jwks(
        mut self,
        resolver: &'a crate::domain::remote_client_documents::RemoteClientDocumentResolver,
    ) -> Self {
        self.remote_jwks = Some(resolver);
        self
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
            let resolved_client;
            let verification_client = if let (Some(uri), Some(resolver)) =
                (client.jwks_uri.as_deref(), config.remote_jwks)
            {
                let jwks = resolver.jwks(uri).await.map_err(|error| {
                    tracing::warn!(%error, "dynamic client jwks_uri could not be refreshed");
                    TokenManagementClientAuthError::InvalidClient
                })?;
                resolved_client = {
                    let mut client = client.clone();
                    client.jwks = Some(jwks);
                    client
                };
                &resolved_client
            } else {
                client
            };
            verify_private_key_jwt_claims_for_issuer(
                config.issuer,
                request.endpoint_path(),
                verification_client,
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
#[path = "../../../tests/unit/http/token/client_auth.rs"]
mod tests;
