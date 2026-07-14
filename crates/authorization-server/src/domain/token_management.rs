use std::{future::Future, pin::Pin, sync::Arc};

use chrono::Utc;
use nazo_auth::{
    CLIENT_ASSERTION_TYPE_JWT_BEARER, ClientAuthenticationContext, IntrospectionSignInput,
    OAuthClient, unverified_client_assertion_client_id,
};
use nazo_http_actix::{
    TokenClientAuthTransportFacts, TokenIntrospectionRepresentation, TokenManagementError,
    TokenManagementFuture, TokenManagementOperations, TokenManagementRateLimitError,
    TokenManagementRequestFacts, TokenManagementRequestGuard, TokenOnlyForm,
};
use serde_json::json;

use crate::{
    adapters::{
        audit::{audit_event, audit_fields},
        security::blake3_hex,
    },
    domain::client_jwe::{JwePayloadKind, client_jwe_key, encrypt_compact_jwe},
    http::{
        authorization::{AuthorizationHttpConfig, ServerAuthorizationService},
        token::{
            ServerTokenService,
            client_auth::{
                ClientAuthConfig, ClientAuthRequestFacts, TokenManagementClientAuthError,
                authenticate_introspection_client_with_dependencies,
                authenticate_revocation_client_with_dependencies,
                perform_dummy_client_secret_verification,
            },
        },
    },
};

#[derive(Clone)]
pub(crate) struct ServerTokenManagementRequestGuard {
    token_service: Arc<ServerTokenService>,
    config: Arc<AuthorizationHttpConfig>,
}

impl ServerTokenManagementRequestGuard {
    pub(crate) fn new(
        token_service: Arc<ServerTokenService>,
        config: Arc<AuthorizationHttpConfig>,
    ) -> Self {
        Self {
            token_service,
            config,
        }
    }
}

impl TokenManagementRequestGuard for ServerTokenManagementRequestGuard {
    fn enforce<'a>(
        &'a self,
        request: &'a TokenManagementRequestFacts,
    ) -> Pin<Box<dyn Future<Output = Result<(), TokenManagementRateLimitError>> + Send + 'a>> {
        let subject = request.source_ip.clone();
        Box::pin(async move {
            let count = self
                .token_service
                .increment_token_management_rate(&subject, self.config.rate_limit_window_seconds)
                .await
                .map_err(|error| {
                    tracing::warn!(%error, "token management rate limit increment failed");
                    TokenManagementRateLimitError::Unavailable
                })?;
            if count > self.config.token_management_max_requests {
                return Err(TokenManagementRateLimitError::Limited {
                    retry_after_seconds: self.config.rate_limit_window_seconds,
                });
            }
            Ok(())
        })
    }
}

#[derive(Clone)]
pub(crate) struct ServerTokenManagementOperations {
    token_service: Arc<ServerTokenService>,
    authorization_service: Arc<ServerAuthorizationService>,
    config: Arc<AuthorizationHttpConfig>,
}

impl ServerTokenManagementOperations {
    pub(crate) fn new(
        token_service: Arc<ServerTokenService>,
        authorization_service: Arc<ServerAuthorizationService>,
        config: Arc<AuthorizationHttpConfig>,
    ) -> Self {
        Self {
            token_service,
            authorization_service,
            config,
        }
    }

    async fn authenticate(
        &self,
        request: &TokenManagementRequestFacts,
        client_auth: &TokenClientAuthTransportFacts,
        form: &TokenOnlyForm,
        context: ClientAuthenticationContext,
    ) -> Result<OAuthClient, TokenManagementError> {
        let has_basic = client_auth.basic_challenge();
        let presentation = client_auth.presentation();
        let assertion_client_id = client_auth
            .client_assertion()
            .filter(|_| {
                client_auth.client_assertion_type() == Some(CLIENT_ASSERTION_TYPE_JWT_BEARER)
            })
            .and_then(unverified_client_assertion_client_id);
        let mtls_client_id = if !presentation.http_basic
            && !presentation.client_assertion_type
            && !presentation.client_assertion
            && !presentation.form_client_secret
            && request.client_certificate.is_some()
        {
            form.client_id.clone()
        } else {
            None
        };
        let credentials = client_auth.presented_credentials(assertion_client_id, mtls_client_id);
        let Some(client_id) = credentials.client_id.as_deref() else {
            return Err(TokenManagementError::InvalidClient {
                basic_challenge: has_basic,
            });
        };
        let client = match self.authorization_service.client_by_id(client_id).await {
            Ok(Some(client)) => client,
            Ok(None) => {
                perform_dummy_client_secret_verification(
                    &credentials,
                    &self.config.client_secret_pepper,
                );
                return Err(TokenManagementError::InvalidClient {
                    basic_challenge: has_basic,
                });
            }
            Err(error) => {
                tracing::warn!(%error, "failed to query oauth token-management client");
                return Err(TokenManagementError::ClientLookupUnavailable);
            }
        };
        let config = ClientAuthConfig::new(&self.config.issuer, &self.config.client_secret_pepper);
        let auth_request =
            ClientAuthRequestFacts::new(&request.endpoint_path, request.client_certificate.clone());
        let result = match context {
            ClientAuthenticationContext::ConfidentialOnly => {
                authenticate_introspection_client_with_dependencies(
                    &self.authorization_service,
                    config,
                    &auth_request,
                    &client,
                    &credentials,
                )
                .await
            }
            ClientAuthenticationContext::AllowPublicNone => {
                authenticate_revocation_client_with_dependencies(
                    &self.authorization_service,
                    config,
                    &auth_request,
                    &client,
                    &credentials,
                )
                .await
            }
        };
        result.map_err(|error| map_auth_error(error, has_basic))?;
        Ok(client)
    }

    async fn protected_introspection(
        &self,
        client: &OAuthClient,
        inspection: &nazo_auth::TokenInspection,
    ) -> Result<String, TokenManagementError> {
        let body = inspection.clone().into_document();
        let token = self
            .token_service
            .sign_introspection_response(IntrospectionSignInput {
                issuer: &self.config.issuer,
                audience: &client.client_id,
                body: &body,
            })
            .await
            .map_err(|error| {
                tracing::warn!(%error, "failed to sign token introspection response");
                TokenManagementError::ResponseProtectionFailed
            })?;
        let key = client_jwe_key(
            client.jwks.as_ref(),
            client.introspection_encrypted_response_alg.as_deref(),
            client.introspection_encrypted_response_enc.as_deref(),
            "introspection",
        )
        .map_err(|error| {
            tracing::warn!(%error, "failed to resolve introspection encryption key");
            TokenManagementError::ResponseProtectionFailed
        })?;
        match key {
            Some(key) => encrypt_compact_jwe(&key, token.as_bytes(), JwePayloadKind::NestedJwt)
                .map_err(|error| {
                    tracing::warn!(%error, "failed to encrypt introspection response");
                    TokenManagementError::ResponseProtectionFailed
                }),
            None => Ok(token),
        }
    }
}

impl TokenManagementOperations for ServerTokenManagementOperations {
    fn introspect<'a>(
        &'a self,
        request: TokenManagementRequestFacts,
        client_auth: TokenClientAuthTransportFacts,
        form: TokenOnlyForm,
        signed_response_requested: bool,
    ) -> TokenManagementFuture<'a, TokenIntrospectionRepresentation> {
        Box::pin(async move {
            let client = self
                .authenticate(
                    &request,
                    &client_auth,
                    &form,
                    ClientAuthenticationContext::ConfidentialOnly,
                )
                .await?;
            let inspection = self
                .token_service
                .inspect_token(&self.config.issuer, &form.token, &client, Utc::now())
                .await
                .map_err(|error| {
                    tracing::warn!(%error, "failed to inspect token state");
                    TokenManagementError::InspectionUnavailable
                })?;
            if signed_response_requested && self.config.profile.requires_signed_introspection() {
                return self
                    .protected_introspection(&client, &inspection)
                    .await
                    .map(TokenIntrospectionRepresentation::Jwt);
            }
            Ok(TokenIntrospectionRepresentation::Inspection(inspection))
        })
    }

    fn revoke<'a>(
        &'a self,
        request: TokenManagementRequestFacts,
        client_auth: TokenClientAuthTransportFacts,
        form: TokenOnlyForm,
    ) -> TokenManagementFuture<'a, ()> {
        Box::pin(async move {
            let client = self
                .authenticate(
                    &request,
                    &client_auth,
                    &form,
                    ClientAuthenticationContext::AllowPublicNone,
                )
                .await?;
            let updated = self
                .token_service
                .revoke_token(&self.config.issuer, &form.token, &client)
                .await
                .map_err(|error| {
                    tracing::warn!(%error, "failed to revoke token");
                    TokenManagementError::RevocationUnavailable
                })?;
            audit_event(
                "token_revoked",
                audit_fields(&[
                    ("client_id", json!(client.client_id)),
                    ("token_hash", json!(blake3_hex(&form.token))),
                    ("updated", json!(updated)),
                    ("source_ip_hash", json!(blake3_hex(&request.source_ip))),
                ]),
            );
            Ok(())
        })
    }
}

fn map_auth_error(
    error: TokenManagementClientAuthError,
    basic_challenge: bool,
) -> TokenManagementError {
    match error {
        TokenManagementClientAuthError::InvalidClient
        | TokenManagementClientAuthError::PublicClientCredentialsForbidden => {
            TokenManagementError::InvalidClient { basic_challenge }
        }
        TokenManagementClientAuthError::StoreUnavailable => {
            TokenManagementError::AuthenticationStoreUnavailable
        }
    }
}
