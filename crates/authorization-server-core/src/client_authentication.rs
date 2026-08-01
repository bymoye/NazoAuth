use crate::OAuthClient;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientAuthenticationMethod {
    None,
    ClientSecretBasic,
    ClientSecretPost,
    PrivateKeyJwt,
    TlsClientAuth,
    SelfSignedTlsClientAuth,
}

impl ClientAuthenticationMethod {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::ClientSecretBasic => "client_secret_basic",
            Self::ClientSecretPost => "client_secret_post",
            Self::PrivateKeyJwt => "private_key_jwt",
            Self::TlsClientAuth => "tls_client_auth",
            Self::SelfSignedTlsClientAuth => "self_signed_tls_client_auth",
        }
    }
}

impl TryFrom<&str> for ClientAuthenticationMethod {
    type Error = ClientAuthenticationPolicyError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "none" => Ok(Self::None),
            "client_secret_basic" => Ok(Self::ClientSecretBasic),
            "client_secret_post" => Ok(Self::ClientSecretPost),
            "private_key_jwt" => Ok(Self::PrivateKeyJwt),
            "tls_client_auth" => Ok(Self::TlsClientAuth),
            "self_signed_tls_client_auth" => Ok(Self::SelfSignedTlsClientAuth),
            _ => Err(ClientAuthenticationPolicyError::InvalidClient),
        }
    }
}

#[derive(Clone, Default)]
pub struct PresentedClientCredentials {
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub client_assertion: Option<String>,
    pub method: String,
}

impl std::fmt::Debug for PresentedClientCredentials {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PresentedClientCredentials")
            .field("client_id", &self.client_id)
            .field(
                "client_secret",
                &self.client_secret.as_ref().map(|_| "[REDACTED]"),
            )
            .field(
                "client_assertion",
                &self.client_assertion.as_ref().map(|_| "[REDACTED]"),
            )
            .field("method", &self.method)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientAuthenticationContext {
    ConfidentialOnly,
    AllowPublicNone,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientAuthenticationPolicyError {
    InvalidClient,
    PublicClientCredentialsForbidden,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientAuthenticationRequirement<'a> {
    PublicClient,
    ClientSecret {
        method: ClientAuthenticationMethod,
        secret: &'a str,
    },
    PrivateKeyJwt {
        assertion: &'a str,
    },
    MutualTls {
        method: ClientAuthenticationMethod,
    },
}

/// Select the single built-in authentication operation after validating the complete credential
/// shape. Cryptographic and storage adapters execute only the returned operation.
pub fn client_authentication_requirement<'a>(
    client: &OAuthClient,
    credentials: &'a PresentedClientCredentials,
    context: ClientAuthenticationContext,
) -> Result<ClientAuthenticationRequirement<'a>, ClientAuthenticationPolicyError> {
    if credentials.client_id.as_deref() != Some(client.client_id.as_str()) {
        return Err(ClientAuthenticationPolicyError::InvalidClient);
    }
    let presented_method = ClientAuthenticationMethod::try_from(credentials.method.as_str())?;

    match client.client_type.as_str() {
        "public" => {
            if client.token_endpoint_auth_method != "none" {
                return Err(ClientAuthenticationPolicyError::InvalidClient);
            }
            if context == ClientAuthenticationContext::AllowPublicNone
                && presented_method == ClientAuthenticationMethod::None
                && credentials.client_secret.is_none()
                && credentials.client_assertion.is_none()
            {
                return Ok(ClientAuthenticationRequirement::PublicClient);
            }
            return Err(ClientAuthenticationPolicyError::PublicClientCredentialsForbidden);
        }
        "confidential" => {}
        _ => return Err(ClientAuthenticationPolicyError::InvalidClient),
    }

    let registered_method =
        ClientAuthenticationMethod::try_from(client.token_endpoint_auth_method.as_str())?;
    // The trusted HTTP adapter can prove possession of a certificate, but the registered client
    // policy determines whether that certificate is PKI-bound or self-signed/JWKS-bound.
    let transport_method_matches = registered_method == presented_method
        || matches!(
            (registered_method, presented_method),
            (
                ClientAuthenticationMethod::SelfSignedTlsClientAuth,
                ClientAuthenticationMethod::TlsClientAuth
            )
        );
    if !transport_method_matches {
        return Err(ClientAuthenticationPolicyError::InvalidClient);
    }

    match registered_method {
        ClientAuthenticationMethod::ClientSecretBasic
        | ClientAuthenticationMethod::ClientSecretPost => {
            let secret = credentials
                .client_secret
                .as_deref()
                .filter(|secret| !secret.is_empty())
                .ok_or(ClientAuthenticationPolicyError::InvalidClient)?;
            if credentials.client_assertion.is_some() {
                return Err(ClientAuthenticationPolicyError::InvalidClient);
            }
            Ok(ClientAuthenticationRequirement::ClientSecret {
                method: registered_method,
                secret,
            })
        }
        ClientAuthenticationMethod::PrivateKeyJwt => {
            let assertion = credentials
                .client_assertion
                .as_deref()
                .filter(|assertion| !assertion.is_empty())
                .ok_or(ClientAuthenticationPolicyError::InvalidClient)?;
            if credentials.client_secret.is_some() {
                return Err(ClientAuthenticationPolicyError::InvalidClient);
            }
            Ok(ClientAuthenticationRequirement::PrivateKeyJwt { assertion })
        }
        ClientAuthenticationMethod::TlsClientAuth
        | ClientAuthenticationMethod::SelfSignedTlsClientAuth => {
            if credentials.client_secret.is_some() || credentials.client_assertion.is_some() {
                return Err(ClientAuthenticationPolicyError::InvalidClient);
            }
            Ok(ClientAuthenticationRequirement::MutualTls {
                method: registered_method,
            })
        }
        ClientAuthenticationMethod::None => Err(ClientAuthenticationPolicyError::InvalidClient),
    }
}

#[cfg(test)]
#[path = "../tests/unit/client_authentication.rs"]
mod tests;
