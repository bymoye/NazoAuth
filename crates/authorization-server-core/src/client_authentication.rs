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
mod tests {
    use super::*;
    use crate::ValidatedClientRegistration;
    use serde_json::json;
    use uuid::Uuid;

    fn client(client_type: &str, method: &str) -> OAuthClient {
        OAuthClient {
            id: Uuid::now_v7(),
            tenant_id: Uuid::nil(),
            realm_id: Uuid::nil(),
            organization_id: Uuid::nil(),
            registration: ValidatedClientRegistration {
                client_id: "client-1".to_owned(),
                client_name: "Client".to_owned(),
                client_type: client_type.to_owned(),
                redirect_uris: Vec::new(),
                post_logout_redirect_uris: Vec::new(),
                scopes: Vec::new(),
                allowed_audiences: Vec::new(),
                grant_types: Vec::new(),
                token_endpoint_auth_method: method.to_owned(),
                subject_type: "public".to_owned(),
                sector_identifier_uri: None,
                sector_identifier_host: None,
                require_dpop_bound_tokens: false,
                allow_client_assertion_audience_array: false,
                allow_client_assertion_endpoint_audience: false,
                require_par_request_object: false,
                allow_authorization_code_without_pkce: false,
                backchannel_logout_uri: None,
                backchannel_logout_session_required: false,
                frontchannel_logout_uri: None,
                frontchannel_logout_session_required: false,
                tls_client_auth_subject_dn: None,
                tls_client_auth_cert_sha256: None,
                tls_client_auth_san_dns: Vec::new(),
                tls_client_auth_san_uri: Vec::new(),
                tls_client_auth_san_ip: Vec::new(),
                tls_client_auth_san_email: Vec::new(),
                jwks: Some(json!({"keys": []})),
                introspection_encrypted_response_alg: None,
                introspection_encrypted_response_enc: None,
                userinfo_signed_response_alg: None,
                userinfo_encrypted_response_alg: None,
                userinfo_encrypted_response_enc: None,
                authorization_signed_response_alg: None,
                authorization_encrypted_response_alg: None,
                authorization_encrypted_response_enc: None,
            },
            require_mtls_bound_tokens: false,
            is_active: true,
        }
    }

    #[test]
    fn fixed_methods_require_exact_material() {
        let secret = PresentedClientCredentials {
            client_id: Some("client-1".to_owned()),
            client_secret: Some("secret".to_owned()),
            method: "client_secret_basic".to_owned(),
            ..Default::default()
        };
        assert!(matches!(
            client_authentication_requirement(
                &client("confidential", "client_secret_basic"),
                &secret,
                ClientAuthenticationContext::ConfidentialOnly,
            ),
            Ok(ClientAuthenticationRequirement::ClientSecret {
                method: ClientAuthenticationMethod::ClientSecretBasic,
                secret: "secret",
            })
        ));

        let missing_assertion = PresentedClientCredentials {
            client_id: Some("client-1".to_owned()),
            method: "private_key_jwt".to_owned(),
            ..Default::default()
        };
        assert_eq!(
            client_authentication_requirement(
                &client("confidential", "private_key_jwt"),
                &missing_assertion,
                ClientAuthenticationContext::ConfidentialOnly,
            ),
            Err(ClientAuthenticationPolicyError::InvalidClient)
        );
    }

    #[test]
    fn public_none_is_explicit_and_rejects_hidden_credentials() {
        let none = PresentedClientCredentials {
            client_id: Some("client-1".to_owned()),
            method: "none".to_owned(),
            ..Default::default()
        };
        assert_eq!(
            client_authentication_requirement(
                &client("public", "none"),
                &none,
                ClientAuthenticationContext::AllowPublicNone,
            ),
            Ok(ClientAuthenticationRequirement::PublicClient)
        );

        let hidden_secret = PresentedClientCredentials {
            client_secret: Some("secret".to_owned()),
            ..none
        };
        assert_eq!(
            client_authentication_requirement(
                &client("public", "none"),
                &hidden_secret,
                ClientAuthenticationContext::AllowPublicNone,
            ),
            Err(ClientAuthenticationPolicyError::PublicClientCredentialsForbidden)
        );
    }

    #[test]
    fn all_builtin_methods_are_fixed_and_unknown_methods_fail_closed() {
        for (raw, expected) in [
            ("none", ClientAuthenticationMethod::None),
            (
                "client_secret_basic",
                ClientAuthenticationMethod::ClientSecretBasic,
            ),
            (
                "client_secret_post",
                ClientAuthenticationMethod::ClientSecretPost,
            ),
            ("private_key_jwt", ClientAuthenticationMethod::PrivateKeyJwt),
            ("tls_client_auth", ClientAuthenticationMethod::TlsClientAuth),
            (
                "self_signed_tls_client_auth",
                ClientAuthenticationMethod::SelfSignedTlsClientAuth,
            ),
        ] {
            assert_eq!(ClientAuthenticationMethod::try_from(raw), Ok(expected));
            assert_eq!(expected.as_str(), raw);
        }
        assert_eq!(
            ClientAuthenticationMethod::try_from("future_auth_method"),
            Err(ClientAuthenticationPolicyError::InvalidClient)
        );
    }

    #[test]
    fn presented_credentials_debug_output_redacts_secret_material() {
        let credentials = PresentedClientCredentials {
            client_id: Some("client-1".to_owned()),
            client_secret: Some("never-log-this-secret".to_owned()),
            client_assertion: Some("never-log-this-assertion".to_owned()),
            method: "private_key_jwt".to_owned(),
        };
        let debug = format!("{credentials:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("never-log-this-secret"));
        assert!(!debug.contains("never-log-this-assertion"));
    }

    #[test]
    fn method_mismatch_and_credential_smuggling_fail_before_adapter_execution() {
        let mismatch = PresentedClientCredentials {
            client_id: Some("client-1".to_owned()),
            client_secret: Some("secret".to_owned()),
            method: "client_secret_post".to_owned(),
            ..Default::default()
        };
        assert_eq!(
            client_authentication_requirement(
                &client("confidential", "client_secret_basic"),
                &mismatch,
                ClientAuthenticationContext::ConfidentialOnly,
            ),
            Err(ClientAuthenticationPolicyError::InvalidClient)
        );

        let smuggled = PresentedClientCredentials {
            client_id: Some("client-1".to_owned()),
            client_secret: Some("secret".to_owned()),
            client_assertion: Some("assertion".to_owned()),
            method: "client_secret_basic".to_owned(),
        };
        assert_eq!(
            client_authentication_requirement(
                &client("confidential", "client_secret_basic"),
                &smuggled,
                ClientAuthenticationContext::ConfidentialOnly,
            ),
            Err(ClientAuthenticationPolicyError::InvalidClient)
        );
    }

    #[test]
    fn transport_mtls_presentation_preserves_the_registered_self_signed_policy() {
        let transport_credentials = PresentedClientCredentials {
            client_id: Some("client-1".to_owned()),
            method: "tls_client_auth".to_owned(),
            ..Default::default()
        };
        assert_eq!(
            client_authentication_requirement(
                &client("confidential", "self_signed_tls_client_auth"),
                &transport_credentials,
                ClientAuthenticationContext::ConfidentialOnly,
            ),
            Ok(ClientAuthenticationRequirement::MutualTls {
                method: ClientAuthenticationMethod::SelfSignedTlsClientAuth,
            })
        );
    }

    #[test]
    fn credential_client_id_must_match_the_resolved_tenant_scoped_client() {
        let credentials = PresentedClientCredentials {
            client_id: Some("other-client".to_owned()),
            client_secret: Some("secret".to_owned()),
            method: "client_secret_basic".to_owned(),
            ..Default::default()
        };
        assert_eq!(
            client_authentication_requirement(
                &client("confidential", "client_secret_basic"),
                &credentials,
                ClientAuthenticationContext::ConfidentialOnly,
            ),
            Err(ClientAuthenticationPolicyError::InvalidClient)
        );
    }
}
