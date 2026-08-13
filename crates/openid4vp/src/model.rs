use chrono::{DateTime, Utc};
use nazo_digital_credentials::{DcqlQuery, VerifiedCredential};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::VP_TOKEN_RESPONSE_TYPE;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientIdPrefix {
    RedirectUri,
    X509SanDns,
    X509Hash,
}

impl ClientIdPrefix {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RedirectUri => "redirect_uri",
            Self::X509SanDns => "x509_san_dns",
            Self::X509Hash => "x509_hash",
        }
    }
}

impl std::str::FromStr for ClientIdPrefix {
    type Err = PresentationError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "redirect_uri" => Ok(Self::RedirectUri),
            "x509_san_dns" => Ok(Self::X509SanDns),
            "x509_hash" => Ok(Self::X509Hash),
            _ => Err(PresentationError::InvalidRequest),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseMode {
    DirectPost,
    #[serde(rename = "direct_post.jwt")]
    DirectPostJwt,
}

impl ResponseMode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DirectPost => "direct_post",
            Self::DirectPostJwt => "direct_post.jwt",
        }
    }
}

impl std::str::FromStr for ResponseMode {
    type Err = PresentationError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "direct_post" => Ok(Self::DirectPost),
            "direct_post.jwt" => Ok(Self::DirectPostJwt),
            _ => Err(PresentationError::InvalidRequest),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestMethod {
    UrlQuery,
    RequestUriSignedGet,
    RequestUriSignedPost,
}

impl RequestMethod {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UrlQuery => "url_query",
            Self::RequestUriSignedGet => "request_uri_signed_get",
            Self::RequestUriSignedPost => "request_uri_signed_post",
        }
    }
}

impl std::str::FromStr for RequestMethod {
    type Err = PresentationError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "url_query" => Ok(Self::UrlQuery),
            "request_uri_signed_get" => Ok(Self::RequestUriSignedGet),
            "request_uri_signed_post" => Ok(Self::RequestUriSignedPost),
            _ => Err(PresentationError::InvalidRequest),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientMetadata {
    pub vp_formats_supported: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwks: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypted_response_enc_values_supported: Option<Vec<String>>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifierInfo {
    pub format: String,
    pub data: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_ids: Option<Vec<String>>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransactionData {
    #[serde(rename = "type")]
    pub transaction_type: String,
    pub credential_ids: Vec<String>,
    pub transaction_data_hashes_alg: Vec<String>,
    #[serde(flatten)]
    pub claims: serde_json::Map<String, Value>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AuthorizationRequest {
    pub client_id: String,
    pub response_type: String,
    pub response_mode: String,
    pub response_uri: String,
    pub nonce: String,
    pub state: String,
    pub dcql_query: DcqlQuery,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_metadata: Option<ClientMetadata>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verifier_info: Option<Vec<VerifierInfo>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transaction_data: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wallet_nonce: Option<String>,
}

impl AuthorizationRequest {
    pub fn validate(&self) -> Result<(), PresentationError> {
        if self.response_type != VP_TOKEN_RESPONSE_TYPE
            || self.nonce.is_empty()
            || self.state.is_empty()
            // The verifier does not yet parse the holder-binding proof's
            // transaction_data_hashes. Accepting transaction_data here would
            // let a wallet present a proof that is not bound to the requested
            // transaction, so fail closed until that verifier path exists.
            || self.transaction_data.is_some()
            || !matches!(
                self.response_mode.as_str(),
                "direct_post" | "direct_post.jwt"
            )
        {
            return Err(PresentationError::InvalidRequest);
        }
        self.dcql_query
            .validate()
            .map_err(|_| PresentationError::InvalidDcql)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AuthorizationResponse {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vp_token: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectPostJwtResponse {
    pub response: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PresentationTransaction {
    pub id: Uuid,
    pub client_id_prefix: ClientIdPrefix,
    pub request_method: RequestMethod,
    pub response_mode: ResponseMode,
    pub wallet_authorization_endpoint: String,
    pub request: AuthorizationRequest,
    pub request_object: Option<String>,
    pub request_uri: Option<String>,
    #[serde(skip)]
    pub conformance_lease_id: Option<Uuid>,
    #[serde(skip)]
    pub response_encryption_private_key: Option<Vec<u8>>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PresentationResult {
    pub transaction_id: Uuid,
    pub credentials: Vec<VerifiedCredential>,
    pub completed_at: DateTime<Utc>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PresentationError {
    #[error("presentation request is invalid")]
    InvalidRequest,
    #[error("DCQL query is invalid")]
    InvalidDcql,
    #[error("presentation response state is invalid")]
    InvalidState,
    #[error("presentation response is malformed")]
    InvalidResponse,
    #[error("presentation credential does not satisfy DCQL")]
    DcqlUnsatisfied,
    #[error("presentation transaction is expired or already consumed")]
    InvalidTransaction,
    #[error("presentation is not trusted")]
    UntrustedPresentation,
}
