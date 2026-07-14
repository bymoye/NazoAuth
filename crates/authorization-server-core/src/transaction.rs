use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::{OidcClaimRequest, deserialize_authorization_details, empty_authorization_details};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ConsentPayload {
    pub request_id: String,
    pub user_id: Uuid,
    pub client_id: String,
    pub client_name: String,
    pub redirect_uri: String,
    pub redirect_uri_was_supplied: bool,
    pub scopes: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resource_indicators: Vec<String>,
    #[serde(
        default = "empty_authorization_details",
        deserialize_with = "deserialize_authorization_details"
    )]
    pub authorization_details: Value,
    pub state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_mode: Option<String>,
    pub nonce: Option<String>,
    pub auth_time: i64,
    pub amr: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oidc_sid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acr: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub userinfo_claims: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub userinfo_claim_requests: Vec<OidcClaimRequest>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub id_token_claims: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub id_token_claim_requests: Vec<OidcClaimRequest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code_challenge: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code_challenge_method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dpop_jkt: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtls_x5t_s256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pushed_request_uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pushed_request_digest: Option<String>,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PushedAuthorizationRequest {
    pub client_id: String,
    pub params: HashMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dpop_jkt: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtls_x5t_s256: Option<String>,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CodePayload {
    pub code_id: String,
    pub user_id: Uuid,
    pub client_id: String,
    pub redirect_uri: String,
    pub redirect_uri_was_supplied: bool,
    pub scopes: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resource_indicators: Vec<String>,
    #[serde(
        default = "empty_authorization_details",
        deserialize_with = "deserialize_authorization_details"
    )]
    pub authorization_details: Value,
    pub nonce: Option<String>,
    pub auth_time: i64,
    pub amr: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oidc_sid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acr: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub userinfo_claims: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub userinfo_claim_requests: Vec<OidcClaimRequest>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub id_token_claims: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub id_token_claim_requests: Vec<OidcClaimRequest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code_challenge: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code_challenge_method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dpop_jkt: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtls_x5t_s256: Option<String>,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum AuthorizationCodeState {
    Pending {
        payload: CodePayload,
    },
    Consuming {
        payload: CodePayload,
        consuming_at: DateTime<Utc>,
    },
    Consumed {
        marker: ConsumedAuthorizationCode,
    },
    Failed {
        failed_at: DateTime<Utc>,
        error: String,
    },
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ConsumedAuthorizationCode {
    pub client_id: Uuid,
    pub access_token_jti: String,
    pub access_token_expires_at: i64,
    pub refresh_token_family_id: Option<Uuid>,
    pub consumed_at: DateTime<Utc>,
}
