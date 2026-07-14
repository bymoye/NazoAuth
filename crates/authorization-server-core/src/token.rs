use chrono::{DateTime, Utc};
use serde_json::Value;
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq)]
pub struct RefreshToken {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub token_family_id: Uuid,
    pub client_id: Uuid,
    pub user_id: Option<Uuid>,
    pub scopes: Value,
    pub audience: Value,
    pub authorization_details: Value,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub subject: String,
    pub dpop_jkt: Option<String>,
    pub mtls_x5t_s256: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LostResponseRetry {
    pub original_id: Uuid,
    pub retry_started_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct NewRefreshToken {
    pub raw_token: String,
    pub tenant_id: Uuid,
    pub family_id: Uuid,
    pub rotated_from_id: Option<Uuid>,
    pub lost_response_retry: Option<LostResponseRetry>,
    pub client_id: Uuid,
    pub user_id: Option<Uuid>,
    pub scopes: Vec<String>,
    pub audiences: Vec<String>,
    pub authorization_details: Value,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub subject: String,
    pub dpop_jkt: Option<String>,
    pub mtls_x5t_s256: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RefreshTokenPersistResult {
    Inserted,
    RotationConflict,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackchannelLogoutDelivery {
    pub id: Uuid,
    pub logout_uri: String,
    pub logout_token: String,
    pub attempts: i32,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingBackchannelLogoutDelivery {
    pub tenant_id: Uuid,
    pub client_id: Uuid,
    pub client_public_id: String,
    pub logout_uri: String,
    pub logout_token: String,
    pub expires_at: DateTime<Utc>,
}
