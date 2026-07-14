//! OAuth/OIDC 流程中的序列化载荷。
// 这些结构体会进入 JWT、Valkey 临时键或 token 签发逻辑，字段名需保持协议稳定。
use chrono::{DateTime, Utc};
use serde_json::Value;
use uuid::Uuid;

pub(crate) use nazo_auth::{
    AuthorizationCodeState, CodePayload, ConsentPayload, ConsumedAuthorizationCode,
    OidcClaimRequest, PushedAuthorizationRequest,
};

/// token 签发函数所需的归一化输入。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RefreshTokenPolicy {
    IssueNew,
    Rotate {
        family_id: Uuid,
        rotated_from_id: Uuid,
    },
    RotateLostResponse {
        family_id: Uuid,
        original_id: Uuid,
        successor_id: Uuid,
        retry_started_at: DateTime<Utc>,
    },
    PreserveExisting,
}

pub(crate) struct TokenIssue {
    pub(crate) user_id: Option<Uuid>,
    pub(crate) subject: String,
    pub(crate) scopes: Vec<String>,
    pub(crate) authorization_details: Value,
    pub(crate) audiences: Vec<String>,
    pub(crate) nonce: Option<String>,
    pub(crate) auth_time: Option<i64>,
    pub(crate) amr: Vec<String>,
    pub(crate) oidc_sid: Option<String>,
    pub(crate) acr: Option<String>,
    pub(crate) userinfo_claims: Vec<String>,
    pub(crate) userinfo_claim_requests: Vec<OidcClaimRequest>,
    pub(crate) id_token_claims: Vec<String>,
    pub(crate) id_token_claim_requests: Vec<OidcClaimRequest>,
    pub(crate) include_refresh: bool,
    pub(crate) refresh_token_policy: RefreshTokenPolicy,
    pub(crate) dpop_jkt: Option<String>,
    pub(crate) refresh_token_dpop_jkt: Option<String>,
    pub(crate) mtls_x5t_s256: Option<String>,
    pub(crate) refresh_token_mtls_x5t_s256: Option<String>,
    pub(crate) authorization_code_hash: Option<String>,
    pub(crate) actor: Option<Value>,
    pub(crate) issued_token_type: Option<String>,
    pub(crate) native_sso: Option<NativeSsoTokenBinding>,
}

#[derive(Clone, Debug)]
pub(crate) struct NativeSsoTokenBinding {
    pub(crate) device_secret: String,
    pub(crate) ds_hash: String,
    pub(crate) sid: String,
}

#[cfg(test)]
#[path = "../../tests/in_source/src/domain/oauth/tests/oauth.rs"]
mod tests;
