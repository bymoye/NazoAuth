//! Diesel 查询结果行模型。
// Row 结构体只描述数据库投影，不承载 handler 业务流程。
use chrono::{DateTime, Utc};
use diesel::{Queryable, QueryableByName, Selectable};
use serde::Serialize;
use serde_json::Value;
use uuid::Uuid;

/// users 表完整用户行。
#[derive(Debug, Queryable, QueryableByName, Selectable, Serialize, Clone)]
#[diesel(table_name = crate::schema::users)]
pub(crate) struct UserRow {
    #[diesel(sql_type = diesel::sql_types::Uuid)]
    pub(crate) id: Uuid,
    #[diesel(sql_type = diesel::sql_types::Uuid)]
    pub(crate) tenant_id: Uuid,
    #[diesel(sql_type = diesel::sql_types::Uuid)]
    pub(crate) realm_id: Uuid,
    #[diesel(sql_type = diesel::sql_types::Uuid)]
    pub(crate) organization_id: Uuid,
    #[diesel(sql_type = diesel::sql_types::VarChar)]
    pub(crate) username: String,
    #[diesel(sql_type = diesel::sql_types::VarChar)]
    pub(crate) email: String,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::VarChar>)]
    pub(crate) display_name: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::VarChar>)]
    pub(crate) avatar_url: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::VarChar>)]
    pub(crate) given_name: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::VarChar>)]
    pub(crate) family_name: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::VarChar>)]
    pub(crate) middle_name: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::VarChar>)]
    pub(crate) nickname: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::VarChar>)]
    pub(crate) profile_url: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::VarChar>)]
    pub(crate) website_url: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::VarChar>)]
    pub(crate) gender: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::VarChar>)]
    pub(crate) birthdate: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::VarChar>)]
    pub(crate) zoneinfo: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::VarChar>)]
    pub(crate) locale: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Text)]
    pub(crate) role: String,
    #[diesel(sql_type = diesel::sql_types::Int4)]
    pub(crate) admin_level: i32,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::VarChar>)]
    pub(crate) address_formatted: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::VarChar>)]
    pub(crate) address_street_address: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::VarChar>)]
    pub(crate) address_locality: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::VarChar>)]
    pub(crate) address_region: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::VarChar>)]
    pub(crate) address_postal_code: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::VarChar>)]
    pub(crate) address_country: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::VarChar>)]
    pub(crate) phone_number: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Bool)]
    pub(crate) phone_number_verified: bool,
    #[diesel(sql_type = diesel::sql_types::Bool)]
    pub(crate) email_verified: bool,
    #[diesel(sql_type = diesel::sql_types::Bool)]
    pub(crate) mfa_enabled: bool,
    #[diesel(sql_type = diesel::sql_types::VarChar)]
    pub(crate) password_hash: String,
    #[diesel(sql_type = diesel::sql_types::Bool)]
    pub(crate) is_active: bool,
    #[diesel(sql_type = diesel::sql_types::Timestamptz)]
    pub(crate) created_at: DateTime<Utc>,
    #[diesel(sql_type = diesel::sql_types::Timestamptz)]
    pub(crate) updated_at: DateTime<Utc>,
}

#[derive(Debug, Queryable, QueryableByName, Selectable, Serialize, Clone)]
#[diesel(table_name = crate::schema::user_passkey_credentials)]
pub(crate) struct PasskeyCredentialRow {
    #[diesel(sql_type = diesel::sql_types::Uuid)]
    pub(crate) id: Uuid,
    #[diesel(sql_type = diesel::sql_types::Uuid)]
    pub(crate) tenant_id: Uuid,
    #[diesel(sql_type = diesel::sql_types::Uuid)]
    pub(crate) user_id: Uuid,
    #[diesel(sql_type = diesel::sql_types::VarChar)]
    pub(crate) credential_id: String,
    #[diesel(sql_type = diesel::sql_types::Jsonb)]
    pub(crate) credential: Value,
    #[diesel(sql_type = diesel::sql_types::VarChar)]
    pub(crate) label: String,
    #[diesel(sql_type = diesel::sql_types::Int8)]
    pub(crate) sign_count: i64,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Timestamptz>)]
    pub(crate) last_used_at: Option<DateTime<Utc>>,
    #[diesel(sql_type = diesel::sql_types::Timestamptz)]
    pub(crate) created_at: DateTime<Utc>,
    #[diesel(sql_type = diesel::sql_types::Timestamptz)]
    pub(crate) updated_at: DateTime<Utc>,
}

#[derive(Debug, Queryable, QueryableByName, Selectable, Serialize, Clone)]
#[diesel(table_name = crate::schema::external_identity_links)]
pub(crate) struct ExternalIdentityLinkRow {
    #[diesel(sql_type = diesel::sql_types::Uuid)]
    pub(crate) id: Uuid,
    #[diesel(sql_type = diesel::sql_types::Uuid)]
    pub(crate) tenant_id: Uuid,
    #[diesel(sql_type = diesel::sql_types::Uuid)]
    pub(crate) user_id: Uuid,
    #[diesel(sql_type = diesel::sql_types::VarChar)]
    pub(crate) provider_type: String,
    #[diesel(sql_type = diesel::sql_types::VarChar)]
    pub(crate) provider_id: String,
    #[diesel(sql_type = diesel::sql_types::VarChar)]
    pub(crate) subject: String,
    #[diesel(sql_type = diesel::sql_types::VarChar)]
    pub(crate) email: String,
    #[diesel(sql_type = diesel::sql_types::Jsonb)]
    pub(crate) claims: Value,
    #[diesel(sql_type = diesel::sql_types::Timestamptz)]
    pub(crate) created_at: DateTime<Utc>,
    #[diesel(sql_type = diesel::sql_types::Timestamptz)]
    pub(crate) updated_at: DateTime<Utc>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Timestamptz>)]
    pub(crate) last_login_at: Option<DateTime<Utc>>,
}

/// oauth_clients 表完整客户端行。
#[derive(Debug, Queryable, QueryableByName, Selectable, Serialize, Clone)]
#[diesel(table_name = crate::schema::oauth_clients)]
pub(crate) struct ClientRow {
    #[diesel(sql_type = diesel::sql_types::Uuid)]
    pub(crate) id: Uuid,
    #[diesel(sql_type = diesel::sql_types::Uuid)]
    pub(crate) tenant_id: Uuid,
    #[diesel(sql_type = diesel::sql_types::Uuid)]
    pub(crate) realm_id: Uuid,
    #[diesel(sql_type = diesel::sql_types::Uuid)]
    pub(crate) organization_id: Uuid,
    #[diesel(sql_type = diesel::sql_types::VarChar)]
    pub(crate) client_id: String,
    #[diesel(sql_type = diesel::sql_types::VarChar)]
    pub(crate) client_name: String,
    #[diesel(sql_type = diesel::sql_types::Text)]
    pub(crate) client_type: String,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::VarChar>)]
    pub(crate) client_secret_hash: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Jsonb)]
    pub(crate) redirect_uris: Value,
    #[diesel(sql_type = diesel::sql_types::Jsonb)]
    pub(crate) scopes: Value,
    #[diesel(sql_type = diesel::sql_types::Jsonb)]
    pub(crate) allowed_audiences: Value,
    #[diesel(sql_type = diesel::sql_types::Jsonb)]
    pub(crate) grant_types: Value,
    #[diesel(sql_type = diesel::sql_types::VarChar)]
    pub(crate) token_endpoint_auth_method: String,
    #[diesel(sql_type = diesel::sql_types::Bool)]
    pub(crate) require_dpop_bound_tokens: bool,
    #[diesel(sql_type = diesel::sql_types::Bool)]
    pub(crate) require_mtls_bound_tokens: bool,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::VarChar>)]
    pub(crate) tls_client_auth_subject_dn: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::VarChar>)]
    pub(crate) tls_client_auth_cert_sha256: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Jsonb)]
    pub(crate) tls_client_auth_san_dns: Value,
    #[diesel(sql_type = diesel::sql_types::Jsonb)]
    pub(crate) tls_client_auth_san_uri: Value,
    #[diesel(sql_type = diesel::sql_types::Jsonb)]
    pub(crate) tls_client_auth_san_ip: Value,
    #[diesel(sql_type = diesel::sql_types::Jsonb)]
    pub(crate) tls_client_auth_san_email: Value,
    #[diesel(sql_type = diesel::sql_types::Bool)]
    pub(crate) allow_client_assertion_audience_array: bool,
    #[diesel(sql_type = diesel::sql_types::Bool)]
    pub(crate) allow_client_assertion_endpoint_audience: bool,
    #[diesel(sql_type = diesel::sql_types::Bool)]
    pub(crate) require_par_request_object: bool,
    #[diesel(sql_type = diesel::sql_types::Bool)]
    pub(crate) allow_authorization_code_without_pkce: bool,
    #[diesel(sql_type = diesel::sql_types::Bool)]
    pub(crate) is_active: bool,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Jsonb>)]
    pub(crate) jwks: Option<Value>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::VarChar>)]
    pub(crate) introspection_encrypted_response_alg: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::VarChar>)]
    pub(crate) introspection_encrypted_response_enc: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::VarChar>)]
    pub(crate) userinfo_signed_response_alg: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::VarChar>)]
    pub(crate) userinfo_encrypted_response_alg: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::VarChar>)]
    pub(crate) userinfo_encrypted_response_enc: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::VarChar>)]
    pub(crate) authorization_signed_response_alg: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::VarChar>)]
    pub(crate) authorization_encrypted_response_alg: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::VarChar>)]
    pub(crate) authorization_encrypted_response_enc: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Jsonb)]
    pub(crate) post_logout_redirect_uris: Value,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::VarChar>)]
    pub(crate) backchannel_logout_uri: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Bool)]
    pub(crate) backchannel_logout_session_required: bool,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::VarChar>)]
    pub(crate) frontchannel_logout_uri: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Bool)]
    pub(crate) frontchannel_logout_session_required: bool,
    #[diesel(sql_type = diesel::sql_types::Text)]
    pub(crate) subject_type: String,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Text>)]
    pub(crate) sector_identifier_uri: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Text>)]
    pub(crate) sector_identifier_host: Option<String>,
}

/// oauth_tokens 表 token 行。
#[derive(Debug, Queryable, QueryableByName, Selectable)]
#[diesel(table_name = crate::schema::oauth_tokens)]
pub(crate) struct TokenRow {
    #[diesel(sql_type = diesel::sql_types::Uuid)]
    pub(crate) id: Uuid,
    #[diesel(sql_type = diesel::sql_types::Uuid)]
    pub(crate) tenant_id: Uuid,
    #[diesel(sql_type = diesel::sql_types::Uuid)]
    pub(crate) token_family_id: Uuid,
    #[diesel(sql_type = diesel::sql_types::Uuid)]
    pub(crate) client_id: Uuid,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Uuid>)]
    pub(crate) user_id: Option<Uuid>,
    #[diesel(sql_type = diesel::sql_types::Jsonb)]
    pub(crate) scopes: Value,
    #[diesel(sql_type = diesel::sql_types::Jsonb)]
    pub(crate) audience: Value,
    #[diesel(sql_type = diesel::sql_types::Jsonb)]
    pub(crate) authorization_details: Value,
    #[diesel(sql_type = diesel::sql_types::Timestamptz)]
    pub(crate) issued_at: DateTime<Utc>,
    #[diesel(sql_type = diesel::sql_types::Timestamptz)]
    pub(crate) expires_at: DateTime<Utc>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Timestamptz>)]
    pub(crate) revoked_at: Option<DateTime<Utc>>,
    #[diesel(sql_type = diesel::sql_types::VarChar)]
    pub(crate) subject: String,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::VarChar>)]
    pub(crate) dpop_jkt: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::VarChar>)]
    pub(crate) mtls_x5t_s256: Option<String>,
}

/// 当前用户已授权应用列表行。
#[derive(Debug, Queryable, QueryableByName)]
pub(crate) struct MyApplicationRow {
    #[diesel(sql_type = diesel::sql_types::VarChar)]
    pub(crate) client_id: String,
    #[diesel(sql_type = diesel::sql_types::VarChar)]
    pub(crate) client_name: String,
    #[diesel(sql_type = diesel::sql_types::Jsonb)]
    pub(crate) last_scopes: Value,
    #[diesel(sql_type = diesel::sql_types::Timestamptz)]
    pub(crate) last_authorized_at: DateTime<Utc>,
    #[diesel(sql_type = diesel::sql_types::Int4)]
    pub(crate) authorization_count: i32,
}

/// 当前用户访问接入申请列表行。
#[derive(Debug, Queryable, QueryableByName)]
pub(crate) struct UserAccessRequestRow {
    #[diesel(sql_type = diesel::sql_types::Uuid)]
    pub(crate) id: Uuid,
    #[diesel(sql_type = diesel::sql_types::VarChar)]
    pub(crate) site_name: String,
    #[diesel(sql_type = diesel::sql_types::VarChar)]
    pub(crate) site_url: String,
    #[diesel(sql_type = diesel::sql_types::Text)]
    pub(crate) request_description: String,
    #[diesel(sql_type = diesel::sql_types::SmallInt)]
    pub(crate) status: i16,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Text>)]
    pub(crate) admin_note: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Uuid>)]
    pub(crate) approved_client_id: Option<Uuid>,
    #[diesel(sql_type = diesel::sql_types::Timestamptz)]
    pub(crate) created_at: DateTime<Utc>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Timestamptz>)]
    pub(crate) resolved_at: Option<DateTime<Utc>>,
}

/// 管理端访问接入申请列表行。
#[derive(Debug, Queryable, QueryableByName)]
pub(crate) struct AccessRequestRow {
    #[diesel(sql_type = diesel::sql_types::Uuid)]
    pub(crate) id: Uuid,
    #[diesel(sql_type = diesel::sql_types::Uuid)]
    pub(crate) user_id: Uuid,
    #[diesel(sql_type = diesel::sql_types::VarChar)]
    pub(crate) user_email: String,
    #[diesel(sql_type = diesel::sql_types::VarChar)]
    pub(crate) site_name: String,
    #[diesel(sql_type = diesel::sql_types::VarChar)]
    pub(crate) site_url: String,
    #[diesel(sql_type = diesel::sql_types::Text)]
    pub(crate) request_description: String,
    #[diesel(sql_type = diesel::sql_types::SmallInt)]
    pub(crate) status: i16,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Text>)]
    pub(crate) admin_note: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Uuid>)]
    pub(crate) approved_client_id: Option<Uuid>,
    #[diesel(sql_type = diesel::sql_types::Timestamptz)]
    pub(crate) created_at: DateTime<Utc>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Timestamptz>)]
    pub(crate) resolved_at: Option<DateTime<Utc>>,
}

/// 管理端授权记录列表行。
#[derive(Debug, Queryable, QueryableByName)]
pub(crate) struct GrantRow {
    #[diesel(sql_type = diesel::sql_types::Uuid)]
    pub(crate) user_id: Uuid,
    #[diesel(sql_type = diesel::sql_types::VarChar)]
    pub(crate) email: String,
    #[diesel(sql_type = diesel::sql_types::VarChar)]
    pub(crate) client_id: String,
    #[diesel(sql_type = diesel::sql_types::VarChar)]
    pub(crate) client_name: String,
    #[diesel(sql_type = diesel::sql_types::Timestamptz)]
    pub(crate) last_authorized_at: DateTime<Utc>,
    #[diesel(sql_type = diesel::sql_types::Int4)]
    pub(crate) authorization_count: i32,
    #[diesel(sql_type = diesel::sql_types::Jsonb)]
    pub(crate) last_scopes: Value,
    #[diesel(sql_type = diesel::sql_types::Jsonb)]
    pub(crate) last_authorization_details: Value,
}

/// 待处理访问申请去重查询行。
#[derive(Debug, Queryable, QueryableByName)]
pub(crate) struct PendingAccessRequestRow {
    #[diesel(sql_type = diesel::sql_types::Uuid)]
    pub(crate) user_id: Uuid,
    #[diesel(sql_type = diesel::sql_types::VarChar)]
    pub(crate) site_name: String,
}
