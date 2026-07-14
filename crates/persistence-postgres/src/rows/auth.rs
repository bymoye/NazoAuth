use chrono::{DateTime, Utc};
use serde_json::Value;
use uuid::Uuid;

#[derive(Debug, diesel::Queryable, diesel::QueryableByName, diesel::Selectable)]
#[diesel(table_name = crate::schema::oauth_tokens)]
pub(crate) struct RefreshTokenRow {
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

#[derive(Clone, Debug, diesel::QueryableByName)]
pub(crate) struct BackchannelLogoutDeliveryRow {
    #[diesel(sql_type = diesel::sql_types::Uuid)]
    pub(crate) id: Uuid,
    #[diesel(sql_type = diesel::sql_types::Text)]
    pub(crate) logout_uri: String,
    #[diesel(sql_type = diesel::sql_types::Text)]
    pub(crate) logout_token: String,
    #[diesel(sql_type = diesel::sql_types::Integer)]
    pub(crate) attempts: i32,
    #[diesel(sql_type = diesel::sql_types::Timestamptz)]
    pub(crate) expires_at: DateTime<Utc>,
}
