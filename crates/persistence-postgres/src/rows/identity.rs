use chrono::{DateTime, Utc};
use diesel::{Queryable, Selectable};
use serde_json::Value;
use uuid::Uuid;

#[allow(dead_code)]
#[derive(Clone, Debug, Queryable, Selectable)]
#[diesel(table_name = crate::schema::users)]
pub(crate) struct UserRow {
    pub(crate) id: Uuid,
    pub(crate) tenant_id: Uuid,
    pub(crate) realm_id: Uuid,
    pub(crate) organization_id: Uuid,
    pub(crate) username: String,
    pub(crate) email: String,
    pub(crate) password_hash: String,
    pub(crate) is_active: bool,
    pub(crate) mfa_enabled: bool,
    pub(crate) created_at: DateTime<Utc>,
    pub(crate) updated_at: DateTime<Utc>,
    pub(crate) email_verified: bool,
    pub(crate) display_name: Option<String>,
    pub(crate) avatar_url: Option<String>,
    pub(crate) given_name: Option<String>,
    pub(crate) family_name: Option<String>,
    pub(crate) middle_name: Option<String>,
    pub(crate) nickname: Option<String>,
    pub(crate) profile_url: Option<String>,
    pub(crate) website_url: Option<String>,
    pub(crate) gender: Option<String>,
    pub(crate) birthdate: Option<String>,
    pub(crate) zoneinfo: Option<String>,
    pub(crate) locale: Option<String>,
    pub(crate) role: String,
    pub(crate) admin_level: i32,
    pub(crate) address_formatted: Option<String>,
    pub(crate) address_street_address: Option<String>,
    pub(crate) address_locality: Option<String>,
    pub(crate) address_region: Option<String>,
    pub(crate) address_postal_code: Option<String>,
    pub(crate) address_country: Option<String>,
    pub(crate) phone_number: Option<String>,
    pub(crate) phone_number_verified: bool,
}

/// Focused account read model. Password verifier material is intentionally
/// absent so non-authentication queries cannot retrieve it from PostgreSQL.
#[derive(Clone, Debug, Queryable, Selectable)]
#[diesel(table_name = crate::schema::users)]
pub(crate) struct PublicAccountRow {
    pub(crate) id: Uuid,
    pub(crate) tenant_id: Uuid,
    pub(crate) realm_id: Uuid,
    pub(crate) organization_id: Uuid,
    pub(crate) username: String,
    pub(crate) email: String,
    pub(crate) is_active: bool,
    pub(crate) mfa_enabled: bool,
    pub(crate) created_at: DateTime<Utc>,
    pub(crate) updated_at: DateTime<Utc>,
    pub(crate) email_verified: bool,
    pub(crate) display_name: Option<String>,
    pub(crate) avatar_url: Option<String>,
    pub(crate) given_name: Option<String>,
    pub(crate) family_name: Option<String>,
    pub(crate) middle_name: Option<String>,
    pub(crate) nickname: Option<String>,
    pub(crate) profile_url: Option<String>,
    pub(crate) website_url: Option<String>,
    pub(crate) gender: Option<String>,
    pub(crate) birthdate: Option<String>,
    pub(crate) zoneinfo: Option<String>,
    pub(crate) locale: Option<String>,
    pub(crate) role: String,
    pub(crate) admin_level: i32,
    pub(crate) address_formatted: Option<String>,
    pub(crate) address_street_address: Option<String>,
    pub(crate) address_locality: Option<String>,
    pub(crate) address_region: Option<String>,
    pub(crate) address_postal_code: Option<String>,
    pub(crate) address_country: Option<String>,
    pub(crate) phone_number: Option<String>,
    pub(crate) phone_number_verified: bool,
}

#[derive(Clone, Debug, Queryable, Selectable)]
#[diesel(table_name = crate::schema::users)]
pub(crate) struct PrincipalRow {
    pub(crate) id: Uuid,
    pub(crate) tenant_id: Uuid,
    pub(crate) realm_id: Uuid,
    pub(crate) organization_id: Uuid,
    pub(crate) is_active: bool,
    pub(crate) role: String,
    pub(crate) admin_level: i32,
}

#[derive(Clone, Debug, Queryable, Selectable)]
#[diesel(table_name = crate::schema::users)]
pub(crate) struct SubjectClaimsRow {
    pub(crate) id: Uuid,
    pub(crate) tenant_id: Uuid,
    pub(crate) realm_id: Uuid,
    pub(crate) organization_id: Uuid,
    pub(crate) username: String,
    pub(crate) email: String,
    pub(crate) is_active: bool,
    pub(crate) updated_at: DateTime<Utc>,
    pub(crate) email_verified: bool,
    pub(crate) display_name: Option<String>,
    pub(crate) avatar_url: Option<String>,
    pub(crate) given_name: Option<String>,
    pub(crate) family_name: Option<String>,
    pub(crate) middle_name: Option<String>,
    pub(crate) nickname: Option<String>,
    pub(crate) profile_url: Option<String>,
    pub(crate) website_url: Option<String>,
    pub(crate) gender: Option<String>,
    pub(crate) birthdate: Option<String>,
    pub(crate) zoneinfo: Option<String>,
    pub(crate) locale: Option<String>,
    pub(crate) role: String,
    pub(crate) admin_level: i32,
    pub(crate) address_formatted: Option<String>,
    pub(crate) address_street_address: Option<String>,
    pub(crate) address_locality: Option<String>,
    pub(crate) address_region: Option<String>,
    pub(crate) address_postal_code: Option<String>,
    pub(crate) address_country: Option<String>,
    pub(crate) phone_number: Option<String>,
    pub(crate) phone_number_verified: bool,
}

#[derive(Clone, Debug, Queryable, Selectable)]
#[diesel(table_name = crate::schema::users)]
pub(crate) struct AuthenticationIdentityRow {
    pub(crate) id: Uuid,
    pub(crate) tenant_id: Uuid,
    pub(crate) realm_id: Uuid,
    pub(crate) organization_id: Uuid,
    pub(crate) username: String,
    pub(crate) email: String,
    pub(crate) password_hash: String,
    pub(crate) is_active: bool,
    pub(crate) mfa_enabled: bool,
    pub(crate) email_verified: bool,
    pub(crate) role: String,
    pub(crate) admin_level: i32,
}

#[derive(Clone, Debug, Queryable, Selectable)]
#[diesel(table_name = crate::schema::user_passkey_credentials)]
pub(crate) struct PasskeyCredentialRow {
    pub(crate) id: Uuid,
    pub(crate) tenant_id: Uuid,
    pub(crate) user_id: Uuid,
    pub(crate) credential_id: String,
    pub(crate) credential: Value,
    pub(crate) label: String,
    pub(crate) sign_count: i64,
    pub(crate) last_used_at: Option<DateTime<Utc>>,
    pub(crate) created_at: DateTime<Utc>,
    pub(crate) updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Queryable, Selectable)]
#[diesel(table_name = crate::schema::external_identity_links)]
pub(crate) struct ExternalIdentityLinkRow {
    pub(crate) id: Uuid,
    pub(crate) tenant_id: Uuid,
    pub(crate) user_id: Uuid,
    pub(crate) provider_type: String,
    pub(crate) provider_id: String,
    pub(crate) subject: String,
    pub(crate) email: String,
    pub(crate) claims: Value,
    pub(crate) created_at: DateTime<Utc>,
    pub(crate) updated_at: DateTime<Utc>,
    pub(crate) last_login_at: Option<DateTime<Utc>>,
}
