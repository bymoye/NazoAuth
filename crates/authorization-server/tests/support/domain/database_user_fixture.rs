use chrono::{DateTime, Utc};
use diesel::{Queryable, QueryableByName, Selectable};
use serde::Serialize;
use serde_json::Value;
use uuid::Uuid;

use nazo_identity::{
    AccountIdentity, OrganizationId, PostalAddress, Principal, PublicAccount, RealmId,
    TenantContext, TenantId, UserId, UserProfile, UserRole, ports::FederationLink,
};

#[derive(Debug, Queryable, QueryableByName, Selectable, Serialize, Clone)]
#[diesel(table_name = crate::schema::users)]
pub(crate) struct DatabaseUserFixture {
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
    pub(crate) email_verified: bool,
    pub(crate) mfa_enabled: bool,
    pub(crate) password_hash: String,
    pub(crate) is_active: bool,
    pub(crate) created_at: DateTime<Utc>,
    pub(crate) updated_at: DateTime<Utc>,
}

impl DatabaseUserFixture {
    pub(crate) fn identity(&self) -> PublicAccount {
        self.clone()
            .try_into()
            .expect("database user fixture must contain a valid identity")
    }
}

impl TryFrom<DatabaseUserFixture> for PublicAccount {
    type Error = &'static str;

    fn try_from(row: DatabaseUserFixture) -> Result<Self, Self::Error> {
        let role = match (row.role.as_str(), row.admin_level) {
            ("user", 0) => UserRole::User,
            ("admin", level) if level > 0 => UserRole::Admin {
                level: u32::try_from(level).map_err(|_| "invalid admin level")?,
            },
            _ => return Err("invalid role/admin level combination"),
        };
        Ok(Self {
            principal: Principal {
                user_id: UserId::new(row.id).map_err(|_| "invalid user ID")?,
                tenant: TenantContext {
                    tenant_id: TenantId::new(row.tenant_id).map_err(|_| "invalid tenant ID")?,
                    realm_id: RealmId::new(row.realm_id).map_err(|_| "invalid realm ID")?,
                    organization_id: OrganizationId::new(row.organization_id)
                        .map_err(|_| "invalid organization ID")?,
                },
                role,
                active: row.is_active,
            },
            account: AccountIdentity {
                username: row.username,
                email: row.email,
                email_verified: row.email_verified,
                mfa_enabled: row.mfa_enabled,
            },
            profile: UserProfile {
                display_name: row.display_name,
                avatar_url: row.avatar_url,
                given_name: row.given_name,
                family_name: row.family_name,
                middle_name: row.middle_name,
                nickname: row.nickname,
                profile_url: row.profile_url,
                website_url: row.website_url,
                gender: row.gender,
                birthdate: row.birthdate,
                zoneinfo: row.zoneinfo,
                locale: row.locale,
                address: PostalAddress {
                    formatted: row.address_formatted,
                    street_address: row.address_street_address,
                    locality: row.address_locality,
                    region: row.address_region,
                    postal_code: row.address_postal_code,
                    country: row.address_country,
                },
                phone_number: row.phone_number,
                phone_number_verified: row.phone_number_verified,
            },
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }
}

#[derive(Debug, Queryable, QueryableByName, Selectable, Serialize, Clone)]
#[diesel(table_name = crate::schema::user_passkey_credentials)]
pub(crate) struct DatabasePasskeyFixture {
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

#[derive(Debug, Queryable, QueryableByName, Selectable, Serialize, Clone)]
#[diesel(table_name = crate::schema::external_identity_links)]
pub(crate) struct DatabaseExternalIdentityFixture {
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

impl DatabaseExternalIdentityFixture {
    pub(crate) fn federation_link(&self) -> FederationLink {
        FederationLink {
            id: self.id,
            tenant_id: TenantId::new(self.tenant_id).expect("valid fixture tenant ID"),
            user_id: UserId::new(self.user_id).expect("valid fixture user ID"),
            provider_type: self.provider_type.clone(),
            provider_id: self.provider_id.clone(),
            subject: self.subject.clone(),
            email: self.email.clone(),
            claims: self.claims.clone(),
            created_at: self.created_at,
            updated_at: self.updated_at,
            last_login_at: self.last_login_at,
        }
    }
}
