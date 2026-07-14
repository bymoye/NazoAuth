use diesel::{QueryResult, sql_query};
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl};
use nazo_auth::OAuthClient;
use nazo_identity::ports::RepositoryError;
use uuid::Uuid;

use crate::{DbPool, repositories::clients::upsert_client_on_connection};

#[derive(Clone)]
pub struct OidfSeedUser {
    pub tenant_id: Uuid,
    pub realm_id: Uuid,
    pub organization_id: Uuid,
    pub username: String,
    pub email: String,
    pub password_hash: String,
}

#[derive(Clone)]
pub struct OidfSeedClient {
    pub client: OAuthClient,
    pub client_secret_hash: Option<String>,
}

pub async fn seed_oidf_atomically(
    pool: &DbPool,
    user: &OidfSeedUser,
    clients: &[OidfSeedClient],
) -> Result<(), RepositoryError> {
    let mut connection = pool.get().await.map_err(|_| RepositoryError::Unavailable)?;
    connection
        .transaction::<(), diesel::result::Error, _>(async move |connection| {
            upsert_user(connection, user).await?;
            for client in clients {
                upsert_client_on_connection(
                    connection,
                    &client.client,
                    client.client_secret_hash.as_deref(),
                )
                .await?;
            }
            Ok(())
        })
        .await
        .map_err(|error| RepositoryError::Unexpected(error.to_string()))
}

async fn upsert_user(connection: &mut AsyncPgConnection, user: &OidfSeedUser) -> QueryResult<()> {
    sql_query(
        r#"
        INSERT INTO users (
            tenant_id,
            realm_id,
            organization_id,
            username,
            email,
            password_hash,
            is_active,
            email_verified,
            role,
            admin_level,
            display_name,
            given_name,
            family_name,
            middle_name,
            nickname,
            profile_url,
            avatar_url,
            website_url,
            gender,
            birthdate,
            zoneinfo,
            locale,
            address_formatted,
            address_street_address,
            address_locality,
            address_region,
            address_postal_code,
            address_country,
            phone_number,
            phone_number_verified
        )
        VALUES (
            $1,
            $2,
            $3,
            $4,
            $5,
            $6,
            TRUE,
            TRUE,
            'user',
            0,
            'OIDF Local User',
            'OIDF',
            'Local',
            'Conformance',
            'oidf',
            'https://auth.nazo.run/profile/oidf-local',
            'https://auth.nazo.run/avatar/oidf-local.png',
            'https://auth.nazo.run/',
            'unspecified',
            '2000-01-01',
            'Asia/Shanghai',
            'en-US',
            'OIDF Local Test Address',
            '1 Conformance Way',
            'Test City',
            'CA',
            '94000',
            'US',
            '+15555550100',
            TRUE
        )
        ON CONFLICT (tenant_id, email) DO UPDATE
        SET password_hash = EXCLUDED.password_hash,
            is_active = TRUE,
            email_verified = TRUE,
            display_name = 'OIDF Local User',
            given_name = 'OIDF',
            family_name = 'Local',
            middle_name = 'Conformance',
            nickname = 'oidf',
            profile_url = 'https://auth.nazo.run/profile/oidf-local',
            avatar_url = 'https://auth.nazo.run/avatar/oidf-local.png',
            website_url = 'https://auth.nazo.run/',
            gender = 'unspecified',
            birthdate = '2000-01-01',
            zoneinfo = 'Asia/Shanghai',
            locale = 'en-US',
            address_formatted = 'OIDF Local Test Address',
            address_street_address = '1 Conformance Way',
            address_locality = 'Test City',
            address_region = 'CA',
            address_postal_code = '94000',
            address_country = 'US',
            phone_number = '+15555550100',
            phone_number_verified = TRUE,
            updated_at = CURRENT_TIMESTAMP
        "#,
    )
    .bind::<diesel::sql_types::Uuid, _>(user.tenant_id)
    .bind::<diesel::sql_types::Uuid, _>(user.realm_id)
    .bind::<diesel::sql_types::Uuid, _>(user.organization_id)
    .bind::<diesel::sql_types::VarChar, _>(&user.username)
    .bind::<diesel::sql_types::VarChar, _>(&user.email)
    .bind::<diesel::sql_types::VarChar, _>(&user.password_hash)
    .execute(connection)
    .await
    .map(|_| ())
}
