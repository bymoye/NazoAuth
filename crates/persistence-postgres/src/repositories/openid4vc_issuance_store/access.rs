use super::super::Openid4vciRepository;
use super::AccessRow;
use chrono::{DateTime, Utc};
use diesel::{OptionalExtension, sql_query, sql_types};
use diesel_async::RunQueryDsl;
use nazo_openid4vci::{CredentialAccess, CredentialStoreError, CredentialStoreFuture};

impl Openid4vciRepository {
    pub(super) fn access_upsert<'a>(
        &'a self,
        token_hash: &'a str,
        access: &'a CredentialAccess,
    ) -> CredentialStoreFuture<'a, Result<(), CredentialStoreError>> {
        Box::pin(async move {
            let mut connection = self
                .pool
                .get()
                .await
                .map_err(|_| CredentialStoreError::Unavailable)?;
            sql_query(
                "INSERT INTO openid4vci_access_grants \
                 (token_id,token_hash,tenant_id,subject_id,client_id,credential_configuration_ids,credential_identifiers,dpop_jkt,expires_at) \
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) \
                 ON CONFLICT (token_hash) DO UPDATE SET \
                   credential_configuration_ids = EXCLUDED.credential_configuration_ids, \
                   credential_identifiers = EXCLUDED.credential_identifiers, \
                   dpop_jkt = EXCLUDED.dpop_jkt, expires_at = EXCLUDED.expires_at \
                 WHERE openid4vci_access_grants.token_id = EXCLUDED.token_id \
                   AND openid4vci_access_grants.tenant_id = EXCLUDED.tenant_id \
                   AND openid4vci_access_grants.subject_id = EXCLUDED.subject_id \
                   AND openid4vci_access_grants.client_id = EXCLUDED.client_id",
            )
            .bind::<sql_types::Uuid, _>(access.token_id)
            .bind::<sql_types::Text, _>(token_hash)
            .bind::<sql_types::Uuid, _>(access.tenant_id)
            .bind::<sql_types::Uuid, _>(access.subject_id)
            .bind::<sql_types::Text, _>(&access.client_id)
            .bind::<sql_types::Jsonb, _>(serde_json::json!(access.configuration_ids))
            .bind::<sql_types::Jsonb, _>(serde_json::json!(access.credential_identifiers))
            .bind::<sql_types::Nullable<sql_types::Text>, _>(access.dpop_jkt.as_deref())
            .bind::<sql_types::Timestamptz, _>(access.expires_at)
            .execute(&mut connection)
            .await
            .map_err(|_| CredentialStoreError::Unavailable)?;
            Ok(())
        })
    }

    pub(super) fn access_resolve<'a>(
        &'a self,
        token_hash: &'a str,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<Option<CredentialAccess>, CredentialStoreError>> {
        Box::pin(async move {
            let mut connection = self
                .pool
                .get()
                .await
                .map_err(|_| CredentialStoreError::Unavailable)?;
            let row = sql_query(
                "SELECT token_id, tenant_id, subject_id, client_id, credential_configuration_ids, \
                 credential_identifiers, dpop_jkt, expires_at FROM openid4vci_access_grants \
                 WHERE token_hash = $1 AND revoked_at IS NULL AND expires_at > $2",
            )
            .bind::<sql_types::Text, _>(token_hash)
            .bind::<sql_types::Timestamptz, _>(now)
            .get_result::<AccessRow>(&mut connection)
            .await
            .optional()
            .map_err(|_| CredentialStoreError::Unavailable)?;
            row.map(TryInto::try_into)
                .transpose()
                .map_err(|_| CredentialStoreError::Unavailable)
        })
    }
}
