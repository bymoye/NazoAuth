//! PostgreSQL implementation of the tenant-bound signing-key persistence port.
use anyhow::{Context as _, ensure};
use diesel::{OptionalExtension as _, QueryableByName, sql_query, sql_types};
use diesel_async::RunQueryDsl;
use nazo_key_management::{
    PersistedSigningKeyset, SigningKeyRepository, SigningKeyRepositoryFuture,
    SigningKeysetCompareAndSwapResult, SigningKeysetCreateResult,
};
use uuid::Uuid;

use crate::{DbConnection, DbPool};

#[derive(Clone)]
pub struct SigningKeysetRepository {
    pool: DbPool,
    tenant_id: Uuid,
}

impl SigningKeysetRepository {
    #[must_use]
    pub fn for_tenant(pool: DbPool, tenant_id: Uuid) -> Self {
        Self { pool, tenant_id }
    }

    async fn load_on(
        &self,
        connection: &mut DbConnection,
    ) -> anyhow::Result<Option<PersistedSigningKeyset>> {
        Ok(sql_query(
            "SELECT revision, public_metadata, encrypted_private_material, wrapping_key_id \
             FROM tenant_signing_keysets WHERE tenant_id = $1",
        )
        .bind::<sql_types::Uuid, _>(self.tenant_id)
        .get_result::<KeysetRow>(connection)
        .await
        .optional()?
        .map(Into::into))
    }
}

impl SigningKeyRepository for SigningKeysetRepository {
    fn load(&self) -> SigningKeyRepositoryFuture<'_, Option<PersistedSigningKeyset>> {
        Box::pin(async move {
            let mut connection = self.pool.get().await?;
            self.load_on(&mut connection).await
        })
    }

    fn create_if_absent(
        &self,
        candidate: PersistedSigningKeyset,
    ) -> SigningKeyRepositoryFuture<'_, SigningKeysetCreateResult> {
        Box::pin(async move {
            ensure!(
                candidate.revision == 1,
                "initial signing-key revision must be 1"
            );
            let mut connection = self.pool.get().await?;
            let created = sql_query(
                "INSERT INTO tenant_signing_keysets \
                 (tenant_id, revision, public_metadata, encrypted_private_material, wrapping_key_id) \
                 VALUES ($1, $2, $3, $4, $5) ON CONFLICT (tenant_id) DO NOTHING \
                 RETURNING revision, public_metadata, encrypted_private_material, wrapping_key_id",
            )
            .bind::<sql_types::Uuid, _>(self.tenant_id)
            .bind::<sql_types::BigInt, _>(candidate.revision)
            .bind::<sql_types::Jsonb, _>(candidate.public_metadata)
            .bind::<sql_types::Binary, _>(candidate.encrypted_private_material)
            .bind::<sql_types::Text, _>(candidate.wrapping_key_id)
            .get_result::<KeysetRow>(&mut connection)
            .await
            .optional()?;
            if let Some(row) = created {
                return Ok(SigningKeysetCreateResult::Created(row.into()));
            }
            // A separate statement sees the concurrent INSERT that won the
            // conflict, even when it committed after our INSERT snapshot.
            let existing = self
                .load_on(&mut connection)
                .await?
                .context("tenant signing keyset disappeared during initialization")?;
            Ok(SigningKeysetCreateResult::Existing(existing))
        })
    }

    fn compare_and_swap(
        &self,
        expected_revision: i64,
        candidate: PersistedSigningKeyset,
    ) -> SigningKeyRepositoryFuture<'_, SigningKeysetCompareAndSwapResult> {
        Box::pin(async move {
            ensure!(
                expected_revision > 0
                    && expected_revision.checked_add(1) == Some(candidate.revision),
                "signing-key update must advance exactly one revision"
            );
            let mut connection = self.pool.get().await?;
            let updated = sql_query(
                "UPDATE tenant_signing_keysets SET revision = $2, public_metadata = $3, \
                 encrypted_private_material = $4, wrapping_key_id = $5, updated_at = CURRENT_TIMESTAMP \
                 WHERE tenant_id = $1 AND revision = $6 \
                 RETURNING revision, public_metadata, encrypted_private_material, wrapping_key_id",
            )
            .bind::<sql_types::Uuid, _>(self.tenant_id)
            .bind::<sql_types::BigInt, _>(candidate.revision)
            .bind::<sql_types::Jsonb, _>(candidate.public_metadata)
            .bind::<sql_types::Binary, _>(candidate.encrypted_private_material)
            .bind::<sql_types::Text, _>(candidate.wrapping_key_id)
            .bind::<sql_types::BigInt, _>(expected_revision)
            .get_result::<KeysetRow>(&mut connection)
            .await
            .optional()?;
            if let Some(row) = updated {
                return Ok(SigningKeysetCompareAndSwapResult::Applied(row.into()));
            }
            let current = self
                .load_on(&mut connection)
                .await?
                .context("tenant signing keyset no longer exists")?;
            Ok(SigningKeysetCompareAndSwapResult::Conflict(current))
        })
    }
}

#[derive(QueryableByName)]
struct KeysetRow {
    #[diesel(sql_type = sql_types::BigInt)]
    revision: i64,
    #[diesel(sql_type = sql_types::Jsonb)]
    public_metadata: serde_json::Value,
    #[diesel(sql_type = sql_types::Binary)]
    encrypted_private_material: Vec<u8>,
    #[diesel(sql_type = sql_types::Text)]
    wrapping_key_id: String,
}

impl From<KeysetRow> for PersistedSigningKeyset {
    fn from(row: KeysetRow) -> Self {
        Self {
            revision: row.revision,
            public_metadata: row.public_metadata,
            encrypted_private_material: row.encrypted_private_material,
            wrapping_key_id: row.wrapping_key_id,
        }
    }
}
