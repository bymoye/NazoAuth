use chrono::{DateTime, Duration, Utc};
use diesel::{ExpressionMethods, OptionalExtension, QueryDsl, SelectableHelper};
use diesel_async::{AsyncConnection, RunQueryDsl};
use nazo_identity::ports::RepositoryError;
use serde_json::Value;
use std::future::Future;
use uuid::Uuid;

use crate::{DbPool, get_conn, schema::conformance_leases};

pub const MIN_CONFORMANCE_LEASE_SECONDS: i64 = 60;
pub const MAX_CONFORMANCE_LEASE_SECONDS: i64 = 24 * 60 * 60;
const LEASED_DYNAMIC_REGISTRATION_PROFILE: &str = "oidc-fapi-ciba";
const CIBA_DECISION_CLAIM_SECONDS: i64 = 30;
// One immediate attempt plus 120 quarter-second waits covers the full
// thirty-second claim deadline before returning a bounded conflict.
const CIBA_REVOKE_WAIT_ATTEMPTS: usize = 121;
const CIBA_REVOKE_WAIT_MILLIS: u64 = 250;

#[derive(Clone, Debug, diesel::Queryable, diesel::Selectable)]
#[diesel(table_name = crate::schema::conformance_leases)]
pub struct ConformanceLease {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub profile: String,
    pub material_sha256: String,
    pub dynamic_registration_initial_access_token_sha256: Option<String>,
    pub ciba_automated_decision_token_sha256: Option<String>,
    pub public_material: Option<Value>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub cleaned_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ConformanceLeaseTokenDigests<'a> {
    pub dynamic_registration_initial_access_token_sha256: Option<&'a str>,
    pub ciba_automated_decision_token_sha256: Option<&'a str>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConformanceLeaseCleanup {
    pub cleaned_leases: i32,
    pub deleted_clients: i32,
}

#[derive(Clone, Debug, diesel::QueryableByName)]
pub struct ConformanceLeasePublicMaterial {
    #[diesel(sql_type = diesel::sql_types::Uuid)]
    pub lease_id: Uuid,
    #[diesel(sql_type = diesel::sql_types::Jsonb)]
    pub public_material: Value,
}

#[derive(Clone)]
pub struct ConformanceLeaseRepository {
    pool: DbPool,
}

impl ConformanceLeaseRepository {
    #[must_use]
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    pub async fn create(
        &self,
        tenant_id: Uuid,
        profile: &str,
        material_sha256: &str,
        token_digests: ConformanceLeaseTokenDigests<'_>,
        public_material: Option<Value>,
        ttl_seconds: i64,
    ) -> Result<ConformanceLease, RepositoryError> {
        let ConformanceLeaseTokenDigests {
            dynamic_registration_initial_access_token_sha256,
            ciba_automated_decision_token_sha256,
        } = token_digests;
        if !(MIN_CONFORMANCE_LEASE_SECONDS..=MAX_CONFORMANCE_LEASE_SECONDS).contains(&ttl_seconds) {
            return Err(RepositoryError::Consistency(format!(
                "conformance lease ttl_seconds must be between {MIN_CONFORMANCE_LEASE_SECONDS} and {MAX_CONFORMANCE_LEASE_SECONDS}"
            )));
        }
        let profile = profile.trim();
        if profile.is_empty() || profile.len() > 64 {
            return Err(RepositoryError::Consistency(
                "conformance lease profile must contain 1 to 64 bytes".to_owned(),
            ));
        }
        if material_sha256.len() != 64
            || !material_sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(RepositoryError::Consistency(
                "conformance lease material_sha256 must be a lowercase SHA-256 digest".to_owned(),
            ));
        }
        for (digest, purpose) in [
            (
                dynamic_registration_initial_access_token_sha256,
                "dynamic registration initial access token",
            ),
            (
                ciba_automated_decision_token_sha256,
                "CIBA automated decision token",
            ),
        ] {
            if digest.is_some_and(|digest| {
                digest.len() != 64
                    || !digest
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            }) {
                return Err(RepositoryError::Consistency(format!(
                    "conformance lease {purpose} must be a lowercase SHA-256 digest"
                )));
            }
        }
        if (dynamic_registration_initial_access_token_sha256.is_some()
            || ciba_automated_decision_token_sha256.is_some())
            && profile != LEASED_DYNAMIC_REGISTRATION_PROFILE
        {
            return Err(RepositoryError::Consistency(
                "conformance lease token bindings are only valid for the oidc-fapi-ciba profile"
                    .to_owned(),
            ));
        }

        let now = Utc::now();
        let expires_at = now
            .checked_add_signed(Duration::seconds(ttl_seconds))
            .ok_or_else(|| {
                RepositoryError::Consistency("conformance lease ttl overflow".to_owned())
            })?;
        let mut connection = get_conn(&self.pool).await.map_err(map_pool_error)?;
        diesel::insert_into(conformance_leases::table)
            .values((
                conformance_leases::tenant_id.eq(tenant_id),
                conformance_leases::profile.eq(profile),
                conformance_leases::material_sha256.eq(material_sha256),
                conformance_leases::dynamic_registration_initial_access_token_sha256
                    .eq(dynamic_registration_initial_access_token_sha256),
                conformance_leases::ciba_automated_decision_token_sha256
                    .eq(ciba_automated_decision_token_sha256),
                conformance_leases::public_material.eq(public_material),
                conformance_leases::created_at.eq(now),
                conformance_leases::expires_at.eq(expires_at),
            ))
            .returning(ConformanceLease::as_returning())
            .get_result(&mut connection)
            .await
            .map_err(map_diesel_error)
    }

    pub async fn list(&self, tenant_id: Uuid) -> Result<Vec<ConformanceLease>, RepositoryError> {
        let mut connection = get_conn(&self.pool).await.map_err(map_pool_error)?;
        conformance_leases::table
            .filter(conformance_leases::tenant_id.eq(tenant_id))
            .order(conformance_leases::created_at.desc())
            .limit(100)
            .select(ConformanceLease::as_select())
            .load(&mut connection)
            .await
            .map_err(map_diesel_error)
    }

    pub async fn revoke(&self, tenant_id: Uuid, lease_id: Uuid) -> Result<i64, RepositoryError> {
        for _ in 0..CIBA_REVOKE_WAIT_ATTEMPTS {
            let mut connection = get_conn(&self.pool).await.map_err(map_pool_error)?;
            // Keep the lease row update first in this single statement. A
            // CIBA decision claim excludes this update until the callback has
            // completed or its bounded crash-recovery deadline has elapsed.
            let row = diesel::sql_query(
                r#"
                WITH revoked AS (
                    UPDATE conformance_leases
                    SET revoked_at = COALESCE(revoked_at, CURRENT_TIMESTAMP),
                        public_material = NULL
                    WHERE tenant_id = $1
                      AND id = $2
                      AND (ciba_decision_claim_id IS NULL
                           OR ciba_decision_claim_expires_at <= CURRENT_TIMESTAMP)
                    RETURNING id, tenant_id
                ), deactivated AS (
                    UPDATE oauth_clients client
                    SET is_active = FALSE, updated_at = CURRENT_TIMESTAMP
                    FROM revoked
                    WHERE client.tenant_id = revoked.tenant_id
                      AND client.conformance_lease_id = revoked.id
                    RETURNING client.id
                )
                SELECT EXISTS(SELECT 1 FROM revoked) AS found,
                       (SELECT COUNT(*) FROM deactivated)::BIGINT AS deactivated_clients
                "#,
            )
            .bind::<diesel::sql_types::Uuid, _>(tenant_id)
            .bind::<diesel::sql_types::Uuid, _>(lease_id)
            .get_result::<RevokeRow>(&mut connection)
            .await
            .map_err(map_diesel_error)?;
            if row.found {
                return Ok(row.deactivated_clients);
            }

            let status = diesel::sql_query(
                r#"
                SELECT ciba_decision_claim_expires_at
                FROM conformance_leases
                WHERE tenant_id = $1 AND id = $2
                "#,
            )
            .bind::<diesel::sql_types::Uuid, _>(tenant_id)
            .bind::<diesel::sql_types::Uuid, _>(lease_id)
            .get_result::<LeaseClaimStatusRow>(&mut connection)
            .await
            .optional()
            .map_err(map_diesel_error)?;
            let Some(status) = status else {
                return Err(RepositoryError::NotFound);
            };
            if status
                .ciba_decision_claim_expires_at
                .is_none_or(|expires_at| expires_at <= Utc::now())
            {
                // The row was present without a live claim but the update
                // raced another state transition. Retry through the same
                // single-statement boundary rather than reporting success.
                continue;
            }
            drop(connection);
            tokio::time::sleep(std::time::Duration::from_millis(CIBA_REVOKE_WAIT_MILLIS)).await;
        }
        Err(RepositoryError::Conflict)
    }

    pub async fn cleanup(&self) -> Result<ConformanceLeaseCleanup, RepositoryError> {
        let mut connection = get_conn(&self.pool).await.map_err(map_pool_error)?;
        let result = diesel::sql_query(
            "SELECT cleaned_leases, deleted_clients FROM nazo_oauth_cleanup_expired_conformance_leases()",
        )
        .get_result::<CleanupRow>(&mut connection)
        .await
        .map(|row| ConformanceLeaseCleanup {
            cleaned_leases: row.cleaned_leases,
            deleted_clients: row.deleted_clients,
        })
        .map_err(map_diesel_error)?;
        diesel::update(
            conformance_leases::table.filter(conformance_leases::cleaned_at.is_not_null()),
        )
        .set(conformance_leases::public_material.eq::<Option<Value>>(None))
        .execute(&mut connection)
        .await
        .map_err(map_diesel_error)?;
        Ok(result)
    }

    /// Resolves exactly one effective lease for the tenant, profile, and
    /// dynamic-registration credential digest. Duplicate matches indicate a
    /// corrupt capability boundary and fail closed.
    pub async fn active_dynamic_registration_lease_id(
        &self,
        tenant_id: Uuid,
        profile: &str,
        initial_access_token_sha256: &str,
    ) -> Result<Option<Uuid>, RepositoryError> {
        if profile != LEASED_DYNAMIC_REGISTRATION_PROFILE {
            return Err(RepositoryError::Consistency(
                "dynamic registration conformance lease lookup is only valid for the oidc-fapi-ciba profile"
                    .to_owned(),
            ));
        }
        let mut connection = get_conn(&self.pool).await.map_err(map_pool_error)?;
        let matches = diesel::sql_query(
            r#"
            SELECT id AS lease_id
            FROM conformance_leases
            WHERE tenant_id = $1
              AND profile = $2
              AND dynamic_registration_initial_access_token_sha256 = $3
              AND expires_at > CURRENT_TIMESTAMP
              AND revoked_at IS NULL
              AND cleaned_at IS NULL
            ORDER BY id
            LIMIT 2
            "#,
        )
        .bind::<diesel::sql_types::Uuid, _>(tenant_id)
        .bind::<diesel::sql_types::Text, _>(profile)
        .bind::<diesel::sql_types::Text, _>(initial_access_token_sha256)
        .load::<LeaseIdRow>(&mut connection)
        .await
        .map_err(map_diesel_error)?;
        match matches.as_slice() {
            [] => Ok(None),
            [lease] => Ok(Some(lease.lease_id)),
            _ => Err(RepositoryError::Consistency(
                "multiple active conformance leases matched one dynamic registration credential"
                    .to_owned(),
            )),
        }
    }

    /// Resolves exactly one effective lease for the tenant, profile, and
    /// per-run CIBA automated-decision credential digest. The caller must
    /// still verify that the transaction client is bound to the returned
    /// lease after loading the transaction state.
    pub async fn active_ciba_automated_decision_lease_id(
        &self,
        tenant_id: Uuid,
        profile: &str,
        token_sha256: &str,
    ) -> Result<Option<Uuid>, RepositoryError> {
        if profile != LEASED_DYNAMIC_REGISTRATION_PROFILE {
            return Err(RepositoryError::Consistency(
                "CIBA automated-decision token lookup is only valid for the oidc-fapi-ciba profile"
                    .to_owned(),
            ));
        }
        let mut connection = get_conn(&self.pool).await.map_err(map_pool_error)?;
        let matches = diesel::sql_query(
            r#"
            SELECT id AS lease_id
            FROM conformance_leases
            WHERE tenant_id = $1
              AND profile = $2
              AND ciba_automated_decision_token_sha256 = $3
              AND expires_at > CURRENT_TIMESTAMP
              AND revoked_at IS NULL
              AND cleaned_at IS NULL
            ORDER BY id
            LIMIT 2
            "#,
        )
        .bind::<diesel::sql_types::Uuid, _>(tenant_id)
        .bind::<diesel::sql_types::Text, _>(profile)
        .bind::<diesel::sql_types::Text, _>(token_sha256)
        .load::<LeaseIdRow>(&mut connection)
        .await
        .map_err(map_diesel_error)?;
        match matches.as_slice() {
            [] => Ok(None),
            [lease] => Ok(Some(lease.lease_id)),
            _ => Err(RepositoryError::Consistency(
                "multiple active conformance leases matched one CIBA automated-decision credential"
                    .to_owned(),
            )),
        }
    }

    /// Returns whether the exact tenant-scoped client is active and bound to
    /// the exact effective lease and profile resolved before transaction state
    /// access. This second check prevents one lease credential from approving
    /// another lease's client transaction.
    pub async fn active_for_client_lease_profile(
        &self,
        tenant_id: Uuid,
        client_id: &str,
        lease_id: Uuid,
        profile: &str,
    ) -> Result<bool, RepositoryError> {
        let mut connection = get_conn(&self.pool).await.map_err(map_pool_error)?;
        diesel::sql_query(
            r#"
            SELECT EXISTS(
                SELECT 1
                FROM oauth_clients client
                JOIN conformance_leases lease
                  ON lease.tenant_id = client.tenant_id
                 AND lease.id = client.conformance_lease_id
                WHERE client.tenant_id = $1
                  AND client.client_id = $2
                  AND client.is_active = TRUE
                  AND lease.id = $3
                  AND lease.profile = $4
                  AND lease.expires_at > CURRENT_TIMESTAMP
                  AND lease.revoked_at IS NULL
                  AND lease.cleaned_at IS NULL
            ) AS active
            "#,
        )
        .bind::<diesel::sql_types::Uuid, _>(tenant_id)
        .bind::<diesel::sql_types::Text, _>(client_id)
        .bind::<diesel::sql_types::Uuid, _>(lease_id)
        .bind::<diesel::sql_types::Text, _>(profile)
        .get_result::<ActiveLeaseRow>(&mut connection)
        .await
        .map(|row| row.active)
        .map_err(map_diesel_error)
    }

    /// Runs one CIBA decision under a short-lived PostgreSQL claim.
    ///
    /// The claim transaction ends before the callback starts, so token
    /// issuance may acquire another connection even when the pool has one
    /// connection. Revocation waits for the bounded claim deadline, and an
    /// expired claim is safely reclaimable after a process crash. The optional
    /// expected lease id is used by the per-run automated-decision credential;
    /// browser decisions pass `None` and use the client's current binding.
    pub async fn with_active_ciba_decision<F, Fut, T>(
        &self,
        tenant_id: Uuid,
        client_id: &str,
        expected_lease_id: Option<Uuid>,
        operation: F,
    ) -> Result<Option<T>, RepositoryError>
    where
        F: FnOnce(Option<i64>) -> Fut + Send,
        Fut: Future<Output = T> + Send,
        T: Send,
    {
        let claim_id = Uuid::now_v7();
        let now = Utc::now();
        let mut connection = get_conn(&self.pool).await.map_err(map_pool_error)?;
        let claim = connection
            .transaction::<CibaDecisionClaimOutcome, diesel::result::Error, _>(
                async move |connection| {
                    let initial = diesel::sql_query(
                        r#"
                        SELECT conformance_lease_id
                        FROM oauth_clients
                        WHERE tenant_id = $1 AND client_id = $2
                        "#,
                    )
                    .bind::<diesel::sql_types::Uuid, _>(tenant_id)
                    .bind::<diesel::sql_types::Text, _>(client_id)
                    .get_result::<ClientLeaseIdRow>(connection)
                    .await
                    .optional()?;
                    let Some(initial) = initial else {
                        return Ok(CibaDecisionClaimOutcome::Missing);
                    };
                    if expected_lease_id
                        .is_some_and(|expected| initial.conformance_lease_id != Some(expected))
                    {
                        return Ok(CibaDecisionClaimOutcome::Missing);
                    }

                    // Revocation and cleanup lock the lease before touching
                    // its clients. Follow that order here to avoid a lock
                    // inversion. The row lock is held only through the claim
                    // write, never through the callback.
                    let lease = if let Some(lease_id) = initial.conformance_lease_id {
                        let lease = diesel::sql_query(
                            r#"
                            SELECT expires_at,
                                   ciba_decision_claim_expires_at
                            FROM conformance_leases
                            WHERE tenant_id = $1
                              AND id = $2
                              AND expires_at > CURRENT_TIMESTAMP
                              AND revoked_at IS NULL
                              AND cleaned_at IS NULL
                            FOR UPDATE
                            "#,
                        )
                        .bind::<diesel::sql_types::Uuid, _>(tenant_id)
                        .bind::<diesel::sql_types::Uuid, _>(lease_id)
                        .get_result::<CibaDecisionLeaseRow>(connection)
                        .await
                        .optional()?;
                        let Some(lease) = lease else {
                            return Ok(CibaDecisionClaimOutcome::Missing);
                        };
                        if lease
                            .ciba_decision_claim_expires_at
                            .is_some_and(|expires_at| expires_at > now)
                        {
                            return Ok(CibaDecisionClaimOutcome::Busy);
                        }
                        Some((lease_id, lease.expires_at))
                    } else {
                        if expected_lease_id.is_some() {
                            return Ok(CibaDecisionClaimOutcome::Missing);
                        }
                        None
                    };

                    let client = diesel::sql_query(
                        r#"
                        SELECT is_active, conformance_lease_id
                        FROM oauth_clients
                        WHERE tenant_id = $1 AND client_id = $2
                        FOR UPDATE
                        "#,
                    )
                    .bind::<diesel::sql_types::Uuid, _>(tenant_id)
                    .bind::<diesel::sql_types::Text, _>(client_id)
                    .get_result::<CibaDecisionClientRow>(connection)
                    .await
                    .optional()?;
                    let Some(client) = client else {
                        return Ok(CibaDecisionClaimOutcome::Missing);
                    };
                    if !client.is_active
                        || client.conformance_lease_id != initial.conformance_lease_id
                        || expected_lease_id
                            .is_some_and(|expected| client.conformance_lease_id != Some(expected))
                    {
                        return Ok(CibaDecisionClaimOutcome::Missing);
                    }

                    let Some((lease_id, lease_expires_at)) = lease else {
                        return Ok(CibaDecisionClaimOutcome::Unleased);
                    };
                    let claim_expires_at = lease_expires_at.min(
                        now.checked_add_signed(Duration::seconds(CIBA_DECISION_CLAIM_SECONDS))
                            .unwrap_or(lease_expires_at),
                    );
                    if claim_expires_at <= now {
                        return Ok(CibaDecisionClaimOutcome::Missing);
                    }
                    diesel::sql_query(
                        r#"
                        UPDATE conformance_leases
                        SET ciba_decision_claim_id = $3,
                            ciba_decision_claim_expires_at = $4
                        WHERE tenant_id = $1 AND id = $2
                        "#,
                    )
                    .bind::<diesel::sql_types::Uuid, _>(tenant_id)
                    .bind::<diesel::sql_types::Uuid, _>(lease_id)
                    .bind::<diesel::sql_types::Uuid, _>(claim_id)
                    .bind::<diesel::sql_types::Timestamptz, _>(claim_expires_at)
                    .execute(connection)
                    .await?;
                    Ok(CibaDecisionClaimOutcome::Claimed {
                        lease_expires_at: claim_expires_at.timestamp(),
                        claim_id,
                    })
                },
            )
            .await
            .map_err(map_diesel_error)?;
        // The callback may use the same pool (including a pool with one
        // connection). Release the transaction connection before invoking it.
        drop(connection);

        match claim {
            CibaDecisionClaimOutcome::Missing => Ok(None),
            CibaDecisionClaimOutcome::Busy => Err(RepositoryError::Conflict),
            CibaDecisionClaimOutcome::Unleased => Ok(Some(operation(None).await)),
            CibaDecisionClaimOutcome::Claimed {
                lease_expires_at,
                claim_id,
            } => {
                let result = operation(Some(lease_expires_at)).await;
                let mut clear_connection = get_conn(&self.pool).await.map_err(map_pool_error)?;
                let cleared = diesel::sql_query(
                    r#"
                    UPDATE conformance_leases
                    SET ciba_decision_claim_id = NULL,
                        ciba_decision_claim_expires_at = NULL
                    WHERE tenant_id = $1 AND ciba_decision_claim_id = $2
                    "#,
                )
                .bind::<diesel::sql_types::Uuid, _>(tenant_id)
                .bind::<diesel::sql_types::Uuid, _>(claim_id)
                .execute(&mut clear_connection)
                .await
                .map_err(map_diesel_error)?;
                if cleared != 1 {
                    return Err(RepositoryError::Conflict);
                }
                Ok(Some(result))
            }
        }
    }

    pub async fn active_public_material_for_client(
        &self,
        tenant_id: Uuid,
        client_id: &str,
    ) -> Result<Option<Value>, RepositoryError> {
        let mut connection = get_conn(&self.pool).await.map_err(map_pool_error)?;
        diesel::sql_query(
            r#"
            SELECT lease.public_material
            FROM oauth_clients client
            JOIN conformance_leases lease
              ON lease.tenant_id = client.tenant_id
             AND lease.id = client.conformance_lease_id
            WHERE client.tenant_id = $1
              AND client.client_id = $2
              AND client.is_active = TRUE
              AND lease.expires_at > CURRENT_TIMESTAMP
              AND lease.revoked_at IS NULL
              AND lease.cleaned_at IS NULL
              AND lease.public_material IS NOT NULL
            "#,
        )
        .bind::<diesel::sql_types::Uuid, _>(tenant_id)
        .bind::<diesel::sql_types::Text, _>(client_id)
        .get_result::<PublicMaterialRow>(&mut connection)
        .await
        .optional()
        .map(|row| row.and_then(|row| row.public_material))
        .map_err(map_diesel_error)
    }

    /// Returns whether the tenant-scoped client is bound to an effective lease
    /// for the exact conformance profile.  This deliberately checks the
    /// binding and lease state in one database statement so callers cannot
    /// accidentally turn any active lease into a process-wide capability.
    pub async fn active_for_client_profile(
        &self,
        tenant_id: Uuid,
        client_id: &str,
        profile: &str,
    ) -> Result<bool, RepositoryError> {
        let mut connection = get_conn(&self.pool).await.map_err(map_pool_error)?;
        diesel::sql_query(
            r#"
            SELECT EXISTS(
                SELECT 1
                FROM oauth_clients client
                JOIN conformance_leases lease
                  ON lease.tenant_id = client.tenant_id
                 AND lease.id = client.conformance_lease_id
                WHERE client.tenant_id = $1
                  AND client.client_id = $2
                  AND client.is_active = TRUE
                  AND lease.profile = $3
                  AND lease.expires_at > CURRENT_TIMESTAMP
                  AND lease.revoked_at IS NULL
                  AND lease.cleaned_at IS NULL
            ) AS active
            "#,
        )
        .bind::<diesel::sql_types::Uuid, _>(tenant_id)
        .bind::<diesel::sql_types::Text, _>(client_id)
        .bind::<diesel::sql_types::Text, _>(profile)
        .get_result::<ActiveLeaseRow>(&mut connection)
        .await
        .map(|row| row.active)
        .map_err(map_diesel_error)
    }

    /// Resolve the one active lease bound to a client.  Automated CIBA
    /// transports use this to turn legacy header/query credentials into the
    /// same per-run lease capability as the default disabled transport.
    pub async fn active_lease_id_for_client(
        &self,
        tenant_id: Uuid,
        client_id: &str,
        profile: &str,
    ) -> Result<Option<Uuid>, RepositoryError> {
        let mut connection = get_conn(&self.pool).await.map_err(map_pool_error)?;
        let matches = diesel::sql_query(
            r#"
            SELECT lease.id AS lease_id
            FROM oauth_clients client
            JOIN conformance_leases lease
              ON lease.tenant_id = client.tenant_id
             AND lease.id = client.conformance_lease_id
            WHERE client.tenant_id = $1
              AND client.client_id = $2
              AND client.is_active = TRUE
              AND lease.profile = $3
              AND lease.expires_at > CURRENT_TIMESTAMP
              AND lease.revoked_at IS NULL
              AND lease.cleaned_at IS NULL
            LIMIT 2
            "#,
        )
        .bind::<diesel::sql_types::Uuid, _>(tenant_id)
        .bind::<diesel::sql_types::Text, _>(client_id)
        .bind::<diesel::sql_types::Text, _>(profile)
        .load::<LeaseIdRow>(&mut connection)
        .await
        .map_err(map_diesel_error)?;
        match matches.as_slice() {
            [] => Ok(None),
            [lease] => Ok(Some(lease.lease_id)),
            _ => Err(RepositoryError::Consistency(
                "multiple active conformance leases matched one client".to_owned(),
            )),
        }
    }

    pub async fn active_public_materials_for_profile(
        &self,
        tenant_id: Uuid,
        profile: &str,
    ) -> Result<Vec<ConformanceLeasePublicMaterial>, RepositoryError> {
        let mut connection = get_conn(&self.pool).await.map_err(map_pool_error)?;
        diesel::sql_query(
            r#"
            SELECT id AS lease_id, public_material
            FROM conformance_leases
            WHERE tenant_id = $1
              AND profile = $2
              AND expires_at > CURRENT_TIMESTAMP
              AND revoked_at IS NULL
              AND cleaned_at IS NULL
              AND public_material IS NOT NULL
            ORDER BY created_at, id
            "#,
        )
        .bind::<diesel::sql_types::Uuid, _>(tenant_id)
        .bind::<diesel::sql_types::Text, _>(profile)
        .load(&mut connection)
        .await
        .map_err(map_diesel_error)
    }

    pub async fn active_public_material_for_lease(
        &self,
        tenant_id: Uuid,
        lease_id: Uuid,
    ) -> Result<Option<Value>, RepositoryError> {
        let mut connection = get_conn(&self.pool).await.map_err(map_pool_error)?;
        diesel::sql_query(
            r#"
            SELECT public_material
            FROM conformance_leases
            WHERE tenant_id = $1
              AND id = $2
              AND expires_at > CURRENT_TIMESTAMP
              AND revoked_at IS NULL
              AND cleaned_at IS NULL
              AND public_material IS NOT NULL
            "#,
        )
        .bind::<diesel::sql_types::Uuid, _>(tenant_id)
        .bind::<diesel::sql_types::Uuid, _>(lease_id)
        .get_result::<PublicMaterialRow>(&mut connection)
        .await
        .optional()
        .map(|row| row.and_then(|row| row.public_material))
        .map_err(map_diesel_error)
    }
}

#[derive(diesel::QueryableByName)]
struct RevokeRow {
    #[diesel(sql_type = diesel::sql_types::Bool)]
    found: bool,
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    deactivated_clients: i64,
}

#[derive(diesel::QueryableByName)]
struct CleanupRow {
    #[diesel(sql_type = diesel::sql_types::Integer)]
    cleaned_leases: i32,
    #[diesel(sql_type = diesel::sql_types::Integer)]
    deleted_clients: i32,
}

#[derive(diesel::QueryableByName)]
struct PublicMaterialRow {
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Jsonb>)]
    public_material: Option<Value>,
}

#[derive(diesel::QueryableByName)]
struct ActiveLeaseRow {
    #[diesel(sql_type = diesel::sql_types::Bool)]
    active: bool,
}

#[derive(diesel::QueryableByName)]
struct LeaseIdRow {
    #[diesel(sql_type = diesel::sql_types::Uuid)]
    lease_id: Uuid,
}

#[derive(diesel::QueryableByName)]
struct ClientLeaseIdRow {
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Uuid>)]
    conformance_lease_id: Option<Uuid>,
}

#[derive(diesel::QueryableByName)]
struct CibaDecisionLeaseRow {
    #[diesel(sql_type = diesel::sql_types::Timestamptz)]
    expires_at: DateTime<Utc>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Timestamptz>)]
    ciba_decision_claim_expires_at: Option<DateTime<Utc>>,
}

#[derive(diesel::QueryableByName)]
struct LeaseClaimStatusRow {
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Timestamptz>)]
    ciba_decision_claim_expires_at: Option<DateTime<Utc>>,
}

#[derive(diesel::QueryableByName)]
struct CibaDecisionClientRow {
    #[diesel(sql_type = diesel::sql_types::Bool)]
    is_active: bool,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Uuid>)]
    conformance_lease_id: Option<Uuid>,
}

enum CibaDecisionClaimOutcome {
    Missing,
    Busy,
    Unleased,
    Claimed {
        lease_expires_at: i64,
        claim_id: Uuid,
    },
}

fn map_pool_error(error: anyhow::Error) -> RepositoryError {
    RepositoryError::Unexpected(error.to_string())
}

fn map_diesel_error(error: diesel::result::Error) -> RepositoryError {
    match error {
        diesel::result::Error::DatabaseError(
            diesel::result::DatabaseErrorKind::UniqueViolation,
            _,
        ) => RepositoryError::Conflict,
        diesel::result::Error::DatabaseError(
            diesel::result::DatabaseErrorKind::CheckViolation,
            details,
        ) => RepositoryError::Consistency(details.message().to_owned()),
        other => RepositoryError::Unexpected(other.to_string()),
    }
}
