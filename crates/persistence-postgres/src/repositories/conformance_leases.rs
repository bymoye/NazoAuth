use chrono::{DateTime, Duration, Utc};
use diesel::{ExpressionMethods, OptionalExtension, QueryDsl, SelectableHelper, sql_query};
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl};
use nazo_auth::PreparedClientRegistration;
use nazo_identity::{
    TenantContext,
    ports::{PasswordHashInput, RepositoryError},
};
use serde_json::Value;
use std::{
    collections::{HashMap, HashSet},
    future::Future,
};
use uuid::Uuid;

use crate::{
    DbPool, get_conn,
    repositories::{
        access_requests::insert_client,
        mtls_trust::{
            ConformanceApprovedTrustAnchor, insert_conformance_approved_trust_anchor_on_connection,
        },
        users::insert_conformance_applicant_on_connection,
    },
    schema::{conformance_lease_applicants, conformance_lease_clients, conformance_leases},
};

pub const MIN_CONFORMANCE_LEASE_SECONDS: i64 = 60;
pub const MAX_CONFORMANCE_LEASE_SECONDS: i64 = 24 * 60 * 60;
const LEASED_DYNAMIC_REGISTRATION_PROFILE: &str = "oidc-fapi-ciba";
const CIBA_DECISION_CLAIM_SECONDS: i64 = 30;
// One immediate attempt plus 120 quarter-second waits covers the full
// thirty-second claim deadline before returning a bounded conflict.
const CIBA_REVOKE_WAIT_ATTEMPTS: usize = 121;
const CIBA_REVOKE_WAIT_MILLIS: u64 = 250;
const MAX_ONBOARDING_CLIENTS: usize = 512;
const MAX_ONBOARDING_TASK_JTI_BYTES: usize = 255;
const MAX_ONBOARDING_LOGICAL_ID_BYTES: usize = 128;
const ATOMIC_CONFORMANCE_PROFILE: &str = "nazoauth-full";

/// Input to the one-transaction conformance provisioning boundary.  The
/// bundle has already been parsed and cryptographically verified by the
/// operator layer; persistence still binds its canonical digest and checks all
/// tenant/role/foreign-key invariants before writing.
#[derive(Clone)]
pub struct ConformanceOnboardingRequest {
    pub tenant: TenantContext,
    pub task_jti: String,
    pub profile: String,
    pub bundle_schema: i32,
    pub bundle_sha256: String,
    pub material_sha256: String,
    /// Canonical HTTPS origin of the Suite used for this run.
    pub suite_origin: String,
    /// DCR initial-access token digest; plaintext token material is never
    /// accepted by this persistence boundary.
    pub dynamic_registration_initial_access_token_sha256: Option<String>,
    /// CIBA automated-decision token digest; plaintext token material is never
    /// accepted by this persistence boundary.
    pub ciba_automated_decision_token_sha256: Option<String>,
    pub client_count: i32,
    pub ttl_seconds: i64,
    pub applicant: ConformanceApplicant,
    pub clients: Vec<ConformanceClient>,
    pub mtls_trust_anchors: Vec<ConformanceMtlsTrustAnchor>,
}

impl std::fmt::Debug for ConformanceOnboardingRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ConformanceOnboardingRequest")
            .field("tenant", &self.tenant)
            .field("task_jti", &self.task_jti)
            .field("profile", &self.profile)
            .field("bundle_schema", &self.bundle_schema)
            .field("bundle_sha256", &self.bundle_sha256)
            .field("material_sha256", &self.material_sha256)
            .field("suite_origin", &self.suite_origin)
            .field(
                "dynamic_registration_initial_access_token_sha256",
                &self
                    .dynamic_registration_initial_access_token_sha256
                    .as_ref()
                    .map(|_| "[REDACTED]"),
            )
            .field(
                "ciba_automated_decision_token_sha256",
                &self
                    .ciba_automated_decision_token_sha256
                    .as_ref()
                    .map(|_| "[REDACTED]"),
            )
            .field("client_count", &self.client_count)
            .field("ttl_seconds", &self.ttl_seconds)
            .field("applicant", &self.applicant)
            .field("clients", &self.clients)
            .field("mtls_trust_anchors", &self.mtls_trust_anchors)
            .finish()
    }
}

#[derive(Clone)]
pub struct ConformanceApplicant {
    pub username: String,
    pub email: String,
    pub password_hash: PasswordHashInput,
    pub email_verified: bool,
}

impl std::fmt::Debug for ConformanceApplicant {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ConformanceApplicant")
            .field("username", &self.username)
            .field("email", &self.email)
            .field("password_hash", &"[REDACTED]")
            .field("email_verified", &self.email_verified)
            .finish()
    }
}

#[derive(Clone, Debug)]
pub struct ConformanceClient {
    pub logical_client_id: String,
    pub prepared: PreparedClientRegistration,
}

#[derive(Clone, Debug)]
pub struct ConformanceMtlsTrustAnchor {
    pub logical_client_id: String,
    pub certificate_pem: String,
    pub certificate_sha256: String,
    pub subject_dn: String,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConformanceOnboardingResult {
    pub lease_id: Uuid,
    pub applicant_user_id: Option<Uuid>,
    pub client_mappings: Vec<ConformanceClientMapping>,
    pub client_count: i32,
    pub bundle_sha256: String,
    pub suite_origin: String,
    pub expires_at: DateTime<Utc>,
    pub idempotent_replay: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConformanceClientMapping {
    pub logical_client_id: String,
    /// Public OAuth client identifier. The database primary key is retained
    /// only inside the transaction for foreign-key and mTLS operations.
    pub client_id: String,
}

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
    pub task_jti: String,
    pub bundle_schema: i32,
    pub bundle_sha256: String,
    pub client_count: i32,
    pub suite_origin: Option<String>,
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

    /// Atomically provisions one conformance run.  The task JTI is the
    /// tenant-scoped idempotency key; `bundle_sha256` and the semantic fields
    /// are compared on every replay before any existing rows are returned.
    ///
    /// The transaction writes the lease, ordinary applicant, lease-bound
    /// clients, and explicitly sourced operator mTLS trust state.  No
    /// repository called here acquires its own connection, so a failed step
    /// rolls all preceding writes back together.
    pub async fn onboard(
        &self,
        request: ConformanceOnboardingRequest,
    ) -> Result<ConformanceOnboardingResult, RepositoryError> {
        let mut request = request;
        request.suite_origin = canonicalize_suite_origin(&request.suite_origin)?;
        validate_onboarding_request(&request)?;
        let mut connection = get_conn(&self.pool).await.map_err(map_pool_error)?;
        let request = request.clone();
        connection
            .transaction::<ConformanceOnboardingResult, OnboardingTxError, _>(
                async move |connection| {
                    let existing = sql_query(
                        "SELECT id, tenant_id, profile, material_sha256,
                                dynamic_registration_initial_access_token_sha256,
                                ciba_automated_decision_token_sha256,
                                expires_at, revoked_at, cleaned_at,
                                task_jti, bundle_schema, bundle_sha256, client_count,
                                suite_origin
                         FROM conformance_leases
                         WHERE tenant_id = $1 AND task_jti = $2
                         FOR UPDATE",
                    )
                    .bind::<diesel::sql_types::Uuid, _>(request.tenant.tenant_id.as_uuid())
                    .bind::<diesel::sql_types::Text, _>(&request.task_jti)
                    .get_result::<OnboardingLeaseRow>(connection)
                    .await
                    .optional()?;

                    if let Some(existing) = existing {
                        return replay_or_conflict(connection, &request, existing).await;
                    }

                    let lease_id = Uuid::now_v7();
                    let now = Utc::now();
                    let expires_at = now
                        .checked_add_signed(Duration::seconds(request.ttl_seconds))
                        .ok_or_else(|| {
                            OnboardingTxError::Repository(RepositoryError::Consistency(
                                "conformance onboarding ttl overflow".to_owned(),
                            ))
                        })?;
                    let inserted = sql_query(
                        "INSERT INTO conformance_leases (
                             id, tenant_id, profile, material_sha256,
                             dynamic_registration_initial_access_token_sha256,
                             ciba_automated_decision_token_sha256,
                             created_at, expires_at, task_jti, bundle_schema,
                             bundle_sha256, client_count, suite_origin, public_material
                         ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, NULL)
                         ON CONFLICT (tenant_id, task_jti) DO NOTHING
                         RETURNING id, tenant_id, profile, material_sha256,
                                   dynamic_registration_initial_access_token_sha256,
                                   ciba_automated_decision_token_sha256,
                                   expires_at, revoked_at, cleaned_at,
                                   task_jti, bundle_schema, bundle_sha256,
                                   client_count, suite_origin",
                    )
                    .bind::<diesel::sql_types::Uuid, _>(lease_id)
                    .bind::<diesel::sql_types::Uuid, _>(request.tenant.tenant_id.as_uuid())
                    .bind::<diesel::sql_types::Text, _>(&request.profile)
                    .bind::<diesel::sql_types::Text, _>(&request.material_sha256)
                    .bind::<diesel::sql_types::Nullable<diesel::sql_types::Text>, _>(
                        request
                            .dynamic_registration_initial_access_token_sha256
                            .as_deref(),
                    )
                    .bind::<diesel::sql_types::Nullable<diesel::sql_types::Text>, _>(
                        request.ciba_automated_decision_token_sha256.as_deref(),
                    )
                    .bind::<diesel::sql_types::Timestamptz, _>(now)
                    .bind::<diesel::sql_types::Timestamptz, _>(expires_at)
                    .bind::<diesel::sql_types::Text, _>(&request.task_jti)
                    .bind::<diesel::sql_types::Integer, _>(request.bundle_schema)
                    .bind::<diesel::sql_types::Text, _>(&request.bundle_sha256)
                    .bind::<diesel::sql_types::Integer, _>(request.client_count)
                    .bind::<diesel::sql_types::Text, _>(&request.suite_origin)
                    .get_result::<OnboardingLeaseRow>(connection)
                    .await
                    .optional()?;
                    let Some(lease) = inserted else {
                        // A concurrent transaction won the unique key race.
                        // It committed before the INSERT returned, so the
                        // locked replay path is now deterministic.
                        let existing = sql_query(
                            "SELECT id, tenant_id, profile, material_sha256,
                                    dynamic_registration_initial_access_token_sha256,
                                    ciba_automated_decision_token_sha256,
                                    expires_at, revoked_at, cleaned_at,
                                    task_jti, bundle_schema, bundle_sha256,
                                    client_count, suite_origin
                             FROM conformance_leases
                             WHERE tenant_id = $1 AND task_jti = $2
                             FOR UPDATE",
                        )
                        .bind::<diesel::sql_types::Uuid, _>(request.tenant.tenant_id.as_uuid())
                        .bind::<diesel::sql_types::Text, _>(&request.task_jti)
                        .get_result::<OnboardingLeaseRow>(connection)
                        .await?;
                        return replay_or_conflict(connection, &request, existing).await;
                    };

                    let applicant_user_id = insert_conformance_applicant_on_connection(
                        connection,
                        request.tenant,
                        &request.applicant.username,
                        &request.applicant.email,
                        request.applicant.password_hash.clone(),
                        request.applicant.email_verified,
                    )
                    .await?;
                    diesel::insert_into(conformance_lease_applicants::table)
                        .values((
                            conformance_lease_applicants::tenant_id
                                .eq(request.tenant.tenant_id.as_uuid()),
                            conformance_lease_applicants::lease_id.eq(lease.id),
                            conformance_lease_applicants::applicant_user_id.eq(applicant_user_id),
                        ))
                        .execute(connection)
                        .await?;

                    let mut client_mappings = Vec::with_capacity(request.clients.len());
                    let mut client_storage_ids = HashMap::with_capacity(request.clients.len());
                    for client in &request.clients {
                        let mut prepared = client.prepared.clone();
                        prepared.conformance_lease_id = Some(lease.id);
                        let approved = insert_client(connection, request.tenant, &prepared)
                            .await
                            .map_err(OnboardingTxError::Repository)?;
                        if approved.client_id.as_str() != prepared.registration.client_id.as_str() {
                            return Err(OnboardingTxError::Repository(
                                RepositoryError::Consistency(
                                    "persistence returned a different public client ID".to_owned(),
                                ),
                            ));
                        }
                        diesel::insert_into(conformance_lease_clients::table)
                            .values((
                                conformance_lease_clients::tenant_id
                                    .eq(request.tenant.tenant_id.as_uuid()),
                                conformance_lease_clients::lease_id.eq(lease.id),
                                conformance_lease_clients::logical_client_id
                                    .eq(&client.logical_client_id),
                                conformance_lease_clients::client_id.eq(approved.id),
                            ))
                            .execute(connection)
                            .await?;
                        client_storage_ids.insert(client.logical_client_id.clone(), approved.id);
                        client_mappings.push(ConformanceClientMapping {
                            logical_client_id: client.logical_client_id.clone(),
                            client_id: approved.client_id,
                        });
                    }

                    for anchor in &request.mtls_trust_anchors {
                        let client_id = client_storage_ids
                            .get(&anchor.logical_client_id)
                            .copied()
                            .ok_or_else(|| {
                                OnboardingTxError::Repository(RepositoryError::Consistency(
                                    "conformance trust anchor references an unknown logical client"
                                        .to_owned(),
                                ))
                            })?;
                        insert_conformance_approved_trust_anchor_on_connection(
                            connection,
                            ConformanceApprovedTrustAnchor {
                                tenant_id: request.tenant.tenant_id,
                                applicant_user_id,
                                client_id,
                                certificate_pem: &anchor.certificate_pem,
                                certificate_sha256: &anchor.certificate_sha256,
                                subject_dn: &anchor.subject_dn,
                                not_before: anchor.not_before,
                                not_after: anchor.not_after,
                            },
                        )
                        .await
                        .map_err(OnboardingTxError::Repository)?;
                    }

                    Ok(ConformanceOnboardingResult {
                        lease_id: lease.id,
                        applicant_user_id: Some(applicant_user_id),
                        client_mappings,
                        client_count: request.client_count,
                        bundle_sha256: request.bundle_sha256,
                        suite_origin: lease.suite_origin.clone().ok_or_else(|| {
                            OnboardingTxError::Repository(RepositoryError::Consistency(
                                "new conformance lease is missing its Suite origin".to_owned(),
                            ))
                        })?,
                        expires_at: lease.expires_at,
                        idempotent_replay: false,
                    })
                },
            )
            .await
            .map_err(OnboardingTxError::into_repository)
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
        let lease_id = Uuid::now_v7();
        let mut connection = get_conn(&self.pool).await.map_err(map_pool_error)?;
        diesel::insert_into(conformance_leases::table)
            .values((
                conformance_leases::id.eq(lease_id),
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
                conformance_leases::task_jti.eq(format!("legacy:{lease_id}")),
                conformance_leases::bundle_schema.eq(1),
                conformance_leases::bundle_sha256.eq(material_sha256),
                conformance_leases::client_count.eq(0),
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

    /// Resolves exactly one active atomic lease for a canonical Suite origin.
    /// Legacy leases have no origin and are deliberately excluded; accepting
    /// an unscoped legacy match would make Suite credentials ambiguous.
    pub async fn active_lease_for_suite_origin(
        &self,
        tenant_id: Uuid,
        profile: &str,
        suite_origin: &str,
    ) -> Result<Option<Uuid>, RepositoryError> {
        if profile != ATOMIC_CONFORMANCE_PROFILE {
            return Err(RepositoryError::Consistency(
                "suite-origin lookup only supports the nazoauth-full profile".to_owned(),
            ));
        }
        let suite_origin = canonicalize_suite_origin(suite_origin)?;
        let mut connection = get_conn(&self.pool).await.map_err(map_pool_error)?;
        let matches = diesel::sql_query(
            r#"
            SELECT id AS lease_id
            FROM conformance_leases
            WHERE tenant_id = $1
              AND profile = $2
              AND suite_origin = $3
              AND expires_at > CURRENT_TIMESTAMP
              AND revoked_at IS NULL
              AND cleaned_at IS NULL
            ORDER BY created_at, id
            LIMIT 2
            "#,
        )
        .bind::<diesel::sql_types::Uuid, _>(tenant_id)
        .bind::<diesel::sql_types::Text, _>(profile)
        .bind::<diesel::sql_types::Text, _>(&suite_origin)
        .load::<LeaseIdRow>(&mut connection)
        .await
        .map_err(map_diesel_error)?;
        match matches.as_slice() {
            [] => Ok(None),
            [lease] => Ok(Some(lease.lease_id)),
            _ => Err(RepositoryError::Consistency(
                "multiple active nazoauth-full leases matched one Suite origin".to_owned(),
            )),
        }
    }

    /// Resolves exactly one effective lease for the tenant and
    /// dynamic-registration credential digest across the supported lease
    /// profiles. The digest is tenant-unique, so profile selection must not
    /// hide the lease that owns the capability.
    pub async fn active_dynamic_registration_lease_id(
        &self,
        tenant_id: Uuid,
        initial_access_token_sha256: &str,
    ) -> Result<Option<Uuid>, RepositoryError> {
        let mut connection = get_conn(&self.pool).await.map_err(map_pool_error)?;
        let matches = diesel::sql_query(
            r#"
            SELECT id AS lease_id
            FROM conformance_leases
            WHERE tenant_id = $1
              AND profile IN ($2, $3)
              AND dynamic_registration_initial_access_token_sha256 = $4
              AND expires_at > CURRENT_TIMESTAMP
              AND revoked_at IS NULL
              AND cleaned_at IS NULL
            ORDER BY id
            LIMIT 2
            "#,
        )
        .bind::<diesel::sql_types::Uuid, _>(tenant_id)
        .bind::<diesel::sql_types::Text, _>(LEASED_DYNAMIC_REGISTRATION_PROFILE)
        .bind::<diesel::sql_types::Text, _>(ATOMIC_CONFORMANCE_PROFILE)
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

    /// Resolves exactly one effective lease for the tenant and per-run CIBA
    /// automated-decision credential digest across the supported lease
    /// profiles. The caller must still verify the transaction client binding.
    pub async fn active_ciba_automated_decision_lease_id(
        &self,
        tenant_id: Uuid,
        token_sha256: &str,
    ) -> Result<Option<Uuid>, RepositoryError> {
        let mut connection = get_conn(&self.pool).await.map_err(map_pool_error)?;
        let matches = diesel::sql_query(
            r#"
            SELECT id AS lease_id
            FROM conformance_leases
            WHERE tenant_id = $1
              AND profile IN ($2, $3)
              AND ciba_automated_decision_token_sha256 = $4
              AND expires_at > CURRENT_TIMESTAMP
              AND revoked_at IS NULL
              AND cleaned_at IS NULL
            ORDER BY id
            LIMIT 2
            "#,
        )
        .bind::<diesel::sql_types::Uuid, _>(tenant_id)
        .bind::<diesel::sql_types::Text, _>(LEASED_DYNAMIC_REGISTRATION_PROFILE)
        .bind::<diesel::sql_types::Text, _>(ATOMIC_CONFORMANCE_PROFILE)
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
struct OnboardingLeaseRow {
    #[diesel(sql_type = diesel::sql_types::Uuid)]
    id: Uuid,
    #[diesel(sql_type = diesel::sql_types::Uuid)]
    tenant_id: Uuid,
    #[diesel(sql_type = diesel::sql_types::Text)]
    profile: String,
    #[diesel(sql_type = diesel::sql_types::Text)]
    material_sha256: String,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Text>)]
    dynamic_registration_initial_access_token_sha256: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Text>)]
    ciba_automated_decision_token_sha256: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Timestamptz)]
    expires_at: DateTime<Utc>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Timestamptz>)]
    revoked_at: Option<DateTime<Utc>>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Timestamptz>)]
    cleaned_at: Option<DateTime<Utc>>,
    #[diesel(sql_type = diesel::sql_types::Text)]
    task_jti: String,
    #[diesel(sql_type = diesel::sql_types::Integer)]
    bundle_schema: i32,
    #[diesel(sql_type = diesel::sql_types::Text)]
    bundle_sha256: String,
    #[diesel(sql_type = diesel::sql_types::Integer)]
    client_count: i32,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Text>)]
    suite_origin: Option<String>,
}

#[derive(diesel::QueryableByName)]
struct ApplicantOwnerRow {
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Uuid>)]
    applicant_user_id: Option<Uuid>,
}

#[derive(diesel::QueryableByName)]
struct ClientMappingRow {
    #[diesel(sql_type = diesel::sql_types::Text)]
    logical_client_id: String,
    #[diesel(sql_type = diesel::sql_types::Uuid)]
    storage_client_id: Uuid,
    #[diesel(sql_type = diesel::sql_types::Text)]
    public_client_id: String,
    #[diesel(sql_type = diesel::sql_types::Bool)]
    client_is_active: bool,
}

#[derive(diesel::QueryableByName)]
struct MtlsAnchorReplayRow {
    #[diesel(sql_type = diesel::sql_types::Uuid)]
    client_id: Uuid,
    #[diesel(sql_type = diesel::sql_types::Text)]
    certificate_sha256: String,
    #[diesel(sql_type = diesel::sql_types::Text)]
    source: String,
    #[diesel(sql_type = diesel::sql_types::SmallInt)]
    status: i16,
    #[diesel(sql_type = diesel::sql_types::Bool)]
    active: bool,
}

async fn replay_or_conflict(
    connection: &mut AsyncPgConnection,
    request: &ConformanceOnboardingRequest,
    existing: OnboardingLeaseRow,
) -> Result<ConformanceOnboardingResult, OnboardingTxError> {
    if existing.tenant_id != request.tenant.tenant_id.as_uuid()
        || existing.task_jti != request.task_jti
        || existing.profile != request.profile
        || existing.material_sha256 != request.material_sha256
        || existing.dynamic_registration_initial_access_token_sha256
            != request.dynamic_registration_initial_access_token_sha256
        || existing.ciba_automated_decision_token_sha256
            != request.ciba_automated_decision_token_sha256
        || existing.bundle_schema != request.bundle_schema
        || existing.bundle_sha256 != request.bundle_sha256
        || existing.client_count != request.client_count
        || existing.suite_origin.as_deref() != Some(request.suite_origin.as_str())
    {
        return Err(OnboardingTxError::Repository(RepositoryError::Conflict));
    }
    if existing.expires_at <= Utc::now()
        || existing.revoked_at.is_some()
        || existing.cleaned_at.is_some()
    {
        return Err(OnboardingTxError::Repository(RepositoryError::Conflict));
    }
    let owner = sql_query(
        "SELECT owner.applicant_user_id
         FROM conformance_lease_applicants owner
         JOIN users applicant
           ON applicant.tenant_id = owner.tenant_id
          AND applicant.id = owner.applicant_user_id
          AND applicant.is_active = TRUE
          AND applicant.role = 'user'
          AND applicant.admin_level = 0
         WHERE owner.tenant_id = $1 AND owner.lease_id = $2
           AND owner.cleaned_at IS NULL
           AND owner.deleted_at IS NULL",
    )
    .bind::<diesel::sql_types::Uuid, _>(request.tenant.tenant_id.as_uuid())
    .bind::<diesel::sql_types::Uuid, _>(existing.id)
    .get_result::<ApplicantOwnerRow>(connection)
    .await
    .optional()?;
    let mappings = sql_query(
        "SELECT mapping.logical_client_id, mapping.client_id AS storage_client_id,
                client.client_id AS public_client_id,
                client.is_active AS client_is_active
         FROM conformance_lease_clients mapping
         JOIN oauth_clients client
           ON client.tenant_id = mapping.tenant_id
          AND client.id = mapping.client_id
          AND client.conformance_lease_id = mapping.lease_id
         WHERE mapping.tenant_id = $1 AND mapping.lease_id = $2
           AND client.is_active = TRUE
         ORDER BY mapping.logical_client_id",
    )
    .bind::<diesel::sql_types::Uuid, _>(request.tenant.tenant_id.as_uuid())
    .bind::<diesel::sql_types::Uuid, _>(existing.id)
    .load::<ClientMappingRow>(connection)
    .await?;
    let Some(owner) = owner.filter(|owner| owner.applicant_user_id.is_some()) else {
        return Err(OnboardingTxError::Repository(RepositoryError::Consistency(
            "conformance lease is missing its live onboarding applicant".to_owned(),
        )));
    };
    if mappings.len() != request.clients.len() {
        return Err(OnboardingTxError::Repository(RepositoryError::Consistency(
            "conformance lease is missing its onboarding ownership rows".to_owned(),
        )));
    }
    let mut by_logical_id = HashMap::with_capacity(mappings.len());
    for mapping in mappings {
        if !mapping.client_is_active
            || by_logical_id
                .insert(
                    mapping.logical_client_id,
                    (mapping.storage_client_id, mapping.public_client_id),
                )
                .is_some()
        {
            return Err(OnboardingTxError::Repository(RepositoryError::Consistency(
                "conformance lease client ownership mapping is inconsistent".to_owned(),
            )));
        }
    }
    let mut client_mappings = Vec::with_capacity(request.clients.len());
    let mut client_storage_ids = HashMap::with_capacity(request.clients.len());
    for client in &request.clients {
        let Some((storage_client_id, public_client_id)) =
            by_logical_id.remove(&client.logical_client_id)
        else {
            return Err(OnboardingTxError::Repository(RepositoryError::Consistency(
                "conformance lease client logical IDs do not match the onboarding bundle"
                    .to_owned(),
            )));
        };
        if client.prepared.registration.client_id.as_str() != public_client_id.as_str() {
            return Err(OnboardingTxError::Repository(RepositoryError::Consistency(
                "conformance lease public client IDs do not match the onboarding bundle".to_owned(),
            )));
        }
        client_storage_ids.insert(client.logical_client_id.clone(), storage_client_id);
        client_mappings.push(ConformanceClientMapping {
            logical_client_id: client.logical_client_id.clone(),
            client_id: public_client_id,
        });
    }
    if !by_logical_id.is_empty() {
        return Err(OnboardingTxError::Repository(RepositoryError::Consistency(
            "conformance lease contains an unexpected logical client mapping".to_owned(),
        )));
    }
    let mut expected_anchors = HashMap::with_capacity(request.mtls_trust_anchors.len());
    for anchor in &request.mtls_trust_anchors {
        let Some(client_id) = client_storage_ids.get(&anchor.logical_client_id).copied() else {
            return Err(OnboardingTxError::Repository(RepositoryError::Consistency(
                "conformance trust anchor references an unknown logical client".to_owned(),
            )));
        };
        expected_anchors.insert(client_id, anchor.certificate_sha256.as_str());
    }
    let persisted_anchors = sql_query(
        "SELECT request.client_id, request.certificate_sha256, request.source,
                request.status,
                (request.status = 1
                 AND request.source = 'operator-conformance'
                 AND request.not_before <= CURRENT_TIMESTAMP
                 AND request.not_after > CURRENT_TIMESTAMP) AS active
         FROM oauth_client_mtls_trust_anchor_requests request
         JOIN conformance_lease_clients mapping
           ON mapping.tenant_id = request.tenant_id
          AND mapping.lease_id = $2
          AND mapping.client_id = request.client_id
         WHERE request.tenant_id = $1",
    )
    .bind::<diesel::sql_types::Uuid, _>(request.tenant.tenant_id.as_uuid())
    .bind::<diesel::sql_types::Uuid, _>(existing.id)
    .load::<MtlsAnchorReplayRow>(connection)
    .await?;
    if persisted_anchors.len() != expected_anchors.len() {
        return Err(OnboardingTxError::Repository(RepositoryError::Consistency(
            "conformance lease trust-anchor ownership rows are incomplete".to_owned(),
        )));
    }
    for anchor in persisted_anchors {
        let Some(expected_digest) = expected_anchors.remove(&anchor.client_id) else {
            return Err(OnboardingTxError::Repository(RepositoryError::Consistency(
                "conformance lease contains an unexpected trust-anchor row".to_owned(),
            )));
        };
        if !anchor.active
            || anchor.status != 1
            || anchor.source != "operator-conformance"
            || anchor.certificate_sha256.as_str() != expected_digest
        {
            return Err(OnboardingTxError::Repository(RepositoryError::Consistency(
                "conformance lease trust-anchor row is inconsistent".to_owned(),
            )));
        }
    }
    if !expected_anchors.is_empty() {
        return Err(OnboardingTxError::Repository(RepositoryError::Consistency(
            "conformance lease trust-anchor rows are missing".to_owned(),
        )));
    }
    Ok(ConformanceOnboardingResult {
        lease_id: existing.id,
        applicant_user_id: owner.applicant_user_id,
        client_mappings,
        client_count: existing.client_count,
        bundle_sha256: existing.bundle_sha256,
        suite_origin: existing.suite_origin.clone().ok_or_else(|| {
            OnboardingTxError::Repository(RepositoryError::Consistency(
                "conformance lease is missing its Suite origin".to_owned(),
            ))
        })?,
        expires_at: existing.expires_at,
        idempotent_replay: true,
    })
}

/// Canonicalizes the Suite origin without accepting credentials, paths, query
/// strings, fragments, or an unusable port. `url::Origin` is the single parser
/// for DNS, IPv4, IPv6, IDNA, host case, and default-port normalization.
pub fn canonicalize_suite_origin(value: &str) -> Result<String, RepositoryError> {
    if value.is_empty()
        || value.len() > 2048
        || value != value.trim()
        || value.chars().any(char::is_control)
    {
        return Err(RepositoryError::Consistency(
            "conformance Suite origin is invalid".to_owned(),
        ));
    }
    let parsed = url::Url::parse(value).map_err(|_| {
        RepositoryError::Consistency("conformance Suite origin is invalid".to_owned())
    })?;
    if parsed.scheme() != "https"
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || parsed.cannot_be_a_base()
        || parsed.host().is_none()
        || parsed.port() == Some(0)
        || parsed.path() != "/"
    {
        return Err(RepositoryError::Consistency(
            "conformance Suite origin must be an HTTPS origin without credentials, path, query, or fragment"
                .to_owned(),
        ));
    }
    Ok(parsed.origin().ascii_serialization())
}

fn validate_onboarding_request(
    request: &ConformanceOnboardingRequest,
) -> Result<(), RepositoryError> {
    if canonicalize_suite_origin(&request.suite_origin)? != request.suite_origin {
        return Err(RepositoryError::Consistency(
            "conformance Suite origin must be canonical".to_owned(),
        ));
    }
    if request.task_jti.trim().is_empty()
        || request.task_jti.len() > MAX_ONBOARDING_TASK_JTI_BYTES
        || request.task_jti != request.task_jti.trim()
        || request.task_jti.chars().any(char::is_control)
    {
        return Err(RepositoryError::Consistency(
            "conformance task_jti must be a bounded, printable identifier".to_owned(),
        ));
    }
    if request.profile.trim().is_empty()
        || request.profile.len() > 64
        || request.profile != request.profile.trim()
        || request.profile.chars().any(char::is_control)
    {
        return Err(RepositoryError::Consistency(
            "conformance profile must contain 1 to 64 bytes".to_owned(),
        ));
    }
    if !(MIN_CONFORMANCE_LEASE_SECONDS..=MAX_CONFORMANCE_LEASE_SECONDS)
        .contains(&request.ttl_seconds)
    {
        return Err(RepositoryError::Consistency(format!(
            "conformance onboarding ttl_seconds must be between {MIN_CONFORMANCE_LEASE_SECONDS} and {MAX_CONFORMANCE_LEASE_SECONDS}"
        )));
    }
    for (digest, label) in [
        (&request.bundle_sha256, "bundle_sha256"),
        (&request.material_sha256, "material_sha256"),
    ] {
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(RepositoryError::Consistency(format!(
                "conformance {label} must be a lowercase SHA-256 digest"
            )));
        }
    }
    for (digest, label) in [
        (
            &request.dynamic_registration_initial_access_token_sha256,
            "dynamic_registration_initial_access_token_sha256",
        ),
        (
            &request.ciba_automated_decision_token_sha256,
            "ciba_automated_decision_token_sha256",
        ),
    ] {
        if digest.as_deref().is_some_and(|digest| {
            digest.len() != 64
                || !digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        }) {
            return Err(RepositoryError::Consistency(format!(
                "conformance {label} must be a lowercase SHA-256 digest"
            )));
        }
    }
    if request.profile != ATOMIC_CONFORMANCE_PROFILE {
        return Err(RepositoryError::Consistency(
            "atomic conformance onboarding only supports the nazoauth-full profile".to_owned(),
        ));
    }
    if request
        .dynamic_registration_initial_access_token_sha256
        .is_none()
        || request.ciba_automated_decision_token_sha256.is_none()
    {
        return Err(RepositoryError::Consistency(
            "nazoauth-full onboarding requires both conformance token digests".to_owned(),
        ));
    }
    if !(1..=32).contains(&request.bundle_schema)
        || request.client_count <= 0
        || usize::try_from(request.client_count).ok() != Some(request.clients.len())
        || request.clients.len() > MAX_ONBOARDING_CLIENTS
    {
        return Err(RepositoryError::Consistency(
            "conformance bundle schema or client count is outside the supported bounds".to_owned(),
        ));
    }
    if request.applicant.username.trim().is_empty()
        || request.applicant.username.len() > 150
        || request.applicant.username != request.applicant.username.trim()
        || request.applicant.username.chars().any(char::is_control)
        || request.applicant.email.trim().is_empty()
        || request.applicant.email.len() > 254
        || request.applicant.email != request.applicant.email.trim()
        || request.applicant.email.chars().any(char::is_control)
    {
        return Err(RepositoryError::Consistency(
            "conformance applicant identity exceeds the persisted bounds".to_owned(),
        ));
    }
    let mut logical_ids = HashSet::with_capacity(request.clients.len());
    let mut public_client_ids = HashSet::with_capacity(request.clients.len());
    for client in &request.clients {
        if client.logical_client_id.trim().is_empty()
            || client.logical_client_id.len() > MAX_ONBOARDING_LOGICAL_ID_BYTES
            || client.logical_client_id != client.logical_client_id.trim()
            || client.logical_client_id.chars().any(char::is_control)
            || !logical_ids.insert(client.logical_client_id.as_str())
        {
            return Err(RepositoryError::Consistency(
                "conformance bundle contains a duplicate or invalid logical client id".to_owned(),
            ));
        }
        if client.prepared.tenant != request.tenant
            || client.prepared.conformance_lease_id.is_some()
            || !public_client_ids.insert(client.prepared.registration.client_id.as_str())
        {
            return Err(RepositoryError::Consistency(
                "conformance prepared clients have inconsistent tenant, lease, or public IDs"
                    .to_owned(),
            ));
        }
    }
    let mut anchor_ids = HashSet::with_capacity(request.mtls_trust_anchors.len());
    for anchor in &request.mtls_trust_anchors {
        if !logical_ids.contains(anchor.logical_client_id.as_str())
            || !anchor_ids.insert(anchor.logical_client_id.as_str())
        {
            return Err(RepositoryError::Consistency(
                "conformance trust anchors must reference unique known logical clients".to_owned(),
            ));
        }
    }
    Ok(())
}

enum OnboardingTxError {
    Diesel(diesel::result::Error),
    Repository(RepositoryError),
}

impl From<diesel::result::Error> for OnboardingTxError {
    fn from(error: diesel::result::Error) -> Self {
        Self::Diesel(error)
    }
}

impl OnboardingTxError {
    fn into_repository(self) -> RepositoryError {
        match self {
            Self::Diesel(error) => map_diesel_error(error),
            Self::Repository(error) => error,
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_request() -> ConformanceOnboardingRequest {
        ConformanceOnboardingRequest {
            tenant: TenantContext::default_system(),
            task_jti: "task-1".to_owned(),
            profile: ATOMIC_CONFORMANCE_PROFILE.to_owned(),
            bundle_schema: 1,
            bundle_sha256: "a".repeat(64),
            material_sha256: "b".repeat(64),
            suite_origin: "https://suite.example.test".to_owned(),
            dynamic_registration_initial_access_token_sha256: Some("c".repeat(64)),
            ciba_automated_decision_token_sha256: Some("d".repeat(64)),
            client_count: 0,
            ttl_seconds: MIN_CONFORMANCE_LEASE_SECONDS,
            applicant: ConformanceApplicant {
                username: "oidf-applicant".to_owned(),
                email: "oidf-applicant@example.invalid".to_owned(),
                password_hash: PasswordHashInput::new("opaque-test-hash").unwrap(),
                email_verified: true,
            },
            clients: Vec::new(),
            mtls_trust_anchors: Vec::new(),
        }
    }

    #[test]
    fn onboarding_rejects_empty_client_bundle_before_database_access() {
        let request = minimal_request();
        let error = validate_onboarding_request(&request).unwrap_err();
        assert!(error.to_string().contains("client count"));
    }

    #[test]
    fn onboarding_rejects_control_character_task_jti() {
        let mut request = minimal_request();
        request.task_jti = "task-\n1".to_owned();
        let error = validate_onboarding_request(&request).unwrap_err();
        assert!(error.to_string().contains("task_jti"));
    }

    #[test]
    fn onboarding_rejects_out_of_range_ttl_before_database_access() {
        let mut request = minimal_request();
        request.ttl_seconds = MAX_CONFORMANCE_LEASE_SECONDS + 1;
        let error = validate_onboarding_request(&request).unwrap_err();
        assert!(error.to_string().contains("ttl_seconds"));
    }

    #[test]
    fn full_onboarding_requires_both_token_digests() {
        let mut request = minimal_request();
        request.ciba_automated_decision_token_sha256 = None;
        let error = validate_onboarding_request(&request).unwrap_err();
        assert!(error.to_string().contains("requires both"));
    }

    #[test]
    fn onboarding_rejects_malformed_or_misprofiled_token_digest() {
        let mut request = minimal_request();
        request.dynamic_registration_initial_access_token_sha256 = Some("not-a-digest".to_owned());
        let error = validate_onboarding_request(&request).unwrap_err();
        assert!(error.to_string().contains("dynamic_registration"));

        request.dynamic_registration_initial_access_token_sha256 = Some("a".repeat(64));
        request.profile = "oidc-core".to_owned();
        let error = validate_onboarding_request(&request).unwrap_err();
        assert!(error.to_string().contains("only supports"));
    }

    #[test]
    fn onboarding_debug_never_contains_password_hash_material() {
        let request = minimal_request();
        let debug = format!("{request:?}");
        assert!(!debug.contains("opaque-test-hash"));
        assert!(!debug.contains(&"c".repeat(64)));
        assert!(!debug.contains(&"d".repeat(64)));
        assert!(debug.contains("REDACTED"));
    }

    #[test]
    fn suite_origin_canonicalizes_scheme_host_and_default_port() {
        assert_eq!(
            canonicalize_suite_origin("HTTPS://Suite.Example.test:443").unwrap(),
            "https://suite.example.test"
        );
        assert_eq!(
            canonicalize_suite_origin("https://Suite.Example.test:8443").unwrap(),
            "https://suite.example.test:8443"
        );
        assert_eq!(
            canonicalize_suite_origin("https://[2001:DB8::1]:443").unwrap(),
            "https://[2001:db8::1]"
        );
        assert_eq!(
            canonicalize_suite_origin("https://[2001:0db8:0:0:0:0:0:1]").unwrap(),
            "https://[2001:db8::1]"
        );
    }

    #[test]
    fn suite_origin_rejects_non_origin_components_and_invalid_ports() {
        for value in [
            "http://suite.example.test",
            "https://suite.example.test/path",
            "https://suite.example.test?query",
            "https://suite.example.test#fragment",
            "https://user@suite.example.test",
            "https://suite.example.test:0",
            "https://suite.example.test:65536",
            "https://2001:db8::1",
        ] {
            assert!(
                canonicalize_suite_origin(value).is_err(),
                "accepted {value}"
            );
        }
    }
}
