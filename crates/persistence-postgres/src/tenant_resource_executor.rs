//! PostgreSQL implementation of the atomic tenant-resource persistence capability.

use std::{collections::BTreeMap, sync::Arc};

use chrono::{DateTime, Utc};
use diesel::{OptionalExtension as _, QueryableByName, sql_query, sql_types};
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl as _};
use futures_util::future::BoxFuture;
use nazo_identity::ports::RepositoryError;
use nazo_identity::{TenantContext, TenantId};
use nazo_operator_protocol::{
    TenantResourceIdentity, TenantResourceKind, TenantResourceMapping, TenantResourceSelector,
    canonical_tenant_resource_manifest_sha256, validate_openid4vc_trust_policy,
};
use nazo_persistence::tenant_resources::{
    ControlTenantResourceFrame, ControlTenantResourceOutcome, PreparedMtlsTrustAnchor,
    PreparedOAuthClient, PreparedTenantResource, TenantResourceAction, TenantResourceExecutorError,
    TenantResourceExecutorPort, TenantResourcePayload, TenantResourcePreparation,
    TenantResourcePreparationError, UserProfileFields, empty_manifest_sha256, operation_name,
    validate_control_outcome,
};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::{
    NewStoredOpenid4vcTrustPolicy, NewTenantResourceBinding, Openid4vcTrustPolicyClientBind,
    Openid4vcTrustPolicyForClient, Openid4vcTrustPolicyRevoke, Openid4vcTrustPolicyWrite,
    OperatorManagedTrustAnchor, TenantResourceBinding, TenantResourceBindingDeactivate,
    TenantResourceRepository, TenantResourceStateCas, UserInsert,
    active_public_client_id_on_connection, append_fresh_security_audit_on_connection,
    deactivate_client_on_connection, delete_operator_managed_dataset_on_connection,
    disable_user_on_connection, insert_client_on_connection,
    insert_operator_managed_trust_anchor_on_connection, insert_user_on_connection,
    protect_dataset_claims, revoke_operator_managed_trust_anchor_on_connection,
    upsert_operator_managed_dataset_on_connection,
};

/// PostgreSQL tenant-resource executor and authoritative state source.
pub struct PostgresTenantResourceExecutor {
    repository: TenantResourceRepository,
    tenant: TenantContext,
    data_key: Option<[u8; 32]>,
    preparation: Arc<dyn TenantResourcePreparation>,
}

impl PostgresTenantResourceExecutor {
    #[must_use]
    pub fn new(
        repository: TenantResourceRepository,
        tenant: TenantContext,
        data_key: Option<[u8; 32]>,
        preparation: Arc<dyn TenantResourcePreparation>,
    ) -> Self {
        Self {
            repository,
            tenant,
            data_key,
            preparation,
        }
    }

    /// Canonical digest of an empty active identity set.
    #[must_use]
    pub fn empty_manifest_sha256() -> String {
        canonical_tenant_resource_manifest_sha256(&[])
            .expect("the empty tenant-resource identity set is valid")
    }
}

impl PostgresTenantResourceExecutor {
    async fn prepare_apply_payloads(
        &self,
        resources: &[PreparedTenantResource],
    ) -> Result<Vec<PreparedApplyPayload>, TenantResourceExecutorError> {
        let mut prepared = Vec::with_capacity(resources.len());
        for resource in resources {
            let Some(payload) = resource.payload.clone() else {
                return Err(TenantResourceExecutorError::Rejected);
            };
            let payload = match payload {
                TenantResourcePayload::User(value) => {
                    let password_hash = self
                        .preparation
                        .hash_user_password(value.password.clone())
                        .await
                        .map_err(map_preparation_error)?;
                    PreparedApplyPayload::User(Box::new(PreparedUser {
                        identity: resource.identity.clone(),
                        password_hash,
                        profile: value.profile,
                        username: value.username,
                        email: value.email,
                        email_verified: value.email_verified,
                    }))
                }
                TenantResourcePayload::OauthClient(value) => {
                    let prepared = self
                        .preparation
                        .prepare_oauth_client(value.request, value.supplied_secret, self.tenant)
                        .await
                        .map_err(map_preparation_error)?;
                    PreparedApplyPayload::OauthClient(Box::new(PreparedClient {
                        identity: resource.identity.clone(),
                        trust_policy_resource_id: value.trust_policy_resource_id,
                        prepared,
                    }))
                }
                TenantResourcePayload::MtlsTrustAnchor(value) => {
                    let PreparedMtlsTrustAnchor {
                        certificate_pem,
                        certificate_sha256,
                        subject_dn,
                        not_before,
                        not_after,
                    } = self
                        .preparation
                        .prepare_mtls_trust_anchor(value.certificate_pem)
                        .await
                        .map_err(map_preparation_error)?;
                    PreparedApplyPayload::Mtls(Box::new(PreparedMtls {
                        identity: resource.identity.clone(),
                        client_resource_id: value.client_resource_id,
                        certificate_pem,
                        certificate_sha256,
                        subject_dn,
                        not_before,
                        not_after,
                    }))
                }
                TenantResourcePayload::Openid4vcDataset(value) => {
                    PreparedApplyPayload::Dataset(Box::new(PreparedDataset {
                        identity: resource.identity.clone(),
                        user_resource_id: value.user_resource_id,
                        configuration_id: value.configuration_id,
                        claims: value.claims,
                    }))
                }
                TenantResourcePayload::Openid4vcTrustPolicy(value) => {
                    validate_openid4vc_trust_policy(&value.public_material)
                        .map_err(|_| TenantResourceExecutorError::Rejected)?;
                    PreparedApplyPayload::TrustPolicy(Box::new(PreparedTrustPolicy {
                        identity: resource.identity.clone(),
                        public_material: value.public_material,
                    }))
                }
            };
            prepared.push(payload);
        }
        prepared.sort_by(|left, right| payload_sort_key(left).cmp(&payload_sort_key(right)));
        Ok(prepared)
    }

    /// Execute one tenant-resource operation on behalf of an accepted
    /// [`nazo_operator_protocol::ControlOperation`] (H07).
    ///
    /// Authorization is the accepted controller-signed operation. Exact
    /// operation-id/request-hash replay, resource mutation, state CAS, audit,
    /// and the typed outcome commit in one PostgreSQL transaction.
    pub(crate) async fn execute_control_operation(
        &self,
        frame: ControlTenantResourceFrame<'_>,
    ) -> Result<ControlTenantResourceOutcome, TenantResourceExecutorError> {
        let ControlTenantResourceFrame {
            deployment_id,
            jti,
            request_sha256,
            actor,
            operation,
            tenant_id,
            resources,
            selectors,
        } = frame;
        if tenant_id != self.tenant.tenant_id.as_uuid().to_string()
            || !is_lower_sha256(request_sha256)
        {
            return Err(TenantResourceExecutorError::Rejected);
        }
        let operation_id =
            Uuid::parse_str(jti).map_err(|_| TenantResourceExecutorError::Rejected)?;
        if let Some(outcome) = self
            .existing_control_outcome(deployment_id, operation_id, request_sha256, operation)
            .await?
        {
            return Ok(outcome);
        }
        let prepared_payloads = match operation {
            TenantResourceAction::Apply => Some(self.prepare_apply_payloads(&resources).await?),
            _ => None,
        };
        let mut connection = self
            .repository
            .connection()
            .await
            .map_err(map_repository_error)?;
        let tenant_uuid = self.tenant.tenant_id.as_uuid();
        let configured_tenant = self.tenant;
        let data_key = self.data_key;
        let deployment_id = deployment_id.to_owned();
        let actor = actor.clone();
        let selectors = selectors.to_vec();

        connection
            .transaction::<ControlTenantResourceOutcome, ExecutorTransactionError, _>(
                async move |connection| {
                    // Serialize replay/conflict decisions and the resource
                    // transaction for one accepted operation identity.
                    TenantResourceRepository::lock_operation_identity_on_connection(
                        connection,
                        &deployment_id,
                        tenant_uuid,
                        jti,
                    )
                    .await
                    .map_err(ExecutorTransactionError::Repository)?;
                    if let Some(outcome) = control_outcome_on_connection(
                        connection,
                        operation_id,
                        request_sha256,
                        tenant_uuid,
                        operation,
                    )
                    .await?
                    {
                        return Ok(outcome);
                    }
                    let current =
                        TenantResourceRepository::state_on_connection(connection, tenant_uuid)
                            .await
                            .map_err(ExecutorTransactionError::Repository)?;
                    let (current_revision, current_manifest) = match current {
                        Some(state) => (state.revision, state.resource_manifest_sha256),
                        None => (0, empty_manifest_sha256()),
                    };

                    let frame = match operation {
                        TenantResourceAction::Apply => ResourceFrame::Apply {
                            resources: &resources,
                            payloads: prepared_payloads.as_deref().ok_or(
                                ExecutorTransactionError::Executor(
                                    TenantResourceExecutorError::Rejected,
                                ),
                            )?,
                        },
                        TenantResourceAction::Revoke => ResourceFrame::Revoke {
                            resources: &resources,
                        },
                        TenantResourceAction::Enumerate => ResourceFrame::Enumerate {
                            selectors: &selectors,
                        },
                    };
                    let frame = run_resource_frame(
                        connection,
                        tenant_uuid,
                        configured_tenant,
                        &data_key,
                        frame,
                    )
                    .await?;

                    if operation == TenantResourceAction::Enumerate {
                        if frame.manifest_sha256 != current_manifest {
                            return Err(ExecutorTransactionError::Executor(
                                TenantResourceExecutorError::Conflict,
                            ));
                        }
                        let audit_event = tenant_resource_audit_event(
                            &deployment_id,
                            &tenant_uuid.to_string(),
                            jti,
                            request_sha256,
                            &actor,
                            operation,
                            current_revision,
                            &frame.manifest_sha256,
                            &frame.resources,
                        );
                        append_fresh_security_audit_on_connection(connection, &audit_event)
                            .await
                            .map_err(ExecutorTransactionError::Diesel)?;
                        let outcome = ControlTenantResourceOutcome {
                            revision: current_revision,
                            resources: frame.resources,
                            resource_mappings: frame.resource_mappings,
                            resource_manifest_sha256: frame.manifest_sha256,
                        };
                        validate_wire_outcome(operation, &outcome)?;
                        record_control_outcome_on_connection(
                            connection,
                            operation_id,
                            request_sha256,
                            tenant_uuid,
                            operation,
                            &outcome,
                        )
                        .await?;
                        return Ok(outcome);
                    }

                    let next_revision = current_revision.checked_add(1).ok_or(
                        ExecutorTransactionError::Executor(
                            TenantResourceExecutorError::Unavailable,
                        ),
                    )?;
                    match TenantResourceRepository::compare_and_set_state_on_connection(
                        connection,
                        tenant_uuid,
                        current_revision,
                        next_revision,
                        &frame.manifest_sha256,
                    )
                    .await
                    .map_err(ExecutorTransactionError::Repository)?
                    {
                        TenantResourceStateCas::Applied(_) => {}
                        TenantResourceStateCas::Conflict(_) => {
                            return Err(transaction_conflict("state_cas"));
                        }
                    }
                    let audit_event = tenant_resource_audit_event(
                        &deployment_id,
                        &tenant_uuid.to_string(),
                        jti,
                        request_sha256,
                        &actor,
                        operation,
                        current_revision,
                        &frame.manifest_sha256,
                        &frame.resources,
                    );
                    append_fresh_security_audit_on_connection(connection, &audit_event)
                        .await
                        .map_err(ExecutorTransactionError::Diesel)?;
                    let outcome = ControlTenantResourceOutcome {
                        revision: next_revision,
                        resources: frame.resources,
                        resource_mappings: frame.resource_mappings,
                        resource_manifest_sha256: frame.manifest_sha256,
                    };
                    validate_wire_outcome(operation, &outcome)?;
                    record_control_outcome_on_connection(
                        connection,
                        operation_id,
                        request_sha256,
                        tenant_uuid,
                        operation,
                        &outcome,
                    )
                    .await?;
                    Ok(outcome)
                },
            )
            .await
            .map_err(map_transaction_error)
    }

    async fn existing_control_outcome(
        &self,
        deployment_id: &str,
        operation_id: Uuid,
        request_hash: &str,
        operation: TenantResourceAction,
    ) -> Result<Option<ControlTenantResourceOutcome>, TenantResourceExecutorError> {
        let mut connection = self
            .repository
            .connection()
            .await
            .map_err(map_repository_error)?;
        let tenant_id = self.tenant.tenant_id.as_uuid();
        connection
            .transaction::<Option<ControlTenantResourceOutcome>, ExecutorTransactionError, _>(
                async move |connection| {
                    let operation_id_text = operation_id.to_string();
                    TenantResourceRepository::lock_operation_identity_on_connection(
                        connection,
                        deployment_id,
                        tenant_id,
                        &operation_id_text,
                    )
                    .await
                    .map_err(ExecutorTransactionError::Repository)?;
                    control_outcome_on_connection(
                        connection,
                        operation_id,
                        request_hash,
                        tenant_id,
                        operation,
                    )
                    .await
                },
            )
            .await
            .map_err(map_transaction_error)
    }
}

/// Prepared values are deliberately not `Debug`: password hashes, encrypted
/// claim ciphertext, and registration material should not accidentally enter
/// a trace or panic message.
enum PreparedApplyPayload {
    User(Box<PreparedUser>),
    OauthClient(Box<PreparedClient>),
    Mtls(Box<PreparedMtls>),
    Dataset(Box<PreparedDataset>),
    TrustPolicy(Box<PreparedTrustPolicy>),
}

struct PreparedUser {
    identity: TenantResourceIdentity,
    password_hash: String,
    profile: UserProfileFields,
    username: String,
    email: String,
    email_verified: bool,
}

struct PreparedClient {
    identity: TenantResourceIdentity,
    trust_policy_resource_id: Option<String>,
    prepared: PreparedOAuthClient,
}

struct PreparedMtls {
    identity: TenantResourceIdentity,
    client_resource_id: String,
    certificate_pem: String,
    certificate_sha256: String,
    subject_dn: String,
    not_before: DateTime<Utc>,
    not_after: DateTime<Utc>,
}

struct PreparedDataset {
    identity: TenantResourceIdentity,
    user_resource_id: String,
    configuration_id: String,
    claims: Value,
}

struct PreparedTrustPolicy {
    identity: TenantResourceIdentity,
    public_material: nazo_operator_protocol::Openid4vcTrustPolicy,
}

fn payload_sort_key(payload: &PreparedApplyPayload) -> (u8, &str) {
    match payload {
        PreparedApplyPayload::User(value) => (0, &value.identity.resource_id),
        PreparedApplyPayload::OauthClient(value) => (1, &value.identity.resource_id),
        PreparedApplyPayload::Mtls(value) => (2, &value.identity.resource_id),
        PreparedApplyPayload::Dataset(value) => (3, &value.identity.resource_id),
        PreparedApplyPayload::TrustPolicy(value) => (4, &value.identity.resource_id),
    }
}

fn validate_wire_outcome(
    operation: TenantResourceAction,
    outcome: &ControlTenantResourceOutcome,
) -> Result<(), ExecutorTransactionError> {
    validate_control_outcome(operation, outcome).map_err(ExecutorTransactionError::Executor)
}

#[derive(QueryableByName)]
struct ControlOutcomeRow {
    #[diesel(sql_type = sql_types::Text)]
    request_hash: String,
    #[diesel(sql_type = sql_types::Uuid)]
    tenant_id: Uuid,
    #[diesel(sql_type = sql_types::Text)]
    operation: String,
    #[diesel(sql_type = sql_types::Jsonb)]
    outcome: Value,
}

async fn control_outcome_on_connection(
    connection: &mut AsyncPgConnection,
    operation_id: Uuid,
    request_hash: &str,
    tenant_id: Uuid,
    operation: TenantResourceAction,
) -> Result<Option<ControlTenantResourceOutcome>, ExecutorTransactionError> {
    let row = sql_query(
        "SELECT request_hash, tenant_id, operation, outcome
         FROM tenant_resource_control_operations
         WHERE operation_id = $1",
    )
    .bind::<sql_types::Uuid, _>(operation_id)
    .get_result::<ControlOutcomeRow>(connection)
    .await
    .optional()
    .map_err(ExecutorTransactionError::Diesel)?;
    let Some(row) = row else {
        return Ok(None);
    };
    if row.request_hash != request_hash
        || row.tenant_id != tenant_id
        || row.operation != operation_name(operation)
    {
        return Err(transaction_conflict("control_operation_replay"));
    }
    let outcome = serde_json::from_value(row.outcome).map_err(|_| {
        ExecutorTransactionError::Executor(TenantResourceExecutorError::Unavailable)
    })?;
    validate_wire_outcome(operation, &outcome)?;
    Ok(Some(outcome))
}

async fn record_control_outcome_on_connection(
    connection: &mut AsyncPgConnection,
    operation_id: Uuid,
    request_hash: &str,
    tenant_id: Uuid,
    operation: TenantResourceAction,
    outcome: &ControlTenantResourceOutcome,
) -> Result<(), ExecutorTransactionError> {
    let outcome = serde_json::to_value(outcome).map_err(|_| {
        ExecutorTransactionError::Executor(TenantResourceExecutorError::Unavailable)
    })?;
    let inserted = sql_query(
        "INSERT INTO tenant_resource_control_operations
             (operation_id, request_hash, tenant_id, operation, outcome)
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind::<sql_types::Uuid, _>(operation_id)
    .bind::<sql_types::Text, _>(request_hash)
    .bind::<sql_types::Uuid, _>(tenant_id)
    .bind::<sql_types::Text, _>(operation_name(operation))
    .bind::<sql_types::Jsonb, _>(outcome)
    .execute(connection)
    .await
    .map_err(ExecutorTransactionError::Diesel)?;
    if inserted != 1 {
        return Err(transaction_conflict("control_operation_record"));
    }
    Ok(())
}

/// Typed input of one shared tenant-resource frame.
enum ResourceFrame<'a> {
    Apply {
        resources: &'a [PreparedTenantResource],
        payloads: &'a [PreparedApplyPayload],
    },
    Revoke {
        resources: &'a [PreparedTenantResource],
    },
    Enumerate {
        selectors: &'a [TenantResourceSelector],
    },
}

/// Normalized outcome of one shared mutation/enumeration frame.
struct MutationFrameResult {
    /// Sorted identities this operation reports (delta for apply/revoke,
    /// selection for enumerate).
    resources: Vec<TenantResourceIdentity>,
    /// Apply-only public identifier mappings; empty otherwise.
    resource_mappings: Vec<TenantResourceMapping>,
    /// Canonical SHA-256 of the complete active identity set implied by this
    /// frame, recomputed from the database inside the caller's transaction.
    manifest_sha256: String,
}

/// Dispatch one tenant-resource ControlOperation onto the CAS engine so
/// ownership checks, dependency ordering, identity locks, and manifest
/// recomputation have one owner.
async fn run_resource_frame(
    connection: &mut AsyncPgConnection,
    tenant_id: Uuid,
    configured_tenant: TenantContext,
    data_key: &Option<[u8; 32]>,
    frame: ResourceFrame<'_>,
) -> Result<MutationFrameResult, ExecutorTransactionError> {
    match frame {
        ResourceFrame::Apply {
            resources,
            payloads,
        } => {
            let (resources, resource_mappings, manifest_sha256) = apply_resources(
                connection,
                tenant_id,
                configured_tenant,
                resources,
                payloads,
                data_key,
            )
            .await?;
            Ok(MutationFrameResult {
                resources,
                resource_mappings,
                manifest_sha256,
            })
        }
        ResourceFrame::Revoke { resources } => {
            let (resources, manifest_sha256) =
                revoke_resources(connection, tenant_id, configured_tenant, resources).await?;
            Ok(MutationFrameResult {
                resources,
                resource_mappings: Vec::new(),
                manifest_sha256,
            })
        }
        ResourceFrame::Enumerate { selectors } => {
            let (selected, complete) =
                enumerate_resources(connection, tenant_id, selectors).await?;
            let manifest_sha256 =
                canonical_tenant_resource_manifest_sha256(&complete).map_err(|_| {
                    ExecutorTransactionError::Executor(TenantResourceExecutorError::Unavailable)
                })?;
            Ok(MutationFrameResult {
                resources: selected,
                resource_mappings: Vec::new(),
                manifest_sha256,
            })
        }
    }
}

async fn apply_resources(
    connection: &mut AsyncPgConnection,
    tenant_id: Uuid,
    tenant: TenantContext,
    resources: &[PreparedTenantResource],
    payloads: &[PreparedApplyPayload],
    data_key: &Option<[u8; 32]>,
) -> Result<
    (
        Vec<TenantResourceIdentity>,
        Vec<TenantResourceMapping>,
        String,
    ),
    ExecutorTransactionError,
> {
    let active = active_binding_map(connection, tenant_id).await?;
    let mut locators = BTreeMap::<ResourceKey, String>::new();
    let delta_keys = resources
        .iter()
        .map(|resource| ResourceKey::from_identity(&resource.identity))
        .collect::<std::collections::BTreeSet<_>>();
    let mut available_keys = active
        .keys()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    available_keys.extend(delta_keys.iter().cloned());
    validate_desired_dependencies(payloads, &available_keys)?;

    // Every identity lock is acquired in one global order before either the
    // dependency-ordered creation phase or the revision CAS.  This keeps a
    // delta apply from racing a revoke/apply for an existing identity.
    let mut locked_keys = active
        .keys()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    locked_keys.extend(delta_keys.iter().cloned());
    for key in locked_keys {
        TenantResourceRepository::lock_binding_identity_on_connection(
            connection,
            tenant_id,
            kind_name(key.kind),
            &key.resource_id,
        )
        .await
        .map_err(ExecutorTransactionError::Repository)?;
    }
    // Active bindings are part of the available dependency graph.  Keep
    // their operator-owned locators in the same map as newly-created delta
    // rows so an mTLS anchor or dataset can refer to a parent omitted from
    // this delta.
    for (key, binding) in &active {
        if !is_operator_locator(&binding.locator, key.kind) {
            return Err(ExecutorTransactionError::Executor(
                TenantResourceExecutorError::Rejected,
            ));
        }
        locators.insert(key.clone(), binding.locator.clone());
    }

    // Reusing an active identity is idempotent only when its digest matches.
    // A changed payload must be fenced through an explicit Revoke followed by
    // a fresh Apply; this delta path never overwrites it in place.
    for resource in resources {
        let key = ResourceKey::new(resource.identity.kind, &resource.identity.resource_id);
        if active
            .get(&key)
            .is_some_and(|binding| binding.resource_digest != resource.identity.digest)
        {
            return Err(ExecutorTransactionError::Executor(
                TenantResourceExecutorError::Conflict,
            ));
        }
    }

    // Logical references are resolved only after users and clients exist.
    for payload in payloads.iter().filter_map(|p| match p {
        PreparedApplyPayload::User(value) => Some(value),
        _ => None,
    }) {
        if locators.contains_key(&ResourceKey::from_identity(&payload.identity)) {
            continue;
        }
        let profile = &payload.profile;
        let id = insert_user_on_connection(
            connection,
            UserInsert {
                tenant,
                username: &payload.username,
                email: &payload.email,
                password_hash: &payload.password_hash,
                email_verified: payload.email_verified,
                display_name: profile.display_name.as_deref(),
                given_name: profile.given_name.as_deref(),
                family_name: profile.family_name.as_deref(),
                middle_name: profile.middle_name.as_deref(),
                nickname: profile.nickname.as_deref(),
                profile_url: profile.profile_url.as_deref(),
                avatar_url: profile.avatar_url.as_deref(),
                website_url: profile.website_url.as_deref(),
                gender: profile.gender.as_deref(),
                birthdate: profile.birthdate.as_deref(),
                zoneinfo: profile.zoneinfo.as_deref(),
                locale: profile.locale.as_deref(),
                address_formatted: profile.address_formatted.as_deref(),
                address_street_address: profile.address_street_address.as_deref(),
                address_locality: profile.address_locality.as_deref(),
                address_region: profile.address_region.as_deref(),
                address_postal_code: profile.address_postal_code.as_deref(),
                address_country: profile.address_country.as_deref(),
                phone_number: profile.phone_number.as_deref(),
                phone_number_verified: profile.phone_number_verified,
            },
        )
        .await
        .map_err(map_diesel_error)?;
        locators.insert(
            ResourceKey::from_identity(&payload.identity),
            user_locator(id),
        );
    }
    for payload in payloads.iter().filter_map(|p| match p {
        PreparedApplyPayload::OauthClient(value) => Some(value),
        _ => None,
    }) {
        if locators.contains_key(&ResourceKey::from_identity(&payload.identity)) {
            continue;
        }
        let client = &payload.prepared.client;
        if client.tenant_id != tenant.tenant_id.as_uuid()
            || client.realm_id != tenant.realm_id.as_uuid()
            || client.organization_id != tenant.organization_id.as_uuid()
        {
            return Err(ExecutorTransactionError::Executor(
                TenantResourceExecutorError::Rejected,
            ));
        }
        insert_client_on_connection(
            connection,
            client,
            payload.prepared.client_secret_hash.as_deref(),
            None,
        )
        .await
        .map_err(map_diesel_error)?;
        locators.insert(
            ResourceKey::from_identity(&payload.identity),
            oauth_client_locator(client.id),
        );
    }
    for payload in payloads.iter().filter_map(|p| match p {
        PreparedApplyPayload::Mtls(value) => Some(value),
        _ => None,
    }) {
        if locators.contains_key(&ResourceKey::from_identity(&payload.identity)) {
            continue;
        }
        let client_key =
            ResourceKey::new(TenantResourceKind::OauthClient, &payload.client_resource_id);
        let client_id = parse_uuid_locator(
            locators
                .get(&client_key)
                .ok_or(ExecutorTransactionError::Executor(
                    TenantResourceExecutorError::Rejected,
                ))?,
            TenantResourceKind::OauthClient,
        )?;
        let request_id = insert_operator_managed_trust_anchor_on_connection(
            connection,
            OperatorManagedTrustAnchor {
                tenant_id: tenant.tenant_id,
                client_id,
                certificate_pem: &payload.certificate_pem,
                certificate_sha256: &payload.certificate_sha256,
                subject_dn: &payload.subject_dn,
                not_before: payload.not_before,
                not_after: payload.not_after,
            },
        )
        .await
        .map_err(map_repository_error)?;
        locators.insert(
            ResourceKey::from_identity(&payload.identity),
            mtls_locator(request_id),
        );
    }
    for payload in payloads.iter().filter_map(|p| match p {
        PreparedApplyPayload::Dataset(value) => Some(value),
        _ => None,
    }) {
        if locators.contains_key(&ResourceKey::from_identity(&payload.identity)) {
            continue;
        }
        let user_key = ResourceKey::new(TenantResourceKind::User, &payload.user_resource_id);
        let user_id = parse_uuid_locator(
            locators
                .get(&user_key)
                .ok_or(ExecutorTransactionError::Executor(
                    TenantResourceExecutorError::Rejected,
                ))?,
            TenantResourceKind::User,
        )?;
        let Some(data_key) = data_key.as_ref() else {
            return Err(ExecutorTransactionError::Executor(
                TenantResourceExecutorError::Unavailable,
            ));
        };
        let ciphertext = protect_dataset_claims(
            data_key,
            tenant_id,
            user_id,
            &payload.configuration_id,
            &payload.claims,
        )
        .map_err(|_| {
            ExecutorTransactionError::Executor(TenantResourceExecutorError::Unavailable)
        })?;
        let affected = upsert_operator_managed_dataset_on_connection(
            connection,
            tenant_id,
            user_id,
            &payload.configuration_id,
            ciphertext,
            None,
            None,
        )
        .await
        .map_err(map_diesel_error)?;
        if affected != 1 {
            return Err(ExecutorTransactionError::Executor(
                TenantResourceExecutorError::Conflict,
            ));
        }
        locators.insert(
            ResourceKey::from_identity(&payload.identity),
            dataset_locator(user_id, &payload.configuration_id),
        );
    }
    for payload in payloads.iter().filter_map(|p| match p {
        PreparedApplyPayload::TrustPolicy(value) => Some(value),
        _ => None,
    }) {
        if locators.contains_key(&ResourceKey::from_identity(&payload.identity)) {
            continue;
        }
        let public_material = serde_json::to_value(&payload.public_material).map_err(|_| {
            ExecutorTransactionError::Executor(TenantResourceExecutorError::Unavailable)
        })?;
        let applied = TenantResourceRepository::apply_openid4vc_trust_policy_on_connection(
            connection,
            NewStoredOpenid4vcTrustPolicy {
                tenant_id,
                resource_id: &payload.identity.resource_id,
                resource_digest: &payload.identity.digest,
                public_material: &public_material,
                wallet_origins: &payload.public_material.wallet_authorization_origins,
            },
        )
        .await
        .map_err(ExecutorTransactionError::Repository)?;
        let policy_id = match applied {
            Openid4vcTrustPolicyWrite::Applied(policy)
            | Openid4vcTrustPolicyWrite::Replayed(policy) => policy.id,
            Openid4vcTrustPolicyWrite::Conflict(_) => {
                return Err(transaction_conflict("trust_policy_apply"));
            }
        };
        locators.insert(
            ResourceKey::from_identity(&payload.identity),
            trust_policy_locator(policy_id),
        );
    }

    // Bind OAuth clients to the policy only after all logical resources have
    // locators.  This preserves the user/client/mTLS/dataset creation order
    // while allowing a client and a new policy to be introduced together.
    for payload in payloads.iter().filter_map(|p| match p {
        PreparedApplyPayload::OauthClient(value) => Some(value),
        _ => None,
    }) {
        let Some(policy_resource_id) = payload.trust_policy_resource_id.as_deref() else {
            continue;
        };
        let policy_key =
            ResourceKey::new(TenantResourceKind::Openid4vcTrustPolicy, policy_resource_id);
        locators
            .get(&policy_key)
            .ok_or(ExecutorTransactionError::Executor(
                TenantResourceExecutorError::Rejected,
            ))?;
        let client_locator = locators
            .get(&ResourceKey::from_identity(&payload.identity))
            .ok_or(ExecutorTransactionError::Executor(
                TenantResourceExecutorError::Rejected,
            ))?;
        let client_id = parse_uuid_locator(client_locator, TenantResourceKind::OauthClient)?;
        let policy_digest = resources
            .iter()
            .find(|resource| ResourceKey::from_identity(&resource.identity) == policy_key)
            .map(|resource| resource.identity.digest.as_str())
            .or_else(|| {
                active
                    .get(&policy_key)
                    .map(|binding| binding.resource_digest.as_str())
            })
            .ok_or(ExecutorTransactionError::Executor(
                TenantResourceExecutorError::Rejected,
            ))?;
        match TenantResourceRepository::bind_openid4vc_trust_policy_client_on_connection(
            connection,
            tenant_id,
            policy_resource_id,
            policy_digest,
            client_id,
        )
        .await
        .map_err(ExecutorTransactionError::Repository)?
        {
            Openid4vcTrustPolicyClientBind::Bound { .. }
            | Openid4vcTrustPolicyClientBind::Replayed { .. } => {}
            Openid4vcTrustPolicyClientBind::Conflict { .. } => {
                return Err(transaction_conflict("trust_policy_client_bind"));
            }
        }
    }

    for resource in resources {
        let key = ResourceKey::from_identity(&resource.identity);
        let locator = locators
            .get(&key)
            .ok_or(ExecutorTransactionError::Executor(
                TenantResourceExecutorError::Rejected,
            ))?;
        TenantResourceRepository::upsert_binding_on_connection(
            connection,
            NewTenantResourceBinding {
                tenant_id,
                resource_kind: kind_name(resource.identity.kind),
                resource_id: &resource.identity.resource_id,
                resource_digest: &resource.identity.digest,
                active: true,
                locator,
            },
        )
        .await
        .map_err(map_repository_error)?;
    }
    let result = sort_identities(resources.iter().map(|r| r.identity.clone()).collect());
    let active_after = active_binding_map(connection, tenant_id).await?;
    let active_after = active_after
        .values()
        .filter_map(|binding| {
            parse_kind(&binding.resource_kind).map(|kind| TenantResourceIdentity {
                kind,
                resource_id: binding.resource_id.clone(),
                digest: binding.resource_digest.clone(),
            })
        })
        .collect::<Vec<_>>();
    let digest = canonical_tenant_resource_manifest_sha256(&active_after)
        .map_err(|_| ExecutorTransactionError::Executor(TenantResourceExecutorError::Rejected))?;

    // Prepare the public mapping set for the typed Apply result. The protocol
    // only exposes User UUIDs and OAuth public client IDs; mTLS, dataset, and
    // trust-policy locators intentionally remain internal.
    let resource_mappings =
        collect_apply_resource_mappings(connection, tenant_id, resources, &locators).await?;
    Ok((result, resource_mappings, digest))
}

async fn collect_apply_resource_mappings(
    connection: &mut AsyncPgConnection,
    tenant_id: Uuid,
    resources: &[PreparedTenantResource],
    locators: &BTreeMap<ResourceKey, String>,
) -> Result<Vec<TenantResourceMapping>, ExecutorTransactionError> {
    let mut mappings = Vec::new();
    for resource in resources {
        let public_id = match resource.identity.kind {
            TenantResourceKind::User => {
                let locator = locators
                    .get(&ResourceKey::from_identity(&resource.identity))
                    .ok_or(ExecutorTransactionError::Executor(
                        TenantResourceExecutorError::Rejected,
                    ))?;
                parse_uuid_locator(locator, TenantResourceKind::User)?.to_string()
            }
            TenantResourceKind::OauthClient => {
                let locator = locators
                    .get(&ResourceKey::from_identity(&resource.identity))
                    .ok_or(ExecutorTransactionError::Executor(
                        TenantResourceExecutorError::Rejected,
                    ))?;
                let client_id = parse_uuid_locator(locator, TenantResourceKind::OauthClient)?;
                active_public_client_id_on_connection(connection, tenant_id, client_id)
                    .await
                    .map_err(ExecutorTransactionError::Repository)?
                    .ok_or_else(|| transaction_conflict("apply_oauth_client_mapping"))?
            }
            TenantResourceKind::MtlsTrustAnchor
            | TenantResourceKind::Openid4vcDataset
            | TenantResourceKind::Openid4vcTrustPolicy => {
                continue;
            }
        };
        mappings.push(TenantResourceMapping {
            kind: resource.identity.kind,
            resource_id: resource.identity.resource_id.clone(),
            public_id,
        });
    }
    mappings.sort_by(|left, right| {
        (kind_order(left.kind), left.resource_id.as_str())
            .cmp(&(kind_order(right.kind), right.resource_id.as_str()))
    });
    Ok(mappings)
}

fn validate_desired_dependencies(
    payloads: &[PreparedApplyPayload],
    available_keys: &std::collections::BTreeSet<ResourceKey>,
) -> Result<(), ExecutorTransactionError> {
    for payload in payloads {
        let dependencies = match payload {
            PreparedApplyPayload::OauthClient(value) => value
                .trust_policy_resource_id
                .as_ref()
                .map(|resource_id| {
                    ResourceKey::new(TenantResourceKind::Openid4vcTrustPolicy, resource_id)
                })
                .into_iter()
                .collect::<Vec<_>>(),
            PreparedApplyPayload::Mtls(value) => vec![ResourceKey::new(
                TenantResourceKind::OauthClient,
                &value.client_resource_id,
            )],
            PreparedApplyPayload::Dataset(value) => vec![ResourceKey::new(
                TenantResourceKind::User,
                &value.user_resource_id,
            )],
            PreparedApplyPayload::TrustPolicy(_) | PreparedApplyPayload::User(_) => Vec::new(),
        };
        if dependencies
            .iter()
            .any(|dependency| !available_keys.contains(dependency))
        {
            return Err(ExecutorTransactionError::Executor(
                TenantResourceExecutorError::Rejected,
            ));
        }
    }
    Ok(())
}

async fn revoke_resources(
    connection: &mut AsyncPgConnection,
    tenant_id: Uuid,
    tenant: TenantContext,
    resources: &[PreparedTenantResource],
) -> Result<(Vec<TenantResourceIdentity>, String), ExecutorTransactionError> {
    let active = active_binding_map(connection, tenant_id).await?;
    let mut targets = Vec::with_capacity(resources.len());
    for resource in resources {
        let key = ResourceKey::from_identity(&resource.identity);
        let Some(binding) = active.get(&key) else {
            return Err(transaction_conflict("revoke_missing_binding"));
        };
        if binding.resource_digest != resource.identity.digest {
            return Err(transaction_conflict("revoke_digest"));
        }
        targets.push((resource.identity.clone(), binding.locator.clone()));
    }
    let target_keys = targets
        .iter()
        .map(|(identity, _)| ResourceKey::from_identity(identity))
        .collect::<std::collections::BTreeSet<_>>();
    for key in &target_keys {
        TenantResourceRepository::lock_binding_identity_on_connection(
            connection,
            tenant_id,
            kind_name(key.kind),
            &key.resource_id,
        )
        .await
        .map_err(ExecutorTransactionError::Repository)?;
    }
    validate_revoke_dependency_closure(connection, tenant_id, &active, &target_keys).await?;
    targets.sort_by(|left, right| {
        kind_order(right.0.kind)
            .cmp(&kind_order(left.0.kind))
            .then_with(|| left.0.resource_id.cmp(&right.0.resource_id))
    });

    for (identity, locator) in &targets {
        let deactivated = TenantResourceRepository::deactivate_binding_on_connection(
            connection,
            tenant_id,
            kind_name(identity.kind),
            &identity.resource_id,
            &identity.digest,
        )
        .await
        .map_err(map_repository_error)?;
        match deactivated {
            TenantResourceBindingDeactivate::Deactivated(_) => {}
            TenantResourceBindingDeactivate::Conflict(_) => {
                return Err(transaction_conflict("revoke_binding_fence"));
            }
        }
        revoke_locator(
            connection,
            tenant_id,
            tenant,
            identity.kind,
            &identity.resource_id,
            &identity.digest,
            locator,
        )
        .await?;
    }
    let revoked = targets
        .into_iter()
        .map(|(identity, _)| identity)
        .collect::<Vec<_>>();
    let active_after = active_binding_map(connection, tenant_id).await?;
    let remaining = active_after
        .values()
        .filter_map(|binding| {
            parse_kind(&binding.resource_kind).map(|kind| TenantResourceIdentity {
                kind,
                resource_id: binding.resource_id.clone(),
                digest: binding.resource_digest.clone(),
            })
        })
        .collect::<Vec<_>>();
    let digest = canonical_tenant_resource_manifest_sha256(&remaining)
        .map_err(|_| ExecutorTransactionError::Executor(TenantResourceExecutorError::Rejected))?;
    Ok((sort_identities(revoked), digest))
}

#[derive(QueryableByName)]
struct MtlsParentClientRow {
    #[diesel(sql_type = sql_types::Uuid)]
    client_id: Uuid,
}

async fn validate_revoke_dependency_closure(
    connection: &mut AsyncPgConnection,
    tenant_id: Uuid,
    active: &BTreeMap<ResourceKey, TenantResourceBinding>,
    targets: &std::collections::BTreeSet<ResourceKey>,
) -> Result<(), ExecutorTransactionError> {
    for (child_key, child) in active {
        if targets.contains(child_key) {
            continue;
        }
        let parent_locator = match child_key.kind {
            TenantResourceKind::Openid4vcDataset => {
                match parse_locator(&child.locator, TenantResourceKind::Openid4vcDataset)? {
                    ResourceLocator::Dataset { subject_id, .. } => user_locator(subject_id),
                    _ => unreachable!(),
                }
            }
            TenantResourceKind::MtlsTrustAnchor => {
                let request_id =
                    parse_uuid_locator(&child.locator, TenantResourceKind::MtlsTrustAnchor)?;
                let parent = sql_query(
                    "SELECT client_id
                     FROM oauth_client_mtls_trust_anchor_requests
                     WHERE tenant_id = $1 AND id = $2
                       AND source = 'operator-managed' AND status = 1",
                )
                .bind::<sql_types::Uuid, _>(tenant_id)
                .bind::<sql_types::Uuid, _>(request_id)
                .get_result::<MtlsParentClientRow>(connection)
                .await
                .map_err(map_diesel_error)?;
                oauth_client_locator(parent.client_id)
            }
            TenantResourceKind::OauthClient => {
                let client_id =
                    parse_uuid_locator(&child.locator, TenantResourceKind::OauthClient)?;
                let public_client =
                    active_public_client_id_on_connection(connection, tenant_id, client_id)
                        .await
                        .map_err(ExecutorTransactionError::Repository)?
                        .ok_or_else(|| transaction_conflict("oauth_client_dependency"))?;
                match TenantResourceRepository::openid4vc_trust_policy_for_client_on_connection(
                    connection,
                    tenant_id,
                    &public_client,
                )
                .await
                .map_err(ExecutorTransactionError::Repository)?
                {
                    Openid4vcTrustPolicyForClient::Active(policy)
                        if targets.contains(&ResourceKey::new(
                            TenantResourceKind::Openid4vcTrustPolicy,
                            &policy.resource_id,
                        )) =>
                    {
                        return Err(ExecutorTransactionError::Executor(
                            TenantResourceExecutorError::Rejected,
                        ));
                    }
                    Openid4vcTrustPolicyForClient::Active(_)
                    | Openid4vcTrustPolicyForClient::BoundInactive
                    | Openid4vcTrustPolicyForClient::Unbound => {}
                }
                continue;
            }
            TenantResourceKind::Openid4vcTrustPolicy | TenantResourceKind::User => continue,
        };
        let parent = active
            .iter()
            .find_map(|(key, binding)| (binding.locator == parent_locator).then_some(key));
        let Some(parent) = parent else {
            return Err(ExecutorTransactionError::Executor(
                TenantResourceExecutorError::Unavailable,
            ));
        };
        if targets.contains(parent) {
            return Err(ExecutorTransactionError::Executor(
                TenantResourceExecutorError::Rejected,
            ));
        }
    }
    Ok(())
}

async fn revoke_locator(
    connection: &mut AsyncPgConnection,
    tenant_id: Uuid,
    tenant: TenantContext,
    kind: TenantResourceKind,
    resource_id: &str,
    expected_digest: &str,
    locator: &str,
) -> Result<(), ExecutorTransactionError> {
    match parse_locator(locator, kind)? {
        ResourceLocator::User(id) => {
            let user_id = nazo_identity::UserId::try_from(id).map_err(|_| {
                ExecutorTransactionError::Executor(TenantResourceExecutorError::Rejected)
            })?;
            let tenant_id = TenantId::try_from(tenant_id).map_err(|_| {
                ExecutorTransactionError::Executor(TenantResourceExecutorError::Rejected)
            })?;
            if !disable_user_on_connection(connection, tenant_id, user_id)
                .await
                .map_err(map_diesel_error)?
            {
                return Err(ExecutorTransactionError::Executor(
                    TenantResourceExecutorError::Rejected,
                ));
            }
        }
        ResourceLocator::OauthClient(id) => {
            if !deactivate_client_on_connection(connection, tenant_id, id)
                .await
                .map_err(map_diesel_error)?
            {
                return Err(ExecutorTransactionError::Executor(
                    TenantResourceExecutorError::Rejected,
                ));
            }
        }
        ResourceLocator::Mtls(request_id) => {
            if !revoke_operator_managed_trust_anchor_on_connection(
                connection,
                tenant.tenant_id,
                request_id,
            )
            .await
            .map_err(map_repository_error)?
            {
                return Err(ExecutorTransactionError::Executor(
                    TenantResourceExecutorError::Rejected,
                ));
            }
        }
        ResourceLocator::Dataset {
            subject_id,
            configuration_id,
        } => {
            if !delete_operator_managed_dataset_on_connection(
                connection,
                tenant_id,
                subject_id,
                &configuration_id,
            )
            .await
            .map_err(map_diesel_error)?
            {
                return Err(ExecutorTransactionError::Executor(
                    TenantResourceExecutorError::Rejected,
                ));
            }
        }
        ResourceLocator::TrustPolicy(policy_id) => {
            let result = TenantResourceRepository::revoke_openid4vc_trust_policy_on_connection(
                connection,
                tenant_id,
                resource_id,
                expected_digest,
            )
            .await
            .map_err(ExecutorTransactionError::Repository)?;
            match result {
                Openid4vcTrustPolicyRevoke::Revoked(policy) if policy.id == policy_id => {}
                Openid4vcTrustPolicyRevoke::Revoked(_) => {
                    return Err(ExecutorTransactionError::Executor(
                        TenantResourceExecutorError::Rejected,
                    ));
                }
                Openid4vcTrustPolicyRevoke::Conflict(_) => {
                    return Err(transaction_conflict("trust_policy_revoke_digest"));
                }
                Openid4vcTrustPolicyRevoke::AlreadyAbsent => {
                    return Err(ExecutorTransactionError::Executor(
                        TenantResourceExecutorError::Rejected,
                    ));
                }
            }
        }
    }
    Ok(())
}

fn is_operator_locator(locator: &str, kind: TenantResourceKind) -> bool {
    parse_locator(locator, kind).is_ok()
}

/// Authoritative read-only enumeration.  Returns the selector-filtered,
/// sorted identity set plus the complete active set so callers can assert
/// manifest consistency without a second read.
async fn enumerate_resources(
    connection: &mut AsyncPgConnection,
    tenant_id: Uuid,
    selectors: &[TenantResourceSelector],
) -> Result<(Vec<TenantResourceIdentity>, Vec<TenantResourceIdentity>), ExecutorTransactionError> {
    let active = TenantResourceRepository::active_bindings_on_connection(connection, tenant_id)
        .await
        .map_err(map_repository_error)?;
    let selected = |binding: &TenantResourceBinding| {
        selectors.is_empty()
            || selectors.iter().any(|selector| {
                kind_name(selector.kind) == binding.resource_kind
                    && selector.resource_id == binding.resource_id
            })
    };
    let mut result = Vec::new();
    let mut complete = Vec::new();
    for binding in active.into_iter() {
        let kind = parse_kind(&binding.resource_kind).ok_or(ExecutorTransactionError::Executor(
            TenantResourceExecutorError::Unavailable,
        ))?;
        complete.push(TenantResourceIdentity {
            kind,
            resource_id: binding.resource_id.clone(),
            digest: binding.resource_digest.clone(),
        });
        if selected(&binding) {
            result.push(TenantResourceIdentity {
                kind,
                resource_id: binding.resource_id,
                digest: binding.resource_digest,
            });
        }
        if complete.len() > nazo_operator_protocol::MAX_TENANT_RESOURCE_IDENTITIES
            || result.len() > nazo_operator_protocol::MAX_TENANT_RESOURCE_IDENTITIES
        {
            return Err(ExecutorTransactionError::Executor(
                TenantResourceExecutorError::TooLarge,
            ));
        }
    }
    Ok((sort_identities(result), sort_identities(complete)))
}

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
struct ResourceKey {
    kind: TenantResourceKind,
    resource_id: String,
}

impl ResourceKey {
    fn new(kind: TenantResourceKind, resource_id: &str) -> Self {
        Self {
            kind,
            resource_id: resource_id.to_owned(),
        }
    }

    fn from_identity(identity: &TenantResourceIdentity) -> Self {
        Self::new(identity.kind, &identity.resource_id)
    }
}

async fn active_binding_map(
    connection: &mut AsyncPgConnection,
    tenant_id: Uuid,
) -> Result<BTreeMap<ResourceKey, TenantResourceBinding>, ExecutorTransactionError> {
    let mut map = BTreeMap::new();
    for binding in TenantResourceRepository::active_bindings_on_connection(connection, tenant_id)
        .await
        .map_err(map_repository_error)?
    {
        let Some(kind) = parse_kind(&binding.resource_kind) else {
            return Err(ExecutorTransactionError::Executor(
                TenantResourceExecutorError::Unavailable,
            ));
        };
        map.insert(ResourceKey::new(kind, &binding.resource_id), binding);
    }
    Ok(map)
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ResourceLocator {
    User(Uuid),
    OauthClient(Uuid),
    Mtls(Uuid),
    TrustPolicy(Uuid),
    Dataset {
        subject_id: Uuid,
        configuration_id: String,
    },
}

fn parse_locator(
    locator: &str,
    expected_kind: TenantResourceKind,
) -> Result<ResourceLocator, ExecutorTransactionError> {
    let mut parts = locator.split('/');
    let prefix = parts.next().unwrap_or_default();
    let value = parts.next().unwrap_or_default();
    let result = match (prefix, expected_kind) {
        ("user", TenantResourceKind::User) if parts.next().is_none() => {
            Uuid::parse_str(value).ok().map(ResourceLocator::User)
        }
        ("oauth-client", TenantResourceKind::OauthClient) if parts.next().is_none() => {
            Uuid::parse_str(value)
                .ok()
                .map(ResourceLocator::OauthClient)
        }
        ("mtls-trust-anchor", TenantResourceKind::MtlsTrustAnchor) if parts.next().is_none() => {
            Uuid::parse_str(value).ok().map(ResourceLocator::Mtls)
        }
        ("openid4vc-trust-policy", TenantResourceKind::Openid4vcTrustPolicy)
            if parts.next().is_none() =>
        {
            Uuid::parse_str(value)
                .ok()
                .map(ResourceLocator::TrustPolicy)
        }
        ("openid4vc-dataset", TenantResourceKind::Openid4vcDataset) => {
            let configuration = parts.collect::<Vec<_>>().join("/");
            Uuid::parse_str(value).ok().and_then(|subject_id| {
                (!configuration.is_empty()).then_some(ResourceLocator::Dataset {
                    subject_id,
                    configuration_id: configuration,
                })
            })
        }
        _ => None,
    };
    result.ok_or(ExecutorTransactionError::Executor(
        TenantResourceExecutorError::Rejected,
    ))
}

fn parse_uuid_locator(
    locator: &str,
    kind: TenantResourceKind,
) -> Result<Uuid, ExecutorTransactionError> {
    match parse_locator(locator, kind)? {
        ResourceLocator::User(id)
        | ResourceLocator::OauthClient(id)
        | ResourceLocator::Mtls(id)
        | ResourceLocator::TrustPolicy(id) => Ok(id),
        ResourceLocator::Dataset { .. } => Err(ExecutorTransactionError::Executor(
            TenantResourceExecutorError::Rejected,
        )),
    }
}

fn user_locator(id: Uuid) -> String {
    format!("user/{id}")
}

fn oauth_client_locator(id: Uuid) -> String {
    format!("oauth-client/{id}")
}

fn mtls_locator(id: Uuid) -> String {
    format!("mtls-trust-anchor/{id}")
}

fn trust_policy_locator(id: Uuid) -> String {
    format!("openid4vc-trust-policy/{id}")
}

fn dataset_locator(subject_id: Uuid, configuration_id: &str) -> String {
    format!("openid4vc-dataset/{subject_id}/{configuration_id}")
}

fn kind_name(kind: TenantResourceKind) -> &'static str {
    match kind {
        TenantResourceKind::OauthClient => "oauth-client",
        TenantResourceKind::MtlsTrustAnchor => "mtls-trust-anchor",
        TenantResourceKind::Openid4vcDataset => "openid4vc-dataset",
        TenantResourceKind::Openid4vcTrustPolicy => "openid4vc-trust-policy",
        TenantResourceKind::User => "user",
    }
}

fn parse_kind(value: &str) -> Option<TenantResourceKind> {
    match value {
        "oauth-client" => Some(TenantResourceKind::OauthClient),
        "mtls-trust-anchor" => Some(TenantResourceKind::MtlsTrustAnchor),
        "openid4vc-dataset" => Some(TenantResourceKind::Openid4vcDataset),
        "openid4vc-trust-policy" => Some(TenantResourceKind::Openid4vcTrustPolicy),
        "user" => Some(TenantResourceKind::User),
        _ => None,
    }
}

fn identity_sort_key(identity: &TenantResourceIdentity) -> (u8, &str) {
    (kind_order(identity.kind), &identity.resource_id)
}

fn kind_order(kind: TenantResourceKind) -> u8 {
    match kind {
        TenantResourceKind::User => 0,
        TenantResourceKind::OauthClient => 1,
        TenantResourceKind::MtlsTrustAnchor => 2,
        TenantResourceKind::Openid4vcDataset => 3,
        TenantResourceKind::Openid4vcTrustPolicy => 4,
    }
}

fn sort_identities(mut identities: Vec<TenantResourceIdentity>) -> Vec<TenantResourceIdentity> {
    identities.sort_by(|left, right| identity_sort_key(left).cmp(&identity_sort_key(right)));
    identities
}

/// Build the append-only security-audit event for one executed tenant-resource
/// frame. Explicit fields keep the audit shape independent from the wire type.
#[allow(clippy::too_many_arguments)]
fn tenant_resource_audit_event(
    deployment_id: &str,
    tenant_id: &str,
    jti: &str,
    request_sha256: &str,
    actor: &Value,
    operation: TenantResourceAction,
    expected_revision: u64,
    resource_manifest_sha256: &str,
    resources: &[TenantResourceIdentity],
) -> crate::SecurityAuditEvent {
    crate::SecurityAuditEvent {
        event_id: Uuid::now_v7(),
        event_type: format!("tenant_resource_{}", operation_name(operation)),
        event_category: "tenant_resource".to_owned(),
        payload: json!({
            "deployment_id": deployment_id,
            "tenant_id": tenant_id,
            "jti": jti,
            "request_sha256": request_sha256,
            "actor": actor,
            "operation": operation_name(operation),
            "expected_revision": expected_revision,
            "resource_manifest_sha256": resource_manifest_sha256,
            "resources": resources,
        }),
        occurred_at: Utc::now(),
    }
}

#[derive(Debug)]
enum ExecutorTransactionError {
    Executor(TenantResourceExecutorError),
    Repository(RepositoryError),
    Diesel(diesel::result::Error),
}

fn transaction_conflict(stage: &'static str) -> ExecutorTransactionError {
    tracing::debug!(
        stage,
        "tenant-resource operation rejected by a consistency fence"
    );
    ExecutorTransactionError::Executor(TenantResourceExecutorError::Conflict)
}

impl From<TenantResourceExecutorError> for ExecutorTransactionError {
    fn from(error: TenantResourceExecutorError) -> Self {
        Self::Executor(error)
    }
}

impl From<diesel::result::Error> for ExecutorTransactionError {
    fn from(error: diesel::result::Error) -> Self {
        Self::Diesel(error)
    }
}

fn map_transaction_error(error: ExecutorTransactionError) -> TenantResourceExecutorError {
    match error {
        ExecutorTransactionError::Executor(error) => error,
        ExecutorTransactionError::Repository(error) => map_repository_error(error),
        ExecutorTransactionError::Diesel(error) => diesel_executor_error(error),
    }
}

fn map_repository_error(error: RepositoryError) -> TenantResourceExecutorError {
    match error {
        RepositoryError::Conflict => TenantResourceExecutorError::Conflict,
        RepositoryError::Unavailable | RepositoryError::NotFound => {
            TenantResourceExecutorError::Unavailable
        }
        RepositoryError::AlreadyProcessed => TenantResourceExecutorError::Rejected,
        RepositoryError::Consistency(_) | RepositoryError::Unexpected(_) => {
            TenantResourceExecutorError::Unavailable
        }
    }
}

fn map_diesel_error(error: diesel::result::Error) -> ExecutorTransactionError {
    ExecutorTransactionError::Executor(diesel_executor_error(error))
}

fn diesel_executor_error(error: diesel::result::Error) -> TenantResourceExecutorError {
    match error {
        diesel::result::Error::DatabaseError(
            diesel::result::DatabaseErrorKind::UniqueViolation,
            _,
        ) => TenantResourceExecutorError::Conflict,
        diesel::result::Error::NotFound => TenantResourceExecutorError::Rejected,
        _ => TenantResourceExecutorError::Unavailable,
    }
}

fn map_preparation_error(error: TenantResourcePreparationError) -> TenantResourceExecutorError {
    match error {
        TenantResourcePreparationError::Rejected => TenantResourceExecutorError::Rejected,
        TenantResourcePreparationError::Unavailable => TenantResourceExecutorError::Unavailable,
    }
}

fn is_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

impl TenantResourceExecutorPort for PostgresTenantResourceExecutor {
    fn execute_control_operation<'a>(
        &'a self,
        frame: ControlTenantResourceFrame<'a>,
    ) -> BoxFuture<'a, Result<ControlTenantResourceOutcome, TenantResourceExecutorError>> {
        Box::pin(PostgresTenantResourceExecutor::execute_control_operation(
            self, frame,
        ))
    }
}
