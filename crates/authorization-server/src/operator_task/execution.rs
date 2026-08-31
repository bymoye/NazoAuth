//! E05/H07: dispatch of accepted [`ControlOperationPayload`]s onto the existing
//! NazoAuth business engines.
//!
//! No business logic lives here.  Every arm delegates to the engine that
//! already owns the domain:
//!
//! | variant                     | engine                                   | resumable state owner (resume_allowed) |
//! |-----------------------------|------------------------------------------|----------------------------------------|
//! | `migrate-apply`             | selected adapter migration runner       | the adapter's migration ledger deduplicates re-entry → `true` |
//! | `keys-list`                 | `keyctl::operator_list`                  | read-only; no side effect to duplicate → `true` |
//! | `keys-validate`             | `keyctl::operator_validate`              | read-only; no side effect to duplicate → `true` |
//! | `keys-generate-local`       | `keyctl::operator_generate_local`        | private-key write may precede keyset publication; crash is ambiguous → `false` |
//! | `keys-register-external`    | `keyctl::operator_register_external`     | keyset store is documented idempotent for an identical kid/alg/key_ref/JWK registration and fails closed on drift → `true` |
//! | `tenant-resource-*`         | shared tenant-resource CAS engine        | exact operation-id/request-hash outcome ledger → `true` |
//!
//! The mapping table above is normative for [`resume_allowed`]: re-entering a
//! checkpoint marked `true` is safe because its owner ledger provably
//! deduplicates the mutation; everything else fails closed instead of
//! guessing.  Output is only ever the journaled
//! [`nazo_operator_protocol::ControlResult`] — engines' rich return values
//! have exactly one wire channel, the closed typed
//! [`nazo_operator_protocol::ControlResultData`].

use std::{
    fs::{self, File},
    io::Read as _,
    path::{Path, PathBuf},
};

use anyhow::{Context as _, bail};
use chrono::{Duration, Utc};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use super::{OperatorPersistence, control_journal::SideEffectError};
use crate::adapters::security::constant_time_eq;
use nazo_identity::{TenantBoundaryDefinition, TenantProvisioningRequest};
use nazo_operator_protocol::{
    ControlOperationPayload, ControlResultData, ControlTenantDirectoryBinding,
    TenantResourceIdentity, TenantResourceSelector,
};
use nazo_persistence::directory_control::{
    DirectoryControlAction, DirectoryControlFrame, DirectoryControlOutcome,
    TenantDirectoryControlError,
};
use nazo_persistence::tenant_resources::{
    ControlTenantResourceFrame, ControlTenantResourceOutcome, PreparedTenantResource,
    TenantResourceAction, TenantResourceExecutorError, decode_change_set_payloads,
};

/// Per-run provenance handed to engines whose durable records name the
/// accepted operation (audit events only; never an authorization input).
pub(super) struct ExecutionContext<'a> {
    /// Accepted operation id (`operation_id`, doubles as jti).
    pub(super) operation_id: &'a str,
    /// Signed deployment binding proven local at admission.
    pub(super) deployment_id: &'a str,
    /// Authorization snapshot from first journal acceptance.
    pub(super) controller_id: &'a str,
    pub(super) kid: &'a str,
    /// Canonical request hash of the accepted operation.
    pub(super) request_hash: &'a str,
}

/// E05 resume ownership decision per closed variant (see module table).
pub(super) fn resume_allowed(operation: &ControlOperationPayload) -> bool {
    match operation {
        ControlOperationPayload::MigrateApply => true,
        ControlOperationPayload::KeysList | ControlOperationPayload::KeysValidate => true,
        ControlOperationPayload::KeysGenerateLocal { .. } => false,
        ControlOperationPayload::KeysRegisterExternal { .. } => true,
        ControlOperationPayload::TenantResourceApply { .. }
        | ControlOperationPayload::TenantResourceEnumerate { .. }
        | ControlOperationPayload::TenantResourceRevoke { .. }
        | ControlOperationPayload::RecoveryInvalidate { .. }
        | ControlOperationPayload::TenantDirectoryCreate { .. }
        | ControlOperationPayload::TenantDirectoryUpdate { .. }
        | ControlOperationPayload::TenantDirectoryDisable { .. }
        | ControlOperationPayload::TenantDirectoryReload { .. }
        | ControlOperationPayload::TenantDirectoryFinalize { .. }
        | ControlOperationPayload::TenantDirectoryDescribe => true,
    }
}

pub(super) async fn execute_with_persistence(
    operation: &ControlOperationPayload,
    context: &ExecutionContext<'_>,
    persistence: &dyn OperatorPersistence,
) -> Result<Option<ControlResultData>, SideEffectError> {
    execute_inner(operation, context, Some(persistence)).await
}

pub(super) async fn execute_inner(
    operation: &ControlOperationPayload,
    context: &ExecutionContext<'_>,
    persistence: Option<&dyn OperatorPersistence>,
) -> Result<Option<ControlResultData>, SideEffectError> {
    match operation {
        ControlOperationPayload::MigrateApply => {
            let persistence = require_persistence(persistence)?;
            Ok(persistence.run_migrations().await.map(|_| None)?)
        }
        ControlOperationPayload::KeysList => {
            Ok(crate::keyctl::operator_list().await.map(|_| None)?)
        }
        ControlOperationPayload::KeysValidate => {
            Ok(crate::keyctl::operator_validate().await.map(|_| None)?)
        }
        ControlOperationPayload::KeysGenerateLocal { alg, purposes } => {
            Ok(crate::keyctl::operator_generate_local(alg, purposes)
                .await
                .map(|_| None)?)
        }
        ControlOperationPayload::KeysRegisterExternal {
            kid,
            alg,
            key_ref,
            public_jwk_sha256,
        } => {
            // The mounted JWK is payload material, not an identity envelope:
            // its bytes must hash exactly to the signed `public_jwk_sha256`
            // claim before registration proceeds.
            let public_jwk = verify_public_jwk(public_jwk_sha256)?;
            Ok(
                crate::keyctl::operator_register_external(kid, alg, key_ref, &public_jwk)
                    .await
                    .map(|_| None)?,
            )
        }
        ControlOperationPayload::TenantResourceEnumerate {
            tenant_id,
            selectors,
        } => {
            let persistence = require_persistence(persistence)?;
            let outcome = run_tenant_resource_operation(
                TenantResourceAction::Enumerate,
                tenant_id,
                Vec::new(),
                selectors,
                context,
                persistence,
            )
            .await?;
            Ok(Some(
                outcome.control_result_data(TenantResourceAction::Enumerate),
            ))
        }
        ControlOperationPayload::TenantResourceApply {
            tenant_id,
            resources,
        } => {
            let prepared = prepare_apply_change_set(resources)?;
            let persistence = require_persistence(persistence)?;
            let outcome = run_tenant_resource_operation(
                TenantResourceAction::Apply,
                tenant_id,
                prepared,
                &[],
                context,
                persistence,
            )
            .await?;
            Ok(Some(
                outcome.control_result_data(TenantResourceAction::Apply),
            ))
        }
        ControlOperationPayload::TenantResourceRevoke {
            tenant_id,
            resources,
        } => {
            let prepared = resources
                .iter()
                .cloned()
                .map(|identity| PreparedTenantResource {
                    identity,
                    payload: None,
                })
                .collect();
            let persistence = require_persistence(persistence)?;
            let outcome = run_tenant_resource_operation(
                TenantResourceAction::Revoke,
                tenant_id,
                prepared,
                &[],
                context,
                persistence,
            )
            .await?;
            Ok(Some(
                outcome.control_result_data(TenantResourceAction::Revoke),
            ))
        }
        ControlOperationPayload::RecoveryInvalidate { state_epoch } => {
            let persistence = require_persistence(persistence)?;
            run_recovery_invalidation(state_epoch, context, persistence)
                .await
                .map(Some)
        }
        ControlOperationPayload::TenantDirectoryCreate {
            expected_revision,
            tenant,
            realm,
            organization,
            issuer,
            external_host,
        } => {
            let parse_boundary_id =
                |boundary: &nazo_operator_protocol::ControlTenantBoundary,
                 error: &'static str|
                 -> Result<nazo_identity::TenantId, SideEffectError> {
                    Uuid::parse_str(&boundary.id)
                        .map_err(|_| SideEffectError::Terminal(anyhow::anyhow!(error)))?
                        .try_into()
                        .map_err(|_| SideEffectError::Terminal(anyhow::anyhow!(error)))
                };
            let tenant_id = parse_boundary_id(tenant, "tenant boundary id is invalid")?;
            let realm_id = Uuid::parse_str(&realm.id)
                .map_err(|_| {
                    SideEffectError::Terminal(anyhow::anyhow!("realm boundary id is invalid"))
                })?
                .try_into()
                .map_err(|_| {
                    SideEffectError::Terminal(anyhow::anyhow!("realm boundary id is invalid"))
                })?;
            let organization_id = Uuid::parse_str(&organization.id)
                .map_err(|_| {
                    SideEffectError::Terminal(anyhow::anyhow!(
                        "organization boundary id is invalid"
                    ))
                })?
                .try_into()
                .map_err(|_| {
                    SideEffectError::Terminal(anyhow::anyhow!(
                        "organization boundary id is invalid"
                    ))
                })?;
            let provisioning = TenantProvisioningRequest {
                tenant: TenantBoundaryDefinition {
                    id: tenant_id,
                    slug: tenant.slug.clone(),
                    display_name: tenant.display_name.clone(),
                },
                realm: TenantBoundaryDefinition {
                    id: realm_id,
                    slug: realm.slug.clone(),
                    display_name: realm.display_name.clone(),
                },
                organization: TenantBoundaryDefinition {
                    id: organization_id,
                    slug: organization.slug.clone(),
                    display_name: organization.display_name.clone(),
                },
                binding: nazo_identity::TenantDirectoryBinding {
                    tenant: nazo_identity::TenantContext {
                        tenant_id,
                        realm_id,
                        organization_id,
                    },
                    runtime_revision: 1,
                    issuer: issuer.clone(),
                    external_host: external_host.clone(),
                },
            };
            let persistence = require_persistence(persistence)?;
            run_directory_control_operation(
                DirectoryControlAction::Create {
                    expected_revision: *expected_revision,
                    provisioning: Box::new(provisioning),
                },
                context,
                persistence,
            )
            .await
            .map(Some)
        }
        ControlOperationPayload::TenantDirectoryUpdate {
            expected_revision,
            tenant_id,
            issuer,
            external_host,
        } => {
            let persistence = require_persistence(persistence)?;
            run_directory_control_operation(
                DirectoryControlAction::Update {
                    expected_revision: *expected_revision,
                    tenant_id: parse_control_tenant_id(tenant_id)?,
                    issuer: issuer.clone(),
                    external_host: external_host.clone(),
                },
                context,
                persistence,
            )
            .await
            .map(Some)
        }
        ControlOperationPayload::TenantDirectoryDisable {
            expected_revision,
            tenant_id,
        } => {
            let persistence = require_persistence(persistence)?;
            run_directory_control_operation(
                DirectoryControlAction::Disable {
                    expected_revision: *expected_revision,
                    tenant_id: parse_control_tenant_id(tenant_id)?,
                },
                context,
                persistence,
            )
            .await
            .map(Some)
        }
        ControlOperationPayload::TenantDirectoryReload {
            expected_revision,
            tenant_id,
        } => {
            let persistence = require_persistence(persistence)?;
            run_directory_control_operation(
                DirectoryControlAction::Reload {
                    expected_revision: *expected_revision,
                    tenant_id: parse_control_tenant_id(tenant_id)?,
                },
                context,
                persistence,
            )
            .await
            .map(Some)
        }
        ControlOperationPayload::TenantDirectoryFinalize {
            expected_revision,
            tenant_id,
        } => {
            let persistence = require_persistence(persistence)?;
            run_directory_control_operation(
                DirectoryControlAction::Finalize {
                    expected_revision: *expected_revision,
                    tenant_id: parse_control_tenant_id(tenant_id)?,
                },
                context,
                persistence,
            )
            .await
            .map(Some)
        }
        ControlOperationPayload::TenantDirectoryDescribe => {
            let persistence = require_persistence(persistence)?;
            run_directory_control_operation(DirectoryControlAction::Describe, context, persistence)
                .await
                .map(Some)
        }
    }
}

fn parse_control_tenant_id(tenant_id: &str) -> Result<nazo_identity::TenantId, SideEffectError> {
    Uuid::parse_str(tenant_id)
        .map_err(|_| SideEffectError::Terminal(anyhow::anyhow!("tenant id is invalid")))?
        .try_into()
        .map_err(|_| SideEffectError::Terminal(anyhow::anyhow!("tenant id is invalid")))
}

/// Runs one directory lifecycle action through the authoritative atomic
/// boundary that owns the revision fence, audit, and outcome ledger.
async fn run_directory_control_operation(
    action: DirectoryControlAction,
    context: &ExecutionContext<'_>,
    persistence: &dyn OperatorPersistence,
) -> Result<ControlResultData, SideEffectError> {
    let actor = serde_json::json!({
        "kind": "controller",
        "controller_id": context.controller_id,
        "kid": context.kid,
    });
    let outcome = persistence
        .tenant_directory_executor()
        .execute_control_operation(DirectoryControlFrame {
            deployment_id: context.deployment_id,
            jti: context.operation_id,
            request_sha256: context.request_hash,
            actor: &actor,
            action,
        })
        .await
        .map_err(map_directory_control_error)?;
    Ok(match outcome {
        DirectoryControlOutcome::Mutation(outcome) => ControlResultData::TenantDirectoryMutation {
            action: outcome.action,
            tenant_id: outcome.tenant_id,
            previous_revision: outcome.previous_revision,
            revision: outcome.revision,
        },
        DirectoryControlOutcome::Describe(outcome) => ControlResultData::TenantDirectoryDescribe {
            revision: outcome.revision,
            tenants: outcome
                .tenants
                .into_iter()
                .map(|binding| ControlTenantDirectoryBinding {
                    tenant_id: binding.tenant.tenant_id.as_uuid().to_string(),
                    realm_id: binding.tenant.realm_id.as_uuid().to_string(),
                    organization_id: binding.tenant.organization_id.as_uuid().to_string(),
                    runtime_revision: binding.runtime_revision,
                    issuer: binding.issuer,
                    external_host: binding.external_host,
                })
                .collect(),
        },
    })
}

fn map_directory_control_error(error: TenantDirectoryControlError) -> SideEffectError {
    match error {
        TenantDirectoryControlError::Conflict => SideEffectError::Terminal(anyhow::anyhow!(
            "tenant directory operation lost its consistency fence"
        )),
        TenantDirectoryControlError::Rejected => SideEffectError::Terminal(anyhow::anyhow!(
            "tenant directory operation was rejected by the authoritative directory"
        )),
        TenantDirectoryControlError::Unavailable => SideEffectError::Retryable(anyhow::anyhow!(
            "tenant directory persistence is unavailable"
        )),
    }
}

fn require_persistence(
    persistence: Option<&dyn OperatorPersistence>,
) -> Result<&dyn OperatorPersistence, SideEffectError> {
    persistence.ok_or_else(|| {
        SideEffectError::Retryable(anyhow::anyhow!(
            "operator persistence adapter is unavailable"
        ))
    })
}

/// The state epoch is selected before the candidate starts; this operation
/// durably records the post-restore boundary in that restored database and
/// revokes all its refresh tokens. It never claims to revoke stateless JWTs:
/// ctl keeps ingress closed until the returned absolute deadline has passed.
async fn run_recovery_invalidation(
    state_epoch: &str,
    context: &ExecutionContext<'_>,
    persistence: &dyn OperatorPersistence,
) -> Result<ControlResultData, SideEffectError> {
    let config = crate::config::ConfigSource::load_for_migrations()?;
    let configured_epoch = config.transient_state_epoch()?;
    if configured_epoch.is_nil() || configured_epoch.to_string() != state_epoch {
        return Err(anyhow::anyhow!(
            "recovery operation state epoch does not match the running candidate"
        )
        .into());
    }
    let active_tenant = nazo_identity::TenantContext::default_system()
        .tenant_id
        .as_uuid();
    let access_token_ttl = crate::settings::bounded_access_token_ttl_seconds(&config)?;
    let id_token_ttl = crate::settings::bounded_id_token_ttl_seconds(&config)?;
    let completed_at = Utc::now();
    let not_before = completed_at
        + Duration::seconds(
            access_token_ttl
                .max(id_token_ttl)
                .saturating_add(crate::settings::RECOVERY_ACCESS_TOKEN_CLOCK_SKEW_SECONDS)
                .saturating_add(1),
        );
    let outcome = persistence
        .recovery_invalidations()
        .invalidate_after_restore(
            Uuid::parse_str(context.operation_id).context("operation id is invalid")?,
            context.request_hash,
            active_tenant,
            configured_epoch,
            not_before,
            completed_at,
        )
        .await
        .map_err(map_recovery_persistence_error)?;
    Ok(ControlResultData::RecoveryInvalidation {
        state_epoch: outcome.state_epoch.to_string(),
        not_before: outcome.not_before.timestamp(),
        revoked_refresh_tokens: outcome.revoked_refresh_tokens,
    })
}

pub(super) fn map_recovery_persistence_error(
    error: nazo_identity::ports::RepositoryError,
) -> SideEffectError {
    match error {
        // This is the durable unique (tenant_id, state_epoch) outcome owned
        // by a different operation. Retrying cannot change it.
        nazo_identity::ports::RepositoryError::Conflict
        | nazo_identity::ports::RepositoryError::Consistency(_) => SideEffectError::Terminal(
            anyhow::anyhow!("recovery invalidation conflicts with durable authority"),
        ),
        nazo_identity::ports::RepositoryError::Unavailable
        | nazo_identity::ports::RepositoryError::Unexpected(_) => SideEffectError::Retryable(
            anyhow::anyhow!("recovery invalidation persistence is unavailable"),
        ),
        nazo_identity::ports::RepositoryError::NotFound
        | nazo_identity::ports::RepositoryError::AlreadyProcessed => SideEffectError::Terminal(
            anyhow::anyhow!("recovery invalidation persistence rejected the operation"),
        ),
    }
}

/// Run one tenant-resource frame through the selected adapter's CAS engine,
/// which owns all server-side tenant-resource validation and mutation.
async fn run_tenant_resource_operation(
    operation: TenantResourceAction,
    tenant_id: &str,
    resources: Vec<PreparedTenantResource>,
    selectors: &[TenantResourceSelector],
    context: &ExecutionContext<'_>,
    persistence: &dyn OperatorPersistence,
) -> Result<ControlTenantResourceOutcome, SideEffectError> {
    let composed =
        crate::tenant_resource_preparation::control_plane_resources(persistence.admin_clients())
            .await
            .map_err(|error| {
                SideEffectError::Retryable(
                    error.context("tenant-resource registration policy bridge is unavailable"),
                )
            })?;
    let executor = persistence.tenant_resource_executor(
        composed.tenant,
        composed.data_encryption_key,
        composed.preparation,
    );
    let actor = serde_json::json!({
        "kind": "controller",
        "controller_id": context.controller_id,
        "kid": context.kid,
    });
    executor
        .execute_control_operation(ControlTenantResourceFrame {
            deployment_id: context.deployment_id,
            jti: context.operation_id,
            request_sha256: context.request_hash,
            actor: &actor,
            operation,
            tenant_id,
            resources,
            selectors,
        })
        .await
        .map_err(map_engine_error)
}

pub(super) fn map_engine_error(error: TenantResourceExecutorError) -> SideEffectError {
    match error {
        TenantResourceExecutorError::Conflict => SideEffectError::Terminal(anyhow::anyhow!(
            "tenant-resource operation lost its consistency fence"
        )),
        TenantResourceExecutorError::Rejected => SideEffectError::Terminal(anyhow::anyhow!(
            "tenant-resource operation was rejected by policy"
        )),
        TenantResourceExecutorError::InvalidPayload(message) => {
            SideEffectError::Terminal(anyhow::anyhow!(message))
        }
        TenantResourceExecutorError::TooLarge => {
            SideEffectError::Terminal(anyhow::anyhow!("tenant-resource payload is too large"))
        }
        // This includes a lost transaction-commit response. Re-entering the
        // same operation id and request hash is safe because the transaction
        // committed its typed outcome in the durable replay ledger.
        TenantResourceExecutorError::Unavailable => SideEffectError::Retryable(anyhow::anyhow!(
            "tenant-resource persistence is unavailable"
        )),
    }
}

const EXTERNAL_CHANGE_SET_PATH: &str = "/run/nazauth-operator/change-set.json";
pub(super) const MAX_CHANGE_SET_BYTES: usize = 4 * 1024 * 1024;

fn configured_change_set_path() -> PathBuf {
    super::configured_path(
        "NAZOAUTH_OPERATOR_CHANGE_SET_FILE",
        EXTERNAL_CHANGE_SET_PATH,
    )
}

/// Read the privileged mounted change-set manifest and bind every per-resource
/// payload to the signed identity digests (same material-binding pattern as
/// the external public JWK).  Returns typed payloads ready for the CAS engine.
fn prepare_apply_change_set(
    identities: &[TenantResourceIdentity],
) -> anyhow::Result<Vec<PreparedTenantResource>> {
    let path = configured_change_set_path();
    let raw = read_regular_bounded_file(&path)?;
    prepare_change_set_material(&raw, identities).map_err(|error| {
        anyhow::anyhow!("mounted change set {} is unusable: {error}", path.display())
    })
}

/// Pure digest binding of already-read change-set bytes against the signed
/// identity set.
pub(super) fn prepare_change_set_material(
    raw_manifest: &[u8],
    identities: &[TenantResourceIdentity],
) -> anyhow::Result<Vec<PreparedTenantResource>> {
    let mut authorized = std::collections::BTreeMap::new();
    for identity in identities {
        if authorized
            .insert(
                (identity.kind, identity.resource_id.clone()),
                identity.clone(),
            )
            .is_some()
        {
            bail!("signed resource identities must be unique");
        }
    }
    decode_change_set_payloads(raw_manifest, &authorized).map_err(anyhow::Error::new)
}

pub(super) fn read_regular_bounded_file(path: &std::path::Path) -> anyhow::Result<Vec<u8>> {
    read_regular_file_bounded(path, MAX_CHANGE_SET_BYTES, "operator change-set material")
}

fn read_regular_file_bounded(
    path: &Path,
    max_bytes: usize,
    material: &str,
) -> anyhow::Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("{material} must be a regular non-symlink file");
    }
    if metadata.len() > max_bytes as u64 {
        bail!("{material} exceeds the maximum size");
    }
    let file = File::open(path).with_context(|| format!("failed to read {}", path.display()))?;
    let opened_metadata = file
        .metadata()
        .with_context(|| format!("failed to inspect opened file {}", path.display()))?;
    if !opened_metadata.is_file() || opened_metadata.len() > max_bytes as u64 {
        bail!("{material} is not a bounded regular file");
    }
    let mut raw = Vec::with_capacity((opened_metadata.len() as usize).min(max_bytes));
    file.take(max_bytes.saturating_add(1) as u64)
        .read_to_end(&mut raw)
        .with_context(|| format!("failed to read {}", path.display()))?;
    if raw.is_empty() || raw.len() > max_bytes {
        bail!("{material} is empty or oversized");
    }
    Ok(raw)
}

const EXTERNAL_PUBLIC_JWK_PATH: &str = "/run/nazauth-operator/public.jwk";
const MAX_EXTERNAL_PUBLIC_JWK_BYTES: usize = 64 * 1024;

fn verify_public_jwk(expected_sha256: &str) -> anyhow::Result<Vec<u8>> {
    let path = super::configured_path(
        "NAZOAUTH_OPERATOR_PUBLIC_JWK_FILE",
        EXTERNAL_PUBLIC_JWK_PATH,
    );
    verify_public_jwk_at(expected_sha256, path)
}

pub(super) fn verify_public_jwk_at(
    expected_sha256: &str,
    path: PathBuf,
) -> anyhow::Result<Vec<u8>> {
    let bytes =
        read_regular_file_bounded(&path, MAX_EXTERNAL_PUBLIC_JWK_BYTES, "external public JWK")
            .context("external public JWK was not mounted")?;
    let actual: String = Sha256::digest(&bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    if !constant_time_eq(actual.as_bytes(), expected_sha256.as_bytes()) {
        bail!("external public JWK digest mismatch");
    }
    Ok(bytes)
}
