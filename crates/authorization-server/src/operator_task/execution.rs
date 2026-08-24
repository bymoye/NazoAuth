//! E05/H07: dispatch of accepted [`ControlOperationPayload`]s onto the existing
//! NazoAuth business engines.
//!
//! No business logic lives here.  Every arm delegates to the engine that
//! already owns the domain:
//!
//! | variant                     | engine                                   | resumable state owner (resume_allowed) |
//! |-----------------------------|------------------------------------------|----------------------------------------|
//! | `migrate-apply`             | `cli::run_migrations` (Diesel runner)    | `__diesel_schema_migrations` ledger deduplicates re-entry → `true` |
//! | `keys-list`                 | `keyctl::operator_list`                  | read-only; no side effect to duplicate → `true` |
//! | `keys-validate`             | `keyctl::operator_validate`              | read-only; no side effect to duplicate → `true` |
//! | `keys-generate-local`       | `keyctl::operator_generate_local`        | keyset store dedupes the exact `(alg, purposes)` registration and returns the existing kid → `true` |
//! | `keys-register-external`    | `keyctl::operator_register_external`     | keyset store is documented idempotent for an identical kid/alg/key_ref/JWK registration and fails closed on drift → `true` |
//! | `tenant-resource-enumerate` | shared tenant-resource CAS engine        | read-only authoritative state read → `true` |
//! | `tenant-resource-apply`     | shared tenant-resource CAS engine (H07)  | fail closed → `false`: this driver deliberately writes no `tenant_resource_operations` replay row, so a crash that leaves the journal `executing` cannot prove whether the transaction committed; re-entry must not guess |
//! | `tenant-resource-revoke`    | same engine as apply (H07)               | same as apply → `false` |
//!
//! The mapping table above is normative for [`resume_allowed`]: re-entering a
//! checkpoint marked `true` is safe because its owner ledger provably
//! deduplicates the mutation; everything else fails closed instead of
//! guessing.  Output is only ever the journaled
//! [`nazo_operator_protocol::ControlResult`] — engines' rich return values
//! have exactly one wire channel, the closed typed
//! [`nazo_operator_protocol::ControlResultData`] (enumerate only).

use std::{fs, path::PathBuf};

use anyhow::{Context as _, bail};
use sha2::{Digest as _, Sha256};

use crate::adapters::security::constant_time_eq;
use crate::tenant_resource_executor::{
    ControlTenantResourceOutcome, PostgresTenantResourceExecutor,
};
use crate::tenant_resource_provider::{
    PreparedTenantResource, TenantResourceExecutorError, decode_change_set_payloads,
};
use nazo_operator_protocol::{
    ControlOperationPayload, ControlResultData, TenantResourceIdentity, TenantResourceOperation,
    TenantResourceSelector,
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
        ControlOperationPayload::KeysGenerateLocal { .. }
        | ControlOperationPayload::KeysRegisterExternal { .. } => true,
        ControlOperationPayload::TenantResourceEnumerate { .. } => true,
        // Serviced through the shared CAS engine since H07, but without a DB
        // replay ledger behind them (see the module table): an ambiguous
        // crash window must fail closed rather than risk a duplicate
        // mutation or a false failure report.
        ControlOperationPayload::TenantResourceApply { .. }
        | ControlOperationPayload::TenantResourceRevoke { .. } => false,
    }
}

pub(super) async fn execute(
    operation: &ControlOperationPayload,
    context: &ExecutionContext<'_>,
) -> anyhow::Result<Option<ControlResultData>> {
    match operation {
        ControlOperationPayload::MigrateApply => crate::cli::run_migrations().await.map(|_| None),
        ControlOperationPayload::KeysList => crate::keyctl::operator_list().await.map(|_| None),
        ControlOperationPayload::KeysValidate => {
            crate::keyctl::operator_validate().await.map(|_| None)
        }
        ControlOperationPayload::KeysGenerateLocal { alg, purposes } => {
            crate::keyctl::operator_generate_local(alg, purposes)
                .await
                .map(|_| None)
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
            let path = verify_public_jwk(public_jwk_sha256)?;
            crate::keyctl::operator_register_external(kid, alg, key_ref, path)
                .await
                .map(|_| None)
        }
        ControlOperationPayload::TenantResourceEnumerate {
            tenant_id,
            selectors,
        } => {
            let outcome = run_tenant_resource_operation(
                TenantResourceOperation::Enumerate,
                tenant_id,
                Vec::new(),
                selectors,
                context,
            )
            .await?;
            Ok(Some(ControlResultData::TenantResourceEnumerate {
                revision: outcome.revision,
                resources: outcome.resources,
            }))
        }
        ControlOperationPayload::TenantResourceApply {
            tenant_id,
            resources,
        } => {
            let prepared = prepare_apply_change_set(resources)?;
            run_tenant_resource_operation(
                TenantResourceOperation::Apply,
                tenant_id,
                prepared,
                &[],
                context,
            )
            .await
            .map(|_| None)
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
            run_tenant_resource_operation(
                TenantResourceOperation::Revoke,
                tenant_id,
                prepared,
                &[],
                context,
            )
            .await
            .map(|_| None)
        }
    }
}

/// Run one tenant-resource frame through the shared PostgreSQL CAS engine,
/// reusing every server-side ownership check of the HTTP provider path.
async fn run_tenant_resource_operation(
    operation: TenantResourceOperation,
    tenant_id: &str,
    resources: Vec<PreparedTenantResource>,
    selectors: &[TenantResourceSelector],
    context: &ExecutionContext<'_>,
) -> anyhow::Result<ControlTenantResourceOutcome> {
    let pool = super::operator_database()
        .await
        .context("tenant-resource operations require the application database")?;
    let composed = crate::tenant_resource_preparation::control_plane_resources(pool.clone())
        .await
        .context("tenant-resource registration policy bridge is unavailable")?;
    let executor = PostgresTenantResourceExecutor::new(
        nazo_postgres::TenantResourceRepository::new(pool),
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
        .execute_control_operation(
            crate::tenant_resource_executor::ControlTenantResourceFrame {
                deployment_id: context.deployment_id,
                jti: context.operation_id,
                request_sha256: context.request_hash,
                actor: &actor,
                operation,
                tenant_id,
                resources,
                selectors,
            },
        )
        .await
        .map_err(map_engine_error)
}

fn map_engine_error(error: TenantResourceExecutorError) -> anyhow::Error {
    match error {
        TenantResourceExecutorError::Conflict => {
            anyhow::anyhow!("tenant-resource operation lost its consistency fence")
        }
        TenantResourceExecutorError::Rejected => {
            anyhow::anyhow!("tenant-resource operation was rejected by policy")
        }
        TenantResourceExecutorError::Unavailable => {
            anyhow::anyhow!("tenant-resource persistence is unavailable")
        }
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
    decode_change_set_payloads(raw_manifest, None, &authorized).map_err(anyhow::Error::new)
}

pub(super) fn read_regular_bounded_file(path: &std::path::Path) -> anyhow::Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("operator change-set material must be a regular non-symlink file");
    }
    if metadata.len() > MAX_CHANGE_SET_BYTES as u64 {
        bail!("operator change-set material exceeds the maximum size");
    }
    let raw = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    if raw.is_empty() || raw.len() > MAX_CHANGE_SET_BYTES {
        bail!("operator change-set material is empty or oversized");
    }
    Ok(raw)
}

const EXTERNAL_PUBLIC_JWK_PATH: &str = "/run/nazauth-operator/public.jwk";

fn verify_public_jwk(expected_sha256: &str) -> anyhow::Result<PathBuf> {
    let path = super::configured_path(
        "NAZOAUTH_OPERATOR_PUBLIC_JWK_FILE",
        EXTERNAL_PUBLIC_JWK_PATH,
    );
    verify_public_jwk_at(expected_sha256, path)
}

pub(super) fn verify_public_jwk_at(
    expected_sha256: &str,
    path: PathBuf,
) -> anyhow::Result<PathBuf> {
    let bytes = fs::read(&path).context("external public JWK was not mounted")?;
    let actual: String = Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    if !constant_time_eq(actual.as_bytes(), expected_sha256.as_bytes()) {
        bail!("external public JWK digest mismatch");
    }
    Ok(path)
}
