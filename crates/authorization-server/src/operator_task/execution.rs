//! E05: dispatch of accepted [`ControlOperationPayload`]s onto the existing
//! NazoAuth business engines.
//!
//! No business logic lives here.  Every arm delegates to the engine that
//! already owns the domain:
//!
//! | variant                   | engine                                   | resumable state owner (resume_allowed) |
//! |---------------------------|------------------------------------------|----------------------------------------|
//! | `migrate-apply`           | `cli::run_migrations` (Diesel runner)    | `__diesel_schema_migrations` ledger deduplicates re-entry → `true` |
//! | `keys-list`               | `keyctl::operator_list`                  | read-only; no side effect to duplicate → `true` |
//! | `keys-validate`           | `keyctl::operator_validate`              | read-only; no side effect to duplicate → `true` |
//! | `keys-generate-local`     | `keyctl::operator_generate_local`        | keyset store dedupes the exact `(alg, purposes)` registration and returns the existing kid → `true` |
//! | `keys-register-external`  | `keyctl::operator_register_external`     | keyset store is documented idempotent for an identical kid/alg/key_ref/JWK registration and fails closed on drift → `true` |
//! | `tenant-resource-enumerate` | tenant-resource state repository       | read-only authoritative state read → `true` |
//! | `tenant-resource-apply`   | refused before journal acceptance        | (owner after H07: per-jti operation ledger + revision CAS) — unreachable here, fail closed with `false` |
//! | `tenant-resource-revoke`  | refused before journal acceptance        | same as apply → `false` |
//!
//! The mapping table above is normative for [`resume_allowed`]: re-entering a
//! checkpoint marked `true` is safe because its owner ledger provably
//! deduplicates the mutation; everything else fails closed instead of
//! guessing.  Output is only ever the journaled
//! [`nazo_operator_protocol::ControlResult`] — engines' rich return values
//! deliberately have no channel in the frozen result contract.

use anyhow::{Context as _, bail};
use sha2::{Digest as _, Sha256};

use super::*;
use crate::adapters::security::constant_time_eq;
use nazo_operator_protocol::ControlOperationPayload;

/// E05 resume ownership decision per closed variant (see module table).
pub(super) fn resume_allowed(operation: &ControlOperationPayload) -> bool {
    match operation {
        ControlOperationPayload::MigrateApply => true,
        ControlOperationPayload::KeysList | ControlOperationPayload::KeysValidate => true,
        ControlOperationPayload::KeysGenerateLocal { .. }
        | ControlOperationPayload::KeysRegisterExternal { .. } => true,
        ControlOperationPayload::TenantResourceEnumerate { .. } => true,
        // These never reach the journal today: admission refuses them before
        // acceptance while H07 completes their payload-channel wiring.  If a
        // future record ever exists, fail closed rather than guess.
        ControlOperationPayload::TenantResourceApply { .. }
        | ControlOperationPayload::TenantResourceRevoke { .. } => false,
    }
}

pub(super) async fn execute(operation: &ControlOperationPayload) -> anyhow::Result<()> {
    match operation {
        ControlOperationPayload::MigrateApply => crate::cli::run_migrations().await.map(|_| ()),
        ControlOperationPayload::KeysList => crate::keyctl::operator_list().await.map(|_| ()),
        ControlOperationPayload::KeysValidate => {
            crate::keyctl::operator_validate().await.map(|_| ())
        }
        ControlOperationPayload::KeysGenerateLocal { alg, purposes } => {
            crate::keyctl::operator_generate_local(alg, purposes)
                .await
                .map(|_| ())
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
                .map(|_| ())
        }
        ControlOperationPayload::TenantResourceEnumerate { tenant_id, .. } => {
            enumerate_tenant_state(tenant_id).await
        }
        ControlOperationPayload::TenantResourceApply { .. }
        | ControlOperationPayload::TenantResourceRevoke { .. } => {
            bail!("tenant-resource mutations are not serviced by the one-shot operator")
        }
    }
}

/// Authoritative read-only enumeration through the tenant-resource state
/// owner (the same CAS revision row the PostgreSQL executor fences on).  The
/// empty initial state is valid.
async fn enumerate_tenant_state(tenant_id: &str) -> anyhow::Result<()> {
    let tenant_uuid = uuid::Uuid::parse_str(tenant_id)
        .context("tenant-resource operation carries a malformed tenant id")?;
    let pool = super::operator_database()
        .await
        .context("tenant-resource enumeration requires the application database")?;
    let repository = nazo_postgres::TenantResourceRepository::new(pool);
    let _state = repository
        .state(tenant_uuid)
        .await
        .map_err(|error| anyhow::anyhow!("tenant-resource state is unavailable: {error}"))?;
    Ok(())
}

const EXTERNAL_PUBLIC_JWK_PATH: &str = "/run/nazauth-operator/public.jwk";

fn verify_public_jwk(expected_sha256: &str) -> anyhow::Result<PathBuf> {
    let path = configured_path(
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
