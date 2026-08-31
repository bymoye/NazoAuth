//! Authoritative tenant-directory lifecycle operations for the control plane.
//!
//! HTTP and controller consumers must reach the directory through this one
//! transaction boundary so every mutation, its audit event, and its
//! replay-safe operation outcome commit atomically together. The port is
//! deliberately concrete: five lifecycle actions with revision-fenced
//! semantics, no generic command surface.

use futures_util::future::BoxFuture;
use nazo_identity::{TenantDirectoryBinding, TenantId, TenantProvisioningRequest};
use serde::{Deserialize, Serialize};

/// One revision-fenced directory lifecycle action.
#[derive(Clone, Debug)]
pub enum DirectoryControlAction {
    /// Provision the tenant boundary and its canonical routing binding.
    Create {
        expected_revision: u64,
        provisioning: Box<TenantProvisioningRequest>,
    },
    /// Update the canonical issuer/host of one routed tenant.
    Update {
        expected_revision: u64,
        tenant_id: TenantId,
        issuer: String,
        external_host: String,
    },
    /// Suspend one routed tenant.
    Disable {
        expected_revision: u64,
        tenant_id: TenantId,
    },
    /// Publish a new tenant-local runtime generation after deterministic
    /// material has been installed and is ready for candidate validation.
    Reload {
        expected_revision: u64,
        tenant_id: TenantId,
    },
    /// Remove one routed tenant's binding.
    Finalize {
        expected_revision: u64,
        tenant_id: TenantId,
    },
    /// Read the authoritative directory snapshot.
    Describe,
}

/// Typed input of one directory control operation.
#[derive(Clone, Debug)]
pub struct DirectoryControlFrame<'a> {
    /// Accepted operation's signed deployment binding.
    pub deployment_id: &'a str,
    /// Accepted operation id (doubles as the ledger jti).
    pub jti: &'a str,
    /// Canonical request hash of the accepted operation.
    pub request_sha256: &'a str,
    /// Actor/controller identity recorded in the audit event.
    pub actor: &'a serde_json::Value,
    pub action: DirectoryControlAction,
}

/// Wire-stable outcome of a directory mutation. `action` mirrors the closed
/// lifecycle vocabulary (`create`, `update`, `disable`, `reload`, `finalize`).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DirectoryMutationOutcome {
    pub action: String,
    pub tenant_id: String,
    pub previous_revision: u64,
    pub revision: u64,
}

/// Wire-stable outcome of a directory describe.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DirectoryDescribeOutcome {
    pub revision: u64,
    pub tenants: Vec<TenantDirectoryBinding>,
}

/// Replay-safe outcome of one accepted directory control operation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum DirectoryControlOutcome {
    Mutation(DirectoryMutationOutcome),
    Describe(DirectoryDescribeOutcome),
}

impl DirectoryControlOutcome {
    /// The directory revision this outcome reports.
    #[must_use]
    pub fn revision(&self) -> u64 {
        match self {
            Self::Mutation(outcome) => outcome.revision,
            Self::Describe(outcome) => outcome.revision,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TenantDirectoryControlError {
    /// The revision fence or the operation ledger lost a race. Retrying with
    /// a fresh expected revision is safe; replaying the same operation id
    /// replays the recorded outcome.
    Conflict,
    /// The authoritative directory rejected the request (stale revision,
    /// unknown tenant, conflicting binding, or invalid routing identity).
    Rejected,
    /// The directory storage is unavailable; the operation may be retried.
    Unavailable,
}

impl std::fmt::Display for TenantDirectoryControlError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Conflict => "tenant directory operation lost its consistency fence",
            Self::Rejected => "tenant directory operation was rejected",
            Self::Unavailable => "tenant directory persistence is unavailable",
        })
    }
}

impl std::error::Error for TenantDirectoryControlError {}

/// Atomic directory lifecycle boundary implemented by each database adapter.
pub trait TenantDirectoryControlPort: Send + Sync {
    fn execute_control_operation<'a>(
        &'a self,
        frame: DirectoryControlFrame<'a>,
    ) -> BoxFuture<'a, Result<DirectoryControlOutcome, TenantDirectoryControlError>>;
}
