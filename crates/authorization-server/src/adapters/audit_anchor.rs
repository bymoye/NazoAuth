//! External audit-ledger anchoring.
//!
//! The server owns only the writer-side [`AuditAnchorPreflight`] handle.  The
//! exporter command owns the database exporter role, HTTPS transport and sink
//! credential.  The implementation is split by those lifecycle boundaries so
//! the protocol and decision logic can be tested without a live database or
//! network.

pub(crate) mod config;
mod preflight;
mod protocol;
mod status;
mod transport;
mod worker;

pub(crate) use config::{
    AuditAnchorPreflightConfig, AuditAnchorWorkerConfig, preflight_config_from_source,
    worker_config_from_source,
};
pub(crate) use preflight::AuditAnchorPreflight;
pub(crate) use worker::run_worker;

#[cfg(test)]
#[path = "../../tests/unit/adapters/audit_anchor.rs"]
mod tests;
