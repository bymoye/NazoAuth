#![forbid(unsafe_code)]

#[cfg(test)]
#[macro_use]
#[path = "../tests/support/macros.rs"]
mod test_macros;

mod adapters;
pub mod bootstrap;
pub mod cli;
pub mod config;
mod conformance_lease;
mod control_discovery;
mod crypto;
mod domain;
mod http;
mod keyctl;
mod operator_task;
mod runtime_modules;
#[cfg(test)]
#[path = "../tests/support/schema.rs"]
mod schema;
mod settings;

#[cfg(test)]
#[path = "../tests/support/mod.rs"]
pub(crate) mod test_support;
