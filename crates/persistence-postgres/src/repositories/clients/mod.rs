mod admin;
mod base;
mod dynamic_registration;
mod logout;
mod mapping;
mod mutation;
mod query;

pub use base::OAuthClientRepository;
pub(crate) use base::{bind_conformance_lease, conformance_lease_is_effective};

// Mapping helpers are kept private to the repository module while remaining available to
// the compatibility unit tests mounted below.
#[cfg(test)]
use mapping::string_array;
use mapping::{OAuthClientRecord, map_error, registered_logout_client};

#[cfg(test)]
use nazo_identity::ports::RepositoryError;
#[cfg(test)]
use serde_json::Value;

#[cfg(test)]
#[path = "../../../tests/unit/repositories/clients.rs"]
mod tests;
