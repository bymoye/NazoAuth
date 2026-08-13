//! Dynamic client registration protocol policy and dependency ports.

//! The facade keeps the historical `dynamic_client_registration` module path stable while
//! each responsibility lives in a focused child module.

mod errors;
mod parse;
mod policy;
mod ports;
mod request;

pub use errors::DynamicRegistrationError;
pub use parse::{parse_client_configuration_update, response_types_from_client};
pub use policy::{DynamicRegistrationPolicy, prepare_dynamic_client_registration};
pub use ports::{
    ClientSecretDigesterPort, DynamicRegistrationClientStore, DynamicRegistrationDependencyError,
    DynamicRegistrationFuture, DynamicRegistrationSecretPort,
};
pub use request::{DynamicClientRegistrationRequest, PreparedDynamicClientRegistration};

#[cfg(test)]
use crate::{ClientPresentationMetadata, OAuthClient};
#[cfg(test)]
use policy::negotiate_metadata_choice;

#[cfg(test)]
#[path = "../../tests/unit/dynamic_client_registration.rs"]
mod tests;
