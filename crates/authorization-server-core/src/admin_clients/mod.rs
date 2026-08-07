mod errors;
mod helpers;
mod patch;
mod policy;
mod ports;
mod registration;
mod requests;
mod service;
mod types;
mod validation;

// Keep the historical test path (`admin_clients::sector_identifier_host_for_redirects`) while
// the implementation lives with the other registration helpers.
#[cfg(test)]
use helpers::sector_identifier_host_for_redirects;

pub use errors::AdminClientError;
pub use patch::prepare_client_patch;
pub use policy::AdminClientPolicy;
pub use ports::{
    AdminClientCryptoPort, AdminClientFuture, AdminClientPortError, AdminClientRepositoryPort,
    SectorIdentifierFuture, SectorIdentifierResolverPort,
};
pub use registration::prepare_client_registration;
pub use requests::{CreateClientRequest, PatchClientRequest};
pub use service::{AdminClientService, insert_prepared_client};
pub use types::{CreatedClient, PreparedClientRegistration};
