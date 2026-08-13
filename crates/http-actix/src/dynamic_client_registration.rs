// Dynamic client registration is kept as one transport-facing module for
// callers and route wiring. Its protocol, security, IP-boundary, and response
// mechanics live in focused siblings under `dynamic_client_registration/`.

// These compatibility imports intentionally remain in the façade: the
// historical `#[path]` unit-test mount is a child of this module and uses the
// same names through `super::*`.
#[cfg(test)]
#[allow(unused_imports)]
use std::{future::Future, pin::Pin, sync::Arc};

#[cfg(test)]
#[allow(unused_imports)]
use actix_web::{
    FromRequest, HttpRequest, HttpResponse,
    http::{StatusCode, header},
    web::{Data, Json, Path, Payload},
};
#[cfg(test)]
#[allow(unused_imports)]
use nazo_auth::{
    AdminClientCryptoPort, AdminClientError, AdminClientPolicy, ClientSecretDigesterPort,
    DynamicClientRegistrationRequest, DynamicRegistrationError, DynamicRegistrationPolicy,
    DynamicRegistrationSecretPort, OAuthClient, PreparedClientRegistration,
    SectorIdentifierResolverPort, parse_client_configuration_update,
    prepare_dynamic_client_registration, response_types_from_client,
};
#[cfg(test)]
#[allow(unused_imports)]
use nazo_identity::TenantContext;
#[cfg(test)]
#[allow(unused_imports)]
use serde_json::{Value, json};
#[cfg(test)]
#[allow(unused_imports)]
use uuid::Uuid;

mod auth;
mod handlers;
mod ip;
mod response;
mod types;

pub use handlers::{
    client_configuration_delete, client_configuration_get, client_configuration_put,
    dynamic_client_registration,
};
pub use ip::{
    ClientIpConfig, ClientIpHeaderMode, ClientIpParseError, IpCidr, client_ip_with_config,
    client_ip_with_context, parse_forwarded_for_value, parse_trusted_proxy_cidrs,
    request_from_trusted_proxy_cidrs,
};
pub use nazo_auth::{
    DynamicRegistrationClientStore, DynamicRegistrationDependencyError, DynamicRegistrationFuture,
};
pub use types::{
    DynamicRegistrationEndpoint, DynamicRegistrationEndpointConfig,
    DynamicRegistrationRateLimitError, DynamicRegistrationRequestGuard,
    DynamicRegistrationSecurityServices, RemoteJwksFuture, RemoteJwksResolverPort,
};

// Preserve the old private names for the mounted unit tests and any crate-local
// test helpers. These are not part of the public transport API.
#[cfg(test)]
#[allow(unused_imports)]
use auth::{
    authenticate_registration_client, authorize_initial_access, bearer_token, enforce_rate_limit,
    initial_access_token_authorized, submitted_secret_matches,
};
#[cfg(test)]
#[allow(unused_imports)]
use handlers::prepare_insert;
#[cfg(test)]
#[allow(unused_imports)]
use response::{
    dynamic_registration_created_response, dynamic_registration_error_response,
    dynamic_registration_response, encode_path_segment, initial_access_denied, lookup_failed,
    map_insert_error, registration_access_denied,
};

#[cfg(test)]
#[path = "../tests/unit/dynamic_client_registration.rs"]
mod tests;
