//! Database-row and client-key adapters for framework-independent OAuth policy.
use crate::domain::ClientRow;
pub(crate) use nazo_auth::{
    RedirectUriError, is_subset, is_valid_pkce_value, parse_resource_indicators, parse_scope,
    string_array_values as json_array_to_strings,
};
pub(crate) fn client_supports_grant(client: &ClientRow, grant_type: &str) -> bool {
    client.grant_types.iter().any(|grant| grant == grant_type)
}

pub(crate) fn audiences_allowed(client: &ClientRow, audiences: &[String]) -> bool {
    !audiences.is_empty() && nazo_auth::is_subset(audiences, &client.allowed_audiences)
}

pub(crate) fn registered_redirect_uri(
    client: &ClientRow,
    requested_redirect_uri: Option<&str>,
) -> Result<String, RedirectUriError> {
    nazo_auth::resolve_registered_redirect_uri(
        &client.client_type,
        &client.redirect_uris,
        requested_redirect_uri,
    )
}

#[cfg(test)]
#[path = "../../tests/unit/domain/client_policy/oauth_client_jwks.rs"]
mod oauth_client_jwks_tests;
