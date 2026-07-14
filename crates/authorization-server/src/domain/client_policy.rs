//! Database-row and client-key adapters for framework-independent OAuth policy.
use crate::domain::ClientRow;
pub(crate) use nazo_auth::{
    RedirectUriError, is_subset, is_valid_pkce_value, parse_resource_indicators, parse_scope,
    string_array_values as json_array_to_strings,
};
#[cfg(test)]
use serde_json::Value;

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
pub(crate) fn client_jwks_matching_encryption_key_count(jwks: &Value, alg: &str) -> usize {
    nazo_key_management::client_jwks_matching_encryption_key_count(jwks, alg)
}

#[cfg(test)]
pub(crate) fn client_jwks_contains_signing_key(jwks: &Value) -> bool {
    nazo_key_management::client_jwks_contains_signing_key(jwks)
}

#[cfg(test)]
pub(crate) fn validate_client_jwks(jwks: &Value) -> anyhow::Result<()> {
    validate_client_jwks_with_missing_kid_policy(jwks, false)
}

#[cfg(test)]
pub(crate) fn validate_client_jwks_with_missing_kid_policy(
    jwks: &Value,
    allow_missing_kid: bool,
) -> anyhow::Result<()> {
    nazo_key_management::validate_client_jwks_with_missing_kid_policy(jwks, allow_missing_kid)
        .map_err(anyhow::Error::msg)
}

#[cfg(test)]
pub(crate) fn validate_self_signed_mtls_jwks(jwks: &Value) -> bool {
    nazo_key_management::validate_self_signed_mtls_jwks(jwks)
}

#[cfg(test)]
pub(crate) fn authorization_code_key(code: &str) -> String {
    format!(
        "oauth:auth_code:{}",
        crate::adapters::security::blake3_hex(code)
    )
}

#[cfg(test)]
#[path = "../../tests/in_source/src/support/tests/oauth_client_jwks.rs"]
mod oauth_client_jwks_tests;
