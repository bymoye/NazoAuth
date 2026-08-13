//! Parsing and validation for RFC 7592 client configuration updates.

use serde_json::Value;

use crate::OAuthClient;

use super::{errors::DynamicRegistrationError, request::DynamicClientRegistrationRequest};

pub fn parse_client_configuration_update(
    mut payload: Value,
    current: &OAuthClient,
    current_has_secret: bool,
    submitted_secret_matches: bool,
) -> Result<DynamicClientRegistrationRequest, DynamicRegistrationError> {
    let Some(object) = payload.as_object_mut() else {
        return Err(DynamicRegistrationError::new(
            "invalid_request",
            "Client configuration update body must be a JSON object.",
        ));
    };
    for field in [
        "registration_access_token",
        "registration_client_uri",
        "client_secret_expires_at",
        "client_id_issued_at",
    ] {
        if object.contains_key(field) {
            return Err(DynamicRegistrationError::new(
                "invalid_request",
                format!("{field} is managed by the authorization server."),
            ));
        }
    }
    let client_id = object
        .remove("client_id")
        .and_then(|value| value.as_str().map(ToOwned::to_owned))
        .ok_or_else(|| {
            DynamicRegistrationError::invalid_client_metadata(
                "client_id must be present in a client configuration update.",
            )
        })?;
    if client_id != current.client_id {
        return Err(DynamicRegistrationError::invalid_client_metadata(
            "client_id must match the client configuration endpoint.",
        ));
    }
    let client_secret = object.remove("client_secret");
    match (current_has_secret, client_secret) {
        (true, Some(Value::String(_))) if submitted_secret_matches => {}
        (true, _) => {
            return Err(DynamicRegistrationError::invalid_client_metadata(
                "client_secret must match the current client secret.",
            ));
        }
        (false, Some(_)) => {
            return Err(DynamicRegistrationError::invalid_client_metadata(
                "public or assertion-based clients must not submit client_secret.",
            ));
        }
        (false, None) => {}
    }
    serde_json::from_value(payload).map_err(|error| {
        DynamicRegistrationError::invalid_client_metadata(format!(
            "Invalid client metadata: {error}"
        ))
    })
}
#[must_use]
pub fn response_types_from_client(client: &OAuthClient) -> Vec<String> {
    if client
        .grant_types
        .iter()
        .any(|grant| grant == "authorization_code")
    {
        vec!["code".to_owned()]
    } else {
        Vec::new()
    }
}
