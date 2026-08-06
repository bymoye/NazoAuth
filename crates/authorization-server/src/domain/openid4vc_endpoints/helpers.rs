use std::collections::{BTreeMap, BTreeSet};

use nazo_openid4vc_http_actix::{
    CredentialEndpointResponse, CredentialHttpError, CredentialResponseBody, PresentationHttpError,
};
use nazo_openid4vci::{
    CredentialAccess, CredentialConfiguration, CredentialError, CredentialRequest,
    CredentialResponse, CredentialResponseEncoding, StoredCredentialResponse,
};
use serde_json::Value;
use uuid::Uuid;

use super::openid4vci::openid4vci_configuration_id_from_identifier;

pub(super) fn authorized_credentials(
    details: &Value,
    scope: &str,
    issuer: &str,
    configurations: &BTreeMap<String, CredentialConfiguration>,
) -> Result<(Vec<String>, Vec<nazo_openid4vci::CredentialIdentifier>), CredentialHttpError> {
    let mut ids = BTreeSet::new();
    let mut identifiers = BTreeSet::new();
    for detail in details.as_array().into_iter().flatten() {
        if detail.get("type").and_then(Value::as_str) != Some("openid_credential") {
            continue;
        }
        if detail
            .get("locations")
            .and_then(Value::as_array)
            .is_some_and(|locations| {
                !locations
                    .iter()
                    .any(|location| location.as_str() == Some(issuer))
            })
        {
            continue;
        }
        if let Some(id) = detail
            .get("credential_configuration_id")
            .and_then(Value::as_str)
        {
            ids.insert(id.to_owned());
        }
        for identifier in detail
            .get("credential_identifiers")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
        {
            identifiers.insert(identifier.to_owned());
        }
    }
    for requested_scope in scope.split_ascii_whitespace() {
        for (id, configuration) in configurations {
            if configuration.scope.as_deref() == Some(requested_scope) {
                ids.insert(id.clone());
            }
        }
    }
    if ids.is_empty() && identifiers.is_empty() {
        return Err(vci_error(
            403,
            "insufficient_scope",
            "Access token does not authorize credential issuance.",
        ));
    }
    if ids.iter().any(|id| !configurations.contains_key(id)) {
        return Err(vci_error(
            403,
            "insufficient_scope",
            "Access token references an unknown credential configuration.",
        ));
    }
    Ok((
        ids.into_iter().collect(),
        identifiers
            .into_iter()
            .map(nazo_openid4vci::CredentialIdentifier)
            .collect(),
    ))
}

pub(super) fn resolve_configuration_id(
    request: &CredentialRequest,
    access: &CredentialAccess,
) -> Result<String, CredentialHttpError> {
    request.validate_identifier().map_err(|_| {
        vci_error(
            400,
            "invalid_credential_request",
            "Exactly one credential identifier is required.",
        )
    })?;
    if let Some(id) = &request.credential_configuration_id {
        if !access.configuration_ids.iter().any(|allowed| allowed == id) {
            return Err(vci_error(
                400,
                "unknown_credential_configuration",
                "Credential configuration is not authorized.",
            ));
        }
        if !access.credential_identifiers.is_empty() {
            return Err(vci_error(
                400,
                "invalid_credential_request",
                "Credential identifier is required for this access token.",
            ));
        }
        return Ok(id.clone());
    }
    let identifier = request.credential_identifier.as_ref().expect("validated");
    let Some(configuration_id) = access
        .credential_identifiers
        .iter()
        .find(|allowed| *allowed == identifier)
        .and_then(openid4vci_configuration_id_from_identifier)
        .or_else(|| {
            access
                .configuration_ids
                .iter()
                .any(|allowed| allowed == &identifier.0)
                .then(|| identifier.0.clone())
        })
    else {
        return Err(vci_error(
            400,
            "unknown_credential_identifier",
            "Credential identifier is not authorized.",
        ));
    };
    access
        .configuration_ids
        .iter()
        .any(|allowed| allowed == &configuration_id)
        .then_some(configuration_id)
        .ok_or_else(|| {
            vci_error(
                400,
                "unknown_credential_identifier",
                "Credential identifier does not match an authorized configuration.",
            )
        })
}

pub(super) fn extract_proof_nonce(proofs: Option<&nazo_openid4vci::Proofs>) -> Option<String> {
    let encoded = proofs?.0.values().next()?.first()?.as_str()?;
    let claims = nazo_digital_credentials::decode_compact_jwt(encoded)
        .ok()?
        .claims;
    claims
        .get("nonce")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
}

/// Build the retry key from the canonical request model. The proof JWT is
/// intentionally retained in full: a retry must resend the exact proof body
/// that produced the committed response. A newly signed proof (even with the
/// same holder key and nonce) is a different request and is rejected once the
/// single-use nonce has been consumed.
pub(super) fn issuance_request_digest<T: serde::Serialize>(
    kind: &str,
    request: &T,
    request_url: &str,
    method: &str,
) -> Result<String, CredentialHttpError> {
    let request = serde_json::to_value(request)
        .map_err(|_| vci_error(500, "server_error", "Credential request digest failed."))?;
    let input = serde_json::json!({
        "version": 1,
        "kind": kind,
        "request": request,
        "request_url": request_url,
        "method": method,
    });
    let encoded = serde_json::to_vec(&input)
        .map_err(|_| vci_error(500, "server_error", "Credential request digest failed."))?;
    Ok(blake3::hash(&encoded).to_hex().to_string())
}

pub(super) fn stable_issuance_id(token_id: Uuid, request_digest: &str) -> Uuid {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"nazo-openid4vci-issuance-v1");
    hasher.update(token_id.as_bytes());
    hasher.update(request_digest.as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest.as_bytes()[..16]);
    Uuid::from_bytes(bytes)
}

pub(super) fn stored_response(
    issuance_id: Uuid,
    token_id: Uuid,
    request_digest: String,
    body: &CredentialResponseBody,
    dpop_nonce: Option<String>,
    expires_at: chrono::DateTime<chrono::Utc>,
) -> Result<StoredCredentialResponse, CredentialHttpError> {
    let (encoding, body) = match body {
        CredentialResponseBody::Json(value) => (
            CredentialResponseEncoding::Json,
            serde_json::to_vec(value).map_err(|_| {
                vci_error(500, "server_error", "Credential response encoding failed.")
            })?,
        ),
        CredentialResponseBody::Jwt(value) => {
            (CredentialResponseEncoding::Jwt, value.as_bytes().to_vec())
        }
    };
    let status = match body_encoding_is_deferred(&encoding, &body) {
        true => 202,
        false => 200,
    };
    Ok(StoredCredentialResponse {
        issuance_id,
        token_id,
        request_digest,
        body,
        encoding,
        status,
        dpop_nonce,
        expires_at,
    })
}

pub(super) fn body_encoding_is_deferred(
    encoding: &CredentialResponseEncoding,
    body: &[u8],
) -> bool {
    matches!(encoding, CredentialResponseEncoding::Json)
        && serde_json::from_slice::<CredentialResponse>(body)
            .ok()
            .is_some_and(|response| response.transaction_id.is_some())
}

pub(super) fn response_from_record(
    response: StoredCredentialResponse,
) -> Result<CredentialEndpointResponse<CredentialResponseBody>, CredentialHttpError> {
    let body = match response.encoding {
        CredentialResponseEncoding::Json => serde_json::from_slice(&response.body)
            .map(CredentialResponseBody::Json)
            .map_err(|_| {
                vci_error(
                    503,
                    "server_error",
                    "Stored credential response is invalid.",
                )
            })?,
        CredentialResponseEncoding::Jwt => String::from_utf8(response.body)
            .map(CredentialResponseBody::Jwt)
            .map_err(|_| {
                vci_error(
                    503,
                    "server_error",
                    "Stored credential response is invalid.",
                )
            })?,
    };
    Ok(CredentialEndpointResponse {
        body,
        dpop_nonce: response.dpop_nonce,
    })
}

pub(super) fn map_issuance_error(
    error: nazo_openid4vci::CredentialIssuanceError,
) -> CredentialHttpError {
    match error {
        nazo_openid4vci::CredentialIssuanceError::Credential(CredentialError::InvalidNonce) => {
            vci_error(400, "invalid_nonce", "Credential proof nonce is invalid.")
        }
        nazo_openid4vci::CredentialIssuanceError::Credential(CredentialError::InvalidProof)
        | nazo_openid4vci::CredentialIssuanceError::Proof(_) => {
            vci_error(400, "invalid_proof", "Credential proof is invalid.")
        }
        nazo_openid4vci::CredentialIssuanceError::InvalidHolderBinding => vci_error(
            400,
            "invalid_proof",
            "Credential holder binding is invalid.",
        ),
        nazo_openid4vci::CredentialIssuanceError::Unauthorized => vci_error(
            403,
            "insufficient_scope",
            "Credential issuance is not authorized.",
        ),
        _ => vci_error(503, "server_error", "Credential issuance failed."),
    }
}

pub(super) const fn vci_error(
    status: u16,
    error: &'static str,
    description: &'static str,
) -> CredentialHttpError {
    CredentialHttpError {
        status,
        error,
        description,
        dpop_nonce: None,
    }
}
pub(super) const fn vp_error(
    status: u16,
    error: &'static str,
    description: &'static str,
) -> PresentationHttpError {
    PresentationHttpError {
        status,
        error,
        description,
    }
}

#[cfg(test)]
#[path = "../../../tests/unit/domain/openid4vc_endpoints_helpers.rs"]
mod tests;
