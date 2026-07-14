use crate::{ProtocolError, ProtocolErrorCode, SecurityProfile, SenderConstraintPolicy};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClientProfile<'a> {
    pub client_type: &'a str,
    pub authentication_method: &'a str,
    pub sender_constraint: SenderConstraintPolicy,
}

pub fn validate_token_request_profile(
    profile: SecurityProfile,
    client: ClientProfile<'_>,
) -> Result<(), ProtocolError> {
    if !profile.requires_fapi2_security() {
        return Ok(());
    }
    if client.client_type != "confidential" {
        return Err(ProtocolError::new(
            ProtocolErrorCode::UnauthorizedClient,
            "FAPI2 profiles require confidential clients.",
        ));
    }
    if !matches!(
        client.authentication_method,
        "private_key_jwt" | "tls_client_auth" | "self_signed_tls_client_auth"
    ) {
        return Err(ProtocolError::new(
            ProtocolErrorCode::InvalidClient,
            "FAPI2 profiles require private_key_jwt or mTLS client authentication.",
        ));
    }
    if !client.sender_constraint.is_sender_constrained() {
        return Err(ProtocolError::new(
            ProtocolErrorCode::InvalidRequest,
            "FAPI2 profiles require sender-constrained access tokens.",
        ));
    }
    Ok(())
}
