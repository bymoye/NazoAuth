use nazo_identity::TenantContext;
use serde_json::Value;

use super::{AdminClientCryptoPort, AdminClientError};
use crate::{
    ClientProfile, ClientSecurityPolicy, SecurityProfile, SenderConstraintPolicy,
    validate_token_request_profile,
};

#[derive(Clone)]
pub struct AdminClientPolicy {
    pub tenant: TenantContext,
    pub pairwise_subject_secret: Option<String>,
    pub client_secret_pepper: String,
}

impl std::fmt::Debug for AdminClientPolicy {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AdminClientPolicy")
            .field("tenant", &self.tenant)
            .field(
                "pairwise_subject_secret",
                &self.pairwise_subject_secret.as_ref().map(|_| "[REDACTED]"),
            )
            .field("client_secret_pepper", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Copy)]
pub(super) struct ClientSecurityPolicyContext<'a> {
    pub(super) client_type: &'a str,
    pub(super) authentication_method: &'a str,
    pub(super) require_dpop_bound_tokens: bool,
    pub(super) require_mtls_bound_tokens: bool,
    pub(super) jwks_uri: Option<&'a str>,
    pub(super) jwks: Option<&'a Value>,
}

pub(super) fn validate_composable_security_policy<C: AdminClientCryptoPort + ?Sized>(
    policy: &ClientSecurityPolicy,
    context: ClientSecurityPolicyContext<'_>,
    crypto: &C,
) -> Result<(), AdminClientError> {
    if policy.requires_fapi2_security() {
        let sender_constraint = match (
            context.require_dpop_bound_tokens,
            context.require_mtls_bound_tokens,
        ) {
            (false, false) => SenderConstraintPolicy::BearerAllowed,
            (true, false) => SenderConstraintPolicy::DpopRequired,
            (false, true) => SenderConstraintPolicy::MtlsRequired,
            (true, true) => SenderConstraintPolicy::DpopOrMtls,
        };
        validate_token_request_profile(
            SecurityProfile::Fapi2Security,
            ClientProfile {
                client_type: context.client_type,
                authentication_method: context.authentication_method,
                sender_constraint,
            },
        )
        .map_err(|error| AdminClientError::InvalidRequest(error.description.to_owned()))?;
    }
    if policy.require_signed_authorization_request
        && context.jwks_uri.is_none()
        && !context
            .jwks
            .is_some_and(|jwks| crypto.contains_signing_key(jwks))
    {
        return Err(AdminClientError::InvalidRequest(
            "signed authorization requests require a client signing key".to_owned(),
        ));
    }
    Ok(())
}
