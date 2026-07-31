use anyhow::bail;
pub(crate) use nazo_auth::DpopNoncePolicy;
use nazo_auth::{ClientAssuranceLevel, ClientSecurityPolicy, OAuthClient};

use crate::config::ConfigSource;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AuthorizationServerProfile {
    Oauth2Baseline,
    Fapi2Security,
    Fapi2MessageSigningAuthzRequest,
    Fapi2MessageSigningJarm,
    Fapi2MessageSigningIntrospection,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CibaSecurityProfile {
    FapiCibaId1,
    Fapi2Ciba,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RequestObjectJtiPolicy {
    Optional,
    RequiredForSignedJar,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum SubjectType {
    Public,
    Pairwise,
}

impl AuthorizationServerProfile {
    pub(super) fn from_config(config: &ConfigSource) -> anyhow::Result<Self> {
        match config
            .string("AUTHORIZATION_SERVER_PROFILE", "oauth2-baseline")
            .trim()
            .to_ascii_lowercase()
            .as_str()
        {
            "oauth2-baseline" | "baseline" => Ok(Self::Oauth2Baseline),
            "fapi2-security" => Ok(Self::Fapi2Security),
            "fapi2-message-signing-authz-request" => Ok(Self::Fapi2MessageSigningAuthzRequest),
            "fapi2-message-signing-jarm" => Ok(Self::Fapi2MessageSigningJarm),
            "fapi2-message-signing-introspection" => Ok(Self::Fapi2MessageSigningIntrospection),
            value => bail!("AUTHORIZATION_SERVER_PROFILE is not supported: {value}"),
        }
    }

    pub(crate) fn requires_fapi2_security(self) -> bool {
        matches!(
            self,
            Self::Fapi2Security
                | Self::Fapi2MessageSigningAuthzRequest
                | Self::Fapi2MessageSigningJarm
                | Self::Fapi2MessageSigningIntrospection
        )
    }

    pub(crate) fn requires_signed_authorization_request(self) -> bool {
        self == Self::Fapi2MessageSigningAuthzRequest
    }

    pub(crate) fn requires_signed_authorization_response(self) -> bool {
        self == Self::Fapi2MessageSigningJarm
    }

    pub(crate) fn effective_client_policy(self, client: &OAuthClient) -> ClientSecurityPolicy {
        self.effective_security_policy(client.security_policy.as_ref())
    }

    pub(crate) fn effective_security_policy(
        self,
        explicit: Option<&ClientSecurityPolicy>,
    ) -> ClientSecurityPolicy {
        explicit
            .cloned()
            .unwrap_or_else(|| self.legacy_client_policy())
    }

    pub(crate) fn legacy_client_policy(self) -> ClientSecurityPolicy {
        ClientSecurityPolicy {
            assurance: if self.requires_fapi2_security() {
                ClientAssuranceLevel::Fapi2
            } else {
                ClientAssuranceLevel::Baseline
            },
            require_signed_authorization_request: self.requires_signed_authorization_request(),
            require_signed_authorization_response: self.requires_signed_authorization_response(),
            require_signed_introspection_response: self == Self::Fapi2MessageSigningIntrospection,
            // Legacy clients preserve the prior server-wide behavior. The
            // corresponding runtime module and grant allowlist remain required.
            session_management: true,
            allow_cross_device_flows: true,
            ..ClientSecurityPolicy::default()
        }
    }
}

impl CibaSecurityProfile {
    pub(super) fn from_config(config: &ConfigSource) -> anyhow::Result<Self> {
        match config
            .string("CIBA_SECURITY_PROFILE", "fapi-ciba-id1")
            .trim()
            .to_ascii_lowercase()
            .as_str()
        {
            "fapi-ciba-id1" => Ok(Self::FapiCibaId1),
            "fapi2-ciba" => Ok(Self::Fapi2Ciba),
            value => bail!("CIBA_SECURITY_PROFILE is not supported: {value}"),
        }
    }

    pub(crate) fn requires_fapi2_hardening(self) -> bool {
        self == Self::Fapi2Ciba
    }

    pub(crate) const fn requires_fapi_ciba(self) -> bool {
        matches!(self, Self::FapiCibaId1 | Self::Fapi2Ciba)
    }
}

pub(super) fn dpop_nonce_policy_from_config(
    config: &ConfigSource,
) -> anyhow::Result<DpopNoncePolicy> {
    dpop_nonce_policy_from_config_key(config, "DPOP_NONCE_POLICY", "required")
}

pub(super) fn fapi_resource_dpop_nonce_policy_from_config(
    config: &ConfigSource,
) -> anyhow::Result<DpopNoncePolicy> {
    // RFC 9449 resource-server nonces are optional. The official FAPI2 DPoP
    // resource tests do not retry an initial protected-resource nonce
    // challenge, so the resource endpoint keeps nonce challenges optional by
    // default while DPoP jti replay protection remains mandatory.
    dpop_nonce_policy_from_config_key(config, "FAPI_RESOURCE_DPOP_NONCE_POLICY", "optional")
}

fn dpop_nonce_policy_from_config_key(
    config: &ConfigSource,
    key: &str,
    default: &str,
) -> anyhow::Result<DpopNoncePolicy> {
    match config
        .string(key, default)
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "required" | "require" | "strict" => Ok(DpopNoncePolicy::Required),
        "optional" => Ok(DpopNoncePolicy::Optional),
        value => bail!("{key} must be required or optional, got {value}"),
    }
}

impl RequestObjectJtiPolicy {
    pub(super) fn from_config(config: &ConfigSource) -> anyhow::Result<Self> {
        match config
            .string("REQUEST_OBJECT_JTI_POLICY", "optional")
            .trim()
            .to_ascii_lowercase()
            .as_str()
        {
            "optional" => Ok(Self::Optional),
            "required-for-signed-jar" | "required_signed_jar" | "required" => {
                Ok(Self::RequiredForSignedJar)
            }
            value => bail!(
                "REQUEST_OBJECT_JTI_POLICY must be optional or required-for-signed-jar, got {value}"
            ),
        }
    }
}

impl SubjectType {
    pub(super) fn from_config(config: &ConfigSource) -> anyhow::Result<Self> {
        match config
            .string("SUBJECT_TYPE", "public")
            .trim()
            .to_ascii_lowercase()
            .as_str()
        {
            "public" => Ok(Self::Public),
            "pairwise" => Ok(Self::Pairwise),
            value => bail!("SUBJECT_TYPE must be public or pairwise, got {value}"),
        }
    }
}

#[cfg(test)]
#[path = "../../tests/unit/settings_profile.rs"]
mod tests;
