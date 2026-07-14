use anyhow::bail;

use crate::config::ConfigSource;

mod providers;
pub(crate) use providers::{
    ExternalLoginProvider, ExternalLoginProviderAdapter, FederationProviderRegistry,
    SocialProviderKind, SocialProviderSettings,
};

#[derive(Clone)]
pub(crate) struct FederationSettings {
    pub(crate) providers: FederationProviderRegistry,
    pub(crate) saml_gateway: Option<SamlGatewaySettings>,
}

#[derive(Clone)]
pub(crate) struct OidcFederationSettings {
    pub(crate) provider_id: String,
    pub(crate) issuer: String,
    pub(crate) authorization_endpoint: String,
    pub(crate) token_endpoint: String,
    pub(crate) jwks_url: String,
    pub(crate) client_id: String,
    pub(crate) client_secret: String,
    pub(crate) redirect_uri: String,
    pub(crate) scopes: String,
}

#[derive(Clone)]
pub(crate) struct SamlGatewaySettings {
    pub(crate) issuer: String,
    pub(crate) audience: String,
    pub(crate) secret: String,
}

impl FederationSettings {
    pub(super) fn from_config(config: &ConfigSource) -> anyhow::Result<Self> {
        let providers = FederationProviderRegistry::from_config(config)?;
        let saml_gateway = SamlGatewaySettings::from_config(config)?;
        Ok(Self {
            providers,
            saml_gateway,
        })
    }
}

impl SamlGatewaySettings {
    fn from_config(config: &ConfigSource) -> anyhow::Result<Option<Self>> {
        if !config.bool("FEDERATION_SAML_GATEWAY_ENABLED", false)? {
            return Ok(None);
        }
        let settings = Self {
            issuer: config.required_string("FEDERATION_SAML_GATEWAY_ISSUER")?,
            audience: config.required_string("FEDERATION_SAML_GATEWAY_AUDIENCE")?,
            secret: config.required_string("FEDERATION_SAML_GATEWAY_SECRET")?,
        };
        if settings.secret.len() < 32 {
            bail!("FEDERATION_SAML_GATEWAY_SECRET must be at least 32 bytes");
        }
        Ok(Some(settings))
    }
}
