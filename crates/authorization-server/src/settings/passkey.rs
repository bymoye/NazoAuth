use anyhow::bail;
use nazo_auth::validate_issuer_url;

use crate::config::ConfigSource;

#[derive(Clone)]
pub(crate) struct PasskeySettings {
    pub(crate) rp_id: String,
    pub(crate) rp_name: String,
    pub(crate) origin: String,
    pub(crate) require_user_verification: bool,
    pub(crate) require_user_handle: bool,
    pub(crate) strict_base64: bool,
}

impl PasskeySettings {
    pub(super) fn from_config(config: &ConfigSource, issuer: &str) -> anyhow::Result<Self> {
        let origin = config
            .optional_string("PASSKEY_ORIGIN")
            .unwrap_or_else(|| issuer.trim_end_matches('/').to_owned());
        validate_issuer_url(&origin)?;
        let rp_id = match config.optional_string("PASSKEY_RP_ID") {
            Some(value) => value,
            None => passkey_auth::RpId::try_from_url(&origin)
                .map_err(|error| anyhow::anyhow!("PASSKEY_ORIGIN cannot derive RP ID: {error}"))?
                .as_str()
                .to_owned(),
        };
        if rp_id.trim().is_empty()
            || rp_id.contains("://")
            || rp_id.contains('/')
            || rp_id.contains(':')
        {
            bail!("PASSKEY_RP_ID must be a bare host name without scheme, port, or path");
        }
        Ok(Self {
            rp_id,
            rp_name: config.string("PASSKEY_RP_NAME", "Nazo OAuth"),
            origin,
            require_user_verification: config.bool("PASSKEY_REQUIRE_USER_VERIFICATION", true)?,
            require_user_handle: config.bool("PASSKEY_REQUIRE_USER_HANDLE", true)?,
            strict_base64: config.bool("PASSKEY_STRICT_BASE64", true)?,
        })
    }
}
