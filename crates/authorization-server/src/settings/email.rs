use anyhow::{Context, bail};
use lettre::message::Mailbox;

use super::positive_u64;
use crate::config::ConfigSource;

#[derive(Clone)]
pub(crate) struct EmailSettings {
    pub(crate) delivery: EmailDelivery,
    pub(crate) code_ttl_seconds: u64,
    pub(crate) send_cooldown_seconds: u64,
    pub(crate) send_peer_cooldown_seconds: u64,
}

#[derive(Clone)]
pub(crate) enum EmailDelivery {
    Disabled,
    Smtp(SmtpEmailSettings),
}

#[derive(Clone)]
pub(crate) struct SmtpEmailSettings {
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) tls: SmtpTlsMode,
    pub(crate) username: Option<String>,
    pub(crate) password: Option<String>,
    pub(crate) from: Mailbox,
}

#[derive(Clone, Copy)]
pub(crate) enum SmtpTlsMode {
    StartTls,
    ImplicitTls,
    None,
}

impl EmailSettings {
    pub(super) fn from_config(config: &ConfigSource) -> anyhow::Result<Self> {
        let delivery = match config
            .string("EMAIL_DELIVERY", "disabled")
            .trim()
            .to_ascii_lowercase()
            .as_str()
        {
            "disabled" => EmailDelivery::Disabled,
            "smtp" => EmailDelivery::Smtp(SmtpEmailSettings::from_config(config)?),
            value => bail!("EMAIL_DELIVERY must be disabled or smtp, got {value}"),
        };

        Ok(Self {
            delivery,
            code_ttl_seconds: positive_u64(
                config,
                "EMAIL_CODE_TTL_SECONDS",
                900,
                "EMAIL_CODE_TTL_SECONDS",
            )?,
            send_cooldown_seconds: positive_u64(
                config,
                "EMAIL_CODE_SEND_COOLDOWN_SECONDS",
                60,
                "EMAIL_CODE_SEND_COOLDOWN_SECONDS",
            )?,
            send_peer_cooldown_seconds: positive_u64(
                config,
                "EMAIL_CODE_PEER_COOLDOWN_SECONDS",
                5,
                "EMAIL_CODE_PEER_COOLDOWN_SECONDS",
            )?,
        })
    }
}

impl SmtpEmailSettings {
    fn from_config(config: &ConfigSource) -> anyhow::Result<Self> {
        let username = config.optional_string("EMAIL_SMTP_USERNAME");
        let password = config.optional_string("EMAIL_SMTP_PASSWORD");
        if username.is_some() != password.is_some() {
            bail!("EMAIL_SMTP_USERNAME and EMAIL_SMTP_PASSWORD must be configured together");
        }

        let from = config
            .required_string("EMAIL_FROM")?
            .parse::<Mailbox>()
            .context("EMAIL_FROM must be a valid mailbox")?;

        Ok(Self {
            host: config.required_string("EMAIL_SMTP_HOST")?,
            port: config.parse("EMAIL_SMTP_PORT", 587)?,
            tls: SmtpTlsMode::from_config(config)?,
            username,
            password,
            from,
        })
    }
}

impl SmtpTlsMode {
    fn from_config(config: &ConfigSource) -> anyhow::Result<Self> {
        match config
            .string("EMAIL_SMTP_TLS", "starttls")
            .trim()
            .to_ascii_lowercase()
            .as_str()
        {
            "starttls" => Ok(Self::StartTls),
            "implicit" | "tls" => Ok(Self::ImplicitTls),
            "none" | "plain" => Ok(Self::None),
            value => bail!("EMAIL_SMTP_TLS must be starttls, implicit, or none, got {value}"),
        }
    }
}
