//! 邮件投递封装。

use std::time::Duration;

use anyhow::Context;
use lettre::{
    Address, AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
    message::{Mailbox, SinglePart, header::ContentType},
    transport::smtp::{
        authentication::Credentials,
        client::{Tls, TlsParameters},
    },
};

use crate::settings::{EmailDelivery, Settings, SmtpEmailSettings, SmtpTlsMode};

use super::email_templates::VerificationEmail;

#[cfg(test)]
pub(crate) struct EmailRecipient {
    pub(crate) normalized: String,
    pub(crate) mailbox: Mailbox,
}

pub(crate) fn normalize_email_address(raw: &str) -> anyhow::Result<String> {
    Ok(nazo_identity::email::normalize_email_address(raw)?)
}

fn parse_email_address(raw: &str) -> anyhow::Result<Address> {
    let normalized = raw.trim().to_ascii_lowercase();
    normalized
        .parse::<Address>()
        .context("email address is invalid")
}

#[cfg(test)]
pub(crate) fn parse_email_recipient(raw: &str) -> anyhow::Result<EmailRecipient> {
    let address = parse_email_address(raw)?;
    let normalized = address.to_string();
    Ok(EmailRecipient {
        normalized,
        mailbox: Mailbox::new(None, address),
    })
}

pub(crate) fn email_delivery_configured(settings: &Settings) -> bool {
    matches!(&settings.identity.email.delivery, EmailDelivery::Smtp(_))
}

async fn send_verification_email_with_ttl(
    smtp: &SmtpEmailSettings,
    recipient: Mailbox,
    code: &str,
    code_ttl_seconds: u64,
) -> anyhow::Result<()> {
    let message = Message::builder()
        .from(smtp.from.clone())
        .to(recipient)
        .subject("Nazo OAuth 注册验证码")
        .singlepart(html_part(
            VerificationEmail::new(code, code_ttl_seconds).render_html(),
        ))
        .context("failed to build verification email")?;

    build_smtp_transport(smtp)?
        .send(message)
        .await
        .context("failed to send verification email")?;
    Ok(())
}

#[derive(Clone)]
pub(crate) struct SmtpVerificationEmailDelivery {
    smtp: Option<SmtpEmailSettings>,
}

impl SmtpVerificationEmailDelivery {
    pub(crate) fn from_delivery(delivery: &EmailDelivery) -> Self {
        Self {
            smtp: match delivery {
                EmailDelivery::Disabled => None,
                EmailDelivery::Smtp(smtp) => Some(smtp.clone()),
            },
        }
    }
}

impl nazo_identity::ports::VerificationEmailDeliveryPort for SmtpVerificationEmailDelivery {
    fn deliver<'a>(
        &'a self,
        normalized_email: &'a str,
        code: &'a str,
        code_ttl_seconds: u64,
    ) -> nazo_identity::ports::RepositoryFuture<'a, ()> {
        Box::pin(async move {
            let smtp = self.smtp.as_ref().ok_or_else(|| {
                nazo_identity::ports::RepositoryError::Unexpected(
                    "email delivery is disabled".to_owned(),
                )
            })?;
            let address = parse_email_address(normalized_email).map_err(|error| {
                nazo_identity::ports::RepositoryError::Unexpected(error.to_string())
            })?;
            send_verification_email_with_ttl(
                smtp,
                Mailbox::new(None, address),
                code,
                code_ttl_seconds,
            )
            .await
            .map_err(|error| nazo_identity::ports::RepositoryError::Unexpected(error.to_string()))
        })
    }
}

fn build_smtp_transport(
    smtp: &SmtpEmailSettings,
) -> anyhow::Result<AsyncSmtpTransport<Tokio1Executor>> {
    let tls_parameters =
        || TlsParameters::new(smtp.host.clone()).context("failed to build SMTP TLS parameters");

    let tls = match smtp.tls {
        SmtpTlsMode::StartTls => Tls::Required(tls_parameters()?),
        SmtpTlsMode::ImplicitTls => Tls::Wrapper(tls_parameters()?),
        SmtpTlsMode::None => Tls::None,
    };

    let mut builder = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&smtp.host)
        .port(smtp.port)
        .tls(tls)
        .timeout(Some(Duration::from_secs(30)));

    if let (Some(username), Some(password)) = (&smtp.username, &smtp.password) {
        builder = builder.credentials(Credentials::new(username.clone(), password.clone()));
    }

    Ok(builder.build())
}

fn html_part(body: String) -> SinglePart {
    SinglePart::builder()
        .header(ContentType::TEXT_HTML)
        .body(body)
}

#[cfg(test)]
#[path = "../../tests/in_source/src/support/tests/email.rs"]
mod tests;
