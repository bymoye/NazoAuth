use crate::adapters::security::constant_time_eq;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use hmac::{Hmac, KeyInit, Mac};
use serde::Deserialize;
use sha2::Sha256;

use crate::settings::SamlGatewaySettings;

type HmacSha256 = Hmac<Sha256>;
pub(super) const SAML_ASSERTION_CLOCK_SKEW_SECONDS: i64 = 60;
pub(super) const SAML_ASSERTION_MAX_TTL_SECONDS: i64 = 300;

#[derive(Clone, Deserialize)]
pub(crate) struct SamlGatewayAssertion {
    pub(super) issuer: String,
    pub(super) audience: String,
    pub(super) subject: String,
    pub(super) email: String,
    pub(super) name: Option<String>,
    pub(super) iat: i64,
    pub(super) exp: i64,
    pub(super) signature: String,
}

pub(super) fn valid_saml_gateway_assertion(
    settings: &SamlGatewaySettings,
    assertion: &SamlGatewayAssertion,
    normalized_email: &str,
) -> bool {
    let now = Utc::now().timestamp();
    if assertion.issuer != settings.issuer
        || assertion.audience != settings.audience
        || assertion.subject.trim().is_empty()
        || assertion.iat > now.saturating_add(SAML_ASSERTION_CLOCK_SKEW_SECONDS)
        || assertion.exp <= now
        || assertion.exp.saturating_sub(assertion.iat) > SAML_ASSERTION_MAX_TTL_SECONDS
    {
        return false;
    }
    let expected = saml_gateway_signature(
        &settings.secret,
        &assertion.issuer,
        &assertion.audience,
        &assertion.subject,
        normalized_email,
        assertion.iat,
        assertion.exp,
    );
    constant_time_eq(expected.as_bytes(), assertion.signature.as_bytes())
}

pub(super) fn saml_gateway_signature(
    secret: &str,
    issuer: &str,
    audience: &str,
    subject: &str,
    email: &str,
    iat: i64,
    exp: i64,
) -> String {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key");
    mac.update(format!("{issuer}\n{audience}\n{subject}\n{email}\n{iat}\n{exp}").as_bytes());
    URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
}

#[cfg(test)]
#[path = "../../../../tests/in_source/src/http/auth/tests/federation_saml.rs"]
mod tests;
