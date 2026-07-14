#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SenderConstraintPolicy {
    BearerAllowed,
    DpopRequired,
    MtlsRequired,
    DpopOrMtls,
}

impl SenderConstraintPolicy {
    #[must_use]
    pub const fn is_sender_constrained(self) -> bool {
        !matches!(self, Self::BearerAllowed)
    }
}

#[must_use]
pub fn is_valid_dpop_jkt(value: &str) -> bool {
    value.len() == 43
        && URL_SAFE_NO_PAD
            .decode(value)
            .is_ok_and(|bytes| bytes.len() == 32)
}

#[must_use]
pub fn normalize_sha256_thumbprint(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if is_valid_dpop_jkt(trimmed) {
        return Some(trimmed.to_owned());
    }

    let hex = trimmed
        .chars()
        .filter(|ch| !matches!(ch, ':' | ' ' | '\t' | '\r' | '\n'))
        .collect::<String>();
    if hex.len() != 64 || !hex.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return None;
    }
    let mut bytes = Vec::with_capacity(32);
    for index in (0..hex.len()).step_by(2) {
        bytes.push(u8::from_str_radix(&hex[index..index + 2], 16).ok()?);
    }
    Some(URL_SAFE_NO_PAD.encode(bytes))
}
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
