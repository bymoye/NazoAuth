use std::{error::Error, fmt};

use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;

pub const MFA_TOTP_PERIOD_SECONDS: i64 = 30;
pub const MFA_TOTP_DIGITS: usize = 6;
pub const MFA_BACKUP_CODE_COUNT: usize = 10;
const MFA_TOTP_SKEW_STEPS: i64 = 1;
const BASE32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MfaVerificationMethod {
    Totp,
    BackupCode,
}

impl MfaVerificationMethod {
    #[must_use]
    pub const fn amr(self) -> &'static str {
        match self {
            Self::Totp => "otp",
            Self::BackupCode => "recovery_code",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MfaPolicyError {
    NegativeTotpStep,
    InvalidHmacKey,
    ShortDigest,
}

impl fmt::Display for MfaPolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::NegativeTotpStep => "TOTP step must be non-negative",
            Self::InvalidHmacKey => "TOTP HMAC key is invalid",
            Self::ShortDigest => "TOTP HMAC digest is too short",
        })
    }
}

impl Error for MfaPolicyError {}

#[must_use]
pub fn generate_totp_secret_base32() -> String {
    base32_encode(&rand::random::<[u8; 20]>())
}

#[must_use]
pub fn otpauth_uri(issuer: &str, account_name: &str, secret_base32: &str) -> String {
    format!(
        "otpauth://totp/{}:{}?secret={}&issuer={}&algorithm=SHA1&digits={}&period={}",
        urlencoding::encode(issuer),
        urlencoding::encode(account_name),
        secret_base32,
        urlencoding::encode(issuer),
        MFA_TOTP_DIGITS,
        MFA_TOTP_PERIOD_SECONDS
    )
}

#[must_use]
pub fn verified_totp_step(
    secret_base32: &str,
    code: &str,
    now: i64,
    last_used_step: Option<i64>,
) -> Option<i64> {
    let candidate = code.trim();
    if candidate.len() != MFA_TOTP_DIGITS || !candidate.bytes().all(|value| value.is_ascii_digit())
    {
        return None;
    }
    let secret = base32_decode(secret_base32)?;
    let step = now.div_euclid(MFA_TOTP_PERIOD_SECONDS);
    (-MFA_TOTP_SKEW_STEPS..=MFA_TOTP_SKEW_STEPS).find_map(|offset| {
        let candidate_step = step.checked_add(offset)?;
        if last_used_step.is_some_and(|last| candidate_step <= last) {
            return None;
        }
        let expected = totp_for_step(&secret, candidate_step).ok()?;
        constant_time_eq(expected.as_bytes(), candidate.as_bytes()).then_some(candidate_step)
    })
}

#[must_use]
pub fn generate_backup_code() -> String {
    const RANGE: u32 = 100_000;
    const LIMIT: u32 = u32::MAX - (u32::MAX % RANGE);

    fn chunk() -> u32 {
        loop {
            let value = u32::from_be_bytes(rand::random::<[u8; 4]>());
            if value < LIMIT {
                return value % RANGE;
            }
        }
    }

    format!("{:05}-{:05}", chunk(), chunk())
}

#[must_use]
pub fn normalize_backup_code(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.len() == 10 && trimmed.bytes().all(|value| value.is_ascii_digit()) {
        return Some(trimmed.to_owned());
    }
    let bytes = trimmed.as_bytes();
    if bytes.len() == 11
        && matches!(bytes[5], b'-' | b' ')
        && bytes[..5].iter().all(u8::is_ascii_digit)
        && bytes[6..].iter().all(u8::is_ascii_digit)
    {
        return Some(format!("{}{}", &trimmed[..5], &trimmed[6..]));
    }
    None
}

pub fn totp_for_step(secret: &[u8], step: i64) -> Result<String, MfaPolicyError> {
    if step < 0 {
        return Err(MfaPolicyError::NegativeTotpStep);
    }
    let mut mac =
        Hmac::<Sha1>::new_from_slice(secret).map_err(|_| MfaPolicyError::InvalidHmacKey)?;
    mac.update(&(step as u64).to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = digest
        .last()
        .map(|value| (value & 0x0f) as usize)
        .filter(|offset| offset + 4 <= digest.len())
        .ok_or(MfaPolicyError::ShortDigest)?;
    let binary = (((digest[offset] & 0x7f) as u32) << 24)
        | ((digest[offset + 1] as u32) << 16)
        | ((digest[offset + 2] as u32) << 8)
        | (digest[offset + 3] as u32);
    Ok(format!(
        "{:0width$}",
        binary % 10u32.pow(MFA_TOTP_DIGITS as u32),
        width = MFA_TOTP_DIGITS
    ))
}

#[must_use]
pub fn base32_encode(bytes: &[u8]) -> String {
    let mut output = String::with_capacity((bytes.len() * 8).div_ceil(5));
    let mut buffer = 0u32;
    let mut bits = 0u8;
    for byte in bytes {
        buffer = (buffer << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 5 {
            let index = ((buffer >> (bits - 5)) & 0x1f) as usize;
            output.push(BASE32_ALPHABET[index] as char);
            bits -= 5;
        }
    }
    if bits > 0 {
        let index = ((buffer << (5 - bits)) & 0x1f) as usize;
        output.push(BASE32_ALPHABET[index] as char);
    }
    output
}

#[must_use]
pub fn base32_decode(value: &str) -> Option<Vec<u8>> {
    let mut buffer = 0u32;
    let mut bits = 0u8;
    let mut output = Vec::new();
    for character in value
        .chars()
        .filter(|character| !character.is_ascii_whitespace())
    {
        let character = character.to_ascii_uppercase();
        let index = match character {
            'A'..='Z' => character as u32 - 'A' as u32,
            '2'..='7' => character as u32 - '2' as u32 + 26,
            '=' => continue,
            _ => return None,
        };
        buffer = (buffer << 5) | index;
        bits += 5;
        if bits >= 8 {
            output.push(((buffer >> (bits - 8)) & 0xff) as u8);
            bits -= 8;
        }
    }
    (!output.is_empty()).then_some(output)
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0u8, |difference, (left, right)| difference | (left ^ right))
        == 0
}
