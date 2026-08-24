//! Recovery Root contract shared by NazoAuth and `nazoauthctl` (04A).
//!
//! This module is the single authoritative source for every cross-end fact of
//! the recovery plane:
//!
//! * the display/parsing alphabet of the 32-byte Recovery Secret
//!   (`NAZO-RECOVERY-` + 64 lowercase hex, optional prefix and grouping
//!   whitespace tolerated on input, always exactly 32 decoded bytes);
//! * the pinned KDF: HKDF-SHA-256 (RFC 5869) with
//!   `salt = deployment_id` ASCII bytes, `info = "nazoauthctl/recovery"` and a
//!   32-byte output used directly as the Ed25519 seed.  The storage layer pins
//!   this parameter set as the KDF id [`RECOVERY_KDF_ID`] next to every stored
//!   Recovery Public Key, so a future parameter change cannot silently
//!   reinterpret old rows;
//! * the canonical challenge message that the control side signs with the
//!   *old* Recovery Key and NazoAuth verifies against the *currently* stored
//!   Recovery Public Key.
//!
//! Only public key material ever crosses the wire towards NazoAuth: nothing
//! here can serialize the secret, and the secret-taking inputs of these
//! functions are plain caller-owned buffers that never enter logs or errors.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest as _, Sha256};

use crate::ProtocolError;
use crate::verification::validate_file_identifier_value;

/// Display prefix of every Recovery Secret (`NAZO-RECOVERY-` + 64 hex).
pub const RECOVERY_SECRET_PREFIX: &str = "NAZO-RECOVERY-";
/// Pinned KDF identifier stored alongside every persisted Recovery Public Key.
///
/// `hkdf-sha256-v1` means exactly: HKDF-SHA-256 per RFC 5869 with
/// `salt = deployment_id` bytes, `info = "nazoauthctl/recovery"`, `L = 32`,
/// and the output used verbatim as the Ed25519 seed.
pub const RECOVERY_KDF_ID: &str = "hkdf-sha256-v1";
/// Fixed RFC 5869 `info` string of the pinned parameter set.
pub const RECOVERY_KDF_INFO: &[u8] = b"nazoauthctl/recovery";
/// Canonical `action` discriminator inside the signed challenge message.
pub const RECOVERY_CHALLENGE_ACTION: &str = "controller-recovery";

const HEX_DIGITS_LOWER: &[u8] = b"0123456789abcdef";

/// Render one Recovery Secret in the single mandated display form:
/// `NAZO-RECOVERY-` + 64 lowercase hex characters.  The caller owns the
/// returned string; nothing else retains or logs it.
#[must_use]
pub fn format_recovery_secret(secret: &[u8; 32]) -> String {
    let mut rendered = String::with_capacity(RECOVERY_SECRET_PREFIX.len() + 64);
    rendered.push_str(RECOVERY_SECRET_PREFIX);
    for byte in secret {
        rendered.push(HEX_DIGITS_LOWER[usize::from(byte >> 4)] as char);
        rendered.push(HEX_DIGITS_LOWER[usize::from(byte & 0x0f)] as char);
    }
    rendered
}

/// Parse a human-transcribed Recovery Secret back into its exact 32 bytes.
///
/// Tolerated input shapes (04A D10 §3): an optional display prefix (case
/// insensitive) and arbitrary grouping whitespace between the hex digits;
/// either hex case is accepted.  After normalization the input must be
/// exactly 64 hexadecimal digits — anything else is rejected instead of
/// truncated or padded.
pub fn parse_recovery_secret(text: &str) -> Result<[u8; 32], ProtocolError> {
    let trimmed = text.trim();
    let lowered_prefix = RECOVERY_SECRET_PREFIX.to_ascii_lowercase();
    let without_prefix = trimmed
        .strip_prefix(RECOVERY_SECRET_PREFIX)
        .or_else(|| trimmed.strip_prefix(lowered_prefix.as_str()))
        .unwrap_or(trimmed);
    let mut hex = String::with_capacity(64);
    for character in without_prefix.chars() {
        if character.is_whitespace() {
            continue;
        }
        hex.push(character.to_ascii_lowercase());
    }
    if hex.len() != 64 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(ProtocolError::Policy(
            "recovery secret must decode to exactly 32 bytes",
        ));
    }
    let mut secret = [0u8; 32];
    for (index, pair) in hex.as_bytes().chunks(2).enumerate() {
        let high = (pair[0] as char)
            .to_digit(16)
            .expect("digits validated above") as u8;
        let low = (pair[1] as char)
            .to_digit(16)
            .expect("digits validated above") as u8;
        secret[index] = (high << 4) | low;
    }
    Ok(secret)
}

/// HKDF-SHA-256 (RFC 5869) with the pinned parameters of this contract.
///
/// Implemented directly over the workspace `hmac` primitive so the parameter
/// freeze lives beside the constants it interprets; pinned against the RFC
/// 5869 test vectors in the unit suite.
#[must_use]
pub fn hkdf_sha256_v1(ikm: &[u8], salt: &[u8], info: &[u8], output_length: usize) -> Vec<u8> {
    fn mac(key: &[u8]) -> Hmac<Sha256> {
        Hmac::<Sha256>::new_from_slice(key).expect("HMAC-SHA-256 accepts any key length")
    }
    // Extract (RFC 5869 §2.2): PRK = HMAC-Hash(salt, IKM); an empty salt is
    // replaced by zeroes of Hash size per the RFC.
    let zero_salt = [0u8; 32];
    let salt: &[u8] = if salt.is_empty() { &zero_salt } else { salt };
    let mut extractor = mac(salt);
    extractor.update(ikm);
    let prk = extractor.finalize().into_bytes();
    // Expand (RFC 5869 §2.3).
    let mut okm = Vec::with_capacity(output_length);
    let mut block: Vec<u8> = Vec::new();
    let mut counter: u8 = 1;
    while okm.len() < output_length {
        let mut expander = mac(&prk);
        expander.update(&block);
        expander.update(info);
        expander.update(&[counter]);
        block = expander.finalize().into_bytes().to_vec();
        let take = (output_length - okm.len()).min(block.len());
        okm.extend_from_slice(&block[..take]);
        counter = counter
            .checked_add(1)
            .expect("hkdf output length exceeded the counter space");
    }
    okm
}

/// Deterministic derivation of the Ed25519 Recovery Key seed from one
/// Recovery Secret and one deployment identity (04A §2).  One flipped bit of
/// secret or deployment yields an unrelated key.
#[must_use]
pub fn derive_recovery_seed(secret: &[u8; 32], deployment_id: &str) -> [u8; 32] {
    let okm = hkdf_sha256_v1(secret, deployment_id.as_bytes(), RECOVERY_KDF_INFO, 32);
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&okm);
    seed
}

/// Ed25519 verifying key of a derived Recovery Key seed.
#[must_use]
pub fn recovery_verifying_key(seed: &[u8; 32]) -> VerifyingKey {
    SigningKey::from_bytes(seed).verifying_key()
}

/// Raw public-key bytes of a derived Recovery Key.
#[must_use]
pub fn recovery_public_key_bytes(seed: &[u8; 32]) -> [u8; 32] {
    recovery_verifying_key(seed).to_bytes()
}

/// `kid` of a Recovery Public Key: unpadded base64url SHA-256 of the raw
/// bytes — the same material-binding convention as controller slot kids, so
/// one display rule covers the whole control plane.
#[must_use]
pub fn recovery_kid(public_key: &[u8; 32]) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(public_key))
}

/// The exact payload a fresh-2FA approval covers when rotating the Recovery
/// Root (04A D12).  The digest input is compact sorted-key JSON, mirroring the
/// controller identity actions, so the approving screen and every committing
/// call derive identical fingerprints from identical payloads.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryRootRotation {
    pub deployment_id: String,
    /// Unpadded base64url SHA-256 of `public_key`.
    pub kid: String,
    pub public_key: [u8; 32],
}

pub const RECOVERY_ROOT_ROTATE_ACTION: &str = "recovery-root-rotate";

impl RecoveryRootRotation {
    /// Validate the payload shape before anything may anchor an approval.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        validate_file_identifier_value(&self.deployment_id)?;
        if self.kid != recovery_kid(&self.public_key) {
            return Err(ProtocolError::Policy("kid does not match key material"));
        }
        Ok(())
    }

    /// Lowercase hex SHA-256 of the canonical payload; the value an approval
    /// is bound to and a commit must reproduce exactly.
    #[must_use]
    pub fn action_sha256(&self) -> String {
        let value = serde_json::json!({
            "action": RECOVERY_ROOT_ROTATE_ACTION,
            "deployment_id": self.deployment_id,
            "kid": self.kid,
            "public_key": URL_SAFE_NO_PAD.encode(self.public_key),
        });
        let mut encoded = String::with_capacity(64);
        for byte in Sha256::digest(serde_json::to_vec(&value).expect("json serialization")) {
            use std::fmt::Write as _;
            write!(&mut encoded, "{byte:02x}").expect("hex writing cannot fail");
        }
        encoded
    }
}

/// The exact proposal a recovery challenge binds and the control side signs:
/// the replacement controller key, the replacement Recovery Public Key, and
/// the deployment they belong to.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryProposal {
    pub deployment_id: String,
    /// Bounded human label of the recovered controller slot.
    pub controller_label: String,
    /// Unpadded base64url SHA-256 of `controller_public_key`.
    pub controller_kid: String,
    pub controller_public_key: [u8; 32],
    /// Unpadded base64url SHA-256 of `recovery_public_key`.
    pub recovery_kid: String,
    pub recovery_public_key: [u8; 32],
}

impl RecoveryProposal {
    /// Validate every field before the proposal may anchor a challenge.
    ///
    /// The server enforces the identical rules at challenge issuance, so two
    /// implementations cannot drift apart on what "well formed" means.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        validate_file_identifier_value(&self.deployment_id)?;
        if self.controller_label.is_empty()
            || self.controller_label.len() > 128
            || self.controller_label.chars().any(char::is_control)
        {
            return Err(ProtocolError::Policy("invalid controller label"));
        }
        for (kid, key) in [
            (&self.controller_kid, &self.controller_public_key),
            (&self.recovery_kid, &self.recovery_public_key),
        ] {
            if kid != &recovery_kid(key) {
                return Err(ProtocolError::Policy("kid does not match key material"));
            }
        }
        Ok(())
    }

    /// Canonical bytes the control side signs with the OLD Recovery Key.
    ///
    /// Sorted-key compact JSON (`serde_json` maps are order-deterministic), so
    /// signer and verifier derive byte-identical messages independently.
    #[must_use]
    pub fn challenge_message(&self, challenge_id: &str, nonce: &[u8; 32]) -> Vec<u8> {
        let value = serde_json::json!({
            "action": RECOVERY_CHALLENGE_ACTION,
            "challenge_id": challenge_id,
            "controller": {
                "kid": self.controller_kid,
                "label": self.controller_label,
                "public_key": URL_SAFE_NO_PAD.encode(self.controller_public_key),
            },
            "deployment_id": self.deployment_id,
            "nonce": URL_SAFE_NO_PAD.encode(nonce),
            "recovery": {
                "kid": self.recovery_kid,
                "public_key": URL_SAFE_NO_PAD.encode(self.recovery_public_key),
            },
        });
        serde_json::to_vec(&value).expect("sorted-key JSON serialization cannot fail")
    }

    /// Reference signer used by `nazoauthctl` and the test suites: signs the
    /// canonical challenge message with the OLD Recovery Key.
    #[must_use]
    pub fn sign_challenge(
        &self,
        challenge_id: &str,
        nonce: &[u8; 32],
        old_seed: &[u8; 32],
    ) -> [u8; 64] {
        SigningKey::from_bytes(old_seed)
            .sign(&self.challenge_message(challenge_id, nonce))
            .to_bytes()
    }

    /// Verify one Ed25519 signature over the canonical challenge message
    /// against one candidate Recovery Public Key.  Signature verification is
    /// the constant-time boundary of the recovery plane; the identifiers
    /// compared around it are non-secret public values.
    #[must_use]
    pub fn verify_challenge_signature(
        &self,
        challenge_id: &str,
        nonce: &[u8; 32],
        recovery_public_key: &[u8; 32],
        signature: &[u8; 64],
    ) -> bool {
        use ed25519_dalek::Verifier as _;
        let Ok(signature) = ed25519_dalek::Signature::from_slice(signature) else {
            return false;
        };
        let Ok(verifying_key) = VerifyingKey::from_bytes(recovery_public_key) else {
            return false;
        };
        verifying_key
            .verify(&self.challenge_message(challenge_id, nonce), &signature)
            .is_ok()
    }
}
