use std::{fmt, future::Future, pin::Pin};

use rand::Rng as _;
use uuid::Uuid;

pub type SigningKeyRepositoryFuture<'a, T> =
    Pin<Box<dyn Future<Output = anyhow::Result<T>> + Send + 'a>>;

/// One tenant-bound, authoritative keyset record. The public projection and
/// encrypted private payload are one generation: callers must authenticate
/// both with [`SigningKeyWrappingKeyRing::open_generation`] before use.
#[derive(Clone, Debug)]
pub struct PersistedSigningKeyset {
    pub revision: i64,
    pub public_metadata: serde_json::Value,
    /// Twelve-byte nonce followed by AES-GCM ciphertext and tag.
    pub encrypted_private_material: Vec<u8>,
    pub wrapping_key_id: String,
}

#[derive(Clone, Debug)]
pub enum SigningKeysetCreateResult {
    Created(PersistedSigningKeyset),
    Existing(PersistedSigningKeyset),
}

#[derive(Clone, Debug)]
pub enum SigningKeysetCompareAndSwapResult {
    Applied(PersistedSigningKeyset),
    Conflict(PersistedSigningKeyset),
}

/// Persistence boundary for the one tenant selected by its adapter.
///
/// The adapter owns SQL and atomicity. Key-management owns key generation,
/// metadata validation, encryption, and lifecycle transitions.
pub trait SigningKeyRepository: Send + Sync {
    fn load(&self) -> SigningKeyRepositoryFuture<'_, Option<PersistedSigningKeyset>>;

    fn create_if_absent(
        &self,
        candidate: PersistedSigningKeyset,
    ) -> SigningKeyRepositoryFuture<'_, SigningKeysetCreateResult>;

    fn compare_and_swap(
        &self,
        expected_revision: i64,
        candidate: PersistedSigningKeyset,
    ) -> SigningKeyRepositoryFuture<'_, SigningKeysetCompareAndSwapResult>;
}

/// Deployment-provided wrapping material for persisted signing-key private
/// material. The current key seals new generations; the previous key exists
/// only to read a generation sealed before a wrapping-key rotation.
#[derive(Clone)]
pub struct SigningKeyWrappingKeyRing {
    current: WrappingKey,
    previous: Option<WrappingKey>,
}

#[derive(Clone)]
struct WrappingKey {
    id: String,
    key: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SealedKeyMaterial {
    pub wrapping_key_id: String,
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

impl SealedKeyMaterial {
    #[must_use]
    pub fn into_persisted_bytes(self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.nonce.len() + self.ciphertext.len());
        bytes.extend_from_slice(&self.nonce);
        bytes.extend_from_slice(&self.ciphertext);
        bytes
    }

    pub fn from_persisted_bytes(
        wrapping_key_id: String,
        bytes: &[u8],
    ) -> anyhow::Result<Self> {
        let nonce = bytes
            .get(..12)
            .ok_or_else(|| anyhow::anyhow!("signing-key encrypted material is malformed"))?
            .try_into()
            .expect("twelve-byte slice converts to nonce");
        let ciphertext = bytes[12..].to_vec();
        Ok(Self {
            wrapping_key_id,
            nonce,
            ciphertext,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SigningKeyWrappingKeyError {
    EmptyId,
    IdTooLong,
    DuplicateId,
}

impl fmt::Display for SigningKeyWrappingKeyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::EmptyId => "signing-key encryption key id must not be empty",
            Self::IdTooLong => "signing-key encryption key id must be at most 128 bytes",
            Self::DuplicateId => "signing-key encryption current and previous ids must differ",
        })
    }
}

impl std::error::Error for SigningKeyWrappingKeyError {}

impl SigningKeyWrappingKeyRing {
    pub fn new(
        current_id: impl Into<String>,
        current_key: [u8; 32],
        previous: Option<(String, [u8; 32])>,
    ) -> Result<Self, SigningKeyWrappingKeyError> {
        let current = WrappingKey::new(current_id.into(), current_key)?;
        let previous = previous
            .map(|(id, key)| WrappingKey::new(id, key))
            .transpose()?;
        if previous.as_ref().is_some_and(|key| key.id == current.id) {
            return Err(SigningKeyWrappingKeyError::DuplicateId);
        }
        Ok(Self { current, previous })
    }

    #[must_use]
    pub fn current_id(&self) -> &str {
        &self.current.id
    }

    pub fn seal(
        &self,
        tenant_id: Uuid,
        purpose: &str,
        plaintext: &[u8],
    ) -> anyhow::Result<SealedKeyMaterial> {
        let mut nonce = [0_u8; 12];
        rand::rng().fill_bytes(&mut nonce);
        Ok(SealedKeyMaterial {
            wrapping_key_id: self.current.id.clone(),
            nonce,
            ciphertext: crate::crypto::aes_256_gcm_encrypt(
                &self.current.key,
                &nonce,
                &associated_data(tenant_id, purpose),
                plaintext,
            )?,
        })
    }

    pub fn open(
        &self,
        tenant_id: Uuid,
        purpose: &str,
        material: &SealedKeyMaterial,
    ) -> anyhow::Result<Vec<u8>> {
        let key = self
            .key_for(&material.wrapping_key_id)
            .ok_or_else(|| anyhow::anyhow!("signing-key wrapping key is unavailable"))?;
        if material.ciphertext.len() < 16 {
            anyhow::bail!("signing-key encrypted material is malformed");
        }
        let split = material.ciphertext.len() - 16;
        crate::crypto::aes_256_gcm_decrypt(
            key,
            &material.nonce,
            &associated_data(tenant_id, purpose),
            &material.ciphertext[..split],
            &material.ciphertext[split..],
        )
    }

    pub fn seal_generation(
        &self,
        tenant_id: Uuid,
        revision: i64,
        public_metadata: &serde_json::Value,
        plaintext: &[u8],
    ) -> anyhow::Result<SealedKeyMaterial> {
        self.seal_with_aad(plaintext, generation_associated_data(tenant_id, revision, public_metadata)?)
    }

    pub fn open_generation(
        &self,
        tenant_id: Uuid,
        revision: i64,
        public_metadata: &serde_json::Value,
        material: &SealedKeyMaterial,
    ) -> anyhow::Result<Vec<u8>> {
        self.open_with_aad(material, generation_associated_data(tenant_id, revision, public_metadata)?)
    }

    fn seal_with_aad(&self, plaintext: &[u8], aad: Vec<u8>) -> anyhow::Result<SealedKeyMaterial> {
        let mut nonce = [0_u8; 12];
        rand::rng().fill_bytes(&mut nonce);
        Ok(SealedKeyMaterial {
            wrapping_key_id: self.current.id.clone(),
            nonce,
            ciphertext: crate::crypto::aes_256_gcm_encrypt(&self.current.key, &nonce, &aad, plaintext)?,
        })
    }

    fn open_with_aad(&self, material: &SealedKeyMaterial, aad: Vec<u8>) -> anyhow::Result<Vec<u8>> {
        let key = self.key_for(&material.wrapping_key_id).ok_or_else(|| anyhow::anyhow!("signing-key wrapping key is unavailable"))?;
        let split = material.ciphertext.len().checked_sub(16).ok_or_else(|| anyhow::anyhow!("signing-key encrypted material is malformed"))?;
        crate::crypto::aes_256_gcm_decrypt(key, &material.nonce, &aad, &material.ciphertext[..split], &material.ciphertext[split..])
    }

    fn key_for(&self, id: &str) -> Option<&[u8; 32]> {
        if self.current.id == id {
            Some(&self.current.key)
        } else {
            self.previous
                .as_ref()
                .filter(|key| key.id == id)
                .map(|key| &key.key)
        }
    }
}

impl WrappingKey {
    fn new(id: String, key: [u8; 32]) -> Result<Self, SigningKeyWrappingKeyError> {
        if id.trim().is_empty() {
            return Err(SigningKeyWrappingKeyError::EmptyId);
        }
        if id.len() > 128 {
            return Err(SigningKeyWrappingKeyError::IdTooLong);
        }
        Ok(Self { id, key })
    }
}

fn associated_data(tenant_id: Uuid, purpose: &str) -> Vec<u8> {
    let mut aad = b"nazoauth/signing-key-material/v1\0".to_vec();
    aad.extend_from_slice(tenant_id.as_bytes());
    aad.push(0);
    aad.extend_from_slice(purpose.as_bytes());
    aad
}

fn generation_associated_data(tenant_id: Uuid, revision: i64, metadata: &serde_json::Value) -> anyhow::Result<Vec<u8>> {
    use sha2::{Digest as _, Sha256};

    let mut aad = b"nazoauth/signing-keyset/v1\0".to_vec();
    aad.extend_from_slice(tenant_id.as_bytes());
    aad.extend_from_slice(&revision.to_be_bytes());
    aad.extend_from_slice(&Sha256::digest(serde_json::to_vec(metadata)?));
    Ok(aad)
}
