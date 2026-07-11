//! JWT 签名密钥材料。
//! active 签名后端用于签发，active 与未退役 previous 公钥用于 JWKS 输出和验签。

use serde_json::Value;
use std::{
    sync::{Arc, RwLock},
    time::Duration,
};

#[derive(Clone)]
pub(crate) struct VerificationKey {
    pub(crate) kid: String,
    pub(crate) public_jwk: Value,
    /// Paired private material retained only for live local keys so response
    /// signing capabilities and signing execution use the same keyset snapshot.
    pub(crate) local_signing_key: Option<Vec<u8>>,
}

#[derive(Clone)]
pub(crate) struct ExternalSigningKey {
    pub(crate) command: Arc<Vec<String>>,
    pub(crate) key_ref: String,
    pub(crate) timeout: Duration,
}

#[derive(Clone)]
pub(crate) enum ActiveSigningKey {
    LocalPkcs8Der(Vec<u8>),
    ExternalCommand(ExternalSigningKey),
}

/// 当前服务实例可用的 JWT keyset。
#[derive(Clone)]
pub(crate) struct Keyset {
    pub(crate) active_kid: String,
    pub(crate) active_alg: jsonwebtoken::Algorithm,
    pub(crate) active_signing_key: ActiveSigningKey,
    pub(crate) verification_keys: Vec<VerificationKey>,
}

#[derive(Clone)]
pub(crate) struct KeysetStore {
    inner: Arc<RwLock<Arc<Keyset>>>,
}

impl KeysetStore {
    pub(crate) fn new(keyset: Keyset) -> Self {
        Self {
            inner: Arc::new(RwLock::new(Arc::new(keyset))),
        }
    }

    pub(crate) fn snapshot(&self) -> Arc<Keyset> {
        match self.inner.read() {
            Ok(keyset) => keyset.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    pub(crate) fn replace(&self, keyset: Keyset) {
        match self.inner.write() {
            Ok(mut current) => *current = Arc::new(keyset),
            Err(poisoned) => *poisoned.into_inner() = Arc::new(keyset),
        }
    }
}
