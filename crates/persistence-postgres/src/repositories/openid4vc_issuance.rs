#[path = "openid4vc_issuance_crypto.rs"]
mod crypto;
#[path = "openid4vc_issuance_offer.rs"]
mod offer;
#[path = "openid4vc_issuance_store/mod.rs"]
mod store;

use crate::DbPool;

#[derive(Clone)]
pub struct Openid4vciRepository {
    pool: DbPool,
    data_key: [u8; 32],
}

impl Openid4vciRepository {
    #[must_use]
    pub fn new(pool: DbPool, data_key: [u8; 32]) -> Self {
        Self { pool, data_key }
    }
}
