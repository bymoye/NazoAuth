use aes_gcm::{
    Aes256Gcm, KeyInit,
    aead::{Aead, Payload},
};
use nazo_openid4vci::CredentialStoreError;
use rand::Rng;
use uuid::Uuid;
pub(super) fn protect_payload(
    key: &[u8; 32],
    transaction_id: Uuid,
    plaintext: &[u8],
) -> Result<Vec<u8>, CredentialStoreError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CredentialStoreError::Unavailable)?;
    let mut nonce = [0_u8; 12];
    rand::rng().fill_bytes(&mut nonce);
    let mut protected = nonce.to_vec();
    protected.extend_from_slice(
        &cipher
            .encrypt(
                (&nonce).into(),
                Payload {
                    msg: plaintext,
                    aad: transaction_id.as_bytes(),
                },
            )
            .map_err(|_| CredentialStoreError::Unavailable)?,
    );
    Ok(protected)
}

pub(super) fn unprotect_payload(
    key: &[u8; 32],
    transaction_id: Uuid,
    protected: &[u8],
) -> Result<Vec<u8>, diesel::result::Error> {
    let (nonce, ciphertext) = protected
        .split_at_checked(12)
        .ok_or(diesel::result::Error::RollbackTransaction)?;
    let nonce: &[u8; 12] = nonce
        .try_into()
        .map_err(|_| diesel::result::Error::RollbackTransaction)?;
    Aes256Gcm::new_from_slice(key)
        .map_err(|_| diesel::result::Error::RollbackTransaction)?
        .decrypt(
            nonce.into(),
            Payload {
                msg: ciphertext,
                aad: transaction_id.as_bytes(),
            },
        )
        .map_err(|_| diesel::result::Error::RollbackTransaction)
}
