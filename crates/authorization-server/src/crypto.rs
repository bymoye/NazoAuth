use anyhow::anyhow;
use aws_lc_rs::{
    aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey},
    rsa::{OAEP_SHA256_MGF1SHA256, OaepPublicEncryptingKey, PublicEncryptingKey},
};
use der::{
    Encode,
    asn1::{Any, BitString, UintRef},
};
use x509_cert::spki::{AlgorithmIdentifierOwned, ObjectIdentifier, SubjectPublicKeyInfoOwned};

#[derive(der::Sequence)]
struct RsaPublicKey<'a> {
    modulus: UintRef<'a>,
    public_exponent: UintRef<'a>,
}

fn rsa_public_spki(n: &[u8], e: &[u8]) -> anyhow::Result<Vec<u8>> {
    let pkcs1 = RsaPublicKey {
        modulus: UintRef::new(n)?,
        public_exponent: UintRef::new(e)?,
    }
    .to_der()?;
    Ok(SubjectPublicKeyInfoOwned {
        algorithm: AlgorithmIdentifierOwned {
            oid: ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1"),
            parameters: Some(Any::null()),
        },
        subject_public_key: BitString::from_bytes(&pkcs1)?,
    }
    .to_der()?)
}

pub(crate) fn rsa_oaep_sha256_encrypt(
    n: &[u8],
    e: &[u8],
    plaintext: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let public = PublicEncryptingKey::from_der(&rsa_public_spki(n, e)?)
        .map_err(|_| anyhow!("invalid RSA public key"))?;
    let public =
        OaepPublicEncryptingKey::new(public).map_err(|_| anyhow!("invalid RSA-OAEP public key"))?;
    let mut ciphertext = vec![0; public.ciphertext_size()];
    Ok(public
        .encrypt(&OAEP_SHA256_MGF1SHA256, plaintext, &mut ciphertext, None)
        .map_err(|_| anyhow!("RSA-OAEP-256 encryption failed"))?
        .to_vec())
}

pub(crate) fn aes_256_gcm_encrypt(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> anyhow::Result<(Vec<u8>, [u8; 16])> {
    let key = LessSafeKey::new(
        UnboundKey::new(&AES_256_GCM, key).map_err(|_| anyhow!("invalid AES-256-GCM key"))?,
    );
    let nonce = Nonce::try_assume_unique_for_key(nonce)
        .map_err(|_| anyhow!("invalid AES-256-GCM nonce"))?;
    let mut ciphertext = plaintext.to_vec();
    let tag = key
        .seal_in_place_separate_tag(nonce, Aad::from(aad), &mut ciphertext)
        .map_err(|_| anyhow!("AES-256-GCM encryption failed"))?;
    Ok((
        ciphertext,
        tag.as_ref().try_into().expect("AES-GCM tag is 16 bytes"),
    ))
}

pub(crate) fn aes_256_gcm_decrypt(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let key = LessSafeKey::new(
        UnboundKey::new(&AES_256_GCM, key).map_err(|_| anyhow!("invalid AES-256-GCM key"))?,
    );
    let nonce = Nonce::try_assume_unique_for_key(nonce)
        .map_err(|_| anyhow!("invalid AES-256-GCM nonce"))?;
    let mut protected = Vec::with_capacity(ciphertext.len() + tag.len());
    protected.extend_from_slice(ciphertext);
    protected.extend_from_slice(tag);
    let plaintext = key
        .open_in_place(nonce, Aad::from(aad), &mut protected)
        .map_err(|_| anyhow!("AES-256-GCM authentication failed"))?;
    Ok(plaintext.to_vec())
}
