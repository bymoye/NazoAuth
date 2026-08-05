use anyhow::{Context, anyhow};
use aws_lc_rs::{
    aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey},
    encoding::{AsDer, Pkcs8V1Der},
    rsa::{
        KeyPair, KeySize, OAEP_SHA256_MGF1SHA256, OaepPrivateDecryptingKey, PrivateDecryptingKey,
    },
    signature::KeyPair as _,
};

fn generate_rsa_pkcs8_der(bits: usize) -> anyhow::Result<Vec<u8>> {
    let size = match bits {
        2048 => KeySize::Rsa2048,
        3072 => KeySize::Rsa3072,
        4096 => KeySize::Rsa4096,
        _ => return Err(anyhow!("unsupported RSA key size {bits}")),
    };
    let key = KeyPair::generate(size).map_err(|_| anyhow!("AWS-LC RSA key generation failed"))?;
    Ok(AsDer::<Pkcs8V1Der<'static>>::as_der(&key)
        .map_err(|_| anyhow!("AWS-LC RSA PKCS#8 encoding failed"))?
        .as_ref()
        .to_vec())
}

pub(crate) fn generate_rsa_pkcs1_der(bits: usize) -> anyhow::Result<Vec<u8>> {
    let pkcs8 = generate_rsa_pkcs8_der(bits)?;
    let private_key = pkcs8::PrivateKeyInfoRef::try_from(pkcs8.as_slice())
        .context("AWS-LC produced invalid RSA PKCS#8")?;
    Ok(private_key.private_key.as_bytes().to_vec())
}

pub(crate) fn generate_rsa_pkcs8_pem(bits: usize) -> anyhow::Result<Vec<u8>> {
    let der = generate_rsa_pkcs8_der(bits)?;
    Ok(pem::encode(&pem::Pem::new("PRIVATE KEY", der)).into_bytes())
}

fn rsa_pkcs8_from_pem(value: &[u8]) -> anyhow::Result<Vec<u8>> {
    let pem = pem::parse(value).context("invalid private key PEM")?;
    if pem.tag() != "PRIVATE KEY" {
        return Err(anyhow!("RSA private key must use PKCS#8 PRIVATE KEY PEM"));
    }
    Ok(pem.into_contents())
}

pub(crate) fn validate_rsa_pkcs8_pem(value: &[u8]) -> anyhow::Result<()> {
    let der = rsa_pkcs8_from_pem(value)?;
    KeyPair::from_pkcs8(&der).map_err(|_| anyhow!("invalid RSA PKCS#8 private key"))?;
    Ok(())
}

pub(crate) fn rsa_public_components_from_pem(
    value: &[u8],
) -> anyhow::Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let der = rsa_pkcs8_from_pem(value)?;
    let key = KeyPair::from_pkcs8(&der).map_err(|_| anyhow!("invalid RSA PKCS#8 private key"))?;
    let public = key.public_key();
    let public_der = AsDer::as_der(public)
        .map_err(|_| anyhow!("AWS-LC RSA public-key encoding failed"))?
        .as_ref()
        .to_vec();
    Ok((
        public.modulus().big_endian_without_leading_zero().to_vec(),
        public.exponent().big_endian_without_leading_zero().to_vec(),
        public_der,
    ))
}

pub(crate) fn rsa_oaep_sha256_decrypt(
    private_key_pem: &[u8],
    ciphertext: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let der = rsa_pkcs8_from_pem(private_key_pem)?;
    let private = PrivateDecryptingKey::from_pkcs8(&der)
        .map_err(|_| anyhow!("invalid RSA PKCS#8 private key"))?;
    let private = OaepPrivateDecryptingKey::new(private)
        .map_err(|_| anyhow!("invalid RSA-OAEP private key"))?;
    let mut plaintext = vec![0; private.min_output_size()];
    Ok(private
        .decrypt(&OAEP_SHA256_MGF1SHA256, ciphertext, &mut plaintext, None)
        .map_err(|_| anyhow!("RSA-OAEP-256 decryption failed"))?
        .to_vec())
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

#[cfg(test)]
#[path = "../tests/support/crypto.rs"]
pub(crate) mod test_support;
