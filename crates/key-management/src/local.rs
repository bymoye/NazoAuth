use std::{future::Future, pin::Pin};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nazo_auth::{SignError, Signature};

pub(crate) trait SigningBackend {
    fn sign<'a>(
        &'a self,
        signing_input: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = Result<Signature, SignError>> + Send + 'a>>;
}

pub(crate) struct LocalBackend<'a> {
    pub(crate) algorithm: jsonwebtoken::Algorithm,
    pub(crate) private_key: &'a [u8],
}

impl SigningBackend for LocalBackend<'_> {
    fn sign<'a>(
        &'a self,
        signing_input: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = Result<Signature, SignError>> + Send + 'a>> {
        Box::pin(async move {
            let encoded = sign(self.algorithm, self.private_key, signing_input)
                .map_err(|_| SignError::SigningFailed)?;
            let bytes = URL_SAFE_NO_PAD
                .decode(encoded)
                .map_err(|_| SignError::SigningFailed)?;
            Ok(Signature::new(bytes))
        })
    }
}

fn sign(
    algorithm: jsonwebtoken::Algorithm,
    private_pkcs8_der: &[u8],
    signing_input: &[u8],
) -> jsonwebtoken::errors::Result<String> {
    let key = match algorithm {
        jsonwebtoken::Algorithm::EdDSA => jsonwebtoken::EncodingKey::from_ed_der(private_pkcs8_der),
        jsonwebtoken::Algorithm::RS256 | jsonwebtoken::Algorithm::PS256 => {
            jsonwebtoken::EncodingKey::from_rsa_der(private_pkcs8_der)
        }
        jsonwebtoken::Algorithm::ES256 => jsonwebtoken::EncodingKey::from_ec_der(private_pkcs8_der),
        _ => return Err(jsonwebtoken::errors::ErrorKind::InvalidAlgorithm.into()),
    };
    jsonwebtoken::crypto::sign(signing_input, &key, algorithm)
}
