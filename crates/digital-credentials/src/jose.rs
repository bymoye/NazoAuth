use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct JwtHeader {
    pub alg: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub typ: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwk: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x5c: Option<Vec<String>>,
    #[serde(flatten)]
    pub extensions: serde_json::Map<String, Value>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CompactJwt {
    pub encoded_header: String,
    pub encoded_payload: String,
    pub encoded_signature: String,
    pub header: JwtHeader,
    pub claims: Value,
}

impl CompactJwt {
    #[must_use]
    pub fn signing_input(&self) -> String {
        format!("{}.{}", self.encoded_header, self.encoded_payload)
    }
}

pub fn decode_compact_jwt(input: &str) -> Result<CompactJwt, JoseError> {
    let mut parts = input.split('.');
    let (Some(encoded_header), Some(encoded_payload), Some(encoded_signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(JoseError::MalformedJwt);
    };
    if encoded_signature.is_empty() {
        return Err(JoseError::UnsignedJwt);
    }
    let header = decode_json(encoded_header).map_err(|_| JoseError::MalformedHeader)?;
    let claims = decode_json(encoded_payload).map_err(|_| JoseError::MalformedClaims)?;
    Ok(CompactJwt {
        encoded_header: encoded_header.to_owned(),
        encoded_payload: encoded_payload.to_owned(),
        encoded_signature: encoded_signature.to_owned(),
        header,
        claims,
    })
}

fn decode_json<T: serde::de::DeserializeOwned>(input: &str) -> Result<T, serde_json::Error> {
    let bytes = URL_SAFE_NO_PAD
        .decode(input)
        .map_err(|error| serde_json::Error::io(std::io::Error::other(error)))?;
    serde_json::from_slice(&bytes)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompactJwe {
    pub protected: String,
    pub encrypted_key: String,
    pub initialization_vector: String,
    pub ciphertext: String,
    pub authentication_tag: String,
}

pub fn parse_compact_jwe(input: &str) -> Result<CompactJwe, JoseError> {
    let parts = input.split('.').collect::<Vec<_>>();
    // RFC 7516 compact serialization always has five parts, but direct key
    // agreement algorithms such as ECDH-ES carry no encrypted CEK.  In that
    // case the second part is intentionally empty (`protected..iv.ct.tag`).
    if parts.len() != 5
        || parts[0].is_empty()
        || parts[2].is_empty()
        || parts[3].is_empty()
        || parts[4].is_empty()
    {
        return Err(JoseError::MalformedJwe);
    }
    Ok(CompactJwe {
        protected: parts[0].to_owned(),
        encrypted_key: parts[1].to_owned(),
        initialization_vector: parts[2].to_owned(),
        ciphertext: parts[3].to_owned(),
        authentication_tag: parts[4].to_owned(),
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum JoseError {
    #[error("JWT compact serialization is malformed")]
    MalformedJwt,
    #[error("JWT header is malformed")]
    MalformedHeader,
    #[error("JWT claims are malformed")]
    MalformedClaims,
    #[error("unsigned JWTs are not accepted")]
    UnsignedJwt,
    #[error("JWE compact serialization is malformed")]
    MalformedJwe,
}
