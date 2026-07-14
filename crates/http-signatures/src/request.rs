use httpsig::prelude::message_component::{HttpMessageComponent, HttpMessageComponentId};
use sfv::{DictSerializer, Integer, KeyRef, StringRef};
use thiserror::Error;
use url::Url;

use crate::content_digest;

const SIGNATURE_NAME: &str = "sig1";
const REQUEST_TAG: &str = "fapi-2-request";

pub struct RequestInput<'a> {
    pub method: &'a str,
    pub target_uri: &'a str,
    pub headers: &'a [(&'a str, &'a str)],
    pub body: &'a [u8],
}

pub struct RequestPolicy<'a> {
    pub created: i64,
    pub keyid: &'a str,
    pub algorithm: &'a str,
    pub covered_headers: &'a [&'a str],
}

pub struct SignatureFields {
    pub signature_input: String,
    pub signature: String,
}

pub struct PreparedSignature {
    signature_base: Vec<u8>,
    signature_input: String,
    signature_name: &'static str,
}

impl PreparedSignature {
    pub fn signature_base(&self) -> &[u8] {
        &self.signature_base
    }

    pub fn finish(self, signature: &[u8]) -> SignatureFields {
        let mut serializer = DictSerializer::new();
        let _ = serializer.bare_item(key(self.signature_name), signature);
        let signature = serializer
            .finish()
            .expect("signature dictionary is non-empty");

        SignatureFields {
            signature_input: self.signature_input,
            signature,
        }
    }

    pub(crate) fn new(
        signature_base: Vec<u8>,
        signature_input: String,
        signature_name: &'static str,
    ) -> Self {
        Self {
            signature_base,
            signature_input,
            signature_name,
        }
    }
}

#[derive(Debug, Error)]
pub enum RequestError {
    #[error("invalid HTTP signature input: {0}")]
    InvalidInput(String),
}

pub fn prepare_request(
    input: RequestInput<'_>,
    policy: RequestPolicy<'_>,
) -> Result<PreparedSignature, RequestError> {
    validate_method(input.method)?;
    let target_uri = canonical_target_uri(input.target_uri)?;
    if !matches!(
        policy.algorithm,
        "ed25519" | "rsa-v1_5-sha256" | "ecdsa-p256-sha256"
    ) {
        return Err(RequestError::InvalidInput(
            "unsupported signature algorithm".into(),
        ));
    }
    if policy.keyid.is_empty() {
        return Err(RequestError::InvalidInput(
            "key ID must not be empty".into(),
        ));
    }

    let authorization = unique_header(input.headers, "authorization")?
        .ok_or_else(|| RequestError::InvalidInput("missing Authorization header".into()))?;
    let dpop = unique_header(input.headers, "dpop")?;
    let supplied_digest = unique_header(input.headers, "content-digest")?;
    let computed_digest = (!input.body.is_empty()).then(|| content_digest(input.body));
    if supplied_digest != computed_digest.as_deref() && supplied_digest.is_some() {
        return Err(RequestError::InvalidInput(
            "Content-Digest does not match the request body".into(),
        ));
    }

    let mut components = vec![
        method_component(input.method)?,
        component("@target-uri", target_uri.as_str())?,
        field_component("authorization", authorization)?,
    ];
    if let Some(value) = dpop {
        components.push(field_component("dpop", value)?);
    }
    if let Some(digest) = computed_digest {
        components.push(field_component("content-digest", &digest)?);
    }
    let mut selected = std::collections::HashSet::new();
    for name in policy.covered_headers {
        if name.is_empty() || !name.bytes().all(is_token_byte) {
            return Err(RequestError::InvalidInput(
                "invalid additional covered header name".into(),
            ));
        }
        let name = name.to_ascii_lowercase();
        if matches!(
            name.as_str(),
            "authorization" | "dpop" | "content-digest" | "signature" | "signature-input"
        ) || !selected.insert(name.clone())
        {
            return Err(RequestError::InvalidInput(
                "duplicate additional covered component".into(),
            ));
        }
        let value = unique_header(input.headers, &name)?.ok_or_else(|| {
            RequestError::InvalidInput(format!("missing additional covered header: {name}"))
        })?;
        components.push(field_component(&name, value)?);
    }

    let signature_input = signature_input(&components, policy)?;
    let parameters = signature_input
        .strip_prefix(&format!("{SIGNATURE_NAME}="))
        .expect("serializer emitted the requested dictionary key");
    let mut signature_base = components
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("\n");
    signature_base.push_str("\n\"@signature-params\": ");
    signature_base.push_str(parameters);

    Ok(PreparedSignature {
        signature_base: signature_base.into_bytes(),
        signature_input,
        signature_name: SIGNATURE_NAME,
    })
}

fn validate_method(method: &str) -> Result<(), RequestError> {
    if method.is_empty() || !method.bytes().all(is_token_byte) {
        return Err(RequestError::InvalidInput("invalid HTTP method".into()));
    }
    Ok(())
}

pub(crate) fn canonical_target_uri(target_uri: &str) -> Result<String, RequestError> {
    if target_uri
        .bytes()
        .any(|byte| byte.is_ascii_control() || byte == b' ')
    {
        return Err(RequestError::InvalidInput("invalid target URI".into()));
    }
    let uri = Url::parse(target_uri)
        .map_err(|_| RequestError::InvalidInput("invalid target URI".into()))?;
    if !matches!(uri.scheme(), "http" | "https")
        || uri.host().is_none()
        || uri.fragment().is_some()
        || !uri.username().is_empty()
        || uri.password().is_some()
    {
        return Err(RequestError::InvalidInput("invalid target URI".into()));
    }
    Ok(uri.into())
}

fn unique_header<'a>(
    headers: &'a [(&str, &'a str)],
    wanted: &str,
) -> Result<Option<&'a str>, RequestError> {
    let mut values = headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case(wanted))
        .map(|(_, value)| *value);
    let first = values.next();
    if values.next().is_some() {
        return Err(RequestError::InvalidInput(format!(
            "duplicate covered header: {wanted}"
        )));
    }
    Ok(first)
}

pub(crate) fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

pub(crate) fn is_reserved_signature_field(name: &str) -> bool {
    matches!(name, "signature" | "signature-input")
}

pub(crate) fn component(name: &str, value: &str) -> Result<HttpMessageComponent, RequestError> {
    let id = HttpMessageComponentId::try_from(name)
        .map_err(|error| RequestError::InvalidInput(error.to_string()))?;
    HttpMessageComponent::try_from((&id, &[value.to_owned()][..]))
        .map_err(|error| RequestError::InvalidInput(error.to_string()))
}

pub(crate) fn method_component(method: &str) -> Result<HttpMessageComponent, RequestError> {
    HttpMessageComponent::try_from(format!("\"@method\": {method}").as_str())
        .map_err(|error| RequestError::InvalidInput(error.to_string()))
}

pub(crate) fn field_component(
    name: &str,
    value: &str,
) -> Result<HttpMessageComponent, RequestError> {
    if !value.is_ascii()
        || value.bytes().any(|byte| {
            byte == b'\r'
                || byte == b'\n'
                || byte == 0
                || (byte < 0x20 && byte != b'\t')
                || byte == 0x7f
        })
    {
        return Err(RequestError::InvalidInput(format!(
            "non-ASCII covered field value: {name}"
        )));
    }
    component(name, value.trim_matches([' ', '\t']))
}

fn signature_input(
    components: &[HttpMessageComponent],
    policy: RequestPolicy<'_>,
) -> Result<String, RequestError> {
    let created = Integer::try_from(policy.created)
        .map_err(|error| RequestError::InvalidInput(error.to_string()))?;
    let keyid = StringRef::from_str(policy.keyid)
        .map_err(|error| RequestError::InvalidInput(error.to_string()))?;
    let algorithm = StringRef::from_str(policy.algorithm)
        .map_err(|error| RequestError::InvalidInput(error.to_string()))?;
    let tag = StringRef::from_str(REQUEST_TAG).expect("static tag is a valid structured string");

    let mut serializer = DictSerializer::new();
    let mut inner = serializer.inner_list(key(SIGNATURE_NAME));
    for component in components {
        let id = component.id.to_string();
        let id = StringRef::from_str(id.trim_matches('"'))
            .map_err(|error| RequestError::InvalidInput(error.to_string()))?;
        let _ = inner.bare_item(id);
    }
    let _ = inner
        .finish()
        .parameter(key("created"), created)
        .parameter(key("keyid"), keyid)
        .parameter(key("alg"), algorithm)
        .parameter(key("tag"), tag);

    Ok(serializer
        .finish()
        .expect("signature dictionary is non-empty"))
}

fn key(value: &str) -> &KeyRef {
    KeyRef::from_str(value).expect("static dictionary and parameter keys are valid")
}
