use sfv::{
    BareItem, DictSerializer, Dictionary, FieldType, Integer, KeyRef, ListEntry, Parser, StringRef,
};
use thiserror::Error;
use url::Url;

use crate::request::is_reserved_signature_field;
use crate::verify::{
    fingerprint, integer_parameter, signature_bytes, string_parameter, top_level_member_count,
    top_level_parameter_count, validate_parameters, validate_time,
};
use crate::{
    PreparedSignature, RequestInput, SignatureFields, VerificationPolicy, VerifiedInput,
    VerifyError, content_digest_field_matches,
};

const SIGNATURE_NAME: &str = "nazo";
const RESPONSE_TAG: &str = "fapi-2-response";

pub struct ResponseInput<'a> {
    pub status: u16,
    pub headers: &'a [(&'a str, &'a str)],
    pub body: &'a [u8],
}

pub struct OriginalRequest<'a> {
    pub input: RequestInput<'a>,
    pub signature_fields: Option<&'a SignatureFields>,
}

pub struct ResponsePolicy<'a> {
    pub created: i64,
    pub keyid: &'a str,
    pub algorithm: &'a str,
    pub covered_headers: &'a [&'a str],
    pub covered_request_headers: &'a [&'a str],
}

#[derive(Debug, Error)]
pub enum ResponseError {
    #[error("invalid HTTP response signature input: {0}")]
    InvalidInput(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Source {
    Response,
    Request,
}

struct Component {
    name: String,
    source: Source,
    value: String,
}

pub fn prepare_response(
    response: ResponseInput<'_>,
    original: OriginalRequest<'_>,
    policy: ResponsePolicy<'_>,
) -> Result<PreparedSignature, ResponseError> {
    validate_policy(policy.keyid, policy.algorithm)?;
    let components = response_components(&response, &original, &policy)?;
    let signature_input = serialize_signature_input(&components, policy)?;
    let params = signature_input
        .strip_prefix(&format!("{SIGNATURE_NAME}="))
        .expect("serializer emitted the response signature label");
    let mut base = components
        .iter()
        .map(component_line)
        .collect::<Vec<_>>()
        .join("\n");
    base.push_str("\n\"@signature-params\": ");
    base.push_str(params);
    Ok(PreparedSignature::new(
        base.into_bytes(),
        signature_input,
        SIGNATURE_NAME,
    ))
}

pub fn parse_response_for_verification(
    response: ResponseInput<'_>,
    original: OriginalRequest<'_>,
    fields: SignatureFields,
    policy: VerificationPolicy,
) -> Result<VerifiedInput, VerifyError> {
    validate_body_digest(response.headers, response.body)?;
    validate_original_digest(&original).map_err(|_| VerifyError::DigestMismatch)?;

    let signature_input: Dictionary = Parser::new(&fields.signature_input)
        .parse()
        .map_err(|_| VerifyError::MalformedSignature)?;
    let signatures: Dictionary = Parser::new(&fields.signature)
        .parse()
        .map_err(|_| VerifyError::MalformedSignature)?;
    if top_level_member_count(&fields.signature_input) > signature_input.len()
        || top_level_member_count(&fields.signature) > signatures.len()
    {
        return Err(VerifyError::AmbiguousSignature);
    }
    if signature_input.is_empty() || signatures.is_empty() {
        return Err(VerifyError::MissingSignature);
    }
    if signature_input.len() != 1 || signatures.len() != 1 {
        return Err(VerifyError::AmbiguousSignature);
    }
    let input_entry = signature_input
        .get(SIGNATURE_NAME)
        .ok_or(VerifyError::MissingSignature)?;
    let signature_entry = signatures
        .get(SIGNATURE_NAME)
        .ok_or(VerifyError::MissingSignature)?;
    let params = match input_entry {
        ListEntry::InnerList(inner) => inner,
        ListEntry::Item(_) => return Err(VerifyError::MalformedSignature),
    };
    if top_level_parameter_count(&fields.signature_input) != params.params.len() {
        return Err(VerifyError::MalformedSignature);
    }
    let signature = signature_bytes(signature_entry)?.to_vec();
    let created = integer_parameter(params, "created").ok_or(VerifyError::InvalidCreated)?;
    let keyid = string_parameter(params, "keyid")
        .filter(|value| !value.is_empty())
        .ok_or(VerifyError::MalformedSignature)?;
    let algorithm = string_parameter(params, "alg").ok_or(VerifyError::MalformedSignature)?;
    let tag = string_parameter(params, "tag").ok_or(VerifyError::InvalidTag)?;
    if tag != RESPONSE_TAG {
        return Err(VerifyError::InvalidTag);
    }
    if !supported_algorithm(algorithm) {
        return Err(VerifyError::UnsupportedAlgorithm);
    }
    validate_parameters(params)?;
    validate_time(params, created, policy)?;

    let expected_components = received_response_components(params, &response, &original)?;

    let serialized = signature_input
        .serialize()
        .ok_or(VerifyError::MalformedSignature)?;
    let signature_params = serialized
        .strip_prefix(SIGNATURE_NAME)
        .and_then(|value| value.strip_prefix('='))
        .ok_or(VerifyError::MalformedSignature)?;
    let mut base = expected_components
        .iter()
        .map(component_line)
        .collect::<Vec<_>>()
        .join("\n");
    base.push_str("\n\"@signature-params\": ");
    base.push_str(signature_params);
    let replay_fingerprint = fingerprint(
        &signature,
        keyid.as_bytes(),
        response.status.to_string().as_bytes(),
        original.input.method.as_bytes(),
        original.input.target_uri.as_bytes(),
    );

    Ok(VerifiedInput::new(
        base.into_bytes(),
        signature,
        keyid.to_owned(),
        algorithm.to_owned(),
        created,
        replay_fingerprint,
    ))
}

fn response_components(
    response: &ResponseInput<'_>,
    original: &OriginalRequest<'_>,
    policy: &ResponsePolicy<'_>,
) -> Result<Vec<Component>, ResponseError> {
    if !(100..=599).contains(&response.status) {
        return Err(invalid("invalid HTTP response status"));
    }
    validate_method(original.input.method)?;
    let target_uri = canonical_target_uri(original.input.target_uri)?;

    let supplied_response_digest = unique_header(response.headers, "content-digest")?;
    let response_digest = if response.body.is_empty() {
        if supplied_response_digest.is_some() {
            return Err(invalid(
                "Content-Digest is not allowed for an empty response body",
            ));
        }
        None
    } else {
        let supplied = supplied_response_digest
            .ok_or_else(|| invalid("response Content-Digest is missing"))?;
        validate_digest_value(supplied, response.body)
            .map_err(|_| invalid("response Content-Digest does not match its body"))?;
        Some(normalize_field("content-digest", supplied)?)
    };
    validate_original_digest(original)?;

    let mut components = vec![Component {
        name: "@status".into(),
        source: Source::Response,
        value: response.status.to_string(),
    }];
    if let Some(digest) = response_digest {
        components.push(Component {
            name: "content-digest".into(),
            source: Source::Response,
            value: digest,
        });
    }
    append_extra_headers(
        &mut components,
        response.headers,
        policy.covered_headers,
        Source::Response,
    )?;
    components.push(Component {
        name: "@method".into(),
        source: Source::Request,
        value: original.input.method.to_owned(),
    });
    components.push(Component {
        name: "@target-uri".into(),
        source: Source::Request,
        value: target_uri,
    });
    if let Some(digest) = unique_header(original.input.headers, "content-digest")? {
        components.push(Component {
            name: "content-digest".into(),
            source: Source::Request,
            value: normalize_field("content-digest", digest)?,
        });
    }
    if let Some(fields) = original.signature_fields {
        components.push(Component {
            name: "signature-input".into(),
            source: Source::Request,
            value: normalize_field("signature-input", &fields.signature_input)?,
        });
        components.push(Component {
            name: "signature".into(),
            source: Source::Request,
            value: normalize_field("signature", &fields.signature)?,
        });
    }
    append_extra_headers(
        &mut components,
        original.input.headers,
        policy.covered_request_headers,
        Source::Request,
    )?;
    Ok(components)
}

fn append_extra_headers(
    components: &mut Vec<Component>,
    headers: &[(&str, &str)],
    selected: &[&str],
    source: Source,
) -> Result<(), ResponseError> {
    for selected_name in selected {
        if selected_name.is_empty() || !selected_name.bytes().all(is_token_byte) {
            return Err(invalid("invalid additional covered header name"));
        }
        let name = selected_name.to_ascii_lowercase();
        if is_reserved_signature_field(&name)
            || components
                .iter()
                .any(|component| component.source == source && component.name == name)
        {
            return Err(invalid("duplicate additional covered component"));
        }
        let value = unique_header(headers, &name)?
            .ok_or_else(|| invalid(format!("missing additional covered header: {name}")))?;
        components.push(Component {
            name: name.clone(),
            source,
            value: normalize_field(&name, value)?,
        });
    }
    Ok(())
}

fn serialize_signature_input(
    components: &[Component],
    policy: ResponsePolicy<'_>,
) -> Result<String, ResponseError> {
    let created = Integer::try_from(policy.created).map_err(|error| invalid(error.to_string()))?;
    let keyid = StringRef::from_str(policy.keyid).map_err(|error| invalid(error.to_string()))?;
    let algorithm =
        StringRef::from_str(policy.algorithm).map_err(|error| invalid(error.to_string()))?;
    let tag = StringRef::from_str(RESPONSE_TAG).expect("static response tag is valid");
    let mut serializer = DictSerializer::new();
    let mut inner = serializer.inner_list(key(SIGNATURE_NAME));
    for component in components {
        let name =
            StringRef::from_str(&component.name).map_err(|error| invalid(error.to_string()))?;
        let item = inner.bare_item(name);
        if component.source == Source::Request {
            let _ = item.parameter(key("req"), true);
        }
    }
    let _ = inner
        .finish()
        .parameter(key("created"), created)
        .parameter(key("keyid"), keyid)
        .parameter(key("alg"), algorithm)
        .parameter(key("tag"), tag);
    serializer
        .finish()
        .ok_or_else(|| invalid("empty signature input"))
}

fn received_response_components(
    params: &sfv::InnerList,
    response: &ResponseInput<'_>,
    original: &OriginalRequest<'_>,
) -> Result<Vec<Component>, VerifyError> {
    if !(100..=599).contains(&response.status) {
        return Err(VerifyError::MissingComponent);
    }
    validate_method(original.input.method).map_err(|_| VerifyError::MissingComponent)?;
    let target_uri = canonical_target_uri(original.input.target_uri)
        .map_err(|_| VerifyError::MissingComponent)?;
    let mut required = vec![
        ("@status", Source::Response),
        ("@method", Source::Request),
        ("@target-uri", Source::Request),
    ];
    if !response.body.is_empty() {
        required.push(("content-digest", Source::Response));
    }
    if !original.input.body.is_empty() {
        required.push(("content-digest", Source::Request));
    }
    if original.signature_fields.is_some() {
        required.push(("signature-input", Source::Request));
        required.push(("signature", Source::Request));
    }

    let mut seen = std::collections::HashSet::with_capacity(params.items.len());
    let mut components = Vec::with_capacity(params.items.len());
    for item in &params.items {
        let BareItem::String(name) = &item.bare_item else {
            return Err(VerifyError::MalformedSignature);
        };
        let source = if item.params.is_empty() {
            Source::Response
        } else if item.params.len() == 1
            && matches!(item.params.get("req"), Some(BareItem::Boolean(true)))
        {
            Source::Request
        } else {
            return Err(VerifyError::MalformedSignature);
        };
        let name = name.as_str();
        if !seen.insert((name, source)) {
            return Err(VerifyError::MissingComponent);
        }
        let value = match (name, source) {
            ("@status", Source::Response) => response.status.to_string(),
            ("@method", Source::Request) => original.input.method.to_owned(),
            ("@target-uri", Source::Request) => target_uri.clone(),
            (name, _) if name.starts_with('@') => return Err(VerifyError::MissingComponent),
            (name, Source::Response) if is_reserved_signature_field(name) => {
                return Err(VerifyError::MissingComponent);
            }
            (name, _)
                if name.is_empty()
                    || name != name.to_ascii_lowercase()
                    || !name.bytes().all(is_token_byte) =>
            {
                return Err(VerifyError::MissingComponent);
            }
            ("signature-input", Source::Request) => original
                .signature_fields
                .map(|fields| normalize_field("signature-input", &fields.signature_input))
                .transpose()
                .map_err(|_| VerifyError::MissingComponent)?
                .ok_or(VerifyError::MissingComponent)?,
            ("signature", Source::Request) => original
                .signature_fields
                .map(|fields| normalize_field("signature", &fields.signature))
                .transpose()
                .map_err(|_| VerifyError::MissingComponent)?
                .ok_or(VerifyError::MissingComponent)?,
            (name, Source::Response) => unique_header_for_verification(response.headers, name)?,
            (name, Source::Request) => {
                unique_header_for_verification(original.input.headers, name)?
            }
        };
        components.push(Component {
            name: name.to_owned(),
            source,
            value,
        });
    }
    if required
        .iter()
        .any(|(name, source)| !seen.contains(&(*name, *source)))
    {
        return Err(VerifyError::MissingComponent);
    }
    Ok(components)
}

fn unique_header_for_verification(
    headers: &[(&str, &str)],
    wanted: &str,
) -> Result<String, VerifyError> {
    let mut values = headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case(wanted))
        .map(|(_, value)| *value);
    let value = values.next().ok_or(VerifyError::MissingComponent)?;
    if values.next().is_some() {
        return Err(VerifyError::MissingComponent);
    }
    normalize_field(wanted, value).map_err(|_| VerifyError::MissingComponent)
}

fn component_line(component: &Component) -> String {
    let req = if component.source == Source::Request {
        ";req"
    } else {
        ""
    };
    format!("\"{}\"{req}: {}", component.name, component.value)
}

fn validate_original_digest(original: &OriginalRequest<'_>) -> Result<(), ResponseError> {
    let supplied = unique_header(original.input.headers, "content-digest")?;
    match (original.input.body.is_empty(), supplied) {
        (true, None) => Ok(()),
        (true, Some(_)) => Err(invalid(
            "request Content-Digest is invalid for an empty body",
        )),
        (false, None) => Err(invalid("request Content-Digest is missing")),
        (false, Some(value)) => validate_digest_value(value, original.input.body)
            .map_err(|_| invalid("request Content-Digest does not match its body")),
    }
}

fn validate_body_digest(headers: &[(&str, &str)], body: &[u8]) -> Result<(), VerifyError> {
    let supplied = unique_header_verify(headers, "content-digest")?;
    match (body.is_empty(), supplied) {
        (true, None) => Ok(()),
        (true, Some(_)) | (false, None) => Err(VerifyError::DigestMismatch),
        (false, Some(value)) => validate_digest_value(value, body),
    }
}

fn validate_digest_value(value: &str, body: &[u8]) -> Result<(), VerifyError> {
    content_digest_field_matches(value, body)
        .then_some(())
        .ok_or(VerifyError::DigestMismatch)
}

fn validate_policy(keyid: &str, algorithm: &str) -> Result<(), ResponseError> {
    if keyid.is_empty() {
        return Err(invalid("key ID must not be empty"));
    }
    if !supported_algorithm(algorithm) {
        return Err(invalid("unsupported signature algorithm"));
    }
    Ok(())
}

fn supported_algorithm(algorithm: &str) -> bool {
    matches!(
        algorithm,
        "ed25519" | "rsa-v1_5-sha256" | "ecdsa-p256-sha256"
    )
}

fn validate_method(method: &str) -> Result<(), ResponseError> {
    if method.is_empty() || !method.bytes().all(is_token_byte) {
        return Err(invalid("invalid HTTP method"));
    }
    Ok(())
}

fn canonical_target_uri(target_uri: &str) -> Result<String, ResponseError> {
    if target_uri
        .bytes()
        .any(|byte| byte.is_ascii_control() || byte == b' ')
    {
        return Err(invalid("invalid target URI"));
    }
    let uri = Url::parse(target_uri).map_err(|_| invalid("invalid target URI"))?;
    if !matches!(uri.scheme(), "http" | "https")
        || uri.host().is_none()
        || uri.fragment().is_some()
        || !uri.username().is_empty()
        || uri.password().is_some()
    {
        return Err(invalid("invalid target URI"));
    }
    Ok(uri.into())
}

fn normalize_field(name: &str, value: &str) -> Result<String, ResponseError> {
    if !value.is_ascii()
        || value.bytes().any(|byte| {
            byte == b'\r'
                || byte == b'\n'
                || byte == 0
                || (byte < 0x20 && byte != b'\t')
                || byte == 0x7f
        })
    {
        return Err(invalid(format!("invalid covered field value: {name}")));
    }
    Ok(value.trim_matches([' ', '\t']).to_owned())
}

fn unique_header<'a>(
    headers: &'a [(&str, &'a str)],
    wanted: &str,
) -> Result<Option<&'a str>, ResponseError> {
    let mut values = headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case(wanted))
        .map(|(_, value)| *value);
    let first = values.next();
    if values.next().is_some() {
        return Err(invalid(format!("duplicate covered header: {wanted}")));
    }
    Ok(first)
}

fn unique_header_verify<'a>(
    headers: &'a [(&str, &'a str)],
    wanted: &str,
) -> Result<Option<&'a str>, VerifyError> {
    let mut values = headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case(wanted))
        .map(|(_, value)| *value);
    let first = values.next();
    if values.next().is_some() {
        return Err(VerifyError::DigestMismatch);
    }
    Ok(first)
}

fn is_token_byte(byte: u8) -> bool {
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

fn key(value: &str) -> &KeyRef {
    KeyRef::from_str(value).expect("static dictionary and parameter keys are valid")
}

fn invalid(message: impl Into<String>) -> ResponseError {
    ResponseError::InvalidInput(message.into())
}
