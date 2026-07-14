use std::fmt;

use sfv::{BareItem, Dictionary, FieldType, InnerList, ListEntry, Parser};
use sha2::{Digest, Sha256};
use url::Url;

use crate::request::{
    canonical_target_uri, component, field_component, is_reserved_signature_field, is_token_byte,
    method_component,
};
use crate::{RequestInput, SignatureFields, VerifyError, content_digest_field_matches};

const REQUEST_TAG: &str = "fapi-2-request";

#[derive(Debug, Clone, Copy)]
pub struct VerificationPolicy {
    pub now: i64,
    pub max_age_seconds: i64,
    pub future_skew_seconds: i64,
}

pub struct VerifiedInput {
    signature_base: Vec<u8>,
    signature: Vec<u8>,
    keyid: String,
    algorithm: String,
    created: i64,
    replay_fingerprint: [u8; 32],
}

impl fmt::Debug for VerifiedInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VerifiedInput { .. }")
    }
}

impl VerifiedInput {
    pub fn signature_base(&self) -> &[u8] {
        &self.signature_base
    }

    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    pub fn keyid(&self) -> &str {
        &self.keyid
    }

    pub fn algorithm(&self) -> &str {
        &self.algorithm
    }

    pub fn created(&self) -> i64 {
        self.created
    }

    pub fn replay_fingerprint(&self) -> &[u8; 32] {
        &self.replay_fingerprint
    }

    pub(crate) fn new(
        signature_base: Vec<u8>,
        signature: Vec<u8>,
        keyid: String,
        algorithm: String,
        created: i64,
        replay_fingerprint: [u8; 32],
    ) -> Self {
        Self {
            signature_base,
            signature,
            keyid,
            algorithm,
            created,
            replay_fingerprint,
        }
    }
}

pub fn parse_request_for_verification(
    input: RequestInput<'_>,
    fields: SignatureFields,
    policy: VerificationPolicy,
) -> Result<VerifiedInput, VerifyError> {
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
    if signature_input.len() > 1 || signatures.len() > 1 {
        return Err(VerifyError::AmbiguousSignature);
    }
    let (label, input_entry) = signature_input
        .first()
        .ok_or(VerifyError::MissingSignature)?;
    let signature_entry = signatures
        .get(label.as_str())
        .ok_or(VerifyError::MissingSignature)?;

    let params = match input_entry {
        ListEntry::InnerList(inner) => inner,
        ListEntry::Item(_) => return Err(VerifyError::MalformedSignature),
    };
    if top_level_parameter_count(&fields.signature_input) != params.params.len() {
        return Err(VerifyError::MalformedSignature);
    }
    let signature = signature_bytes(signature_entry)?.to_vec();
    let components = component_names(params)?;
    let created = integer_parameter(params, "created").ok_or(VerifyError::InvalidCreated)?;
    let keyid = string_parameter(params, "keyid")
        .filter(|value| !value.is_empty())
        .ok_or(VerifyError::MalformedSignature)?;
    let algorithm = string_parameter(params, "alg").ok_or(VerifyError::MalformedSignature)?;
    let tag = string_parameter(params, "tag").ok_or(VerifyError::InvalidTag)?;
    if tag != REQUEST_TAG {
        return Err(VerifyError::InvalidTag);
    }
    if !matches!(
        algorithm,
        "ed25519" | "rsa-v1_5-sha256" | "ecdsa-p256-sha256"
    ) {
        return Err(VerifyError::UnsupportedAlgorithm);
    }
    validate_parameters(params)?;
    validate_time(params, created, policy)?;
    let supplied_digest = validate_digest(&input)?;

    let authorization = unique_header(input.headers, "authorization")
        .map_err(|_| VerifyError::MissingComponent)?
        .ok_or(VerifyError::MissingComponent)?;
    let dpop = unique_header(input.headers, "dpop").map_err(|_| VerifyError::MissingComponent)?;
    let mut required = vec!["@method", "@target-uri", "authorization"];
    if dpop.is_some() {
        required.push("dpop");
    }
    if supplied_digest.is_some() {
        required.push("content-digest");
    }
    let mut seen = std::collections::HashSet::with_capacity(components.len());
    let target_uri =
        canonical_target_uri(input.target_uri).map_err(|_| VerifyError::MissingComponent)?;
    let mut reconstructed = Vec::with_capacity(components.len());
    for name in &components {
        if !seen.insert(name.as_str()) {
            return Err(VerifyError::MissingComponent);
        }
        let value = match name.as_str() {
            "@method" => method_component(input.method),
            "@target-uri" => component("@target-uri", &target_uri),
            name if name.starts_with('@')
                || name.is_empty()
                || is_reserved_signature_field(name)
                || name != name.to_ascii_lowercase()
                || !name.bytes().all(is_token_byte) =>
            {
                return Err(VerifyError::MissingComponent);
            }
            name => {
                let value = unique_header(input.headers, name)
                    .map_err(|_| VerifyError::MissingComponent)?
                    .ok_or(VerifyError::MissingComponent)?;
                field_component(name, value)
            }
        }
        .map_err(|_| VerifyError::MissingComponent)?;
        reconstructed.push(value);
    }
    if required.iter().any(|name| !seen.contains(name)) {
        return Err(VerifyError::MissingComponent);
    }

    let serialized = signature_input
        .serialize()
        .ok_or(VerifyError::MalformedSignature)?;
    let signature_params = serialized
        .strip_prefix(label.as_str())
        .and_then(|value| value.strip_prefix('='))
        .ok_or(VerifyError::MalformedSignature)?;
    let mut signature_base = reconstructed
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("\n")
        .into_bytes();
    signature_base.extend_from_slice(b"\n\"@signature-params\": ");
    signature_base.extend_from_slice(signature_params.as_bytes());

    let target_uri = Url::parse(input.target_uri)
        .map_err(|_| VerifyError::MissingComponent)?
        .to_string();
    let replay_fingerprint = fingerprint(
        &signature,
        keyid.as_bytes(),
        input.method.as_bytes(),
        target_uri.as_bytes(),
        authorization.trim_matches([' ', '\t']).as_bytes(),
    );

    Ok(VerifiedInput {
        signature_base,
        signature,
        keyid: keyid.to_owned(),
        algorithm: algorithm.to_owned(),
        created,
        replay_fingerprint,
    })
}

pub(crate) fn signature_bytes(entry: &ListEntry) -> Result<&[u8], VerifyError> {
    match entry {
        ListEntry::Item(item)
            if item.params.is_empty() && matches!(item.bare_item, BareItem::ByteSequence(_)) =>
        {
            match &item.bare_item {
                BareItem::ByteSequence(bytes) => Ok(bytes),
                _ => unreachable!(),
            }
        }
        _ => Err(VerifyError::MalformedSignature),
    }
}

fn component_names(inner: &InnerList) -> Result<Vec<String>, VerifyError> {
    inner
        .items
        .iter()
        .map(|item| {
            if !item.params.is_empty() {
                return Err(VerifyError::MalformedSignature);
            }
            match &item.bare_item {
                BareItem::String(value) => Ok(value.as_str().to_owned()),
                _ => Err(VerifyError::MalformedSignature),
            }
        })
        .collect()
}

pub(crate) fn string_parameter<'a>(inner: &'a InnerList, name: &str) -> Option<&'a str> {
    match inner.params.get(name) {
        Some(BareItem::String(value)) => Some(value.as_str()),
        _ => None,
    }
}

pub(crate) fn integer_parameter(inner: &InnerList, name: &str) -> Option<i64> {
    match inner.params.get(name) {
        Some(BareItem::Integer(value)) => Some((*value).into()),
        _ => None,
    }
}

pub(crate) fn validate_parameters(inner: &InnerList) -> Result<(), VerifyError> {
    if inner.params.keys().any(|key| {
        !matches!(
            key.as_str(),
            "created" | "expires" | "keyid" | "alg" | "tag"
        )
    }) {
        return Err(VerifyError::MalformedSignature);
    }
    Ok(())
}

pub(crate) fn validate_time(
    inner: &InnerList,
    created: i64,
    policy: VerificationPolicy,
) -> Result<(), VerifyError> {
    if policy.max_age_seconds < 0
        || policy.future_skew_seconds < 0
        || created < policy.now.saturating_sub(policy.max_age_seconds)
        || created > policy.now.saturating_add(policy.future_skew_seconds)
    {
        return Err(VerifyError::InvalidCreated);
    }
    if let Some(expires) = inner.params.get("expires") {
        let BareItem::Integer(expires) = expires else {
            return Err(VerifyError::InvalidCreated);
        };
        let expires: i64 = (*expires).into();
        if expires < created || expires < policy.now {
            return Err(VerifyError::InvalidCreated);
        }
    }
    Ok(())
}

fn validate_digest<'a>(input: &'a RequestInput<'_>) -> Result<Option<&'a str>, VerifyError> {
    let supplied =
        unique_header(input.headers, "content-digest").map_err(|_| VerifyError::DigestMismatch)?;
    if input.body.is_empty() {
        return supplied
            .is_none()
            .then_some(None)
            .ok_or(VerifyError::DigestMismatch);
    }
    let supplied = supplied.ok_or(VerifyError::DigestMismatch)?;
    if !content_digest_field_matches(supplied, input.body) {
        return Err(VerifyError::DigestMismatch);
    }
    Ok(Some(supplied))
}

fn unique_header<'a>(headers: &'a [(&str, &'a str)], wanted: &str) -> Result<Option<&'a str>, ()> {
    let mut values = headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case(wanted))
        .map(|(_, value)| *value);
    let first = values.next();
    if values.next().is_some() {
        return Err(());
    }
    Ok(first)
}

pub(crate) fn top_level_member_count(field: &str) -> usize {
    if field.trim().is_empty() {
        return 0;
    }
    let mut count = 1;
    scan_unquoted(field, |byte, depth| {
        if byte == b',' && depth == 0 {
            count += 1;
        }
    });
    count
}

pub(crate) fn top_level_parameter_count(field: &str) -> usize {
    let mut count = 0;
    scan_unquoted(field, |byte, depth| {
        if byte == b';' && depth == 0 {
            count += 1;
        }
    });
    count
}

fn scan_unquoted(field: &str, mut visit: impl FnMut(u8, usize)) {
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    let mut in_binary = false;
    for byte in field.bytes() {
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
            continue;
        }
        if in_binary {
            if byte == b':' {
                in_binary = false;
            }
            continue;
        }
        match byte {
            b'"' => in_string = true,
            b':' => in_binary = true,
            b'(' => depth += 1,
            b')' => depth = depth.saturating_sub(1),
            _ => visit(byte, depth),
        }
    }
}

pub(crate) fn fingerprint(
    parts0: &[u8],
    parts1: &[u8],
    parts2: &[u8],
    parts3: &[u8],
    parts4: &[u8],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for part in [parts0, parts1, parts2, parts3, parts4] {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part);
    }
    hasher.finalize().into()
}
