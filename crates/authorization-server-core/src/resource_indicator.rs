use std::collections::HashSet;

const INTERNAL_RESOURCE_SET_PREFIX: &str = "nazo-internal-resource-set:";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceIndicatorError {
    Invalid,
    Duplicate,
}

pub fn parse_resource_indicators(values: &[String]) -> Result<Vec<String>, ResourceIndicatorError> {
    let mut seen = HashSet::new();
    let mut resources = Vec::with_capacity(values.len());
    for value in values {
        let parsed = url::Url::parse(value).map_err(|_| ResourceIndicatorError::Invalid)?;
        if parsed.fragment().is_some() {
            return Err(ResourceIndicatorError::Invalid);
        }
        if !seen.insert(value.clone()) {
            return Err(ResourceIndicatorError::Duplicate);
        }
        resources.push(value.clone());
    }
    Ok(resources)
}

/// Parses a resource value after the transport boundary has normalized repeated
/// RFC 8707 parameters into the server's private representation.
pub fn parse_resource_indicator_parameter(
    value: Option<&str>,
) -> Result<Vec<String>, ResourceIndicatorError> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    if let Some(encoded) = value.strip_prefix(INTERNAL_RESOURCE_SET_PREFIX) {
        let values = serde_json::from_str::<Vec<String>>(encoded)
            .map_err(|_| ResourceIndicatorError::Invalid)?;
        return parse_resource_indicators(&values);
    }
    parse_resource_indicators(&[value.to_owned()])
}

/// Encodes transport-validated repeated values into a private in-process form.
#[must_use]
pub fn encode_resource_indicators(values: &[String]) -> Option<String> {
    (!values.is_empty()).then(|| {
        format!(
            "{INTERNAL_RESOURCE_SET_PREFIX}{}",
            serde_json::to_string(values)
                .expect("resource indicator serialization must be infallible")
        )
    })
}

#[cfg(test)]
#[path = "../tests/unit/resource_indicator.rs"]
mod tests;
