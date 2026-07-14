use std::collections::HashSet;

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

/// Parses the server's compatibility representation for a `resource` parameter.
///
/// A single URI and the legacy JSON-array representation are both accepted. The
/// resulting values always pass the same URI, fragment, and duplicate checks.
pub fn parse_resource_indicator_parameter(
    value: Option<&str>,
) -> Result<Vec<String>, ResourceIndicatorError> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    if let Ok(values) = serde_json::from_str::<Vec<String>>(value) {
        return parse_resource_indicators(&values);
    }
    parse_resource_indicators(&[value.to_owned()])
}

/// Encodes resource indicators for storage in the existing single-value parameter map.
#[must_use]
pub fn encode_resource_indicators(values: &[String]) -> Option<String> {
    (!values.is_empty()).then(|| {
        serde_json::to_string(values).expect("resource indicator serialization must be infallible")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resource_indicators_require_absolute_unique_fragmentless_uris() {
        assert_eq!(
            parse_resource_indicators(&["https://api.example".to_owned()]).unwrap(),
            ["https://api.example"]
        );
        assert_eq!(
            parse_resource_indicators(&["relative".to_owned()]),
            Err(ResourceIndicatorError::Invalid)
        );
        assert_eq!(
            parse_resource_indicators(&["https://api.example#fragment".to_owned()]),
            Err(ResourceIndicatorError::Invalid)
        );
    }

    #[test]
    fn parameter_compatibility_representation_uses_the_same_validation() {
        assert_eq!(
            parse_resource_indicator_parameter(Some("https://api.example")).unwrap(),
            ["https://api.example"]
        );
        let encoded = encode_resource_indicators(&[
            "https://api.example".to_owned(),
            "https://admin.example".to_owned(),
        ])
        .unwrap();
        assert_eq!(
            parse_resource_indicator_parameter(Some(&encoded)).unwrap(),
            ["https://api.example", "https://admin.example"]
        );
        assert!(encode_resource_indicators(&[]).is_none());
        assert_eq!(
            parse_resource_indicator_parameter(Some(
                r#"["https://api.example","https://api.example"]"#
            )),
            Err(ResourceIndicatorError::Duplicate)
        );
    }
}
