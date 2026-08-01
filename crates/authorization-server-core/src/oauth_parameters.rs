//! Framework-independent parsing and collection policy for OAuth parameters and claims.

use std::collections::HashSet;

use serde_json::Value;

/// Parses an OAuth space-delimited scope value without assigning policy to scope names.
#[must_use]
pub fn parse_scope(raw: &str) -> Vec<String> {
    raw.split_whitespace().map(ToOwned::to_owned).collect()
}

/// Returns the string members of a JSON array, ignoring malformed non-string members.
#[must_use]
pub fn string_array_values(value: &Value) -> Vec<String> {
    value
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|value| value.as_str().map(ToOwned::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

/// Tests whether every requested value is present in the allowed collection.
#[must_use]
pub fn is_subset(requested: &[String], allowed: &[String]) -> bool {
    requested.iter().all(|value| allowed.contains(value))
}

/// Normalizes the OAuth JWT `aud` representation to its string values.
#[must_use]
pub fn token_audience_values(audience: &Value) -> Vec<String> {
    match audience {
        Value::String(value) => vec![value.clone()],
        Value::Array(values) => values
            .iter()
            .filter_map(|value| value.as_str().map(ToOwned::to_owned))
            .collect(),
        _ => Vec::new(),
    }
}

#[must_use]
pub fn token_audience_contains(audience: &Value, expected: &str) -> bool {
    match audience {
        Value::String(audience) => audience == expected,
        Value::Array(audiences) => audiences
            .iter()
            .filter_map(Value::as_str)
            .any(|audience| audience == expected),
        _ => false,
    }
}

/// Detects duplicate security-sensitive OAuth parameters in a raw form-encoded query.
#[must_use]
pub fn has_duplicate_oauth_parameter(raw_query: &str, parameter_names: &[&str]) -> bool {
    let mut seen = HashSet::new();
    for (key, _) in url::form_urlencoded::parse(raw_query.as_bytes()) {
        if parameter_names.contains(&key.as_ref()) && !seen.insert(key.into_owned()) {
            return true;
        }
    }
    false
}

#[cfg(test)]
#[path = "../tests/unit/oauth_parameters.rs"]
mod tests;
