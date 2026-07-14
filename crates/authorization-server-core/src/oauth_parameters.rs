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
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn scope_and_subset_policy_preserve_oauth_semantics() {
        assert_eq!(
            parse_scope("  openid   email openid "),
            ["openid", "email", "openid"]
        );
        assert!(is_subset(
            &parse_scope("openid email"),
            &parse_scope("email profile openid")
        ));
        assert!(is_subset(&[], &parse_scope("openid")));
    }

    #[test]
    fn json_string_collections_ignore_non_string_members() {
        assert_eq!(
            string_array_values(&json!(["openid", 1, null, "email"])),
            ["openid", "email"]
        );
        assert!(string_array_values(&json!({"scope": "openid"})).is_empty());
    }

    #[test]
    fn token_audience_policy_accepts_string_or_array_only() {
        assert_eq!(token_audience_values(&json!("api")), ["api"]);
        assert_eq!(
            token_audience_values(&json!(["api", 1, null, "admin"])),
            ["api", "admin"]
        );
        assert!(token_audience_values(&json!(true)).is_empty());
        assert!(token_audience_contains(&json!(["other", "api"]), "api"));
    }

    #[test]
    fn duplicate_detection_is_limited_to_named_parameters() {
        assert!(has_duplicate_oauth_parameter(
            "client_id=one&scope=openid&client_id=two",
            &["client_id", "redirect_uri"]
        ));
        assert!(!has_duplicate_oauth_parameter(
            "scope=openid&scope=email&client_id=one",
            &["client_id", "redirect_uri"]
        ));
    }
}
