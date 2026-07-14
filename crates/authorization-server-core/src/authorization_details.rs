//! RFC 9396-style authorization-details policy.

use std::{error::Error, fmt};

use serde::Deserialize;
use serde_json::Value;

const AUTHORIZATION_DETAILS_MAX_BYTES: usize = 16 * 1024;
pub const SUPPORTED_AUTHORIZATION_DETAILS_TYPES: &[&str] =
    &["account_information", "payment_initiation"];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorizationDetailsError;

impl fmt::Display for AuthorizationDetailsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid authorization_details")
    }
}

impl Error for AuthorizationDetailsError {}

pub fn parse_authorization_details(raw: Option<&str>) -> Result<Value, AuthorizationDetailsError> {
    let Some(raw) = raw else {
        return Ok(empty_authorization_details());
    };
    if raw.len() > AUTHORIZATION_DETAILS_MAX_BYTES {
        return Err(AuthorizationDetailsError);
    }
    let value: Value = serde_json::from_str(raw).map_err(|_| AuthorizationDetailsError)?;
    validate_authorization_details(&value)?;
    Ok(value)
}

#[must_use]
pub fn empty_authorization_details() -> Value {
    Value::Array(Vec::new())
}

pub fn deserialize_authorization_details<'de, D>(deserializer: D) -> Result<Value, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Value::deserialize(deserializer)?;
    normalize_authorization_details(value)
        .map_err(|_| serde::de::Error::custom("authorization_details must be a valid JSON array"))
}

pub fn normalize_authorization_details(value: Value) -> Result<Value, AuthorizationDetailsError> {
    match value {
        Value::Null => Ok(empty_authorization_details()),
        Value::Object(object) if object.is_empty() => Ok(empty_authorization_details()),
        other => {
            validate_authorization_details(&other)?;
            Ok(other)
        }
    }
}

pub fn canonical_authorization_details(value: &Value) -> Result<String, AuthorizationDetailsError> {
    validate_authorization_details(value)?;
    serde_json::to_string(value).map_err(|_| AuthorizationDetailsError)
}

#[must_use]
pub fn authorization_details_empty(value: &Value) -> bool {
    value.as_array().is_none_or(Vec::is_empty)
}

#[must_use]
pub fn high_risk_authorization_details(value: &Value) -> bool {
    value.as_array().is_some_and(|items| {
        items.iter().any(|item| {
            let Some(object) = item.as_object() else {
                return false;
            };
            let type_ = object.get("type").and_then(Value::as_str).unwrap_or("");
            type_.contains("payment")
                || object
                    .get("actions")
                    .and_then(Value::as_array)
                    .is_some_and(|actions| {
                        actions.iter().filter_map(Value::as_str).any(|action| {
                            matches!(
                                action,
                                "write" | "create" | "update" | "delete" | "transfer" | "payment"
                            )
                        })
                    })
        })
    })
}

fn validate_authorization_details(value: &Value) -> Result<(), AuthorizationDetailsError> {
    let Some(items) = value.as_array() else {
        return Err(AuthorizationDetailsError);
    };
    if items.len() > 32 {
        return Err(AuthorizationDetailsError);
    }
    for item in items {
        let Some(object) = item.as_object() else {
            return Err(AuthorizationDetailsError);
        };
        let Some(type_) = object.get("type").and_then(Value::as_str) else {
            return Err(AuthorizationDetailsError);
        };
        if type_.trim().is_empty()
            || type_.len() > 256
            || !SUPPORTED_AUTHORIZATION_DETAILS_TYPES.contains(&type_)
        {
            return Err(AuthorizationDetailsError);
        }
        if let Some(actions) = object.get("actions") {
            let Some(actions) = actions.as_array() else {
                return Err(AuthorizationDetailsError);
            };
            if actions.is_empty() || actions.len() > 32 {
                return Err(AuthorizationDetailsError);
            }
            for action in actions {
                let Some(action) = action.as_str() else {
                    return Err(AuthorizationDetailsError);
                };
                if action.trim().is_empty() || action.len() > 128 {
                    return Err(AuthorizationDetailsError);
                }
            }
        }
    }
    Ok(())
}
