//! 结构化安全审计日志。

pub(crate) const AUDIT_SCHEMA_VERSION: &str = "nazo.audit.v1";

const SENSITIVE_FIELD_NAMES: &[&str] = &[
    "access_token",
    "refresh_token",
    "authorization_code",
    "client_secret",
    "dpop_proof",
    "client_assertion",
];

const AUDIT_EVENT_DEFINITIONS: &[(&str, &str)] = &[
    ("admin_user_updated", "administration"),
    ("authorization_approved", "authorization"),
    ("authorization_denied", "authorization"),
    ("authorization_prompt_none_approved", "authorization"),
    ("ciba_authorization_approved", "authorization"),
    ("ciba_authorization_denied", "authorization"),
    ("ciba_authorization_started", "authorization"),
    ("client_assertion_replay_detected", "credential_replay"),
    ("client_created", "client_lifecycle"),
    ("client_updated", "client_lifecycle"),
    ("dynamic_client_configuration_read", "client_lifecycle"),
    ("dynamic_client_configuration_updated", "client_lifecycle"),
    ("dynamic_client_deleted", "client_lifecycle"),
    ("dynamic_client_registered", "client_lifecycle"),
    ("dpop_replay_detected", "credential_replay"),
    ("external_identity_linked", "identity_lifecycle"),
    ("external_identity_relink_denied", "identity_lifecycle"),
    ("external_identity_unlinked", "identity_lifecycle"),
    ("federation_login_success", "authentication"),
    ("login_failure", "authentication"),
    ("login_success", "authentication"),
    ("mfa_backup_codes_regenerated", "authentication"),
    ("mfa_challenge_failure", "authentication"),
    ("mfa_challenge_success", "authentication"),
    ("mfa_disabled", "authentication"),
    ("mfa_totp_enabled", "authentication"),
    ("oidc_logout", "session_lifecycle"),
    ("passkey_login_failure", "authentication"),
    ("passkey_login_success", "authentication"),
    ("passkey_registered", "authentication"),
    ("passkey_registration_rejected", "authentication"),
    ("refresh_reuse_detected", "token_replay"),
    ("refresh_rotated", "token_lifecycle"),
    ("scim_token_denied", "provisioning"),
    ("scim_token_used", "provisioning"),
    ("token_issued", "token_lifecycle"),
    ("token_revoked", "token_lifecycle"),
];

pub(crate) fn audit_event(event: &str, mut fields: serde_json::Map<String, serde_json::Value>) {
    debug_assert!(audit_event_name_valid(event));
    debug_assert!(audit_event_category(event).is_some());
    for key in SENSITIVE_FIELD_NAMES {
        fields.remove(*key);
    }
    fields.insert(
        "schema_version".to_owned(),
        serde_json::Value::String(AUDIT_SCHEMA_VERSION.to_owned()),
    );
    if let Some(category) = audit_event_category(event) {
        fields.insert(
            "event_category".to_owned(),
            serde_json::Value::String(category.to_owned()),
        );
    }
    tracing::info!(
        target: "audit",
        event,
        fields = %serde_json::Value::Object(fields),
        "security audit event"
    );
}

pub(crate) fn audit_fields(
    items: &[(&str, serde_json::Value)],
) -> serde_json::Map<String, serde_json::Value> {
    items
        .iter()
        .map(|(key, value)| ((*key).to_owned(), value.clone()))
        .collect()
}

fn audit_event_category(event: &str) -> Option<&'static str> {
    AUDIT_EVENT_DEFINITIONS
        .iter()
        .find_map(|(name, category)| (*name == event).then_some(*category))
}

fn audit_event_name_valid(event: &str) -> bool {
    let mut chars = event.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    first.is_ascii_lowercase()
        && chars.all(|value| value.is_ascii_lowercase() || value.is_ascii_digit() || value == '_')
}

#[cfg(test)]
#[path = "../../tests/in_source/src/support/tests/audit.rs"]
mod tests;
