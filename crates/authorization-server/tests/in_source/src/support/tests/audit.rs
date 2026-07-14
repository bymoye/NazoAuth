use super::*;
use serde_json::json;

#[test]
fn audit_fields_can_remove_sensitive_material() {
    let mut fields = audit_fields(&[
        ("client_id", json!("client-1")),
        ("access_token", json!("secret-token")),
    ]);
    for key in SENSITIVE_FIELD_NAMES {
        fields.remove(*key);
    }

    assert_eq!(fields.get("client_id"), Some(&json!("client-1")));
    assert!(fields.get("access_token").is_none());
}

#[test]
fn audit_event_names_are_allowlisted_and_siem_ready() {
    for (name, category) in AUDIT_EVENT_DEFINITIONS {
        assert!(audit_event_name_valid(name));
        assert_eq!(audit_event_category(name), Some(*category));
        assert!(audit_event_name_valid(category));
    }
    assert!(audit_event_category("unknown_event").is_none());
    assert!(!audit_event_name_valid("LoginSuccess"));
    assert!(!audit_event_name_valid("login-success"));
    assert!(!audit_event_name_valid(""));
}

#[test]
fn audit_event_definitions_include_dynamic_client_lifecycle() {
    for name in [
        "dynamic_client_registered",
        "dynamic_client_configuration_read",
        "dynamic_client_configuration_updated",
        "dynamic_client_deleted",
    ] {
        assert_eq!(audit_event_category(name), Some("client_lifecycle"));
    }
}

#[test]
fn audit_event_definitions_include_external_identity_lifecycle() {
    assert_eq!(
        audit_event_category("external_identity_linked"),
        Some("identity_lifecycle")
    );
    assert_eq!(
        audit_event_category("external_identity_unlinked"),
        Some("identity_lifecycle")
    );
    assert_eq!(
        audit_event_category("external_identity_relink_denied"),
        Some("identity_lifecycle")
    );
}

#[test]
fn audit_event_definitions_include_ciba_authorization_lifecycle() {
    for name in [
        "ciba_authorization_started",
        "ciba_authorization_approved",
        "ciba_authorization_denied",
    ] {
        assert_eq!(audit_event_category(name), Some("authorization"));
    }
}

#[test]
fn audit_event_definitions_include_mfa_step_up() {
    assert_eq!(
        audit_event_category("mfa_step_up_success"),
        Some("authentication")
    );
}

#[test]
fn audit_schema_version_is_stable_for_collectors() {
    assert_eq!(AUDIT_SCHEMA_VERSION, "nazo.audit.v1");
}
