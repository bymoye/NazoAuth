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
fn audit_event_definitions_include_administrative_user_lifecycle() {
    for name in ["admin_user_created", "admin_user_updated"] {
        assert_eq!(audit_event_category(name), Some("administration"));
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
        "ciba_authorization_intent",
        "ciba_authorization_approved",
        "ciba_authorization_denied",
        "ciba_decision_intent",
    ] {
        assert_eq!(audit_event_category(name), Some("authorization"));
    }
}

#[test]
fn audit_event_definitions_include_device_authorization_lifecycle() {
    for name in [
        "device_authorization_started",
        "device_authorization_approved",
        "device_authorization_denied",
        "device_decision_intent",
    ] {
        assert_eq!(audit_event_category(name), Some("authorization"));
        assert!(prepare_event(name, serde_json::Map::new()).is_ok());
    }
}

#[test]
fn audit_event_definitions_include_authorization_decision_intent() {
    assert_eq!(
        audit_event_category("authorization_decision_intent"),
        Some("authorization")
    );
    assert!(prepare_event("authorization_decision_intent", serde_json::Map::new()).is_ok());
}

#[test]
fn audit_event_definitions_include_token_issuance_intent() {
    assert_eq!(
        audit_event_category("token_issuance_intent"),
        Some("token_lifecycle")
    );
    assert!(prepare_event("token_issuance_intent", serde_json::Map::new()).is_ok());
}

#[test]
fn audit_event_definitions_include_mfa_step_up() {
    assert_eq!(
        audit_event_category("mfa_step_up_success"),
        Some("authentication")
    );
}

#[test]
fn audit_event_definitions_include_trust_and_credential_control_planes() {
    for name in [
        "mtls_trust_anchor_requested",
        "mtls_trust_anchor_approved",
        "mtls_trust_anchor_rejected",
        "mtls_trust_anchor_revoked",
        "mtls_trust_bundle_exported",
    ] {
        assert_eq!(audit_event_category(name), Some("trust_lifecycle"));
    }
    for name in [
        "openid4vci_credential_dataset_updated",
        "openid4vci_credential_dataset_deleted",
    ] {
        assert_eq!(audit_event_category(name), Some("credential_lifecycle"));
    }
}

#[test]
fn audit_schema_version_is_stable_for_collectors() {
    assert_eq!(AUDIT_SCHEMA_VERSION, "nazo.audit.v1");
}

#[test]
fn prepare_event_normalizes_security_payload_and_rejects_unknown_or_oversized_events() {
    let queued = prepare_event(
        "login_success",
        audit_fields(&[
            ("user_id", json!("user-1")),
            ("access_token", json!("must-not-persist")),
        ]),
    )
    .expect("allowlisted audit event should be prepared");
    assert_eq!(queued.event_type, "login_success");
    assert_eq!(queued.event_category, "authentication");
    assert_eq!(
        queued.payload["schema_version"],
        json!(AUDIT_SCHEMA_VERSION)
    );
    assert_eq!(queued.payload["event_category"], json!("authentication"));
    assert!(queued.payload.get("access_token").is_none());

    assert!(matches!(
        prepare_event("unknown_event", serde_json::Map::new()),
        Err("unknown_event_type")
    ));
    let oversized = audit_fields(&[(
        "large",
        json!("x".repeat(nazo_postgres::MAX_SECURITY_AUDIT_PAYLOAD_BYTES + 1)),
    )]);
    assert!(matches!(
        prepare_event("login_success", oversized),
        Err("payload_too_large")
    ));
}

#[test]
fn prepare_event_redacts_every_known_credential_from_intent_and_outcome_payloads() {
    let mut fields = audit_fields(&[("request_id_hash", json!("request-hash"))]);
    for key in SENSITIVE_FIELD_NAMES {
        fields.insert((*key).to_owned(), json!(format!("{key}-raw-secret")));
    }

    for event in [
        "authorization_decision_intent",
        "ciba_decision_intent",
        "device_decision_intent",
        "token_issuance_intent",
        "token_issued",
    ] {
        let queued = prepare_event(event, fields.clone())
            .expect("high-impact audit event should be allowlisted");
        let serialized = serde_json::to_string(&queued.payload).expect("payload should serialize");
        for key in SENSITIVE_FIELD_NAMES {
            assert!(
                queued.payload.get(*key).is_none(),
                "{event} must omit sensitive field {key}"
            );
            assert!(
                !serialized.contains(&format!("{key}-raw-secret")),
                "{event} must not serialize sensitive value {key}"
            );
        }
        assert_eq!(queued.payload["request_id_hash"], json!("request-hash"));
    }
}

fn assert_source_order(source: &str, earlier: &str, later: &str) {
    let earlier_offset = source
        .find(earlier)
        .unwrap_or_else(|| panic!("missing source marker {earlier}"));
    let later_offset = source
        .find(later)
        .unwrap_or_else(|| panic!("missing source marker {later}"));
    assert!(
        earlier_offset < later_offset,
        "source marker {earlier} must precede {later}"
    );
}

fn source_body<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
    source
        .split_once(start)
        .unwrap_or_else(|| panic!("missing source boundary {start}"))
        .1
        .split_once(end)
        .unwrap_or_else(|| panic!("missing source boundary {end}"))
        .0
}

#[test]
fn high_impact_state_changes_are_guarded_by_required_audit_intent() {
    // This is a source-level architecture guard for the fail-closed ordering
    // around mutations. Runtime audit serialization is exercised above; this
    // guard prevents a future refactor from moving the required intent behind
    // a state change without pretending to be a protocol E2E test.
    let authorization = include_str!("../../../src/domain/authorization_decision.rs");
    assert_source_order(
        authorization,
        "ensure_audit_storage().await",
        "audit_event_required(\n            \"authorization_decision_intent\"",
    );
    assert_source_order(
        authorization,
        "audit_event_required(\n            \"authorization_decision_intent\"",
        "admit_user_decision(",
    );
    assert!(authorization.contains("AuthorizationDecisionError::AuditUnavailable"));

    let device = include_str!("../../../src/http/token/device.rs");
    assert_source_order(
        device,
        "ensure_audit_storage().await",
        "audit_event_required(\n        \"device_decision_intent\"",
    );
    assert_source_order(
        device,
        "audit_event_required(\n        \"device_decision_intent\"",
        "let result = match form.decision.as_str()",
    );
    assert!(device.contains("设备授权审计无法持久化."));

    let ciba = include_str!("../../../src/http/token/ciba/decision.rs");
    let ciba_intent = source_body(
        ciba,
        "async fn prepare_ciba_decision_intent(",
        "async fn set_ciba_request_decision_with_lease(",
    );
    assert_source_order(
        ciba_intent,
        "ensure_audit_storage().await",
        "audit_event_required(\"ciba_decision_intent\"",
    );
    let ciba_automated = source_body(
        ciba,
        "pub(crate) async fn ciba_automated_decision(",
        "pub(super) fn ciba_automated_decision_auth_req_id(",
    );
    assert!(
        ciba_automated.contains("set_ciba_request_decision_with_lease("),
        "automated CIBA decisions must use the lease-guarded mutation path"
    );
    let ciba_browser = source_body(
        ciba,
        "pub(crate) async fn ciba_decision(",
        "async fn prepare_ciba_decision_intent(",
    );
    assert!(
        ciba_browser.contains("set_ciba_request_decision_with_lease("),
        "browser CIBA decisions must use the lease-guarded mutation path"
    );
    let ciba_lease = source_body(
        ciba,
        "async fn set_ciba_request_decision_with_lease(",
        "pub(super) fn complete_ciba_decision(",
    );
    assert_source_order(
        ciba_lease,
        "prepare_ciba_decision_intent(",
        ".with_active_ciba_decision(",
    );
    assert!(ciba.contains("CIBA decision audit could not be persisted."));

    let issuance = include_str!("../../../src/http/token/issue_grant.rs");
    assert_source_order(
        issuance,
        "ensure_audit_storage().await",
        "audit_event_required(\n        \"token_issuance_intent\"",
    );
    assert_source_order(
        issuance,
        "audit_event_required(\n        \"token_issuance_intent\"",
        "prepare_token_issuance(",
    );
    assert_source_order(
        issuance,
        "record_token_issuance_signed(",
        "audit_event_required(\n        \"token_issued\"",
    );
    assert_source_order(
        issuance,
        "PrepareTokenIssuanceResult::Existing(record)",
        "response_from_token_issuance(&record)",
    );
    assert!(issuance.contains("return response;"));
    assert!(issuance.contains("令牌签发审计无法持久化."));
}
