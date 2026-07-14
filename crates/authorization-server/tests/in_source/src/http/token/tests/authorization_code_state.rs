use super::*;

#[test]
fn consumed_authorization_code_transition_ok_returns_ok() {
    assert!(consumed_authorization_code_transition_result("ok").is_ok());
}

#[test]
fn consumed_authorization_code_transition_non_ok_returns_err() {
    for state in [
        "missing",
        "pending",
        "consumed",
        "failed",
        "busy",
        "malformed",
    ] {
        let error =
            consumed_authorization_code_transition_result(state).expect_err("expected error");
        assert!(
            error.to_string().contains(state),
            "error should mention the unexpected state, got: {error}"
        );
    }
}

#[test]
fn failed_authorization_code_transition_ok_missing_failed_consumed_ok() {
    for state in ["ok", "missing", "failed", "consumed"] {
        assert!(
            failed_authorization_code_transition_result(state).is_ok(),
            "failed marker should tolerate {state}"
        );
    }
}

#[test]
fn failed_authorization_code_transition_other_states_err() {
    for state in ["pending", "busy", "malformed"] {
        let error = failed_authorization_code_transition_result(state).expect_err("expected error");
        assert!(
            error.to_string().contains(state),
            "error should mention the unexpected state, got: {error}"
        );
    }
}

#[test]
fn consumed_authorization_code_ttl_uses_refresh_ttl_when_family_present() {
    assert_eq!(
        consumed_authorization_code_ttl_seconds(300, 2_592_000, Some(Uuid::now_v7())),
        2_592_000
    );
}

#[test]
fn consumed_authorization_code_ttl_uses_access_ttl_when_family_absent() {
    assert_eq!(
        consumed_authorization_code_ttl_seconds(300, 2_592_000, None),
        300
    );
}

#[test]
fn consumed_authorization_code_ttl_floor_is_one_second() {
    assert_eq!(
        consumed_authorization_code_ttl_seconds(0, 2_592_000, None),
        1
    );
    assert_eq!(
        consumed_authorization_code_ttl_seconds(300, -10, Some(Uuid::now_v7())),
        1
    );
}
