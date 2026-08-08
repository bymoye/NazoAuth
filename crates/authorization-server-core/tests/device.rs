use chrono::{Duration, TimeZone, Utc};
use nazo_auth::{
    DeviceAuthorizationApproval, DeviceAuthorizationPayload, DeviceAuthorizationRequestError,
    DeviceAuthorizationRequestPolicy, DeviceAuthorizationState, DevicePollTransition,
    device_authorization_payload, device_authorization_request_payload, evaluate_device_poll,
};
use serde_json::json;
use uuid::Uuid;

fn payload(now: chrono::DateTime<Utc>) -> DeviceAuthorizationPayload {
    DeviceAuthorizationPayload {
        client_id: "device-client".to_owned(),
        client_name: "Device client".to_owned(),
        scopes: vec!["openid".to_owned(), "read".to_owned()],
        resource_indicators: vec!["resource://api".to_owned()],
        authorization_details: json!([]),
        interval_seconds: 10,
        issued_at: now,
        expires_at: now + Duration::minutes(10),
    }
}

fn approval() -> DeviceAuthorizationApproval {
    DeviceAuthorizationApproval {
        user_id: Uuid::from_u128(1),
        subject: "subject-1".to_owned(),
        auth_time: 1_700_000_000,
        amr: vec!["pwd".to_owned()],
        oidc_sid: Some("sid-1".to_owned()),
    }
}

fn request_policy<'a>(
    now: chrono::DateTime<Utc>,
    requested_scopes: Vec<String>,
    allowed_scopes: &'a [String],
    requested_resources: Vec<String>,
    allowed_resources: &'a [String],
) -> DeviceAuthorizationRequestPolicy<'a> {
    DeviceAuthorizationRequestPolicy {
        enabled: true,
        client_active: true,
        client_supports_grant: true,
        client_id: "device-client",
        client_name: "Device client",
        requested_scopes,
        allowed_scopes,
        requested_resources,
        allowed_resources,
        default_resource: "resource://api",
        interval_seconds: 10,
        ttl_seconds: 600,
        now,
    }
}

#[test]
fn device_authorization_policy_fails_closed_at_each_admission_boundary() {
    let now = Utc.timestamp_opt(1_700_000_000, 0).single().unwrap();
    let scopes = vec!["openid".to_owned(), "read".to_owned()];
    let resources = vec!["resource://api".to_owned()];

    let mut disabled = request_policy(
        now,
        vec!["openid".to_owned()],
        &scopes,
        Vec::new(),
        &resources,
    );
    disabled.enabled = false;
    assert_eq!(
        device_authorization_request_payload(disabled),
        Err(DeviceAuthorizationRequestError::Disabled)
    );

    let mut inactive = request_policy(
        now,
        vec!["openid".to_owned()],
        &scopes,
        Vec::new(),
        &resources,
    );
    inactive.client_active = false;
    assert_eq!(
        device_authorization_request_payload(inactive),
        Err(DeviceAuthorizationRequestError::UnauthorizedClient)
    );

    let mut unsupported_grant = request_policy(
        now,
        vec!["openid".to_owned()],
        &scopes,
        Vec::new(),
        &resources,
    );
    unsupported_grant.client_supports_grant = false;
    assert_eq!(
        device_authorization_request_payload(unsupported_grant),
        Err(DeviceAuthorizationRequestError::UnauthorizedClient)
    );

    let invalid_scope = request_policy(
        now,
        vec!["openid".to_owned(), "admin".to_owned()],
        &scopes,
        Vec::new(),
        &resources,
    );
    assert_eq!(
        device_authorization_request_payload(invalid_scope),
        Err(DeviceAuthorizationRequestError::InvalidScope)
    );

    let invalid_resource = request_policy(
        now,
        vec!["openid".to_owned()],
        &scopes,
        vec!["resource://other".to_owned()],
        &resources,
    );
    assert_eq!(
        device_authorization_request_payload(invalid_resource),
        Err(DeviceAuthorizationRequestError::InvalidTarget)
    );
}

#[test]
fn device_authorization_policy_defaults_resource_and_binds_expiry() {
    let now = Utc.timestamp_opt(1_700_000_000, 0).single().unwrap();
    let scopes = vec!["openid".to_owned(), "read".to_owned()];
    let resources = vec!["resource://api".to_owned()];
    let result = device_authorization_request_payload(request_policy(
        now,
        vec!["openid".to_owned(), "read".to_owned()],
        &scopes,
        Vec::new(),
        &resources,
    ))
    .expect("valid device request should produce a payload");

    assert_eq!(result.client_id, "device-client");
    assert_eq!(result.scopes, vec!["openid", "read"]);
    assert_eq!(result.resource_indicators, resources);
    assert_eq!(result.authorization_details, json!([]));
    assert_eq!(result.interval_seconds, 10);
    assert_eq!(result.issued_at, now);
    assert_eq!(result.expires_at, now + Duration::seconds(600));
}

#[test]
fn device_poll_state_machine_preserves_terminal_and_slow_down_contracts() {
    let now = Utc.timestamp_opt(1_700_000_000, 0).single().unwrap();
    let payload = payload(now);
    let approval = approval();

    let first_poll = DeviceAuthorizationState::Pending {
        payload: payload.clone(),
        last_poll_at: None,
        slow_down_count: 0,
    };
    let DevicePollTransition::AuthorizationPending(next) = evaluate_device_poll(&first_poll, now)
    else {
        panic!("first poll should remain pending without slowing down");
    };
    assert!(matches!(next, DeviceAuthorizationState::Pending {
        last_poll_at: Some(value),
        slow_down_count: 0,
        ..
    } if value == now));

    let too_early = DeviceAuthorizationState::Pending {
        payload: payload.clone(),
        last_poll_at: Some(now - Duration::seconds(1)),
        slow_down_count: 0,
    };
    let DevicePollTransition::SlowDown(next) = evaluate_device_poll(&too_early, now) else {
        panic!("polling before the interval must slow the client down");
    };
    assert!(matches!(next, DeviceAuthorizationState::Pending {
        slow_down_count: 1,
        last_poll_at: Some(value),
        ..
    } if value == now));

    let approving = DeviceAuthorizationState::Approving {
        payload: payload.clone(),
        approval: approval.clone(),
        claim_id: Uuid::from_u128(2),
        grant_recorded: true,
        started_at: now,
    };
    assert_eq!(
        evaluate_device_poll(&approving, now),
        DevicePollTransition::AuthorizationPendingUnchanged
    );

    let approved = DeviceAuthorizationState::Approved {
        payload: payload.clone(),
        approval: approval.clone(),
        approved_at: now,
    };
    assert_eq!(
        evaluate_device_poll(&approved, now),
        DevicePollTransition::Approved {
            payload: payload.clone(),
            approval: approval.clone()
        }
    );

    let denied = DeviceAuthorizationState::Denied {
        payload: payload.clone(),
        denied_at: now,
    };
    assert_eq!(
        evaluate_device_poll(&denied, now),
        DevicePollTransition::AccessDenied
    );

    let consumed = DeviceAuthorizationState::Consumed { consumed_at: now };
    assert_eq!(
        evaluate_device_poll(&consumed, now),
        DevicePollTransition::Consumed
    );
    assert_eq!(device_authorization_payload(&consumed), None);

    let expired = DeviceAuthorizationState::Pending {
        payload: DeviceAuthorizationPayload {
            expires_at: now,
            ..payload
        },
        last_poll_at: None,
        slow_down_count: 0,
    };
    assert_eq!(
        evaluate_device_poll(&expired, now),
        DevicePollTransition::Expired
    );
}
