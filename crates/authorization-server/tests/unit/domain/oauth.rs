use super::*;
use serde_json::json;

fn code_payload_json(authorization_details: Value) -> Value {
    json!({
        "code_id": "code-1",
        "user_id": "018fd6c7-96f6-7c6a-b8aa-6c0b9c4c0d01",
        "client_id": "client-1",
        "redirect_uri": "https://client.example/callback",
        "redirect_uri_was_supplied": true,
        "scopes": ["openid", "offline_access"],
        "authorization_details": authorization_details,
        "nonce": null,
        "auth_time": 1780750000,
        "amr": ["password"],
        "issued_at": "2026-06-07T00:00:00Z",
        "expires_at": "2026-06-07T00:05:00Z"
    })
}

#[test]
fn code_payload_defaults_missing_authorization_details_to_empty_array() {
    let mut value = code_payload_json(json!([]));
    value
        .as_object_mut()
        .expect("payload should be an object")
        .remove("authorization_details");

    let payload: CodePayload =
        serde_json::from_value(value).expect("missing authorization_details should parse");

    assert_eq!(payload.authorization_details, json!([]));
}

#[test]
fn code_payload_normalizes_empty_internal_authorization_details_states() {
    for value in [Value::Null, json!({})] {
        let payload: CodePayload = serde_json::from_value(code_payload_json(value))
            .expect("empty internal authorization_details state should parse");

        assert_eq!(payload.authorization_details, json!([]));
    }
}

#[test]
fn code_payload_rejects_non_array_authorization_details() {
    let error = serde_json::from_value::<CodePayload>(code_payload_json(json!({
        "type": "account_information"
    })))
    .expect_err("non-empty object authorization_details should be rejected");

    assert!(error.to_string().contains("authorization_details"));
}

#[test]
fn authorization_code_state_survives_lua_empty_array_roundtrip_shape() {
    let raw = json!({
        "status": "pending",
        "payload": code_payload_json(json!({}))
    });

    let state: AuthorizationCodeState =
        serde_json::from_value(raw).expect("state with lua-shaped empty details should parse");
    let AuthorizationCodeState::Pending { payload } = state else {
        panic!("state should remain pending");
    };

    assert_eq!(payload.authorization_details, json!([]));
}
