use nazo_auth::CreateClientRequest;
use serde_json::json;

#[test]
fn omitted_logout_session_requirements_follow_openid_connect_false_defaults() {
    let request: CreateClientRequest = serde_json::from_value(json!({
        "client_name": "Logout metadata default test",
        "client_type": "confidential",
        "redirect_uris": ["https://client.example/callback"],
        "scopes": ["openid"],
        "allowed_audiences": ["resource://default"],
        "grant_types": ["authorization_code"],
        "token_endpoint_auth_method": "client_secret_basic",
        "jwks": null
    }))
    .expect("minimal client metadata must deserialize");

    assert!(!request.frontchannel_logout_session_required);
    assert!(!request.backchannel_logout_session_required);
}

#[test]
fn explicit_logout_session_requirements_are_preserved() {
    let request: CreateClientRequest = serde_json::from_value(json!({
        "client_name": "Logout metadata opt-in test",
        "client_type": "confidential",
        "redirect_uris": ["https://client.example/callback"],
        "scopes": ["openid"],
        "allowed_audiences": ["resource://default"],
        "grant_types": ["authorization_code"],
        "token_endpoint_auth_method": "client_secret_basic",
        "frontchannel_logout_uri": "https://client.example/frontchannel-logout",
        "frontchannel_logout_session_required": true,
        "backchannel_logout_uri": "https://client.example/backchannel-logout",
        "backchannel_logout_session_required": true,
        "jwks": null
    }))
    .expect("explicit logout client metadata must deserialize");

    assert!(request.frontchannel_logout_session_required);
    assert!(request.backchannel_logout_session_required);
}
