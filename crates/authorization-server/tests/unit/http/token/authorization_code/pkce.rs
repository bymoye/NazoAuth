use super::*;

#[test]
fn baseline_confidential_oidc_compatibility_does_not_weaken_hardened_clients() {
    let mut client = pkce_policy_client();
    let mut payload = code_payload(false);
    payload.code_challenge = None;
    payload.code_challenge_method = None;
    payload.nonce = Some("per-transaction-nonce".to_owned());

    assert!(!authorization_code_requires_pkce(&client, &payload));

    payload.nonce = None;
    assert!(!authorization_code_requires_pkce(&client, &payload));
    payload.nonce = Some("per-transaction-nonce".to_owned());

    client.client_type = "public".to_owned();
    assert!(authorization_code_requires_pkce(&client, &payload));

    client.client_type = "confidential".to_owned();
    client.require_dpop_bound_tokens = true;
    assert!(authorization_code_requires_pkce(&client, &payload));

    client.require_dpop_bound_tokens = false;
    client.require_mtls_bound_tokens = true;
    assert!(authorization_code_requires_pkce(&client, &payload));

    client.require_mtls_bound_tokens = false;
    let mut holder_bound_payload = code_payload(false);
    holder_bound_payload.dpop_jkt = Some("thumbprint".to_owned());
    assert!(authorization_code_requires_pkce(
        &client,
        &holder_bound_payload
    ));

    holder_bound_payload.dpop_jkt = None;
    holder_bound_payload.mtls_x5t_s256 = Some("thumbprint".to_owned());
    assert!(authorization_code_requires_pkce(
        &client,
        &holder_bound_payload
    ));

    holder_bound_payload.mtls_x5t_s256 = None;
    holder_bound_payload.scopes = vec!["accounts".to_owned()];
    assert!(authorization_code_requires_pkce(
        &client,
        &holder_bound_payload
    ));
}
