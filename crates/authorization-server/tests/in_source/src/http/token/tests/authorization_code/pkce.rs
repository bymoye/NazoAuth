use super::*;

#[test]
fn authorization_code_pkce_policy_allows_only_explicit_confidential_compatibility() {
    let mut client = pkce_policy_client();
    let payload = code_payload(false);
    assert!(authorization_code_requires_pkce(&client, &payload));

    client.allow_authorization_code_without_pkce = true;
    assert!(!authorization_code_requires_pkce(&client, &payload));

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
}
