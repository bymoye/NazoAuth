use nazo_auth::{
    DynamicClientRegistrationRequest, DynamicRegistrationPolicy,
    prepare_dynamic_client_registration,
};

const POLICY: DynamicRegistrationPolicy<'_> = DynamicRegistrationPolicy {
    default_audience: "resource://default",
    pairwise_subject_supported: true,
    id_token_signing_algs: &["RS256", "PS256"],
    response_signing_algs: &["RS256", "PS256"],
    request_object_encryption_algs: &["RSA-OAEP-256"],
    request_object_encryption_encs: &["A256GCM"],
};

fn ciba_request(mode: &str) -> DynamicClientRegistrationRequest {
    DynamicClientRegistrationRequest {
        grant_types: Some(vec!["urn:openid:params:grant-type:ciba".to_owned()]),
        token_endpoint_auth_method: Some("private_key_jwt".to_owned()),
        backchannel_token_delivery_mode: Some(mode.to_owned()),
        backchannel_client_notification_endpoint: (mode == "ping")
            .then(|| "https://client.example/ciba-notification".to_owned()),
        backchannel_authentication_request_signing_alg: Some("PS256".to_owned()),
        backchannel_user_code_parameter: Some(false),
        ..DynamicClientRegistrationRequest::default()
    }
}

#[test]
fn poll_and_ping_are_the_only_registered_delivery_modes() {
    for mode in ["poll", "ping"] {
        let prepared = prepare_dynamic_client_registration(ciba_request(mode), POLICY).unwrap();
        assert_eq!(prepared.backchannel_token_delivery_mode, mode);
    }
    let error = prepare_dynamic_client_registration(ciba_request("push"), POLICY).unwrap_err();
    assert_eq!(error.error, "invalid_client_metadata");
    assert!(error.description.contains("push is not supported"));
}

#[test]
fn ping_requires_an_https_notification_endpoint_and_ciba_grant() {
    let mut missing = ciba_request("ping");
    missing.backchannel_client_notification_endpoint = None;
    assert!(prepare_dynamic_client_registration(missing, POLICY).is_err());

    let mut insecure = ciba_request("ping");
    insecure.backchannel_client_notification_endpoint =
        Some("http://client.example/ciba-notification".to_owned());
    assert!(prepare_dynamic_client_registration(insecure, POLICY).is_err());

    let mut without_ciba = ciba_request("ping");
    without_ciba.grant_types = Some(vec!["authorization_code".to_owned()]);
    assert!(prepare_dynamic_client_registration(without_ciba, POLICY).is_err());
}

#[test]
fn ciba_user_code_and_weak_request_signing_are_not_supported() {
    let mut user_code = ciba_request("poll");
    user_code.backchannel_user_code_parameter = Some(true);
    assert!(prepare_dynamic_client_registration(user_code, POLICY).is_err());

    let mut none_alg = ciba_request("poll");
    none_alg.backchannel_authentication_request_signing_alg = Some("none".to_owned());
    assert!(prepare_dynamic_client_registration(none_alg, POLICY).is_err());
}
