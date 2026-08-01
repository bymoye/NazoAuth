use nazo_auth::{
    DynamicClientRegistrationRequest, DynamicRegistrationPolicy,
    prepare_dynamic_client_registration,
};

const POLICY: DynamicRegistrationPolicy<'static> = DynamicRegistrationPolicy {
    default_audience: "https://api.example",
    pairwise_subject_supported: true,
    id_token_signing_algs: &["RS256", "PS256"],
    response_signing_algs: &["RS256", "PS256"],
    request_object_encryption_algs: &["RSA-OAEP-256"],
    request_object_encryption_encs: &["A256GCM"],
};

#[test]
fn dynamic_registration_preserves_https_presentation_metadata() {
    let prepared = prepare_dynamic_client_registration(
        DynamicClientRegistrationRequest {
            logo_uri: Some("https://client.example/logo.svg".to_owned()),
            policy_uri: Some("https://client.example/privacy".to_owned()),
            tos_uri: Some("https://client.example/terms".to_owned()),
            ..DynamicClientRegistrationRequest::default()
        },
        POLICY,
    )
    .expect("HTTPS presentation metadata should be accepted");

    assert_eq!(
        prepared.presentation.logo_uri.as_deref(),
        Some("https://client.example/logo.svg")
    );
    assert_eq!(
        prepared.presentation.policy_uri.as_deref(),
        Some("https://client.example/privacy")
    );
    assert_eq!(
        prepared.presentation.tos_uri.as_deref(),
        Some("https://client.example/terms")
    );
}

#[test]
fn dynamic_registration_rejects_unsafe_presentation_metadata() {
    for request in [
        DynamicClientRegistrationRequest {
            logo_uri: Some("http://client.example/logo.svg".to_owned()),
            ..DynamicClientRegistrationRequest::default()
        },
        DynamicClientRegistrationRequest {
            policy_uri: Some("https://user@client.example/privacy".to_owned()),
            ..DynamicClientRegistrationRequest::default()
        },
        DynamicClientRegistrationRequest {
            tos_uri: Some("https://client.example/terms#fragment".to_owned()),
            ..DynamicClientRegistrationRequest::default()
        },
    ] {
        let error = prepare_dynamic_client_registration(request, POLICY)
            .expect_err("unsafe presentation metadata must fail closed");
        assert_eq!(error.error, "invalid_client_metadata");
    }
}
