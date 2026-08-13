use super::*;
use crate::ValidatedClientRegistration;
use serde_json::json;
use uuid::Uuid;

const POLICY: DynamicRegistrationPolicy<'static> = DynamicRegistrationPolicy {
    default_audience: "https://api.example",
    pairwise_subject_supported: true,
    id_token_signing_algs: &["RS256", "PS256"],
    response_signing_algs: &["RS256", "PS256"],
    request_object_encryption_algs: &["RSA-OAEP-256"],
    request_object_encryption_encs: &["A256GCM"],
};

#[test]
fn default_registration_contract_matches_oidc_code_client_behavior() {
    let prepared =
        prepare_dynamic_client_registration(DynamicClientRegistrationRequest::default(), POLICY)
            .expect("default registration");
    assert_eq!(prepared.client_type, "confidential");
    assert_eq!(
        prepared.grant_types,
        ["authorization_code", "refresh_token"]
    );
    assert_eq!(prepared.response_types, ["code"]);
    assert_eq!(
        prepared.scopes,
        [
            "openid",
            "profile",
            "email",
            "address",
            "phone",
            "offline_access"
        ]
    );
    assert!(!prepared.backchannel_logout_session_required);
    assert!(!prepared.frontchannel_logout_session_required);
}

#[test]
fn software_statement_and_response_type_errors_keep_rfc_codes() {
    for (request, expected) in [
        (
            DynamicClientRegistrationRequest {
                software_statement: Some("statement".to_owned()),
                ..Default::default()
            },
            "invalid_software_statement",
        ),
        (
            DynamicClientRegistrationRequest {
                response_types: Some(vec!["token".to_owned()]),
                ..Default::default()
            },
            "invalid_client_metadata",
        ),
    ] {
        assert_eq!(
            prepare_dynamic_client_registration(request, POLICY)
                .expect_err("invalid metadata")
                .error,
            expected
        );
    }
}

#[test]
fn external_request_uri_registration_is_validated_and_preserved() {
    let prepared = prepare_dynamic_client_registration(
        DynamicClientRegistrationRequest {
            request_uris: Some(vec!["https://client.example/request.jwt".to_owned()]),
            client_name: Some("  Example Client  ".to_owned()),
            ..Default::default()
        },
        POLICY,
    )
    .expect("registered HTTPS request_uri should be accepted");
    assert_eq!(
        prepared.request_uris,
        vec!["https://client.example/request.jwt"]
    );
}

#[test]
fn third_party_initiated_login_uri_requires_https_and_is_preserved() {
    let prepared = prepare_dynamic_client_registration(
        DynamicClientRegistrationRequest {
            initiate_login_uri: Some("https://client.example/login/initiate".to_owned()),
            ..Default::default()
        },
        POLICY,
    )
    .expect("HTTPS initiate_login_uri should be accepted");
    assert_eq!(
        prepared.initiate_login_uri.as_deref(),
        Some("https://client.example/login/initiate")
    );

    let error = prepare_dynamic_client_registration(
        DynamicClientRegistrationRequest {
            initiate_login_uri: Some("http://client.example/login/initiate".to_owned()),
            ..Default::default()
        },
        POLICY,
    )
    .expect_err("non-HTTPS initiate_login_uri must be rejected");
    assert_eq!(error.error, "invalid_client_metadata");
}

#[test]
fn configuration_update_rejects_server_fields_and_requires_matching_credentials() {
    let client = client();
    let managed = parse_client_configuration_update(
        json!({
            "client_id": "client",
            "registration_access_token": "replacement"
        }),
        &client,
        false,
        false,
    )
    .expect_err("server-managed fields must be rejected");
    assert_eq!(managed.error, "invalid_request");

    let wrong_secret = parse_client_configuration_update(
        json!({"client_id": "client", "client_secret": "wrong"}),
        &client,
        true,
        false,
    )
    .expect_err("secret must match");
    assert_eq!(wrong_secret.error, "invalid_client_metadata");

    let update = parse_client_configuration_update(
        json!({
            "client_id": "client",
            "client_secret": "verified-by-adapter",
            "client_name": "Updated"
        }),
        &client,
        true,
        true,
    )
    .expect("authenticated update");
    assert_eq!(update.client_name.as_deref(), Some("Updated"));
}

#[test]
fn configuration_update_rejects_invalid_shapes_and_public_secrets() {
    let client = client();

    for payload in [json!(null), json!([])] {
        let error = parse_client_configuration_update(payload, &client, false, false)
            .expect_err("configuration updates must be JSON objects");
        assert_eq!(error.error, "invalid_request");
    }

    let missing_client_id = parse_client_configuration_update(
        json!({"client_name": "missing-id"}),
        &client,
        false,
        false,
    )
    .expect_err("client_id is required");
    assert_eq!(missing_client_id.error, "invalid_client_metadata");

    let wrong_client_id = parse_client_configuration_update(
        json!({"client_id": "another-client"}),
        &client,
        false,
        false,
    )
    .expect_err("client_id must match the endpoint");
    assert_eq!(wrong_client_id.error, "invalid_client_metadata");

    let public_secret = parse_client_configuration_update(
        json!({"client_id": "client", "client_secret": "unexpected"}),
        &client,
        false,
        false,
    )
    .expect_err("public clients must not submit a client secret");
    assert_eq!(public_secret.error, "invalid_client_metadata");

    let malformed_metadata = parse_client_configuration_update(
        json!({"client_id": "client", "redirect_uris": 42}),
        &client,
        false,
        false,
    )
    .expect_err("invalid metadata types must be rejected");
    assert_eq!(malformed_metadata.error, "invalid_client_metadata");

    let public_update = parse_client_configuration_update(
        json!({"client_id": "client", "client_name": "Public update"}),
        &client,
        false,
        false,
    )
    .expect("public clients may update ordinary metadata");
    assert_eq!(public_update.client_name.as_deref(), Some("Public update"));

    let mut non_code_client = client;
    non_code_client.grant_types = vec!["client_credentials".to_owned()];
    assert!(response_types_from_client(&non_code_client).is_empty());
}

#[test]
fn public_and_confidential_code_clients_share_one_registration_path() {
    for (token_endpoint_auth_method, expected_type) in
        [("none", "public"), ("client_secret_basic", "confidential")]
    {
        let prepared = prepare_dynamic_client_registration(
            DynamicClientRegistrationRequest {
                token_endpoint_auth_method: Some(token_endpoint_auth_method.to_owned()),
                redirect_uris: Some(vec!["https://client.example/cb".to_owned()]),
                ..Default::default()
            },
            POLICY,
        )
        .expect("registration")
        .into_create_client_request();
        assert_eq!(prepared.client_type, expected_type);
    }
}

#[test]
fn private_key_jwt_registration_enables_standard_oidc_token_endpoint_audience() {
    let private_key_jwt = prepare_dynamic_client_registration(
        DynamicClientRegistrationRequest {
            token_endpoint_auth_method: Some("private_key_jwt".to_owned()),
            redirect_uris: Some(vec!["https://client.example/cb".to_owned()]),
            ..Default::default()
        },
        POLICY,
    )
    .expect("private_key_jwt registration")
    .into_create_client_request();
    assert!(private_key_jwt.allow_client_assertion_endpoint_audience);

    let client_secret_basic = prepare_dynamic_client_registration(
        DynamicClientRegistrationRequest {
            token_endpoint_auth_method: Some("client_secret_basic".to_owned()),
            redirect_uris: Some(vec!["https://client.example/cb".to_owned()]),
            ..Default::default()
        },
        POLICY,
    )
    .expect("client_secret_basic registration")
    .into_create_client_request();
    assert!(!client_secret_basic.allow_client_assertion_endpoint_audience);
}

#[test]
fn rp_metadata_choices_select_supported_single_values_and_reject_inconsistency() {
    let prepared = prepare_dynamic_client_registration(
        DynamicClientRegistrationRequest {
            redirect_uris: Some(vec!["https://client.example/cb".to_owned()]),
            grant_types: Some(vec![
                "authorization_code".to_owned(),
                "urn:openid:params:grant-type:ciba".to_owned(),
            ]),
            token_endpoint_auth_method: Some("client_secret_post".to_owned()),
            token_endpoint_auth_methods_supported: Some(vec![
                "unsupported".to_owned(),
                "private_key_jwt".to_owned(),
                "client_secret_post".to_owned(),
            ]),
            subject_types_supported: Some(vec!["pairwise".to_owned(), "public".to_owned()]),
            id_token_signing_alg_values_supported: Some(vec![
                "EdDSA".to_owned(),
                "PS256".to_owned(),
            ]),
            id_token_encryption_alg_values_supported: Some(vec!["RSA-OAEP-256".to_owned()]),
            id_token_encryption_enc_values_supported: Some(vec!["A256GCM".to_owned()]),
            request_object_signing_alg_values_supported: Some(vec![
                "HS256".to_owned(),
                "ES256".to_owned(),
            ]),
            request_object_encryption_alg_values_supported: Some(vec!["RSA-OAEP-256".to_owned()]),
            request_object_encryption_enc_values_supported: Some(vec!["A256GCM".to_owned()]),
            token_endpoint_auth_signing_alg_values_supported: Some(vec![
                "HS256".to_owned(),
                "PS256".to_owned(),
            ]),
            userinfo_signing_alg_values_supported: Some(vec![
                "HS256".to_owned(),
                "ES256".to_owned(),
            ]),
            userinfo_encryption_alg_values_supported: Some(vec![
                "unsupported".to_owned(),
                "ECDH-ES+A256KW".to_owned(),
            ]),
            userinfo_encryption_enc_values_supported: Some(vec!["A256GCM".to_owned()]),
            backchannel_authentication_request_signing_alg_values_supported: Some(vec![
                "RS256".to_owned(),
                "PS256".to_owned(),
            ]),
            authorization_signing_alg_values_supported: Some(vec![
                "HS256".to_owned(),
                "EdDSA".to_owned(),
            ]),
            authorization_encryption_alg_values_supported: Some(vec![
                "unsupported".to_owned(),
                "ECDH-ES".to_owned(),
            ]),
            authorization_encryption_enc_values_supported: Some(vec!["A256GCM".to_owned()]),
            introspection_encryption_alg_values_supported: Some(vec![
                "unsupported".to_owned(),
                "ECDH-ES".to_owned(),
            ]),
            introspection_encryption_enc_values_supported: Some(vec!["A256GCM".to_owned()]),
            introspection_signing_alg_values_supported: Some(vec![
                "EdDSA".to_owned(),
                "RS256".to_owned(),
            ]),
            jwks: Some(serde_json::json!({"keys": []})),
            ..Default::default()
        },
        POLICY,
    )
    .expect("supported choices");
    assert_eq!(prepared.token_endpoint_auth_method, "private_key_jwt");
    assert_eq!(prepared.subject_type.as_deref(), Some("pairwise"));
    assert_eq!(
        prepared.id_token_signed_response_alg.as_deref(),
        Some("PS256")
    );
    assert_eq!(
        prepared.id_token_encrypted_response_alg.as_deref(),
        Some("RSA-OAEP-256")
    );
    assert_eq!(
        prepared.id_token_encrypted_response_enc.as_deref(),
        Some("A256GCM")
    );
    assert_eq!(
        prepared.request_object_signing_alg.as_deref(),
        Some("ES256")
    );
    assert_eq!(
        prepared.request_object_encryption_alg.as_deref(),
        Some("RSA-OAEP-256")
    );
    assert_eq!(
        prepared.request_object_encryption_enc.as_deref(),
        Some("A256GCM")
    );
    assert_eq!(
        prepared.token_endpoint_auth_signing_alg.as_deref(),
        Some("PS256")
    );
    assert_eq!(
        prepared.introspection_signed_response_alg.as_deref(),
        Some("RS256")
    );
    assert_eq!(
        prepared.userinfo_signed_response_alg.as_deref(),
        Some("ES256")
    );
    assert_eq!(
        prepared.userinfo_encrypted_response_alg.as_deref(),
        Some("ECDH-ES+A256KW")
    );
    assert_eq!(
        prepared.userinfo_encrypted_response_enc.as_deref(),
        Some("A256GCM")
    );
    assert_eq!(
        prepared
            .backchannel_authentication_request_signing_alg
            .as_deref(),
        Some("PS256")
    );
    assert_eq!(
        prepared.authorization_signed_response_alg.as_deref(),
        Some("EdDSA")
    );
    assert_eq!(
        prepared.authorization_encrypted_response_alg.as_deref(),
        Some("ECDH-ES")
    );
    assert_eq!(
        prepared.authorization_encrypted_response_enc.as_deref(),
        Some("A256GCM")
    );
    assert_eq!(
        prepared.introspection_encrypted_response_alg.as_deref(),
        Some("ECDH-ES")
    );

    let public_only = prepare_dynamic_client_registration(
        DynamicClientRegistrationRequest {
            redirect_uris: Some(vec!["https://client.example/cb".to_owned()]),
            subject_types_supported: Some(vec!["pairwise".to_owned(), "public".to_owned()]),
            ..Default::default()
        },
        DynamicRegistrationPolicy {
            default_audience: "https://api.example",
            pairwise_subject_supported: false,
            id_token_signing_algs: &["RS256", "PS256"],
            response_signing_algs: &["RS256", "PS256"],
            request_object_encryption_algs: &["RSA-OAEP-256"],
            request_object_encryption_encs: &["A256GCM"],
        },
    )
    .expect("public is selected when pairwise subject state is unavailable");
    assert_eq!(public_only.subject_type.as_deref(), Some("public"));

    let error = prepare_dynamic_client_registration(
        DynamicClientRegistrationRequest {
            redirect_uris: Some(vec!["https://client.example/cb".to_owned()]),
            subject_type: Some("public".to_owned()),
            subject_types_supported: Some(vec!["pairwise".to_owned()]),
            ..Default::default()
        },
        POLICY,
    )
    .expect_err("single value must be one of the declared choices");
    assert_eq!(error.error, "invalid_client_metadata");
}

#[test]
fn every_rp_metadata_choice_fails_closed_when_no_server_value_is_supported() {
    macro_rules! assert_unsupported_choices_are_rejected {
        ($field:ident) => {{
            let mut request = DynamicClientRegistrationRequest {
                redirect_uris: Some(vec!["https://client.example/cb".to_owned()]),
                ..Default::default()
            };
            request.$field = Some(vec!["unsupported".to_owned()]);
            let error = prepare_dynamic_client_registration(request, POLICY)
                .expect_err(concat!(stringify!($field), " must fail closed"));
            assert_eq!(error.error, "invalid_client_metadata");
            assert!(error.description.contains("No supported"));
        }};
    }

    assert_unsupported_choices_are_rejected!(token_endpoint_auth_methods_supported);
    assert_unsupported_choices_are_rejected!(id_token_signing_alg_values_supported);
    assert_unsupported_choices_are_rejected!(id_token_encryption_alg_values_supported);
    assert_unsupported_choices_are_rejected!(id_token_encryption_enc_values_supported);
    assert_unsupported_choices_are_rejected!(request_object_signing_alg_values_supported);
    assert_unsupported_choices_are_rejected!(request_object_encryption_alg_values_supported);
    assert_unsupported_choices_are_rejected!(request_object_encryption_enc_values_supported);
    assert_unsupported_choices_are_rejected!(token_endpoint_auth_signing_alg_values_supported);
    assert_unsupported_choices_are_rejected!(
        backchannel_authentication_request_signing_alg_values_supported
    );
    assert_unsupported_choices_are_rejected!(userinfo_signing_alg_values_supported);
    assert_unsupported_choices_are_rejected!(userinfo_encryption_alg_values_supported);
    assert_unsupported_choices_are_rejected!(userinfo_encryption_enc_values_supported);
    assert_unsupported_choices_are_rejected!(authorization_signing_alg_values_supported);
    assert_unsupported_choices_are_rejected!(authorization_encryption_alg_values_supported);
    assert_unsupported_choices_are_rejected!(authorization_encryption_enc_values_supported);
    assert_unsupported_choices_are_rejected!(introspection_encryption_alg_values_supported);
    assert_unsupported_choices_are_rejected!(introspection_encryption_enc_values_supported);
    assert_unsupported_choices_are_rejected!(introspection_signing_alg_values_supported);
}

#[test]
fn rp_metadata_choice_lists_reject_empty_values() {
    for choices in [Vec::new(), vec![" ".to_owned()]] {
        let error = negotiate_metadata_choice("subject_type", None, Some(choices), &["public"])
            .expect_err("empty choice lists must fail closed");
        assert_eq!(error.error, "invalid_client_metadata");
        assert!(error.description.contains("non-empty"));
    }
}

fn client() -> OAuthClient {
    OAuthClient {
        id: Uuid::now_v7(),
        tenant_id: Uuid::nil(),
        realm_id: Uuid::nil(),
        organization_id: Uuid::nil(),
        registration: ValidatedClientRegistration {
            client_id: "client".to_owned(),
            client_name: "Client".to_owned(),
            client_type: "confidential".to_owned(),
            redirect_uris: vec!["https://client.example/cb".to_owned()],
            post_logout_redirect_uris: Vec::new(),
            scopes: vec!["openid".to_owned()],
            allowed_audiences: vec!["https://api.example".to_owned()],
            grant_types: vec!["authorization_code".to_owned()],
            token_endpoint_auth_method: "client_secret_basic".to_owned(),
            subject_type: "public".to_owned(),
            sector_identifier_uri: None,
            sector_identifier_host: None,
            require_dpop_bound_tokens: false,
            allow_client_assertion_audience_array: false,
            allow_client_assertion_endpoint_audience: false,
            require_par_request_object: false,
            backchannel_logout_uri: None,
            backchannel_logout_session_required: false,
            backchannel_token_delivery_mode: "poll".to_owned(),
            backchannel_client_notification_endpoint: None,
            backchannel_authentication_request_signing_alg: None,
            backchannel_user_code_parameter: false,
            frontchannel_logout_uri: None,
            frontchannel_logout_session_required: false,
            tls_client_auth_subject_dn: None,
            tls_client_auth_cert_sha256: None,
            tls_client_auth_san_dns: Vec::new(),
            tls_client_auth_san_uri: Vec::new(),
            tls_client_auth_san_ip: Vec::new(),
            tls_client_auth_san_email: Vec::new(),
            jwks_uri: None,
            jwks: None,
            request_uris: Vec::new(),
            initiate_login_uri: None,
            presentation: ClientPresentationMetadata::default(),
            id_token_signed_response_alg: None,
            id_token_encrypted_response_alg: None,
            id_token_encrypted_response_enc: None,
            request_object_signing_alg: None,
            request_object_encryption_alg: None,
            request_object_encryption_enc: None,
            token_endpoint_auth_signing_alg: None,
            introspection_signed_response_alg: None,
            introspection_encrypted_response_alg: None,
            introspection_encrypted_response_enc: None,
            userinfo_signed_response_alg: None,
            userinfo_encrypted_response_alg: None,
            userinfo_encrypted_response_enc: None,
            authorization_signed_response_alg: None,
            authorization_encrypted_response_alg: None,
            authorization_encrypted_response_enc: None,
            security_policy: None,
        },
        require_mtls_bound_tokens: false,
        is_active: true,
    }
}
