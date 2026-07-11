use super::*;
use std::path::PathBuf;

use crate::domain::SUPPORTED_AUTHORIZATION_DETAILS_TYPES;
use crate::domain::VerificationKey;
use crate::settings::{
    AuthorizationServerProfile, DpopNoncePolicy, EmailDelivery, EmailSettings, RateLimitSettings,
    RequestObjectJtiPolicy, SubjectType,
};
use crate::support::{ClientIpHeaderMode, IpCidr};

fn keyset(alg: jsonwebtoken::Algorithm) -> Keyset {
    let alg_name = signing_algorithm_name(alg).expect("test alg should be supported");
    Keyset {
        active_kid: "active".to_owned(),
        active_alg: alg,
        active_signing_key: crate::domain::ActiveSigningKey::LocalPkcs8Der(Vec::new()),
        verification_keys: vec![VerificationKey {
            kid: "active".to_owned(),
            public_jwk: json!({"kty": "RSA", "kid": "active", "alg": alg_name, "use": "sig"}),
            local_signing_key: None,
        }],
    }
}

fn settings(profile: AuthorizationServerProfile, trusted_proxy_cidrs: Vec<IpCidr>) -> Settings {
    Settings {
        issuer: "https://issuer.example".to_owned(),
        mtls_endpoint_base_url: "https://mtls.issuer.example".to_owned(),
        frontend_base_url: "https://app.example".to_owned(),
        cors_allowed_origins: vec!["https://app.example".to_owned()],
        default_audience: "resource://default".to_owned(),
        protected_resource_identifier: "https://issuer.example/fapi/resource".to_owned(),
        authorization_server_profile: profile,
        ciba_security_profile:
            crate::settings::CibaSecurityProfile::FapiCibaId1PlainPrivateKeyJwtPoll,
        dpop_nonce_policy: DpopNoncePolicy::Required,
        request_object_jti_policy: RequestObjectJtiPolicy::Optional,
        session_cookie_name: "sid".to_owned(),
        csrf_cookie_name: "csrf".to_owned(),
        cookie_secure: true,
        session_ttl_seconds: 3600,
        auth_code_ttl_seconds: 60,
        access_token_ttl_seconds: 300,
        id_token_ttl_seconds: 600,
        refresh_token_ttl_seconds: 2_592_000,
        avatar_max_bytes: 2_097_152,
        client_delivery_ttl_seconds: 86_400,
        client_secret_pepper: "client-secret-pepper-for-tests-000000000001".to_owned(),
        rate_limit: RateLimitSettings {
            window_seconds: 60,
            auth_max_requests: 30,
            token_max_requests: 60,
            token_management_max_requests: 120,
            login_failure_window_seconds: 900,
            login_failure_email_max_attempts: 50,
            login_failure_ip_email_max_attempts: 5,
        },
        email: EmailSettings {
            delivery: EmailDelivery::Disabled,
            code_ttl_seconds: 900,
            send_cooldown_seconds: 60,
            send_peer_cooldown_seconds: 5,
        },
        email_code_dev_response_enabled: false,
        avatar_storage_dir: PathBuf::from("runtime/avatars"),
        jwk_keys_dir: PathBuf::from("runtime/keys"),
        signing_external_command: Vec::new(),
        signing_external_timeout_ms: 2_000,
        signing_key_rotation_interval_seconds: 7_776_000,
        signing_key_prepublish_seconds: 86_400,
        trusted_proxy_cidrs,
        client_ip_header_mode: ClientIpHeaderMode::None,
        subject_type: SubjectType::Public,
        pairwise_subject_secret: None,
        par_ttl_seconds: 90,
        require_pushed_authorization_requests: profile.requires_fapi2_security(),
        scim_bearer_token: None,
        passkey: crate::settings::PasskeySettings {
            rp_id: "issuer.example".to_owned(),
            rp_name: "Nazo OAuth".to_owned(),
            origin: "https://issuer.example".to_owned(),
            require_user_verification: true,
            require_user_handle: true,
            strict_base64: true,
        },
        federation: crate::settings::FederationSettings {
            providers: crate::settings::FederationProviderRegistry::default(),
            saml_gateway: None,
        },
        enable_request_object: false,
        enable_request_uri_parameter: false,
        enable_par_request_object: false,
        enable_authorization_details: false,
        enable_legacy_audience_param: false,
        enable_device_authorization_grant: false,
        enable_dynamic_client_registration: false,
        enable_frontchannel_logout: false,
        enable_session_management: false,
        enable_ciba: false,
        enable_native_sso: false,
        dynamic_client_registration_initial_access_token: None,
        device_authorization_ttl_seconds: 600,
        device_authorization_poll_interval_seconds: 5,
        ciba_auth_req_id_ttl_seconds: 600,
        ciba_poll_interval_seconds: 5,
        ciba_automated_decision_token: None,
    }
}

#[test]
fn discovery_prompt_values_match_authorization_request_parser() {
    assert_eq!(
        PROMPT_VALUES_SUPPORTED,
        ["login", "consent", "select_account", "none"]
    );
}

#[test]
fn discovery_advertises_supported_id_token_acr() {
    let metadata = authorization_server_metadata(
        &settings(AuthorizationServerProfile::Oauth2Baseline, Vec::new()),
        &keyset(jsonwebtoken::Algorithm::RS256),
    );

    assert!(CLAIMS_SUPPORTED.contains(&"acr"));
    assert_eq!(
        metadata
            .get("acr_values_supported")
            .and_then(Value::as_array)
            .expect("ACR value metadata should be present")
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>(),
        vec!["1"]
    );
}

#[test]
fn discovery_dpop_algorithms_match_authorization_server_validator() {
    let metadata = authorization_server_metadata(
        &settings(AuthorizationServerProfile::Oauth2Baseline, Vec::new()),
        &keyset(jsonwebtoken::Algorithm::RS256),
    );

    assert_eq!(
        metadata
            .get("dpop_signing_alg_values_supported")
            .and_then(Value::as_array)
            .expect("DPoP algorithm metadata should be present")
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>(),
        vec!["EdDSA", "ES256"]
    );
}

#[test]
fn discovery_advertises_supported_rar_types() {
    let mut s = settings(AuthorizationServerProfile::Oauth2Baseline, Vec::new());
    s.enable_authorization_details = true;
    let metadata = authorization_server_metadata(&s, &keyset(jsonwebtoken::Algorithm::RS256));

    assert_eq!(
        metadata
            .get("authorization_details_types_supported")
            .and_then(Value::as_array)
            .expect("RAR type metadata should be present")
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>(),
        SUPPORTED_AUTHORIZATION_DETAILS_TYPES
    );
}

#[test]
fn authorization_server_metadata_lists_configured_protected_resource() {
    let s = settings(AuthorizationServerProfile::Oauth2Baseline, Vec::new());
    let metadata = authorization_server_metadata(&s, &keyset(jsonwebtoken::Algorithm::RS256));

    assert_eq!(
        metadata
            .get("protected_resources")
            .and_then(Value::as_array)
            .expect("protected resource metadata should be present")
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>(),
        vec!["https://issuer.example/fapi/resource"]
    );
}

#[test]
fn protected_resource_metadata_matches_runtime_resource_boundary() {
    let metadata = protected_resource_metadata(
        &settings(AuthorizationServerProfile::Oauth2Baseline, Vec::new()),
        &keyset(jsonwebtoken::Algorithm::RS256),
    );

    assert_eq!(
        metadata.get("resource").and_then(Value::as_str),
        Some("https://issuer.example/fapi/resource")
    );
    assert_eq!(
        metadata
            .get("authorization_servers")
            .and_then(Value::as_array)
            .expect("authorization server list should be present")
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>(),
        vec!["https://issuer.example"]
    );
    assert_eq!(
        metadata
            .get("bearer_methods_supported")
            .and_then(Value::as_array)
            .expect("bearer token transport metadata should be present")
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>(),
        vec!["header", "body"]
    );
    assert_eq!(
        metadata
            .get("dpop_signing_alg_values_supported")
            .and_then(Value::as_array)
            .expect("DPoP metadata should be present")
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>(),
        vec!["EdDSA", "ES256"]
    );
    assert_eq!(
        metadata
            .get("scopes_supported")
            .and_then(Value::as_array)
            .expect("scope metadata should be present")
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>(),
        vec![
            "openid",
            "profile",
            "email",
            "address",
            "phone",
            "offline_access"
        ]
    );
    assert!(metadata.get("jwks_uri").is_none());
    assert!(
        metadata
            .get("tls_client_certificate_bound_access_tokens")
            .is_none()
    );
    assert!(
        metadata
            .get("authorization_details_types_supported")
            .is_none()
    );
    assert!(metadata.get("dpop_bound_access_tokens_required").is_none());
}

#[test]
fn protected_resource_metadata_reflects_mtls_and_rar_configuration() {
    let mut s = settings(
        AuthorizationServerProfile::Oauth2Baseline,
        vec![IpCidr::parse("192.0.2.0/24").unwrap()],
    );
    s.enable_authorization_details = true;
    let metadata = protected_resource_metadata(&s, &keyset(jsonwebtoken::Algorithm::RS256));

    assert_eq!(
        metadata
            .get("tls_client_certificate_bound_access_tokens")
            .and_then(Value::as_bool),
        Some(true)
    );
    assert_eq!(
        metadata
            .get("authorization_details_types_supported")
            .and_then(Value::as_array)
            .expect("RAR metadata should be present")
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>(),
        SUPPORTED_AUTHORIZATION_DETAILS_TYPES
    );
}

#[test]
fn discovery_subject_types_follow_pairwise_configuration() {
    let keyset = keyset(jsonwebtoken::Algorithm::RS256);

    let public_only = authorization_server_metadata(
        &settings(AuthorizationServerProfile::Oauth2Baseline, Vec::new()),
        &keyset,
    );
    assert_eq!(
        public_only
            .get("subject_types_supported")
            .and_then(Value::as_array)
            .expect("subject type metadata should be present")
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>(),
        vec!["public"]
    );

    let mut pairwise_default = settings(AuthorizationServerProfile::Oauth2Baseline, Vec::new());
    pairwise_default.pairwise_subject_secret = Some("01234567890123456789012345678901".to_owned());
    let pairwise_default = authorization_server_metadata(&pairwise_default, &keyset);
    assert_eq!(
        pairwise_default
            .get("subject_types_supported")
            .and_then(Value::as_array)
            .expect("subject type metadata should be present")
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>(),
        vec!["public", "pairwise"]
    );

    let mut pairwise_only = settings(AuthorizationServerProfile::Oauth2Baseline, Vec::new());
    pairwise_only.subject_type = SubjectType::Pairwise;
    pairwise_only.pairwise_subject_secret = Some("01234567890123456789012345678901".to_owned());
    let pairwise_only = authorization_server_metadata(&pairwise_only, &keyset);
    assert_eq!(
        pairwise_only
            .get("subject_types_supported")
            .and_then(Value::as_array)
            .expect("subject type metadata should be present")
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>(),
        vec!["pairwise"]
    );
}

#[test]
fn discovery_advertises_oidc_logout_endpoints_and_backchannel_support() {
    let metadata = authorization_server_metadata(
        &settings(AuthorizationServerProfile::Oauth2Baseline, Vec::new()),
        &keyset(jsonwebtoken::Algorithm::RS256),
    );

    assert_eq!(
        metadata.get("end_session_endpoint").and_then(Value::as_str),
        Some("https://issuer.example/logout")
    );
    assert_eq!(
        metadata
            .get("backchannel_logout_supported")
            .and_then(Value::as_bool),
        Some(true)
    );
    assert_eq!(
        metadata
            .get("backchannel_logout_session_supported")
            .and_then(Value::as_bool),
        Some(true)
    );
}

#[test]
fn discovery_does_not_advertise_unimplemented_protocol_extensions() {
    let metadata = authorization_server_metadata(
        &settings(
            AuthorizationServerProfile::Fapi2MessageSigningAuthzRequest,
            Vec::new(),
        ),
        &keyset(jsonwebtoken::Algorithm::PS256),
    );

    for field in [
        "device_authorization_endpoint",
        "introspection_signing_alg_values_supported",
        "introspection_encryption_alg_values_supported",
        "introspection_encryption_enc_values_supported",
        "frontchannel_logout_supported",
        "check_session_iframe",
    ] {
        assert!(
            metadata.get(field).is_none(),
            "{field} must not be advertised until the feature is implemented"
        );
    }

    let grant_types = metadata
        .get("grant_types_supported")
        .and_then(Value::as_array)
        .expect("grant type metadata should be present")
        .iter()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>();
    assert!(
        !grant_types.contains(&"urn:ietf:params:oauth:grant-type:device_code"),
        "device grant must not be advertised until it is enabled"
    );
    assert!(
        grant_types.contains(&"urn:ietf:params:oauth:grant-type:jwt-bearer"),
        "JWT bearer grant is implemented and must be advertised"
    );
    assert!(
        grant_types.contains(&"urn:ietf:params:oauth:grant-type:token-exchange"),
        "Token Exchange grant is implemented and must be advertised"
    );
}

#[test]
fn discovery_advertises_frontchannel_logout_only_when_enabled() {
    let keyset = keyset(jsonwebtoken::Algorithm::RS256);
    let disabled = authorization_server_metadata(
        &settings(AuthorizationServerProfile::Oauth2Baseline, Vec::new()),
        &keyset,
    );
    assert!(disabled.get("frontchannel_logout_supported").is_none());
    assert!(
        disabled
            .get("frontchannel_logout_session_supported")
            .is_none()
    );

    let mut enabled = settings(AuthorizationServerProfile::Oauth2Baseline, Vec::new());
    enabled.enable_frontchannel_logout = true;
    let metadata = authorization_server_metadata(&enabled, &keyset);

    assert_eq!(
        metadata
            .get("frontchannel_logout_supported")
            .and_then(Value::as_bool),
        Some(true)
    );
    assert_eq!(
        metadata
            .get("frontchannel_logout_session_supported")
            .and_then(Value::as_bool),
        Some(true)
    );
}

#[test]
fn discovery_advertises_session_management_only_when_enabled() {
    let keyset = keyset(jsonwebtoken::Algorithm::RS256);
    let disabled = authorization_server_metadata(
        &settings(AuthorizationServerProfile::Oauth2Baseline, Vec::new()),
        &keyset,
    );
    assert!(disabled.get("check_session_iframe").is_none());

    let mut enabled = settings(AuthorizationServerProfile::Oauth2Baseline, Vec::new());
    enabled.enable_session_management = true;
    let metadata = authorization_server_metadata(&enabled, &keyset);

    assert_eq!(
        metadata.get("check_session_iframe").and_then(Value::as_str),
        Some("https://issuer.example/check_session")
    );
}

#[test]
fn discovery_advertises_native_sso_only_when_enabled() {
    let keyset = keyset(jsonwebtoken::Algorithm::RS256);
    let disabled = authorization_server_metadata(
        &settings(AuthorizationServerProfile::Oauth2Baseline, Vec::new()),
        &keyset,
    );
    assert!(disabled.get("native_sso_supported").is_none());
    assert!(
        !disabled
            .get("scopes_supported")
            .and_then(Value::as_array)
            .expect("scopes should be present")
            .iter()
            .any(|scope| scope.as_str() == Some("device_sso"))
    );

    let mut enabled = settings(AuthorizationServerProfile::Oauth2Baseline, Vec::new());
    enabled.enable_native_sso = true;
    let metadata = authorization_server_metadata(&enabled, &keyset);

    assert_eq!(
        metadata
            .get("native_sso_supported")
            .and_then(Value::as_bool),
        Some(true)
    );
    assert!(
        metadata
            .get("scopes_supported")
            .and_then(Value::as_array)
            .expect("scopes should be present")
            .iter()
            .any(|scope| scope.as_str() == Some("device_sso"))
    );
}

#[test]
fn discovery_advertises_dynamic_registration_only_when_enabled() {
    let keyset = keyset(jsonwebtoken::Algorithm::RS256);
    let disabled = authorization_server_metadata(
        &settings(AuthorizationServerProfile::Oauth2Baseline, Vec::new()),
        &keyset,
    );
    assert!(disabled.get("registration_endpoint").is_none());

    let mut enabled = settings(AuthorizationServerProfile::Oauth2Baseline, Vec::new());
    enabled.enable_dynamic_client_registration = true;
    let metadata = authorization_server_metadata(&enabled, &keyset);

    assert_eq!(
        metadata
            .get("registration_endpoint")
            .and_then(Value::as_str),
        Some("https://issuer.example/register")
    );
}

#[test]
fn discovery_advertises_device_authorization_only_when_enabled() {
    let keyset = keyset(jsonwebtoken::Algorithm::RS256);
    let mut enabled = settings(AuthorizationServerProfile::Oauth2Baseline, Vec::new());
    enabled.enable_device_authorization_grant = true;
    let metadata = authorization_server_metadata(&enabled, &keyset);

    assert_eq!(
        metadata
            .get("device_authorization_endpoint")
            .and_then(Value::as_str),
        Some("https://issuer.example/device_authorization")
    );

    let grant_types = metadata
        .get("grant_types_supported")
        .and_then(Value::as_array)
        .expect("grant type metadata should be present")
        .iter()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>();
    assert!(grant_types.contains(&"urn:ietf:params:oauth:grant-type:device_code"));
}

#[test]
fn discovery_advertises_signed_introspection_only_for_signed_introspection_profile() {
    let keyset = keyset(jsonwebtoken::Algorithm::PS256);
    let baseline = authorization_server_metadata(
        &settings(AuthorizationServerProfile::Oauth2Baseline, Vec::new()),
        &keyset,
    );
    assert!(
        baseline
            .get("introspection_signing_alg_values_supported")
            .is_none()
    );

    let signed_introspection = authorization_server_metadata(
        &settings(
            AuthorizationServerProfile::Fapi2MessageSigningIntrospection,
            Vec::new(),
        ),
        &keyset,
    );

    assert_eq!(
        signed_introspection
            .get("introspection_signing_alg_values_supported")
            .and_then(Value::as_array)
            .expect("signed introspection profile must advertise response signing algs")
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>(),
        vec!["PS256"]
    );
    assert_eq!(
        signed_introspection
            .get("introspection_encryption_alg_values_supported")
            .and_then(Value::as_array)
            .expect("signed introspection profile must advertise supported JWE key-management algs")
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>(),
        vec!["RSA-OAEP-256"]
    );
    assert_eq!(
        signed_introspection
            .get("introspection_encryption_enc_values_supported")
            .and_then(Value::as_array)
            .expect("signed introspection profile must advertise supported JWE content enc algs")
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>(),
        vec!["A256GCM"]
    );
}

#[test]
fn discovery_id_token_algs_include_oidc_rs256_baseline() {
    let keyset = keyset(jsonwebtoken::Algorithm::RS256);

    assert_eq!(
        id_token_signing_alg_values_supported(&keyset),
        vec!["RS256"]
    );
}

#[test]
fn discovery_id_token_algs_include_active_alg_and_rs256_baseline() {
    let keyset = keyset(jsonwebtoken::Algorithm::PS256);

    assert_eq!(
        id_token_signing_alg_values_supported(&keyset),
        vec!["PS256", "RS256"]
    );
}

#[test]
fn discovery_authorization_response_algs_match_active_key_only() {
    let keyset = keyset(jsonwebtoken::Algorithm::PS256);

    assert_eq!(active_signing_alg_values_supported(&keyset), vec!["PS256"]);
}

#[test]
fn discovery_advertises_only_response_algorithms_signable_by_current_keyset() {
    let metadata = authorization_server_metadata(
        &settings(AuthorizationServerProfile::Oauth2Baseline, Vec::new()),
        &keyset(jsonwebtoken::Algorithm::PS256),
    );

    assert_eq!(
        metadata["userinfo_signing_alg_values_supported"],
        json!(["PS256"])
    );
    assert_eq!(
        metadata["authorization_signing_alg_values_supported"],
        json!(["PS256"])
    );
    assert_eq!(
        metadata["userinfo_encryption_alg_values_supported"],
        json!(["RSA-OAEP-256"])
    );
    assert_eq!(
        metadata["userinfo_encryption_enc_values_supported"],
        json!(["A256GCM"])
    );
    assert_eq!(
        metadata["authorization_encryption_alg_values_supported"],
        json!(["RSA-OAEP-256"])
    );
    assert_eq!(
        metadata["authorization_encryption_enc_values_supported"],
        json!(["A256GCM"])
    );
    for field in [
        "userinfo_signing_alg_values_supported",
        "userinfo_encryption_alg_values_supported",
        "userinfo_encryption_enc_values_supported",
        "authorization_encryption_alg_values_supported",
        "authorization_encryption_enc_values_supported",
    ] {
        assert!(
            metadata[field]
                .as_array()
                .expect("crypto metadata must be an array")
                .iter()
                .all(|value| value != "none" && value != "HS256"),
            "{field} must not advertise unsafe algorithms"
        );
    }
}

#[test]
fn discovery_does_not_advertise_mtls_when_no_trusted_proxy_is_configured() {
    let metadata = authorization_server_metadata(
        &settings(AuthorizationServerProfile::Oauth2Baseline, Vec::new()),
        &keyset(jsonwebtoken::Algorithm::RS256),
    );

    assert!(metadata.get("authorization_server_profile").is_none());
    assert!(
        metadata
            .get("token_endpoint_auth_methods_supported")
            .and_then(Value::as_array)
            .expect("methods should be an array")
            .iter()
            .all(|method| !matches!(
                method.as_str(),
                Some("tls_client_auth" | "self_signed_tls_client_auth")
            ))
    );
    assert!(metadata.get("mtls_endpoint_aliases").is_none());
    assert!(
        metadata
            .get("tls_client_certificate_bound_access_tokens")
            .is_none()
    );
}

#[test]
fn discovery_advertises_mtls_only_for_configured_proxy_profile() {
    let metadata = authorization_server_metadata(
        &settings(
            AuthorizationServerProfile::Oauth2Baseline,
            vec![IpCidr::parse("192.0.2.0/24").unwrap()],
        ),
        &keyset(jsonwebtoken::Algorithm::RS256),
    );

    assert_eq!(
        metadata
            .get("tls_client_certificate_bound_access_tokens")
            .and_then(Value::as_bool),
        Some(true)
    );
    assert_eq!(
        metadata
            .pointer("/mtls_endpoint_aliases/token_endpoint")
            .and_then(Value::as_str),
        Some("https://mtls.issuer.example/token")
    );
}

#[test]
fn discovery_fapi2_security_metadata_is_profile_scoped() {
    let metadata = authorization_server_metadata(
        &settings(AuthorizationServerProfile::Fapi2Security, Vec::new()),
        &keyset(jsonwebtoken::Algorithm::RS256),
    );

    assert!(metadata.get("authorization_server_profile").is_none());
    assert_eq!(
        metadata
            .get("require_pushed_authorization_requests")
            .and_then(Value::as_bool),
        Some(true)
    );
    assert_eq!(
        metadata
            .get("token_endpoint_auth_methods_supported")
            .and_then(Value::as_array)
            .expect("methods should be present")
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>(),
        vec!["private_key_jwt"]
    );
    assert_eq!(
        metadata
            .get("response_types_supported")
            .and_then(Value::as_array)
            .expect("response types should be present")
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>(),
        vec!["code"]
    );
    assert_eq!(
        metadata
            .get("response_modes_supported")
            .and_then(Value::as_array)
            .expect("response modes should be present")
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>(),
        vec!["query", "jwt"]
    );
    assert!(
        metadata
            .get("introspection_signing_alg_values_supported")
            .is_none(),
        "base FAPI2 Security must not advertise signed introspection metadata"
    );
    assert!(
        metadata
            .get("introspection_encryption_alg_values_supported")
            .is_none(),
        "base FAPI2 Security must not advertise nested encrypted introspection metadata"
    );
}

#[test]
fn discovery_jarm_profile_requires_signed_authorization_response_metadata() {
    let metadata = authorization_server_metadata(
        &settings(
            AuthorizationServerProfile::Fapi2MessageSigningJarm,
            Vec::new(),
        ),
        &keyset(jsonwebtoken::Algorithm::PS256),
    );

    assert!(metadata.get("authorization_server_profile").is_none());
    assert_eq!(
        metadata
            .get("require_pushed_authorization_requests")
            .and_then(Value::as_bool),
        Some(true)
    );
    assert_eq!(
        metadata
            .get("response_types_supported")
            .and_then(Value::as_array)
            .expect("response types should be present")
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>(),
        vec!["code"]
    );
    assert_eq!(
        metadata
            .get("response_modes_supported")
            .and_then(Value::as_array)
            .expect("response modes should be present")
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>(),
        vec!["jwt"]
    );
    assert_eq!(
        metadata
            .get("authorization_signing_alg_values_supported")
            .and_then(Value::as_array)
            .expect("authorization response algs should be present")
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>(),
        vec!["PS256"]
    );
    assert_eq!(
        metadata
            .get("token_endpoint_auth_methods_supported")
            .and_then(Value::as_array)
            .expect("methods should be present")
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>(),
        vec!["private_key_jwt"]
    );
    assert!(
        metadata
            .get("introspection_signing_alg_values_supported")
            .is_none(),
        "JARM profile must not advertise signed introspection metadata"
    );
    assert!(
        metadata
            .get("introspection_encryption_alg_values_supported")
            .is_none(),
        "JARM profile must not advertise nested encrypted introspection metadata"
    );
}

#[test]
fn discovery_fapi2_with_mtls_advertises_only_fapi_client_auth_methods() {
    let metadata = authorization_server_metadata(
        &settings(
            AuthorizationServerProfile::Fapi2Security,
            vec![IpCidr::parse("192.0.2.0/24").unwrap()],
        ),
        &keyset(jsonwebtoken::Algorithm::RS256),
    );

    assert_eq!(
        metadata
            .get("token_endpoint_auth_methods_supported")
            .and_then(Value::as_array)
            .expect("methods should be present")
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>(),
        vec![
            "private_key_jwt",
            "tls_client_auth",
            "self_signed_tls_client_auth"
        ]
    );
    assert!(
        !metadata
            .get("token_endpoint_auth_methods_supported")
            .and_then(Value::as_array)
            .unwrap()
            .iter()
            .any(|method| matches!(method.as_str(), Some("client_secret_basic" | "none")))
    );
}

#[test]
fn discovery_message_signing_profile_requires_signed_request_object_algs() {
    let metadata = authorization_server_metadata(
        &settings(
            AuthorizationServerProfile::Fapi2MessageSigningAuthzRequest,
            Vec::new(),
        ),
        &keyset(jsonwebtoken::Algorithm::PS256),
    );

    assert!(metadata.get("authorization_server_profile").is_none());
    assert_eq!(
        metadata
            .get("request_object_signing_alg_values_supported")
            .and_then(Value::as_array)
            .expect("request object algs should be present")
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>(),
        vec!["PS256"]
    );
}

#[test]
fn discovery_baseline_advertises_unsigned_request_object_compatibility_only() {
    let baseline = authorization_server_metadata(
        &settings(AuthorizationServerProfile::Oauth2Baseline, Vec::new()),
        &keyset(jsonwebtoken::Algorithm::EdDSA),
    );
    assert_eq!(
        baseline
            .get("request_object_signing_alg_values_supported")
            .and_then(Value::as_array)
            .expect("request object algs should be present")
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>(),
        vec!["none", "EdDSA", "RS256", "ES256", "PS256"]
    );

    let fapi2 = authorization_server_metadata(
        &settings(AuthorizationServerProfile::Fapi2Security, Vec::new()),
        &keyset(jsonwebtoken::Algorithm::EdDSA),
    );
    assert!(
        !fapi2
            .get("request_object_signing_alg_values_supported")
            .and_then(Value::as_array)
            .expect("request object algs should be present")
            .iter()
            .any(|value| value.as_str() == Some("none"))
    );
}

#[test]
fn discovery_ciba_request_object_algs_are_fapi_ciba_scoped() {
    let mut settings = settings(AuthorizationServerProfile::Fapi2Security, Vec::new());
    settings.enable_ciba = true;
    let metadata =
        authorization_server_metadata(&settings, &keyset(jsonwebtoken::Algorithm::PS256));

    assert_eq!(
        metadata
            .get("backchannel_authentication_request_signing_alg_values_supported")
            .and_then(Value::as_array)
            .expect("CIBA request object algs should be present")
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>(),
        vec!["EdDSA", "ES256", "PS256"]
    );
}

#[test]
fn discovery_omits_entire_ciba_surface_when_disabled() {
    let settings = settings(AuthorizationServerProfile::Oauth2Baseline, Vec::new());
    assert!(!settings.enable_ciba);
    let metadata =
        authorization_server_metadata(&settings, &keyset(jsonwebtoken::Algorithm::PS256));

    assert!(
        !metadata
            .get("grant_types_supported")
            .and_then(Value::as_array)
            .expect("grant types should be present")
            .iter()
            .any(|value| value.as_str() == Some(CIBA_GRANT_TYPE))
    );
    for field in [
        "backchannel_authentication_endpoint",
        "backchannel_token_delivery_modes_supported",
        "backchannel_user_code_parameter_supported",
        "backchannel_authentication_request_signing_alg_values_supported",
        "pushed_backchannel_authentication_request_endpoint",
    ] {
        assert!(
            metadata.get(field).is_none(),
            "unexpected CIBA field {field}"
        );
    }
}

#[test]
fn discovery_fapi2_ciba_internal_profile_advertises_only_standard_capabilities() {
    let mut settings = settings(AuthorizationServerProfile::Oauth2Baseline, Vec::new());
    settings.enable_ciba = true;
    settings.ciba_security_profile = crate::settings::CibaSecurityProfile::Fapi2Ciba;
    let metadata =
        authorization_server_metadata(&settings, &keyset(jsonwebtoken::Algorithm::PS256));

    assert!(metadata.get("authorization_server_profile").is_none());
    let serialized = serde_json::to_string(&metadata).expect("metadata should serialize");
    assert!(!serialized.contains("Fapi2Ciba"));
    assert!(!serialized.contains("fapi2-ciba"));
    assert_eq!(
        metadata
            .get("token_endpoint_auth_methods_supported")
            .and_then(Value::as_array)
            .expect("methods should be present")
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>(),
        vec!["private_key_jwt"]
    );
    assert_eq!(
        metadata
            .get("token_endpoint_auth_signing_alg_values_supported")
            .and_then(Value::as_array)
            .expect("client assertion algs should be present")
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>(),
        vec!["EdDSA", "ES256", "PS256"]
    );
    assert_eq!(
        metadata
            .get("backchannel_token_delivery_modes_supported")
            .and_then(Value::as_array)
            .expect("CIBA delivery modes should be present")
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>(),
        vec!["poll"]
    );
    assert!(
        metadata
            .get("pushed_backchannel_authentication_request_endpoint")
            .is_none()
    );
}
