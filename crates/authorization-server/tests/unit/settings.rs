use super::*;
use serde_json::json;

const CLIENT_ATTESTATION_JWKS: &str = r#"{"keys":[{"kty":"EC","crv":"P-256","kid":"client-attester","x":"client-x","y":"client-y"}]}"#;
const KEY_ATTESTATION_JWKS: &str =
    r#"{"keys":[{"kty":"EC","crv":"P-256","kid":"key-attester","x":"holder-x","y":"holder-y"}]}"#;
const ATTESTATION_CREDENTIAL_CONFIGURATIONS: &str = r#"{"pid":{"format":"dc+sd-jwt","scope":"pid","cryptographic_binding_methods_supported":["jwk"],"credential_signing_alg_values_supported":["ES256"],"proof_types_supported":{"attestation":{"proof_signing_alg_values_supported":["ES256"],"key_attestations_required":{"key_storage":["iso_18045_moderate"]}}},"vct":"https://issuer.example/credentials/pid"}}"#;

#[test]
fn key_attestation_policy_can_defer_trust_to_a_scoped_conformance_lease() {
    let config = ConfigSource::from_pairs_for_test([
        ("ENABLE_OPENID4VCI_ISSUER", "true"),
        (
            "OPENID4VC_DATA_ENCRYPTION_KEY",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ),
        (
            "OPENID4VC_SIGNING_CERTIFICATE_CHAIN_FILE",
            "runtime/openid4vc-chain.pem",
        ),
        (
            "OPENID4VC_TRUST_ANCHORS_FILE",
            "runtime/openid4vc-roots.pem",
        ),
        ("OPENID4VC_REVOCATION_POLICY", "required"),
        (
            "OPENID4VC_REVOCATION_SNAPSHOT_FILE",
            "runtime/openid4vc-revocation.json",
        ),
        (
            "OPENID4VCI_CREDENTIAL_CONFIGURATIONS_JSON",
            ATTESTATION_CREDENTIAL_CONFIGURATIONS,
        ),
        (
            "OPENID4VCI_ISSUER_MANAGEMENT_TOKEN",
            "openid4vci-management-token-at-least-32-bytes",
        ),
        (
            "OPENID4VC_CLIENT_ATTESTATION_JWKS_JSON",
            CLIENT_ATTESTATION_JWKS,
        ),
    ]);

    let settings =
        Settings::from_config(&config).expect("lease-scoped trust is resolved at request time");
    assert!(settings.openid4vc.key_attestation_jwks.is_none());
}

#[test]
fn client_attestation_requires_its_own_trust_store() {
    let config = ConfigSource::from_pairs_for_test([
        (
            "OPENID4VC_CLIENT_ATTESTATION_ISSUER",
            "https://attester.example",
        ),
        ("OPENID4VC_KEY_ATTESTATION_JWKS_JSON", KEY_ATTESTATION_JWKS),
    ]);

    let error = settings_error(
        &config,
        "client attestation needs an independent trust store",
    );
    assert!(
        error
            .to_string()
            .contains("OPENID4VC_CLIENT_ATTESTATION_JWKS_JSON")
    );
}

#[test]
fn attestation_trust_stores_reject_private_key_material() {
    let config = ConfigSource::from_pairs_for_test([(
        "OPENID4VC_CLIENT_ATTESTATION_JWKS_JSON",
        r#"{"keys":[{"kty":"EC","crv":"P-256","kid":"private","x":"x","y":"y","d":"secret"}]}"#,
    )]);

    let error = settings_error(&config, "trust configuration must contain public keys only");
    assert!(error.to_string().contains("public verification keys only"));
}

#[test]
fn issuer_and_verifier_management_credentials_must_be_distinct() {
    let shared = "shared-management-credential-at-least-32-bytes";
    let config = ConfigSource::from_pairs_for_test([
        ("OPENID4VCI_ISSUER_MANAGEMENT_TOKEN", shared),
        ("OPENID4VP_VERIFIER_MANAGEMENT_TOKEN", shared),
    ]);

    let error = match Settings::from_config(&config) {
        Ok(_) => panic!("roles must not share a bearer secret"),
        Err(error) => error,
    };

    assert!(error.to_string().contains("must differ"));
}

#[test]
fn default_dpop_nonce_policy_is_required() {
    let settings = Settings::from_config(&ConfigSource::default()).unwrap();

    assert_eq!(
        settings.protocol.dpop_nonce_policy,
        DpopNoncePolicy::Required
    );
}

#[test]
fn shared_ip_admission_defaults_do_not_replace_failed_login_throttling() {
    let settings = Settings::from_config(&ConfigSource::default()).unwrap();
    let rate_limit = &settings.identity.rate_limit;

    assert_eq!(rate_limit.window_seconds, 60);
    assert_eq!(rate_limit.auth_max_requests, 100_000);
    assert_eq!(rate_limit.token_max_requests, 100_000);
    assert_eq!(rate_limit.token_management_max_requests, 100_000);
    assert_eq!(rate_limit.login_failure_window_seconds, 900);
    assert_eq!(rate_limit.login_failure_ip_email_max_attempts, 5);
    assert_eq!(rate_limit.mfa_failure_window_seconds, 900);
    assert_eq!(rate_limit.mfa_failure_max_attempts, 5);
    assert_eq!(settings.session.pending_mfa_session_ttl_seconds, 600);
}

#[test]
fn pending_mfa_session_ttl_must_be_shorter_than_full_session_ttl() {
    let config = ConfigSource::from_pairs_for_test([
        ("SESSION_TTL_SECONDS", "600"),
        ("PENDING_MFA_SESSION_TTL_SECONDS", "600"),
    ]);
    let error = settings_error(
        &config,
        "pending MFA session must expire before full session",
    );
    assert_eq!(
        error.to_string(),
        "PENDING_MFA_SESSION_TTL_SECONDS must be less than SESSION_TTL_SECONDS"
    );
}

#[test]
fn baseline_profile_can_use_optional_dpop_nonce_policy() {
    let config = ConfigSource::from_pairs_for_test([("DPOP_NONCE_POLICY", "optional")]);
    let settings = Settings::from_config(&config).unwrap();

    assert_eq!(
        settings.protocol.dpop_nonce_policy,
        DpopNoncePolicy::Optional
    );
    assert_eq!(
        settings.protocol.fapi_resource_dpop_nonce_policy,
        DpopNoncePolicy::Optional
    );
}

#[test]
fn fapi_profiles_default_to_required_dpop_nonce_policy() {
    for profile in [
        "fapi2-security",
        "fapi2-message-signing-authz-request",
        "fapi2-message-signing-jarm",
        "fapi2-message-signing-introspection",
    ] {
        let config = ConfigSource::from_pairs_for_test([("AUTHORIZATION_SERVER_PROFILE", profile)]);
        let settings = Settings::from_config(&config).unwrap();

        assert_eq!(
            settings.protocol.dpop_nonce_policy,
            DpopNoncePolicy::Required
        );
        assert_eq!(
            settings.protocol.fapi_resource_dpop_nonce_policy,
            DpopNoncePolicy::Optional
        );
        assert!(
            !settings.protocol.require_pushed_authorization_requests,
            "{profile} PAR enforcement is resolved per client"
        );
        assert!(
            settings
                .protocol
                .authorization_server_profile
                .requires_fapi2_security(),
            "{profile} must inherit FAPI2 Security controls"
        );
    }
}

#[test]
fn explicit_global_par_requirement_remains_supported() {
    let config =
        ConfigSource::from_pairs_for_test([("REQUIRE_PUSHED_AUTHORIZATION_REQUESTS", "true")]);
    let settings = Settings::from_config(&config).unwrap();

    assert!(settings.protocol.require_pushed_authorization_requests);
}

#[test]
fn fapi_profiles_can_use_optional_dpop_nonce_policy() {
    let config = ConfigSource::from_pairs_for_test([
        ("AUTHORIZATION_SERVER_PROFILE", "fapi2-security"),
        ("DPOP_NONCE_POLICY", "optional"),
    ]);
    let settings = Settings::from_config(&config).unwrap();

    assert_eq!(
        settings.protocol.dpop_nonce_policy,
        DpopNoncePolicy::Optional
    );
    assert_eq!(
        settings.protocol.fapi_resource_dpop_nonce_policy,
        DpopNoncePolicy::Optional
    );
}

#[test]
fn fapi_resource_nonce_policy_is_independent_from_token_nonce_policy() {
    let config = ConfigSource::from_pairs_for_test([
        ("DPOP_NONCE_POLICY", "required"),
        ("FAPI_RESOURCE_DPOP_NONCE_POLICY", "required"),
    ]);
    let settings = Settings::from_config(&config).unwrap();

    assert_eq!(
        settings.protocol.dpop_nonce_policy,
        DpopNoncePolicy::Required
    );
    assert_eq!(
        settings.protocol.fapi_resource_dpop_nonce_policy,
        DpopNoncePolicy::Required
    );

    let config = ConfigSource::from_pairs_for_test([
        ("DPOP_NONCE_POLICY", "required"),
        ("FAPI_RESOURCE_DPOP_NONCE_POLICY", "optional"),
    ]);
    let settings = Settings::from_config(&config).unwrap();

    assert_eq!(
        settings.protocol.dpop_nonce_policy,
        DpopNoncePolicy::Required
    );
    assert_eq!(
        settings.protocol.fapi_resource_dpop_nonce_policy,
        DpopNoncePolicy::Optional
    );
}

#[test]
fn fapi_profiles_reject_protocol_ttls_above_profile_limits() {
    for profile in [
        "fapi2-security",
        "fapi2-message-signing-authz-request",
        "fapi2-message-signing-jarm",
        "fapi2-message-signing-introspection",
    ] {
        let auth_code_ttl = ConfigSource::from_pairs_for_test([
            ("AUTHORIZATION_SERVER_PROFILE", profile),
            ("AUTH_CODE_TTL_SECONDS", "61"),
        ]);
        let error = settings_error(
            &auth_code_ttl,
            "FAPI authorization code lifetime must be capped at 60 seconds",
        );
        assert_eq!(
            error.to_string(),
            "AUTH_CODE_TTL_SECONDS must be 60 or less for FAPI2 profiles"
        );

        let par_ttl = ConfigSource::from_pairs_for_test([
            ("AUTHORIZATION_SERVER_PROFILE", profile),
            ("PAR_TTL_SECONDS", "600"),
        ]);
        let error = settings_error(
            &par_ttl,
            "FAPI PAR request_uri lifetime must be shorter than 600 seconds",
        );
        assert_eq!(
            error.to_string(),
            "PAR_TTL_SECONDS must be less than 600 for FAPI2 profiles"
        );
    }
}

#[test]
fn security_state_lifetimes_and_cooldowns_must_be_positive() {
    for (key, value, expected) in [
        (
            "SESSION_TTL_SECONDS",
            "0",
            "SESSION_TTL_SECONDS must be positive",
        ),
        (
            "AUTH_CODE_TTL_SECONDS",
            "0",
            "AUTH_CODE_TTL_SECONDS must be positive",
        ),
        (
            "ACCESS_TOKEN_TTL_SECONDS",
            "0",
            "ACCESS_TOKEN_TTL_SECONDS must be positive",
        ),
        (
            "ID_TOKEN_TTL_SECONDS",
            "0",
            "ID_TOKEN_TTL_SECONDS must be positive",
        ),
        (
            "REFRESH_TOKEN_TTL_SECONDS",
            "0",
            "REFRESH_TOKEN_TTL_SECONDS must be positive",
        ),
        (
            "CLIENT_DELIVERY_TTL_SECONDS",
            "0",
            "CLIENT_DELIVERY_TTL_SECONDS must be positive",
        ),
        ("PAR_TTL_SECONDS", "0", "PAR_TTL_SECONDS must be positive"),
        (
            "EMAIL_CODE_TTL_SECONDS",
            "0",
            "EMAIL_CODE_TTL_SECONDS must be positive",
        ),
        (
            "EMAIL_CODE_SEND_COOLDOWN_SECONDS",
            "0",
            "EMAIL_CODE_SEND_COOLDOWN_SECONDS must be positive",
        ),
        (
            "EMAIL_CODE_PEER_COOLDOWN_SECONDS",
            "0",
            "EMAIL_CODE_PEER_COOLDOWN_SECONDS must be positive",
        ),
    ] {
        let config = ConfigSource::from_pairs_for_test([(key, value)]);
        let error = settings_error(&config, "non-positive security lifetime must fail startup");
        assert_eq!(error.to_string(), expected);
    }

    for (key, value, expected) in [
        (
            "ACCESS_TOKEN_TTL_SECONDS",
            "-1",
            "ACCESS_TOKEN_TTL_SECONDS must be positive",
        ),
        (
            "ID_TOKEN_TTL_SECONDS",
            "-1",
            "ID_TOKEN_TTL_SECONDS must be positive",
        ),
        (
            "REFRESH_TOKEN_TTL_SECONDS",
            "-1",
            "REFRESH_TOKEN_TTL_SECONDS must be positive",
        ),
    ] {
        let config = ConfigSource::from_pairs_for_test([(key, value)]);
        let error = settings_error(&config, "negative token lifetime must fail startup");
        assert_eq!(error.to_string(), expected);
    }
}

#[test]
fn invalid_dpop_nonce_policy_is_rejected() {
    let config = ConfigSource::from_pairs_for_test([("DPOP_NONCE_POLICY", "sometimes")]);

    let Err(err) = Settings::from_config(&config) else {
        panic!("invalid DPoP nonce policy must be rejected");
    };

    assert_eq!(
        err.to_string(),
        "DPOP_NONCE_POLICY must be required or optional, got sometimes"
    );
}

#[test]
fn invalid_fapi_resource_dpop_nonce_policy_is_rejected() {
    let config =
        ConfigSource::from_pairs_for_test([("FAPI_RESOURCE_DPOP_NONCE_POLICY", "sometimes")]);

    let Err(err) = Settings::from_config(&config) else {
        panic!("invalid FAPI resource DPoP nonce policy must be rejected");
    };

    assert_eq!(
        err.to_string(),
        "FAPI_RESOURCE_DPOP_NONCE_POLICY must be required or optional, got sometimes"
    );
}

#[test]
fn dpop_nonce_policy_rejects_legacy_compatibility_alias() {
    for value in ["compat", "compatible"] {
        let config = ConfigSource::from_pairs_for_test([("DPOP_NONCE_POLICY", value)]);

        let Err(err) = Settings::from_config(&config) else {
            panic!("legacy DPoP nonce policy alias must be rejected");
        };

        assert_eq!(
            err.to_string(),
            format!("DPOP_NONCE_POLICY must be required or optional, got {value}")
        );
    }
}

#[test]
fn request_object_jti_is_optional_unless_the_operator_requires_it() {
    let settings = Settings::from_config(&ConfigSource::default()).unwrap();

    assert_eq!(
        settings.protocol.request_object_jti_policy,
        RequestObjectJtiPolicy::Optional
    );
}

#[test]
fn request_object_jti_policy_can_require_signed_jar_jti() {
    let config = ConfigSource::from_pairs_for_test([("REQUEST_OBJECT_JTI_POLICY", "required")]);
    let settings = Settings::from_config(&config).unwrap();

    assert_eq!(
        settings.protocol.request_object_jti_policy,
        RequestObjectJtiPolicy::RequiredForSignedJar
    );
}

#[test]
fn invalid_request_object_jti_policy_is_rejected() {
    let config = ConfigSource::from_pairs_for_test([("REQUEST_OBJECT_JTI_POLICY", "always")]);

    assert!(Settings::from_config(&config).is_err());
}

#[test]
fn default_ciba_security_profile_is_fapi_ciba_id1() {
    let settings = Settings::from_config(&ConfigSource::default()).unwrap();

    assert_eq!(
        settings.protocol.ciba_security_profile,
        CibaSecurityProfile::FapiCibaId1
    );
}

#[test]
fn ciba_security_profile_accepts_canonical_fapi2_ciba_value() {
    let config = ConfigSource::from_pairs_for_test([("CIBA_SECURITY_PROFILE", "fapi2-ciba")]);
    let settings = Settings::from_config(&config).unwrap();

    assert_eq!(
        settings.protocol.ciba_security_profile,
        CibaSecurityProfile::Fapi2Ciba
    );
}

#[test]
fn ciba_security_profile_rejects_conformance_and_migration_aliases() {
    for value in [
        "oidf-fapi-ciba",
        "fapi-ciba-id1-plain-private-key-jwt-poll",
        "experimental-fapi2-ciba",
    ] {
        let config = ConfigSource::from_pairs_for_test([("CIBA_SECURITY_PROFILE", value)]);
        assert!(Settings::from_config(&config).is_err());
    }
}

#[test]
fn invalid_ciba_security_profile_is_rejected() {
    let config = ConfigSource::from_pairs_for_test([("CIBA_SECURITY_PROFILE", "fapi-ciba-id2")]);

    let Err(err) = Settings::from_config(&config) else {
        panic!("unknown CIBA security profile must be rejected");
    };

    assert_eq!(
        err.to_string(),
        "CIBA_SECURITY_PROFILE is not supported: fapi-ciba-id2"
    );
}

#[test]
fn ciba_automated_decision_requires_explicit_transport_and_secret() {
    let token_only = ConfigSource::from_pairs_for_test([(
        "CIBA_AUTOMATED_DECISION_TOKEN",
        "test-ciba-automated-decision-token-32",
    )]);
    let lease_gated = Settings::from_config(&token_only).unwrap();
    assert_eq!(
        lease_gated.ciba.ciba_automated_decision_mode,
        CibaAutomatedDecisionMode::Disabled
    );
    assert_eq!(
        lease_gated.ciba.ciba_automated_decision_token.as_deref(),
        Some("test-ciba-automated-decision-token-32")
    );

    let mode_only = ConfigSource::from_pairs_for_test([("CIBA_AUTOMATED_DECISION_MODE", "header")]);
    assert!(Settings::from_config(&mode_only).is_err());

    let configured = ConfigSource::from_pairs_for_test([
        ("CIBA_AUTOMATED_DECISION_MODE", "header"),
        (
            "CIBA_AUTOMATED_DECISION_TOKEN",
            "test-ciba-automated-decision-token-32",
        ),
    ]);
    let settings = Settings::from_config(&configured).unwrap();
    assert_eq!(
        settings.ciba.ciba_automated_decision_mode,
        CibaAutomatedDecisionMode::Header
    );
}

#[test]
fn secure_deployments_default_to_host_only_cookie_names() {
    let config = ConfigSource::from_pairs_for_test([
        ("PUBLIC_BASE_URL", "https://auth.example"),
        (
            "CLIENT_SECRET_PEPPER",
            "test-client-secret-pepper-at-least-32-bytes",
        ),
    ]);
    let settings = Settings::from_config(&config).unwrap();

    assert!(settings.session.cookie_secure);
    assert_eq!(
        settings.session.session_cookie_name,
        "__Host-nazo_oauth_session"
    );
    assert_eq!(settings.session.csrf_cookie_name, "__Host-nazo_oauth_csrf");
}

#[test]
fn feature_gate_settings_default_closed_and_accept_explicit_enablement() {
    let defaults = Settings::from_config(&ConfigSource::default()).unwrap();
    assert!(!defaults.modules.enable_request_object);
    assert!(!defaults.modules.enable_par_request_object);
    assert!(!defaults.modules.enable_authorization_details);
    assert!(!defaults.modules.enable_device_authorization_grant);
    assert!(!defaults.modules.enable_dynamic_client_registration);
    assert!(!defaults.modules.enable_frontchannel_logout);
    assert!(!defaults.modules.enable_session_management);
    assert!(!defaults.modules.enable_ciba);
    assert_eq!(
        defaults.ciba.ciba_automated_decision_mode,
        CibaAutomatedDecisionMode::Disabled
    );
    assert!(!defaults.modules.enable_native_sso);
    assert!(!defaults.modules.enable_scim_security_events);
    assert!(!defaults.modules.enable_openid4vci_issuer);
    assert!(!defaults.modules.enable_openid4vp_verifier);
    assert_eq!(defaults.storage.scim_event_retention_seconds, 604_800);
    assert!(
        defaults
            .modules
            .dynamic_client_registration_initial_access_token
            .is_none()
    );
    assert_eq!(defaults.device.device_authorization_ttl_seconds, 600);
    assert_eq!(
        defaults.device.device_authorization_poll_interval_seconds,
        5
    );
    assert_eq!(defaults.ciba.ciba_auth_req_id_ttl_seconds, 600);
    assert_eq!(defaults.ciba.ciba_poll_interval_seconds, 5);
    assert!(defaults.ciba.ciba_notification_private_origins.is_empty());

    let config = ConfigSource::from_pairs_for_test([
        ("ENABLE_AUTHORIZATION_DETAILS", "true"),
        ("ENABLE_NATIVE_SSO", "true"),
        ("ENABLE_SCIM_SECURITY_EVENTS", "true"),
        ("ENABLE_OPENID4VCI_ISSUER", "true"),
        ("ENABLE_OPENID4VP_VERIFIER", "true"),
        (
            "OPENID4VC_DATA_ENCRYPTION_KEY",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ),
        (
            "OPENID4VC_SIGNING_CERTIFICATE_CHAIN_FILE",
            "runtime/openid4vc-chain.pem",
        ),
        (
            "OPENID4VC_TRUST_ANCHORS_FILE",
            "runtime/openid4vc-roots.pem",
        ),
        ("OPENID4VC_REVOCATION_POLICY", "required"),
        (
            "OPENID4VC_REVOCATION_SNAPSHOT_FILE",
            "runtime/openid4vc-revocation.json",
        ),
        (
            "OPENID4VP_WALLET_AUTHORIZATION_ORIGINS",
            "https://wallet.example",
        ),
        (
            "OPENID4VCI_CREDENTIAL_CONFIGURATIONS_JSON",
            r#"{"example":{"format":"dc+sd-jwt","scope":"example","cryptographic_binding_methods_supported":["jwk"],"credential_signing_alg_values_supported":["ES256"],"proof_types_supported":{"jwt":{"proof_signing_alg_values_supported":["ES256"]}},"vct":"https://issuer.example/credentials/example"}}"#,
        ),
        (
            "OPENID4VCI_ISSUER_MANAGEMENT_TOKEN",
            "openid4vci-management-token-at-least-32-bytes",
        ),
        (
            "OPENID4VP_VERIFIER_MANAGEMENT_TOKEN",
            "openid4vp-management-token-at-least-32-bytes",
        ),
        ("SCIM_EVENT_RETENTION_SECONDS", "86400"),
        (
            "DYNAMIC_CLIENT_REGISTRATION_INITIAL_ACCESS_TOKEN",
            "register-token",
        ),
        ("DEVICE_AUTHORIZATION_TTL_SECONDS", "300"),
        ("DEVICE_AUTHORIZATION_POLL_INTERVAL_SECONDS", "7"),
        ("CIBA_AUTH_REQ_ID_TTL_SECONDS", "240"),
        ("CIBA_POLL_INTERVAL_SECONDS", "6"),
        (
            "CIBA_NOTIFICATION_PRIVATE_ORIGINS",
            "https://suite.example, https://callback.internal:9443",
        ),
        (
            "BACKCHANNEL_LOGOUT_PRIVATE_ORIGINS",
            "http://localhost:8080, https://logout.internal:9443",
        ),
    ]);
    let settings = Settings::from_config(&config).unwrap();

    assert!(!settings.modules.enable_request_object);
    assert!(!settings.modules.enable_par_request_object);
    assert!(settings.modules.enable_authorization_details);
    assert!(!settings.modules.enable_device_authorization_grant);
    assert!(settings.modules.enable_dynamic_client_registration);
    assert!(!settings.modules.enable_frontchannel_logout);
    assert!(!settings.modules.enable_session_management);
    assert!(!settings.modules.enable_ciba);
    assert!(settings.modules.enable_native_sso);
    assert!(settings.modules.enable_scim_security_events);
    assert!(settings.modules.enable_openid4vci_issuer);
    assert!(settings.modules.enable_openid4vp_verifier);
    assert_eq!(settings.storage.scim_event_retention_seconds, 86_400);
    assert_eq!(
        settings
            .modules
            .dynamic_client_registration_initial_access_token
            .as_deref(),
        Some("register-token")
    );
    assert_eq!(settings.device.device_authorization_ttl_seconds, 300);
    assert_eq!(
        settings.device.device_authorization_poll_interval_seconds,
        7
    );
    assert_eq!(settings.ciba.ciba_auth_req_id_ttl_seconds, 240);
    assert_eq!(settings.ciba.ciba_poll_interval_seconds, 6);
    assert_eq!(
        settings.ciba.ciba_notification_private_origins,
        ["https://suite.example", "https://callback.internal:9443"]
    );
    assert_eq!(
        settings.modules.backchannel_logout_private_origins,
        ["http://localhost:8080", "https://logout.internal:9443"]
    );
}

#[test]
fn scim_event_retention_is_bounded_for_delivery_and_data_minimization() {
    for value in ["3599", "2592001"] {
        let config = ConfigSource::from_pairs_for_test([("SCIM_EVENT_RETENTION_SECONDS", value)]);
        let error = settings_error(&config, "unbounded SCIM retention must fail startup");
        assert_eq!(
            error.to_string(),
            "SCIM_EVENT_RETENTION_SECONDS must be between 3600 and 2592000"
        );
    }
}

#[test]
fn dynamic_client_registration_is_enabled_only_with_an_initial_access_token() {
    let missing_token = ConfigSource::from_pairs_for_test([]);
    let settings = Settings::from_config(&missing_token).unwrap();
    assert!(!settings.modules.enable_dynamic_client_registration);

    let protected = ConfigSource::from_pairs_for_test([(
        "DYNAMIC_CLIENT_REGISTRATION_INITIAL_ACCESS_TOKEN",
        "register-token",
    )]);
    let settings = Settings::from_config(&protected).unwrap();
    assert!(settings.modules.enable_dynamic_client_registration);
    assert_eq!(
        settings
            .modules
            .dynamic_client_registration_initial_access_token
            .as_deref(),
        Some("register-token")
    );
}

#[test]
fn token_issuance_response_key_ring_requires_independent_current_pair() {
    let missing = ConfigSource::from_pairs_for_test([]);
    assert!(
        crate::settings::token_issuance_response_key_ring(&missing)
            .expect_err("missing response key must fail closed")
            .to_string()
            .contains("TOKEN_ISSUANCE_RESPONSE_ENCRYPTION_KEY")
    );

    let valid = ConfigSource::from_pairs_for_test([
        (
            "TOKEN_ISSUANCE_RESPONSE_ENCRYPTION_KEY",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ),
        ("TOKEN_ISSUANCE_RESPONSE_ENCRYPTION_KEY_ID", "current"),
        (
            "TOKEN_ISSUANCE_RESPONSE_PREVIOUS_ENCRYPTION_KEY",
            "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
        ),
        (
            "TOKEN_ISSUANCE_RESPONSE_PREVIOUS_ENCRYPTION_KEY_ID",
            "previous",
        ),
    ]);
    let ring = crate::settings::token_issuance_response_key_ring(&valid)
        .expect("independent current/previous key ring should parse");
    assert_eq!(ring.current_id(), "current");

    let duplicate = ConfigSource::from_pairs_for_test([
        (
            "TOKEN_ISSUANCE_RESPONSE_ENCRYPTION_KEY",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ),
        ("TOKEN_ISSUANCE_RESPONSE_ENCRYPTION_KEY_ID", "same"),
        (
            "TOKEN_ISSUANCE_RESPONSE_PREVIOUS_ENCRYPTION_KEY",
            "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
        ),
        ("TOKEN_ISSUANCE_RESPONSE_PREVIOUS_ENCRYPTION_KEY_ID", "same"),
    ]);
    assert!(crate::settings::token_issuance_response_key_ring(&duplicate).is_err());
}

#[test]
fn non_loopback_issuer_requires_client_secret_pepper() {
    let config =
        ConfigSource::from_pairs_for_test([("PUBLIC_BASE_URL", "https://auth.example.test")]);
    let error = settings_error(
        &config,
        "production issuer must configure client secret pepper",
    );
    assert_eq!(
        error.to_string(),
        "CLIENT_SECRET_PEPPER is required for non-loopback issuers"
    );
}

#[test]
fn public_base_url_drives_same_origin_defaults() {
    let config = ConfigSource::from_pairs_for_test([
        ("PUBLIC_BASE_URL", "https://auth.example.test"),
        (
            "CLIENT_SECRET_PEPPER",
            "client-secret-pepper-for-tests-000000000001",
        ),
    ]);
    let settings = Settings::from_config(&config).unwrap();

    assert_eq!(settings.endpoint.issuer, "https://auth.example.test");
    assert_eq!(
        settings.endpoint.mtls_endpoint_base_url,
        "https://auth.example.test"
    );
    assert_eq!(
        settings.endpoint.frontend_base_url,
        "https://auth.example.test/ui/"
    );
    assert_eq!(
        settings.endpoint.cors_allowed_origins,
        vec!["https://auth.example.test"]
    );
    assert!(settings.session.cookie_secure);
    assert_eq!(
        settings.identity.passkey.origin,
        "https://auth.example.test"
    );
    assert_eq!(settings.identity.passkey.rp_id, "auth.example.test");
    assert_eq!(
        settings.protocol.protected_resource_identifier,
        "https://auth.example.test/fapi/resource"
    );
}

#[test]
fn explicit_legacy_url_settings_override_public_base_url_derivations() {
    let config = ConfigSource::from_pairs_for_test([
        ("PUBLIC_BASE_URL", "https://auth.example.test"),
        ("ISSUER", "https://issuer.example.test"),
        (
            "CLIENT_SECRET_PEPPER",
            "client-secret-pepper-for-tests-000000000001",
        ),
        ("FRONTEND_BASE_URL", "https://app.example.test/ui/"),
        ("CORS_ALLOWED_ORIGINS", "https://app.example.test"),
        ("PASSKEY_ORIGIN", "https://passkeys.example.test"),
        ("PASSKEY_RP_ID", "passkeys.example.test"),
    ]);
    let settings = Settings::from_config(&config).unwrap();

    assert_eq!(settings.endpoint.issuer, "https://issuer.example.test");
    assert_eq!(
        settings.endpoint.frontend_base_url,
        "https://app.example.test/ui/"
    );
    assert_eq!(
        settings.endpoint.cors_allowed_origins,
        vec!["https://app.example.test"]
    );
    assert_eq!(
        settings.identity.passkey.origin,
        "https://passkeys.example.test"
    );
    assert_eq!(settings.identity.passkey.rp_id, "passkeys.example.test");
    assert_eq!(
        settings.protocol.protected_resource_identifier,
        "https://issuer.example.test/fapi/resource"
    );
}

#[test]
fn explicit_protected_resource_identifier_overrides_issuer_default() {
    let config = ConfigSource::from_pairs_for_test([
        ("PUBLIC_BASE_URL", "https://auth.example.test"),
        (
            "CLIENT_SECRET_PEPPER",
            "client-secret-pepper-for-tests-000000000001",
        ),
        (
            "PROTECTED_RESOURCE_IDENTIFIER",
            "https://api.example.test/payments",
        ),
    ]);
    let settings = Settings::from_config(&config).unwrap();

    assert_eq!(
        settings.protocol.protected_resource_identifier,
        "https://api.example.test/payments"
    );
}

#[test]
fn protected_resource_identifier_rejects_fragment_and_non_https_remote_url() {
    for (value, expected) in [
        (
            "https://api.example.test/payments#frag",
            "PROTECTED_RESOURCE_IDENTIFIER 不能包含 fragment",
        ),
        (
            "http://api.example.test/payments",
            "PROTECTED_RESOURCE_IDENTIFIER 必须使用 https，只有 loopback 本地开发地址允许 http",
        ),
    ] {
        let config = ConfigSource::from_pairs_for_test([("PROTECTED_RESOURCE_IDENTIFIER", value)]);

        let error = settings_error(
            &config,
            "invalid protected resource identifier must fail startup",
        );
        assert_eq!(error.to_string(), expected);
    }
}

#[test]
fn data_dir_drives_default_persistent_storage_paths() {
    let config = ConfigSource::from_pairs_for_test([("DATA_DIR", "test-runtime/nazo-oauth")]);
    let settings = Settings::from_config(&config).unwrap();
    let data_dir = std::fs::canonicalize(".")
        .unwrap()
        .join("test-runtime/nazo-oauth");

    assert_eq!(
        settings.storage.avatar_storage_dir,
        data_dir.join("avatars")
    );
    assert_eq!(settings.keys.jwk_keys_dir, data_dir.join("keys"));
}

#[test]
fn explicit_storage_paths_override_data_dir_derivations() {
    let config = ConfigSource::from_pairs_for_test([
        ("DATA_DIR", "test-runtime/nazo-oauth"),
        ("AVATAR_STORAGE_DIR", "test-runtime/avatars"),
        ("JWK_KEYS_DIR", "test-runtime/keys"),
    ]);
    let settings = Settings::from_config(&config).unwrap();
    let config_dir = std::fs::canonicalize(".").unwrap();

    assert_eq!(
        settings.storage.avatar_storage_dir,
        config_dir.join("test-runtime/avatars")
    );
    assert_eq!(
        settings.keys.jwk_keys_dir,
        config_dir.join("test-runtime/keys")
    );
}

#[test]
fn signing_key_rotation_settings_default_to_automatic_lifecycle() {
    let settings = Settings::from_config(&ConfigSource::default()).unwrap();

    assert_eq!(
        settings.keys.signing_key_rotation_interval_seconds,
        7_776_000
    );
    assert_eq!(settings.keys.signing_key_prepublish_seconds, 86_400);
}

#[test]
fn signing_key_rotation_settings_reject_unsafe_windows() {
    for (key, value, expected) in [
        (
            "SIGNING_KEY_ROTATION_INTERVAL_SECONDS",
            "0",
            "SIGNING_KEY_ROTATION_INTERVAL_SECONDS must be positive",
        ),
        (
            "SIGNING_KEY_PREPUBLISH_SECONDS",
            "0",
            "SIGNING_KEY_PREPUBLISH_SECONDS must be positive",
        ),
    ] {
        let config = ConfigSource::from_pairs_for_test([(key, value)]);
        let error = settings_error(&config, "invalid signing key lifecycle setting must fail");
        assert_eq!(error.to_string(), expected);
    }

    let config = ConfigSource::from_pairs_for_test([
        ("SIGNING_KEY_ROTATION_INTERVAL_SECONDS", "3600"),
        ("SIGNING_KEY_PREPUBLISH_SECONDS", "3600"),
    ]);
    let error = settings_error(
        &config,
        "prepublish window must be shorter than rotation interval",
    );
    assert_eq!(
        error.to_string(),
        "SIGNING_KEY_PREPUBLISH_SECONDS must be less than SIGNING_KEY_ROTATION_INTERVAL_SECONDS"
    );
}

#[test]
fn pairwise_subject_secret_must_be_configured_and_strong_enough() {
    let missing = ConfigSource::from_pairs_for_test([("SUBJECT_TYPE", "pairwise")]);
    let error = settings_error(
        &missing,
        "pairwise subject type must not start without a server secret",
    );
    assert_eq!(
        error.to_string(),
        "PAIRWISE_SUBJECT_SECRET is required when SUBJECT_TYPE=pairwise"
    );

    let weak = ConfigSource::from_pairs_for_test([
        ("SUBJECT_TYPE", "public"),
        ("PAIRWISE_SUBJECT_SECRET", "short"),
    ]);
    let error = settings_error(&weak, "weak pairwise subject secret must fail startup");
    assert_eq!(
        error.to_string(),
        "pairwise_subject_secret must be at least 32 bytes"
    );
}

fn settings_error(config: &ConfigSource, expected_context: &str) -> anyhow::Error {
    match Settings::from_config(config) {
        Ok(_) => panic!("{expected_context}"),
        Err(error) => error,
    }
}

#[test]
fn smtp_delivery_requires_paired_credentials() {
    for (key, value) in [
        ("EMAIL_SMTP_USERNAME", "smtp-user"),
        ("EMAIL_SMTP_PASSWORD", "smtp-password"),
    ] {
        let config = ConfigSource::from_pairs_for_test([
            ("EMAIL_DELIVERY", "smtp"),
            ("EMAIL_SMTP_HOST", "smtp.example.test"),
            ("EMAIL_FROM", "Nazo Auth <no-reply@example.test>"),
            (key, value),
        ]);

        let error = settings_error(
            &config,
            "SMTP must not start with only one authentication credential",
        );
        assert_eq!(
            error.to_string(),
            "EMAIL_SMTP_USERNAME and EMAIL_SMTP_PASSWORD must be configured together"
        );
    }
}

#[test]
fn smtp_delivery_rejects_invalid_sender_and_tls_mode() {
    let invalid_from = ConfigSource::from_pairs_for_test([
        ("EMAIL_DELIVERY", "smtp"),
        ("EMAIL_SMTP_HOST", "smtp.example.test"),
        ("EMAIL_FROM", "not a mailbox"),
    ]);

    let error = settings_error(
        &invalid_from,
        "SMTP sender must be a syntactically valid mailbox",
    );
    assert_eq!(error.to_string(), "EMAIL_FROM must be a valid mailbox");

    let invalid_tls = ConfigSource::from_pairs_for_test([
        ("EMAIL_DELIVERY", "smtp"),
        ("EMAIL_SMTP_HOST", "smtp.example.test"),
        ("EMAIL_FROM", "Nazo Auth <no-reply@example.test>"),
        ("EMAIL_SMTP_TLS", "opportunistic"),
    ]);

    let error = settings_error(&invalid_tls, "unknown SMTP TLS modes must fail closed");
    assert_eq!(
        error.to_string(),
        "EMAIL_SMTP_TLS must be starttls, implicit, or none, got opportunistic"
    );
}

#[test]
fn smtp_delivery_accepts_encrypted_tls_modes_without_secret_leakage() {
    for (raw, expected) in [
        ("starttls", SmtpTlsMode::StartTls),
        ("implicit", SmtpTlsMode::ImplicitTls),
    ] {
        let config = ConfigSource::from_pairs_for_test([
            ("EMAIL_DELIVERY", "smtp"),
            ("EMAIL_SMTP_HOST", "smtp.example.test"),
            ("EMAIL_FROM", "Nazo Auth <no-reply@example.test>"),
            ("EMAIL_SMTP_USERNAME", "smtp-user"),
            ("EMAIL_SMTP_PASSWORD", "smtp-password"),
            ("EMAIL_SMTP_TLS", raw),
        ]);

        let settings = Settings::from_config(&config).unwrap();
        let EmailDelivery::Smtp(smtp) = settings.identity.email.delivery else {
            panic!("smtp delivery should be enabled");
        };
        assert_eq!(smtp.host, "smtp.example.test");
        assert_eq!(smtp.username.as_deref(), Some("smtp-user"));
        assert_eq!(smtp.password.as_deref(), Some("smtp-password"));
        assert!(matches!(
            (smtp.tls, expected),
            (SmtpTlsMode::StartTls, SmtpTlsMode::StartTls)
                | (SmtpTlsMode::ImplicitTls, SmtpTlsMode::ImplicitTls)
                | (SmtpTlsMode::None, SmtpTlsMode::None)
        ));
    }
}

#[test]
fn smtp_delivery_allows_cleartext_only_for_credential_free_loopback_development() {
    let allowed = ConfigSource::from_pairs_for_test([
        ("ISSUER", "http://127.0.0.1:8000"),
        ("EMAIL_DELIVERY", "smtp"),
        ("EMAIL_SMTP_HOST", "localhost"),
        ("EMAIL_FROM", "Nazo Auth <no-reply@example.test>"),
        ("EMAIL_SMTP_TLS", "none"),
    ]);
    let settings = Settings::from_config(&allowed).expect("loopback development SMTP");
    let EmailDelivery::Smtp(smtp) = settings.identity.email.delivery else {
        panic!("smtp delivery should be enabled");
    };
    assert!(matches!(smtp.tls, SmtpTlsMode::None));

    for config in [
        ConfigSource::from_pairs_for_test([
            ("ISSUER", "https://auth.example.test"),
            (
                "CLIENT_SECRET_PEPPER",
                "test-client-secret-pepper-that-is-long-enough-0001",
            ),
            ("EMAIL_DELIVERY", "smtp"),
            ("EMAIL_SMTP_HOST", "localhost"),
            ("EMAIL_FROM", "Nazo Auth <no-reply@example.test>"),
            ("EMAIL_SMTP_TLS", "none"),
        ]),
        ConfigSource::from_pairs_for_test([
            ("ISSUER", "http://127.0.0.1:8000"),
            ("EMAIL_DELIVERY", "smtp"),
            ("EMAIL_SMTP_HOST", "localhost"),
            ("EMAIL_FROM", "Nazo Auth <no-reply@example.test>"),
            ("EMAIL_SMTP_USERNAME", "user"),
            ("EMAIL_SMTP_PASSWORD", "password"),
            ("EMAIL_SMTP_TLS", "none"),
        ]),
    ] {
        assert_eq!(
            settings_error(&config, "cleartext SMTP must fail closed").to_string(),
            "EMAIL_SMTP_TLS=none is restricted to credential-free loopback development"
        );
    }
}

#[test]
fn email_code_dev_response_requires_debug_loopback_issuer() {
    let allowed = ConfigSource::from_pairs_for_test([
        ("ISSUER", "http://localhost:8000"),
        ("EMAIL_CODE_DEV_RESPONSE_ENABLED", "true"),
    ]);
    let allowed_result = Settings::from_config(&allowed);
    if cfg!(debug_assertions) {
        assert!(
            allowed_result
                .expect("debug loopback issuer")
                .identity
                .email_code_dev_response_enabled
        );
    } else {
        let Err(error) = allowed_result else {
            panic!("release build must reject verification-code response")
        };
        assert_eq!(
            error.to_string(),
            "EMAIL_CODE_DEV_RESPONSE_ENABLED=true requires a debug build and loopback HTTP issuer"
        );
    }

    let public = ConfigSource::from_pairs_for_test([
        ("ISSUER", "https://auth.example.test"),
        (
            "CLIENT_SECRET_PEPPER",
            "test-client-secret-pepper-that-is-long-enough-0001",
        ),
        ("EMAIL_CODE_DEV_RESPONSE_ENABLED", "true"),
    ]);
    assert_eq!(
        settings_error(&public, "public issuer must not return verification codes").to_string(),
        "EMAIL_CODE_DEV_RESPONSE_ENABLED=true requires a debug build and loopback HTTP issuer"
    );
}

fn oidc_provider_registry_config_with(
    override_key: &'static str,
    override_value: &str,
) -> ConfigSource {
    // OIDC 配置只通过 FEDERATION_PROVIDER_CONFIGS 进入系统；测试覆盖同一输入面。
    let mut provider = json!({
        "provider_id": "oidc-upstream",
        "enabled": true,
        "display_name": "OIDC",
        "adapter_type": "oidc",
        "issuer": "https://idp.example.test",
        "authorization_endpoint": "https://idp.example.test/authorize",
        "token_endpoint": "https://idp.example.test/token",
        "jwks_url": "https://idp.example.test/jwks",
        "client_id": "client-1",
        "client_secret": "secret-1",
        "redirect_uri": "https://auth.example.test/auth/federation/oidc-upstream/callback",
        "scopes": "openid email profile",
    });
    provider[override_key] = json!(override_value);
    ConfigSource::from_owned_pairs_for_test([(
        "FEDERATION_PROVIDER_CONFIGS".to_owned(),
        json!([provider]).to_string(),
    )])
}

#[test]
fn oidc_federation_rejects_insecure_runtime_urls() {
    for (key, value) in [
        ("issuer", "http://idp.example.test"),
        (
            "authorization_endpoint",
            "http://idp.example.test/authorize",
        ),
        ("token_endpoint", "http://idp.example.test/token"),
        ("jwks_url", "http://idp.example.test/jwks"),
        (
            "redirect_uri",
            "http://auth.example.test/auth/federation/oidc-upstream/callback",
        ),
    ] {
        let config = oidc_provider_registry_config_with(key, value);

        let error = settings_error(
            &config,
            "OIDC federation URLs must remain HTTPS except loopback development URLs",
        );
        assert!(
            error.to_string().contains("https"),
            "unexpected error for {key}: {error}"
        );
    }
}

#[test]
fn oidc_federation_requires_openid_scope() {
    let config = oidc_provider_registry_config_with("scopes", "email profile");

    let error = settings_error(
        &config,
        "OIDC federation without openid scope cannot produce an OIDC identity",
    );
    assert_eq!(
        error.to_string(),
        "FEDERATION_PROVIDER_CONFIGS must include openid"
    );
}

#[test]
fn federation_provider_registry_parses_enabled_oidc_and_social_modules() {
    let config = ConfigSource::from_pairs_for_test([(
        "FEDERATION_PROVIDER_CONFIGS",
        r#"[
            {
                "provider_id": "google",
                "enabled": true,
                "display_name": "Google",
                "adapter_type": "oidc",
                "display_order": 20,
                "issuer": "https://accounts.google.com",
                "authorization_endpoint": "https://accounts.google.com/o/oauth2/v2/auth",
                "token_endpoint": "https://oauth2.googleapis.com/token",
                "jwks_url": "https://www.googleapis.com/oauth2/v3/certs",
                "client_id": "google-client",
                "client_secret": "google-secret",
                "redirect_uri": "https://auth.example.test/auth/federation/google/callback",
                "scopes": "openid email profile"
            },
            {
                "provider_id": "qq",
                "enabled": true,
                "display_name": "QQ",
                "adapter_type": "oauth2_social",
                "provider_kind": "qq",
                "display_order": 10,
                "client_id": "qq-client",
                "client_secret": "qq-secret",
                "redirect_uri": "https://auth.example.test/auth/federation/qq/callback"
            },
            {
                "provider_id": "disabled",
                "enabled": false,
                "display_name": "Disabled",
                "adapter_type": "oauth2_social",
                "provider_kind": "wechat",
                "client_id": "disabled-client",
                "client_secret": "disabled-secret",
                "redirect_uri": "https://auth.example.test/auth/federation/disabled/callback"
            }
        ]"#,
    )]);

    let settings = Settings::from_config(&config).unwrap();
    let providers = settings
        .identity
        .federation
        .providers
        .enabled_public_providers()
        .collect::<Vec<_>>();

    assert_eq!(providers.len(), 2);
    assert_eq!(providers[0].provider_id, "qq");
    assert_eq!(providers[0].display_name, "QQ");
    assert_eq!(providers[0].adapter_type(), "oauth2_social");
    match &providers[0].adapter {
        ExternalLoginProviderAdapter::Social(social) => {
            assert_eq!(social.kind, SocialProviderKind::Qq);
            assert_eq!(social.scopes, "get_user_info");
            assert_eq!(social.subject_claim, "openid");
            assert_eq!(
                social.openid_endpoint.as_deref(),
                Some("https://graph.qq.com/oauth2.0/me")
            );
        }
        ExternalLoginProviderAdapter::Oidc(_) => panic!("QQ must use the social adapter"),
    }

    assert_eq!(providers[1].provider_id, "google");
    assert_eq!(providers[1].adapter_type(), "oidc");
    assert!(
        settings
            .identity
            .federation
            .providers
            .enabled_provider("disabled")
            .is_none(),
        "disabled provider must not be visible to login surfaces"
    );
}

#[test]
fn federation_provider_registry_fails_closed_for_incomplete_enabled_provider() {
    let config = ConfigSource::from_pairs_for_test([(
        "FEDERATION_PROVIDER_CONFIGS",
        r#"[{
            "provider_id": "google",
            "enabled": true,
            "display_name": "Google",
            "adapter_type": "oidc",
            "issuer": "https://accounts.google.com"
        }]"#,
    )]);

    let error = settings_error(&config, "incomplete provider config must fail closed");
    assert_eq!(
        error.to_string(),
        "authorization_endpoint is required for enabled federation provider"
    );
}

#[test]
fn federation_provider_registry_rejects_duplicate_provider_ids() {
    let config = ConfigSource::from_pairs_for_test([(
        "FEDERATION_PROVIDER_CONFIGS",
        r#"[
            {
                "provider_id": "google",
                "enabled": false,
                "display_name": "Google A",
                "adapter_type": "oauth2_social",
                "provider_kind": "qq",
                "client_id": "a",
                "client_secret": "a-secret",
                "redirect_uri": "https://auth.example.test/auth/federation/google/callback"
            },
            {
                "provider_id": "google",
                "enabled": false,
                "display_name": "Google B",
                "adapter_type": "oauth2_social",
                "provider_kind": "wechat",
                "client_id": "b",
                "client_secret": "b-secret",
                "redirect_uri": "https://auth.example.test/auth/federation/google-b/callback"
            }
        ]"#,
    )]);

    let error = settings_error(&config, "duplicate provider ids must fail closed");
    assert_eq!(error.to_string(), "duplicate federation provider_id google");
}

#[test]
fn saml_gateway_requires_strong_shared_secret_when_enabled() {
    let config = ConfigSource::from_pairs_for_test([
        ("FEDERATION_SAML_GATEWAY_ENABLED", "true"),
        (
            "FEDERATION_SAML_GATEWAY_ISSUER",
            "https://auth.example.test",
        ),
        (
            "FEDERATION_SAML_GATEWAY_AUDIENCE",
            "https://sp.example.test",
        ),
        ("FEDERATION_SAML_GATEWAY_SECRET", "short"),
    ]);

    let error = settings_error(&config, "SAML gateway MAC secret must not be weak");
    assert_eq!(
        error.to_string(),
        "FEDERATION_SAML_GATEWAY_SECRET must be at least 32 bytes"
    );
}
#[test]
fn fapi_http_signature_settings_default_closed() {
    let settings = Settings::from_config(&ConfigSource::default()).unwrap();

    assert!(!settings.modules.enable_fapi_http_signatures);
    assert_eq!(settings.protocol.fapi_http_signature_max_age_seconds, 60);
}

#[test]
fn fapi_http_signature_max_age_accepts_inclusive_boundaries() {
    for value in ["1", "300"] {
        let config = ConfigSource::from_pairs_for_test([
            ("ENABLE_FAPI_HTTP_SIGNATURES", "true"),
            ("FAPI_HTTP_SIGNATURE_MAX_AGE_SECONDS", value),
        ]);
        let settings = Settings::from_config(&config).unwrap();

        assert!(settings.modules.enable_fapi_http_signatures);
        assert_eq!(
            settings
                .protocol
                .fapi_http_signature_max_age_seconds
                .to_string(),
            value
        );
    }
}

#[test]
fn fapi_http_signature_max_age_rejects_invalid_values() {
    for value in ["0", "301", "not-an-integer"] {
        let config =
            ConfigSource::from_pairs_for_test([("FAPI_HTTP_SIGNATURE_MAX_AGE_SECONDS", value)]);
        assert!(Settings::from_config(&config).is_err(), "accepted {value}");
    }
}
