use std::collections::BTreeSet;

use nazo_runtime_modules::{ActiveModuleSnapshot, ModuleId, ModuleRevision};
use serde_json::{Value, json};

use super::*;

const ACTIVE_RS256: &[&str] = &["RS256"];
const ID_TOKEN_RS256: &[&str] = &["RS256"];
const RESPONSE_RS256: &[&str] = &["RS256"];

fn input() -> AuthorizationServerMetadataInput<'static> {
    AuthorizationServerMetadataInput {
        issuer: "https://issuer.example",
        mtls_endpoint_base_url: "https://mtls.issuer.example",
        mtls_enabled: false,
        profile: MetadataAuthorizationServerProfile::Oauth2Baseline,
        ciba_profile: CibaMetadataProfile::FapiCiba,
        subject_type: MetadataSubjectType::Public,
        pairwise_subject_enabled: false,
        protected_resource_identifier: "https://issuer.example/fapi/resource",
        require_pushed_authorization_requests: false,
        request_uri_parameter_enabled: false,
        signing_algorithms: MetadataSigningAlgorithms {
            active: ACTIVE_RS256,
            id_token: ID_TOKEN_RS256,
            response: RESPONSE_RS256,
        },
    }
}

fn snapshot(accepting: impl IntoIterator<Item = ModuleId>) -> ActiveModuleSnapshot {
    ActiveModuleSnapshot {
        revision: ModuleRevision::new(7),
        accepting: accepting.into_iter().collect(),
        draining: BTreeSet::new(),
    }
}

fn resource_input(mtls_enabled: bool) -> ProtectedResourceMetadataInput<'static> {
    ProtectedResourceMetadataInput {
        issuer: "https://issuer.example",
        protected_resource_identifier: "https://issuer.example/fapi/resource",
        mtls_enabled,
    }
}

fn merge(parts: impl IntoIterator<Item = Value>) -> Value {
    let mut merged = serde_json::Map::new();
    for part in parts {
        merged.extend(
            part.as_object()
                .expect("metadata fixture part must be an object")
                .clone(),
        );
    }
    Value::Object(merged)
}

#[test]
fn baseline_document_shape_is_locked() {
    let actual = authorization_server_metadata(
        input(),
        &snapshot([
            ModuleId::JwtBearerGrant,
            ModuleId::TokenExchange,
            ModuleId::Jarm,
        ]),
    );

    assert_eq!(
        actual,
        merge([
            json!({
                "issuer": "https://issuer.example",
                "authorization_endpoint": "https://issuer.example/authorize",
                "token_endpoint": "https://issuer.example/token",
                "end_session_endpoint": "https://issuer.example/logout",
                "pushed_authorization_request_endpoint": "https://issuer.example/par",
                "revocation_endpoint": "https://issuer.example/revoke",
                "introspection_endpoint": "https://issuer.example/introspect",
                "userinfo_endpoint": "https://issuer.example/userinfo",
                "jwks_uri": "https://issuer.example/jwks.json",
                "response_types_supported": ["code"],
                "response_modes_supported": ["query", "jwt"],
                "subject_types_supported": ["public"],
                "id_token_signing_alg_values_supported": ["RS256"],
                "userinfo_signing_alg_values_supported": ["RS256"],
                "userinfo_encryption_alg_values_supported": ["RSA-OAEP-256"],
                "userinfo_encryption_enc_values_supported": ["A256GCM"],
                "authorization_signing_alg_values_supported": ["RS256"],
                "authorization_encryption_alg_values_supported": ["RSA-OAEP-256"],
                "authorization_encryption_enc_values_supported": ["A256GCM"]
            }),
            json!({
                "token_endpoint_auth_methods_supported": [
                    "client_secret_basic", "client_secret_post", "private_key_jwt", "none"
                ],
                "token_endpoint_auth_signing_alg_values_supported": [
                    "EdDSA", "RS256", "ES256", "PS256"
                ],
                "revocation_endpoint_auth_methods_supported": [
                    "client_secret_basic", "client_secret_post", "private_key_jwt", "none"
                ],
                "revocation_endpoint_auth_signing_alg_values_supported": [
                    "EdDSA", "RS256", "ES256", "PS256"
                ],
                "introspection_endpoint_auth_methods_supported": [
                    "client_secret_basic", "client_secret_post", "private_key_jwt", "none"
                ],
                "introspection_endpoint_auth_signing_alg_values_supported": [
                    "EdDSA", "RS256", "ES256", "PS256"
                ],
                "scopes_supported": [
                    "openid", "profile", "email", "address", "phone", "offline_access"
                ],
                "claims_supported": [
                    "sub", "auth_time", "amr", "nonce", "acr", "preferred_username", "name",
                    "given_name", "family_name", "middle_name", "nickname", "profile", "picture",
                    "website", "gender", "birthdate", "zoneinfo", "locale", "email",
                    "email_verified", "address", "phone_number", "phone_number_verified",
                    "updated_at"
                ]
            }),
            json!({
                "acr_values_supported": ["1"],
                "prompt_values_supported": ["login", "consent", "select_account", "none"],
                "grant_types_supported": [
                    "authorization_code", "refresh_token", "client_credentials",
                    "urn:ietf:params:oauth:grant-type:jwt-bearer",
                    "urn:ietf:params:oauth:grant-type:token-exchange"
                ],
                "protected_resources": ["https://issuer.example/fapi/resource"],
                "authorization_response_iss_parameter_supported": true,
                "claims_parameter_supported": true,
                "backchannel_logout_supported": true,
                "backchannel_logout_session_supported": true,
                "require_pushed_authorization_requests": false,
                "code_challenge_methods_supported": ["S256"],
                "dpop_signing_alg_values_supported": ["EdDSA", "ES256"],
                "request_object_signing_alg_values_supported": [
                    "none", "EdDSA", "RS256", "ES256", "PS256"
                ],
                "request_uri_parameter_supported": false
            }),
        ])
    );
}

#[test]
fn runtime_module_advertisements_are_table_driven() {
    struct Case {
        module: ModuleId,
        field: &'static str,
        expected: Value,
    }

    let cases = [
        Case {
            module: ModuleId::DeviceAuthorization,
            field: "device_authorization_endpoint",
            expected: json!("https://issuer.example/device_authorization"),
        },
        Case {
            module: ModuleId::Ciba,
            field: "backchannel_authentication_endpoint",
            expected: json!("https://issuer.example/bc-authorize"),
        },
        Case {
            module: ModuleId::DynamicClientRegistration,
            field: "registration_endpoint",
            expected: json!("https://issuer.example/register"),
        },
        Case {
            module: ModuleId::RequestObjects,
            field: "request_parameter_supported",
            expected: json!(true),
        },
        Case {
            module: ModuleId::AuthorizationDetails,
            field: "authorization_details_types_supported",
            expected: json!(["account_information", "payment_initiation"]),
        },
        Case {
            module: ModuleId::NativeSso,
            field: "native_sso_supported",
            expected: json!(true),
        },
        Case {
            module: ModuleId::FrontchannelLogout,
            field: "frontchannel_logout_supported",
            expected: json!(true),
        },
        Case {
            module: ModuleId::SessionManagement,
            field: "check_session_iframe",
            expected: json!("https://issuer.example/check_session"),
        },
    ];

    let disabled = authorization_server_metadata(input(), &snapshot([]));
    for case in cases {
        assert!(
            disabled.get(case.field).is_none(),
            "{} must be absent while {:?} is disabled",
            case.field,
            case.module
        );
        let enabled = authorization_server_metadata(input(), &snapshot([case.module]));
        assert_eq!(
            enabled.get(case.field),
            Some(&case.expected),
            "{} must follow {:?}",
            case.field,
            case.module
        );
    }
}

#[test]
fn grant_modules_change_only_the_typed_grant_catalog() {
    let cases = [
        (
            ModuleId::JwtBearerGrant,
            "urn:ietf:params:oauth:grant-type:jwt-bearer",
        ),
        (
            ModuleId::TokenExchange,
            "urn:ietf:params:oauth:grant-type:token-exchange",
        ),
        (
            ModuleId::DeviceAuthorization,
            "urn:ietf:params:oauth:grant-type:device_code",
        ),
        (ModuleId::Ciba, "urn:openid:params:grant-type:ciba"),
    ];

    for (module, grant) in cases {
        let metadata = authorization_server_metadata(input(), &snapshot([module]));
        let grants = metadata["grant_types_supported"]
            .as_array()
            .expect("grant catalog must be an array");
        assert!(grants.iter().any(|value| value == grant), "{module:?}");
    }
}

#[test]
fn jarm_capability_controls_jwt_response_mode() {
    let disabled = authorization_server_metadata(input(), &snapshot([]));
    let enabled = authorization_server_metadata(input(), &snapshot([ModuleId::Jarm]));

    assert_eq!(disabled["response_modes_supported"], json!(["query"]));
    assert_eq!(enabled["response_modes_supported"], json!(["query", "jwt"]));
}

#[test]
fn draining_modules_are_not_advertised_as_accepting_new_transactions() {
    let snapshot = ActiveModuleSnapshot {
        revision: ModuleRevision::new(8),
        accepting: BTreeSet::new(),
        draining: ModuleId::ALL.into_iter().collect(),
    };
    let metadata = authorization_server_metadata(input(), &snapshot);

    assert_eq!(
        metadata["grant_types_supported"],
        json!(["authorization_code", "refresh_token", "client_credentials"])
    );
    for field in [
        "device_authorization_endpoint",
        "backchannel_authentication_endpoint",
        "registration_endpoint",
        "request_parameter_supported",
        "authorization_details_types_supported",
        "native_sso_supported",
        "frontchannel_logout_supported",
        "check_session_iframe",
    ] {
        assert!(metadata.get(field).is_none(), "unexpected field {field}");
    }
}

#[test]
fn non_standard_http_signatures_and_scim_do_not_mutate_standard_metadata() {
    let baseline = authorization_server_metadata(input(), &snapshot([]));
    for module in [ModuleId::HttpMessageSignatures, ModuleId::Scim] {
        assert_eq!(
            authorization_server_metadata(input(), &snapshot([module])),
            baseline,
            "{module:?} must not invent a standard discovery field"
        );
    }
}

#[test]
fn ciba_metadata_is_complete_and_profile_scoped() {
    let snapshot = snapshot([ModuleId::Ciba]);
    let baseline = authorization_server_metadata(input(), &snapshot);
    assert_eq!(
        baseline["backchannel_token_delivery_modes_supported"],
        json!(["poll"])
    );
    assert_eq!(
        baseline["backchannel_user_code_parameter_supported"],
        json!(false)
    );
    assert_eq!(
        baseline["backchannel_authentication_request_signing_alg_values_supported"],
        json!(["EdDSA", "ES256", "PS256"])
    );

    let hardened = authorization_server_metadata(
        AuthorizationServerMetadataInput {
            ciba_profile: CibaMetadataProfile::Fapi2Ciba,
            ..input()
        },
        &snapshot,
    );
    assert_eq!(
        hardened["token_endpoint_auth_methods_supported"],
        json!(["private_key_jwt"])
    );
    assert_eq!(
        hardened["token_endpoint_auth_signing_alg_values_supported"],
        json!(["EdDSA", "ES256", "PS256"])
    );
}

#[test]
fn fapi_profiles_publish_only_the_selected_security_contract() {
    const ACTIVE_PS256: &[&str] = &["PS256"];
    const RESPONSE_PS256: &[&str] = &["PS256"];
    let snapshot = snapshot([ModuleId::Jarm]);
    let cases = [
        (
            MetadataAuthorizationServerProfile::Fapi2Security,
            json!(["query", "jwt"]),
            json!(["EdDSA", "RS256", "ES256", "PS256"]),
            false,
        ),
        (
            MetadataAuthorizationServerProfile::Fapi2MessageSigningAuthorizationRequest,
            json!(["query", "jwt"]),
            json!(["PS256"]),
            false,
        ),
        (
            MetadataAuthorizationServerProfile::Fapi2MessageSigningJarm,
            json!(["jwt"]),
            json!(["EdDSA", "RS256", "ES256", "PS256"]),
            false,
        ),
        (
            MetadataAuthorizationServerProfile::Fapi2MessageSigningIntrospection,
            json!(["query", "jwt"]),
            json!(["EdDSA", "RS256", "ES256", "PS256"]),
            true,
        ),
    ];

    for (profile, response_modes, request_algs, signed_introspection) in cases {
        let metadata = authorization_server_metadata(
            AuthorizationServerMetadataInput {
                profile,
                require_pushed_authorization_requests: true,
                signing_algorithms: MetadataSigningAlgorithms {
                    active: ACTIVE_PS256,
                    id_token: ACTIVE_PS256,
                    response: RESPONSE_PS256,
                },
                ..input()
            },
            &snapshot,
        );
        assert_eq!(metadata["response_modes_supported"], response_modes);
        assert_eq!(
            metadata["request_object_signing_alg_values_supported"],
            request_algs
        );
        assert_eq!(
            metadata.get("introspection_signing_alg_values_supported"),
            signed_introspection.then_some(&json!(["PS256"]))
        );
        assert_eq!(
            metadata["token_endpoint_auth_methods_supported"],
            json!(["private_key_jwt"])
        );
        assert_eq!(metadata["require_pushed_authorization_requests"], true);
    }
}

#[test]
fn request_uri_subject_and_mtls_configuration_are_preserved_exactly() {
    const ACTIVE_PS256: &[&str] = &["PS256"];
    const RESPONSE: &[&str] = &["PS256", "EdDSA"];
    let metadata = authorization_server_metadata(
        AuthorizationServerMetadataInput {
            mtls_enabled: true,
            subject_type: MetadataSubjectType::Pairwise,
            pairwise_subject_enabled: true,
            request_uri_parameter_enabled: true,
            signing_algorithms: MetadataSigningAlgorithms {
                active: ACTIVE_PS256,
                id_token: ACTIVE_PS256,
                response: RESPONSE,
            },
            ..input()
        },
        &snapshot([]),
    );

    assert_eq!(metadata["subject_types_supported"], json!(["pairwise"]));
    assert_eq!(
        metadata["id_token_signing_alg_values_supported"],
        json!(["PS256", "RS256"])
    );
    assert_eq!(
        metadata["userinfo_signing_alg_values_supported"],
        json!(["PS256", "EdDSA"])
    );
    assert_eq!(metadata["request_uri_parameter_supported"], true);
    assert_eq!(metadata["require_request_uri_registration"], true);
    assert_eq!(
        metadata["token_endpoint_auth_methods_supported"],
        json!([
            "client_secret_basic",
            "client_secret_post",
            "private_key_jwt",
            "tls_client_auth",
            "self_signed_tls_client_auth",
            "none"
        ])
    );
    assert_eq!(
        metadata.pointer("/mtls_endpoint_aliases/token_endpoint"),
        Some(&json!("https://mtls.issuer.example/token"))
    );
}

#[test]
fn id_token_metadata_includes_non_primary_eligible_signing_keys() {
    const ID_TOKEN_ALGORITHMS: &[&str] = &["RS256", "PS256"];
    const RESPONSE_ALGORITHMS: &[&str] = &["RS256", "PS256"];
    let metadata = authorization_server_metadata(
        AuthorizationServerMetadataInput {
            signing_algorithms: MetadataSigningAlgorithms {
                active: ACTIVE_RS256,
                id_token: ID_TOKEN_ALGORITHMS,
                response: RESPONSE_ALGORITHMS,
            },
            ..input()
        },
        &snapshot([]),
    );

    assert_eq!(
        metadata["id_token_signing_alg_values_supported"],
        json!(["PS256", "RS256"])
    );
}

#[test]
fn protected_resource_metadata_uses_the_same_rar_snapshot() {
    let disabled = protected_resource_metadata(resource_input(false), &snapshot([]));
    assert_eq!(
        disabled,
        json!({
            "resource": "https://issuer.example/fapi/resource",
            "authorization_servers": ["https://issuer.example"],
            "resource_name": "Nazo OAuth Protected Resource",
            "bearer_methods_supported": ["header", "body"],
            "scopes_supported": [
                "openid", "profile", "email", "address", "phone", "offline_access"
            ],
            "dpop_signing_alg_values_supported": ["EdDSA", "ES256"]
        })
    );

    let enabled = protected_resource_metadata(
        resource_input(true),
        &snapshot([ModuleId::AuthorizationDetails]),
    );
    assert_eq!(
        enabled["authorization_details_types_supported"],
        json!(["account_information", "payment_initiation"])
    );
    assert_eq!(enabled["tls_client_certificate_bound_access_tokens"], true);
}
