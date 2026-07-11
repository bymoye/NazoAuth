use super::prelude::*;
use crate::domain::Keyset;
use crate::http::authorization::BASELINE_ACR_VALUE;
use crate::http::token::{
    CIBA_GRANT_TYPE, DEVICE_CODE_GRANT_TYPE, JWT_BEARER_GRANT_TYPE, TOKEN_EXCHANGE_GRANT_TYPE,
};
use crate::settings::{AuthorizationServerProfile, CibaSecurityProfile, Settings, SubjectType};
use crate::support::{
    SUPPORTED_CLIENT_JWE_CONTENT_ENC_ALGS, SUPPORTED_CLIENT_JWE_KEY_MANAGEMENT_ALGS,
};

const CLIENT_JWT_SIGNING_ALGS: [&str; 4] = ["EdDSA", "RS256", "ES256", "PS256"];
const DPOP_SIGNING_ALGS: [&str; 2] = ["EdDSA", "ES256"];
const FAPI_CIBA_REQUEST_OBJECT_SIGNING_ALGS: [&str; 3] = ["EdDSA", "ES256", "PS256"];
const REQUEST_OBJECT_SIGNING_ALGS: [&str; 4] = ["EdDSA", "RS256", "ES256", "PS256"];
const BASELINE_REQUEST_OBJECT_SIGNING_ALGS: [&str; 5] =
    ["none", "EdDSA", "RS256", "ES256", "PS256"];
const PROMPT_VALUES_SUPPORTED: [&str; 4] = ["login", "consent", "select_account", "none"];
const CLAIMS_SUPPORTED: [&str; 24] = [
    "sub",
    "auth_time",
    "amr",
    "nonce",
    "acr",
    "preferred_username",
    "name",
    "given_name",
    "family_name",
    "middle_name",
    "nickname",
    "profile",
    "picture",
    "website",
    "gender",
    "birthdate",
    "zoneinfo",
    "locale",
    "email",
    "email_verified",
    "address",
    "phone_number",
    "phone_number_verified",
    "updated_at",
];
const CLIENT_AUTH_METHODS: [&str; 6] = [
    "client_secret_basic",
    "client_secret_post",
    "private_key_jwt",
    "tls_client_auth",
    "self_signed_tls_client_auth",
    "none",
];
const FAPI2_CLIENT_AUTH_METHODS: [&str; 3] = [
    "private_key_jwt",
    "tls_client_auth",
    "self_signed_tls_client_auth",
];
const SCOPES_SUPPORTED: [&str; 6] = [
    "openid",
    "profile",
    "email",
    "address",
    "phone",
    "offline_access",
];

pub(crate) async fn health() -> Json<Value> {
    Json(json!({"status": "正常"}))
}

pub(crate) async fn captcha_config() -> Json<Value> {
    Json(json!({
        "turnstile_enabled": false,
        "turnstile_site_key": null,
        "registration_enabled": true
    }))
}

fn authorization_server_metadata_value(state: &AppState) -> Value {
    let keyset = state.keyset.snapshot();
    authorization_server_metadata(&state.settings, &keyset)
}

fn authorization_server_metadata(settings: &Settings, keyset: &Keyset) -> Value {
    let issuer = settings.issuer.as_str();
    let mtls_base = settings.mtls_endpoint_base_url.as_str();
    let id_token_signing_algs = id_token_signing_alg_values_supported(keyset);
    let authorization_signing_algs = active_signing_alg_values_supported(keyset);
    let mtls_enabled = !settings.trusted_proxy_cidrs.is_empty();
    let token_auth_methods = token_endpoint_auth_methods_supported(
        settings.authorization_server_profile,
        settings.ciba_security_profile,
        mtls_enabled,
    );
    let token_auth_signing_algs = token_endpoint_auth_signing_alg_values_supported(settings);
    let request_object_signing_algs = request_object_signing_alg_values_supported(
        settings.authorization_server_profile,
        authorization_signing_algs.as_slice(),
    );
    let response_modes = response_modes_supported(settings.authorization_server_profile);
    let mut grant_types = vec![
        "authorization_code",
        "refresh_token",
        "client_credentials",
        JWT_BEARER_GRANT_TYPE,
        TOKEN_EXCHANGE_GRANT_TYPE,
    ];
    if settings.enable_device_authorization_grant {
        grant_types.push(DEVICE_CODE_GRANT_TYPE);
    }
    if settings.enable_ciba {
        grant_types.push(CIBA_GRANT_TYPE);
    }
    let mut scopes_supported = SCOPES_SUPPORTED.to_vec();
    if settings.enable_native_sso {
        scopes_supported.push("device_sso");
    }
    let mut metadata = json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}/authorize"),
        "token_endpoint": format!("{issuer}/token"),
        "end_session_endpoint": format!("{issuer}/logout"),
        "pushed_authorization_request_endpoint": format!("{issuer}/par"),
        "revocation_endpoint": format!("{issuer}/revoke"),
        "introspection_endpoint": format!("{issuer}/introspect"),
        "userinfo_endpoint": format!("{issuer}/userinfo"),
        "jwks_uri": format!("{issuer}/jwks.json"),
        "response_types_supported": ["code"],
        "response_modes_supported": response_modes,
        "subject_types_supported": match (&settings.pairwise_subject_secret, &settings.subject_type) {
            (None, _) => vec!["public"],
            (Some(_), SubjectType::Pairwise) => vec!["pairwise"],
            (Some(_), _) => vec!["public", "pairwise"],
        },
        "id_token_signing_alg_values_supported": id_token_signing_algs,
        "authorization_signing_alg_values_supported": authorization_signing_algs,
        "token_endpoint_auth_methods_supported": token_auth_methods,
        "token_endpoint_auth_signing_alg_values_supported": token_auth_signing_algs,
        "revocation_endpoint_auth_methods_supported": token_auth_methods,
        "revocation_endpoint_auth_signing_alg_values_supported": CLIENT_JWT_SIGNING_ALGS,
        "introspection_endpoint_auth_methods_supported": token_auth_methods,
        "introspection_endpoint_auth_signing_alg_values_supported": CLIENT_JWT_SIGNING_ALGS,
        "scopes_supported": scopes_supported,
        "claims_supported": CLAIMS_SUPPORTED,
        "acr_values_supported": [BASELINE_ACR_VALUE],
        "prompt_values_supported": PROMPT_VALUES_SUPPORTED,
        "grant_types_supported": grant_types,
        "protected_resources": [settings.protected_resource_identifier.as_str()],
        "authorization_response_iss_parameter_supported": true,
        "claims_parameter_supported": true,
        "backchannel_logout_supported": true,
        "backchannel_logout_session_supported": true,
        "require_pushed_authorization_requests": settings.require_pushed_authorization_requests,
        "code_challenge_methods_supported": ["S256"],
        "dpop_signing_alg_values_supported": DPOP_SIGNING_ALGS,
        "request_object_signing_alg_values_supported": request_object_signing_algs
    });
    if settings.enable_authorization_details {
        metadata["authorization_details_types_supported"] =
            json!(["account_information", "payment_initiation"]);
    }
    if settings.enable_device_authorization_grant {
        metadata["device_authorization_endpoint"] = json!(format!("{issuer}/device_authorization"));
    }
    if settings.enable_dynamic_client_registration {
        metadata["registration_endpoint"] = json!(format!("{issuer}/register"));
    }
    if settings.enable_frontchannel_logout {
        metadata["frontchannel_logout_supported"] = json!(true);
        metadata["frontchannel_logout_session_supported"] = json!(true);
    }
    if settings.enable_session_management {
        metadata["check_session_iframe"] = json!(format!("{issuer}/check_session"));
    }
    if settings.enable_ciba {
        metadata["backchannel_authentication_endpoint"] = json!(format!("{issuer}/bc-authorize"));
        metadata["backchannel_token_delivery_modes_supported"] = json!(["poll"]);
        metadata["backchannel_user_code_parameter_supported"] = json!(false);
        metadata["backchannel_authentication_request_signing_alg_values_supported"] =
            json!(FAPI_CIBA_REQUEST_OBJECT_SIGNING_ALGS);
    }
    if settings.enable_native_sso {
        metadata["native_sso_supported"] = json!(true);
    }
    if settings
        .authorization_server_profile
        .requires_signed_introspection()
    {
        metadata["introspection_signing_alg_values_supported"] =
            json!(active_signing_alg_values_supported(keyset));
        metadata["introspection_encryption_alg_values_supported"] =
            json!(SUPPORTED_CLIENT_JWE_KEY_MANAGEMENT_ALGS);
        metadata["introspection_encryption_enc_values_supported"] =
            json!(SUPPORTED_CLIENT_JWE_CONTENT_ENC_ALGS);
    }
    if settings.enable_request_object {
        metadata["request_parameter_supported"] = json!(true);
    }
    if settings.enable_request_uri_parameter {
        metadata["request_uri_parameter_supported"] = json!(true);
        metadata["require_request_uri_registration"] = json!(true);
    } else {
        metadata["request_uri_parameter_supported"] = json!(false);
    }
    if mtls_enabled {
        metadata["tls_client_certificate_bound_access_tokens"] = json!(true);
        metadata["mtls_endpoint_aliases"] = json!({
            "token_endpoint": format!("{mtls_base}/token"),
            "pushed_authorization_request_endpoint": format!("{mtls_base}/par"),
            "revocation_endpoint": format!("{mtls_base}/revoke"),
            "introspection_endpoint": format!("{mtls_base}/introspect"),
            "userinfo_endpoint": format!("{mtls_base}/userinfo")
        });
    }
    metadata
}

fn protected_resource_metadata(settings: &Settings, _keyset: &Keyset) -> Value {
    let mtls_enabled = !settings.trusted_proxy_cidrs.is_empty();
    let mut metadata = json!({
        "resource": settings.protected_resource_identifier.as_str(),
        "authorization_servers": [settings.issuer.as_str()],
        "resource_name": "Nazo OAuth Protected Resource",
        "bearer_methods_supported": ["header", "body"],
        "scopes_supported": SCOPES_SUPPORTED,
        "dpop_signing_alg_values_supported": DPOP_SIGNING_ALGS
    });
    if mtls_enabled {
        metadata["tls_client_certificate_bound_access_tokens"] = json!(true);
    }
    if settings.enable_authorization_details {
        metadata["authorization_details_types_supported"] =
            json!(["account_information", "payment_initiation"]);
    }
    metadata
}

fn token_endpoint_auth_methods_supported(
    profile: AuthorizationServerProfile,
    ciba_profile: CibaSecurityProfile,
    mtls_enabled: bool,
) -> Vec<&'static str> {
    let methods = if profile.requires_fapi2_security() || ciba_profile.requires_fapi2_hardening() {
        FAPI2_CLIENT_AUTH_METHODS.as_slice()
    } else {
        CLIENT_AUTH_METHODS.as_slice()
    };
    methods
        .iter()
        .copied()
        .filter(|method| {
            mtls_enabled || !matches!(*method, "tls_client_auth" | "self_signed_tls_client_auth")
        })
        .collect()
}

fn token_endpoint_auth_signing_alg_values_supported(settings: &Settings) -> Vec<&'static str> {
    if settings.ciba_security_profile.requires_fapi2_hardening() {
        return FAPI_CIBA_REQUEST_OBJECT_SIGNING_ALGS.to_vec();
    }
    CLIENT_JWT_SIGNING_ALGS.to_vec()
}

fn request_object_signing_alg_values_supported(
    profile: AuthorizationServerProfile,
    active_signing_algs: &[&'static str],
) -> Vec<&'static str> {
    if profile.requires_signed_authorization_request() {
        return active_signing_algs.to_vec();
    }
    if profile.requires_fapi2_security() {
        return REQUEST_OBJECT_SIGNING_ALGS.to_vec();
    }
    BASELINE_REQUEST_OBJECT_SIGNING_ALGS.to_vec()
}

fn response_modes_supported(profile: AuthorizationServerProfile) -> Vec<&'static str> {
    if profile.requires_signed_authorization_response() {
        return vec!["jwt"];
    }
    vec!["query", "jwt"]
}

fn active_signing_alg_values_supported(keyset: &Keyset) -> Vec<&'static str> {
    signing_algorithm_name(keyset.active_alg)
        .map(|alg| vec![alg])
        .unwrap_or_default()
}

fn id_token_signing_alg_values_supported(keyset: &Keyset) -> Vec<&'static str> {
    let mut values = active_signing_alg_values_supported(keyset);
    values.push("RS256");
    values.sort_unstable();
    values.dedup();
    values
}

pub(crate) async fn discovery(state: Data<AppState>) -> Json<Value> {
    Json(authorization_server_metadata_value(&state))
}

pub(crate) async fn oauth_authorization_server_metadata(state: Data<AppState>) -> Json<Value> {
    Json(authorization_server_metadata_value(&state))
}

pub(crate) async fn oauth_protected_resource_metadata(state: Data<AppState>) -> Json<Value> {
    Json(protected_resource_metadata(
        &state.settings,
        &state.keyset.snapshot(),
    ))
}

pub(crate) async fn jwks(state: Data<AppState>) -> Json<Value> {
    Json(state.keyset.snapshot().jwks())
}

#[cfg(test)]
#[path = "../../tests/in_source/src/http/tests/well_known.rs"]
mod tests;
