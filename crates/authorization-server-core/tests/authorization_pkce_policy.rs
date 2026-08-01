use std::collections::HashMap;

use nazo_auth::{
    AuthorizationCapabilityPolicy, AuthorizationClientPolicy, AuthorizationPolicyError,
    AuthorizationProfilePolicy, normalize_authorization_request,
};

fn request(include_nonce: bool, include_pkce: bool) -> HashMap<String, String> {
    let mut parameters = HashMap::from([
        ("response_type".to_owned(), "code".to_owned()),
        ("scope".to_owned(), "openid phone".to_owned()),
    ]);
    if include_nonce {
        parameters.insert("nonce".to_owned(), "per-transaction-nonce".to_owned());
    }
    if include_pkce {
        parameters.insert("code_challenge".to_owned(), "A".repeat(43));
        parameters.insert("code_challenge_method".to_owned(), "S256".to_owned());
    }
    parameters
}

fn normalize(
    parameters: &HashMap<String, String>,
    client_type: &str,
    pkce_required: bool,
) -> Result<nazo_auth::NormalizedAuthorizationRequest, AuthorizationPolicyError> {
    let scopes = ["openid".to_owned(), "phone".to_owned()];
    let audiences = [];
    normalize_authorization_request(
        parameters,
        AuthorizationClientPolicy {
            client_type,
            allowed_scopes: &scopes,
            allowed_audiences: &audiences,
            require_dpop_bound_tokens: false,
            require_mtls_bound_tokens: false,
        },
        AuthorizationCapabilityPolicy {
            authorization_details: true,
            jarm: true,
            native_sso: true,
            form_post: true,
        },
        AuthorizationProfilePolicy {
            signed_authorization_response_required: false,
            pkce_required,
        },
        false,
    )
}

#[test]
fn baseline_confidential_oidc_client_may_omit_pkce() {
    let normalized = normalize(&request(true, false), "confidential", false)
        .expect("baseline confidential OIDC code flow permits PKCE to be omitted");

    assert_eq!(normalized.code_challenge, None);
}

#[test]
fn public_client_cannot_replace_pkce_with_oidc_nonce() {
    assert_eq!(
        normalize(&request(true, false), "public", false),
        Err(AuthorizationPolicyError::InvalidRequest)
    );
}

#[test]
fn baseline_confidential_oidc_code_flow_remains_core_compatible_without_nonce() {
    assert!(normalize(&request(false, false), "confidential", false).is_ok());
}

#[test]
fn confidential_non_oidc_code_flow_requires_pkce() {
    let mut parameters = request(false, false);
    parameters.insert("scope".to_owned(), "phone".to_owned());

    assert_eq!(
        normalize(&parameters, "confidential", false),
        Err(AuthorizationPolicyError::InvalidRequest)
    );
}

#[test]
fn hardened_profile_requires_pkce_even_for_confidential_oidc_client() {
    assert_eq!(
        normalize(&request(true, false), "confidential", true),
        Err(AuthorizationPolicyError::InvalidRequest)
    );
    assert!(normalize(&request(true, true), "confidential", true).is_ok());
}
