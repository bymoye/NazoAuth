use serde_json::json;

use super::*;

fn rsa_key(exponent: &[u8], modulus: &[u8]) -> Value {
    json!({
        "kty": "RSA",
        "alg": "RS256",
        "use": "sig",
        "key_ops": ["verify"],
        "n": URL_SAFE_NO_PAD.encode(modulus),
        "e": URL_SAFE_NO_PAD.encode(exponent),
    })
}

#[test]
fn shared_rsa_policy_rejects_weak_moduli_and_invalid_exponents() {
    let modulus = [0xff; 256];
    assert!(jwt_decoding_key_from_jwk(&rsa_key(&[1, 0, 1], &modulus), Algorithm::RS256).is_some());
    assert!(jwt_decoding_key_from_jwk(&rsa_key(&[1], &modulus), Algorithm::RS256).is_none());
    assert!(jwt_decoding_key_from_jwk(&rsa_key(&[2], &modulus), Algorithm::RS256).is_none());
    assert!(
        jwt_decoding_key_from_jwk(&rsa_key(&[1, 0, 1], &[0xff; 255]), Algorithm::RS256).is_none()
    );
}

#[test]
fn shared_jwk_policy_rejects_private_material_and_ambiguous_key_ids() {
    let mut public = json!({
        "kid": "key",
        "kty": "OKP",
        "crv": "Ed25519",
        "alg": "EdDSA",
        "x": URL_SAFE_NO_PAD.encode([7; 32]),
    });
    for member in ["k", "d", "p", "q", "dp", "dq", "qi", "oth"] {
        public[member] = json!("private");
        assert!(jwt_decoding_key_from_jwk(&public, Algorithm::EdDSA).is_none());
        public.as_object_mut().unwrap().remove(member);
    }
    let client = OAuthClient {
        id: uuid::Uuid::from_u128(1),
        tenant_id: uuid::Uuid::from_u128(2),
        realm_id: uuid::Uuid::from_u128(3),
        organization_id: uuid::Uuid::from_u128(4),
        registration: crate::ValidatedClientRegistration {
            client_id: "client".to_owned(),
            client_name: "Client".to_owned(),
            client_type: "confidential".to_owned(),
            redirect_uris: Vec::new(),
            post_logout_redirect_uris: Vec::new(),
            scopes: Vec::new(),
            allowed_audiences: Vec::new(),
            grant_types: Vec::new(),
            token_endpoint_auth_method: "private_key_jwt".to_owned(),
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
            jwks: Some(json!({"keys": [public.clone(), public]})),
            request_uris: Vec::new(),
            initiate_login_uri: None,
            presentation: crate::ClientPresentationMetadata::default(),
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
            security_policy: crate::ClientSecurityPolicy::default(),
        },
        require_mtls_bound_tokens: false,
        is_active: true,
    };
    assert!(client_jwt_decoding_key(&client, "key", Algorithm::EdDSA).is_none());
}
