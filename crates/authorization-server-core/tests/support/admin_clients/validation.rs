use anyhow::anyhow;
use serde_json::Value;

use super::{ClientMetadata as ValidatedMetadata, validate_client_metadata as validate_metadata};
use crate::admin_clients::{AdminClientCryptoPort, CreateClientRequest};
use crate::client_jwe_encryption_key_matches_alg;

pub(super) const SUPPORTED_CLIENT_JWT_SIGNING_ALGS: &[&str] = &["EdDSA", "RS256", "ES256", "PS256"];

pub(super) struct ClientMetadataFixture<'a> {
    pub(super) client_type: &'a str,
    pub(super) redirect_uris: &'a [String],
    pub(super) post_logout_redirect_uris: &'a [String],
    pub(super) scopes: &'a [String],
    pub(super) allowed_audiences: &'a [String],
    pub(super) grant_types: &'a [String],
    pub(super) token_endpoint_auth_method: &'a str,
    pub(super) backchannel_logout_uri: Option<&'a str>,
    pub(super) frontchannel_logout_uri: Option<&'a str>,
    pub(super) jwks: Option<&'a Value>,
    pub(super) introspection_encrypted_response_alg: Option<&'a str>,
    pub(super) introspection_encrypted_response_enc: Option<&'a str>,
    pub(super) userinfo_signed_response_alg: Option<&'a str>,
    pub(super) userinfo_encrypted_response_alg: Option<&'a str>,
    pub(super) userinfo_encrypted_response_enc: Option<&'a str>,
    pub(super) authorization_signed_response_alg: Option<&'a str>,
    pub(super) authorization_encrypted_response_alg: Option<&'a str>,
    pub(super) authorization_encrypted_response_enc: Option<&'a str>,
    pub(super) response_signing_algorithms: &'a [&'static str],
    pub(super) mtls_binding: Option<&'a ClientMtlsMetadataFixture>,
}

#[derive(Default)]
pub(super) struct ClientMtlsMetadataFixture {
    pub(super) tls_client_auth_subject_dn: Option<String>,
    pub(super) tls_client_auth_cert_sha256: Option<String>,
    pub(super) tls_client_auth_san_dns: Vec<String>,
    pub(super) tls_client_auth_san_uri: Vec<String>,
    pub(super) tls_client_auth_san_ip: Vec<String>,
    pub(super) tls_client_auth_san_email: Vec<String>,
}

pub(super) fn validate_metadata_fixture(metadata: ClientMetadataFixture<'_>) -> anyhow::Result<()> {
    let mtls = metadata.mtls_binding;
    let request = CreateClientRequest {
        conformance_lease_id: None,
        client_name: "metadata-validation-test".to_owned(),
        client_type: metadata.client_type.to_owned(),
        redirect_uris: metadata.redirect_uris.to_vec(),
        post_logout_redirect_uris: metadata.post_logout_redirect_uris.to_vec(),
        scopes: metadata.scopes.to_vec(),
        allowed_audiences: metadata.allowed_audiences.to_vec(),
        grant_types: metadata.grant_types.to_vec(),
        token_endpoint_auth_method: metadata.token_endpoint_auth_method.to_owned(),
        subject_type: None,
        sector_identifier_uri: None,
        require_dpop_bound_tokens: false,
        require_mtls_bound_tokens: false,
        allow_client_assertion_audience_array: false,
        allow_client_assertion_endpoint_audience: false,
        require_par_request_object: false,
        backchannel_logout_uri: metadata.backchannel_logout_uri.map(ToOwned::to_owned),
        backchannel_logout_session_required: true,
        backchannel_token_delivery_mode: "poll".to_owned(),
        backchannel_client_notification_endpoint: None,
        backchannel_authentication_request_signing_alg: None,
        backchannel_user_code_parameter: false,
        frontchannel_logout_uri: metadata.frontchannel_logout_uri.map(ToOwned::to_owned),
        frontchannel_logout_session_required: true,
        tls_client_auth_subject_dn: mtls.and_then(|value| value.tls_client_auth_subject_dn.clone()),
        tls_client_auth_cert_sha256: mtls
            .and_then(|value| value.tls_client_auth_cert_sha256.clone()),
        tls_client_auth_san_dns: mtls
            .map(|value| value.tls_client_auth_san_dns.clone())
            .unwrap_or_default(),
        tls_client_auth_san_uri: mtls
            .map(|value| value.tls_client_auth_san_uri.clone())
            .unwrap_or_default(),
        tls_client_auth_san_ip: mtls
            .map(|value| value.tls_client_auth_san_ip.clone())
            .unwrap_or_default(),
        tls_client_auth_san_email: mtls
            .map(|value| value.tls_client_auth_san_email.clone())
            .unwrap_or_default(),
        jwks_uri: None,
        jwks: metadata.jwks.cloned(),
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
        introspection_encrypted_response_alg: metadata
            .introspection_encrypted_response_alg
            .map(ToOwned::to_owned),
        introspection_encrypted_response_enc: metadata
            .introspection_encrypted_response_enc
            .map(ToOwned::to_owned),
        userinfo_signed_response_alg: metadata.userinfo_signed_response_alg.map(ToOwned::to_owned),
        userinfo_encrypted_response_alg: metadata
            .userinfo_encrypted_response_alg
            .map(ToOwned::to_owned),
        userinfo_encrypted_response_enc: metadata
            .userinfo_encrypted_response_enc
            .map(ToOwned::to_owned),
        authorization_signed_response_alg: metadata
            .authorization_signed_response_alg
            .map(ToOwned::to_owned),
        authorization_encrypted_response_alg: metadata
            .authorization_encrypted_response_alg
            .map(ToOwned::to_owned),
        authorization_encrypted_response_enc: metadata
            .authorization_encrypted_response_enc
            .map(ToOwned::to_owned),
        security_policy: crate::ClientSecurityPolicy::default(),
    };
    let crypto = MetadataTestCrypto;
    let response_signing_algorithms = metadata
        .response_signing_algorithms
        .iter()
        .map(|algorithm| (*algorithm).to_owned())
        .collect::<Vec<_>>();
    validate_metadata(
        ValidatedMetadata::from_create(&request),
        &response_signing_algorithms,
        &response_signing_algorithms,
        &crypto,
    )
    .map_err(|error| anyhow!(error.to_string()))
}

struct MetadataTestCrypto;

impl AdminClientCryptoPort for MetadataTestCrypto {
    fn response_signing_algorithms(&self) -> Vec<String> {
        SUPPORTED_CLIENT_JWT_SIGNING_ALGS
            .iter()
            .map(|algorithm| (*algorithm).to_owned())
            .collect()
    }

    fn issue_client_secret(&self, _pepper: &str) -> (String, String) {
        unreachable!("metadata validation must not issue client secrets")
    }

    fn validate_jwks(&self, jwks: &Value) -> Result<(), String> {
        let keys = jwks
            .get("keys")
            .and_then(Value::as_array)
            .ok_or_else(|| "jwks.keys 必须是数组".to_owned())?;
        if keys.is_empty() {
            return Err("jwks.keys 不能为空".to_owned());
        }
        const PRIVATE_MEMBERS: &[&str] = &["d", "p", "q", "dp", "dq", "qi", "oth", "k"];
        if keys.iter().any(|key| {
            key.as_object().is_some_and(|object| {
                PRIVATE_MEMBERS
                    .iter()
                    .any(|member| object.contains_key(*member))
            })
        }) {
            return Err("jwks 不能包含私钥材料".to_owned());
        }
        Ok(())
    }

    fn validate_rfc4514_dn(&self, value: &str) -> Result<(), String> {
        (!value.trim().is_empty() && value.contains('='))
            .then_some(())
            .ok_or_else(|| "invalid RFC 4514 DN".to_owned())
    }

    fn matching_encryption_key_count(&self, jwks: &Value, algorithm: &str) -> usize {
        jwks.get("keys")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter(|key| client_jwe_encryption_key_matches_alg(key, algorithm))
            .count()
    }

    fn contains_signing_key(&self, jwks: &Value) -> bool {
        jwks.get("keys")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .any(|key| {
                key.get("use").and_then(Value::as_str) != Some("enc")
                    && key
                        .get("alg")
                        .and_then(Value::as_str)
                        .is_some_and(|algorithm| {
                            SUPPORTED_CLIENT_JWT_SIGNING_ALGS.contains(&algorithm)
                        })
            })
    }

    fn valid_self_signed_mtls_jwks(&self, jwks: &Value) -> bool {
        jwks.get("keys")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .any(|key| {
                key.get("x5c")
                    .and_then(Value::as_array)
                    .is_some_and(|chain| !chain.is_empty())
            })
    }
}
