use super::{AdminClientCryptoPort, AdminClientError, CreateClientRequest};
#[cfg(test)]
use super::{sector_identifier_host_for_redirects, validate_pkce_compatibility_policy};
use crate::{OAuthClient, normalize_sha256_thumbprint, validate_oauth_redirect_uri};
use serde_json::Value;

const SUPPORTED_GRANT_TYPES: &[&str] = &[
    "authorization_code",
    "refresh_token",
    "client_credentials",
    "urn:ietf:params:oauth:grant-type:jwt-bearer",
    "urn:openid:params:grant-type:ciba",
    "urn:ietf:params:oauth:grant-type:device_code",
    "urn:ietf:params:oauth:grant-type:token-exchange",
];
const SUPPORTED_TOKEN_AUTH_METHODS: &[&str] = &[
    "none",
    "client_secret_basic",
    "client_secret_post",
    "private_key_jwt",
    "tls_client_auth",
    "self_signed_tls_client_auth",
];
const SUPPORTED_CLIENT_JWE_KEY_MANAGEMENT_ALGS: &[&str] = &["RSA-OAEP-256"];
const SUPPORTED_CLIENT_JWE_CONTENT_ENC_ALGS: &[&str] = &["A256GCM"];
const SUPPORTED_CLIENT_JWT_SIGNING_ALGS: &[&str] = &["EdDSA", "RS256", "ES256", "PS256"];

#[cfg(test)]
mod tests {
    use super::{
        AdminClientError, sector_identifier_host_for_redirects, validate_pkce_compatibility_policy,
    };

    #[test]
    fn pkce_legacy_exception_is_limited_to_confidential_non_dpop_clients() {
        assert!(validate_pkce_compatibility_policy(false, "public", true).is_ok());
        assert!(validate_pkce_compatibility_policy(true, "confidential", false).is_ok());

        let public_error = validate_pkce_compatibility_policy(true, "public", false).unwrap_err();
        assert_eq!(
            public_error.to_string(),
            "PKCE compatibility exceptions are limited to confidential clients"
        );

        let dpop_error =
            validate_pkce_compatibility_policy(true, "confidential", true).unwrap_err();
        assert_eq!(dpop_error.to_string(), "DPoP-bound clients must use PKCE");
    }

    #[test]
    fn policy_debug_output_redacts_server_secrets() {
        let policy = super::super::AdminClientPolicy {
            tenant: nazo_identity::TenantContext::default_system(),
            pairwise_subject_secret: Some("pairwise-secret".to_owned()),
            client_secret_pepper: "client-secret-pepper".to_owned(),
        };
        let debug = format!("{policy:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("pairwise-secret"));
        assert!(!debug.contains("client-secret-pepper"));
    }

    #[test]
    fn sector_identifier_document_requires_every_redirect() {
        let redirect_uris = vec![
            "https://client.example/callback".to_owned(),
            "https://client.example/alternate".to_owned(),
        ];
        let sector_uris = vec![
            "https://client.example/callback".to_owned(),
            "https://client.example/alternate".to_owned(),
        ];
        assert_eq!(
            sector_identifier_host_for_redirects(
                "https://sector.example/client.json",
                &redirect_uris,
                &sector_uris,
            )
            .expect("valid sector document"),
            "sector.example"
        );

        let error = sector_identifier_host_for_redirects(
            "https://sector.example/client.json",
            &[
                "https://client.example/callback".to_owned(),
                "https://other.example/callback".to_owned(),
            ],
            &["https://client.example/callback".to_owned()],
        )
        .expect_err("unlisted redirect must fail");
        assert!(matches!(error, AdminClientError::InvalidRequest(_)));
        assert!(error.to_string().contains("other.example"));
    }

    #[test]
    fn sector_identifier_uri_must_have_a_host() {
        let error = sector_identifier_host_for_redirects(
            "not-a-uri",
            &["https://client.example/callback".to_owned()],
            &["https://client.example/callback".to_owned()],
        )
        .expect_err("sector identifier URI without a host must fail");
        assert_eq!(
            error.to_string(),
            "sector_identifier_uri host 解析失败: InvalidUri"
        );
    }
}

#[cfg(test)]
#[path = "validation/metadata_tests.rs"]
mod metadata_tests;
#[cfg(test)]
#[path = "validation/mtls_tests.rs"]
mod mtls_tests;
#[cfg(test)]
mod test_support;

pub(super) struct ClientMetadata<'a> {
    client_type: &'a str,
    redirect_uris: &'a [String],
    post_logout_redirect_uris: &'a [String],
    scopes: &'a [String],
    allowed_audiences: &'a [String],
    grant_types: &'a [String],
    token_endpoint_auth_method: &'a str,
    backchannel_logout_uri: Option<&'a str>,
    frontchannel_logout_uri: Option<&'a str>,
    jwks: Option<&'a Value>,
    allow_jwks_without_kid: bool,
    introspection_encrypted_response_alg: Option<&'a str>,
    introspection_encrypted_response_enc: Option<&'a str>,
    userinfo_signed_response_alg: Option<&'a str>,
    userinfo_encrypted_response_alg: Option<&'a str>,
    userinfo_encrypted_response_enc: Option<&'a str>,
    authorization_signed_response_alg: Option<&'a str>,
    authorization_encrypted_response_alg: Option<&'a str>,
    authorization_encrypted_response_enc: Option<&'a str>,
    mtls: ClientMtlsMetadata<'a>,
}

struct ClientMtlsMetadata<'a> {
    subject_dn: Option<&'a str>,
    cert_sha256: Option<&'a str>,
    san_dns: &'a [String],
    san_uri: &'a [String],
    san_ip: &'a [String],
    san_email: &'a [String],
}

impl<'a> ClientMetadata<'a> {
    pub(super) fn from_create(request: &'a CreateClientRequest) -> Self {
        Self {
            client_type: &request.client_type,
            redirect_uris: &request.redirect_uris,
            post_logout_redirect_uris: &request.post_logout_redirect_uris,
            scopes: &request.scopes,
            allowed_audiences: &request.allowed_audiences,
            grant_types: &request.grant_types,
            token_endpoint_auth_method: &request.token_endpoint_auth_method,
            backchannel_logout_uri: request.backchannel_logout_uri.as_deref(),
            frontchannel_logout_uri: request.frontchannel_logout_uri.as_deref(),
            jwks: request.jwks.as_ref(),
            allow_jwks_without_kid: request.allow_jwks_without_kid,
            introspection_encrypted_response_alg: request
                .introspection_encrypted_response_alg
                .as_deref(),
            introspection_encrypted_response_enc: request
                .introspection_encrypted_response_enc
                .as_deref(),
            userinfo_signed_response_alg: request.userinfo_signed_response_alg.as_deref(),
            userinfo_encrypted_response_alg: request.userinfo_encrypted_response_alg.as_deref(),
            userinfo_encrypted_response_enc: request.userinfo_encrypted_response_enc.as_deref(),
            authorization_signed_response_alg: request.authorization_signed_response_alg.as_deref(),
            authorization_encrypted_response_alg: request
                .authorization_encrypted_response_alg
                .as_deref(),
            authorization_encrypted_response_enc: request
                .authorization_encrypted_response_enc
                .as_deref(),
            mtls: ClientMtlsMetadata {
                subject_dn: request.tls_client_auth_subject_dn.as_deref(),
                cert_sha256: request.tls_client_auth_cert_sha256.as_deref(),
                san_dns: &request.tls_client_auth_san_dns,
                san_uri: &request.tls_client_auth_san_uri,
                san_ip: &request.tls_client_auth_san_ip,
                san_email: &request.tls_client_auth_san_email,
            },
        }
    }

    pub(super) fn from_client(client: &'a OAuthClient) -> Self {
        Self {
            client_type: &client.client_type,
            redirect_uris: &client.redirect_uris,
            post_logout_redirect_uris: &client.post_logout_redirect_uris,
            scopes: &client.scopes,
            allowed_audiences: &client.allowed_audiences,
            grant_types: &client.grant_types,
            token_endpoint_auth_method: &client.token_endpoint_auth_method,
            backchannel_logout_uri: client.backchannel_logout_uri.as_deref(),
            frontchannel_logout_uri: client.frontchannel_logout_uri.as_deref(),
            jwks: client.jwks.as_ref(),
            allow_jwks_without_kid: false,
            introspection_encrypted_response_alg: client
                .introspection_encrypted_response_alg
                .as_deref(),
            introspection_encrypted_response_enc: client
                .introspection_encrypted_response_enc
                .as_deref(),
            userinfo_signed_response_alg: client.userinfo_signed_response_alg.as_deref(),
            userinfo_encrypted_response_alg: client.userinfo_encrypted_response_alg.as_deref(),
            userinfo_encrypted_response_enc: client.userinfo_encrypted_response_enc.as_deref(),
            authorization_signed_response_alg: client.authorization_signed_response_alg.as_deref(),
            authorization_encrypted_response_alg: client
                .authorization_encrypted_response_alg
                .as_deref(),
            authorization_encrypted_response_enc: client
                .authorization_encrypted_response_enc
                .as_deref(),
            mtls: ClientMtlsMetadata {
                subject_dn: client.tls_client_auth_subject_dn.as_deref(),
                cert_sha256: client.tls_client_auth_cert_sha256.as_deref(),
                san_dns: &client.tls_client_auth_san_dns,
                san_uri: &client.tls_client_auth_san_uri,
                san_ip: &client.tls_client_auth_san_ip,
                san_email: &client.tls_client_auth_san_email,
            },
        }
    }
}

pub(super) fn validate_client_metadata<C: AdminClientCryptoPort + ?Sized>(
    metadata: ClientMetadata<'_>,
    response_signing_algorithms: &[String],
    crypto: &C,
) -> Result<(), AdminClientError> {
    if !matches!(metadata.client_type, "public" | "confidential") {
        return invalid("客户端类型无效");
    }
    validate_unique_non_empty("scope", metadata.scopes)?;
    validate_unique_non_empty("audience", metadata.allowed_audiences)?;
    validate_unique_non_empty("grant_type", metadata.grant_types)?;
    for grant in metadata.grant_types {
        if !SUPPORTED_GRANT_TYPES.contains(&grant.as_str()) {
            return invalid(format!("不支持的 grant_type: {grant}"));
        }
    }
    if !SUPPORTED_TOKEN_AUTH_METHODS.contains(&metadata.token_endpoint_auth_method) {
        return invalid("客户端认证方式无效");
    }
    if metadata.client_type == "public" && metadata.token_endpoint_auth_method != "none" {
        return invalid("public 客户端只能使用 none 认证方式");
    }
    if metadata.client_type == "confidential" && metadata.token_endpoint_auth_method == "none" {
        return invalid("confidential 客户端必须使用机密认证方式");
    }
    if let Some(jwks) = metadata.jwks
        && metadata.token_endpoint_auth_method != "self_signed_tls_client_auth"
    {
        crypto
            .validate_jwks(jwks, metadata.allow_jwks_without_kid)
            .map_err(AdminClientError::InvalidRequest)?;
    }
    validate_jwe_metadata(
        "introspection",
        metadata.introspection_encrypted_response_alg,
        metadata.introspection_encrypted_response_enc,
        metadata.jwks,
        crypto,
    )?;
    validate_response_crypto_metadata(
        "userinfo",
        metadata.userinfo_signed_response_alg,
        metadata.userinfo_encrypted_response_alg,
        metadata.userinfo_encrypted_response_enc,
        metadata.jwks,
        response_signing_algorithms,
        crypto,
    )?;
    validate_response_crypto_metadata(
        "authorization",
        metadata.authorization_signed_response_alg,
        metadata.authorization_encrypted_response_alg,
        metadata.authorization_encrypted_response_enc,
        metadata.jwks,
        response_signing_algorithms,
        crypto,
    )?;
    if metadata.token_endpoint_auth_method == "private_key_jwt" {
        let Some(jwks) = metadata.jwks else {
            return invalid("private_key_jwt 客户端必须配置 jwks");
        };
        if !crypto.contains_signing_key(jwks) {
            return invalid("private_key_jwt 客户端必须配置签名 jwks");
        }
    }
    if metadata.token_endpoint_auth_method == "tls_client_auth"
        && !metadata.mtls.has_binding_material()
    {
        return invalid("tls_client_auth 客户端必须注册 subject DN、SAN 或证书 SHA-256 绑定材料");
    }
    if metadata.token_endpoint_auth_method == "self_signed_tls_client_auth"
        && !metadata
            .jwks
            .is_some_and(|jwks| crypto.valid_self_signed_mtls_jwks(jwks))
    {
        return invalid("self_signed_tls_client_auth 客户端必须注册有效 x5c 证书");
    }
    validate_mtls_metadata(&metadata.mtls)?;
    if metadata.client_type == "public"
        && metadata
            .grant_types
            .iter()
            .any(|grant| grant == "client_credentials")
    {
        return invalid("public 客户端不能使用 client_credentials 授权类型");
    }
    if metadata
        .grant_types
        .iter()
        .any(|grant| grant == "client_credentials")
        && metadata.scopes.iter().any(|scope| scope == "openid")
    {
        return invalid("client_credentials 客户端不能申请 openid 作用域");
    }
    if metadata
        .grant_types
        .iter()
        .any(|grant| grant == "refresh_token")
        && !metadata
            .grant_types
            .iter()
            .any(|grant| grant == "authorization_code")
    {
        return invalid("refresh_token 授权类型必须与 authorization_code 一起启用");
    }
    if metadata
        .scopes
        .iter()
        .any(|scope| scope == "offline_access")
        && !metadata
            .grant_types
            .iter()
            .any(|grant| grant == "refresh_token")
    {
        return invalid("offline_access 作用域必须与 refresh_token 授权类型一起启用");
    }
    if metadata
        .grant_types
        .iter()
        .any(|grant| grant == "authorization_code")
        && metadata.redirect_uris.is_empty()
    {
        return invalid("authorization_code 客户端必须注册 redirect_uri");
    }
    for uri in metadata.redirect_uris {
        validate_oauth_redirect_uri(metadata.client_type, uri)
            .map_err(|error| AdminClientError::InvalidRequest(error.to_string()))?;
    }
    validate_unique_non_empty(
        "post_logout_redirect_uri",
        metadata.post_logout_redirect_uris,
    )?;
    for uri in metadata.post_logout_redirect_uris {
        validate_oauth_redirect_uri(metadata.client_type, uri)
            .map_err(|error| AdminClientError::InvalidRequest(error.to_string()))?;
    }
    if let Some(uri) = metadata.backchannel_logout_uri {
        validate_logout_uri("backchannel_logout_uri", uri)?;
    }
    if let Some(uri) = metadata.frontchannel_logout_uri {
        validate_logout_uri("frontchannel_logout_uri", uri)?;
    }
    Ok(())
}

fn validate_jwe_metadata<C: AdminClientCryptoPort + ?Sized>(
    response_name: &str,
    algorithm: Option<&str>,
    encryption: Option<&str>,
    jwks: Option<&Value>,
    crypto: &C,
) -> Result<(), AdminClientError> {
    match (algorithm, encryption) {
        (None, None) => Ok(()),
        (None, Some(_)) => invalid(format!(
            "{response_name}_encrypted_response_enc 不能在未设置 {response_name}_encrypted_response_alg 时使用"
        )),
        (Some(_), None) => invalid(format!(
            "{response_name}_encrypted_response_alg 必须同时配置 {response_name}_encrypted_response_enc"
        )),
        (Some(algorithm), Some(encryption)) => {
            if !SUPPORTED_CLIENT_JWE_KEY_MANAGEMENT_ALGS.contains(&algorithm) {
                return invalid(format!(
                    "{response_name}_encrypted_response_alg 必须是 {}",
                    SUPPORTED_CLIENT_JWE_KEY_MANAGEMENT_ALGS.join(", ")
                ));
            }
            if !SUPPORTED_CLIENT_JWE_CONTENT_ENC_ALGS.contains(&encryption) {
                return invalid(format!(
                    "{response_name}_encrypted_response_enc 必须是 {}",
                    SUPPORTED_CLIENT_JWE_CONTENT_ENC_ALGS.join(", ")
                ));
            }
            let capability_name = if response_name == "introspection" {
                "encrypted introspection response".to_owned()
            } else {
                format!("{response_name} encrypted response")
            };
            match jwks.map(|jwks| crypto.matching_encryption_key_count(jwks, algorithm)) {
                Some(1) => Ok(()),
                Some(2..) => invalid(format!(
                    "启用 {capability_name} 必须且只能配置一个匹配的 jwks 加密公钥"
                )),
                _ => invalid(format!(
                    "启用 {capability_name} 必须配置匹配的 jwks 加密公钥"
                )),
            }
        }
    }
}

fn validate_response_crypto_metadata<C: AdminClientCryptoPort + ?Sized>(
    response_name: &str,
    signing_algorithm: Option<&str>,
    encryption_algorithm: Option<&str>,
    encryption: Option<&str>,
    jwks: Option<&Value>,
    response_signing_algorithms: &[String],
    crypto: &C,
) -> Result<(), AdminClientError> {
    if let Some(algorithm) = signing_algorithm
        && (!SUPPORTED_CLIENT_JWT_SIGNING_ALGS.contains(&algorithm)
            || !response_signing_algorithms
                .iter()
                .any(|available| available == algorithm))
    {
        return invalid(format!(
            "{response_name}_signed_response_alg 签名算法必须是当前服务可用算法: {}",
            response_signing_algorithms.join(", ")
        ));
    }
    validate_jwe_metadata(
        response_name,
        encryption_algorithm,
        encryption,
        jwks,
        crypto,
    )
}

fn validate_mtls_metadata(metadata: &ClientMtlsMetadata<'_>) -> Result<(), AdminClientError> {
    if metadata
        .subject_dn
        .is_some_and(|value| value.trim().is_empty())
    {
        return invalid("tls_client_auth_subject_dn 不能为空");
    }
    if metadata
        .cert_sha256
        .is_some_and(|value| normalize_sha256_thumbprint(value).is_none())
    {
        return invalid("tls_client_auth_cert_sha256 必须是 SHA-256 证书指纹");
    }
    validate_unique_non_empty("tls_client_auth_san_dns", metadata.san_dns)?;
    validate_unique_non_empty("tls_client_auth_san_uri", metadata.san_uri)?;
    validate_unique_non_empty("tls_client_auth_san_ip", metadata.san_ip)?;
    validate_unique_non_empty("tls_client_auth_san_email", metadata.san_email)?;
    for value in metadata.san_ip {
        value.parse::<std::net::IpAddr>().map_err(|_| {
            AdminClientError::InvalidRequest(format!(
                "tls_client_auth_san_ip 必须是合法 IP 地址: {value}"
            ))
        })?;
    }
    Ok(())
}

impl ClientMtlsMetadata<'_> {
    fn has_binding_material(&self) -> bool {
        self.subject_dn
            .is_some_and(|value| !value.trim().is_empty())
            || self
                .cert_sha256
                .and_then(normalize_sha256_thumbprint)
                .is_some()
            || !self.san_dns.is_empty()
            || !self.san_uri.is_empty()
            || !self.san_ip.is_empty()
            || !self.san_email.is_empty()
    }
}

fn validate_logout_uri(field: &str, uri: &str) -> Result<(), AdminClientError> {
    let parsed = url::Url::parse(uri)
        .map_err(|error| AdminClientError::InvalidRequest(error.to_string()))?;
    if parsed.fragment().is_some() {
        return invalid(format!("{field} 不能包含 fragment"));
    }
    match parsed.scheme() {
        "https" => Ok(()),
        "http"
            if parsed.host_str().is_some_and(|host| {
                matches!(host, "localhost" | "127.0.0.1" | "::1") || host.ends_with(".localhost")
            }) =>
        {
            Ok(())
        }
        _ => invalid(format!("{field} 必须使用 https 或 loopback http")),
    }
}

fn validate_unique_non_empty(name: &str, values: &[String]) -> Result<(), AdminClientError> {
    let mut seen = std::collections::HashSet::new();
    for value in values {
        let trimmed = value.trim();
        if trimmed.is_empty() || value != trimmed || trimmed.split_whitespace().count() != 1 {
            return invalid(format!("{name} 不能为空或包含空白字符"));
        }
        if !seen.insert(trimmed) {
            return invalid(format!("{name} 不能重复: {trimmed}"));
        }
    }
    Ok(())
}

fn invalid<T>(message: impl Into<String>) -> Result<T, AdminClientError> {
    Err(AdminClientError::InvalidRequest(message.into()))
}

pub(super) fn default_true() -> bool {
    true
}
