use super::{AdminClientCryptoPort, AdminClientError, CreateClientRequest};
use crate::{
    MAX_CIBA_LOGOUT_URI_BYTES, OAuthClient, SUPPORTED_CLIENT_JWE_CONTENT_ENC_ALGS,
    SUPPORTED_CLIENT_JWE_KEY_MANAGEMENT_ALGS, normalize_sha256_thumbprint,
    validate_oauth_redirect_uri,
};
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
    "attest_jwt_client_auth",
];
use crate::SUPPORTED_CLIENT_JWT_SIGNING_ALGS;

#[cfg(test)]
#[path = "../../tests/unit/admin_clients/validation.rs"]
mod tests;

#[cfg(test)]
#[path = "../../tests/unit/admin_clients/validation/metadata.rs"]
mod metadata_tests;
#[cfg(test)]
#[path = "../../tests/unit/admin_clients/validation/mtls.rs"]
mod mtls_tests;
#[cfg(test)]
#[path = "../../tests/support/admin_clients/validation.rs"]
mod test_support;

pub(super) struct ClientMetadata<'a> {
    client_type: &'a str,
    redirect_uris: &'a [String],
    post_logout_redirect_uris: &'a [String],
    scopes: &'a [String],
    allowed_audiences: &'a [String],
    grant_types: &'a [String],
    token_endpoint_auth_method: &'a str,
    backchannel_token_delivery_mode: &'a str,
    backchannel_client_notification_endpoint: Option<&'a str>,
    backchannel_authentication_request_signing_alg: Option<&'a str>,
    backchannel_user_code_parameter: bool,
    backchannel_logout_uri: Option<&'a str>,
    frontchannel_logout_uri: Option<&'a str>,
    jwks: Option<&'a Value>,
    id_token_signed_response_alg: Option<&'a str>,
    id_token_encrypted_response_alg: Option<&'a str>,
    id_token_encrypted_response_enc: Option<&'a str>,
    request_object_signing_alg: Option<&'a str>,
    request_object_encryption_alg: Option<&'a str>,
    request_object_encryption_enc: Option<&'a str>,
    token_endpoint_auth_signing_alg: Option<&'a str>,
    introspection_signed_response_alg: Option<&'a str>,
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
            backchannel_token_delivery_mode: &request.backchannel_token_delivery_mode,
            backchannel_client_notification_endpoint: request
                .backchannel_client_notification_endpoint
                .as_deref(),
            backchannel_authentication_request_signing_alg: request
                .backchannel_authentication_request_signing_alg
                .as_deref(),
            backchannel_user_code_parameter: request.backchannel_user_code_parameter,
            backchannel_logout_uri: request.backchannel_logout_uri.as_deref(),
            frontchannel_logout_uri: request.frontchannel_logout_uri.as_deref(),
            jwks: request.jwks.as_ref(),
            id_token_signed_response_alg: request.id_token_signed_response_alg.as_deref(),
            id_token_encrypted_response_alg: request.id_token_encrypted_response_alg.as_deref(),
            id_token_encrypted_response_enc: request.id_token_encrypted_response_enc.as_deref(),
            request_object_signing_alg: request.request_object_signing_alg.as_deref(),
            request_object_encryption_alg: request.request_object_encryption_alg.as_deref(),
            request_object_encryption_enc: request.request_object_encryption_enc.as_deref(),
            token_endpoint_auth_signing_alg: request.token_endpoint_auth_signing_alg.as_deref(),
            introspection_signed_response_alg: request.introspection_signed_response_alg.as_deref(),
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
            backchannel_token_delivery_mode: &client.backchannel_token_delivery_mode,
            backchannel_client_notification_endpoint: client
                .backchannel_client_notification_endpoint
                .as_deref(),
            backchannel_authentication_request_signing_alg: client
                .backchannel_authentication_request_signing_alg
                .as_deref(),
            backchannel_user_code_parameter: client.backchannel_user_code_parameter,
            backchannel_logout_uri: client.backchannel_logout_uri.as_deref(),
            frontchannel_logout_uri: client.frontchannel_logout_uri.as_deref(),
            jwks: client.jwks.as_ref(),
            id_token_signed_response_alg: client.id_token_signed_response_alg.as_deref(),
            id_token_encrypted_response_alg: client.id_token_encrypted_response_alg.as_deref(),
            id_token_encrypted_response_enc: client.id_token_encrypted_response_enc.as_deref(),
            request_object_signing_alg: client.request_object_signing_alg.as_deref(),
            request_object_encryption_alg: client.request_object_encryption_alg.as_deref(),
            request_object_encryption_enc: client.request_object_encryption_enc.as_deref(),
            token_endpoint_auth_signing_alg: client.token_endpoint_auth_signing_alg.as_deref(),
            introspection_signed_response_alg: client.introspection_signed_response_alg.as_deref(),
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
    id_token_signing_algorithms: &[String],
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
    let ciba_enabled = metadata
        .grant_types
        .iter()
        .any(|grant| grant == "urn:openid:params:grant-type:ciba");
    if !matches!(metadata.backchannel_token_delivery_mode, "poll" | "ping") {
        return invalid("backchannel_token_delivery_mode 必须是 poll 或 ping；push 不受支持");
    }
    if metadata.backchannel_token_delivery_mode == "ping" && !ciba_enabled {
        return invalid("ping delivery mode 只能用于启用 CIBA grant 的客户端");
    }
    match (
        metadata.backchannel_token_delivery_mode,
        metadata.backchannel_client_notification_endpoint,
    ) {
        ("ping", None) => {
            return invalid("ping delivery mode 必须配置 backchannel_client_notification_endpoint");
        }
        ("poll", Some(_)) => {
            return invalid("poll delivery mode 不得配置 backchannel_client_notification_endpoint");
        }
        _ => {}
    }
    if let Some(uri) = metadata.backchannel_client_notification_endpoint {
        validate_ciba_notification_uri(uri)?;
    }
    if metadata.backchannel_user_code_parameter {
        return invalid("backchannel_user_code_parameter=true 不受支持");
    }
    if metadata
        .backchannel_authentication_request_signing_alg
        .is_some_and(|algorithm| !matches!(algorithm, "EdDSA" | "ES256" | "PS256"))
    {
        return invalid(
            "backchannel_authentication_request_signing_alg 必须是 EdDSA、ES256 或 PS256",
        );
    }
    if !ciba_enabled
        && (metadata
            .backchannel_authentication_request_signing_alg
            .is_some()
            || metadata.backchannel_user_code_parameter)
    {
        return invalid("CIBA 注册元数据只能用于启用 CIBA grant 的客户端");
    }
    if let Some(jwks) = metadata.jwks
        && metadata.token_endpoint_auth_method != "self_signed_tls_client_auth"
    {
        crypto
            .validate_jwks(jwks)
            .map_err(AdminClientError::InvalidRequest)?;
    }
    validate_response_crypto_metadata(
        "id_token",
        metadata.id_token_signed_response_alg,
        metadata.id_token_encrypted_response_alg,
        metadata.id_token_encrypted_response_enc,
        metadata.jwks,
        id_token_signing_algorithms,
        crypto,
    )?;
    validate_response_crypto_metadata(
        "introspection",
        metadata.introspection_signed_response_alg,
        metadata.introspection_encrypted_response_alg,
        metadata.introspection_encrypted_response_enc,
        metadata.jwks,
        response_signing_algorithms,
        crypto,
    )?;
    validate_request_object_crypto_metadata(
        metadata.request_object_signing_alg,
        metadata.request_object_encryption_alg,
        metadata.request_object_encryption_enc,
    )?;
    for (field, algorithm) in [
        (
            "request_object_signing_alg",
            metadata.request_object_signing_alg,
        ),
        (
            "token_endpoint_auth_signing_alg",
            metadata.token_endpoint_auth_signing_alg,
        ),
        (
            "backchannel_authentication_request_signing_alg",
            metadata.backchannel_authentication_request_signing_alg,
        ),
    ] {
        if let Some(algorithm) = algorithm
            && !metadata
                .jwks
                .is_some_and(|jwks| crypto.contains_signing_key_for_algorithm(jwks, algorithm))
        {
            return invalid(format!("{field} 必须有一个算法匹配的客户端签名 jwks 公钥"));
        }
    }
    if let Some(algorithm) = metadata.token_endpoint_auth_signing_alg {
        if metadata.token_endpoint_auth_method != "private_key_jwt" {
            return invalid("token_endpoint_auth_signing_alg 只能用于 private_key_jwt 客户端");
        }
        if !SUPPORTED_CLIENT_JWT_SIGNING_ALGS.contains(&algorithm) {
            return invalid(format!(
                "token_endpoint_auth_signing_alg 必须是 {}",
                SUPPORTED_CLIENT_JWT_SIGNING_ALGS.join(", ")
            ));
        }
    }
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
    if metadata.token_endpoint_auth_method == "tls_client_auth" {
        let selector_count = metadata.mtls.standard_selector_count();
        if selector_count != 1 {
            return invalid(
                "tls_client_auth 客户端必须且只能注册一个 RFC 8705 subject DN 或 SAN 绑定值",
            );
        }
    }
    if metadata.token_endpoint_auth_method == "self_signed_tls_client_auth"
        && !metadata
            .jwks
            .is_some_and(|jwks| crypto.valid_self_signed_mtls_jwks(jwks))
    {
        return invalid("self_signed_tls_client_auth 客户端必须注册有效 x5c 证书");
    }
    validate_mtls_metadata(&metadata.mtls, crypto)?;
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
        && !metadata.grant_types.iter().any(|grant| {
            matches!(
                grant.as_str(),
                "authorization_code"
                    | "urn:openid:params:grant-type:ciba"
                    | "urn:ietf:params:oauth:grant-type:device_code"
            )
        })
    {
        return invalid(
            "refresh_token 必须与当前实现能够签发 refresh token 的 authorization_code、CIBA 或 device_code 授权类型一起启用",
        );
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
        validate_uri_length("post_logout_redirect_uri", uri)?;
        validate_oauth_redirect_uri(metadata.client_type, uri)
            .map_err(|error| AdminClientError::InvalidRequest(error.to_string()))?;
    }
    if let Some(uri) = metadata.backchannel_logout_uri {
        validate_logout_uri("backchannel_logout_uri", uri)?;
    }
    if let Some(uri) = metadata.frontchannel_logout_uri {
        validate_logout_uri("frontchannel_logout_uri", uri)?;
        validate_frontchannel_logout_origin(uri, metadata.redirect_uris)?;
    }
    Ok(())
}

fn validate_ciba_notification_uri(uri: &str) -> Result<(), AdminClientError> {
    validate_uri_length("backchannel_client_notification_endpoint", uri)?;
    let parsed = url::Url::parse(uri).map_err(|_| {
        AdminClientError::InvalidRequest(
            "backchannel_client_notification_endpoint 必须是绝对 HTTPS URI".to_owned(),
        )
    })?;
    if parsed.scheme() != "https"
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.fragment().is_some()
    {
        return invalid(
            "backchannel_client_notification_endpoint 必须是无 userinfo 和 fragment 的绝对 HTTPS URI",
        );
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

fn validate_request_object_crypto_metadata(
    signing_algorithm: Option<&str>,
    encryption_algorithm: Option<&str>,
    encryption: Option<&str>,
) -> Result<(), AdminClientError> {
    if let Some(algorithm) = signing_algorithm
        && !SUPPORTED_CLIENT_JWT_SIGNING_ALGS.contains(&algorithm)
    {
        return invalid(format!(
            "request_object_signing_alg 必须是 {}",
            SUPPORTED_CLIENT_JWT_SIGNING_ALGS.join(", ")
        ));
    }
    match (encryption_algorithm, encryption) {
        (None, None) => Ok(()),
        (None, Some(_)) => invalid(
            "request_object_encryption_enc 不能在未设置 request_object_encryption_alg 时使用",
        ),
        (Some(_), None) => {
            invalid("request_object_encryption_alg 必须同时配置 request_object_encryption_enc")
        }
        (Some("RSA-OAEP-256"), Some("A256GCM")) => Ok(()),
        (Some(_), Some(_)) => invalid("request_object encryption 必须使用 RSA-OAEP-256 和 A256GCM"),
    }
}

fn validate_mtls_metadata<C: AdminClientCryptoPort + ?Sized>(
    metadata: &ClientMtlsMetadata<'_>,
    crypto: &C,
) -> Result<(), AdminClientError> {
    if metadata
        .subject_dn
        .is_some_and(|value| value.trim().is_empty())
    {
        return invalid("tls_client_auth_subject_dn 不能为空");
    }
    if let Some(subject_dn) = metadata.subject_dn {
        crypto
            .validate_rfc4514_dn(subject_dn)
            .map_err(AdminClientError::InvalidRequest)?;
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
    for value in metadata.san_dns {
        if !matches!(url::Host::parse(value), Ok(url::Host::Domain(_))) {
            return invalid(format!(
                "tls_client_auth_san_dns 必须是合法 DNS 名称: {value}"
            ));
        }
    }
    for value in metadata.san_uri {
        let parsed = url::Url::parse(value).map_err(|_| {
            AdminClientError::InvalidRequest(format!(
                "tls_client_auth_san_uri 必须是合法绝对 URI: {value}"
            ))
        })?;
        if parsed.scheme().is_empty() {
            return invalid(format!(
                "tls_client_auth_san_uri 必须是合法绝对 URI: {value}"
            ));
        }
    }
    for value in metadata.san_ip {
        value.parse::<std::net::IpAddr>().map_err(|_| {
            AdminClientError::InvalidRequest(format!(
                "tls_client_auth_san_ip 必须是合法 IP 地址: {value}"
            ))
        })?;
    }
    for value in metadata.san_email {
        let Some((local, domain)) = value.rsplit_once('@') else {
            return invalid(format!(
                "tls_client_auth_san_email 必须是合法邮箱地址: {value}"
            ));
        };
        if local.is_empty() || !matches!(url::Host::parse(domain), Ok(url::Host::Domain(_))) {
            return invalid(format!(
                "tls_client_auth_san_email 必须是合法邮箱地址: {value}"
            ));
        }
    }
    Ok(())
}

impl ClientMtlsMetadata<'_> {
    fn standard_selector_count(&self) -> usize {
        usize::from(self.subject_dn.is_some())
            + self.san_dns.len()
            + self.san_uri.len()
            + self.san_ip.len()
            + self.san_email.len()
    }
}

fn validate_logout_uri(field: &str, uri: &str) -> Result<(), AdminClientError> {
    validate_uri_length(field, uri)?;
    let parsed = url::Url::parse(uri)
        .map_err(|error| AdminClientError::InvalidRequest(error.to_string()))?;
    if parsed.fragment().is_some() {
        return invalid(format!("{field} 不能包含 fragment"));
    }
    if parsed.host_str().is_none() || !parsed.username().is_empty() || parsed.password().is_some() {
        return invalid(format!("{field} 必须是无 userinfo 的绝对网络 URI"));
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

fn validate_uri_length(field: &str, uri: &str) -> Result<(), AdminClientError> {
    if uri.len() > MAX_CIBA_LOGOUT_URI_BYTES {
        return invalid(format!("{field} 超过 {MAX_CIBA_LOGOUT_URI_BYTES} 字节"));
    }
    Ok(())
}

fn validate_frontchannel_logout_origin(
    logout_uri: &str,
    redirect_uris: &[String],
) -> Result<(), AdminClientError> {
    let logout = url::Url::parse(logout_uri)
        .map_err(|error| AdminClientError::InvalidRequest(error.to_string()))?;
    let logout_origin = logout.origin();
    let matches_registered_redirect = redirect_uris.iter().any(|redirect_uri| {
        url::Url::parse(redirect_uri).is_ok_and(|redirect| {
            matches!(redirect.scheme(), "http" | "https") && redirect.origin() == logout_origin
        })
    });
    if !matches_registered_redirect {
        return invalid(
            "frontchannel_logout_uri 的 scheme、host 和有效端口必须与一个 redirect_uri 相同",
        );
    }
    Ok(())
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
