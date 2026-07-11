//! OAuth 作用域、audience 与授权关系工具。
// 只处理 OAuth 语义中的集合判断和授权记录 upsert。

use super::{
    keyset::reject_private_jwk_members,
    mtls::{certificate_x5c_thumbprint, normalize_sha256_thumbprint},
    prelude::*,
    security::{
        SUPPORTED_CLIENT_JWE_CONTENT_ENC_ALGS, SUPPORTED_CLIENT_JWE_KEY_MANAGEMENT_ALGS,
        SUPPORTED_CLIENT_JWT_SIGNING_ALGS, blake3_hex, client_jwt_algorithm_from_name,
        jwt_decoding_key_from_jwk, supported_client_jwt_algorithm_name,
    },
    uri_policy::{oauth_redirect_uri_matches, validate_oauth_redirect_uri},
};

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

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RedirectUriError {
    Missing,
    Invalid,
}

pub(crate) fn json_array_to_strings(value: &Value) -> Vec<String> {
    value
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|v| v.as_str().map(ToOwned::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

pub(crate) fn parse_scope(raw: &str) -> Vec<String> {
    raw.split_whitespace()
        .map(ToOwned::to_owned)
        .filter(|v| !v.is_empty())
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ResourceIndicatorError {
    Invalid,
    Duplicate,
}

pub(crate) fn parse_resource_indicators(
    values: &[String],
) -> Result<Vec<String>, ResourceIndicatorError> {
    let mut seen = std::collections::HashSet::new();
    let mut resources = Vec::new();
    for value in values {
        let parsed = url::Url::parse(value).map_err(|_| ResourceIndicatorError::Invalid)?;
        if parsed.fragment().is_some() {
            return Err(ResourceIndicatorError::Invalid);
        }
        if !seen.insert(value.clone()) {
            return Err(ResourceIndicatorError::Duplicate);
        }
        resources.push(value.clone());
    }
    Ok(resources)
}

pub(crate) fn resource_indicators_from_parameter_value(
    value: Option<&str>,
) -> Result<Vec<String>, ResourceIndicatorError> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    if let Ok(values) = serde_json::from_str::<Vec<String>>(value) {
        return parse_resource_indicators(&values);
    }
    parse_resource_indicators(&[value.to_owned()])
}

pub(crate) fn encoded_resource_indicators(values: &[String]) -> Option<String> {
    (!values.is_empty()).then(|| {
        serde_json::to_string(values).expect("resource indicator serialization must be infallible")
    })
}

pub(crate) fn is_subset(requested: &[String], allowed: &[String]) -> bool {
    requested.iter().all(|s| allowed.contains(s))
}

pub(crate) fn client_supports_grant(client: &ClientRow, grant_type: &str) -> bool {
    json_array_to_strings(&client.grant_types)
        .iter()
        .any(|grant| grant == grant_type)
}

pub(crate) fn audience_allowed(client: &ClientRow, audience: &str) -> bool {
    json_array_to_strings(&client.allowed_audiences)
        .iter()
        .any(|allowed| allowed == audience)
}

pub(crate) fn audiences_allowed(client: &ClientRow, audiences: &[String]) -> bool {
    !audiences.is_empty()
        && audiences
            .iter()
            .all(|audience| audience_allowed(client, audience))
}

pub(crate) fn token_audience_values(audience: &Value) -> Vec<String> {
    match audience {
        Value::String(value) => vec![value.clone()],
        Value::Array(values) => values
            .iter()
            .filter_map(|value| value.as_str().map(ToOwned::to_owned))
            .collect(),
        _ => Vec::new(),
    }
}

pub(crate) fn token_audience_contains(audience: &Value, expected: &str) -> bool {
    token_audience_values(audience)
        .iter()
        .any(|audience| audience == expected)
}

pub(crate) fn token_audience_allowed(client: &ClientRow, audience: &Value) -> bool {
    token_audience_values(audience)
        .iter()
        .any(|audience| audience_allowed(client, audience))
}

pub(crate) fn sorted_scope_string(scopes: &[String]) -> String {
    let mut values = scopes.to_vec();
    values.sort();
    values.dedup();
    values.join(" ")
}

pub(crate) fn has_duplicate_oauth_parameter(raw_query: &str, parameter_names: &[&str]) -> bool {
    let mut seen = std::collections::HashSet::new();
    for (key, _) in url::form_urlencoded::parse(raw_query.as_bytes()) {
        if parameter_names.contains(&key.as_ref()) && !seen.insert(key.into_owned()) {
            return true;
        }
    }
    false
}

pub(crate) fn registered_redirect_uri(
    client: &ClientRow,
    requested_redirect_uri: Option<&str>,
) -> Result<String, RedirectUriError> {
    let registered = json_array_to_strings(&client.redirect_uris);
    if let Some(value) = requested_redirect_uri {
        return registered
            .iter()
            .any(|registered| oauth_redirect_uri_matches(&client.client_type, registered, value))
            .then(|| value.to_owned())
            .ok_or(RedirectUriError::Invalid);
    }
    match registered.as_slice() {
        [only] => Ok(only.clone()),
        _ => Err(RedirectUriError::Missing),
    }
}

pub(crate) fn is_valid_pkce_value(value: &str) -> bool {
    let len = value.len();
    (43..=128).contains(&len)
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'))
}

pub(crate) struct ClientMetadata<'a> {
    pub(crate) client_type: &'a str,
    pub(crate) redirect_uris: &'a [String],
    pub(crate) post_logout_redirect_uris: &'a [String],
    pub(crate) scopes: &'a [String],
    pub(crate) allowed_audiences: &'a [String],
    pub(crate) grant_types: &'a [String],
    pub(crate) token_endpoint_auth_method: &'a str,
    pub(crate) backchannel_logout_uri: Option<&'a str>,
    pub(crate) frontchannel_logout_uri: Option<&'a str>,
    pub(crate) jwks: Option<&'a Value>,
    pub(crate) allow_jwks_without_kid: bool,
    pub(crate) introspection_encrypted_response_alg: Option<&'a str>,
    pub(crate) introspection_encrypted_response_enc: Option<&'a str>,
    pub(crate) userinfo_signed_response_alg: Option<&'a str>,
    pub(crate) userinfo_encrypted_response_alg: Option<&'a str>,
    pub(crate) userinfo_encrypted_response_enc: Option<&'a str>,
    pub(crate) authorization_signed_response_alg: Option<&'a str>,
    pub(crate) authorization_encrypted_response_alg: Option<&'a str>,
    pub(crate) authorization_encrypted_response_enc: Option<&'a str>,
    pub(crate) response_signing_algorithms: &'a [&'static str],
    pub(crate) mtls_binding: Option<&'a ClientMtlsMetadata>,
}

pub(crate) fn validate_client_metadata(metadata: ClientMetadata<'_>) -> anyhow::Result<()> {
    let ClientMetadata {
        client_type,
        redirect_uris,
        post_logout_redirect_uris,
        scopes,
        allowed_audiences,
        grant_types,
        token_endpoint_auth_method,
        backchannel_logout_uri,
        frontchannel_logout_uri,
        jwks,
        allow_jwks_without_kid,
        introspection_encrypted_response_alg,
        introspection_encrypted_response_enc,
        userinfo_signed_response_alg,
        userinfo_encrypted_response_alg,
        userinfo_encrypted_response_enc,
        authorization_signed_response_alg,
        authorization_encrypted_response_alg,
        authorization_encrypted_response_enc,
        response_signing_algorithms,
        mtls_binding,
    } = metadata;
    if !matches!(client_type, "public" | "confidential") {
        anyhow::bail!("客户端类型无效");
    }
    validate_unique_non_empty("scope", scopes)?;
    validate_unique_non_empty("audience", allowed_audiences)?;
    validate_unique_non_empty("grant_type", grant_types)?;
    for grant in grant_types {
        if !SUPPORTED_GRANT_TYPES.contains(&grant.as_str()) {
            anyhow::bail!("不支持的 grant_type: {grant}");
        }
    }
    if !SUPPORTED_TOKEN_AUTH_METHODS.contains(&token_endpoint_auth_method) {
        anyhow::bail!("客户端认证方式无效");
    }
    if client_type == "public" && token_endpoint_auth_method != "none" {
        anyhow::bail!("public 客户端只能使用 none 认证方式");
    }
    if client_type == "confidential" && token_endpoint_auth_method == "none" {
        anyhow::bail!("confidential 客户端必须使用机密认证方式");
    }
    if let Some(jwks) = jwks
        && token_endpoint_auth_method != "self_signed_tls_client_auth"
    {
        validate_client_jwks_with_policy(
            jwks,
            ClientJwksValidationPolicy {
                allow_missing_kid: allow_jwks_without_kid,
            },
        )?;
    }
    validate_introspection_jwe_metadata(
        introspection_encrypted_response_alg,
        introspection_encrypted_response_enc,
        jwks,
    )?;
    validate_response_crypto_metadata(
        "userinfo",
        userinfo_signed_response_alg,
        userinfo_encrypted_response_alg,
        userinfo_encrypted_response_enc,
        jwks,
        response_signing_algorithms,
    )?;
    validate_response_crypto_metadata(
        "authorization",
        authorization_signed_response_alg,
        authorization_encrypted_response_alg,
        authorization_encrypted_response_enc,
        jwks,
        response_signing_algorithms,
    )?;
    if token_endpoint_auth_method == "private_key_jwt" {
        let Some(jwks) = jwks else {
            anyhow::bail!("private_key_jwt 客户端必须配置 jwks");
        };
        if !client_jwks_contains_signing_key(jwks) {
            anyhow::bail!("private_key_jwt 客户端必须配置签名 jwks");
        }
    }
    if token_endpoint_auth_method == "tls_client_auth"
        && !mtls_binding.is_some_and(ClientMtlsMetadata::has_binding_material)
    {
        anyhow::bail!("tls_client_auth 客户端必须注册 subject DN、SAN 或证书 SHA-256 绑定材料");
    }
    if token_endpoint_auth_method == "self_signed_tls_client_auth"
        && !jwks.is_some_and(validate_self_signed_mtls_jwks)
    {
        anyhow::bail!("self_signed_tls_client_auth 客户端必须注册有效 x5c 证书");
    }
    if let Some(mtls_binding) = mtls_binding {
        validate_mtls_metadata(mtls_binding)?;
    }
    if client_type == "public"
        && grant_types
            .iter()
            .any(|grant| grant == "client_credentials")
    {
        anyhow::bail!("public 客户端不能使用 client_credentials 授权类型");
    }
    if grant_types
        .iter()
        .any(|grant| grant == "client_credentials")
        && scopes.iter().any(|scope| scope == "openid")
    {
        anyhow::bail!("client_credentials 客户端不能申请 openid 作用域");
    }
    if grant_types.iter().any(|grant| grant == "refresh_token")
        && !grant_types
            .iter()
            .any(|grant| grant == "authorization_code")
    {
        anyhow::bail!("refresh_token 授权类型必须与 authorization_code 一起启用");
    }
    if scopes.iter().any(|scope| scope == "offline_access")
        && !grant_types.iter().any(|grant| grant == "refresh_token")
    {
        anyhow::bail!("offline_access 作用域必须与 refresh_token 授权类型一起启用");
    }
    if grant_types
        .iter()
        .any(|grant| grant == "authorization_code")
        && redirect_uris.is_empty()
    {
        anyhow::bail!("authorization_code 客户端必须注册 redirect_uri");
    }
    for redirect_uri in redirect_uris {
        validate_oauth_redirect_uri(client_type, redirect_uri)?;
    }
    validate_unique_non_empty("post_logout_redirect_uri", post_logout_redirect_uris)?;
    for redirect_uri in post_logout_redirect_uris {
        validate_oauth_redirect_uri(client_type, redirect_uri)?;
    }
    if let Some(uri) = backchannel_logout_uri {
        validate_logout_notification_uri("backchannel_logout_uri", uri)?;
    }
    if let Some(uri) = frontchannel_logout_uri {
        validate_logout_notification_uri("frontchannel_logout_uri", uri)?;
    }
    Ok(())
}

fn validate_introspection_jwe_metadata(
    alg: Option<&str>,
    enc: Option<&str>,
    jwks: Option<&Value>,
) -> anyhow::Result<()> {
    match (alg, enc) {
        (None, None) => Ok(()),
        (None, Some(_)) => {
            anyhow::bail!(
                "introspection_encrypted_response_enc 不能在未设置 introspection_encrypted_response_alg 时使用"
            );
        }
        (Some(alg), Some(enc)) => {
            if !SUPPORTED_CLIENT_JWE_KEY_MANAGEMENT_ALGS.contains(&alg) {
                anyhow::bail!(
                    "introspection_encrypted_response_alg 必须是 {}",
                    SUPPORTED_CLIENT_JWE_KEY_MANAGEMENT_ALGS.join(", ")
                );
            }
            if !SUPPORTED_CLIENT_JWE_CONTENT_ENC_ALGS.contains(&enc) {
                anyhow::bail!(
                    "introspection_encrypted_response_enc 必须是 {}",
                    SUPPORTED_CLIENT_JWE_CONTENT_ENC_ALGS.join(", ")
                );
            }
            match jwks.map(|jwks| client_jwks_matching_encryption_key_count(jwks, alg)) {
                Some(1) => {}
                Some(2..) => anyhow::bail!(
                    "启用 encrypted introspection response 必须且只能配置一个匹配的 jwks 加密公钥"
                ),
                _ => anyhow::bail!(
                    "启用 encrypted introspection response 必须配置匹配的 jwks 加密公钥"
                ),
            }
            Ok(())
        }
        (Some(_), None) => anyhow::bail!(
            "introspection_encrypted_response_alg 必须同时配置 introspection_encrypted_response_enc"
        ),
    }
}

fn validate_response_crypto_metadata(
    response_name: &str,
    signing_alg: Option<&str>,
    encryption_alg: Option<&str>,
    encryption_enc: Option<&str>,
    jwks: Option<&Value>,
    response_signing_algorithms: &[&str],
) -> anyhow::Result<()> {
    if let Some(signing_alg) = signing_alg
        && (!SUPPORTED_CLIENT_JWT_SIGNING_ALGS.contains(&signing_alg)
            || !response_signing_algorithms.contains(&signing_alg))
    {
        anyhow::bail!(
            "{response_name}_signed_response_alg 签名算法必须是当前服务可用算法: {}",
            response_signing_algorithms.join(", ")
        );
    }
    match (encryption_alg, encryption_enc) {
        (None, None) => Ok(()),
        (None, Some(_)) => anyhow::bail!(
            "{response_name}_encrypted_response_enc 不能在未设置 {response_name}_encrypted_response_alg 时使用"
        ),
        (Some(_), None) => anyhow::bail!(
            "{response_name}_encrypted_response_alg 必须同时配置 {response_name}_encrypted_response_enc"
        ),
        (Some(alg), Some(enc)) => {
            if !SUPPORTED_CLIENT_JWE_KEY_MANAGEMENT_ALGS.contains(&alg) {
                anyhow::bail!(
                    "{response_name}_encrypted_response_alg 必须是 {}",
                    SUPPORTED_CLIENT_JWE_KEY_MANAGEMENT_ALGS.join(", ")
                );
            }
            if !SUPPORTED_CLIENT_JWE_CONTENT_ENC_ALGS.contains(&enc) {
                anyhow::bail!(
                    "{response_name}_encrypted_response_enc 必须是 {}",
                    SUPPORTED_CLIENT_JWE_CONTENT_ENC_ALGS.join(", ")
                );
            }
            match jwks.map(|jwks| client_jwks_matching_encryption_key_count(jwks, alg)) {
                Some(1) => {}
                Some(2..) => anyhow::bail!(
                    "启用 {response_name} encrypted response 必须且只能配置一个匹配的 jwks 加密公钥"
                ),
                _ => anyhow::bail!(
                    "启用 {response_name} encrypted response 必须配置匹配的 jwks 加密公钥"
                ),
            }
            Ok(())
        }
    }
}

fn client_jwks_matching_encryption_key_count(jwks: &Value, alg: &str) -> usize {
    jwks.get("keys")
        .and_then(Value::as_array)
        .map_or(0, |keys| {
            keys.iter()
                .filter(|key| {
                    key.get("use").and_then(Value::as_str) == Some("enc")
                        && key.get("alg").and_then(Value::as_str) == Some(alg)
                        && valid_rsa_jwe_encryption_key(key)
                })
                .count()
        })
}

fn client_jwks_contains_signing_key(jwks: &Value) -> bool {
    jwks.get("keys")
        .and_then(Value::as_array)
        .is_some_and(|keys| {
            keys.iter().any(|key| {
                let public_key_use = key.get("use").and_then(Value::as_str).unwrap_or("sig");
                let Some(alg) = key.get("alg").and_then(Value::as_str) else {
                    return false;
                };
                let Some(algorithm) = client_jwt_algorithm_from_name(alg) else {
                    return false;
                };
                public_key_use == "sig"
                    && supported_client_jwt_algorithm_name(algorithm) == Some(alg)
                    && jwt_decoding_key_from_jwk(key, algorithm).is_some()
            })
        })
}

fn validate_logout_notification_uri(field: &str, uri: &str) -> anyhow::Result<()> {
    let parsed = url::Url::parse(uri)?;
    if parsed.fragment().is_some() {
        anyhow::bail!("{field} 不能包含 fragment");
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
        _ => anyhow::bail!("{field} 必须使用 https 或 loopback http"),
    }
}

fn validate_mtls_metadata(mtls_binding: &ClientMtlsMetadata) -> anyhow::Result<()> {
    if let Some(subject_dn) = mtls_binding.tls_client_auth_subject_dn.as_deref()
        && subject_dn.trim().is_empty()
    {
        anyhow::bail!("tls_client_auth_subject_dn 不能为空");
    }
    if let Some(cert_sha256) = mtls_binding.tls_client_auth_cert_sha256.as_deref()
        && normalize_sha256_thumbprint(cert_sha256).is_none()
    {
        anyhow::bail!("tls_client_auth_cert_sha256 必须是 SHA-256 证书指纹");
    }
    validate_unique_non_empty(
        "tls_client_auth_san_dns",
        &mtls_binding.tls_client_auth_san_dns,
    )?;
    validate_unique_non_empty(
        "tls_client_auth_san_uri",
        &mtls_binding.tls_client_auth_san_uri,
    )?;
    validate_unique_non_empty(
        "tls_client_auth_san_ip",
        &mtls_binding.tls_client_auth_san_ip,
    )?;
    validate_unique_non_empty(
        "tls_client_auth_san_email",
        &mtls_binding.tls_client_auth_san_email,
    )?;
    for value in &mtls_binding.tls_client_auth_san_ip {
        value
            .parse::<std::net::IpAddr>()
            .map_err(|_| anyhow::anyhow!("tls_client_auth_san_ip 必须是合法 IP 地址: {value}"))?;
    }
    Ok(())
}

#[derive(Debug, Default)]
pub(crate) struct ClientMtlsMetadata {
    pub(crate) tls_client_auth_subject_dn: Option<String>,
    pub(crate) tls_client_auth_cert_sha256: Option<String>,
    pub(crate) tls_client_auth_san_dns: Vec<String>,
    pub(crate) tls_client_auth_san_uri: Vec<String>,
    pub(crate) tls_client_auth_san_ip: Vec<String>,
    pub(crate) tls_client_auth_san_email: Vec<String>,
}

impl ClientMtlsMetadata {
    pub(crate) fn has_binding_material(&self) -> bool {
        self.tls_client_auth_subject_dn
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty())
            || self.has_cert_thumbprint()
            || !self.tls_client_auth_san_dns.is_empty()
            || !self.tls_client_auth_san_uri.is_empty()
            || !self.tls_client_auth_san_ip.is_empty()
            || !self.tls_client_auth_san_email.is_empty()
    }

    pub(crate) fn has_cert_thumbprint(&self) -> bool {
        self.tls_client_auth_cert_sha256
            .as_deref()
            .and_then(normalize_sha256_thumbprint)
            .is_some()
    }
}

#[cfg(test)]
pub(crate) fn validate_client_jwks(jwks: &Value) -> anyhow::Result<()> {
    validate_client_jwks_with_policy(
        jwks,
        ClientJwksValidationPolicy {
            allow_missing_kid: false,
        },
    )
}

struct ClientJwksValidationPolicy {
    allow_missing_kid: bool,
}

fn validate_client_jwks_with_policy(
    jwks: &Value,
    policy: ClientJwksValidationPolicy,
) -> anyhow::Result<()> {
    let keys = jwks
        .get("keys")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow::anyhow!("jwks 必须包含 keys 数组"))?;
    if keys.is_empty() {
        anyhow::bail!("jwks.keys 不能为空");
    }
    let mut seen_kids = std::collections::HashSet::new();
    let mut signing_key_count = 0usize;
    let mut kidless_signing_key_count = 0usize;
    for key in keys {
        let key_object = key
            .as_object()
            .ok_or_else(|| anyhow::anyhow!("jwks 公钥必须是 JSON object"))?;
        reject_private_jwk_members(key_object)
            .map_err(|_| anyhow::anyhow!("jwks 不能包含私钥材料或对称密钥材料"))?;
        let kid = key.get("kid").and_then(Value::as_str).unwrap_or_default();
        let public_key_use = key.get("use").and_then(Value::as_str).unwrap_or("sig");
        if public_key_use == "sig" {
            signing_key_count += 1;
        }
        if kid.trim().is_empty() {
            if public_key_use == "enc" {
                anyhow::bail!("jwks 加密公钥必须包含 kid");
            }
            if !policy.allow_missing_kid {
                anyhow::bail!("jwks 公钥必须包含 kid");
            }
            kidless_signing_key_count += 1;
        } else if !seen_kids.insert(kid) {
            anyhow::bail!("jwks kid 不能重复: {kid}");
        }
        let Some(alg) = key.get("alg").and_then(Value::as_str) else {
            anyhow::bail!("jwks 公钥必须声明 alg");
        };
        match public_key_use {
            "sig" => {
                let Some(algorithm) = client_jwt_algorithm_from_name(alg) else {
                    anyhow::bail!(
                        "jwks alg 必须是 {} 或 {}",
                        SUPPORTED_CLIENT_JWT_SIGNING_ALGS.join(", "),
                        SUPPORTED_CLIENT_JWE_KEY_MANAGEMENT_ALGS.join(", ")
                    );
                };
                if supported_client_jwt_algorithm_name(algorithm) != Some(alg)
                    || jwt_decoding_key_from_jwk(key, algorithm).is_none()
                {
                    anyhow::bail!("jwks 公钥材料与 alg 不匹配");
                }
            }
            "enc" => {
                if !SUPPORTED_CLIENT_JWE_KEY_MANAGEMENT_ALGS.contains(&alg)
                    || !valid_rsa_jwe_encryption_key(key)
                {
                    anyhow::bail!("jwks 公钥材料与 alg 不匹配");
                }
            }
            _ => anyhow::bail!("jwks 公钥 use 必须为 sig 或 enc"),
        }
    }
    if kidless_signing_key_count > 0 && signing_key_count != 1 {
        anyhow::bail!("省略 kid 时 jwks 必须且只能包含一个签名公钥");
    }
    Ok(())
}

fn valid_rsa_jwe_encryption_key(key: &Value) -> bool {
    if key.get("kty").and_then(Value::as_str) != Some("RSA") {
        return false;
    }
    let Some(n) = key.get("n").and_then(Value::as_str) else {
        return false;
    };
    let Some(e) = key.get("e").and_then(Value::as_str) else {
        return false;
    };
    let Ok(modulus) = URL_SAFE_NO_PAD.decode(n) else {
        return false;
    };
    let Ok(exponent) = URL_SAFE_NO_PAD.decode(e) else {
        return false;
    };
    modulus.len() >= 256 && !exponent.is_empty()
}

pub(crate) fn validate_self_signed_mtls_jwks(jwks: &Value) -> bool {
    jwks.get("keys")
        .and_then(Value::as_array)
        .is_some_and(|keys| {
            keys.iter().any(|key| {
                key.get("x5c")
                    .and_then(Value::as_array)
                    .and_then(|x5c| x5c.as_slice().first())
                    .and_then(Value::as_str)
                    .and_then(certificate_x5c_thumbprint)
                    .is_some()
            })
        })
}

fn validate_unique_non_empty(name: &str, values: &[String]) -> anyhow::Result<()> {
    let mut seen = std::collections::HashSet::new();
    for value in values {
        let trimmed = value.trim();
        if trimmed.is_empty() || value != trimmed || trimmed.split_whitespace().count() != 1 {
            anyhow::bail!("{name} 不能为空或包含空白字符");
        }
        if !seen.insert(trimmed) {
            anyhow::bail!("{name} 不能重复: {trimmed}");
        }
    }
    Ok(())
}

pub(crate) fn authorization_code_key(code: &str) -> String {
    authorization_code_key_from_hash(&blake3_hex(code))
}

pub(crate) fn authorization_code_key_from_hash(code_hash: &str) -> String {
    format!("oauth:auth_code:{code_hash}")
}

pub(crate) async fn upsert_grant(
    state: &AppState,
    user_id: Uuid,
    client_id: &str,
    scopes: &[String],
    resource_indicators: &[String],
    authorization_details: &Value,
) -> anyhow::Result<()> {
    let Some(client) = find_client(&state.diesel_db, client_id).await? else {
        return Ok(());
    };
    let tenant = default_tenant_context();
    if !tenant.same_tenant(client.tenant_id) {
        anyhow::bail!("client resolved outside the default tenant context");
    }
    let now = Utc::now();
    let mut conn = get_conn(&state.diesel_db).await?;
    diesel::insert_into(user_client_grants::table)
        .values((
            user_client_grants::tenant_id.eq(client.tenant_id),
            user_client_grants::user_id.eq(user_id),
            user_client_grants::client_id.eq(client.id),
            user_client_grants::first_authorized_at.eq(now),
            user_client_grants::last_authorized_at.eq(now),
            user_client_grants::last_scopes.eq(json!(scopes)),
            user_client_grants::last_resource_indicators.eq(json!(resource_indicators)),
            user_client_grants::last_authorization_details.eq(authorization_details.clone()),
            user_client_grants::authorization_count.eq(1),
        ))
        .on_conflict((
            user_client_grants::tenant_id,
            user_client_grants::user_id,
            user_client_grants::client_id,
        ))
        .do_update()
        .set((
            user_client_grants::last_authorized_at.eq(now),
            user_client_grants::last_scopes.eq(json!(scopes)),
            user_client_grants::last_resource_indicators.eq(json!(resource_indicators)),
            user_client_grants::last_authorization_details.eq(authorization_details.clone()),
            user_client_grants::authorization_count.eq(user_client_grants::authorization_count + 1),
        ))
        .execute(&mut conn)
        .await?;
    Ok(())
}

#[cfg(test)]
#[path = "../../tests/in_source/src/support/tests/oauth_client_jwks.rs"]
mod oauth_client_jwks_tests;

#[cfg(test)]
#[path = "../../tests/in_source/src/support/tests/oauth_client_metadata.rs"]
mod oauth_client_metadata_tests;

#[cfg(test)]
#[path = "../../tests/in_source/src/support/tests/oauth_mtls_metadata.rs"]
mod oauth_mtls_metadata_tests;

#[cfg(test)]
#[path = "../../tests/in_source/src/support/tests/oauth_redirect_pkce.rs"]
mod oauth_redirect_pkce_tests;
