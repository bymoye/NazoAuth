//! OAuth/OIDC URL policy, including the OAuth native-app exceptions.

use anyhow::bail;
use url::Url;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedirectUriError {
    Missing,
    Invalid,
}

pub fn validate_issuer_url(value: &str) -> anyhow::Result<()> {
    let url = parse_url("issuer", value)?;
    if !url.has_host() {
        bail!("issuer 必须包含 host");
    }
    if value.ends_with('/') {
        bail!("issuer 不能以 / 结尾");
    }
    reject_url_credentials("issuer", &url)?;
    if url.query().is_some() || url.fragment().is_some() {
        bail!("issuer 不能包含 query 或 fragment");
    }
    validate_https_or_loopback_http("issuer", &url)
}

pub fn validate_frontend_base_url(value: &str) -> anyhow::Result<()> {
    let url = parse_url("FRONTEND_BASE_URL", value)?;
    if !url.has_host() {
        bail!("FRONTEND_BASE_URL 必须包含 host");
    }
    reject_url_credentials("FRONTEND_BASE_URL", &url)?;
    if url.query().is_some() || url.fragment().is_some() {
        bail!("FRONTEND_BASE_URL 不能包含 query 或 fragment");
    }
    validate_https_or_loopback_http("FRONTEND_BASE_URL", &url)
}

pub fn validate_cors_origin(value: &str) -> anyhow::Result<()> {
    let url = parse_url("CORS_ALLOWED_ORIGINS", value)?;
    if !url.has_host() {
        bail!("CORS_ALLOWED_ORIGINS 必须包含 host");
    }
    reject_url_credentials("CORS_ALLOWED_ORIGINS", &url)?;
    if url.path() != "/" || url.query().is_some() || url.fragment().is_some() {
        bail!("CORS_ALLOWED_ORIGINS 只能配置 origin，不能包含 path、query 或 fragment");
    }
    validate_https_or_loopback_http("CORS_ALLOWED_ORIGINS", &url)
}

pub fn validate_protected_resource_identifier(value: &str) -> anyhow::Result<()> {
    let url = parse_url("PROTECTED_RESOURCE_IDENTIFIER", value)?;
    if !url.has_host() {
        bail!("PROTECTED_RESOURCE_IDENTIFIER 必须包含 host");
    }
    reject_url_credentials("PROTECTED_RESOURCE_IDENTIFIER", &url)?;
    if url.fragment().is_some() {
        bail!("PROTECTED_RESOURCE_IDENTIFIER 不能包含 fragment");
    }
    validate_https_or_loopback_http("PROTECTED_RESOURCE_IDENTIFIER", &url)
}

pub fn validate_oauth_redirect_uri(client_type: &str, value: &str) -> anyhow::Result<()> {
    if value.contains('*') {
        bail!("redirect_uri 不支持通配符");
    }
    let uri = parse_url("redirect_uri", value)?;
    reject_url_credentials("redirect_uri", &uri)?;
    if uri.fragment().is_some() {
        bail!("redirect_uri 不能包含 fragment");
    }

    match uri.scheme() {
        "https" => Ok(()),
        "http" => {
            if client_type != "public" || !is_loopback_host(&uri) {
                bail!("http redirect_uri 只允许 public native client 使用 loopback 地址");
            }
            Ok(())
        }
        scheme if client_type == "public" && is_private_use_scheme(scheme) => Ok(()),
        _ => bail!("redirect_uri 必须使用 https、loopback http 或 public native 私有 scheme"),
    }
}

#[must_use]
pub fn oauth_redirect_uri_matches(client_type: &str, registered: &str, requested: &str) -> bool {
    if registered == requested {
        return true;
    }
    if client_type != "public" {
        return false;
    }

    let (Ok(registered), Ok(requested)) = (Url::parse(registered), Url::parse(requested)) else {
        return false;
    };
    registered.scheme() == "http"
        && requested.scheme() == "http"
        && is_loopback_host(&registered)
        && is_loopback_host(&requested)
        && registered.host_str() == requested.host_str()
        && registered.username() == requested.username()
        && registered.password() == requested.password()
        && registered.path() == requested.path()
        && registered.query() == requested.query()
        && registered.fragment() == requested.fragment()
}

/// Resolves the redirect URI using OAuth exact-match rules and the native-app
/// loopback port exception implemented by [`oauth_redirect_uri_matches`].
pub fn resolve_registered_redirect_uri(
    client_type: &str,
    registered: &[String],
    requested_redirect_uri: Option<&str>,
) -> Result<String, RedirectUriError> {
    if let Some(value) = requested_redirect_uri {
        return registered
            .iter()
            .any(|registered| oauth_redirect_uri_matches(client_type, registered, value))
            .then(|| value.to_owned())
            .ok_or(RedirectUriError::Invalid);
    }
    match registered {
        [only] => Ok(only.clone()),
        _ => Err(RedirectUriError::Missing),
    }
}

/// Validates an RFC 7636 `code_verifier` or `code_challenge` value.
#[must_use]
pub fn is_valid_pkce_value(value: &str) -> bool {
    let len = value.len();
    (43..=128).contains(&len)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~'))
}

#[must_use]
pub fn is_loopback_http_url(value: &str) -> bool {
    Url::parse(value)
        .ok()
        .is_some_and(|url| url.scheme() == "http" && is_loopback_host(&url))
}

fn parse_url(name: &str, value: &str) -> anyhow::Result<Url> {
    if value != value.trim() {
        bail!("{name} 不能包含前后空白");
    }
    Url::parse(value).map_err(|_| anyhow::anyhow!("{name} 必须是绝对 URI"))
}

fn validate_https_or_loopback_http(name: &str, url: &Url) -> anyhow::Result<()> {
    match url.scheme() {
        "https" => Ok(()),
        "http" if is_loopback_host(url) => Ok(()),
        _ => bail!("{name} 必须使用 https，只有 loopback 本地开发地址允许 http"),
    }
}

fn reject_url_credentials(name: &str, url: &Url) -> anyhow::Result<()> {
    if !url.username().is_empty() || url.password().is_some() {
        bail!("{name} 不能包含用户名或密码");
    }
    Ok(())
}

fn is_loopback_host(url: &Url) -> bool {
    match url.host() {
        Some(url::Host::Domain(host)) => host.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(addr)) => addr.is_loopback(),
        Some(url::Host::Ipv6(addr)) => addr.is_loopback(),
        None => false,
    }
}

fn is_private_use_scheme(scheme: &str) -> bool {
    scheme.contains('.')
        && scheme
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.'))
}
