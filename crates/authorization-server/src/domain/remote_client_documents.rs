use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use futures_util::StreamExt;
use reqwest::{StatusCode, header};
use serde_json::Value;
use tokio::sync::RwLock;
use url::Url;

use super::sector_identifier::is_blocked_ip;

const MAX_DOCUMENT_BYTES: usize = 128 * 1024;
const JWKS_CACHE_TTL: Duration = Duration::from_secs(30);

#[derive(Clone)]
pub(crate) struct RemoteClientDocumentResolver {
    private_network_origins: Arc<HashSet<String>>,
    jwks_cache: Arc<RwLock<HashMap<String, CachedJwks>>>,
}

#[derive(Clone)]
struct CachedJwks {
    fetched_at: Instant,
    document: Value,
}

impl RemoteClientDocumentResolver {
    pub(crate) fn new(private_network_origins: &[String]) -> Result<Self, String> {
        let mut origins = HashSet::new();
        for value in private_network_origins {
            let parsed = validate_https_url(value, false)?;
            if parsed.path() != "/" || parsed.query().is_some() || parsed.fragment().is_some() {
                return Err(format!(
                    "REMOTE_CLIENT_DOCUMENT_PRIVATE_ORIGINS entry must be an HTTPS origin: {value}"
                ));
            }
            origins.insert(parsed.origin().ascii_serialization());
        }
        Ok(Self {
            private_network_origins: Arc::new(origins),
            jwks_cache: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    pub(crate) async fn jwks(&self, uri: &str) -> Result<Value, String> {
        if let Some(cached) = self.jwks_cache.read().await.get(uri)
            && cached.fetched_at.elapsed() < JWKS_CACHE_TTL
        {
            return Ok(cached.document.clone());
        }
        let body = self.fetch(uri, RemoteDocumentKind::Jwks).await?;
        let document: Value = serde_json::from_slice(&body)
            .map_err(|_| "remote JWKS is not valid JSON".to_owned())?;
        if !document.is_object() || !document.get("keys").is_some_and(Value::is_array) {
            return Err("remote JWKS must be an object containing a keys array".to_owned());
        }
        self.jwks_cache.write().await.insert(
            uri.to_owned(),
            CachedJwks {
                fetched_at: Instant::now(),
                document: document.clone(),
            },
        );
        Ok(document)
    }

    pub(crate) async fn request_object(&self, uri: &str) -> Result<String, String> {
        let body = self.fetch(uri, RemoteDocumentKind::RequestObject).await?;
        let jwt = String::from_utf8(body)
            .map_err(|_| "remote request object must be UTF-8".to_owned())?;
        let jwt = jwt.trim();
        if jwt.is_empty() || jwt.len() > MAX_DOCUMENT_BYTES {
            return Err("remote request object is empty or oversized".to_owned());
        }
        Ok(jwt.to_owned())
    }

    async fn fetch(&self, uri: &str, kind: RemoteDocumentKind) -> Result<Vec<u8>, String> {
        let parsed = validate_https_url(uri, kind == RemoteDocumentKind::RequestObject)?;
        let host = parsed
            .host_str()
            .ok_or_else(|| "remote document URI has no host".to_owned())?;
        let port = parsed.port_or_known_default().unwrap_or(443);
        let allow_private = self
            .private_network_origins
            .contains(&parsed.origin().ascii_serialization());
        let addresses = tokio::net::lookup_host((host, port))
            .await
            .map_err(|_| "remote document DNS resolution failed".to_owned())?
            .collect::<Vec<SocketAddr>>();
        if addresses.is_empty() {
            return Err("remote document DNS returned no addresses".to_owned());
        }
        if !allow_private && addresses.iter().any(|address| is_blocked_ip(address.ip())) {
            return Err("remote document resolved to a blocked network".to_owned());
        }

        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(10))
            .connect_timeout(Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none())
            .resolve_to_addrs(host, &addresses)
            .build()
            .map_err(|_| "remote document HTTP client could not be built".to_owned())?;
        let response = client.get(parsed).send().await.map_err(|error| {
            if error.is_timeout() {
                "remote document request timed out".to_owned()
            } else {
                "remote document request failed".to_owned()
            }
        })?;
        if response.status() != StatusCode::OK {
            return Err("remote document returned a non-success status".to_owned());
        }
        if response
            .content_length()
            .is_some_and(|length| length > MAX_DOCUMENT_BYTES as u64)
        {
            return Err("remote document is oversized".to_owned());
        }
        let content_type = response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("")
            .to_ascii_lowercase();
        if !kind.accepts_content_type(&content_type) {
            return Err("remote document has an unsupported content type".to_owned());
        }
        let mut body = Vec::new();
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|_| "remote document body could not be read".to_owned())?;
            if body.len().saturating_add(chunk.len()) > MAX_DOCUMENT_BYTES {
                return Err("remote document is oversized".to_owned());
            }
            body.extend_from_slice(&chunk);
        }
        Ok(body)
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum RemoteDocumentKind {
    Jwks,
    RequestObject,
}

impl RemoteDocumentKind {
    fn accepts_content_type(self, content_type: &str) -> bool {
        let media_type = content_type.split(';').next().unwrap_or_default().trim();
        match self {
            Self::Jwks => matches!(media_type, "application/json" | "application/jwk-set+json"),
            Self::RequestObject => matches!(
                media_type,
                "application/jwt" | "application/oauth-authz-req+jwt"
            ),
        }
    }
}

fn validate_https_url(value: &str, allow_fragment: bool) -> Result<Url, String> {
    let parsed = Url::parse(value).map_err(|_| "remote document URI is invalid".to_owned())?;
    if parsed.scheme() != "https"
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || (!allow_fragment && parsed.fragment().is_some())
    {
        return Err(
            "remote document URI must be an absolute HTTPS URI without userinfo".to_owned(),
        );
    }
    Ok(parsed)
}

impl nazo_http_actix::RemoteJwksResolverPort for RemoteClientDocumentResolver {
    fn resolve<'a>(&'a self, uri: &'a str) -> nazo_http_actix::RemoteJwksFuture<'a> {
        Box::pin(async move { self.jwks(uri).await })
    }
}

#[cfg(test)]
#[path = "../../tests/unit/domain/remote_client_documents.rs"]
mod tests;
