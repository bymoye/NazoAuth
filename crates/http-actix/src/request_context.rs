use actix_web::HttpRequest;

/// Framework-derived request facts passed to protocol/application code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestContext {
    pub method: String,
    pub path: String,
    pub peer_ip: Option<String>,
}

impl RequestContext {
    pub fn from_request(request: &HttpRequest) -> Self {
        Self {
            method: request.method().as_str().to_owned(),
            path: request.path().to_owned(),
            peer_ip: request.peer_addr().map(|address| address.ip().to_string()),
        }
    }
}
