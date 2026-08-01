use super::*;

#[test]
fn private_origin_allowlist_is_exact_and_https_only() {
    assert!(RemoteClientDocumentResolver::new(&["http://web:8443".to_owned()]).is_err());
    assert!(RemoteClientDocumentResolver::new(&["https://web:8443/path".to_owned()]).is_err());
    let resolver = RemoteClientDocumentResolver::new(&["https://web:8443".to_owned()]).unwrap();
    assert!(
        resolver
            .private_network_origins
            .contains("https://web:8443")
    );
}

#[test]
fn content_types_are_narrowly_accepted() {
    assert!(RemoteDocumentKind::Jwks.accepts_content_type("application/jwk-set+json"));
    assert!(RemoteDocumentKind::Jwks.accepts_content_type("application/json; charset=utf-8"));
    assert!(!RemoteDocumentKind::Jwks.accepts_content_type("application/jsonp"));
    assert!(!RemoteDocumentKind::Jwks.accepts_content_type("text/plain"));
    assert!(RemoteDocumentKind::RequestObject.accepts_content_type("application/jwt"));
    assert!(!RemoteDocumentKind::RequestObject.accepts_content_type("application/json"));
}
