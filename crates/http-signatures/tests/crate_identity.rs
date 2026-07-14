#[test]
fn crate_identity_and_public_docs_are_protocol_generic() {
    assert_eq!(env!("CARGO_PKG_NAME"), "nazo-http-signatures");

    let crate_docs = include_str!("../src/lib.rs");
    assert!(crate_docs.contains("HTTP Message Signatures"));
    assert!(crate_docs.contains("RFC 9421"));
    assert!(crate_docs.contains("Content-Digest"));
    assert!(!crate_docs.contains("FAPI"));
    assert!(
        !crate_docs
            .to_ascii_lowercase()
            .contains("authorization server")
    );
}
