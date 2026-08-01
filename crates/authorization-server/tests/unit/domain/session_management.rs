use super::client_allows_origin;

#[test]
fn client_origin_policy_requires_an_active_client_and_registered_redirect_origin() {
    let redirect_uris = vec![
        "https://client.example/callback".to_owned(),
        "https://client.example:443/alternate".to_owned(),
        "not a URI".to_owned(),
    ];

    assert!(client_allows_origin(
        true,
        &redirect_uris,
        "https://client.example"
    ));
    assert!(!client_allows_origin(
        false,
        &redirect_uris,
        "https://client.example"
    ));
    assert!(!client_allows_origin(
        true,
        &redirect_uris,
        "https://other.example"
    ));
    assert!(!client_allows_origin(
        true,
        &["not a URI".to_owned()],
        "https://client.example"
    ));
}
