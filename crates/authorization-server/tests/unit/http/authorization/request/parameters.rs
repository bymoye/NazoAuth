use super::*;

fn query(values: &[(&str, &str)]) -> HashMap<String, String> {
    values
        .iter()
        .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
        .collect()
}

#[test]
fn duplicate_parameter_policy_covers_authorization_inputs_and_internal_reauth_nonce() {
    let parameters = authorization_duplicate_parameters();

    for expected in AUTHORIZED_REQUEST_PARAMETERS
        .iter()
        .copied()
        .filter(|parameter| *parameter != "resource")
        .chain([reauth_nonce_parameter()])
    {
        assert!(parameters.contains(&expected), "missing {expected}");
    }
    assert!(!parameters.contains(&"resource"));
}

#[test]
fn claim_request_names_preserve_normalized_order() {
    let requests = vec![
        OidcClaimRequest {
            name: "email".to_owned(),
            essential: true,
            value: None,
            values: Vec::new(),
        },
        OidcClaimRequest {
            name: "name".to_owned(),
            essential: false,
            value: None,
            values: Vec::new(),
        },
    ];

    assert_eq!(claim_request_names(&requests), ["email", "name"]);
    assert!(claim_request_names(&[]).is_empty());
}

#[test]
fn verified_dpop_binding_is_added_only_when_the_request_did_not_supply_one() {
    let mut missing = query(&[("client_id", "client")]);
    preserve_verified_dpop_binding(&mut missing, Some("verified-thumbprint"));
    assert_eq!(
        missing.get("dpop_jkt").map(String::as_str),
        Some("verified-thumbprint")
    );

    let mut explicit = query(&[("dpop_jkt", "request-thumbprint")]);
    preserve_verified_dpop_binding(&mut explicit, Some("verified-thumbprint"));
    assert_eq!(
        explicit.get("dpop_jkt").map(String::as_str),
        Some("request-thumbprint")
    );

    let mut absent = HashMap::new();
    preserve_verified_dpop_binding(&mut absent, None);
    assert!(!absent.contains_key("dpop_jkt"));
}

#[test]
fn outer_request_uri_parameters_must_match_pushed_values() {
    let pushed = query(&[("scope", "openid"), ("state", "state-1")]);

    assert!(outer_request_uri_parameters_match_pushed(
        &query(&[("scope", "openid"), ("request_uri", "urn:par:1")]),
        &pushed,
    ));
    assert!(!outer_request_uri_parameters_match_pushed(
        &query(&[("scope", "profile")]),
        &pushed,
    ));
    assert!(outer_request_uri_parameters_match_pushed(
        &query(&[("client_id", "outer-client")]),
        &pushed,
    ));
}

#[test]
fn fapi_outer_request_allows_only_client_id_and_request_uri() {
    assert!(outer_request_uri_parameters_are_fapi_compliant(&query(&[
        ("client_id", "client"),
        ("request_uri", "urn:par:1"),
    ])));
    assert!(!outer_request_uri_parameters_are_fapi_compliant(&query(&[
        ("client_id", "client"),
        ("scope", "openid"),
    ])));
}

#[test]
fn login_query_preserves_the_original_par_reference() {
    let expanded = query(&[("scope", "openid"), ("state", "expanded")]);
    let original = query(&[("request_uri", "urn:par:1"), ("state", "original")]);
    let request_uri = original.get("request_uri");

    assert_eq!(
        authorization_login_query(&expanded, &original, request_uri),
        original
    );
    assert_eq!(
        authorization_login_query(&expanded, &original, None),
        expanded
    );
}

#[test]
fn login_url_encodes_next_request_and_optional_reauth_nonce() {
    let url = authorization_login_url_for_frontend(
        "https://frontend.example/",
        &query(&[("client_id", "client 1")]),
        Some("reauth nonce"),
    );

    assert!(url.starts_with("https://frontend.example/auth?next="));
    let parsed = url::Url::parse(&url).expect("login URL is valid");
    let next = parsed
        .query_pairs()
        .find_map(|(key, value)| (key == "next").then(|| value.into_owned()))
        .expect("next parameter exists");
    let next = url::Url::parse(&format!("https://server.example{next}"))
        .expect("decoded next value is a relative authorization URL");
    assert_eq!(next.path(), "/authorize");
    assert_eq!(
        next.query_pairs()
            .collect::<HashMap<_, _>>()
            .get("client_id"),
        Some(&std::borrow::Cow::Borrowed("client 1"))
    );
    assert_eq!(
        next.query_pairs()
            .collect::<HashMap<_, _>>()
            .get(reauth_nonce_parameter()),
        Some(&std::borrow::Cow::Borrowed("reauth nonce"))
    );
}
