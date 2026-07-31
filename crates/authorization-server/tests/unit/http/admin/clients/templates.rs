use super::*;

#[test]
fn reviewed_templates_are_closed_and_security_preserving() {
    let document = client_templates_document();
    let templates = document["templates"].as_array().unwrap();
    assert_eq!(templates.len(), 4);
    assert_eq!(templates[0]["id"], "web");
    assert_eq!(templates[1]["id"], "native");
    assert_eq!(templates[2]["id"], "service");
    assert_eq!(templates[3]["id"], "fapi2");
    assert_eq!(
        templates[1]["defaults"]["token_endpoint_auth_method"],
        "none"
    );
    assert_eq!(templates[1]["defaults"]["require_dpop_bound_tokens"], true);
    assert_eq!(
        templates[3]["defaults"]["token_endpoint_auth_method"],
        "private_key_jwt"
    );
    assert_eq!(
        templates[3]["defaults"]["security_policy"]["assurance"],
        "fapi2"
    );
}
