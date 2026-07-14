use super::*;

#[test]
fn remembered_mfa_device_user_agent_hash_is_bound_to_non_empty_header() {
    let with_agent = actix_web::test::TestRequest::default()
        .insert_header((header::USER_AGENT, "Example Browser"))
        .to_http_request();
    let empty_agent = actix_web::test::TestRequest::default()
        .insert_header((header::USER_AGENT, "   "))
        .to_http_request();
    let missing_agent = actix_web::test::TestRequest::default().to_http_request();

    assert_eq!(
        request_user_agent_hash(&with_agent).as_deref(),
        Some(blake3_hex("Example Browser").as_str())
    );
    assert_eq!(
        request_user_agent_hash(&empty_agent),
        None,
        "blank User-Agent must not create a reusable remembered-device binding"
    );
    assert_eq!(
        request_user_agent_hash(&missing_agent),
        None,
        "missing User-Agent must remain unbound rather than matching an attacker supplied blank value"
    );
}
