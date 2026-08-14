use super::*;
use actix_web::{http::header, test::TestRequest};
use nazo_http_actix::ScimCursorProtector;
use nazo_identity::scim::{SCIM_CURSOR_NONCE_LEN, SCIM_CURSOR_TAG_LEN};

#[test]
fn bearer_token_requires_bearer_scheme_and_one_nonempty_token() {
    let valid = TestRequest::default()
        .insert_header((header::AUTHORIZATION, "Bearer scim-token"))
        .to_http_request();
    assert_eq!(bearer_token(&valid), Some("scim-token"));

    let case_insensitive = TestRequest::default()
        .insert_header((header::AUTHORIZATION, "bearer\tscim-token"))
        .to_http_request();
    assert_eq!(bearer_token(&case_insensitive), Some("scim-token"));

    for value in [
        "Basic scim-token",
        "Bearer",
        "Bearer ",
        "Bearer scim-token extra",
    ] {
        let request = TestRequest::default()
            .insert_header((header::AUTHORIZATION, value))
            .to_http_request();
        assert_eq!(bearer_token(&request), None, "malformed bearer: {value:?}");
    }
}

#[test]
fn scim_cursor_protection_round_trips_and_rejects_tampering_or_truncation() {
    let protector = ServerScimCursorProtector::new("cursor-pepper")
        .expect("cursor protector should derive a key");
    let plaintext = b"tenant=system;actor=token-1;offset=20";
    let protected = protector
        .protect(plaintext)
        .expect("cursor should be encrypted");

    assert!(protected.len() > SCIM_CURSOR_NONCE_LEN + SCIM_CURSOR_TAG_LEN);
    assert_eq!(
        protector
            .unprotect(&protected)
            .expect("cursor should decrypt"),
        plaintext
    );

    let mut tampered = protected.clone();
    tampered[SCIM_CURSOR_NONCE_LEN] ^= 1;
    assert!(protector.unprotect(&tampered).is_err());
    assert!(
        protector
            .unprotect(&[0; SCIM_CURSOR_NONCE_LEN + SCIM_CURSOR_TAG_LEN])
            .is_err()
    );
}
