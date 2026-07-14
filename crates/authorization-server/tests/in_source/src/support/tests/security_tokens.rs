use super::*;

// ---------------------------------------------------------------------------
// access_token_header
// ---------------------------------------------------------------------------

#[test]
fn access_token_header_sets_alg_kid_and_at_jwt_type() {
    let header = access_token_header(jsonwebtoken::Algorithm::ES256, "key-id-1");

    assert_eq!(header.alg, jsonwebtoken::Algorithm::ES256);
    assert_eq!(header.typ.as_deref(), Some("at+jwt"));
    assert_eq!(header.kid.as_deref(), Some("key-id-1"));
}

#[test]
fn access_token_header_supports_rs256_and_eddsa_algorithms() {
    for (alg, kid) in [
        (jsonwebtoken::Algorithm::RS256, "rsa-key"),
        (jsonwebtoken::Algorithm::EdDSA, "ed-key"),
        (jsonwebtoken::Algorithm::PS256, "ps-key"),
    ] {
        let header = access_token_header(alg, kid);
        assert_eq!(header.alg, alg);
        assert_eq!(header.typ.as_deref(), Some("at+jwt"));
        assert_eq!(header.kid.as_deref(), Some(kid));
    }
}
