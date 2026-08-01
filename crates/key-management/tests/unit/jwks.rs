use serde_json::json;

use super::*;

#[test]
fn jwks_never_publishes_private_members() {
    let jwks = public_jwks(
        &[VerificationKey {
            kid: "public-only".to_owned(),
            public_jwk: json!({
                "kty": "OKP", "crv": "Ed25519", "x": "public", "d": "private",
                "kid": "public-only", "alg": "EdDSA", "use": "sig"
            }),
            signing_purposes: Default::default(),
        }],
        &json!({
            "kty": "RSA", "use": "enc", "alg": "RSA-OAEP-256",
            "kid": "request-object", "n": "public", "e": "AQAB"
        }),
    );
    assert!(jwks["keys"][0].get("d").is_none());
    assert_eq!(jwks["keys"][1]["use"], "enc");
}
