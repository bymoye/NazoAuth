use nazo_auth::{IntrospectionSignInput, TokenSignerPort};
use serde_json::json;

use crate::KeyManager;

#[tokio::test]
async fn introspection_response_uses_registered_algorithm() {
    let manager = KeyManager::for_test_with_auxiliary(jsonwebtoken::Algorithm::PS256);
    let token = manager
        .sign_introspection_response(IntrospectionSignInput {
            issuer: "https://issuer.example",
            audience: "client",
            body: &json!({"active": true}),
            signing_algorithm: Some("PS256"),
        })
        .await
        .expect("PS256 introspection response");
    let header = jsonwebtoken::decode_header(&token).expect("JWT header");

    assert_eq!(header.alg, jsonwebtoken::Algorithm::PS256);
    assert_eq!(header.typ.as_deref(), Some("token-introspection+jwt"));
}
