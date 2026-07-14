use serde_json::{Value, json};

use crate::VerificationKey;

pub(crate) fn public_jwks(keys: &[VerificationKey]) -> Value {
    json!({
        "keys": keys.iter().map(|key| {
            let mut public = key.public_jwk.clone();
            if let Some(object) = public.as_object_mut() {
                for member in ["d", "p", "q", "dp", "dq", "qi", "oth", "k"] {
                    object.remove(member);
                }
            }
            public
        }).collect::<Vec<_>>()
    })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn jwks_never_publishes_private_members() {
        let jwks = public_jwks(&[VerificationKey {
            kid: "public-only".to_owned(),
            public_jwk: json!({
                "kty": "OKP", "crv": "Ed25519", "x": "public", "d": "private",
                "kid": "public-only", "alg": "EdDSA", "use": "sig"
            }),
        }]);
        assert!(jwks["keys"][0].get("d").is_none());
    }
}
