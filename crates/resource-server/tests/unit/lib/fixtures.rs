use super::*;
use jsonwebtoken::{
    EncodingKey, Header,
    jwk::{Jwk, PublicKeyUse},
};
use openssl::rsa::Rsa;
use serde_json::json;

pub(crate) struct Fixture {
    pub(crate) verifier: ResourceServerVerifier,
    pub(super) jwks: Value,
    pub(super) encoding_key: EncodingKey,
}

pub(crate) struct DpopFixture {
    pub(crate) encoding_key: EncodingKey,
    pub(crate) public_jwk: Jwk,
    pub(crate) jkt: String,
}

pub(crate) fn fixture() -> Fixture {
    let der = Rsa::generate(2048).unwrap().private_key_to_der().unwrap();
    let encoding_key = EncodingKey::from_rsa_der(&der);
    let mut jwk = Jwk::from_encoding_key(&encoding_key, Algorithm::RS256).unwrap();
    jwk.common.key_id = Some("test-rs256".to_owned());
    jwk.common.public_key_use = Some(PublicKeyUse::Signature);
    let jwks = json!({"keys": [serde_json::to_value(jwk).unwrap()]});
    let mut config = ResourceServerVerifierConfig::new(
        "https://issuer.example",
        "resource://default",
        jwks.clone(),
    );
    config.required_scopes = vec!["read".to_owned()];
    Fixture {
        verifier: ResourceServerVerifier::new(config).unwrap(),
        jwks,
        encoding_key,
    }
}

pub(crate) fn dpop_fixture() -> DpopFixture {
    let der = Rsa::generate(2048).unwrap().private_key_to_der().unwrap();
    let encoding_key = EncodingKey::from_rsa_der(&der);
    let mut public_jwk = Jwk::from_encoding_key(&encoding_key, Algorithm::RS256).unwrap();
    public_jwk.common.key_id = Some("dpop-rs256".to_owned());
    public_jwk.common.public_key_use = Some(PublicKeyUse::Signature);
    let public_jwk_value = serde_json::to_value(&public_jwk).unwrap();
    let jkt = dpop_jwk_thumbprint(&public_jwk_value).unwrap();
    DpopFixture {
        encoding_key,
        public_jwk,
        jkt,
    }
}

pub(crate) fn token(
    fixture: &Fixture,
    claim_overrides: Value,
    header_overrides: Option<Header>,
) -> String {
    let now = Utc::now().timestamp();
    let mut claims = json!({
        "iss": "https://issuer.example",
        "sub": "subject-1",
        "tenant_id": "00000000-0000-0000-0000-000000000001",
        "aud": "resource://default",
        "client_id": "client-1",
        "scope": "read write",
        "authorization_details": [],
        "token_use": "access",
        "jti": "jti-1",
        "iat": now,
        "nbf": now,
        "exp": now + 300
    });
    merge_object(&mut claims, claim_overrides);
    let mut header = header_overrides.unwrap_or_else(|| {
        let mut header = Header::new(Algorithm::RS256);
        header.typ = Some("at+jwt".to_owned());
        header.kid = Some("test-rs256".to_owned());
        header
    });
    if header.kid.is_none() {
        header.kid = Some("test-rs256".to_owned());
    }
    jsonwebtoken::encode(&header, &claims, &fixture.encoding_key).unwrap()
}

pub(crate) fn dpop_proof(
    fixture: &DpopFixture,
    access_token: &str,
    method: &str,
    htu: &str,
    jti: &str,
    nonce: Option<&str>,
    ath_override: Option<&str>,
) -> String {
    let mut claims = json!({
        "htu": htu,
        "htm": method,
        "iat": Utc::now().timestamp(),
        "jti": jti,
        "ath": ath_override
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| access_token_hash(access_token)),
    });
    if let Some(nonce) = nonce {
        claims["nonce"] = json!(nonce);
    }
    let mut header = Header::new(Algorithm::RS256);
    header.typ = Some("dpop+jwt".to_owned());
    header.jwk = Some(fixture.public_jwk.clone());
    jsonwebtoken::encode(&header, &claims, &fixture.encoding_key).unwrap()
}

pub(super) fn merge_object(target: &mut Value, overrides: Value) {
    let target = target.as_object_mut().unwrap();
    for (key, value) in overrides.as_object().unwrap() {
        target.insert(key.clone(), value.clone());
    }
}

pub(super) fn bearer(token: &str) -> String {
    format!("Bearer {token}")
}

pub(super) fn dpop(token: &str) -> String {
    format!("DPoP {token}")
}
