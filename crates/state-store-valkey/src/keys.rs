const FAPI_HTTP_SIGNATURE_REPLAY_PREFIX: &str = "fapi_http_signature_replay:";

pub(crate) fn fapi_http_signature_replay(fingerprint: &[u8; 32]) -> String {
    format!(
        "{FAPI_HTTP_SIGNATURE_REPLAY_PREFIX}{}",
        blake3::Hash::from_bytes(*fingerprint).to_hex()
    )
}

fn blake3_hex(value: &str) -> String {
    blake3::hash(value.as_bytes()).to_hex().to_string()
}

pub(crate) fn dpop_replay(jkt: &str, jti: &str) -> String {
    format!("oauth:dpop:jti:{jkt}:{}", blake3_hex(jti))
}

pub(crate) fn dpop_nonce(nonce: &str) -> String {
    format!("oauth:dpop:nonce:{}", blake3_hex(nonce))
}

pub(crate) fn private_key_jwt_replay(client_id: &str, jti: &str) -> String {
    format!(
        "oauth:client_assertion:jti:{}:{}",
        blake3_hex(client_id),
        blake3_hex(jti)
    )
}

pub(crate) fn jar_replay(client_id: &str, jti: &str) -> String {
    format!(
        "oauth:jar:jti:{}:{}",
        blake3_hex(client_id),
        blake3_hex(jti)
    )
}

pub(crate) fn jwt_bearer_replay(client_id: &str, jti: &str) -> String {
    format!(
        "oauth:jwt_bearer:jti:{}:{}",
        blake3_hex(client_id),
        blake3_hex(jti)
    )
}

pub(crate) fn session(session_id: &str) -> String {
    format!("oauth:session:{session_id}")
}

pub(crate) fn client_delivery(user_id: nazo_identity::UserId, token: &str) -> String {
    format!("oauth:client_delivery:{}:{token}", user_id.as_uuid())
}

pub(crate) fn consent(request_id: &str) -> String {
    format!("oauth:consent:{request_id}")
}

pub(crate) fn par(request_uri: &str) -> String {
    format!("oauth:par:{}", blake3_hex(request_uri))
}

pub(crate) fn authorization_code_hash(code_hash: &str) -> String {
    format!("oauth:auth_code:{code_hash}")
}

pub(crate) fn authorization_code(code: &str) -> String {
    authorization_code_hash(&blake3_hex(code))
}

pub(crate) fn reauth_nonce(nonce: &str) -> String {
    format!("oauth:authorization:reauth:{}", blake3_hex(nonce))
}

pub(crate) fn ciba(auth_req_id: &str) -> String {
    format!("oauth:ciba:{}", blake3_hex(auth_req_id))
}

pub(crate) fn device_code(device_code: &str) -> String {
    device_code_hash(&blake3_hex(device_code))
}

pub(crate) fn device_code_hash(device_code_hash: &str) -> String {
    format!("oauth:device:code:{device_code_hash}")
}

pub(crate) fn normalize_user_code(value: &str) -> String {
    value
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .flat_map(char::to_uppercase)
        .collect()
}

pub(crate) fn device_user_code(user_code: &str) -> String {
    format!(
        "oauth:device:user_code:{}",
        blake3_hex(&normalize_user_code(user_code))
    )
}

pub(crate) fn email_send(email: &str) -> String {
    format!("oauth:email_verify:send:{email}")
}
pub(crate) fn email_peer_send(subject: &str) -> String {
    format!("oauth:email_verify:peer_send:{}", blake3_hex(subject))
}
pub(crate) fn email_code(email: &str) -> String {
    format!("oauth:email_verify:code:{email}")
}
pub(crate) fn passkey_registration(ceremony_id: &str) -> String {
    format!("oauth:passkey:registration:{ceremony_id}")
}
pub(crate) fn passkey_authentication(ceremony_id: &str) -> String {
    format!("oauth:passkey:authentication:{ceremony_id}")
}
pub(crate) fn oidc_federation(state: &str) -> String {
    format!("oauth:federation:oidc:state:{}", blake3_hex(state))
}
pub(crate) fn social_federation(state: &str) -> String {
    format!("oauth:federation:social:state:{}", blake3_hex(state))
}
pub(crate) fn saml_federation_replay(signature: &str) -> String {
    format!("oauth:federation:saml:replay:{}", blake3_hex(signature))
}
pub(crate) fn rate(dimension: &str, subject: &str) -> String {
    format!("oauth:rate:{dimension}:{}", blake3_hex(subject.trim()))
}
pub(crate) fn login_failure(dimension: &str, subject: &str) -> String {
    format!(
        "oauth:login_failure:{dimension}:{}",
        blake3_hex(subject.trim())
    )
}
pub(crate) fn access_token_subject(tenant_id: uuid::Uuid, jti: &str) -> String {
    format!("oauth:access_token:subject:{tenant_id}:{}", blake3_hex(jti))
}
pub(crate) fn native_sso(secret: &str) -> String {
    format!("oauth:native_sso:device_secret:{}", blake3_hex(secret))
}
