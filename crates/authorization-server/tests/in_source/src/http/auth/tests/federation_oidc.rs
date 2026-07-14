use super::*;
use crate::adapters::security::random_urlsafe_token;
use crate::settings::OidcFederationSettings;
use crate::test_support::ClientSigningFixture;
use crate::test_support::client_signing_fixture;
use jsonwebtoken::{Algorithm, Header};
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

fn provider() -> OidcFederationSettings {
    OidcFederationSettings {
        provider_id: "test-oidc".to_owned(),
        issuer: "https://issuer.example".to_owned(),
        authorization_endpoint: "https://issuer.example/authorize".to_owned(),
        token_endpoint: "https://issuer.example/token".to_owned(),
        jwks_url: "https://issuer.example/jwks".to_owned(),
        client_id: "client-1".to_owned(),
        client_secret: "secret".to_owned(),
        redirect_uri: "https://auth.example/federation/test-oidc/callback".to_owned(),
        scopes: "openid email".to_owned(),
    }
}

#[test]
fn oidc_authorization_url_includes_all_required_params() {
    let provider = provider();
    let nonce = random_urlsafe_token();
    let location = oidc_authorization_url(&provider, "state-1", &nonce, "verifier-1");
    let url = url::Url::parse(&location).unwrap();
    let params = url
        .query_pairs()
        .collect::<std::collections::HashMap<_, _>>();

    assert_eq!(
        url.as_str().split('?').next(),
        Some("https://issuer.example/authorize")
    );
    assert_eq!(
        params.get("response_type").map(|v| v.as_ref()),
        Some("code")
    );
    assert_eq!(
        params.get("client_id").map(|v| v.as_ref()),
        Some("client-1")
    );
    assert_eq!(
        params.get("redirect_uri").map(|v| v.as_ref()),
        Some("https://auth.example/federation/test-oidc/callback")
    );
    assert_eq!(
        params.get("scope").map(|v| v.as_ref()),
        Some("openid email")
    );
    assert_eq!(params.get("state").map(|v| v.as_ref()), Some("state-1"));
    assert_eq!(
        params.get("nonce").map(|v| v.as_ref()),
        Some(nonce.as_str())
    );
    assert_eq!(
        params.get("code_challenge_method").map(|v| v.as_ref()),
        Some("S256")
    );
    assert_eq!(
        params.get("code_challenge").map(|v| v.as_ref()),
        Some(pkce_s256("verifier-1").as_str())
    );
}

#[test]
fn oidc_state_key_includes_blake3_hash() {
    let key = oidc_state_key("state-value");
    assert!(key.starts_with("oauth:federation:oidc:state:"));
    assert_eq!(key.len(), 28 + 64);
}

#[test]
fn oidc_state_key_is_deterministic() {
    assert_eq!(oidc_state_key("same"), oidc_state_key("same"));
    assert_ne!(oidc_state_key("one"), oidc_state_key("two"));
}

#[test]
fn audience_contains_matches_string() {
    assert!(audience_contains(&json!("client-1"), "client-1"));
}

#[test]
fn audience_contains_rejects_string_mismatch() {
    assert!(!audience_contains(&json!("other"), "client-1"));
}

#[test]
fn audience_contains_matches_array_element() {
    let aud = json!(["client-1", "client-2"]);
    assert!(audience_contains(&aud, "client-1"));
    assert!(audience_contains(&aud, "client-2"));
}

#[test]
fn audience_contains_rejects_array_without_match() {
    assert!(!audience_contains(
        &json!(["other-1", "other-2"]),
        "client-1"
    ));
}

#[test]
fn audience_contains_returns_false_for_non_string_non_array() {
    assert!(!audience_contains(&json!(null), "client-1"));
    assert!(!audience_contains(&json!(42), "client-1"));
    assert!(!audience_contains(&json!({"key": "value"}), "client-1"));
}

async fn one_shot_json_server(
    status: &'static str,
    body: Value,
) -> (String, tokio::task::JoinHandle<String>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("test server should bind");
    let addr: SocketAddr = listener.local_addr().expect("test server address");
    let handle = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("test request should arrive");
        let request = read_http_request(&mut stream).await;
        let response_body = body.to_string();
        let response = format!(
            "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
            response_body.len(),
            response_body
        );
        stream
            .write_all(response.as_bytes())
            .await
            .expect("response should write");
        request
    });
    (format!("http://{addr}"), handle)
}

async fn read_http_request(stream: &mut TcpStream) -> String {
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 1024];
    let mut expected_len = None;
    loop {
        let read = stream.read(&mut chunk).await.expect("request should read");
        if read == 0 {
            break;
        }
        buffer.extend_from_slice(&chunk[..read]);
        if expected_len.is_none()
            && let Some(header_end) = buffer.windows(4).position(|window| window == b"\r\n\r\n")
        {
            let headers = String::from_utf8_lossy(&buffer[..header_end]);
            let content_length = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().ok())
                        .flatten()
                })
                .unwrap_or(0);
            expected_len = Some(header_end + 4 + content_length);
        }
        if expected_len.is_some_and(|len| buffer.len() >= len) {
            break;
        }
    }
    String::from_utf8_lossy(&buffer).to_string()
}

fn raw_header_value<'a>(request: &'a str, name: &str) -> Option<&'a str> {
    request.lines().find_map(|line| {
        let (header_name, value) = line.split_once(':')?;
        header_name
            .eq_ignore_ascii_case(name)
            .then_some(value.trim())
    })
}

fn form_body_value(request: &str, key: &str) -> Option<String> {
    let body = request.split("\r\n\r\n").nth(1)?;
    url::form_urlencoded::parse(body.as_bytes())
        .find_map(|(name, value)| (name == key).then(|| value.into_owned()))
}

#[actix_web::test]
async fn exchange_oidc_code_posts_basic_authenticated_authorization_code_request() {
    let (endpoint, request) =
        one_shot_json_server("200 OK", json!({"id_token": "signed-id-token"})).await;
    let mut provider = provider();
    provider.token_endpoint = endpoint;

    let token = exchange_oidc_code(&provider, "code-1", "verifier-1")
        .await
        .expect("valid token response should parse");
    let request = request.await.expect("test server should finish");

    assert_eq!(token.id_token, "signed-id-token");
    assert!(request.starts_with("POST / HTTP/1.1"));
    assert!(
        request.contains("authorization: Basic Y2xpZW50LTE6c2VjcmV0")
            || request.contains("Authorization: Basic Y2xpZW50LTE6c2VjcmV0")
    );
    assert_eq!(
        raw_header_value(&request, "content-type"),
        Some("application/x-www-form-urlencoded")
    );
    assert_eq!(
        form_body_value(&request, "grant_type").as_deref(),
        Some("authorization_code")
    );
    assert_eq!(form_body_value(&request, "code").as_deref(), Some("code-1"));
    assert_eq!(
        form_body_value(&request, "redirect_uri").as_deref(),
        Some("https://auth.example/federation/test-oidc/callback")
    );
    assert_eq!(
        form_body_value(&request, "code_verifier").as_deref(),
        Some("verifier-1")
    );
}

#[actix_web::test]
async fn fetch_oidc_jwks_requires_keys_array_from_provider_response() {
    let (valid_endpoint, valid_request) = one_shot_json_server("200 OK", json!({"keys": []})).await;
    let mut provider = provider();
    provider.jwks_url = valid_endpoint;

    assert_eq!(
        fetch_oidc_jwks(&provider)
            .await
            .expect("keys array should be accepted"),
        json!({"keys": []})
    );
    let valid_request = valid_request.await.expect("test server should finish");
    assert!(valid_request.starts_with("GET / HTTP/1.1"));

    let (invalid_endpoint, invalid_request) =
        one_shot_json_server("200 OK", json!({"not_keys": []})).await;
    provider.jwks_url = invalid_endpoint;

    assert!(
        fetch_oidc_jwks(&provider).await.is_err(),
        "JWKS responses without a keys array must fail closed"
    );
    invalid_request
        .await
        .expect("invalid JWKS request should finish");
}

fn signed_id_token(
    provider: &OidcFederationSettings,
    kid: &str,
    fixture: &ClientSigningFixture,
    nonce: &str,
    overrides: Value,
) -> String {
    let now = Utc::now().timestamp();
    let mut claims = json!({
        "iss": provider.issuer,
        "sub": "subject-1",
        "aud": provider.client_id,
        "exp": now + 300,
        "iat": now,
        "nonce": nonce,
        "email": "user@example.com",
        "email_verified": true,
        "name": "User One"
    });
    let claims_object = claims
        .as_object_mut()
        .expect("test claims should be a JSON object");
    for (key, value) in overrides.as_object().into_iter().flatten() {
        claims_object.insert(key.clone(), value.clone());
    }
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(kid.to_owned());
    fixture.encode_jwt(&header, &claims)
}

#[test]
fn verify_oidc_id_token_accepts_matching_signed_claims_and_rejects_policy_mismatches() {
    let provider = provider();
    let key = client_signing_fixture(Algorithm::RS256);
    let jwk = key.public_jwk("oidc-kid");
    let jwks = json!({"keys": [jwk]});
    let nonce = random_urlsafe_token();
    let token = signed_id_token(&provider, "oidc-kid", &key, &nonce, json!({}));

    let claims = verify_oidc_id_token(&provider, &jwks, &token, &nonce)
        .expect("matching issuer, audience, nonce, kid, and signature should pass");
    assert_eq!(claims.sub, "subject-1");
    assert_eq!(claims.email.as_deref(), Some("user@example.com"));
    assert_eq!(claims.email_verified, Some(true));
    assert_eq!(claims.name.as_deref(), Some("User One"));

    let mismatched_nonce = random_urlsafe_token();
    assert!(verify_oidc_id_token(&provider, &jwks, &token, &mismatched_nonce).is_err());

    let wrong_audience = signed_id_token(
        &provider,
        "oidc-kid",
        &key,
        &nonce,
        json!({"aud": "other-client"}),
    );
    assert!(verify_oidc_id_token(&provider, &jwks, &wrong_audience, &nonce).is_err());

    let multiple_audiences_without_azp = signed_id_token(
        &provider,
        "oidc-kid",
        &key,
        &nonce,
        json!({"aud": [provider.client_id, "other-client"]}),
    );
    assert!(
        verify_oidc_id_token(&provider, &jwks, &multiple_audiences_without_azp, &nonce).is_err()
    );
    let multiple_audiences_with_azp = signed_id_token(
        &provider,
        "oidc-kid",
        &key,
        &nonce,
        json!({
            "aud": [provider.client_id, "other-client"],
            "azp": provider.client_id
        }),
    );
    assert!(verify_oidc_id_token(&provider, &jwks, &multiple_audiences_with_azp, &nonce).is_ok());

    let future_iat = signed_id_token(
        &provider,
        "oidc-kid",
        &key,
        &nonce,
        json!({"iat": Utc::now().timestamp() + 120}),
    );
    assert!(verify_oidc_id_token(&provider, &jwks, &future_iat, &nonce).is_err());
}

#[test]
fn verify_oidc_id_token_requires_kid_and_matching_supported_jwk() {
    let provider = provider();
    let key = client_signing_fixture(Algorithm::RS256);
    let jwk = key.public_jwk("oidc-kid");
    let jwks = json!({"keys": [jwk]});
    let nonce = random_urlsafe_token();
    let unknown_kid = signed_id_token(&provider, "unknown-kid", &key, &nonce, json!({}));
    assert!(verify_oidc_id_token(&provider, &jwks, &unknown_kid, &nonce).is_err());

    let mut header = Header::new(Algorithm::RS256);
    header.kid = None;
    let token_without_kid = key.encode_jwt(
        &header,
        &json!({
            "iss": provider.issuer,
            "sub": "subject-1",
            "aud": provider.client_id,
            "exp": Utc::now().timestamp() + 300,
            "nonce": nonce
        }),
    );
    assert!(verify_oidc_id_token(&provider, &jwks, &token_without_kid, &nonce).is_err());

    let mut private_jwk = jwks.clone();
    private_jwk["keys"][0]["d"] = json!("private-material");
    let valid_token = signed_id_token(&provider, "oidc-kid", &key, &nonce, json!({}));
    assert!(verify_oidc_id_token(&provider, &private_jwk, &valid_token, &nonce).is_err());
}
