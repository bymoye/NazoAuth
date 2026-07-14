#[cfg(test)]
use crate::adapters::security::blake3_hex;
use crate::adapters::security::{jwt_decoding_key_from_jwk, pkce_s256};
use chrono::Utc;
use serde::Deserialize;
use serde_json::Value;
#[cfg(test)]
use serde_json::json;

use crate::settings::OidcFederationSettings;

#[derive(Deserialize)]
pub(crate) struct OidcCallbackQuery {
    pub(super) code: Option<String>,
    pub(super) state: Option<String>,
    pub(super) error: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct OidcTokenResponse {
    pub(super) id_token: String,
}

#[derive(Deserialize)]
pub(super) struct OidcIdTokenClaims {
    pub(super) iss: String,
    pub(super) sub: String,
    pub(super) aud: Value,
    pub(super) azp: Option<String>,
    pub(super) exp: i64,
    pub(super) iat: Option<i64>,
    pub(super) nonce: Option<String>,
    pub(super) email: Option<String>,
    pub(super) email_verified: Option<bool>,
    pub(super) name: Option<String>,
    pub(super) given_name: Option<String>,
    pub(super) family_name: Option<String>,
}

pub(super) fn oidc_authorization_url(
    provider: &OidcFederationSettings,
    state: &str,
    nonce: &str,
    verifier: &str,
) -> String {
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    serializer
        .append_pair("response_type", "code")
        .append_pair("client_id", &provider.client_id)
        .append_pair("redirect_uri", &provider.redirect_uri)
        .append_pair("scope", &provider.scopes)
        .append_pair("state", state)
        .append_pair("nonce", nonce)
        .append_pair("code_challenge_method", "S256")
        .append_pair("code_challenge", &pkce_s256(verifier));
    format!(
        "{}?{}",
        provider.authorization_endpoint,
        serializer.finish()
    )
}

#[cfg(test)]
pub(super) fn oidc_state_key(state: &str) -> String {
    format!("oauth:federation:oidc:state:{}", blake3_hex(state))
}

pub(super) async fn exchange_oidc_code(
    provider: &OidcFederationSettings,
    code: &str,
    verifier: &str,
) -> anyhow::Result<OidcTokenResponse> {
    let client = super::federation_http_client()?;
    let body = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("grant_type", "authorization_code")
        .append_pair("code", code)
        .append_pair("redirect_uri", &provider.redirect_uri)
        .append_pair("code_verifier", verifier)
        .finish();
    let response = client
        .post(&provider.token_endpoint)
        .basic_auth(&provider.client_id, Some(&provider.client_secret))
        .header(
            reqwest::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .body(body)
        .send()
        .await?;
    super::federation_json_response(response).await
}

pub(super) async fn fetch_oidc_jwks(provider: &OidcFederationSettings) -> anyhow::Result<Value> {
    let client = super::federation_http_client()?;
    let response = client.get(&provider.jwks_url).send().await?;
    let value = super::federation_json_response::<Value>(response).await?;
    if value.get("keys").and_then(Value::as_array).is_none() {
        anyhow::bail!("OIDC JWKS does not contain keys array");
    }
    Ok(value)
}

pub(super) fn verify_oidc_id_token(
    provider: &OidcFederationSettings,
    jwks: &Value,
    token: &str,
    expected_nonce: &str,
) -> anyhow::Result<OidcIdTokenClaims> {
    let header = jsonwebtoken::decode_header(token)?;
    if !matches!(
        header.alg,
        jsonwebtoken::Algorithm::RS256
            | jsonwebtoken::Algorithm::PS256
            | jsonwebtoken::Algorithm::ES256
            | jsonwebtoken::Algorithm::EdDSA
    ) {
        anyhow::bail!("OIDC ID Token algorithm is not allowed");
    }
    let kid = header
        .kid
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("missing kid"))?;
    let keys = jwks
        .get("keys")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow::anyhow!("missing keys"))?;
    let key = keys
        .iter()
        .find(|key| key.get("kid").and_then(Value::as_str) == Some(kid))
        .ok_or_else(|| anyhow::anyhow!("kid not found"))?;
    let decoding_key = jwt_decoding_key_from_jwk(key, header.alg)
        .ok_or_else(|| anyhow::anyhow!("unsupported OIDC JWK"))?;
    let mut validation = jsonwebtoken::Validation::new(header.alg);
    validation.set_issuer(&[provider.issuer.as_str()]);
    validation.set_audience(&[provider.client_id.as_str()]);
    let token = jsonwebtoken::decode::<OidcIdTokenClaims>(token, &decoding_key, &validation)?;
    let claims = token.claims;
    let audience_count = claims.aud.as_array().map_or(1, Vec::len);
    if claims.nonce.as_deref() != Some(expected_nonce)
        || !audience_contains(&claims.aud, &provider.client_id)
        || (audience_count > 1 && claims.azp.as_deref() != Some(&provider.client_id))
        || claims.exp <= Utc::now().timestamp()
        || claims
            .iat
            .is_some_and(|iat| iat > Utc::now().timestamp().saturating_add(60))
    {
        anyhow::bail!("OIDC ID Token claims failed policy");
    }
    Ok(claims)
}

fn audience_contains(aud: &Value, client_id: &str) -> bool {
    match aud {
        Value::String(value) => value == client_id,
        Value::Array(values) => values.iter().any(|value| value.as_str() == Some(client_id)),
        _ => false,
    }
}

#[cfg(test)]
#[path = "../../../../tests/in_source/src/http/auth/tests/federation_oidc.rs"]
mod tests;
