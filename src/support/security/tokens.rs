use super::jwt_decoding_key_from_jwk;
use std::path::Path;

use base64::Engine as _;
use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::domain::{AppState, Claims, ConfirmationClaims, OidcClaimRequest};
use crate::support::{
    pem_to_der, sign_local_jwt_input, signing_algorithm_name, sorted_scope_string,
};

pub(crate) struct AccessTokenJwtInput<'a> {
    pub(crate) tenant_id: Uuid,
    pub(crate) subject: &'a str,
    pub(crate) user_id: Option<Uuid>,
    pub(crate) subject_type: &'a str,
    pub(crate) client_id: &'a str,
    pub(crate) audiences: &'a [String],
    pub(crate) scopes: &'a [String],
    pub(crate) authorization_details: &'a Value,
    pub(crate) userinfo_claims: &'a [String],
    pub(crate) userinfo_claim_requests: &'a [OidcClaimRequest],
    pub(crate) ttl: i64,
    pub(crate) dpop_jkt: Option<&'a str>,
    pub(crate) mtls_x5t_s256: Option<&'a str>,
    pub(crate) actor: Option<&'a Value>,
}

pub(crate) struct IssuedAccessToken {
    pub(crate) token: String,
    pub(crate) jti: String,
    pub(crate) exp: i64,
}

pub(super) fn validate_access_token_sender_constraint(
    dpop_jkt: Option<&str>,
    mtls_x5t_s256: Option<&str>,
) -> jsonwebtoken::errors::Result<()> {
    if dpop_jkt.is_some() && mtls_x5t_s256.is_some() {
        return Err(jsonwebtoken::errors::Error::from(
            jsonwebtoken::errors::ErrorKind::InvalidToken,
        ));
    }
    Ok(())
}

pub(crate) async fn make_jwt(
    state: &AppState,
    input: AccessTokenJwtInput<'_>,
) -> jsonwebtoken::errors::Result<IssuedAccessToken> {
    validate_access_token_sender_constraint(input.dpop_jkt, input.mtls_x5t_s256)?;
    let now = Utc::now().timestamp();
    let jti = Uuid::now_v7().to_string();
    let exp = now + input.ttl;
    let claims = access_token_claims(&state.settings.issuer, input, now, &jti);
    let keyset = state.keyset.snapshot();
    let header = access_token_header(keyset.active_alg, &keyset.active_kid);
    let token = keyset.sign_jwt(&header, &claims).await?;
    Ok(IssuedAccessToken { token, jti, exp })
}

pub(super) fn access_token_claims(
    issuer: &str,
    input: AccessTokenJwtInput<'_>,
    now: i64,
    jti: &str,
) -> Claims {
    Claims {
        iss: issuer.to_owned(),
        sub: input.subject.to_string(),
        tenant_id: input.tenant_id.to_string(),
        user_id: access_token_public_user_id(input.user_id, input.subject),
        subject_type: input.subject_type.to_string(),
        aud: token_audience_claim(input.audiences),
        client_id: input.client_id.to_string(),
        scope: sorted_scope_string(input.scopes),
        authorization_details: input.authorization_details.clone(),
        token_use: "access".into(),
        jti: jti.to_owned(),
        iat: now,
        nbf: now,
        exp: now + input.ttl,
        cnf: match (input.dpop_jkt, input.mtls_x5t_s256) {
            (Some(jkt), None) => Some(ConfirmationClaims {
                jkt: Some(jkt.to_owned()),
                x5t_s256: None,
            }),
            (None, Some(x5t_s256)) => Some(ConfirmationClaims {
                jkt: None,
                x5t_s256: Some(x5t_s256.to_owned()),
            }),
            _ => None,
        },
        act: input.actor.cloned(),
        userinfo_claims: input.userinfo_claims.to_vec(),
        userinfo_claim_requests: input.userinfo_claim_requests.to_vec(),
    }
}

fn access_token_public_user_id(user_id: Option<Uuid>, subject: &str) -> Option<String> {
    let user_id = user_id?;
    (subject == user_id.to_string()).then_some(user_id.to_string())
}

fn token_audience_claim(audiences: &[String]) -> Value {
    match audiences {
        [audience] => json!(audience),
        _ => json!(audiences),
    }
}

pub(super) fn access_token_header(alg: jsonwebtoken::Algorithm, kid: &str) -> jsonwebtoken::Header {
    let mut header = jsonwebtoken::Header::new(alg);
    header.typ = Some("at+jwt".to_string());
    header.kid = Some(kid.to_owned());
    header
}

pub(crate) struct IdTokenInput<'a> {
    pub(crate) subject: &'a str,
    pub(crate) client_id: &'a str,
    pub(crate) nonce: Option<String>,
    pub(crate) auth_time: Option<i64>,
    pub(crate) amr: &'a [String],
    pub(crate) sid: Option<&'a str>,
    pub(crate) acr: Option<&'a str>,
    pub(crate) extra_claims: Option<&'a Value>,
    pub(crate) ttl: i64,
    pub(crate) signing_alg: Option<jsonwebtoken::Algorithm>,
}

pub(crate) async fn make_id_token(
    state: &AppState,
    input: IdTokenInput<'_>,
) -> jsonwebtoken::errors::Result<String> {
    let now = Utc::now().timestamp();
    let claims = id_token_claims(&state.settings.issuer, &input, now);
    let keyset = state.keyset.snapshot();
    let alg = input.signing_alg.unwrap_or(keyset.active_alg);
    let (kid, token) = if alg == keyset.active_alg {
        let mut header = jsonwebtoken::Header::new(keyset.active_alg);
        header.typ = Some("JWT".to_string());
        header.kid = Some(keyset.active_kid.clone());
        return keyset.sign_jwt(&header, &Value::Object(claims)).await;
    } else {
        local_signing_key_for_alg(&state.settings.jwk_keys_dir, alg).await?
    };
    let mut header = jsonwebtoken::Header::new(alg);
    header.typ = Some("JWT".to_string());
    header.kid = Some(kid);
    let encoded_header = BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?);
    let encoded_claims = BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(&Value::Object(claims))?);
    let signing_input = format!("{encoded_header}.{encoded_claims}");
    let signature = sign_local_jwt_input(alg, &token, signing_input.as_bytes())?;
    Ok(format!("{signing_input}.{signature}"))
}

const BASE64_URL_SAFE_NO_PAD: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::URL_SAFE_NO_PAD;

async fn local_signing_key_for_alg(
    jwk_keys_dir: &Path,
    alg: jsonwebtoken::Algorithm,
) -> jsonwebtoken::errors::Result<(String, Vec<u8>)> {
    let Some(alg_name) = signing_algorithm_name(alg) else {
        return Err(jsonwebtoken::errors::ErrorKind::InvalidAlgorithm.into());
    };
    let keyset_path = jwk_keys_dir.join("keyset.json");
    let raw = tokio::fs::read_to_string(&keyset_path)
        .await
        .map_err(|_| jsonwebtoken::errors::ErrorKind::InvalidAlgorithm)?;
    let payload = serde_json::from_str::<Value>(&raw)
        .map_err(|_| jsonwebtoken::errors::ErrorKind::InvalidAlgorithm)?;
    let Some(keys) = payload.get("keys").and_then(Value::as_array) else {
        return Err(jsonwebtoken::errors::ErrorKind::InvalidAlgorithm.into());
    };
    for entry in keys {
        if entry.get("alg").and_then(Value::as_str) != Some(alg_name)
            || key_is_retired(entry)
            || entry
                .get("backend")
                .and_then(Value::as_str)
                .unwrap_or("local-pem")
                != "local-pem"
        {
            continue;
        }
        let Some(kid) = entry.get("kid").and_then(Value::as_str) else {
            continue;
        };
        let Some(file_name) = entry.get("file").and_then(Value::as_str) else {
            continue;
        };
        let raw_key = match tokio::fs::read_to_string(jwk_keys_dir.join(file_name)).await {
            Ok(raw_key) => raw_key,
            Err(_) => continue,
        };
        if let Some(der) = pem_to_der(&raw_key) {
            return Ok((kid.to_owned(), der));
        }
    }
    Err(jsonwebtoken::errors::ErrorKind::InvalidAlgorithm.into())
}

fn key_is_retired(entry: &Value) -> bool {
    entry
        .get("retire_at")
        .and_then(Value::as_str)
        .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
        .is_some_and(|retire_at| retire_at.with_timezone(&Utc) <= Utc::now())
}

pub(super) fn id_token_claims(
    issuer: &str,
    input: &IdTokenInput<'_>,
    now: i64,
) -> serde_json::Map<String, Value> {
    let mut claims = serde_json::Map::new();
    claims.insert("iss".to_owned(), json!(issuer));
    claims.insert("sub".to_owned(), json!(input.subject));
    claims.insert("aud".to_owned(), json!(input.client_id));
    claims.insert("iat".to_owned(), json!(now));
    claims.insert("nbf".to_owned(), json!(now));
    claims.insert("exp".to_owned(), json!(now + input.ttl));
    claims.insert("jti".to_owned(), json!(Uuid::now_v7().to_string()));
    if let Some(nonce) = &input.nonce {
        claims.insert("nonce".to_owned(), json!(nonce));
    }
    if let Some(auth_time) = input.auth_time {
        claims.insert("auth_time".to_owned(), json!(auth_time));
    }
    if !input.amr.is_empty() {
        claims.insert("amr".to_owned(), json!(input.amr));
    }
    if let Some(sid) = input.sid {
        claims.insert("sid".to_owned(), json!(sid));
    }
    if let Some(acr) = input.acr {
        claims.insert("acr".to_owned(), json!(acr));
    }
    if let Some(extra_claims) = input.extra_claims.and_then(Value::as_object) {
        for (key, value) in extra_claims {
            if !matches!(
                key.as_str(),
                "iss"
                    | "sub"
                    | "aud"
                    | "iat"
                    | "nbf"
                    | "exp"
                    | "jti"
                    | "nonce"
                    | "auth_time"
                    | "azp"
                    | "amr"
                    | "sid"
                    | "acr"
            ) {
                claims.insert(key.clone(), value.clone());
            }
        }
    }
    claims
}

pub(crate) struct AuthorizationResponseJwtInput<'a> {
    pub(crate) client_id: &'a str,
    pub(crate) code: Option<&'a str>,
    pub(crate) error: Option<&'a str>,
    pub(crate) state: Option<&'a str>,
    pub(crate) ttl: i64,
}

pub(crate) struct BackchannelLogoutTokenInput<'a> {
    pub(crate) client_id: &'a str,
    pub(crate) subject: Option<&'a str>,
    pub(crate) sid: Option<&'a str>,
    pub(crate) ttl: i64,
}

pub(crate) async fn make_backchannel_logout_token(
    state: &AppState,
    input: BackchannelLogoutTokenInput<'_>,
) -> jsonwebtoken::errors::Result<String> {
    let now = Utc::now().timestamp();
    let claims = backchannel_logout_token_claims(&state.settings.issuer, &input, now);
    let keyset = state.keyset.snapshot();
    let mut header = jsonwebtoken::Header::new(keyset.active_alg);
    header.typ = Some("logout+jwt".to_string());
    header.kid = Some(keyset.active_kid.clone());
    keyset.sign_jwt(&header, &Value::Object(claims)).await
}

pub(super) fn backchannel_logout_token_claims(
    issuer: &str,
    input: &BackchannelLogoutTokenInput<'_>,
    now: i64,
) -> serde_json::Map<String, Value> {
    let mut claims = serde_json::Map::new();
    claims.insert("iss".to_owned(), json!(issuer));
    claims.insert("aud".to_owned(), json!(input.client_id));
    claims.insert("iat".to_owned(), json!(now));
    claims.insert("nbf".to_owned(), json!(now));
    claims.insert("exp".to_owned(), json!(now + input.ttl.max(1)));
    claims.insert("jti".to_owned(), json!(Uuid::now_v7().to_string()));
    claims.insert(
        "events".to_owned(),
        json!({"http://schemas.openid.net/event/backchannel-logout": {}}),
    );
    if let Some(subject) = input.subject {
        claims.insert("sub".to_owned(), json!(subject));
    }
    if let Some(sid) = input.sid {
        claims.insert("sid".to_owned(), json!(sid));
    }
    claims
}

pub(crate) async fn make_authorization_response_jwt(
    state: &AppState,
    input: AuthorizationResponseJwtInput<'_>,
) -> jsonwebtoken::errors::Result<String> {
    let now = Utc::now().timestamp();
    let claims = authorization_response_jwt_claims(&state.settings.issuer, &input, now);
    let keyset = state.keyset.snapshot();
    let mut header = jsonwebtoken::Header::new(keyset.active_alg);
    header.typ = Some("oauth-authz-resp+jwt".to_string());
    header.kid = Some(keyset.active_kid.clone());
    keyset.sign_jwt(&header, &Value::Object(claims)).await
}

pub(super) fn authorization_response_jwt_claims(
    issuer: &str,
    input: &AuthorizationResponseJwtInput<'_>,
    now: i64,
) -> serde_json::Map<String, Value> {
    let mut claims = serde_json::Map::new();
    claims.insert("iss".to_owned(), json!(issuer));
    claims.insert("aud".to_owned(), json!(input.client_id));
    claims.insert("iat".to_owned(), json!(now));
    claims.insert("nbf".to_owned(), json!(now));
    claims.insert("exp".to_owned(), json!(now + input.ttl.max(1)));
    claims.insert("jti".to_owned(), json!(Uuid::now_v7().to_string()));
    if let Some(code) = input.code {
        claims.insert("code".to_owned(), json!(code));
    }
    if let Some(error) = input.error {
        claims.insert("error".to_owned(), json!(error));
    }
    if let Some(state_value) = input.state {
        claims.insert("state".to_owned(), json!(state_value));
    }
    claims
}

pub(crate) fn decode_access_claims(state: &AppState, token: &str) -> Option<Claims> {
    let header = jsonwebtoken::decode_header(token).ok()?;
    if header.typ.as_deref() != Some("at+jwt") || signing_algorithm_name(header.alg).is_none() {
        return None;
    }
    let keyset = state.keyset.snapshot();
    let verification_key = keyset.verification_key(header.kid.as_deref()?)?;
    let decoding_key = jwt_decoding_key_from_jwk(&verification_key.public_jwk, header.alg)?;
    let mut validation = jsonwebtoken::Validation::new(header.alg);
    validation.validate_aud = false;
    validation.set_issuer(&[state.settings.issuer.as_str()]);
    let token_data = jsonwebtoken::decode::<Claims>(token, &decoding_key, &validation).ok()?;
    if token_data.claims.token_use != "access" {
        return None;
    }
    Some(token_data.claims)
}
