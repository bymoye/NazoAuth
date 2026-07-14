use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use nazo_auth::{
    AccessTokenClaimsInput, AccessTokenSignInput, Claims, IdTokenClaimsInput, IdTokenSignInput,
    IntrospectionSignInput, IssuedAccessToken, SigningPurpose, TokenFuture, TokenPortError,
    TokenSignerPort, access_token_claims, id_token_claims,
};
use serde_json::Value;
use uuid::Uuid;

use crate::{KeyManager, signing_algorithm_from_name};

impl TokenSignerPort for KeyManager {
    fn sign_access_token<'a>(
        &'a self,
        input: AccessTokenSignInput<'a>,
    ) -> TokenFuture<'a, IssuedAccessToken> {
        Box::pin(async move {
            let now = Utc::now().timestamp();
            let jti = Uuid::now_v7().to_string();
            let expires_at = now + input.ttl_seconds;
            let claims = access_token_claims(
                input.issuer,
                AccessTokenClaimsInput {
                    tenant_id: input.tenant_id,
                    subject: input.subject,
                    user_id: input.user_id,
                    subject_type: input.subject_type,
                    client_id: input.client_id,
                    audiences: input.audiences,
                    scopes: input.scopes,
                    authorization_details: input.authorization_details,
                    userinfo_claims: input.userinfo_claims,
                    userinfo_claim_requests: input.userinfo_claim_requests,
                    ttl: input.ttl_seconds,
                    dpop_jkt: input.dpop_jkt,
                    mtls_x5t_s256: input.mtls_x5t_s256,
                    actor: input.actor,
                },
                now,
                &jti,
            );
            let keyset = self.snapshot();
            let mut header = jsonwebtoken::Header::new(keyset.active_alg);
            header.typ = Some("at+jwt".to_owned());
            header.kid = Some(keyset.active_kid.clone());
            let token = self
                .encode_jwt(SigningPurpose::AccessToken, &header, &claims)
                .await
                .map_err(|_| TokenPortError::Unavailable)?;
            Ok(IssuedAccessToken {
                token,
                jti,
                expires_at,
            })
        })
    }

    fn sign_id_token<'a>(&'a self, input: IdTokenSignInput<'a>) -> TokenFuture<'a, String> {
        Box::pin(async move {
            let claims = id_token_claims(
                input.issuer,
                &IdTokenClaimsInput {
                    subject: input.subject,
                    client_id: input.client_id,
                    nonce: input.nonce,
                    auth_time: input.auth_time,
                    amr: input.amr,
                    sid: input.sid,
                    acr: input.acr,
                    extra_claims: input.extra_claims,
                    ttl: input.ttl_seconds,
                },
                Utc::now().timestamp(),
            );
            let algorithm = match input.signing_algorithm {
                Some(name) => {
                    signing_algorithm_from_name(name).ok_or(TokenPortError::Unexpected)?
                }
                None => self.snapshot().active_alg,
            };
            let mut header = jsonwebtoken::Header::new(algorithm);
            header.typ = Some("JWT".to_owned());
            self.encode_jwt(SigningPurpose::IdToken, &header, &Value::Object(claims))
                .await
                .map_err(|_| TokenPortError::Unavailable)
        })
    }

    fn decode_access_token<'a>(
        &'a self,
        issuer: &'a str,
        token: &'a str,
    ) -> TokenFuture<'a, Option<Claims>> {
        Box::pin(async move {
            let Some(header) = jsonwebtoken::decode_header(token).ok() else {
                return Ok(None);
            };
            if header.typ.as_deref() != Some("at+jwt")
                || crate::signing_algorithm_name(header.alg).is_none()
            {
                return Ok(None);
            }
            let snapshot = self.snapshot();
            let Some(key) = header
                .kid
                .as_deref()
                .and_then(|kid| snapshot.verification_key(kid))
            else {
                return Ok(None);
            };
            let Some(decoding_key) = decoding_key(&key.public_jwk, header.alg) else {
                return Ok(None);
            };
            let mut validation = jsonwebtoken::Validation::new(header.alg);
            validation.validate_aud = false;
            validation.set_issuer(&[issuer]);
            let Some(data) = jsonwebtoken::decode::<Claims>(token, &decoding_key, &validation).ok()
            else {
                return Ok(None);
            };
            Ok((data.claims.token_use == "access").then_some(data.claims))
        })
    }

    fn decode_id_token<'a>(
        &'a self,
        issuer: &'a str,
        token: &'a str,
    ) -> TokenFuture<'a, Option<Value>> {
        Box::pin(async move {
            let Some(header) = jsonwebtoken::decode_header(token).ok() else {
                return Ok(None);
            };
            let snapshot = self.snapshot();
            let Some(key) = header
                .kid
                .as_deref()
                .and_then(|kid| snapshot.verification_key(kid))
            else {
                return Ok(None);
            };
            let Some(decoding_key) = decoding_key(&key.public_jwk, header.alg) else {
                return Ok(None);
            };
            let mut validation = jsonwebtoken::Validation::new(header.alg);
            validation.validate_aud = false;
            validation.validate_exp = false;
            validation.set_issuer(&[issuer]);
            Ok(
                jsonwebtoken::decode::<Value>(token, &decoding_key, &validation)
                    .ok()
                    .map(|data| data.claims),
            )
        })
    }

    fn sign_introspection_response<'a>(
        &'a self,
        input: IntrospectionSignInput<'a>,
    ) -> TokenFuture<'a, String> {
        Box::pin(async move {
            let snapshot = self.snapshot();
            let mut header = jsonwebtoken::Header::new(snapshot.active_alg);
            header.typ = Some("token-introspection+jwt".to_owned());
            header.kid = Some(snapshot.active_kid.clone());
            let claims = serde_json::json!({
                "iss": input.issuer,
                "aud": input.audience,
                "iat": Utc::now().timestamp(),
                "token_introspection": input.body,
            });
            self.encode_jwt(SigningPurpose::AccessToken, &header, &claims)
                .await
                .map_err(|_| TokenPortError::Unavailable)
        })
    }
}

fn decoding_key(
    key: &Value,
    algorithm: jsonwebtoken::Algorithm,
) -> Option<jsonwebtoken::DecodingKey> {
    let algorithm_name = crate::signing_algorithm_name(algorithm)?;
    if key.get("d").is_some()
        || key
            .get("alg")
            .and_then(Value::as_str)
            .is_some_and(|value| value != algorithm_name)
        || key
            .get("use")
            .and_then(Value::as_str)
            .is_some_and(|value| value != "sig")
    {
        return None;
    }
    match algorithm {
        jsonwebtoken::Algorithm::EdDSA
            if key.get("kty").and_then(Value::as_str) == Some("OKP")
                && key.get("crv").and_then(Value::as_str) == Some("Ed25519") =>
        {
            let x = key.get("x")?.as_str()?;
            if URL_SAFE_NO_PAD.decode(x).ok()?.len() != 32 {
                return None;
            }
            jsonwebtoken::DecodingKey::from_ed_components(x).ok()
        }
        jsonwebtoken::Algorithm::RS256 | jsonwebtoken::Algorithm::PS256
            if key.get("kty").and_then(Value::as_str) == Some("RSA") =>
        {
            let modulus = key.get("n")?.as_str()?;
            let exponent = key.get("e")?.as_str()?;
            if URL_SAFE_NO_PAD.decode(modulus).ok()?.len() < 256
                || URL_SAFE_NO_PAD.decode(exponent).ok()?.is_empty()
            {
                return None;
            }
            jsonwebtoken::DecodingKey::from_rsa_components(modulus, exponent).ok()
        }
        jsonwebtoken::Algorithm::ES256
            if key.get("kty").and_then(Value::as_str) == Some("EC")
                && key.get("crv").and_then(Value::as_str) == Some("P-256") =>
        {
            let x = key.get("x")?.as_str()?;
            let y = key.get("y")?.as_str()?;
            if URL_SAFE_NO_PAD.decode(x).ok()?.len() != 32
                || URL_SAFE_NO_PAD.decode(y).ok()?.len() != 32
            {
                return None;
            }
            jsonwebtoken::DecodingKey::from_ec_components(x, y).ok()
        }
        _ => None,
    }
}
