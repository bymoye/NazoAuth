#[cfg(test)]
use super::jwt_decoding_key_from_jwk;

#[cfg(test)]
use chrono::Utc;
#[cfg(test)]
use nazo_auth::Claims;
#[cfg(test)]
use nazo_auth::{AccessTokenClaimsInput, OidcClaimRequest};
#[cfg(test)]
use serde_json::Value;
#[cfg(test)]
use uuid::Uuid;

#[cfg(test)]
use nazo_key_management::signing_algorithm_name;

#[cfg(test)]
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

#[cfg(test)]
pub(crate) struct IssuedAccessToken {
    pub(crate) token: String,
    pub(crate) jti: String,
}

#[cfg(test)]
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

#[cfg(test)]
pub(crate) async fn make_jwt(
    keyset: &nazo_key_management::KeyManager,
    issuer: &str,
    input: AccessTokenJwtInput<'_>,
) -> jsonwebtoken::errors::Result<IssuedAccessToken> {
    validate_access_token_sender_constraint(input.dpop_jkt, input.mtls_x5t_s256)?;
    let now = Utc::now().timestamp();
    let jti = Uuid::now_v7().to_string();
    let claims = nazo_auth::access_token_claims(
        issuer,
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
            ttl: input.ttl,
            dpop_jkt: input.dpop_jkt,
            mtls_x5t_s256: input.mtls_x5t_s256,
            actor: input.actor,
        },
        now,
        &jti,
    );
    let key_snapshot = keyset.snapshot();
    let header = access_token_header(key_snapshot.active_alg, &key_snapshot.active_kid);
    let token = keyset
        .encode_jwt(nazo_auth::SigningPurpose::AccessToken, &header, &claims)
        .await?;
    Ok(IssuedAccessToken { token, jti })
}

#[cfg(test)]
pub(super) fn access_token_header(alg: jsonwebtoken::Algorithm, kid: &str) -> jsonwebtoken::Header {
    let mut header = jsonwebtoken::Header::new(alg);
    header.typ = Some("at+jwt".to_string());
    header.kid = Some(kid.to_owned());
    header
}

#[cfg(test)]
pub(crate) async fn sign_response_jwt(
    keyset: &nazo_key_management::KeyManager,
    purpose: nazo_auth::SigningPurpose,
    claims: &Value,
    typ: &str,
    signing_alg: Option<jsonwebtoken::Algorithm>,
) -> jsonwebtoken::errors::Result<String> {
    let key_snapshot = keyset.snapshot();
    let alg = signing_alg.unwrap_or(key_snapshot.active_alg);
    let mut header = jsonwebtoken::Header::new(alg);
    header.typ = Some(typ.to_owned());
    keyset.encode_jwt(purpose, &header, claims).await
}

#[cfg(test)]
pub(crate) fn decode_access_claims_with(
    keyset: &nazo_key_management::KeyManager,
    issuer: &str,
    token: &str,
) -> Option<Claims> {
    let header = jsonwebtoken::decode_header(token).ok()?;
    if header.typ.as_deref() != Some("at+jwt") || signing_algorithm_name(header.alg).is_none() {
        return None;
    }
    let key_snapshot = keyset.snapshot();
    let verification_key = key_snapshot.verification_key(header.kid.as_deref()?)?;
    let decoding_key = jwt_decoding_key_from_jwk(&verification_key.public_jwk, header.alg)?;
    let mut validation = jsonwebtoken::Validation::new(header.alg);
    validation.validate_aud = false;
    validation.set_issuer(&[issuer]);
    let token_data = jsonwebtoken::decode::<Claims>(token, &decoding_key, &validation).ok()?;
    if token_data.claims.token_use != "access" {
        return None;
    }
    Some(token_data.claims)
}
