use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::authorization_details_empty;

pub const SUPPORTED_USER_CLAIMS: &[&str] = &[
    "preferred_username",
    "name",
    "given_name",
    "family_name",
    "middle_name",
    "nickname",
    "profile",
    "picture",
    "website",
    "gender",
    "birthdate",
    "zoneinfo",
    "locale",
    "updated_at",
    "email",
    "email_verified",
    "address",
    "phone_number",
    "phone_number_verified",
];

#[must_use]
pub fn supported_user_claim(name: &str) -> bool {
    SUPPORTED_USER_CLAIMS.contains(&name)
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConfirmationClaims {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jkt: Option<String>,
    #[serde(rename = "x5t#S256", default, skip_serializing_if = "Option::is_none")]
    pub x5t_s256: Option<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct OidcClaimRequest {
    pub name: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub essential: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub values: Vec<Value>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Claims {
    pub iss: String,
    pub sub: String,
    pub tenant_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    pub subject_type: String,
    pub aud: Value,
    pub client_id: String,
    pub scope: String,
    #[serde(default, skip_serializing_if = "authorization_details_empty")]
    pub authorization_details: Value,
    pub token_use: String,
    pub jti: String,
    pub iat: i64,
    pub nbf: i64,
    pub exp: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cnf: Option<ConfirmationClaims>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub act: Option<Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub userinfo_claims: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub userinfo_claim_requests: Vec<OidcClaimRequest>,
}

pub struct AccessTokenClaimsInput<'a> {
    pub tenant_id: Uuid,
    pub subject: &'a str,
    pub user_id: Option<Uuid>,
    pub subject_type: &'a str,
    pub client_id: &'a str,
    pub audiences: &'a [String],
    pub scopes: &'a [String],
    pub authorization_details: &'a Value,
    pub userinfo_claims: &'a [String],
    pub userinfo_claim_requests: &'a [OidcClaimRequest],
    pub ttl: i64,
    pub dpop_jkt: Option<&'a str>,
    pub mtls_x5t_s256: Option<&'a str>,
    pub actor: Option<&'a Value>,
}

#[must_use]
pub fn access_token_claims(
    issuer: &str,
    input: AccessTokenClaimsInput<'_>,
    now: i64,
    jti: &str,
) -> Claims {
    Claims {
        iss: issuer.to_owned(),
        sub: input.subject.to_owned(),
        tenant_id: input.tenant_id.to_string(),
        user_id: access_token_public_user_id(input.user_id, input.subject),
        subject_type: input.subject_type.to_owned(),
        aud: token_audience_claim(input.audiences),
        client_id: input.client_id.to_owned(),
        scope: sorted_scope_string(input.scopes),
        authorization_details: input.authorization_details.clone(),
        token_use: "access".to_owned(),
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

fn sorted_scope_string(scopes: &[String]) -> String {
    let mut values = scopes.to_vec();
    values.sort();
    values.dedup();
    values.join(" ")
}

pub struct IdTokenClaimsInput<'a> {
    pub subject: &'a str,
    pub client_id: &'a str,
    pub nonce: Option<&'a str>,
    pub auth_time: Option<i64>,
    pub amr: &'a [String],
    pub sid: Option<&'a str>,
    pub acr: Option<&'a str>,
    pub extra_claims: Option<&'a Value>,
    pub ttl: i64,
}

#[must_use]
pub fn id_token_claims(
    issuer: &str,
    input: &IdTokenClaimsInput<'_>,
    now: i64,
) -> serde_json::Map<String, Value> {
    let mut claims = registered_claims(issuer, input.subject, input.client_id, now, input.ttl);
    if let Some(nonce) = input.nonce {
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

pub struct BackchannelLogoutClaimsInput<'a> {
    pub client_id: &'a str,
    pub subject: Option<&'a str>,
    pub sid: Option<&'a str>,
    pub ttl: i64,
}

#[must_use]
pub fn backchannel_logout_token_claims(
    issuer: &str,
    input: &BackchannelLogoutClaimsInput<'_>,
    now: i64,
) -> serde_json::Map<String, Value> {
    let mut claims = registered_claims(issuer, "", input.client_id, now, input.ttl.max(1));
    claims.remove("sub");
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

pub struct AuthorizationResponseClaimsInput<'a> {
    pub client_id: &'a str,
    pub code: Option<&'a str>,
    pub error: Option<&'a str>,
    pub state: Option<&'a str>,
    pub ttl: i64,
}

#[must_use]
pub fn authorization_response_jwt_claims(
    issuer: &str,
    input: &AuthorizationResponseClaimsInput<'_>,
    now: i64,
) -> serde_json::Map<String, Value> {
    let mut claims = registered_claims(issuer, "", input.client_id, now, input.ttl.max(1));
    claims.remove("sub");
    if let Some(code) = input.code {
        claims.insert("code".to_owned(), json!(code));
    }
    if let Some(error) = input.error {
        claims.insert("error".to_owned(), json!(error));
    }
    if let Some(state) = input.state {
        claims.insert("state".to_owned(), json!(state));
    }
    claims
}

fn registered_claims(
    issuer: &str,
    subject: &str,
    audience: &str,
    now: i64,
    ttl: i64,
) -> serde_json::Map<String, Value> {
    let mut claims = serde_json::Map::new();
    claims.insert("iss".to_owned(), json!(issuer));
    claims.insert("sub".to_owned(), json!(subject));
    claims.insert("aud".to_owned(), json!(audience));
    claims.insert("iat".to_owned(), json!(now));
    claims.insert("nbf".to_owned(), json!(now));
    claims.insert("exp".to_owned(), json!(now + ttl));
    claims.insert("jti".to_owned(), json!(Uuid::now_v7().to_string()));
    claims
}
