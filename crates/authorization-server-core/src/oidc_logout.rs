use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, KeyInit, Mac};
use serde::Deserialize;
use serde_json::Value;
use sha2::Sha256;
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LogoutClient {
    pub redirect_uris: Vec<String>,
    pub subject_type: String,
    pub sector_identifier_host: Option<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct IdTokenHintClaims {
    pub sub: String,
    pub aud: Value,
    #[serde(default)]
    pub sid: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LogoutPolicyError {
    ClientAudienceMismatch,
    AmbiguousAudience,
    ClientRequiredForRedirect,
    RegisteredClientRequired,
    UnregisteredRedirect,
    InvalidRedirect,
    PairwiseSecretMissing,
    UnsupportedSubjectType,
}

impl std::fmt::Display for LogoutPolicyError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::ClientAudienceMismatch => "client_id does not match id_token_hint audience",
            Self::AmbiguousAudience => {
                "client_id is required when id_token_hint has multiple audiences"
            }
            Self::ClientRequiredForRedirect => {
                "client_id or id_token_hint is required with post_logout_redirect_uri"
            }
            Self::RegisteredClientRequired => {
                "post_logout_redirect_uri requires a registered client"
            }
            Self::UnregisteredRedirect => "post_logout_redirect_uri is not registered",
            Self::InvalidRedirect => "post_logout_redirect_uri is invalid",
            Self::PairwiseSecretMissing => "PAIRWISE_SUBJECT_SECRET is required",
            Self::UnsupportedSubjectType => "unsupported client subject_type",
        })
    }
}

impl std::error::Error for LogoutPolicyError {}

pub fn resolve_logout_client_id(
    client_id: Option<&str>,
    post_logout_redirect_uri_present: bool,
    hint: Option<&IdTokenHintClaims>,
) -> Result<Option<String>, LogoutPolicyError> {
    match (client_id, hint) {
        (Some(client_id), Some(hint)) if !audience_contains(&hint.aud, client_id) => {
            Err(LogoutPolicyError::ClientAudienceMismatch)
        }
        (Some(client_id), _) => Ok(Some(client_id.to_owned())),
        (None, Some(hint)) => single_audience(&hint.aud)
            .map(Some)
            .ok_or(LogoutPolicyError::AmbiguousAudience),
        (None, None) if post_logout_redirect_uri_present => {
            Err(LogoutPolicyError::ClientRequiredForRedirect)
        }
        (None, None) => Ok(None),
    }
}

#[must_use]
pub fn audience_contains(aud: &Value, client_id: &str) -> bool {
    match aud {
        Value::String(value) => value == client_id,
        Value::Array(values) => values.iter().any(|value| value.as_str() == Some(client_id)),
        _ => false,
    }
}

#[must_use]
pub fn single_audience(aud: &Value) -> Option<String> {
    match aud {
        Value::String(value) => Some(value.clone()),
        Value::Array(values) => {
            let audiences = values
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .take(2)
                .collect::<Vec<_>>();
            match audiences.as_slice() {
                [audience] => Some(audience.clone()),
                _ => None,
            }
        }
        _ => None,
    }
}

pub fn validate_post_logout_redirect(
    uri: Option<&str>,
    state: Option<&str>,
    registered_uris: Option<&[String]>,
) -> Result<Option<String>, LogoutPolicyError> {
    let Some(uri) = uri else {
        return Ok(None);
    };
    let Some(registered_uris) = registered_uris else {
        return Err(LogoutPolicyError::RegisteredClientRequired);
    };
    if !registered_uris.iter().any(|registered| registered == uri) {
        return Err(LogoutPolicyError::UnregisteredRedirect);
    }
    let mut url = url::Url::parse(uri).map_err(|_| LogoutPolicyError::InvalidRedirect)?;
    if let Some(state) = state.filter(|state| !state.is_empty()) {
        url.query_pairs_mut().append_pair("state", state);
    }
    Ok(Some(url.into()))
}

pub fn id_token_hint_matches_session(
    issuer: &str,
    pairwise_subject_secret: Option<&str>,
    client: Option<&LogoutClient>,
    user_id: Uuid,
    oidc_sid: &str,
    hint: &IdTokenHintClaims,
) -> bool {
    if hint
        .sid
        .as_deref()
        .is_some_and(|hint_sid| hint_sid != oidc_sid)
    {
        return false;
    }
    client.is_some_and(|client| {
        logout_subjects_for_client(issuer, pairwise_subject_secret, user_id, client)
            .is_ok_and(|subjects| subjects.iter().any(|subject| subject == &hint.sub))
    })
}

pub fn unique_logout_subject_for_client(
    issuer: &str,
    pairwise_subject_secret: Option<&str>,
    user_id: Uuid,
    client: &LogoutClient,
) -> Result<Option<String>, LogoutPolicyError> {
    let subjects = logout_subjects_for_client(issuer, pairwise_subject_secret, user_id, client)?;
    match subjects.as_slice() {
        [subject] => Ok(Some(subject.clone())),
        _ => Ok(None),
    }
}

pub fn logout_subjects_for_client(
    issuer: &str,
    pairwise_subject_secret: Option<&str>,
    user_id: Uuid,
    client: &LogoutClient,
) -> Result<Vec<String>, LogoutPolicyError> {
    let redirect_uris = if client.redirect_uris.is_empty() {
        vec![String::new()]
    } else {
        client.redirect_uris.clone()
    };
    let mut subjects = Vec::with_capacity(redirect_uris.len());
    for redirect_uri in redirect_uris {
        subjects.push(oidc_subject_for_client(
            issuer,
            pairwise_subject_secret,
            user_id,
            &client.subject_type,
            client.sector_identifier_host.as_deref(),
            &redirect_uri,
        )?);
    }
    subjects.sort();
    subjects.dedup();
    Ok(subjects)
}

pub fn frontchannel_logout_url(
    uri: &str,
    session_required: bool,
    issuer: &str,
    oidc_sid: &str,
) -> Result<String, url::ParseError> {
    let mut url = url::Url::parse(uri)?;
    if session_required {
        url.query_pairs_mut()
            .append_pair("iss", issuer)
            .append_pair("sid", oidc_sid);
    }
    Ok(url.to_string())
}

pub fn oidc_subject_for_client(
    issuer: &str,
    pairwise_subject_secret: Option<&str>,
    user_id: Uuid,
    subject_type: &str,
    sector_identifier_host: Option<&str>,
    redirect_uri: &str,
) -> Result<String, LogoutPolicyError> {
    match subject_type {
        "public" => Ok(user_id.to_string()),
        "pairwise" => {
            let secret = pairwise_subject_secret
                .filter(|secret| secret.len() >= 32)
                .ok_or(LogoutPolicyError::PairwiseSecretMissing)?;
            let host = sector_identifier_host
                .filter(|host| !host.is_empty())
                .map(str::to_owned)
                .unwrap_or_else(|| {
                    url::Url::parse(redirect_uri)
                        .ok()
                        .and_then(|url| url.host_str().map(str::to_owned))
                        .unwrap_or_default()
                });
            Ok(pairwise_subject(secret.as_bytes(), issuer, &host, user_id))
        }
        _ => Err(LogoutPolicyError::UnsupportedSubjectType),
    }
}

#[must_use]
pub fn pairwise_subject(
    secret: &[u8],
    issuer: &str,
    sector_identifier_host: &str,
    user_id: Uuid,
) -> String {
    debug_assert!(secret.len() >= 32);
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(issuer.as_bytes());
    mac.update(b"\x1f");
    mac.update(sector_identifier_host.as_bytes());
    mac.update(b"\x1f");
    mac.update(user_id.to_string().as_bytes());
    URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_client_rejects_conflicting_hint_audience() {
        let hint = IdTokenHintClaims {
            sub: "subject".to_owned(),
            aud: Value::String("client-a".to_owned()),
            sid: None,
        };
        assert_eq!(
            resolve_logout_client_id(Some("client-b"), false, Some(&hint)),
            Err(LogoutPolicyError::ClientAudienceMismatch)
        );
    }

    #[test]
    fn redirect_state_is_appended_without_replacing_registered_query() {
        let registered = vec!["https://client.example/logout?source=op".to_owned()];
        assert_eq!(
            validate_post_logout_redirect(
                Some("https://client.example/logout?source=op"),
                Some("logout-state"),
                Some(&registered),
            )
            .expect("registered redirect"),
            Some("https://client.example/logout?source=op&state=logout-state".to_owned())
        );
    }
}
