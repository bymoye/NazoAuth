use crate::{adapters::email::normalize_email_address, adapters::security::pkce_s256};
use serde::Deserialize;
use serde_json::{Value, json};
use url::Url;

use crate::settings::{SocialProviderKind, SocialProviderSettings};

#[derive(Debug)]
pub(super) struct SocialIdentity {
    pub(super) subject: String,
    pub(super) email: Option<String>,
    pub(super) display_name: Option<String>,
    pub(super) claims: Value,
}

#[derive(Deserialize)]
struct SocialTokenResponse {
    access_token: String,
    #[serde(default)]
    openid: Option<String>,
    #[serde(default)]
    unionid: Option<String>,
    #[serde(default)]
    expires_in: Option<i64>,
}

pub(super) fn social_authorization_url(
    provider: &SocialProviderSettings,
    state: &str,
    verifier: &str,
) -> String {
    // QQ 与微信使用不同的 client 参数名；adapter 在这里收敛差异，
    // 上层 handler 不需要知道 provider-specific URL 细节。
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    serializer
        .append_pair("response_type", "code")
        .append_pair("redirect_uri", &provider.redirect_uri)
        .append_pair("scope", &provider.scopes)
        .append_pair("state", state)
        .append_pair("code_challenge_method", "S256")
        .append_pair("code_challenge", &pkce_s256(verifier));
    match provider.kind {
        SocialProviderKind::Wechat => {
            serializer.append_pair("appid", &provider.client_id);
        }
        SocialProviderKind::Qq | SocialProviderKind::Custom => {
            serializer.append_pair("client_id", &provider.client_id);
        }
    }
    format!(
        "{}?{}",
        provider.authorization_endpoint,
        serializer.finish()
    )
}

pub(super) async fn resolve_social_identity(
    provider: &SocialProviderSettings,
    code: &str,
    verifier: &str,
) -> anyhow::Result<SocialIdentity> {
    // 第三方 access token 只在 adapter 内使用，用完即丢；不会写入本地 session、
    // OAuth token 表或审计字段。
    let token = exchange_social_code(provider, code, verifier).await?;
    let openid_claims = fetch_social_openid(provider, &token).await?;
    let userinfo = fetch_social_userinfo(provider, &token, openid_claims.as_ref()).await?;
    normalize_social_identity(provider, &token, openid_claims, userinfo)
}

async fn exchange_social_code(
    provider: &SocialProviderSettings,
    code: &str,
    verifier: &str,
) -> anyhow::Result<SocialTokenResponse> {
    let client = super::federation_http_client()?;
    let body = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("grant_type", "authorization_code")
        .append_pair("code", code)
        .append_pair("redirect_uri", &provider.redirect_uri)
        .append_pair("code_verifier", verifier)
        .append_pair("client_id", &provider.client_id)
        .append_pair("client_secret", &provider.client_secret)
        .finish();
    let response = client
        .post(&provider.token_endpoint)
        .header(
            reqwest::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .body(body)
        .send()
        .await?;
    parse_social_token_response(super::federation_text_response(response).await?)
}

async fn fetch_social_openid(
    provider: &SocialProviderSettings,
    token: &SocialTokenResponse,
) -> anyhow::Result<Option<Value>> {
    let Some(endpoint) = &provider.openid_endpoint else {
        return Ok(None);
    };
    let client = super::federation_http_client()?;
    let response = client
        .get(url_with_query_params(
            endpoint,
            &[("access_token", token.access_token.as_str())],
        )?)
        .send()
        .await?;
    let response = super::federation_text_response(response).await?;
    Ok(Some(parse_json_or_jsonp(&response)?))
}

async fn fetch_social_userinfo(
    provider: &SocialProviderSettings,
    token: &SocialTokenResponse,
    openid_claims: Option<&Value>,
) -> anyhow::Result<Value> {
    let client = super::federation_http_client()?;
    let request = match provider.kind {
        SocialProviderKind::Qq => {
            let openid = claim_string(openid_claims, "openid")
                .or(token.openid.as_deref())
                .ok_or_else(|| anyhow::anyhow!("QQ openid missing"))?;
            client.get(url_with_query_params(
                &provider.userinfo_endpoint,
                &[
                    ("access_token", token.access_token.as_str()),
                    ("oauth_consumer_key", provider.client_id.as_str()),
                    ("openid", openid),
                ],
            )?)
        }
        SocialProviderKind::Wechat => {
            let openid = token
                .openid
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("WeChat openid missing"))?;
            client.get(url_with_query_params(
                &provider.userinfo_endpoint,
                &[
                    ("access_token", token.access_token.as_str()),
                    ("openid", openid),
                ],
            )?)
        }
        SocialProviderKind::Custom => client
            .get(&provider.userinfo_endpoint)
            .bearer_auth(&token.access_token),
    };
    super::federation_json_response(request.send().await?).await
}

fn url_with_query_params(endpoint: &str, params: &[(&str, &str)]) -> anyhow::Result<Url> {
    // 当前 reqwest 构建未启用 RequestBuilder::query；统一用 url crate
    // 组装查询参数，避免不同 feature 组合改变 HTTP 请求语义。
    let mut url = Url::parse(endpoint)?;
    {
        let mut pairs = url.query_pairs_mut();
        for (key, value) in params {
            pairs.append_pair(key, value);
        }
    }
    Ok(url)
}

fn normalize_social_identity(
    provider: &SocialProviderSettings,
    token: &SocialTokenResponse,
    openid_claims: Option<Value>,
    userinfo: Value,
) -> anyhow::Result<SocialIdentity> {
    // subject 优先来自 provider 配置的 subject_claim；QQ/微信可用 token 或
    // openid endpoint 结果补齐 openid/unionid，但不能把 email 当作身份根。
    let subject = claim_string(Some(&userinfo), &provider.subject_claim)
        .or_else(|| token_claim_string(token, &provider.subject_claim))
        .or_else(|| claim_string(openid_claims.as_ref(), &provider.subject_claim))
        .map(str::to_owned)
        .ok_or_else(|| anyhow::anyhow!("social subject claim missing"))?;
    let email = provider
        .email_claim
        .as_deref()
        .and_then(|claim| claim_string(Some(&userinfo), claim))
        .map(normalize_email_address)
        .transpose()?;
    let email_verified = provider
        .email_verified_claim
        .as_deref()
        .and_then(|claim| claim_bool(Some(&userinfo), claim))
        .unwrap_or(false);
    let display_name = provider
        .name_claim
        .as_deref()
        .and_then(|claim| claim_string(Some(&userinfo), claim))
        .map(str::to_owned);
    let union_id = provider
        .union_id_claim
        .as_deref()
        .and_then(|claim| {
            claim_string(Some(&userinfo), claim)
                .or_else(|| token_claim_string(token, claim))
                .or_else(|| claim_string(openid_claims.as_ref(), claim))
        })
        .map(str::to_owned);
    let claims = json!({
        "adapter": "oauth2_social",
        "kind": format!("{:?}", provider.kind).to_ascii_lowercase(),
        "subject": subject.clone(),
        "email": email.clone(),
        "email_verified": email_verified,
        "display_name": display_name.clone(),
        "union_id": union_id,
        "userinfo": userinfo,
        "openid": openid_claims,
        "expires_in": token.expires_in,
    });
    Ok(SocialIdentity {
        subject,
        email: email.filter(|_| email_verified),
        display_name,
        claims,
    })
}

fn parse_social_token_response(body: String) -> anyhow::Result<SocialTokenResponse> {
    // QQ 传统响应可能是 form-urlencoded；微信和大多数 provider 返回 JSON。
    if let Ok(value) = serde_json::from_str::<SocialTokenResponse>(&body) {
        return Ok(value);
    }
    let values = url::form_urlencoded::parse(body.as_bytes())
        .into_owned()
        .collect::<std::collections::HashMap<_, _>>();
    let access_token = values
        .get("access_token")
        .filter(|value| !value.is_empty())
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("social token response missing access_token"))?;
    Ok(SocialTokenResponse {
        access_token,
        openid: values.get("openid").cloned(),
        unionid: values.get("unionid").cloned(),
        expires_in: values
            .get("expires_in")
            .and_then(|value| value.parse::<i64>().ok()),
    })
}

fn parse_json_or_jsonp(body: &str) -> anyhow::Result<Value> {
    let trimmed = body.trim();
    if let Ok(value) = serde_json::from_str::<Value>(trimmed) {
        return Ok(value);
    }
    let Some(start) = trimmed.find('{') else {
        anyhow::bail!("social JSONP body missing object");
    };
    let Some(end) = trimmed.rfind('}') else {
        anyhow::bail!("social JSONP body missing object end");
    };
    Ok(serde_json::from_str::<Value>(&trimmed[start..=end])?)
}

fn token_claim_string<'a>(token: &'a SocialTokenResponse, claim: &str) -> Option<&'a str> {
    match claim {
        "openid" => token.openid.as_deref(),
        "unionid" => token.unionid.as_deref(),
        _ => None,
    }
}

fn claim_string<'a>(value: Option<&'a Value>, claim: &str) -> Option<&'a str> {
    value?
        .get(claim)?
        .as_str()
        .filter(|value| !value.is_empty())
}

fn claim_bool(value: Option<&Value>, claim: &str) -> Option<bool> {
    value?.get(claim)?.as_bool()
}

#[cfg(test)]
#[path = "../../../../tests/in_source/src/http/auth/tests/federation_social.rs"]
mod tests;
