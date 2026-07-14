use std::collections::HashSet;

use anyhow::{Context, bail};
use nazo_auth::validate_issuer_url;
use serde::Deserialize;

use crate::config::ConfigSource;

use super::OidcFederationSettings;

// 第三方登录 provider 的运行时注册表。它是登录入口可见性、路由分发
// 和 adapter 选择的单一事实源，避免核心登录流程硬编码某一个 provider。
#[derive(Clone, Default)]
pub(crate) struct FederationProviderRegistry {
    providers: Vec<ExternalLoginProvider>,
}

// 单个 provider 的公共元数据。secret 等敏感材料只保留在 adapter 配置中，
// 公开给前端的 provider 列表只能使用这里的非敏感字段。
#[derive(Clone)]
pub(crate) struct ExternalLoginProvider {
    pub(crate) provider_id: String,
    pub(crate) enabled: bool,
    pub(crate) display_name: String,
    pub(crate) icon: Option<String>,
    pub(crate) display_order: i32,
    pub(crate) adapter: ExternalLoginProviderAdapter,
}

// 每种接入协议由独立 adapter 承担，新增 provider 类型时只扩展这里的枚举
// 和对应模块，不把 provider 差异泄漏到 session 或 account linking 模型。
#[derive(Clone)]
pub(crate) enum ExternalLoginProviderAdapter {
    Oidc(OidcFederationSettings),
    Social(SocialProviderSettings),
}

// OAuth2 social provider 的归一化配置。QQ、微信等 provider 不伪装成 OIDC；
// 它们只提供外部身份获取能力，第三方 access token 不会进入本平台 token 模型。
#[derive(Clone)]
pub(crate) struct SocialProviderSettings {
    pub(crate) kind: SocialProviderKind,
    pub(crate) authorization_endpoint: String,
    pub(crate) token_endpoint: String,
    pub(crate) openid_endpoint: Option<String>,
    pub(crate) userinfo_endpoint: String,
    pub(crate) client_id: String,
    pub(crate) client_secret: String,
    pub(crate) redirect_uri: String,
    pub(crate) scopes: String,
    pub(crate) subject_claim: String,
    pub(crate) email_claim: Option<String>,
    pub(crate) email_verified_claim: Option<String>,
    pub(crate) name_claim: Option<String>,
    pub(crate) union_id_claim: Option<String>,
}

// provider_kind 决定 social adapter 的默认端点、默认 scope 和身份字段。
// 自定义 provider 必须显式提供端点，避免把未知 provider 当作 QQ/微信处理。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SocialProviderKind {
    Qq,
    Wechat,
    Custom,
}

// FEDERATION_PROVIDER_CONFIGS 的 JSON 输入形态。该结构只用于配置解析；
// 解析后立即转换为强类型 adapter，运行时不再依赖松散 JSON。
#[derive(Deserialize)]
struct ProviderConfig {
    provider_id: String,
    #[serde(default)]
    enabled: bool,
    display_name: String,
    adapter_type: String,
    #[serde(default)]
    icon: Option<String>,
    #[serde(default)]
    display_order: i32,
    client_id: Option<String>,
    client_secret: Option<String>,
    redirect_uri: Option<String>,
    scopes: Option<String>,
    issuer: Option<String>,
    authorization_endpoint: Option<String>,
    token_endpoint: Option<String>,
    jwks_url: Option<String>,
    provider_kind: Option<String>,
    openid_endpoint: Option<String>,
    userinfo_endpoint: Option<String>,
    subject_claim: Option<String>,
    email_claim: Option<String>,
    email_verified_claim: Option<String>,
    name_claim: Option<String>,
    union_id_claim: Option<String>,
}

impl FederationProviderRegistry {
    // 从 JSON 配置构建 provider registry；登录运行时只读取这一处事实源。
    pub(super) fn from_config(config: &ConfigSource) -> anyhow::Result<Self> {
        let mut providers = Vec::new();
        if let Some(raw) = config.optional_string("FEDERATION_PROVIDER_CONFIGS") {
            let parsed = serde_json::from_str::<Vec<ProviderConfig>>(&raw)
                .context("FEDERATION_PROVIDER_CONFIGS must be a JSON array")?;
            for config in parsed {
                providers.push(config.into_provider()?);
            }
        }
        validate_unique_provider_ids(&providers)?;
        providers.sort_by(|left, right| {
            left.display_order
                .cmp(&right.display_order)
                .then_with(|| left.provider_id.cmp(&right.provider_id))
        });
        Ok(Self { providers })
    }

    // 只返回 enabled provider，供登录入口和动态路由使用。
    // 未启用 provider 即使配置存在，也不能出现在前端入口中。
    pub(crate) fn enabled_public_providers(&self) -> impl Iterator<Item = &ExternalLoginProvider> {
        self.providers.iter().filter(|provider| provider.enabled)
    }

    // 管理端 onboarding 需要查看 disabled provider 的非敏感配置状态。
    pub(crate) fn configured_providers(&self) -> impl Iterator<Item = &ExternalLoginProvider> {
        self.providers.iter()
    }

    // 路由分发只能命中 enabled provider；disabled 或未知 provider 都按不可用处理。
    pub(crate) fn enabled_provider(&self, provider_id: &str) -> Option<&ExternalLoginProvider> {
        self.providers
            .iter()
            .find(|provider| provider.enabled && provider.provider_id == provider_id)
    }
}

impl ExternalLoginProvider {
    // adapter_type 是返回给前端和文档的稳定字符串，不暴露内部枚举名称。
    pub(crate) fn adapter_type(&self) -> &'static str {
        match &self.adapter {
            ExternalLoginProviderAdapter::Oidc(_) => "oidc",
            ExternalLoginProviderAdapter::Social(_) => "oauth2_social",
        }
    }
}

impl ProviderConfig {
    // 将松散配置转换成强类型 provider。配置不完整时直接启动失败，
    // 而不是在用户点击登录时再进入半配置状态。
    fn into_provider(self) -> anyhow::Result<ExternalLoginProvider> {
        validate_provider_id(&self.provider_id)?;
        let display_name = required_text(Some(self.display_name.clone()), "display_name")?;
        let adapter = match self.adapter_type.as_str() {
            "oidc" => ExternalLoginProviderAdapter::Oidc(self.clone_oidc()?),
            "oauth2_social" => ExternalLoginProviderAdapter::Social(self.clone_social()?),
            other => bail!("unsupported federation provider adapter_type {other}"),
        };
        Ok(ExternalLoginProvider {
            provider_id: self.provider_id,
            enabled: self.enabled,
            display_name,
            icon: self.icon.and_then(trimmed_optional),
            display_order: self.display_order,
            adapter,
        })
    }

    // OIDC provider 必须提供 issuer、端点、JWKS、client 凭据和 openid scope。
    // 这些字段共同决定 ID Token 校验边界，不能在运行时补默认值。
    fn clone_oidc(&self) -> anyhow::Result<OidcFederationSettings> {
        let settings = OidcFederationSettings {
            provider_id: self.provider_id.clone(),
            issuer: required_text(self.issuer.clone(), "issuer")?,
            authorization_endpoint: required_text(
                self.authorization_endpoint.clone(),
                "authorization_endpoint",
            )?,
            token_endpoint: required_text(self.token_endpoint.clone(), "token_endpoint")?,
            jwks_url: required_text(self.jwks_url.clone(), "jwks_url")?,
            client_id: required_text(self.client_id.clone(), "client_id")?,
            client_secret: required_text(self.client_secret.clone(), "client_secret")?,
            redirect_uri: required_text(self.redirect_uri.clone(), "redirect_uri")?,
            scopes: self
                .scopes
                .clone()
                .and_then(trimmed_optional)
                .unwrap_or_else(|| "openid email profile".to_owned()),
        };
        validate_oidc_settings(&settings, "FEDERATION_PROVIDER_CONFIGS")?;
        Ok(settings)
    }

    // OAuth2 social provider 支持 provider preset，但仍要求 client 凭据和 redirect URI
    // 显式配置。preset 只提供公开端点和 claim 名称，不提供任何信任决策。
    fn clone_social(&self) -> anyhow::Result<SocialProviderSettings> {
        let kind = match self
            .provider_kind
            .as_deref()
            .unwrap_or("custom")
            .trim()
            .to_ascii_lowercase()
            .as_str()
        {
            "qq" => SocialProviderKind::Qq,
            "wechat" | "weixin" => SocialProviderKind::Wechat,
            "custom" => SocialProviderKind::Custom,
            other => bail!("unsupported oauth2_social provider_kind {other}"),
        };
        let defaults = SocialProviderDefaults::for_kind(kind);
        let settings = SocialProviderSettings {
            kind,
            authorization_endpoint: self
                .authorization_endpoint
                .clone()
                .and_then(trimmed_optional)
                .unwrap_or_else(|| defaults.authorization_endpoint.to_owned()),
            token_endpoint: self
                .token_endpoint
                .clone()
                .and_then(trimmed_optional)
                .unwrap_or_else(|| defaults.token_endpoint.to_owned()),
            openid_endpoint: self
                .openid_endpoint
                .clone()
                .and_then(trimmed_optional)
                .or_else(|| defaults.openid_endpoint.map(str::to_owned)),
            userinfo_endpoint: self
                .userinfo_endpoint
                .clone()
                .and_then(trimmed_optional)
                .unwrap_or_else(|| defaults.userinfo_endpoint.to_owned()),
            client_id: required_text(self.client_id.clone(), "client_id")?,
            client_secret: required_text(self.client_secret.clone(), "client_secret")?,
            redirect_uri: required_text(self.redirect_uri.clone(), "redirect_uri")?,
            scopes: self
                .scopes
                .clone()
                .and_then(trimmed_optional)
                .unwrap_or_else(|| defaults.scopes.to_owned()),
            subject_claim: self
                .subject_claim
                .clone()
                .and_then(trimmed_optional)
                .unwrap_or_else(|| defaults.subject_claim.to_owned()),
            email_claim: self
                .email_claim
                .clone()
                .and_then(trimmed_optional)
                .or_else(|| defaults.email_claim.map(str::to_owned)),
            email_verified_claim: self
                .email_verified_claim
                .clone()
                .and_then(trimmed_optional)
                .or_else(|| defaults.email_verified_claim.map(str::to_owned)),
            name_claim: self
                .name_claim
                .clone()
                .and_then(trimmed_optional)
                .or_else(|| defaults.name_claim.map(str::to_owned)),
            union_id_claim: self
                .union_id_claim
                .clone()
                .and_then(trimmed_optional)
                .or_else(|| defaults.union_id_claim.map(str::to_owned)),
        };
        validate_issuer_url(&settings.authorization_endpoint)?;
        validate_issuer_url(&settings.token_endpoint)?;
        if let Some(endpoint) = &settings.openid_endpoint {
            validate_issuer_url(endpoint)?;
        }
        validate_issuer_url(&settings.userinfo_endpoint)?;
        validate_issuer_url(&settings.redirect_uri)?;
        Ok(settings)
    }
}

// OIDC URL 与 openid scope 校验集中在这里，所有 OIDC provider 共用同一规则。
pub(super) fn validate_oidc_settings(
    settings: &OidcFederationSettings,
    scopes_key: &str,
) -> anyhow::Result<()> {
    validate_issuer_url(&settings.issuer)?;
    validate_issuer_url(&settings.authorization_endpoint)?;
    validate_issuer_url(&settings.token_endpoint)?;
    validate_issuer_url(&settings.jwks_url)?;
    validate_issuer_url(&settings.redirect_uri)?;
    if !settings
        .scopes
        .split_whitespace()
        .any(|scope| scope == "openid")
    {
        bail!("{scopes_key} must include openid");
    }
    Ok(())
}

// provider_id 参与 DB 外部身份唯一键和路由路径，必须全局唯一。
fn validate_unique_provider_ids(providers: &[ExternalLoginProvider]) -> anyhow::Result<()> {
    let mut seen = HashSet::new();
    for provider in providers {
        if !seen.insert(provider.provider_id.as_str()) {
            bail!("duplicate federation provider_id {}", provider.provider_id);
        }
    }
    Ok(())
}

// provider_id 会进入 URL path、审计字段和外部身份唯一键，因此限制为小写 ASCII。
fn validate_provider_id(provider_id: &str) -> anyhow::Result<()> {
    if provider_id.is_empty()
        || provider_id.len() > 64
        || !provider_id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
    {
        bail!(
            "federation provider_id must be 1-64 lowercase ASCII letters, digits, hyphen, or underscore"
        );
    }
    Ok(())
}

// 必填字符串统一 trim，避免空白字符串绕过配置完整性检查。
fn required_text(value: Option<String>, field: &str) -> anyhow::Result<String> {
    value
        .and_then(trimmed_optional)
        .ok_or_else(|| anyhow::anyhow!("{field} is required for enabled federation provider"))
}

// 可选字符串统一 trim，空字符串等价于未配置。
fn trimmed_optional(value: String) -> Option<String> {
    let value = value.trim().to_owned();
    (!value.is_empty()).then_some(value)
}

// Social preset 只描述公开协议端点和 claim 名称，不包含 secret 或 tenant 策略。
struct SocialProviderDefaults {
    authorization_endpoint: &'static str,
    token_endpoint: &'static str,
    openid_endpoint: Option<&'static str>,
    userinfo_endpoint: &'static str,
    scopes: &'static str,
    subject_claim: &'static str,
    email_claim: Option<&'static str>,
    email_verified_claim: Option<&'static str>,
    name_claim: Option<&'static str>,
    union_id_claim: Option<&'static str>,
}

impl SocialProviderDefaults {
    // QQ 和微信不是 OIDC provider，必须走 OAuth2 social adapter 的显式归一化路径。
    fn for_kind(kind: SocialProviderKind) -> Self {
        match kind {
            SocialProviderKind::Qq => Self {
                authorization_endpoint: "https://graph.qq.com/oauth2.0/authorize",
                token_endpoint: "https://graph.qq.com/oauth2.0/token",
                openid_endpoint: Some("https://graph.qq.com/oauth2.0/me"),
                userinfo_endpoint: "https://graph.qq.com/user/get_user_info",
                scopes: "get_user_info",
                subject_claim: "openid",
                email_claim: None,
                email_verified_claim: None,
                name_claim: Some("nickname"),
                union_id_claim: Some("unionid"),
            },
            SocialProviderKind::Wechat => Self {
                authorization_endpoint: "https://open.weixin.qq.com/connect/qrconnect",
                token_endpoint: "https://api.weixin.qq.com/sns/oauth2/access_token",
                openid_endpoint: None,
                userinfo_endpoint: "https://api.weixin.qq.com/sns/userinfo",
                scopes: "snsapi_login",
                subject_claim: "unionid",
                email_claim: None,
                email_verified_claim: None,
                name_claim: Some("nickname"),
                union_id_claim: Some("unionid"),
            },
            SocialProviderKind::Custom => Self {
                authorization_endpoint: "",
                token_endpoint: "",
                openid_endpoint: None,
                userinfo_endpoint: "",
                scopes: "profile",
                subject_claim: "sub",
                email_claim: Some("email"),
                email_verified_claim: Some("email_verified"),
                name_claim: Some("name"),
                union_id_claim: None,
            },
        }
    }
}
