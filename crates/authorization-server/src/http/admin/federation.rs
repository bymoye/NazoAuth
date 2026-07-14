//! 管理端第三方登录 provider 配置视图。
//! 这里只暴露启停状态、展示信息和回调地址，不返回 secret 或第三方 token。
use nazo_http_actix::json_response_no_store;

use crate::http::sessions::{AdminSessionHandles, require_admin_or_forbidden_with_handles};
use crate::settings::{ExternalLoginProviderAdapter, Settings};
use actix_web::web::Data;
use actix_web::{HttpRequest, HttpResponse};
use serde_json::{Value, json};
use std::sync::Arc;

#[derive(Clone)]
pub(crate) struct AdminFederationConfig {
    providers: Arc<[Value]>,
}

impl AdminFederationConfig {
    pub(crate) fn from_settings(settings: &Settings) -> Self {
        Self {
            providers: settings
                .identity
                .federation
                .providers
                .configured_providers()
                .map(admin_provider_view)
                .collect::<Vec<_>>()
                .into(),
        }
    }

    fn providers(&self) -> &[Value] {
        &self.providers
    }
}

pub(crate) async fn admin_federation_providers(
    admin_sessions: Data<AdminSessionHandles>,
    config: Data<AdminFederationConfig>,
    req: HttpRequest,
) -> HttpResponse {
    if let Err(response) = require_admin_or_forbidden_with_handles(&admin_sessions, &req).await {
        return response;
    }
    // 管理端 onboarding 需要能核对 callback 与 adapter 类型，但不能读取
    // client_secret、第三方 access token 或 JWKS 原始内容。
    json_response_no_store(json!({ "providers": config.providers() }))
}

fn admin_provider_view(provider: &crate::settings::ExternalLoginProvider) -> Value {
    match &provider.adapter {
        ExternalLoginProviderAdapter::Oidc(oidc) => json!({
            "provider_id": &provider.provider_id,
            "enabled": provider.enabled,
            "display_name": &provider.display_name,
            "adapter_type": provider.adapter_type(),
            "display_order": provider.display_order,
            "redirect_uri": &oidc.redirect_uri,
            "issuer": &oidc.issuer,
            "authorization_endpoint": &oidc.authorization_endpoint,
            "token_endpoint_configured": true,
            "jwks_url_configured": true,
            "secret_configured": true,
        }),
        ExternalLoginProviderAdapter::Social(social) => json!({
            "provider_id": &provider.provider_id,
            "enabled": provider.enabled,
            "display_name": &provider.display_name,
            "adapter_type": provider.adapter_type(),
            "display_order": provider.display_order,
            "redirect_uri": &social.redirect_uri,
            "provider_kind": format!("{:?}", social.kind).to_ascii_lowercase(),
            "authorization_endpoint": &social.authorization_endpoint,
            "token_endpoint_configured": true,
            "userinfo_endpoint": &social.userinfo_endpoint,
            "openid_endpoint_configured": social.openid_endpoint.is_some(),
            "secret_configured": true,
        }),
    }
}

#[cfg(test)]
#[path = "../../../tests/in_source/src/http/admin/tests/federation.rs"]
mod tests;
