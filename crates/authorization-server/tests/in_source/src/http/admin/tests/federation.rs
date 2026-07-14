use super::*;
use crate::settings::{
    ExternalLoginProvider, ExternalLoginProviderAdapter, OidcFederationSettings,
};

#[test]
fn admin_provider_view_exposes_onboarding_metadata_without_secret_material() {
    let provider = ExternalLoginProvider {
        provider_id: "google".to_owned(),
        enabled: true,
        display_name: "Google".to_owned(),
        icon: Some("google".to_owned()),
        display_order: 10,
        adapter: ExternalLoginProviderAdapter::Oidc(OidcFederationSettings {
            provider_id: "google".to_owned(),
            issuer: "https://accounts.google.com".to_owned(),
            authorization_endpoint: "https://accounts.google.com/o/oauth2/v2/auth".to_owned(),
            token_endpoint: "https://oauth2.googleapis.com/token".to_owned(),
            jwks_url: "https://www.googleapis.com/oauth2/v3/certs".to_owned(),
            client_id: "google-client".to_owned(),
            client_secret: "google-secret".to_owned(),
            redirect_uri: "https://auth.example/auth/federation/google/callback".to_owned(),
            scopes: "openid email profile".to_owned(),
        }),
    };

    // 管理端 onboarding 可以确认端点是否配置，但不能返回 secret 原文。
    let view = admin_provider_view(&provider);
    assert_eq!(view["provider_id"], "google");
    assert_eq!(
        view["redirect_uri"],
        "https://auth.example/auth/federation/google/callback"
    );
    assert_eq!(view["secret_configured"], true);
    assert!(view.get("client_secret").is_none());
    assert!(view.get("access_token").is_none());
}

#[test]
fn admin_federation_handler_uses_focused_dependencies() {
    let source = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/http/admin/federation.rs"
    ));

    assert!(!source.contains("Data<TestAppState>"));
    assert!(!source.contains("diesel_db"));
    assert!(!source.contains("valkey_connection"));
    assert!(source.contains("Data<AdminSessionHandles>"));
    assert!(source.contains("Data<AdminFederationConfig>"));
}
