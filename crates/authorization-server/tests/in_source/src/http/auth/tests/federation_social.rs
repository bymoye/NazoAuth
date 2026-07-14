use super::*;

fn qq_provider() -> SocialProviderSettings {
    SocialProviderSettings {
        kind: SocialProviderKind::Qq,
        authorization_endpoint: "https://graph.qq.com/oauth2.0/authorize".to_owned(),
        token_endpoint: "https://graph.qq.com/oauth2.0/token".to_owned(),
        openid_endpoint: Some("https://graph.qq.com/oauth2.0/me".to_owned()),
        userinfo_endpoint: "https://graph.qq.com/user/get_user_info".to_owned(),
        client_id: "qq-client".to_owned(),
        client_secret: "qq-secret".to_owned(),
        redirect_uri: "https://auth.example/federation/qq/callback".to_owned(),
        scopes: "get_user_info".to_owned(),
        subject_claim: "openid".to_owned(),
        email_claim: Some("email".to_owned()),
        email_verified_claim: Some("email_verified".to_owned()),
        name_claim: Some("nickname".to_owned()),
        union_id_claim: Some("unionid".to_owned()),
    }
}

fn wechat_provider() -> SocialProviderSettings {
    SocialProviderSettings {
        kind: SocialProviderKind::Wechat,
        authorization_endpoint: "https://open.weixin.qq.com/connect/qrconnect".to_owned(),
        token_endpoint: "https://api.weixin.qq.com/sns/oauth2/access_token".to_owned(),
        openid_endpoint: None,
        userinfo_endpoint: "https://api.weixin.qq.com/sns/userinfo".to_owned(),
        client_id: "wechat-client".to_owned(),
        client_secret: "wechat-secret".to_owned(),
        redirect_uri: "https://auth.example/federation/wechat/callback".to_owned(),
        scopes: "snsapi_login".to_owned(),
        subject_claim: "unionid".to_owned(),
        email_claim: None,
        email_verified_claim: None,
        name_claim: Some("nickname".to_owned()),
        union_id_claim: Some("unionid".to_owned()),
    }
}

#[test]
fn social_authorization_url_uses_provider_specific_client_parameter() {
    // QQ 使用 OAuth2 标准 client_id，微信开放平台使用 appid；
    // 该差异必须停留在 social adapter 内部。
    let qq = social_authorization_url(&qq_provider(), "state-1", "verifier-1");
    let qq_url = url::Url::parse(&qq).unwrap();
    let qq_params = qq_url
        .query_pairs()
        .collect::<std::collections::HashMap<_, _>>();
    assert_eq!(
        qq_params.get("client_id").map(|value| value.as_ref()),
        Some("qq-client")
    );
    assert_eq!(qq_params.get("appid"), None);
    assert_eq!(
        qq_params.get("code_challenge").map(|value| value.as_ref()),
        Some(pkce_s256("verifier-1").as_str())
    );

    let wechat = social_authorization_url(&wechat_provider(), "state-2", "verifier-2");
    let wechat_url = url::Url::parse(&wechat).unwrap();
    let wechat_params = wechat_url
        .query_pairs()
        .collect::<std::collections::HashMap<_, _>>();
    assert_eq!(
        wechat_params.get("appid").map(|value| value.as_ref()),
        Some("wechat-client")
    );
    assert_eq!(wechat_params.get("client_id"), None);
}

#[test]
fn social_token_parser_accepts_json_and_form_urlencoded_provider_responses() {
    // QQ 可能返回 form-urlencoded，微信通常返回 JSON；两种响应都只产生
    // adapter 内部的短期 access token 结构。
    let form = parse_social_token_response(
        "access_token=qq-token&expires_in=7776000&openid=qq-openid".to_owned(),
    )
    .unwrap();
    assert_eq!(form.access_token, "qq-token");
    assert_eq!(form.openid.as_deref(), Some("qq-openid"));
    assert_eq!(form.expires_in, Some(7_776_000));

    let json = parse_social_token_response(
        r#"{"access_token":"wechat-token","openid":"wechat-openid","unionid":"wechat-union"}"#
            .to_owned(),
    )
    .unwrap();
    assert_eq!(json.access_token, "wechat-token");
    assert_eq!(json.openid.as_deref(), Some("wechat-openid"));
    assert_eq!(json.unionid.as_deref(), Some("wechat-union"));
}

#[test]
fn social_jsonp_parser_accepts_qq_openid_wrapper_without_executing_script() {
    // QQ openid endpoint 返回 JSONP 包装；这里只截取 JSON 对象，不执行脚本内容。
    let parsed =
        parse_json_or_jsonp(r#"callback( {"client_id":"qq-client","openid":"qq-openid"} );"#)
            .unwrap();

    assert_eq!(parsed["client_id"], "qq-client");
    assert_eq!(parsed["openid"], "qq-openid");
}

#[test]
fn social_identity_normalization_uses_subject_claim_and_verified_email_only() {
    let provider = qq_provider();
    let token = SocialTokenResponse {
        access_token: "qq-token".to_owned(),
        openid: Some("qq-openid".to_owned()),
        unionid: Some("qq-union".to_owned()),
        expires_in: Some(300),
    };
    let identity = normalize_social_identity(
        &provider,
        &token,
        Some(json!({"openid": "qq-openid"})),
        json!({
            "openid": "qq-openid",
            "email": "User@Example.COM",
            "email_verified": true,
            "nickname": "QQ User"
        }),
    )
    .unwrap();

    assert_eq!(identity.subject, "qq-openid");
    assert_eq!(identity.email.as_deref(), Some("user@example.com"));
    assert_eq!(identity.display_name.as_deref(), Some("QQ User"));

    let unverified = normalize_social_identity(
        &provider,
        &token,
        Some(json!({"openid": "qq-openid"})),
        json!({
            "openid": "qq-openid",
            "email": "user@example.com",
            "email_verified": false
        }),
    )
    .unwrap();
    assert_eq!(unverified.email, None);
}
