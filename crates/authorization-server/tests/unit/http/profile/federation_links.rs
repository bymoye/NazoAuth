use crate::test_support::DatabaseExternalIdentityFixture;

use crate::domain::tenancy::DEFAULT_TENANT_ID;

use chrono::Utc;

use super::*;

#[test]
fn federation_link_json_excludes_raw_provider_claims() {
    let link = DatabaseExternalIdentityFixture {
        id: Uuid::now_v7(),
        tenant_id: DEFAULT_TENANT_ID,
        user_id: Uuid::now_v7(),
        provider_type: "oidc".to_owned(),
        provider_id: "google".to_owned(),
        subject: "provider-subject".to_owned(),
        email: "user@example.com".to_owned(),
        claims: json!({
            "access_token": "must-not-leak",
            "raw": "provider response"
        }),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        last_login_at: None,
    };

    // 列表视图只返回绑定索引和展示字段；原始 claims 不进入前端响应。
    let value = federation_link_json(link.federation_link());
    assert_eq!(value["provider_id"], "google");
    assert_eq!(value["subject"], "provider-subject");
    assert!(value.get("claims").is_none());
    assert!(value.get("access_token").is_none());
}
