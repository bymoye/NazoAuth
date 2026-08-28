use super::*;

fn approval(action: &str) -> ApprovalRequestBody {
    ApprovalRequestBody {
        action: action.to_owned(),
        deployment_id: "deployment-a".to_owned(),
        controller_id: Some("019c8ca2-30a6-7cc9-9f2a-4f5a6b7c8d90".to_owned()),
        label: Some("primary".to_owned()),
        public_key: Some("key".to_owned()),
        kid: Some("kid".to_owned()),
        recovery_public_key: Some("recovery-key".to_owned()),
        recovery_kid: Some("recovery-kid".to_owned()),
    }
}

#[test]
fn rotate_and_revoke_approval_reject_recovery_fields() {
    for action in ["rotate", "revoke"] {
        let response = approval(action)
            .change()
            .expect_err("recovery fields must be rejected");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}

#[test]
fn rotate_and_revoke_commit_json_reject_recovery_fields() {
    let rotate = serde_json::json!({
        "approval_token": "approval",
        "deployment_id": "deployment-a",
        "controller_id": "019c8ca2-30a6-7cc9-9f2a-4f5a6b7c8d90",
        "label": "primary",
        "public_key": "key",
        "kid": "kid",
        "recovery_public_key": "forbidden"
    });
    assert!(serde_json::from_value::<SlotRotateBody>(rotate).is_err());

    let revoke = serde_json::json!({
        "approval_token": "approval",
        "deployment_id": "deployment-a",
        "controller_id": "019c8ca2-30a6-7cc9-9f2a-4f5a6b7c8d90",
        "recovery_kid": "forbidden"
    });
    assert!(serde_json::from_value::<SlotRevokeBody>(revoke).is_err());
}
