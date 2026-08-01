use serde_json::json;

use crate::{Claims, ConfirmationClaims};

use super::{TokenInspection, TokenPortError, access_token_type, validate_sender_constraint};

fn access_claims(confirmation: Option<ConfirmationClaims>) -> Claims {
    Claims {
        iss: "https://issuer.example".to_owned(),
        sub: "subject".to_owned(),
        tenant_id: uuid::Uuid::nil().to_string(),
        user_id: None,
        subject_type: "client".to_owned(),
        aud: json!("resource://default"),
        client_id: "client".to_owned(),
        scope: "openid".to_owned(),
        authorization_details: json!([]),
        token_use: "access".to_owned(),
        jti: "jti".to_owned(),
        iat: 1,
        nbf: 1,
        exp: 2,
        cnf: confirmation,
        act: None,
        userinfo_claims: Vec::new(),
        userinfo_claim_requests: Vec::new(),
    }
}

#[test]
fn access_token_cannot_bind_two_sender_constraints() {
    assert_eq!(
        validate_sender_constraint(Some("dpop"), Some("mtls")),
        Err(TokenPortError::InvalidSenderConstraint)
    );
    assert!(validate_sender_constraint(Some("dpop"), None).is_ok());
    assert!(validate_sender_constraint(None, Some("mtls")).is_ok());
}

#[test]
fn introspection_reports_dpop_only_for_dpop_bound_tokens() {
    assert_eq!(access_token_type(&access_claims(None)), "Bearer");
    assert_eq!(
        access_token_type(&access_claims(Some(ConfirmationClaims {
            jkt: Some("thumbprint".to_owned()),
            x5t_s256: None,
        }))),
        "DPoP"
    );
    assert_eq!(
        access_token_type(&access_claims(Some(ConfirmationClaims {
            jkt: None,
            x5t_s256: Some("certificate-thumbprint".to_owned()),
        }))),
        "Bearer"
    );
}

#[test]
fn token_inspection_builds_exact_rfc7662_documents() {
    assert_eq!(
        TokenInspection::Inactive.into_document(),
        json!({"active": false})
    );
    assert_eq!(
        TokenInspection::ActiveRefresh {
            scope: "openid offline_access".to_owned(),
            client_id: "client".to_owned(),
            expires_at: 20,
            issued_at: 10,
            subject: "subject".to_owned(),
        }
        .into_document(),
        json!({
            "active": true,
            "scope": "openid offline_access",
            "client_id": "client",
            "exp": 20,
            "iat": 10,
            "sub": "subject",
        })
    );
}
