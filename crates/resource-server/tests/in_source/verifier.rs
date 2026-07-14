use super::fixtures::*;
use super::*;
use jsonwebtoken::{Algorithm, Header};
use serde_json::json;

fn verifier_with(config: ResourceServerVerifierConfig) -> ResourceServerVerifier {
    ResourceServerVerifier::new(config.clone()).unwrap_or_else(|error| {
        panic!("verifier config should be valid: {error:?}, config: {config:?}")
    })
}

fn token_with_exact_header(
    fixture: &Fixture,
    claim_overrides: serde_json::Value,
    header: Header,
) -> String {
    let now = Utc::now().timestamp();
    let mut claims = json!({
        "iss": "https://issuer.example",
        "sub": "subject-1",
        "aud": "resource://default",
        "client_id": "client-1",
        "scope": "read write",
        "authorization_details": [],
        "token_use": "access",
        "jti": "jti-1",
        "iat": now,
        "nbf": now,
        "exp": now + 300
    });
    merge_object(&mut claims, claim_overrides);
    jsonwebtoken::encode(&header, &claims, &fixture.encoding_key).unwrap()
}

#[test]
fn verifies_jwt_access_token_with_required_scope() {
    let fixture = fixture();
    let verified = fixture
        .verifier
        .verify(&token(&fixture, json!({}), None))
        .unwrap();

    assert_eq!(verified.issuer, "https://issuer.example");
    assert_eq!(verified.subject, "subject-1");
    assert_eq!(verified.audiences, vec!["resource://default"]);
    assert_eq!(verified.scopes, vec!["read", "write"]);
}

#[test]
fn rejects_token_with_missing_kid_before_key_lookup() {
    let fixture = fixture();
    let mut header = Header::new(Algorithm::RS256);
    header.typ = Some("at+jwt".to_owned());

    let error = fixture
        .verifier
        .verify(&token_with_exact_header(&fixture, json!({}), header))
        .unwrap_err();

    assert_eq!(error, ResourceServerVerifierError::MissingKeyId);
}

#[test]
fn rejects_token_with_unknown_kid() {
    let fixture = fixture();
    let mut header = Header::new(Algorithm::RS256);
    header.typ = Some("at+jwt".to_owned());
    header.kid = Some("unknown-kid".to_owned());

    let error = fixture
        .verifier
        .verify(&token(&fixture, json!({}), Some(header)))
        .unwrap_err();

    assert_eq!(error, ResourceServerVerifierError::UnknownKeyId);
}

#[test]
fn rejects_token_signed_with_disallowed_algorithm() {
    let fixture = fixture();
    let mut config = ResourceServerVerifierConfig::new(
        "https://issuer.example",
        "resource://default",
        fixture.jwks.clone(),
    );
    config.required_scopes = vec!["read".to_owned()];
    config.allowed_algs = vec![Algorithm::PS256];
    let verifier = verifier_with(config);

    let error = verifier
        .verify(&token(&fixture, json!({}), None))
        .unwrap_err();

    assert_eq!(error, ResourceServerVerifierError::UnsupportedAlgorithm);
}

#[test]
fn rejects_token_when_jwk_algorithm_does_not_match_header() {
    let fixture = fixture();
    let mut jwks = fixture.jwks.clone();
    jwks["keys"][0]["alg"] = json!("PS256");
    let mut config =
        ResourceServerVerifierConfig::new("https://issuer.example", "resource://default", jwks);
    config.required_scopes = vec!["read".to_owned()];
    let verifier = verifier_with(config);

    let error = verifier
        .verify(&token(&fixture, json!({}), None))
        .unwrap_err();

    assert_eq!(error, ResourceServerVerifierError::InvalidKey);
}

#[test]
fn rejects_token_with_wrong_issuer() {
    let fixture = fixture();
    let error = fixture
        .verifier
        .verify(&token(
            &fixture,
            json!({"iss": "https://attacker.example"}),
            None,
        ))
        .unwrap_err();

    assert_eq!(error, ResourceServerVerifierError::IssuerMismatch);
}

#[test]
fn rejects_wrong_audience() {
    let fixture = fixture();
    let error = fixture
        .verifier
        .verify(&token(&fixture, json!({"aud": "resource://other"}), None))
        .unwrap_err();

    assert_eq!(error, ResourceServerVerifierError::AudienceMismatch);
}

#[test]
fn accepts_any_configured_audience_from_array() {
    let fixture = fixture();
    let mut config = ResourceServerVerifierConfig::new(
        "https://issuer.example",
        "resource://payments",
        fixture.jwks.clone(),
    );
    config.audiences.push("resource://default".to_owned());
    config.required_scopes = vec!["read".to_owned()];
    let verifier = verifier_with(config);

    let verified = verifier
        .verify(&token(
            &fixture,
            json!({"aud": ["resource://unknown", "resource://default"]}),
            None,
        ))
        .unwrap();

    assert_eq!(
        verified.audiences,
        vec!["resource://unknown", "resource://default"]
    );
}

#[test]
fn rejects_non_string_audience_values() {
    let fixture = fixture();
    let error = fixture
        .verifier
        .verify(&token(
            &fixture,
            json!({"aud": {"resource": "default"}}),
            None,
        ))
        .unwrap_err();

    assert_eq!(error, ResourceServerVerifierError::AudienceMismatch);
}

#[test]
fn rejects_missing_required_scope() {
    let fixture = fixture();
    let error = fixture
        .verifier
        .verify(&token(&fixture, json!({"scope": "write"}), None))
        .unwrap_err();

    assert_eq!(
        error,
        ResourceServerVerifierError::MissingScope("read".to_owned())
    );
}

#[test]
fn rejects_expired_and_not_yet_valid_tokens_with_clock_skew() {
    let fixture = fixture();
    let now = Utc::now().timestamp();
    let outside_skew = fixture.verifier.config.clock_skew_seconds + 60;

    let expired = fixture
        .verifier
        .verify(&token(&fixture, json!({"exp": now - outside_skew}), None))
        .unwrap_err();
    let not_yet_valid = fixture
        .verifier
        .verify(&token(&fixture, json!({"nbf": now + outside_skew}), None))
        .unwrap_err();

    assert_eq!(expired, ResourceServerVerifierError::Expired);
    assert_eq!(not_yet_valid, ResourceServerVerifierError::NotYetValid);
}

#[test]
fn rejects_token_with_non_access_token_use() {
    let fixture = fixture();
    let error = fixture
        .verifier
        .verify(&token(&fixture, json!({"token_use": "id"}), None))
        .unwrap_err();

    assert_eq!(error, ResourceServerVerifierError::WrongTokenType);
}

#[test]
fn rejects_id_token_typ() {
    let fixture = fixture();
    let mut header = Header::new(Algorithm::RS256);
    header.typ = Some("JWT".to_owned());
    header.kid = Some("test-rs256".to_owned());
    let error = fixture
        .verifier
        .verify(&token(&fixture, json!({}), Some(header)))
        .unwrap_err();

    assert_eq!(error, ResourceServerVerifierError::WrongTokenType);
}

#[test]
fn rejects_verifier_configs_missing_trust_anchors() {
    assert_eq!(
        ResourceServerVerifier::new(ResourceServerVerifierConfig::new(
            "",
            "resource://default",
            json!({"keys": []})
        ))
        .unwrap_err(),
        ResourceServerVerifierError::MissingIssuer
    );
    assert_eq!(
        ResourceServerVerifier::new(ResourceServerVerifierConfig {
            audiences: Vec::new(),
            ..ResourceServerVerifierConfig::new(
                "https://issuer.example",
                "resource://default",
                json!({"keys": []})
            )
        })
        .unwrap_err(),
        ResourceServerVerifierError::MissingAudience
    );
    assert_eq!(
        ResourceServerVerifier::new(ResourceServerVerifierConfig::new(
            "https://issuer.example",
            "resource://default",
            json!({})
        ))
        .unwrap_err(),
        ResourceServerVerifierError::MissingJwks
    );
}

#[test]
fn enforces_dpop_jkt_binding() {
    let fixture = fixture();
    let mut config = ResourceServerVerifierConfig::new(
        "https://issuer.example",
        "resource://default",
        fixture.jwks.clone(),
    );
    config.confirmation = ConfirmationPolicy::RequireDpopJkt("jkt-1".to_owned());
    let verifier = ResourceServerVerifier::new(config).unwrap();

    let verified = verifier
        .verify(&token(&fixture, json!({"cnf": {"jkt": "jkt-1"}}), None))
        .unwrap();
    assert_eq!(verified.cnf.unwrap().jkt, Some("jkt-1".to_owned()));
}

#[test]
fn enforces_sender_constraint_policy_variants() {
    assert_eq!(
        validate_confirmation_policy(&ConfirmationPolicy::RequireDpop, None).unwrap_err(),
        ResourceServerVerifierError::MissingSenderConstraint
    );
    assert_eq!(
        validate_confirmation_policy(
            &ConfirmationPolicy::RequireDpop,
            Some(&ConfirmationClaims {
                jkt: Some("jkt-1".to_owned()),
                x5t_s256: None,
            }),
        ),
        Ok(())
    );
    assert_eq!(
        validate_confirmation_policy(
            &ConfirmationPolicy::RequireMtls,
            Some(&ConfirmationClaims {
                jkt: None,
                x5t_s256: Some("thumb-1".to_owned()),
            }),
        ),
        Ok(())
    );
    assert_eq!(
        validate_confirmation_policy(
            &ConfirmationPolicy::RequireMtlsThumbprint("thumb-1".to_owned()),
            Some(&ConfirmationClaims {
                jkt: None,
                x5t_s256: Some("thumb-2".to_owned()),
            }),
        )
        .unwrap_err(),
        ResourceServerVerifierError::MtlsBindingMismatch
    );
    assert_eq!(
        validate_confirmation_policy(
            &ConfirmationPolicy::RequireAnySenderConstraint,
            Some(&ConfirmationClaims {
                jkt: None,
                x5t_s256: None,
            }),
        )
        .unwrap_err(),
        ResourceServerVerifierError::MissingSenderConstraint
    );
}

#[test]
fn rejects_dpop_jkt_mismatch() {
    let fixture = fixture();
    let mut config = ResourceServerVerifierConfig::new(
        "https://issuer.example",
        "resource://default",
        fixture.jwks.clone(),
    );
    config.confirmation = ConfirmationPolicy::RequireDpopJkt("jkt-1".to_owned());
    let verifier = ResourceServerVerifier::new(config).unwrap();

    let error = verifier
        .verify(&token(&fixture, json!({"cnf": {"jkt": "jkt-2"}}), None))
        .unwrap_err();

    assert_eq!(error, ResourceServerVerifierError::DpopBindingMismatch);
}

#[test]
fn enforces_require_any_sender_constraint_with_none_cnf() {
    assert_eq!(
        validate_confirmation_policy(&ConfirmationPolicy::RequireAnySenderConstraint, None,),
        Err(ResourceServerVerifierError::MissingSenderConstraint)
    );
}

#[test]
fn enforces_require_any_sender_constraint_with_jkt() {
    assert_eq!(
        validate_confirmation_policy(
            &ConfirmationPolicy::RequireAnySenderConstraint,
            Some(&ConfirmationClaims {
                jkt: Some("jkt-1".to_owned()),
                x5t_s256: None,
            }),
        ),
        Ok(())
    );
}

#[test]
fn enforces_require_any_sender_constraint_with_x5t() {
    assert_eq!(
        validate_confirmation_policy(
            &ConfirmationPolicy::RequireAnySenderConstraint,
            Some(&ConfirmationClaims {
                jkt: None,
                x5t_s256: Some("thumb-1".to_owned()),
            }),
        ),
        Ok(())
    );
}

#[test]
fn enforces_require_mtls_with_none_cnf() {
    assert_eq!(
        validate_confirmation_policy(&ConfirmationPolicy::RequireMtls, None,),
        Err(ResourceServerVerifierError::MissingSenderConstraint)
    );
}

#[test]
fn enforces_require_mtls_thumbprint_with_none_cnf() {
    assert_eq!(
        validate_confirmation_policy(
            &ConfirmationPolicy::RequireMtlsThumbprint("thumb-1".to_owned()),
            None,
        ),
        Err(ResourceServerVerifierError::MissingSenderConstraint)
    );
}

#[test]
fn enforces_require_mtls_thumbprint_with_matching_cnf() {
    assert_eq!(
        validate_confirmation_policy(
            &ConfirmationPolicy::RequireMtlsThumbprint("thumb-1".to_owned()),
            Some(&ConfirmationClaims {
                jkt: None,
                x5t_s256: Some("thumb-1".to_owned()),
            }),
        ),
        Ok(())
    );
}

#[test]
fn enforces_require_dpop_jkt_with_none_cnf() {
    assert_eq!(
        validate_confirmation_policy(
            &ConfirmationPolicy::RequireDpopJkt("jkt-1".to_owned()),
            None,
        ),
        Err(ResourceServerVerifierError::MissingSenderConstraint)
    );
}
