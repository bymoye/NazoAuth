use chrono::{Duration, Utc};
use nazo_digital_credentials::CredentialFormat;
use nazo_openid4vci::CredentialConfiguration;
use serde_json::{Value, json};

use super::{
    PutCredentialDatasetRequest, openid4vci_authorization_detail,
    openid4vci_configuration_id_from_identifier, token_endpoint_dpop_target_uris,
    validate_managed_dataset,
};

fn dataset_configuration(format: CredentialFormat) -> CredentialConfiguration {
    CredentialConfiguration {
        format,
        scope: Some("credential".to_owned()),
        cryptographic_binding_methods_supported: Vec::new(),
        credential_signing_alg_values_supported: vec!["ES256".to_owned()],
        proof_types_supported: Default::default(),
        vct: None,
        doctype: None,
        credential_metadata: None,
    }
}

fn dataset_request(claims: Value) -> PutCredentialDatasetRequest {
    PutCredentialDatasetRequest {
        claims,
        valid_from: None,
        valid_until: None,
    }
}

#[test]
fn vci_authorization_detail_contains_final_credential_identifier() {
    let detail = openid4vci_authorization_detail("https://issuer.example", "org.iso.18013.5.1.mDL");
    let identifiers = detail["credential_identifiers"]
        .as_array()
        .expect("credential_identifiers array");
    let identifier = nazo_openid4vci::CredentialIdentifier(
        identifiers[0]
            .as_str()
            .expect("identifier string")
            .to_owned(),
    );

    assert_eq!(detail["type"], "openid_credential");
    assert_eq!(
        detail["credential_configuration_id"],
        "org.iso.18013.5.1.mDL"
    );
    assert_eq!(detail["locations"], json!(["https://issuer.example"]));
    assert_eq!(
        openid4vci_configuration_id_from_identifier(&identifier).as_deref(),
        Some("org.iso.18013.5.1.mDL")
    );
}

#[test]
fn managed_sd_jwt_dataset_rejects_reserved_claims_and_structural_abuse() {
    let configuration = dataset_configuration(CredentialFormat::SdJwtVc);
    for claims in [json!({}), json!({"iss":"attacker"}), json!({"cnf":{}})] {
        assert!(validate_managed_dataset(&configuration, &dataset_request(claims)).is_err());
    }

    let mut deep = json!("value");
    for _ in 0..10 {
        deep = json!({"nested": deep});
    }
    assert!(validate_managed_dataset(&configuration, &dataset_request(deep)).is_err());
    assert!(
        validate_managed_dataset(
            &configuration,
            &dataset_request(json!({"biography":"x".repeat(4097)})),
        )
        .is_err()
    );

    validate_managed_dataset(
        &configuration,
        &dataset_request(json!({"given_name":"Ada","age_over_18":true})),
    )
    .expect("ordinary issuer-controlled claims are accepted");
}

#[test]
fn managed_mdoc_dataset_requires_nonempty_namespace_objects() {
    let configuration = dataset_configuration(CredentialFormat::MsoMdoc);
    for claims in [
        json!({"org.iso.18013.5.1": "not-an-object"}),
        json!({"org.iso.18013.5.1": {}}),
        json!({"": {"family_name":"Lovelace"}}),
    ] {
        assert!(validate_managed_dataset(&configuration, &dataset_request(claims)).is_err());
    }

    validate_managed_dataset(
        &configuration,
        &dataset_request(json!({
            "org.iso.18013.5.1": {"family_name":"Lovelace"}
        })),
    )
    .expect("mdoc namespace objects are accepted");
}

#[test]
fn managed_dataset_validity_must_end_after_start_and_now() {
    let configuration = dataset_configuration(CredentialFormat::SdJwtVc);
    let now = Utc::now();
    let claims = json!({"given_name":"Ada"});

    let expired = PutCredentialDatasetRequest {
        claims: claims.clone(),
        valid_from: None,
        valid_until: Some(now - Duration::seconds(1)),
    };
    assert!(validate_managed_dataset(&configuration, &expired).is_err());

    let reversed = PutCredentialDatasetRequest {
        claims,
        valid_from: Some(now + Duration::hours(2)),
        valid_until: Some(now + Duration::hours(1)),
    };
    assert!(validate_managed_dataset(&configuration, &reversed).is_err());
}

#[test]
fn vci_token_dpop_targets_include_public_issuer_endpoint() {
    assert_eq!(
        token_endpoint_dpop_target_uris("https://issuer.example/", "https://suite.example/token"),
        vec!["https://issuer.example/token".to_owned()]
    );
    assert_eq!(
        token_endpoint_dpop_target_uris("https://issuer.example", "https://issuer.example/token"),
        vec!["https://issuer.example/token".to_owned()]
    );
    assert_eq!(
        token_endpoint_dpop_target_uris(
            "https://issuer.example",
            "https://issuer.examplehttps://issuer.example/token"
        ),
        vec!["https://issuer.example/token".to_owned()]
    );
}

#[test]
fn pre_authorized_token_validates_dpop_before_consuming_single_use_state() {
    let source = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/domain/openid4vc_endpoints.rs"
    ));
    let start = source
        .find("fn pre_authorized_token")
        .expect("pre_authorized_token implementation should exist");
    let body = &source[start..];
    let dpop = body
        .find("validate_authorization_server_dpop")
        .expect("pre-authorized token flow must validate DPoP");
    let attestation_replay = body
        .find("consume_private_key_jwt")
        .expect("client attestation replay state is consumed in this flow");
    let pre_authorized_code = body
        .find("consume_pre_authorized_offer")
        .expect("pre-authorized code is consumed in this flow");

    assert!(
        dpop < attestation_replay,
        "DPoP nonce challenges must not consume client attestation replay state"
    );
    assert!(
        dpop < pre_authorized_code,
        "DPoP nonce challenges must not consume the pre-authorized code"
    );
}
