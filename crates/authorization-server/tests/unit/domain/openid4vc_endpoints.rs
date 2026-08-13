use chrono::{Duration, Utc};
use nazo_digital_credentials::CredentialFormat;
use nazo_openid4vci::CredentialConfiguration;
use serde_json::{Value, json};

use super::{
    PutCredentialDatasetRequest,
    openid4vci::{openid4vci_configuration_id_from_identifier, token_endpoint_dpop_target_uris},
    openid4vci_authorization_detail,
    openid4vci_dataset::validate_managed_dataset,
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

    validate_managed_dataset(
        &configuration,
        &PutCredentialDatasetRequest {
            claims: json!({"given_name":"Ada"}),
            valid_from: Some(now + Duration::hours(1)),
            valid_until: Some(now + Duration::hours(2)),
        },
    )
    .expect("a future validity interval must be accepted");
    validate_managed_dataset(
        &configuration,
        &PutCredentialDatasetRequest {
            claims: json!({"given_name":"Ada"}),
            valid_from: None,
            valid_until: Some(now + Duration::hours(1)),
        },
    )
    .expect("a future expiry without an explicit start must be accepted");
}

#[test]
fn managed_dataset_rejects_claim_names_and_json_shape_at_every_boundary() {
    let sd_jwt = dataset_configuration(CredentialFormat::SdJwtVc);
    let mut empty_name = serde_json::Map::new();
    empty_name.insert(String::new(), json!("empty-name"));
    let mut oversized_name = serde_json::Map::new();
    oversized_name.insert("x".repeat(129), json!("too-long-name"));
    for claims in [Value::Object(empty_name), Value::Object(oversized_name)] {
        assert!(validate_managed_dataset(&sd_jwt, &dataset_request(claims)).is_err());
    }

    let oversized_key = "k".repeat(256);
    let mut oversized_key_claims = serde_json::Map::new();
    oversized_key_claims.insert(oversized_key, json!("too-long-key"));
    assert!(
        validate_managed_dataset(
            &sd_jwt,
            &dataset_request(Value::Object(oversized_key_claims)),
        )
        .is_err()
    );

    let too_many_nodes = Value::Array((0..513).map(|_| json!(true)).collect());
    assert!(
        validate_managed_dataset(&sd_jwt, &dataset_request(json!({"values": too_many_nodes})),)
            .is_err()
    );

    let nested_array = json!({"values": ["one", 2, false, null]});
    validate_managed_dataset(&sd_jwt, &dataset_request(nested_array))
        .expect("bounded arrays and scalar values are accepted");
}

#[test]
fn managed_mdoc_dataset_rejects_namespace_and_inner_claim_name_bounds() {
    let configuration = dataset_configuration(CredentialFormat::MsoMdoc);
    let oversized_namespace = "n".repeat(256);
    let mut oversized_namespace_claims = serde_json::Map::new();
    oversized_namespace_claims.insert(oversized_namespace, json!({"family_name": "Lovelace"}));
    assert!(
        validate_managed_dataset(
            &configuration,
            &dataset_request(Value::Object(oversized_namespace_claims)),
        )
        .is_err()
    );

    let oversized_claim_name = "c".repeat(129);
    let mut oversized_inner = serde_json::Map::new();
    oversized_inner.insert(oversized_claim_name, json!("Lovelace"));
    let mut oversized_inner_claims = serde_json::Map::new();
    oversized_inner_claims.insert(
        "org.iso.18013.5.1".to_owned(),
        Value::Object(oversized_inner),
    );
    assert!(
        validate_managed_dataset(
            &configuration,
            &dataset_request(Value::Object(oversized_inner_claims)),
        )
        .is_err()
    );
    assert!(
        validate_managed_dataset(
            &configuration,
            &dataset_request(json!({"org.iso.18013.5.1": {"": "Lovelace"}})),
        )
        .is_err()
    );
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
