use super::*;

#[test]
fn parses_the_closed_purpose_scoped_key_operation() {
    let options = parse_generate_local(
        "ES256",
        &["credential".to_owned(), "presentation_request".to_owned()],
    )
    .unwrap();
    assert_eq!(options.alg, jsonwebtoken::Algorithm::ES256);
    assert_eq!(options.purposes.len(), 2);
}

#[test]
fn rejects_empty_duplicate_or_runtime_signing_purposes() {
    assert!(parse_generate_local("ES256", &[]).is_err());
    assert!(
        parse_generate_local("ES256", &["credential".to_owned(), "credential".to_owned()]).is_err()
    );
    assert!(parse_generate_local("ES256", &["access_token".to_owned()]).is_err());
}

#[test]
fn rejects_unsupported_algorithms() {
    assert!(parse_generate_local("none", &["credential".to_owned()]).is_err());
}

#[tokio::test]
async fn public_operator_key_commands_reject_unsupported_algorithms_before_loading_secrets() {
    let generate = operator_generate_local("none", &["credential".to_owned()])
        .await
        .unwrap_err();
    assert_eq!(generate.to_string(), "unsupported signing alg none");

    let register = operator_register_external(
        "external",
        "none",
        "kms://key/1",
        PathBuf::from("must-not-be-read.json"),
    )
    .await
    .unwrap_err();
    assert_eq!(register.to_string(), "unsupported signing alg none");
}

#[tokio::test]
async fn typed_operator_key_lifecycle_returns_content_revisions() {
    let directory = std::env::temp_dir().join(format!("nazoauth-keyctl-{}", uuid::Uuid::now_v7()));
    let config = ConfigSource::from_owned_pairs_for_test([(
        "JWK_KEYS_DIR".to_owned(),
        directory.display().to_string(),
    )]);
    let key_settings = key_settings_from_config(&config).unwrap();
    nazo_key_management::KeyManager::load_or_create(key_settings.clone())
        .await
        .unwrap();

    let initial = keyset_revision_from(&key_settings).await.unwrap();
    assert_eq!(initial.len(), 64);
    nazo_key_management::KeyManager::validate(&key_settings)
        .await
        .unwrap();

    let options = parse_generate_local("ES256", &["credential".to_owned()]).unwrap();
    let (kid, generated) = generate_local_with_key_settings(&key_settings, None, options)
        .await
        .unwrap();
    assert!(!kid.is_empty());
    assert_ne!(generated, initial);
    nazo_key_management::KeyManager::validate(&key_settings)
        .await
        .unwrap();

    let public_jwk = directory.join("external-public.jwk.json");
    tokio::fs::write(
        &public_jwk,
        serde_json::to_vec(&serde_json::json!({
            "kty":"RSA", "kid":"external", "alg":"RS256", "use":"sig",
            "n":"modulus", "e":"AQAB"
        }))
        .unwrap(),
    )
    .await
    .unwrap();
    nazo_key_management::KeyManager::register_external(
        &key_settings,
        nazo_key_management::ExternalKeyRegistration {
            kid: "external".to_owned(),
            algorithm: jsonwebtoken::Algorithm::RS256,
            key_ref: "kms://key/1".to_owned(),
            public_jwk_file: public_jwk,
        },
    )
    .await
    .unwrap();
    let external = keyset_revision_from(&key_settings).await.unwrap();
    assert_ne!(external, generated);
    nazo_key_management::KeyManager::validate(&key_settings)
        .await
        .unwrap();

    tokio::fs::remove_dir_all(directory).await.unwrap();
}

#[tokio::test]
async fn credential_key_bootstrap_creates_a_matching_idempotent_certificate() {
    let directory = std::env::temp_dir().join(format!(
        "nazoauth-keyctl-certificate-{}",
        uuid::Uuid::now_v7()
    ));
    let certificate = directory.join("openid4vc-signing-chain.pem");
    let config = ConfigSource::from_owned_pairs_for_test([
        ("JWK_KEYS_DIR".to_owned(), directory.display().to_string()),
        (
            "OPENID4VC_SIGNING_CERTIFICATE_CHAIN_FILE".to_owned(),
            certificate.display().to_string(),
        ),
    ]);
    let key_settings = key_settings_from_config(&config).unwrap();
    nazo_key_management::KeyManager::load_or_create(key_settings.clone())
        .await
        .unwrap();

    let options = parse_generate_local(
        "ES256",
        &["credential".to_owned(), "presentation_request".to_owned()],
    )
    .unwrap();
    let (kid, first_revision) =
        generate_local_with_key_settings(&key_settings, Some(&certificate), options)
            .await
            .unwrap();
    let first_certificate = tokio::fs::read(&certificate).await.unwrap();
    assert!(X509::from_pem(&first_certificate).is_ok());

    let options = parse_generate_local(
        "ES256",
        &["credential".to_owned(), "presentation_request".to_owned()],
    )
    .unwrap();
    let (same_kid, same_revision) =
        generate_local_with_key_settings(&key_settings, Some(&certificate), options)
            .await
            .unwrap();
    assert_eq!(same_kid, kid);
    assert_eq!(same_revision, first_revision);
    assert_eq!(
        tokio::fs::read(&certificate).await.unwrap(),
        first_certificate
    );

    tokio::fs::remove_dir_all(directory).await.unwrap();
}
