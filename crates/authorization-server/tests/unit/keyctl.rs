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
async fn typed_operator_key_lifecycle_returns_content_revisions() {
    let directory = std::env::temp_dir().join(format!("nazoauth-keyctl-{}", uuid::Uuid::now_v7()));
    let config = ConfigSource::from_owned_pairs_for_test([(
        "JWK_KEYS_DIR".to_owned(),
        directory.display().to_string(),
    )]);
    let settings = Settings::from_config(&config).unwrap();
    let key_settings = settings.key_settings();
    nazo_key_management::KeyManager::load_or_create(key_settings)
        .await
        .unwrap();

    let initial = list_with_settings(&settings).await.unwrap();
    assert_eq!(initial.len(), 64);
    assert_eq!(validate_with_settings(&settings).await.unwrap(), initial);

    let options = parse_generate_local("ES256", &["credential".to_owned()]).unwrap();
    let (kid, generated) = generate_local_with_settings(&settings, options)
        .await
        .unwrap();
    assert!(!kid.is_empty());
    assert_ne!(generated, initial);
    assert_eq!(validate_with_settings(&settings).await.unwrap(), generated);

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
    let external = register_external_with_settings(
        &settings,
        "external",
        jsonwebtoken::Algorithm::RS256,
        "kms://key/1",
        public_jwk,
    )
    .await
    .unwrap();
    assert_ne!(external, generated);
    assert_eq!(validate_with_settings(&settings).await.unwrap(), external);

    tokio::fs::remove_dir_all(directory).await.unwrap();
}
