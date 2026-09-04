use super::*;

fn key_task_config(
    entries: impl IntoIterator<Item = (&'static str, &'static str)>,
) -> ConfigSource {
    ConfigSource::from_owned_pairs_for_test(
        std::iter::once(("JWK_KEYS_DIR", "runtime/nazoauth-keyctl-config"))
            .chain(entries)
            .map(|(key, value)| (key.to_owned(), value.to_owned())),
    )
}

#[test]
fn key_task_config_closes_the_openid4vc_certificate_contract() {
    let (_, paths) = key_task_config_from(&key_task_config([])).unwrap();
    assert!(paths.is_none());

    let (_, paths) = key_task_config_from(&key_task_config([
        (
            "OPENID4VC_SIGNING_CERTIFICATE_CHAIN_FILE",
            "runtime/openid4vc-chain.pem",
        ),
        (
            "OPENID4VC_TRUST_ANCHORS_FILE",
            "runtime/openid4vc-anchors.pem",
        ),
        ("PUBLIC_BASE_URL", "https://auth.example"),
    ]))
    .unwrap();
    let paths = paths.unwrap();
    assert_eq!(paths.chain, PathBuf::from("runtime/openid4vc-chain.pem"));
    assert_eq!(
        paths.anchors,
        PathBuf::from("runtime/openid4vc-anchors.pem")
    );
    assert_eq!(paths.hostname, "auth.example");

    for entries in [
        vec![(
            "OPENID4VC_SIGNING_CERTIFICATE_CHAIN_FILE",
            "runtime/openid4vc-chain.pem",
        )],
        vec![
            (
                "OPENID4VC_SIGNING_CERTIFICATE_CHAIN_FILE",
                "runtime/openid4vc-chain.pem",
            ),
            (
                "OPENID4VC_TRUST_ANCHORS_FILE",
                "runtime/openid4vc-anchors.pem",
            ),
            ("PUBLIC_BASE_URL", "http://auth.example"),
        ],
        vec![
            (
                "OPENID4VC_SIGNING_CERTIFICATE_CHAIN_FILE",
                "runtime/openid4vc-chain.pem",
            ),
            (
                "OPENID4VC_TRUST_ANCHORS_FILE",
                "runtime/openid4vc-anchors.pem",
            ),
            ("ISSUER", "https://127.0.0.1"),
        ],
        vec![
            (
                "OPENID4VC_SIGNING_CERTIFICATE_CHAIN_FILE",
                "runtime/openid4vc-chain.pem",
            ),
            (
                "OPENID4VC_TRUST_ANCHORS_FILE",
                "runtime/openid4vc-anchors.pem",
            ),
            ("PUBLIC_BASE_URL", "not-an-absolute-url"),
        ],
    ] {
        assert!(key_task_config_from(&key_task_config(entries)).is_err());
    }
}

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

    let register =
        operator_register_external("external", "none", "kms://key/1", b"must-not-be-parsed")
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

    let public_jwk = serde_json::json!({
        "kty":"OKP", "crv":"Ed25519", "kid":"external", "alg":"EdDSA", "use":"sig",
        "x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    });
    nazo_key_management::KeyManager::register_external(
        &key_settings,
        nazo_key_management::ExternalKeyRegistration {
            kid: "external".to_owned(),
            algorithm: jsonwebtoken::Algorithm::EdDSA,
            key_ref: "kms://key/1".to_owned(),
            public_jwk,
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
async fn credential_key_bootstrap_creates_a_matching_idempotent_certificate_chain() {
    let directory = std::env::temp_dir().join(format!(
        "nazoauth-keyctl-certificate-{}",
        uuid::Uuid::now_v7()
    ));
    let certificate = directory.join("openid4vc-certificate-bundle.pem");
    let anchors = certificate.clone();
    let revocation_snapshot = directory.join("revocation-snapshot.json");
    let config = ConfigSource::from_owned_pairs_for_test([
        ("JWK_KEYS_DIR".to_owned(), directory.display().to_string()),
        (
            "OPENID4VC_SIGNING_CERTIFICATE_CHAIN_FILE".to_owned(),
            certificate.display().to_string(),
        ),
        (
            "OPENID4VC_TRUST_ANCHORS_FILE".to_owned(),
            anchors.display().to_string(),
        ),
        (
            "PUBLIC_BASE_URL".to_owned(),
            "https://auth.example".to_owned(),
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
    let paths = Openid4vcCertificatePaths {
        chain: certificate.clone(),
        anchors: anchors.clone(),
        revocation_snapshot: Some(revocation_snapshot.clone()),
        hostname: "auth.example".to_owned(),
        mdoc_profile: None,
    };
    let (kid, first_revision) =
        generate_local_with_key_settings(&key_settings, Some(&paths), options)
            .await
            .unwrap();
    let first_certificate = tokio::fs::read(&certificate).await.unwrap();
    let certificates = CertificateDer::pem_slice_iter(&first_certificate)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(certificates.len(), 2);
    assert_ne!(certificates[0], certificates[1]);
    let (_, leaf) = x509_parser::parse_x509_certificate(&certificates[0]).unwrap();
    let (_, ca) = x509_parser::parse_x509_certificate(&certificates[1]).unwrap();
    assert!(!leaf.is_ca());
    assert!(ca.is_ca());
    let subject_alt_names = leaf.subject_alternative_name().unwrap().unwrap();
    assert_eq!(subject_alt_names.value.general_names.len(), 1);
    assert!(matches!(
        &subject_alt_names.value.general_names[0],
        x509_parser::extensions::GeneralName::DNSName("auth.example")
    ));
    assert!(ca.verify_signature(Some(ca.public_key())).is_ok());
    assert!(leaf.verify_signature(Some(ca.public_key())).is_ok());

    let options = parse_generate_local(
        "ES256",
        &["credential".to_owned(), "presentation_request".to_owned()],
    )
    .unwrap();
    let (same_kid, same_revision) =
        generate_local_with_key_settings(&key_settings, Some(&paths), options)
            .await
            .unwrap();
    assert_eq!(same_kid, kid);
    assert_eq!(same_revision, first_revision);
    assert_eq!(
        tokio::fs::read(&certificate).await.unwrap(),
        first_certificate
    );
    assert_eq!(tokio::fs::read(&anchors).await.unwrap(), first_certificate);
    let snapshot = nazo_digital_credentials::CertificateRevocationSnapshot::from_json(
        &tokio::fs::read(&revocation_snapshot).await.unwrap(),
    )
    .unwrap();
    snapshot.validate_freshness_at(chrono::Utc::now()).unwrap();
    assert!(snapshot.entries.is_empty());

    tokio::fs::write(&certificate, b"not-a-certificate")
        .await
        .unwrap();
    let options = parse_generate_local(
        "ES256",
        &["credential".to_owned(), "presentation_request".to_owned()],
    )
    .unwrap();
    let (repaired_kid, repaired_revision) =
        generate_local_with_key_settings(&key_settings, Some(&paths), options)
            .await
            .unwrap();
    assert_eq!(repaired_kid, kid);
    assert_eq!(repaired_revision, first_revision);
    assert_ne!(
        tokio::fs::read(&certificate).await.unwrap(),
        b"not-a-certificate"
    );
    assert_eq!(
        tokio::fs::read(&anchors).await.unwrap(),
        tokio::fs::read(&certificate).await.unwrap()
    );

    tokio::fs::remove_dir_all(directory).await.unwrap();
}

#[tokio::test]
async fn mdoc_certificate_profile_persists_a_matching_iaca_key_and_serves_snapshot_backed_crls() {
    let directory = std::env::temp_dir().join(format!(
        "nazoauth-mdoc-certificate-{}",
        uuid::Uuid::now_v7()
    ));
    let certificate = directory.join("certificate-bundle.pem");
    let revocation_snapshot = directory.join("revocation-snapshot.json");
    let profile = MdocCertificateProfile {
        issuing_country: "US".to_owned(),
        issuer_contact_uri: "https://auth.example".to_owned(),
        crl_distribution_uri: "https://auth.example/.well-known/mdoc".to_owned(),
    };
    let paths = Openid4vcCertificatePaths {
        chain: certificate.clone(),
        anchors: certificate.clone(),
        revocation_snapshot: Some(revocation_snapshot.clone()),
        hostname: "auth.example".to_owned(),
        mdoc_profile: Some(profile),
    };
    let signing_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let bundle = build_openid4vc_certificate_bundle(
        &signing_key,
        "auth.example",
        paths.mdoc_profile.as_ref(),
    )
    .unwrap();
    activate_openid4vc_certificate_bundle(&paths, &bundle)
        .await
        .unwrap();
    initialize_mdoc_revocation_snapshot(
        &paths,
        bundle.mdoc_material.as_ref().expect("mdoc material"),
    )
    .await
    .unwrap();

    assert!(
        existing_openid4vc_bundle_matches(&paths, &signing_key)
            .await
            .unwrap()
    );
    let chain = tokio::fs::read(&certificate).await.unwrap();
    let certificates = CertificateDer::pem_slice_iter(&chain)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let (_, leaf) = x509_parser::parse_x509_certificate(&certificates[0]).unwrap();
    let (_, ca) = x509_parser::parse_x509_certificate(&certificates[1]).unwrap();
    assert!(mdoc_certificate_profile_matches(
        &leaf,
        &ca,
        paths.mdoc_profile.as_ref().unwrap()
    ));
    let key_path = iaca_private_key_path(&certificate, certificates[1].as_ref()).unwrap();
    assert!(tokio::fs::try_exists(&key_path).await.unwrap());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        assert_eq!(
            std::fs::metadata(&key_path).unwrap().permissions().mode() & 0o077,
            0
        );
        assert_eq!(
            std::fs::metadata(key_path.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o077,
            0
        );
    }

    let source = MdocCrlSource {
        certificate_bundle: certificate.clone(),
        revocation_snapshot: revocation_snapshot.clone(),
        issuer_contact_uri: "https://auth.example".to_owned(),
    };
    let issuer_id = sha256_hex(certificates[1].as_ref());
    let crl = signed_mdoc_crl(&source, &issuer_id)
        .await
        .unwrap()
        .expect("mdoc CRL");
    let (_, parsed_crl) = x509_parser::parse_x509_crl(&crl).unwrap();
    assert!(parsed_crl.verify_signature(ca.public_key()).is_ok());
    assert_eq!(parsed_crl.iter_revoked_certificates().count(), 0);
    let response = crate::http::well_known::mdoc_crl(
        Some(actix_web::web::Data::new(source.clone())),
        issuer_id.clone().into(),
    )
    .await;
    assert_eq!(response.status(), actix_web::http::StatusCode::OK);
    assert_eq!(
        response.headers().get("content-type").unwrap(),
        "application/pkix-crl"
    );
    assert_eq!(
        crate::http::well_known::mdoc_crl(None, issuer_id.clone().into())
            .await
            .status(),
        actix_web::http::StatusCode::NOT_FOUND
    );

    let mut snapshot = nazo_digital_credentials::CertificateRevocationSnapshot::from_json(
        &tokio::fs::read(&revocation_snapshot).await.unwrap(),
    )
    .unwrap();
    assert_eq!(
        parsed_crl.last_update().timestamp(),
        snapshot.this_update.timestamp()
    );
    assert_eq!(
        parsed_crl.next_update().unwrap().timestamp(),
        snapshot.next_update.timestamp()
    );
    snapshot.entries[0].status = nazo_digital_credentials::CertificateRevocationStatus::Revoked;
    snapshot.this_update = chrono::Utc::now();
    tokio::fs::write(&revocation_snapshot, serde_json::to_vec(&snapshot).unwrap())
        .await
        .unwrap();
    let revoked_crl = signed_mdoc_crl(&source, &issuer_id)
        .await
        .unwrap()
        .expect("revoked mdoc CRL");
    let (_, parsed_revoked_crl) = x509_parser::parse_x509_crl(&revoked_crl).unwrap();
    assert!(parsed_revoked_crl.verify_signature(ca.public_key()).is_ok());
    let revoked = parsed_revoked_crl
        .iter_revoked_certificates()
        .collect::<Vec<_>>();
    assert_eq!(revoked.len(), 1);
    assert_eq!(revoked[0].raw_serial(), leaf.raw_serial());

    assert!(
        existing_openid4vc_bundle_matches(&paths, &signing_key)
            .await
            .unwrap()
    );
    initialize_mdoc_revocation_snapshot(&paths, bundle.mdoc_material.as_ref().unwrap())
        .await
        .unwrap();
    let preserved = nazo_digital_credentials::CertificateRevocationSnapshot::from_json(
        &tokio::fs::read(&revocation_snapshot).await.unwrap(),
    )
    .unwrap();
    assert_eq!(
        preserved.entries[0].status,
        nazo_digital_credentials::CertificateRevocationStatus::Revoked
    );

    let rotated = build_openid4vc_certificate_bundle(
        &signing_key,
        "auth.example",
        paths.mdoc_profile.as_ref(),
    )
    .unwrap();
    activate_openid4vc_certificate_bundle(&paths, &rotated)
        .await
        .unwrap();
    let rotated_material = rotated.mdoc_material.as_ref().unwrap();
    initialize_mdoc_revocation_snapshot(&paths, rotated_material)
        .await
        .unwrap();
    let old_crl = signed_mdoc_crl(&source, &issuer_id).await.unwrap().unwrap();
    let (_, old_crl) = x509_parser::parse_x509_crl(&old_crl).unwrap();
    assert!(old_crl.verify_signature(ca.public_key()).is_ok());
    assert_eq!(
        old_crl
            .iter_revoked_certificates()
            .next()
            .unwrap()
            .raw_serial(),
        leaf.raw_serial()
    );
    let new_crl = signed_mdoc_crl(&source, &sha256_hex(&rotated_material.ca_der))
        .await
        .unwrap()
        .unwrap();
    let (_, new_crl) = x509_parser::parse_x509_crl(&new_crl).unwrap();
    let (_, new_ca) = x509_parser::parse_x509_certificate(&rotated_material.ca_der).unwrap();
    assert!(new_crl.verify_signature(new_ca.public_key()).is_ok());
    assert_eq!(new_crl.iter_revoked_certificates().count(), 0);
    assert!(
        signed_mdoc_crl(&source, "../other-tenant")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        signed_mdoc_crl(&source, &"0".repeat(64))
            .await
            .unwrap()
            .is_none()
    );

    let fresh_next_update = snapshot.next_update;
    snapshot.this_update = chrono::Utc::now() - chrono::Duration::hours(2);
    snapshot.next_update = chrono::Utc::now() - chrono::Duration::hours(1);
    tokio::fs::write(&revocation_snapshot, serde_json::to_vec(&snapshot).unwrap())
        .await
        .unwrap();
    assert!(signed_mdoc_crl(&source, &issuer_id).await.is_err());
    snapshot.next_update = fresh_next_update;
    snapshot.entries.clear();
    tokio::fs::write(&revocation_snapshot, serde_json::to_vec(&snapshot).unwrap())
        .await
        .unwrap();
    assert!(signed_mdoc_crl(&source, &issuer_id).await.is_err());
    assert_eq!(
        crate::http::well_known::mdoc_crl(
            Some(actix_web::web::Data::new(source)),
            issuer_id.clone().into()
        )
        .await
        .status(),
        actix_web::http::StatusCode::SERVICE_UNAVAILABLE
    );

    tokio::fs::write(
        iaca_private_key_path(&certificate, &rotated_material.ca_der).unwrap(),
        KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
            .unwrap()
            .serialize_pem(),
    )
    .await
    .unwrap();
    assert!(
        !existing_openid4vc_bundle_matches(&paths, &signing_key)
            .await
            .unwrap()
    );

    tokio::fs::remove_dir_all(directory).await.unwrap();
}

#[tokio::test]
async fn openid4vc_certificate_paths_and_existing_bundle_fail_closed() {
    let directory = std::env::temp_dir().join(format!(
        "nazoauth-keyctl-certificate-boundaries-{}",
        uuid::Uuid::now_v7()
    ));
    tokio::fs::create_dir(&directory).await.unwrap();
    let key_settings = key_settings_from_config(&ConfigSource::from_owned_pairs_for_test([(
        "JWK_KEYS_DIR".to_owned(),
        directory.join("keys").display().to_string(),
    )]))
    .unwrap();
    let certificate = directory.join("bundle.pem");
    let paths = Openid4vcCertificatePaths {
        chain: certificate.clone(),
        anchors: certificate.clone(),
        revocation_snapshot: None,
        hostname: "auth.example".to_owned(),
        mdoc_profile: None,
    };
    let options = parse_generate_local("ES256", &["credential".to_owned()]).unwrap();
    assert!(
        generate_local_with_key_settings(&key_settings, Some(&paths), options)
            .await
            .is_err()
    );

    let private_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    assert!(
        !existing_openid4vc_bundle_matches(&paths, &private_key)
            .await
            .unwrap()
    );

    let split_paths = Openid4vcCertificatePaths {
        chain: directory.join("chain.pem"),
        anchors: directory.join("anchors.pem"),
        revocation_snapshot: None,
        hostname: "auth.example".to_owned(),
        mdoc_profile: None,
    };
    assert!(
        existing_openid4vc_bundle_matches(&split_paths, &private_key)
            .await
            .is_err()
    );
    assert!(
        activate_openid4vc_certificate_bundle(
            &split_paths,
            &Openid4vcCertificateBundle {
                contents: b"bundle".to_vec(),
                mdoc_material: None,
            },
        )
        .await
        .is_err()
    );

    tokio::fs::write(&certificate, b"not-a-certificate")
        .await
        .unwrap();
    assert!(
        !existing_openid4vc_bundle_matches(&paths, &private_key)
            .await
            .unwrap()
    );
    tokio::fs::write(
        &certificate,
        b"-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----\n",
    )
    .await
    .unwrap();
    assert!(
        !existing_openid4vc_bundle_matches(&paths, &private_key)
            .await
            .unwrap()
    );

    let bundle = build_openid4vc_certificate_bundle(&private_key, "auth.example", None).unwrap();
    tokio::fs::write(&certificate, &bundle.contents)
        .await
        .unwrap();
    let different_private_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    assert!(
        !existing_openid4vc_bundle_matches(&paths, &different_private_key)
            .await
            .unwrap()
    );
    let wrong_hostname = Openid4vcCertificatePaths {
        chain: certificate.clone(),
        anchors: certificate.clone(),
        revocation_snapshot: None,
        hostname: "other.example".to_owned(),
        mdoc_profile: None,
    };
    assert!(
        !existing_openid4vc_bundle_matches(&wrong_hostname, &private_key)
            .await
            .unwrap()
    );

    tokio::fs::remove_file(&certificate).await.unwrap();
    tokio::fs::create_dir(&certificate).await.unwrap();
    assert!(
        existing_openid4vc_bundle_matches(&paths, &private_key)
            .await
            .is_err()
    );
    assert!(
        activate_openid4vc_certificate_bundle(
            &paths,
            &Openid4vcCertificateBundle {
                contents: b"bundle".to_vec(),
                mdoc_material: None,
            },
        )
        .await
        .is_err()
    );

    tokio::fs::remove_dir(&certificate).await.unwrap();
    activate_openid4vc_certificate_bundle(
        &paths,
        &Openid4vcCertificateBundle {
            contents: b"atomic-bundle".to_vec(),
            mdoc_material: None,
        },
    )
    .await
    .unwrap();
    assert_eq!(
        tokio::fs::read(&certificate).await.unwrap(),
        b"atomic-bundle"
    );

    tokio::fs::remove_dir_all(directory).await.unwrap();
}
