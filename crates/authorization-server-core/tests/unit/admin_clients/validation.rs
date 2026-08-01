use super::super::sector_identifier_host_for_redirects;
use super::AdminClientError;

#[test]
fn policy_debug_output_redacts_server_secrets() {
    let policy = super::super::AdminClientPolicy {
        tenant: nazo_identity::TenantContext::default_system(),
        pairwise_subject_secret: Some("pairwise-secret".to_owned()),
        client_secret_pepper: "client-secret-pepper".to_owned(),
    };
    let debug = format!("{policy:?}");
    assert!(debug.contains("[REDACTED]"));
    assert!(!debug.contains("pairwise-secret"));
    assert!(!debug.contains("client-secret-pepper"));
}

#[test]
fn sector_identifier_document_requires_every_redirect() {
    let redirect_uris = vec![
        "https://client.example/callback".to_owned(),
        "https://client.example/alternate".to_owned(),
    ];
    let sector_uris = vec![
        "https://client.example/callback".to_owned(),
        "https://client.example/alternate".to_owned(),
    ];
    assert_eq!(
        sector_identifier_host_for_redirects(
            "https://sector.example/client.json",
            &redirect_uris,
            &sector_uris,
        )
        .expect("valid sector document"),
        "sector.example"
    );

    let error = sector_identifier_host_for_redirects(
        "https://sector.example/client.json",
        &[
            "https://client.example/callback".to_owned(),
            "https://other.example/callback".to_owned(),
        ],
        &["https://client.example/callback".to_owned()],
    )
    .expect_err("unlisted redirect must fail");
    assert!(matches!(error, AdminClientError::InvalidRequest(_)));
    assert!(error.to_string().contains("other.example"));
}

#[test]
fn sector_identifier_uri_must_have_a_host() {
    let error = sector_identifier_host_for_redirects(
        "not-a-uri",
        &["https://client.example/callback".to_owned()],
        &["https://client.example/callback".to_owned()],
    )
    .expect_err("sector identifier URI without a host must fail");
    assert_eq!(
        error.to_string(),
        "sector_identifier_uri host 解析失败: InvalidUri"
    );
}
