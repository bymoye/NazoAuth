use super::*;

async fn signed_access_token(
    issuer: &ServerCredentialIssuerOperations,
    subject_id: Uuid,
    dpop_jkt: Option<&str>,
) -> String {
    signed_access_token_with_binding(issuer, subject_id, dpop_jkt, None, Value::Array(Vec::new()))
        .await
}

async fn signed_mtls_access_token(
    issuer: &ServerCredentialIssuerOperations,
    subject_id: Uuid,
    configuration_id: &str,
    mtls_x5t_s256: &str,
) -> String {
    signed_access_token_with_binding(
        issuer,
        subject_id,
        None,
        Some(mtls_x5t_s256),
        json!([openid4vci_authorization_detail(
            &issuer.issuer,
            configuration_id
        )]),
    )
    .await
}

async fn signed_access_token_with_binding(
    issuer: &ServerCredentialIssuerOperations,
    subject_id: Uuid,
    dpop_jkt: Option<&str>,
    mtls_x5t_s256: Option<&str>,
    authorization_details: Value,
) -> String {
    let subject = subject_id.to_string();
    issuer
        .token_service
        .sign_access_token(nazo_auth::AccessTokenSignInput {
            issuer: &issuer.issuer,
            tenant_id: issuer.tenant_id,
            subject: &subject,
            user_id: Some(subject_id),
            subject_type: "user",
            client_id: "unit-client",
            audiences: std::slice::from_ref(&issuer.issuer),
            scopes: &[],
            authorization_details: &authorization_details,
            userinfo_claims: &[],
            userinfo_claim_requests: &[],
            ttl_seconds: 300,
            dpop_jkt,
            mtls_x5t_s256,
            actor: None,
        })
        .await
        .expect("test key manager should sign the access token")
        .token
}

#[tokio::test]
async fn dpop_nonce_generation_fails_closed_when_nonce_state_is_unavailable() {
    let issuer = operations(true).await;
    let error = issuer
        .next_dpop_nonce(&CredentialAccess {
            token_id: Uuid::now_v7(),
            tenant_id: issuer.tenant_id,
            subject_id: Uuid::now_v7(),
            client_id: "unit-client".to_owned(),
            configuration_ids: vec!["unit-config".to_owned()],
            credential_identifiers: Vec::new(),
            dpop_jkt: Some("unit-dpop-thumbprint".to_owned()),
            expires_at: chrono::Utc::now() + chrono::Duration::minutes(5),
        })
        .await
        .expect_err("unavailable DPoP nonce state must fail closed");
    assert_error(
        error,
        503,
        "server_error",
        "DPoP nonce issuance is unavailable.",
    );
}

#[tokio::test]
async fn pre_authorized_token_rejects_invalid_dpop_before_consuming_offer_state() {
    // The fixture uses deliberately unavailable PostgreSQL/Valkey endpoints.  A malformed
    // sender proof must still be rejected at the protocol boundary before either single-use
    // store can be touched; otherwise a retry with a valid proof could observe consumed state.
    let issuer = operations(true).await;
    let error = issuer
        .pre_authorized_token(PreAuthorizedTokenRequest {
            pre_authorized_code: "does-not-exist".to_owned(),
            tx_code: None,
            client_id: None,
            dpop_proof: Some("malformed-dpop-proof".to_owned()),
            client_attestation: None,
            client_attestation_pop: None,
            request_url: "https://issuer.example/token".to_owned(),
        })
        .await
        .expect_err("invalid DPoP must fail before offer state is consumed");

    assert_error(error, 400, "invalid_dpop_proof", "DPoP proof is invalid.");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires NAZO_TEST_DATABASE_URL/DATABASE_URL and VALKEY_URL; run explicitly with --ignored"]
async fn live_access_enforces_dpop_binding_and_validates_presented_proof() {
    let Some(fixture) = LiveEndpointFixture::new("unit-live-dpop-access", false).await else {
        return;
    };

    let opaque_subject_token = fixture
        .issuer
        .token_service
        .sign_access_token(nazo_auth::AccessTokenSignInput {
            issuer: &fixture.issuer.issuer,
            tenant_id: fixture.issuer.tenant_id,
            subject: "opaque-subject",
            user_id: None,
            subject_type: "user",
            client_id: "unit-client",
            audiences: std::slice::from_ref(&fixture.issuer.issuer),
            scopes: &[],
            authorization_details: &Value::Array(Vec::new()),
            userinfo_claims: &[],
            userinfo_claim_requests: &[],
            ttl_seconds: 300,
            dpop_jkt: None,
            mtls_x5t_s256: None,
            actor: None,
        })
        .await
        .expect("test key manager should sign the opaque-subject token")
        .token;
    let error = fixture
        .issuer
        .access(&CredentialRequestContext {
            bearer_token: opaque_subject_token,
            ..request_context()
        })
        .await
        .expect_err("an opaque subject without persisted token state must be rejected");
    assert_error(
        error,
        401,
        "invalid_token",
        "Access token subject is invalid.",
    );

    let bound_token = signed_access_token(
        &fixture.issuer,
        fixture.subject_id,
        Some("unit-dpop-thumbprint"),
    )
    .await;
    let error = fixture
        .issuer
        .access(&CredentialRequestContext {
            bearer_token: bound_token.clone(),
            ..request_context()
        })
        .await
        .expect_err("a DPoP-bound token must not be presented as bearer");
    assert_error(
        error,
        401,
        "invalid_token",
        "A DPoP-bound access token requires the DPoP authorization scheme and proof.",
    );

    let error = fixture
        .issuer
        .access(&CredentialRequestContext {
            bearer_token: bound_token,
            access_token_scheme: AccessTokenScheme::Dpop,
            dpop_proof: Some("not-a-dpop-proof".to_owned()),
            ..request_context()
        })
        .await
        .expect_err("a malformed DPoP proof must be rejected");
    assert_error(error, 401, "invalid_dpop_proof", "DPoP proof is invalid.");

    let unbound_token = signed_access_token(&fixture.issuer, fixture.subject_id, None).await;
    let error = fixture
        .issuer
        .access(&CredentialRequestContext {
            bearer_token: unbound_token,
            access_token_scheme: AccessTokenScheme::Dpop,
            dpop_proof: Some("not-a-dpop-proof".to_owned()),
            ..request_context()
        })
        .await
        .expect_err("an unbound token must not be promoted to DPoP by presentation");
    assert_error(
        error,
        401,
        "invalid_dpop_proof",
        "An unbound access token cannot be presented with DPoP.",
    );

    let mtls_token = signed_mtls_access_token(
        &fixture.issuer,
        fixture.subject_id,
        "unit-live-dpop-access",
        "unit-mtls",
    )
    .await;
    let error = fixture
        .issuer
        .access(&CredentialRequestContext {
            bearer_token: mtls_token.clone(),
            ..request_context()
        })
        .await
        .expect_err("an mTLS-bound token must not be presented as bearer without a certificate");
    assert_error(
        error,
        401,
        "invalid_token",
        "A mTLS-bound access token requires the matching client certificate.",
    );

    let error = fixture
        .issuer
        .access(&CredentialRequestContext {
            bearer_token: mtls_token.clone(),
            mtls_x5t_s256: Some("different-mtls".to_owned()),
            ..request_context()
        })
        .await
        .expect_err("an mTLS-bound token must reject a different certificate");
    assert_error(
        error,
        401,
        "invalid_token",
        "The mTLS client certificate does not match the access token.",
    );

    fixture
        .issuer
        .access(&CredentialRequestContext {
            bearer_token: mtls_token,
            mtls_x5t_s256: Some("unit-mtls".to_owned()),
            ..request_context()
        })
        .await
        .expect("a matching mTLS certificate should authorize the credential token");
    fixture.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires NAZO_TEST_DATABASE_URL/DATABASE_URL and VALKEY_URL; run explicitly with --ignored"]
async fn live_offer_enforces_subject_dataset_lifetime_and_transaction_code_policy() {
    let Some(fixture) = LiveEndpointFixture::new("unit-live-offer-policy", false).await else {
        return;
    };
    let request = |subject_id, grant_types: Vec<String>, tx_code: Option<&str>, expires_in| {
        CreateCredentialOfferRequest {
            subject_id,
            credential_configuration_ids: vec!["unit-live-offer-policy".to_owned()],
            grant_types,
            tx_code: tx_code.map(str::to_owned),
            expires_in,
        }
    };
    let pre_authorized = vec![nazo_openid4vci::PRE_AUTHORIZED_CODE_GRANT.to_owned()];

    let error = fixture
        .issuer
        .create_offer(request(Uuid::now_v7(), pre_authorized.clone(), None, 300))
        .await
        .expect_err("an inactive or unknown subject must be rejected");
    assert_error(
        error,
        400,
        "invalid_request",
        "Credential subject is not active.",
    );

    let error = fixture
        .issuer
        .create_offer(request(fixture.admin_id, pre_authorized.clone(), None, 300))
        .await
        .expect_err("an active subject without a managed dataset must be rejected");
    assert_error(
        error,
        400,
        "invalid_request",
        "Requested credential data is unavailable for the subject.",
    );

    for expires_in in [29, 601] {
        let error = fixture
            .issuer
            .create_offer(request(
                fixture.subject_id,
                pre_authorized.clone(),
                None,
                expires_in,
            ))
            .await
            .expect_err("out-of-policy offer lifetime must be rejected");
        assert_error(
            error,
            400,
            "invalid_request",
            "Credential offer lifetime must be between 30 and 600 seconds.",
        );
    }

    for tx_code in ["123", "123 4", "123456789012345678901234567890123"] {
        let error = fixture
            .issuer
            .create_offer(request(
                fixture.subject_id,
                pre_authorized.clone(),
                Some(tx_code),
                300,
            ))
            .await
            .expect_err("out-of-policy transaction code must be rejected");
        assert_error(
            error,
            400,
            "invalid_request",
            "Transaction code is invalid.",
        );
    }

    for (tx_code, expected_mode) in [("1234", "numeric"), ("a1b2", "text")] {
        let offer = fixture
            .issuer
            .create_offer(request(
                fixture.subject_id,
                vec![
                    "authorization_code".to_owned(),
                    nazo_openid4vci::PRE_AUTHORIZED_CODE_GRANT.to_owned(),
                ],
                Some(tx_code),
                300,
            ))
            .await
            .expect("valid mixed-grant offer must persist");
        let grants = &offer
            .credential_offer
            .grants
            .as_ref()
            .expect("valid offer grants")
            .0;
        assert!(grants.contains_key("authorization_code"));
        let pre_authorized_grant = grants
            .get(nazo_openid4vci::PRE_AUTHORIZED_CODE_GRANT)
            .expect("pre-authorized grant");
        assert_eq!(pre_authorized_grant["tx_code"]["input_mode"], expected_mode);
        assert_eq!(
            pre_authorized_grant["tx_code"]["length"].as_u64(),
            Some(tx_code.len() as u64)
        );

        let retrieved = fixture
            .issuer
            .offer(&offer.offer_id.to_string())
            .await
            .expect("persisted offer must be retrievable");
        assert_eq!(
            retrieved.credential_configuration_ids,
            vec!["unit-live-offer-policy".to_owned()]
        );
    }

    let error = fixture
        .issuer
        .offer(&Uuid::now_v7().to_string())
        .await
        .expect_err("unknown persisted offer must not be disclosed");
    assert_error(
        error,
        404,
        "invalid_request",
        "Credential offer was not found.",
    );
    fixture.cleanup().await;
}
