use chrono::{Duration, Utc};
use diesel::{
    QueryableByName, sql_query,
    sql_types::{BigInt, Binary, Text, Uuid as SqlUuid},
};
use diesel_async::RunQueryDsl;
use nazo_digital_credentials::{CredentialFormat, CredentialQuery, DcqlQuery};
use nazo_openid4vci::{
    AuthorizationCodeGrant, AuthorizationOfferPort, CredentialAccess, CredentialOfferGrants,
    CredentialResponseEncoding, CredentialStoreError, CredentialStorePort, DeferredCredential,
    IssuanceNotification, NonceRecord, NotificationEvent, NotificationHandle,
    PreAuthorizedCodeGrant, StoredCredentialOffer, StoredCredentialResponse,
};
use nazo_openid4vp::{
    AuthorizationRequest, ClientIdPrefix, PresentationResult, PresentationStorePort,
    PresentationTransaction, RequestMethod, ResponseMode,
};
use nazo_postgres::{
    ManagedCredentialDatasetWrite, Openid4vciDatasetRepository, Openid4vciRepository,
    Openid4vpRepository, create_pool, get_conn,
};
use uuid::Uuid;

fn database_url() -> Option<String> {
    let url = std::env::var("NAZO_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .ok();
    if url.is_none() && std::env::var_os("CI").is_some() {
        panic!("CI OpenID4VC repository tests require NAZO_TEST_DATABASE_URL or DATABASE_URL");
    }
    url
}

#[derive(QueryableByName)]
struct CountRow {
    #[diesel(sql_type = BigInt)]
    count: i64,
}

#[derive(QueryableByName)]
struct CiphertextRow {
    #[diesel(sql_type = Binary)]
    claims_ciphertext: Vec<u8>,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn credential_dataset_mutations_require_an_active_admin_and_are_audited_atomically() {
    let Some(database_url) = database_url() else {
        return;
    };
    nazo_postgres::run_pending_migrations(&database_url)
        .await
        .unwrap();
    let pool = create_pool(&database_url, 4).unwrap();
    let tenant_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
    let realm_id = Uuid::parse_str("00000000-0000-0000-0000-000000000002").unwrap();
    let organization_id = Uuid::parse_str("00000000-0000-0000-0000-000000000003").unwrap();
    let admin_id = Uuid::now_v7();
    let user_id = Uuid::now_v7();
    let subject_id = Uuid::now_v7();
    let mut connection = get_conn(&pool).await.unwrap();
    for (id, role, admin_level) in [
        (admin_id, "admin", 1),
        (user_id, "user", 0),
        (subject_id, "user", 0),
    ] {
        sql_query(
            "INSERT INTO users
                (id,tenant_id,realm_id,organization_id,username,email,password_hash,role,admin_level)
             VALUES ($1,$2,$3,$4,$5,$6,'test',$7,$8)",
        )
        .bind::<SqlUuid, _>(id)
        .bind::<SqlUuid, _>(tenant_id)
        .bind::<SqlUuid, _>(realm_id)
        .bind::<SqlUuid, _>(organization_id)
        .bind::<Text, _>(format!("openid4vc-dataset-{id}"))
        .bind::<Text, _>(format!("openid4vc-dataset-{id}@example.test"))
        .bind::<Text, _>(role)
        .bind::<diesel::sql_types::Integer, _>(admin_level)
        .execute(&mut connection)
        .await
        .unwrap();
    }
    drop(connection);

    let repository = Openid4vciDatasetRepository::new(pool.clone(), [0x51; 32]);
    let claims = serde_json::json!({"given_name":"Ada"});
    assert!(
        !repository
            .upsert_managed_dataset(ManagedCredentialDatasetWrite {
                tenant_id,
                actor_user_id: user_id,
                subject_id,
                credential_configuration_id: "pid",
                claims: &claims,
                valid_from: None,
                valid_until: None,
            })
            .await
            .unwrap()
    );
    assert!(
        repository
            .managed_dataset(tenant_id, subject_id, "pid")
            .await
            .unwrap()
            .is_none()
    );

    assert!(
        repository
            .upsert_managed_dataset(ManagedCredentialDatasetWrite {
                tenant_id,
                actor_user_id: admin_id,
                subject_id,
                credential_configuration_id: "pid",
                claims: &claims,
                valid_from: None,
                valid_until: None,
            })
            .await
            .unwrap()
    );
    assert_eq!(
        repository
            .managed_dataset(tenant_id, subject_id, "pid")
            .await
            .unwrap()
            .unwrap()
            .claims,
        claims
    );
    let mut connection = get_conn(&pool).await.unwrap();
    let raw = sql_query(
        "SELECT claims_ciphertext FROM openid4vci_credential_datasets
         WHERE tenant_id = $1 AND subject_id = $2 AND credential_configuration_id = 'pid'",
    )
    .bind::<SqlUuid, _>(tenant_id)
    .bind::<SqlUuid, _>(subject_id)
    .get_result::<CiphertextRow>(&mut connection)
    .await
    .unwrap();
    assert!(
        !raw.claims_ciphertext
            .windows(3)
            .any(|window| window == b"Ada"),
        "issuer-authoritative credential claims must not be stored as plaintext"
    );
    drop(connection);
    let copied_claims = serde_json::json!({"given_name":"Grace"});
    assert!(
        repository
            .upsert_managed_dataset(ManagedCredentialDatasetWrite {
                tenant_id,
                actor_user_id: admin_id,
                subject_id,
                credential_configuration_id: "pid-copy",
                claims: &copied_claims,
                valid_from: None,
                valid_until: None,
            })
            .await
            .unwrap()
    );
    let mut connection = get_conn(&pool).await.unwrap();
    sql_query(
        "UPDATE openid4vci_credential_datasets
         SET claims_ciphertext = $4
         WHERE tenant_id = $1 AND subject_id = $2 AND credential_configuration_id = $3",
    )
    .bind::<SqlUuid, _>(tenant_id)
    .bind::<SqlUuid, _>(subject_id)
    .bind::<Text, _>("pid-copy")
    .bind::<Binary, _>(raw.claims_ciphertext)
    .execute(&mut connection)
    .await
    .unwrap();
    drop(connection);
    assert_eq!(
        repository
            .managed_dataset(tenant_id, subject_id, "pid-copy")
            .await,
        Err(CredentialStoreError::InvalidTransition),
        "ciphertext copied to another dataset identity must fail AAD authentication"
    );
    assert!(
        !repository
            .delete_managed_dataset(tenant_id, user_id, subject_id, "pid")
            .await
            .unwrap()
    );
    assert!(
        repository
            .delete_managed_dataset(tenant_id, admin_id, subject_id, "pid")
            .await
            .unwrap()
    );
    assert!(
        repository
            .delete_managed_dataset(tenant_id, admin_id, subject_id, "pid-copy")
            .await
            .unwrap()
    );

    let mut connection = get_conn(&pool).await.unwrap();
    let events = sql_query(
        "SELECT COUNT(*)::bigint AS count
         FROM openid4vci_credential_dataset_events
         WHERE tenant_id = $1 AND subject_id = $2 AND actor_user_id = $3",
    )
    .bind::<SqlUuid, _>(tenant_id)
    .bind::<SqlUuid, _>(subject_id)
    .bind::<SqlUuid, _>(admin_id)
    .get_result::<CountRow>(&mut connection)
    .await
    .unwrap();
    assert_eq!(
        events.count, 4,
        "each dataset upsert and delete must append an audit event"
    );
    sql_query(
        "DELETE FROM openid4vci_credential_dataset_events
         WHERE tenant_id = $1 AND subject_id = $2",
    )
    .bind::<SqlUuid, _>(tenant_id)
    .bind::<SqlUuid, _>(subject_id)
    .execute(&mut connection)
    .await
    .unwrap();
    sql_query("DELETE FROM users WHERE tenant_id = $1 AND id IN ($2,$3,$4)")
        .bind::<SqlUuid, _>(tenant_id)
        .bind::<SqlUuid, _>(admin_id)
        .bind::<SqlUuid, _>(user_id)
        .bind::<SqlUuid, _>(subject_id)
        .execute(&mut connection)
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn revoking_a_conformance_lease_deletes_its_presentation_transactions() {
    let Some(database_url) = database_url() else {
        return;
    };
    nazo_postgres::run_pending_migrations(&database_url)
        .await
        .unwrap();
    let pool = create_pool(&database_url, 4).unwrap();
    let tenant_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
    let leases = nazo_postgres::ConformanceLeaseRepository::new(pool.clone());
    let lease = leases
        .create(
            tenant_id,
            "openid4vc",
            &"b".repeat(64),
            nazo_postgres::ConformanceLeaseTokenDigests::default(),
            Some(serde_json::json!({"schema": 1})),
            60,
        )
        .await
        .unwrap();
    let transaction_id = Uuid::now_v7();
    let mut connection = get_conn(&pool).await.unwrap();
    sql_query(
        "INSERT INTO openid4vp_transactions \
         (id,tenant_id,client_id_prefix,request_method,response_mode,\
          wallet_authorization_endpoint,state_hash,request,conformance_lease_id,expires_at) \
         VALUES ($1,$2,'redirect_uri','url_query','direct_post',\
                 'https://wallet.example/authorize',$3,$4,$5,CURRENT_TIMESTAMP + INTERVAL '5 minutes')",
    )
    .bind::<SqlUuid, _>(transaction_id)
    .bind::<SqlUuid, _>(tenant_id)
    .bind::<Text, _>("c".repeat(64))
    .bind::<diesel::sql_types::Jsonb, _>(serde_json::json!({"request": "bounded"}))
    .bind::<SqlUuid, _>(lease.id)
    .execute(&mut connection)
    .await
    .unwrap();
    drop(connection);

    leases.revoke(tenant_id, lease.id).await.unwrap();
    let mut connection = get_conn(&pool).await.unwrap();
    let count =
        sql_query("SELECT COUNT(*)::BIGINT AS count FROM openid4vp_transactions WHERE id = $1")
            .bind::<SqlUuid, _>(transaction_id)
            .get_result::<CountRow>(&mut connection)
            .await
            .unwrap();
    assert_eq!(count.count, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn openid4vc_state_is_tenant_bound_and_sensitive_values_are_single_use_and_encrypted_at_rest()
{
    let Some(database_url) = database_url() else {
        return;
    };
    nazo_postgres::run_pending_migrations(&database_url)
        .await
        .unwrap();
    let pool = create_pool(&database_url, 4).unwrap();
    let tenant_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
    let realm_id = Uuid::parse_str("00000000-0000-0000-0000-000000000002").unwrap();
    let organization_id = Uuid::parse_str("00000000-0000-0000-0000-000000000003").unwrap();
    let subject_id = Uuid::now_v7();
    let mut connection = get_conn(&pool).await.unwrap();
    sql_query("INSERT INTO users (id,tenant_id,realm_id,organization_id,username,email,password_hash) VALUES ($1,$2,$3,$4,$5,$6,'test')")
        .bind::<SqlUuid,_>(subject_id)
        .bind::<SqlUuid,_>(tenant_id)
        .bind::<SqlUuid,_>(realm_id)
        .bind::<SqlUuid,_>(organization_id)
        .bind::<Text,_>(format!("openid4vc-{subject_id}"))
        .bind::<Text,_>(format!("openid4vc-{subject_id}@example.test"))
        .execute(&mut connection).await.unwrap();
    drop(connection);

    let now = Utc::now();
    let data_key = [23_u8; 32];
    let issuer = Openid4vciRepository::new(pool.clone(), data_key);
    let issuer_state = format!("issuer-state-{}", Uuid::now_v7());
    let offer = StoredCredentialOffer {
        id: Uuid::now_v7(),
        tenant_id,
        subject_id: Some(subject_id),
        credential_configuration_ids: vec!["pid".to_owned()],
        grants: CredentialOfferGrants::new(
            Some(AuthorizationCodeGrant {
                issuer_state: Some(issuer_state.clone()),
                authorization_server: Some("https://issuer.example".to_owned()),
            }),
            None,
        ),
        expires_at: now + Duration::minutes(5),
    };
    let issuer_state_hash = blake3::hash(issuer_state.as_bytes()).to_hex().to_string();
    issuer
        .insert_offer(&offer, Some(&issuer_state_hash), None, None)
        .await
        .unwrap();
    let loaded_offer = issuer.offer(offer.id, now).await.unwrap().unwrap();
    assert_eq!(loaded_offer.id, offer.id);
    assert_eq!(loaded_offer.tenant_id, offer.tenant_id);
    assert_eq!(loaded_offer.subject_id, offer.subject_id);
    assert_eq!(
        loaded_offer.credential_configuration_ids,
        offer.credential_configuration_ids
    );
    assert_eq!(loaded_offer.grants, offer.grants);
    assert_eq!(
        loaded_offer.expires_at.timestamp_micros(),
        offer.expires_at.timestamp_micros()
    );
    let resolve_at = Utc::now();
    for client_id in ["wallet", "wallet-2"] {
        let authorization = issuer
            .resolve_authorization_offer(&issuer_state_hash, subject_id, client_id, resolve_at)
            .await
            .unwrap()
            .expect("the offer should remain valid for multiple wallet clients");
        assert_eq!(authorization.client_id, client_id);
    }

    let pre_authorized_code = format!("preauth-{}", Uuid::now_v7());
    let pre_authorized_hash = blake3::hash(pre_authorized_code.as_bytes())
        .to_hex()
        .to_string();
    let pre_authorized_offer = StoredCredentialOffer {
        id: Uuid::now_v7(),
        tenant_id,
        subject_id: Some(subject_id),
        credential_configuration_ids: vec!["pid".to_owned()],
        grants: CredentialOfferGrants::new(
            None,
            Some(PreAuthorizedCodeGrant {
                pre_authorized_code,
                tx_code: None,
                authorization_server: Some("https://issuer.example".to_owned()),
            }),
        ),
        expires_at: now + Duration::minutes(5),
    };
    issuer
        .insert_offer(
            &pre_authorized_offer,
            None,
            Some(&pre_authorized_hash),
            None,
        )
        .await
        .unwrap();
    let pre_authorized_consume_at = Utc::now();
    assert!(
        issuer
            .consume_pre_authorized_offer(
                &pre_authorized_hash,
                None,
                "wallet-a",
                pre_authorized_consume_at,
            )
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        issuer
            .consume_pre_authorized_offer(
                &pre_authorized_hash,
                None,
                "wallet-a",
                pre_authorized_consume_at,
            )
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        issuer
            .consume_pre_authorized_offer(
                &pre_authorized_hash,
                None,
                "wallet-b",
                pre_authorized_consume_at,
            )
            .await
            .unwrap()
            .is_none()
    );

    let access = CredentialAccess {
        token_id: Uuid::now_v7(),
        tenant_id,
        subject_id,
        client_id: "wallet".to_owned(),
        configuration_ids: vec!["pid".to_owned()],
        credential_identifiers: Vec::new(),
        dpop_jkt: None,
        expires_at: now + Duration::minutes(5),
    };
    let token_hash = blake3::hash(access.token_id.as_bytes())
        .to_hex()
        .to_string();
    let nonce_hash = blake3::hash(Uuid::now_v7().as_bytes()).to_hex().to_string();
    issuer.upsert_access(&token_hash, &access).await.unwrap();
    issuer
        .issue_nonce(&NonceRecord {
            nonce_hash: nonce_hash.clone(),
            expires_at: now + Duration::minutes(1),
        })
        .await
        .unwrap();
    let nonce_consumed_at = Utc::now();
    assert!(
        issuer
            .consume_nonce(&nonce_hash, nonce_consumed_at)
            .await
            .unwrap()
    );
    assert!(
        !issuer
            .consume_nonce(&nonce_hash, nonce_consumed_at)
            .await
            .unwrap()
    );

    let verifier = Openid4vpRepository::new(pool, tenant_id, data_key);
    let transaction_id = Uuid::now_v7();
    let presentation_state = format!("state-{}", Uuid::now_v7());
    let request = AuthorizationRequest {
        client_id: "redirect_uri:https://verifier.example/response".to_owned(),
        response_type: "vp_token".to_owned(),
        response_mode: "direct_post".to_owned(),
        response_uri: "https://verifier.example/response".to_owned(),
        nonce: "nonce".to_owned(),
        state: presentation_state.clone(),
        dcql_query: DcqlQuery {
            credentials: vec![CredentialQuery {
                id: "pid".to_owned(),
                format: CredentialFormat::SdJwtVc,
                meta: None,
                claims: None,
                claim_sets: None,
                trusted_authorities: None,
                require_cryptographic_holder_binding: Some(true),
            }],
            credential_sets: None,
        },
        client_metadata: None,
        verifier_info: None,
        transaction_data: None,
        wallet_nonce: None,
    };
    let transaction = PresentationTransaction {
        id: transaction_id,
        client_id_prefix: ClientIdPrefix::RedirectUri,
        request_method: RequestMethod::UrlQuery,
        response_mode: ResponseMode::DirectPost,
        wallet_authorization_endpoint: "https://wallet.example/authorize".to_owned(),
        request,
        request_object: None,
        request_uri: None,
        conformance_lease_id: None,
        response_encryption_private_key: Some(vec![7_u8; 32]),
        created_at: now,
        expires_at: now + Duration::minutes(5),
    };
    verifier.create(&transaction).await.unwrap();
    let loaded = verifier
        .request(transaction_id, now)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(loaded.response_encryption_private_key, Some(vec![7_u8; 32]));
    let bound = verifier
        .bind_wallet_nonce(transaction_id, "wallet-nonce", now)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(bound.request.wallet_nonce.as_deref(), Some("wallet-nonce"));
    assert_eq!(
        verifier
            .request(transaction_id, now)
            .await
            .unwrap()
            .unwrap()
            .request
            .wallet_nonce
            .as_deref(),
        Some("wallet-nonce")
    );
    let completed_at = Utc::now();
    let result = PresentationResult {
        transaction_id,
        credentials: Vec::new(),
        completed_at,
    };
    let state_hash = blake3::hash(presentation_state.as_bytes())
        .to_hex()
        .to_string();
    assert!(
        verifier
            .complete(transaction_id, &state_hash, &result, completed_at)
            .await
            .unwrap()
    );
    assert!(
        !verifier
            .complete(transaction_id, &state_hash, &result, completed_at)
            .await
            .unwrap()
    );
    assert_eq!(
        verifier
            .result(transaction_id, now)
            .await
            .unwrap()
            .unwrap()
            .completed,
        Some(result)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recoverable_issuance_leases_commit_responses_and_deferred_credentials_once() {
    let Some(database_url) = database_url() else {
        return;
    };
    nazo_postgres::run_pending_migrations(&database_url)
        .await
        .unwrap();
    let pool = create_pool(&database_url, 4).unwrap();
    let tenant_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
    let realm_id = Uuid::parse_str("00000000-0000-0000-0000-000000000002").unwrap();
    let organization_id = Uuid::parse_str("00000000-0000-0000-0000-000000000003").unwrap();
    let subject_id = Uuid::now_v7();
    let mut connection = get_conn(&pool).await.unwrap();
    sql_query(
        "INSERT INTO users (id,tenant_id,realm_id,organization_id,username,email,password_hash) \
         VALUES ($1,$2,$3,$4,$5,$6,'test')",
    )
    .bind::<SqlUuid, _>(subject_id)
    .bind::<SqlUuid, _>(tenant_id)
    .bind::<SqlUuid, _>(realm_id)
    .bind::<SqlUuid, _>(organization_id)
    .bind::<Text, _>(format!("openid4vc-recovery-{subject_id}"))
    .bind::<Text, _>(format!("openid4vc-recovery-{subject_id}@example.test"))
    .execute(&mut connection)
    .await
    .unwrap();
    drop(connection);

    let now = Utc::now();
    let issuer = Openid4vciRepository::new(pool.clone(), [0x37_u8; 32]);
    let access = CredentialAccess {
        token_id: Uuid::now_v7(),
        tenant_id,
        subject_id,
        client_id: "wallet".to_owned(),
        configuration_ids: vec!["pid".to_owned()],
        credential_identifiers: Vec::new(),
        dpop_jkt: None,
        expires_at: now + Duration::minutes(10),
    };
    let token_hash = blake3::hash(access.token_id.as_bytes())
        .to_hex()
        .to_string();
    issuer.upsert_access(&token_hash, &access).await.unwrap();

    let nonce_hash = blake3::hash(Uuid::now_v7().as_bytes()).to_hex().to_string();
    issuer
        .issue_nonce(&NonceRecord {
            nonce_hash: nonce_hash.clone(),
            expires_at: now + Duration::minutes(5),
        })
        .await
        .unwrap();
    let nonce_now = Utc::now();
    assert!(
        issuer
            .claim_nonce(&nonce_hash, "claim-a", nonce_now)
            .await
            .unwrap()
    );
    assert!(
        !issuer
            .claim_nonce(&nonce_hash, "claim-b", nonce_now)
            .await
            .unwrap()
    );
    assert!(
        !issuer
            .release_nonce(&nonce_hash, "claim-b", nonce_now)
            .await
            .unwrap()
    );
    assert!(
        issuer
            .release_nonce(&nonce_hash, "claim-a", nonce_now)
            .await
            .unwrap()
    );
    assert!(
        issuer
            .claim_nonce(&nonce_hash, "claim-b", nonce_now)
            .await
            .unwrap()
    );
    assert!(
        !issuer
            .finalize_nonce(&nonce_hash, "claim-a", nonce_now)
            .await
            .unwrap()
    );
    assert!(
        issuer
            .finalize_nonce(&nonce_hash, "claim-b", nonce_now)
            .await
            .unwrap()
    );
    assert!(
        !issuer
            .finalize_nonce(&nonce_hash, "claim-b", nonce_now)
            .await
            .unwrap()
    );

    let response_nonce_hash = blake3::hash(Uuid::now_v7().as_bytes()).to_hex().to_string();
    issuer
        .issue_nonce(&NonceRecord {
            nonce_hash: response_nonce_hash.clone(),
            expires_at: now + Duration::minutes(5),
        })
        .await
        .unwrap();
    let response_now = Utc::now();
    assert!(
        issuer
            .claim_nonce(&response_nonce_hash, "response-claim", response_now)
            .await
            .unwrap()
    );
    let response = StoredCredentialResponse {
        issuance_id: Uuid::now_v7(),
        token_id: access.token_id,
        request_digest: blake3::hash(b"issuance-request").to_hex().to_string(),
        body: br#"{"credentials":[]}"#.to_vec(),
        encoding: CredentialResponseEncoding::Json,
        status: 200,
        dpop_nonce: None,
        expires_at: now + Duration::minutes(5),
    };
    let handle = NotificationHandle {
        notification_id: format!("notification-{}", Uuid::now_v7()),
        token_id: access.token_id,
        expires_at: now + Duration::minutes(5),
    };
    assert!(
        issuer
            .finalize_nonce_with_notification_and_response(
                &response_nonce_hash,
                "response-claim",
                &handle,
                &response,
                response_now,
            )
            .await
            .unwrap()
    );
    assert_eq!(
        issuer
            .find_response(
                response.issuance_id,
                response.token_id,
                &response.request_digest,
                response_now,
            )
            .await
            .unwrap()
            .unwrap(),
        response
    );
    assert!(
        !issuer
            .claim_nonce(&response_nonce_hash, "response-retry", response_now)
            .await
            .unwrap()
    );
    let notification = IssuanceNotification {
        notification_id: handle.notification_id.clone(),
        token_id: handle.token_id,
        event: NotificationEvent::CredentialAccepted,
        description: Some("issued".to_owned()),
        occurred_at: now + Duration::seconds(1),
    };
    assert!(issuer.record_notification(&notification).await.unwrap());
    assert!(!issuer.record_notification(&notification).await.unwrap());

    let deferred = DeferredCredential {
        id: Uuid::now_v7(),
        transaction_hash: blake3::hash(b"deferred-transaction").to_hex().to_string(),
        access: access.clone(),
        configuration_id: "pid".to_owned(),
        format: CredentialFormat::SdJwtVc,
        holder_bindings: Vec::new(),
        payload_ciphertext: b"deferred-payload".to_vec(),
        ready_at: now - Duration::seconds(1),
        expires_at: now + Duration::minutes(5),
    };
    issuer.store_deferred(&deferred).await.unwrap();
    let first_claim = issuer
        .claim_ready_deferred(
            &deferred.transaction_hash,
            access.token_id,
            "deferred-a",
            now,
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(first_claim.claim_id, "deferred-a");
    assert_eq!(
        first_claim.credential.payload_ciphertext,
        b"deferred-payload"
    );
    assert!(
        issuer
            .claim_ready_deferred(
                &deferred.transaction_hash,
                access.token_id,
                "deferred-b",
                now,
            )
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        issuer
            .release_deferred(
                &deferred.transaction_hash,
                access.token_id,
                "deferred-a",
                now,
            )
            .await
            .unwrap()
    );
    assert!(
        issuer
            .claim_ready_deferred(
                &deferred.transaction_hash,
                access.token_id,
                "deferred-b",
                now,
            )
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        !issuer
            .release_deferred(
                &deferred.transaction_hash,
                access.token_id,
                "deferred-a",
                now,
            )
            .await
            .unwrap()
    );
    assert!(
        issuer
            .finalize_deferred(
                &deferred.transaction_hash,
                access.token_id,
                "deferred-b",
                now,
            )
            .await
            .unwrap()
    );
    assert!(
        !issuer
            .finalize_deferred(
                &deferred.transaction_hash,
                access.token_id,
                "deferred-b",
                now,
            )
            .await
            .unwrap()
    );
    assert!(
        issuer
            .consume_ready_deferred(&deferred.transaction_hash, access.token_id, now)
            .await
            .unwrap()
            .is_none()
    );

    let atomic_nonce_hash = blake3::hash(Uuid::now_v7().as_bytes()).to_hex().to_string();
    issuer
        .issue_nonce(&NonceRecord {
            nonce_hash: atomic_nonce_hash.clone(),
            expires_at: now + Duration::minutes(5),
        })
        .await
        .unwrap();
    let atomic_now = Utc::now();
    assert!(
        issuer
            .claim_nonce(&atomic_nonce_hash, "atomic-claim", atomic_now)
            .await
            .unwrap()
    );
    let atomic_deferred = DeferredCredential {
        id: Uuid::now_v7(),
        transaction_hash: blake3::hash(b"atomic-deferred-transaction")
            .to_hex()
            .to_string(),
        access: access.clone(),
        configuration_id: "pid".to_owned(),
        format: CredentialFormat::SdJwtVc,
        holder_bindings: Vec::new(),
        payload_ciphertext: b"atomic-payload".to_vec(),
        ready_at: now - Duration::seconds(1),
        expires_at: now + Duration::minutes(5),
    };
    let atomic_response = StoredCredentialResponse {
        issuance_id: Uuid::now_v7(),
        token_id: access.token_id,
        request_digest: blake3::hash(b"atomic-request").to_hex().to_string(),
        body: b"atomic-response".to_vec(),
        encoding: CredentialResponseEncoding::Jwt,
        status: 202,
        dpop_nonce: Some("dpop-nonce".to_owned()),
        expires_at: now + Duration::minutes(5),
    };
    issuer
        .store_deferred_and_finalize_nonce_with_response(
            &atomic_deferred,
            &atomic_nonce_hash,
            "atomic-claim",
            &atomic_response,
            atomic_now,
        )
        .await
        .unwrap();
    assert!(
        !issuer
            .claim_nonce(&atomic_nonce_hash, "atomic-retry", atomic_now)
            .await
            .unwrap()
    );
    assert_eq!(
        issuer
            .find_response(
                atomic_response.issuance_id,
                atomic_response.token_id,
                &atomic_response.request_digest,
                atomic_now,
            )
            .await
            .unwrap()
            .unwrap()
            .body,
        atomic_response.body
    );
    let atomic_claim = issuer
        .claim_ready_deferred(
            &atomic_deferred.transaction_hash,
            access.token_id,
            "atomic-deferred-claim",
            atomic_now,
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        atomic_claim.credential.payload_ciphertext,
        b"atomic-payload"
    );
    assert!(
        issuer
            .finalize_deferred(
                &atomic_deferred.transaction_hash,
                access.token_id,
                &atomic_claim.claim_id,
                atomic_now,
            )
            .await
            .unwrap()
    );

    let mut connection = get_conn(&pool).await.unwrap();
    sql_query("DELETE FROM openid4vci_nonces WHERE nonce_hash IN ($1,$2,$3)")
        .bind::<Text, _>(&nonce_hash)
        .bind::<Text, _>(&response_nonce_hash)
        .bind::<Text, _>(&atomic_nonce_hash)
        .execute(&mut connection)
        .await
        .unwrap();
    sql_query("DELETE FROM users WHERE id = $1 AND tenant_id = $2")
        .bind::<SqlUuid, _>(subject_id)
        .bind::<SqlUuid, _>(tenant_id)
        .execute(&mut connection)
        .await
        .unwrap();
}
