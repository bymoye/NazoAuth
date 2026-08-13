use argon2::{Argon2, PasswordHasher, password_hash::SaltString};
use chrono::{DateTime, Duration, Utc};
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
    PreAuthorizedCodeGrant, StoredCredentialOffer, StoredCredentialResponse, TxCodeDescription,
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

#[derive(QueryableByName)]
struct NonceStateRow {
    #[diesel(sql_type = diesel::sql_types::Timestamptz)]
    created_at: DateTime<Utc>,
    #[diesel(sql_type = diesel::sql_types::Timestamptz)]
    expires_at: DateTime<Utc>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Text>)]
    claim_id: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Timestamptz>)]
    claim_expires_at: Option<DateTime<Utc>>,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Timestamptz>)]
    consumed_at: Option<DateTime<Utc>>,
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
    let mut connection = get_conn(&pool).await.unwrap();
    sql_query("UPDATE users SET is_active = FALSE WHERE tenant_id = $1 AND id = $2")
        .bind::<SqlUuid, _>(tenant_id)
        .bind::<SqlUuid, _>(admin_id)
        .execute(&mut connection)
        .await
        .unwrap();
    drop(connection);
    assert!(
        !repository
            .upsert_managed_dataset(ManagedCredentialDatasetWrite {
                tenant_id,
                actor_user_id: admin_id,
                subject_id,
                credential_configuration_id: "inactive-admin-pid",
                claims: &claims,
                valid_from: None,
                valid_until: None,
            })
            .await
            .unwrap(),
        "inactive administrators cannot write issuer-authoritative datasets"
    );
    assert!(
        repository
            .managed_dataset(tenant_id, subject_id, "inactive-admin-pid")
            .await
            .unwrap()
            .is_none(),
        "a rejected inactive-admin write must not make data readable"
    );
    assert!(
        !repository
            .delete_managed_dataset(tenant_id, admin_id, subject_id, "inactive-admin-pid")
            .await
            .unwrap(),
        "inactive administrators cannot delete issuer-authoritative datasets"
    );
    let mut connection = get_conn(&pool).await.unwrap();
    sql_query("UPDATE users SET is_active = TRUE WHERE tenant_id = $1 AND id = $2")
        .bind::<SqlUuid, _>(tenant_id)
        .bind::<SqlUuid, _>(admin_id)
        .execute(&mut connection)
        .await
        .unwrap();
    drop(connection);
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
    assert_eq!(
        repository
            .dataset(tenant_id, subject_id, "pid")
            .await
            .unwrap()
            .expect("an unbounded dataset should be active"),
        claims
    );
    assert!(
        repository
            .dataset(Uuid::now_v7(), subject_id, "pid")
            .await
            .unwrap()
            .is_none(),
        "dataset reads must remain tenant scoped"
    );
    let mut connection = get_conn(&pool).await.unwrap();
    sql_query(
        "UPDATE openid4vci_credential_datasets
         SET valid_from = CURRENT_TIMESTAMP + INTERVAL '5 minutes'
         WHERE tenant_id = $1 AND subject_id = $2 AND credential_configuration_id = 'pid'",
    )
    .bind::<SqlUuid, _>(tenant_id)
    .bind::<SqlUuid, _>(subject_id)
    .execute(&mut connection)
    .await
    .unwrap();
    drop(connection);
    assert!(
        repository
            .dataset(tenant_id, subject_id, "pid")
            .await
            .unwrap()
            .is_none(),
        "future-valid datasets must not be available to issuance"
    );
    assert!(
        repository
            .managed_dataset(tenant_id, subject_id, "pid")
            .await
            .unwrap()
            .is_some(),
        "management reads retain future validity metadata"
    );
    let mut connection = get_conn(&pool).await.unwrap();
    sql_query(
        "UPDATE openid4vci_credential_datasets
         SET valid_from = NULL, valid_until = CURRENT_TIMESTAMP - INTERVAL '1 second'
         WHERE tenant_id = $1 AND subject_id = $2 AND credential_configuration_id = 'pid'",
    )
    .bind::<SqlUuid, _>(tenant_id)
    .bind::<SqlUuid, _>(subject_id)
    .execute(&mut connection)
    .await
    .unwrap();
    drop(connection);
    assert!(
        repository
            .dataset(tenant_id, subject_id, "pid")
            .await
            .unwrap()
            .is_none(),
        "expired datasets must not be available to issuance"
    );
    let mut connection = get_conn(&pool).await.unwrap();
    sql_query(
        "UPDATE openid4vci_credential_datasets
         SET valid_until = NULL
         WHERE tenant_id = $1 AND subject_id = $2 AND credential_configuration_id = 'pid'",
    )
    .bind::<SqlUuid, _>(tenant_id)
    .bind::<SqlUuid, _>(subject_id)
    .execute(&mut connection)
    .await
    .unwrap();
    drop(connection);
    let mut connection = get_conn(&pool).await.unwrap();
    sql_query("UPDATE users SET role = 'admin', admin_level = 0 WHERE id = $1")
        .bind::<SqlUuid, _>(admin_id)
        .execute(&mut connection)
        .await
        .unwrap();
    drop(connection);
    assert!(
        !repository
            .upsert_managed_dataset(ManagedCredentialDatasetWrite {
                tenant_id,
                actor_user_id: admin_id,
                subject_id,
                credential_configuration_id: "zero-level-admin",
                claims: &claims,
                valid_from: None,
                valid_until: None,
            })
            .await
            .unwrap(),
        "an admin without a positive level cannot write datasets"
    );
    let mut connection = get_conn(&pool).await.unwrap();
    sql_query("UPDATE users SET role = 'admin', admin_level = 1, is_active = TRUE WHERE id = $1")
        .bind::<SqlUuid, _>(admin_id)
        .execute(&mut connection)
        .await
        .unwrap();
    sql_query("UPDATE users SET is_active = FALSE WHERE id = $1")
        .bind::<SqlUuid, _>(subject_id)
        .execute(&mut connection)
        .await
        .unwrap();
    drop(connection);
    assert!(
        !repository
            .upsert_managed_dataset(ManagedCredentialDatasetWrite {
                tenant_id,
                actor_user_id: admin_id,
                subject_id,
                credential_configuration_id: "inactive-subject",
                claims: &claims,
                valid_from: None,
                valid_until: None,
            })
            .await
            .unwrap(),
        "inactive subjects cannot receive issuer-authoritative datasets"
    );
    let mut connection = get_conn(&pool).await.unwrap();
    sql_query("UPDATE users SET is_active = TRUE WHERE id = $1")
        .bind::<SqlUuid, _>(subject_id)
        .execute(&mut connection)
        .await
        .unwrap();
    drop(connection);
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
    sql_query("DELETE FROM conformance_leases WHERE tenant_id = $1 AND id = $2")
        .bind::<SqlUuid, _>(tenant_id)
        .bind::<SqlUuid, _>(lease.id)
        .execute(&mut connection)
        .await
        .unwrap();
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
    let offer_tenant_b_id = Uuid::now_v7();
    let mut connection = get_conn(&pool).await.unwrap();
    sql_query(
        "INSERT INTO tenants (id, slug, display_name, status) \
         VALUES ($1, $2, $3, 'active')",
    )
    .bind::<SqlUuid, _>(offer_tenant_b_id)
    .bind::<Text, _>(format!("openid4vc-offer-isolation-{offer_tenant_b_id}"))
    .bind::<Text, _>("OpenID4VC offer isolation test tenant")
    .execute(&mut connection)
    .await
    .unwrap();
    drop(connection);
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
    let loaded_offer = issuer
        .offer(tenant_id, offer.id, now)
        .await
        .unwrap()
        .unwrap();
    assert!(
        issuer
            .offer(offer_tenant_b_id, offer.id, now)
            .await
            .unwrap()
            .is_none(),
        "a credential offer must not be readable from another tenant"
    );
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
            .resolve_authorization_offer(
                tenant_id,
                &issuer_state_hash,
                subject_id,
                client_id,
                resolve_at,
            )
            .await
            .unwrap()
            .expect("the offer should remain valid for multiple wallet clients");
        assert_eq!(authorization.client_id, client_id);
    }
    assert!(
        issuer
            .resolve_authorization_offer(
                offer_tenant_b_id,
                &issuer_state_hash,
                subject_id,
                "cross-tenant-wallet",
                resolve_at,
            )
            .await
            .unwrap()
            .is_none(),
        "issuer-state offers must not resolve from another tenant"
    );

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
                offer_tenant_b_id,
                &pre_authorized_hash,
                None,
                "cross-tenant-wallet",
                pre_authorized_consume_at,
            )
            .await
            .unwrap()
            .is_none(),
        "a pre-authorized offer must not be consumable from another tenant"
    );
    assert!(
        issuer
            .consume_pre_authorized_offer(
                tenant_id,
                &pre_authorized_hash,
                None,
                "wallet-a",
                pre_authorized_consume_at,
            )
            .await
            .unwrap()
            .is_some(),
        "the original tenant must still be able to consume its offer"
    );
    assert!(
        issuer
            .consume_pre_authorized_offer(
                tenant_id,
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

    let verifier = Openid4vpRepository::new(pool.clone(), tenant_id, data_key);
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
    let tenant_b_id = Uuid::now_v7();
    let mut connection = get_conn(&pool).await.unwrap();
    sql_query(
        "INSERT INTO tenants (id, slug, display_name, status) \
         VALUES ($1, $2, $3, 'active')",
    )
    .bind::<SqlUuid, _>(tenant_b_id)
    .bind::<Text, _>(format!("openid4vc-isolation-{tenant_b_id}"))
    .bind::<Text, _>("OpenID4VC isolation test tenant")
    .execute(&mut connection)
    .await
    .unwrap();
    drop(connection);
    let other_verifier = Openid4vpRepository::new(pool.clone(), tenant_b_id, data_key);
    assert!(
        other_verifier
            .request(transaction_id, now)
            .await
            .unwrap()
            .is_none(),
        "a presentation transaction must not be readable from another tenant"
    );
    assert!(
        other_verifier
            .bind_wallet_nonce(transaction_id, "cross-tenant-wallet-nonce", now)
            .await
            .unwrap()
            .is_none(),
        "a cross-tenant wallet nonce bind must not update the source transaction"
    );
    assert!(
        !other_verifier
            .complete(transaction_id, &state_hash, &result, completed_at)
            .await
            .unwrap(),
        "a cross-tenant completion must not consume the source transaction"
    );
    assert!(
        other_verifier
            .result(transaction_id, now)
            .await
            .unwrap()
            .is_none(),
        "a presentation result must remain invisible across tenants"
    );
    assert_eq!(
        verifier
            .request(transaction_id, now)
            .await
            .unwrap()
            .unwrap()
            .request
            .wallet_nonce
            .as_deref(),
        Some("wallet-nonce"),
        "cross-tenant operations must leave the source transaction unchanged"
    );
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

    let mut connection = get_conn(&pool).await.unwrap();
    sql_query("DELETE FROM openid4vci_nonces WHERE nonce_hash = $1")
        .bind::<Text, _>(&nonce_hash)
        .execute(&mut connection)
        .await
        .unwrap();
    sql_query("DELETE FROM openid4vp_transactions WHERE id = $1")
        .bind::<SqlUuid, _>(transaction_id)
        .execute(&mut connection)
        .await
        .unwrap();
    sql_query("DELETE FROM openid4vci_offers WHERE id IN ($1,$2)")
        .bind::<SqlUuid, _>(offer.id)
        .bind::<SqlUuid, _>(pre_authorized_offer.id)
        .execute(&mut connection)
        .await
        .unwrap();
    sql_query("DELETE FROM users WHERE id = $1 AND tenant_id = $2")
        .bind::<SqlUuid, _>(subject_id)
        .bind::<SqlUuid, _>(tenant_id)
        .execute(&mut connection)
        .await
        .unwrap();
    sql_query("DELETE FROM tenants WHERE id = $1")
        .bind::<SqlUuid, _>(tenant_b_id)
        .execute(&mut connection)
        .await
        .unwrap();
    sql_query("DELETE FROM tenants WHERE id = $1")
        .bind::<SqlUuid, _>(offer_tenant_b_id)
        .execute(&mut connection)
        .await
        .unwrap();
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

    let reclaim_nonce_hash = blake3::hash(Uuid::now_v7().as_bytes()).to_hex().to_string();
    let reclaim_nonce_issued_at = Utc::now();
    issuer
        .issue_nonce(&NonceRecord {
            nonce_hash: reclaim_nonce_hash.clone(),
            expires_at: reclaim_nonce_issued_at + Duration::minutes(30),
        })
        .await
        .unwrap();
    assert!(
        issuer
            .claim_nonce(
                &reclaim_nonce_hash,
                "expired-claim-a",
                reclaim_nonce_issued_at
            )
            .await
            .unwrap()
    );
    let reclaim_nonce_now = reclaim_nonce_issued_at + Duration::minutes(6);
    assert!(
        issuer
            .claim_nonce(&reclaim_nonce_hash, "expired-claim-b", reclaim_nonce_now)
            .await
            .unwrap(),
        "a nonce lease must be reclaimable after claim_expires_at without sleeping"
    );
    assert!(
        !issuer
            .finalize_nonce(&reclaim_nonce_hash, "expired-claim-a", reclaim_nonce_now)
            .await
            .unwrap()
    );
    assert!(
        !issuer
            .release_nonce(&reclaim_nonce_hash, "expired-claim-a", reclaim_nonce_now)
            .await
            .unwrap()
    );
    assert!(
        issuer
            .finalize_nonce(&reclaim_nonce_hash, "expired-claim-b", reclaim_nonce_now)
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
    let stored_response = issuer
        .find_response(
            response.issuance_id,
            response.token_id,
            &response.request_digest,
            response_now,
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored_response.issuance_id, response.issuance_id);
    assert_eq!(stored_response.token_id, response.token_id);
    assert_eq!(stored_response.request_digest, response.request_digest);
    assert_eq!(stored_response.body, response.body);
    assert_eq!(stored_response.encoding, response.encoding);
    assert_eq!(stored_response.status, response.status);
    assert_eq!(stored_response.dpop_nonce, response.dpop_nonce);
    assert_eq!(
        stored_response.expires_at.timestamp_micros(),
        response.expires_at.timestamp_micros()
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

    let deferred_ready_at = Utc::now() + Duration::seconds(1);
    let deferred = DeferredCredential {
        id: Uuid::now_v7(),
        transaction_hash: blake3::hash(b"deferred-transaction").to_hex().to_string(),
        access: access.clone(),
        configuration_id: "pid".to_owned(),
        format: CredentialFormat::SdJwtVc,
        holder_bindings: vec![serde_json::json!({"jwk":{"kid":"holder"}})],
        payload_ciphertext: b"deferred-payload".to_vec(),
        ready_at: deferred_ready_at,
        expires_at: deferred_ready_at + Duration::minutes(5),
    };
    issuer.store_deferred(&deferred).await.unwrap();
    let first_claim = issuer
        .claim_ready_deferred(
            &deferred.transaction_hash,
            access.token_id,
            "deferred-a",
            deferred_ready_at,
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
                deferred_ready_at,
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
                deferred_ready_at,
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
                deferred_ready_at,
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
                deferred_ready_at,
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
                deferred_ready_at,
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
            .consume_ready_deferred(
                &deferred.transaction_hash,
                access.token_id,
                deferred_ready_at,
            )
            .await
            .unwrap()
            .is_none()
    );

    let reclaim_deferred_ready_at = Utc::now() + Duration::seconds(1);
    let reclaim_deferred = DeferredCredential {
        id: Uuid::now_v7(),
        transaction_hash: blake3::hash(b"deferred-reclaim-transaction")
            .to_hex()
            .to_string(),
        access: access.clone(),
        configuration_id: "pid".to_owned(),
        format: CredentialFormat::SdJwtVc,
        holder_bindings: vec![serde_json::json!({"jwk":{"kid":"reclaim"}})],
        payload_ciphertext: b"reclaim-payload".to_vec(),
        ready_at: reclaim_deferred_ready_at,
        expires_at: reclaim_deferred_ready_at + Duration::minutes(30),
    };
    issuer.store_deferred(&reclaim_deferred).await.unwrap();
    assert!(
        issuer
            .claim_ready_deferred(
                &reclaim_deferred.transaction_hash,
                access.token_id,
                "expired-deferred-a",
                reclaim_deferred_ready_at,
            )
            .await
            .unwrap()
            .is_some()
    );
    let reclaim_deferred_now = reclaim_deferred_ready_at + Duration::minutes(6);
    assert!(
        issuer
            .claim_ready_deferred(
                &reclaim_deferred.transaction_hash,
                access.token_id,
                "expired-deferred-b",
                reclaim_deferred_now,
            )
            .await
            .unwrap()
            .is_some(),
        "a deferred lease must be reclaimable after claim_expires_at without sleeping"
    );
    assert!(
        !issuer
            .finalize_deferred(
                &reclaim_deferred.transaction_hash,
                access.token_id,
                "expired-deferred-a",
                reclaim_deferred_now,
            )
            .await
            .unwrap()
    );
    assert!(
        !issuer
            .release_deferred(
                &reclaim_deferred.transaction_hash,
                access.token_id,
                "expired-deferred-a",
                reclaim_deferred_now,
            )
            .await
            .unwrap()
    );
    assert!(
        issuer
            .finalize_deferred(
                &reclaim_deferred.transaction_hash,
                access.token_id,
                "expired-deferred-b",
                reclaim_deferred_now,
            )
            .await
            .unwrap()
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
    let atomic_deferred_ready_at = Utc::now() + Duration::seconds(1);
    let atomic_deferred = DeferredCredential {
        id: Uuid::now_v7(),
        transaction_hash: blake3::hash(b"atomic-deferred-transaction")
            .to_hex()
            .to_string(),
        access: access.clone(),
        configuration_id: "pid".to_owned(),
        format: CredentialFormat::SdJwtVc,
        holder_bindings: vec![serde_json::json!({"jwk":{"kid":"holder"}})],
        payload_ciphertext: b"atomic-payload".to_vec(),
        ready_at: atomic_deferred_ready_at,
        expires_at: atomic_deferred_ready_at + Duration::minutes(5),
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
            atomic_deferred_ready_at,
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
                atomic_deferred_ready_at,
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
            atomic_deferred_ready_at,
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
                atomic_deferred_ready_at,
            )
            .await
            .unwrap()
    );

    let mut connection = get_conn(&pool).await.unwrap();
    sql_query("DELETE FROM openid4vci_nonces WHERE nonce_hash IN ($1,$2,$3,$4)")
        .bind::<Text, _>(&nonce_hash)
        .bind::<Text, _>(&response_nonce_hash)
        .bind::<Text, _>(&atomic_nonce_hash)
        .bind::<Text, _>(&reclaim_nonce_hash)
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn issuance_store_covers_atomic_recovery_and_terminal_error_boundaries() {
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
    .bind::<Text, _>(format!("openid4vc-boundary-{subject_id}"))
    .bind::<Text, _>(format!("openid4vc-boundary-{subject_id}@example.test"))
    .execute(&mut connection)
    .await
    .unwrap();
    drop(connection);

    let issuer = Openid4vciRepository::new(pool.clone(), [0x48_u8; 32]);
    let now = Utc::now();
    let access = CredentialAccess {
        token_id: Uuid::now_v7(),
        tenant_id,
        subject_id,
        client_id: "boundary-wallet".to_owned(),
        configuration_ids: vec!["pid".to_owned()],
        credential_identifiers: Vec::new(),
        dpop_jkt: None,
        expires_at: now + Duration::minutes(30),
    };
    let token_hash = blake3::hash(access.token_id.as_bytes())
        .to_hex()
        .to_string();
    issuer.upsert_access(&token_hash, &access).await.unwrap();
    assert_eq!(
        issuer
            .resolve_access(&token_hash, Utc::now())
            .await
            .unwrap()
            .unwrap()
            .token_id,
        access.token_id
    );
    assert!(
        issuer
            .resolve_access("missing-access-hash", Utc::now())
            .await
            .unwrap()
            .is_none()
    );
    let mut connection = get_conn(&pool).await.unwrap();
    sql_query(
        "UPDATE openid4vci_access_grants SET revoked_at = CURRENT_TIMESTAMP WHERE token_id = $1",
    )
    .bind::<SqlUuid, _>(access.token_id)
    .execute(&mut connection)
    .await
    .unwrap();
    drop(connection);
    assert!(
        issuer
            .resolve_access(&token_hash, Utc::now())
            .await
            .unwrap()
            .is_none(),
        "revoked access grants must not be returned"
    );
    let mut connection = get_conn(&pool).await.unwrap();
    sql_query("UPDATE openid4vci_access_grants SET revoked_at = NULL, credential_identifiers = $2 WHERE token_id = $1")
        .bind::<SqlUuid, _>(access.token_id)
        .bind::<diesel::sql_types::Jsonb, _>(serde_json::json!([1]))
        .execute(&mut connection)
        .await
        .unwrap();
    drop(connection);
    assert_eq!(
        issuer.resolve_access(&token_hash, Utc::now()).await,
        Err(CredentialStoreError::Unavailable),
        "invalid credential identifier JSON must fail closed"
    );
    let mut connection = get_conn(&pool).await.unwrap();
    sql_query(
        "UPDATE openid4vci_access_grants SET credential_identifiers = $2 WHERE token_id = $1",
    )
    .bind::<SqlUuid, _>(access.token_id)
    .bind::<diesel::sql_types::Jsonb, _>(serde_json::json!([]))
    .execute(&mut connection)
    .await
    .unwrap();
    drop(connection);

    // Pre-authorized offers exercise tx-code verification, subject binding,
    // replay protection, and the expired/no-subject branches.
    let pre_authorized_code = format!("preauth-boundary-{}", Uuid::now_v7());
    let pre_authorized_hash = blake3::hash(pre_authorized_code.as_bytes())
        .to_hex()
        .to_string();
    let salt = SaltString::encode_b64(b"0123456789abcdef").unwrap();
    let tx_code_hash = Argon2::default()
        .hash_password(b"2468", &salt)
        .unwrap()
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
                tx_code: Some(TxCodeDescription {
                    input_mode: Some("numeric".to_owned()),
                    length: Some(4),
                    description: None,
                }),
                authorization_server: Some("https://issuer.example".to_owned()),
            }),
        ),
        expires_at: Utc::now() + Duration::minutes(10),
    };
    issuer
        .insert_offer(
            &pre_authorized_offer,
            None,
            Some(&pre_authorized_hash),
            Some(&tx_code_hash),
        )
        .await
        .unwrap();
    assert!(
        issuer
            .consume_pre_authorized_offer(
                tenant_id,
                &pre_authorized_hash,
                Some("0000"),
                "boundary-wallet",
                Utc::now(),
            )
            .await
            .unwrap()
            .is_none()
    );
    let authorization = issuer
        .consume_pre_authorized_offer(
            tenant_id,
            &pre_authorized_hash,
            Some("2468"),
            "boundary-wallet",
            Utc::now(),
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(authorization.subject_id, subject_id);
    assert!(
        issuer
            .consume_pre_authorized_offer(
                tenant_id,
                &pre_authorized_hash,
                Some("2468"),
                "boundary-wallet",
                Utc::now(),
            )
            .await
            .unwrap()
            .is_none()
    );

    let no_subject_code = format!("preauth-no-subject-{}", Uuid::now_v7());
    let no_subject_hash = blake3::hash(no_subject_code.as_bytes())
        .to_hex()
        .to_string();
    let no_subject_offer = StoredCredentialOffer {
        id: Uuid::now_v7(),
        tenant_id,
        subject_id: None,
        credential_configuration_ids: vec!["pid".to_owned()],
        grants: CredentialOfferGrants::new(
            None,
            Some(PreAuthorizedCodeGrant {
                pre_authorized_code: no_subject_code,
                tx_code: None,
                authorization_server: None,
            }),
        ),
        expires_at: Utc::now() + Duration::minutes(10),
    };
    issuer
        .insert_offer(&no_subject_offer, None, Some(&no_subject_hash), None)
        .await
        .unwrap();
    assert!(
        issuer
            .consume_pre_authorized_offer(
                tenant_id,
                &no_subject_hash,
                None,
                "boundary-wallet",
                Utc::now(),
            )
            .await
            .unwrap()
            .is_none(),
        "offers without a subject cannot authorize a token"
    );
    let expired_offer = StoredCredentialOffer {
        id: Uuid::now_v7(),
        tenant_id,
        subject_id: Some(subject_id),
        credential_configuration_ids: vec!["pid".to_owned()],
        grants: CredentialOfferGrants::new(None, None),
        expires_at: Utc::now() + Duration::minutes(10),
    };
    issuer
        .insert_offer(&expired_offer, None, None, None)
        .await
        .unwrap();
    assert!(
        issuer
            .offer(
                tenant_id,
                expired_offer.id,
                expired_offer.expires_at + Duration::seconds(1)
            )
            .await
            .unwrap()
            .is_none()
    );
    let corrupt_offer = StoredCredentialOffer {
        id: Uuid::now_v7(),
        tenant_id,
        subject_id: Some(subject_id),
        credential_configuration_ids: vec!["pid".to_owned()],
        grants: CredentialOfferGrants::new(None, None),
        expires_at: Utc::now() + Duration::minutes(10),
    };
    issuer
        .insert_offer(&corrupt_offer, None, None, None)
        .await
        .unwrap();
    let mut connection = get_conn(&pool).await.unwrap();
    sql_query("UPDATE openid4vci_offers SET grants_ciphertext = $2 WHERE id = $1")
        .bind::<SqlUuid, _>(corrupt_offer.id)
        .bind::<Binary, _>(vec![0_u8, 1, 2])
        .execute(&mut connection)
        .await
        .unwrap();
    drop(connection);
    assert_eq!(
        issuer.offer(tenant_id, corrupt_offer.id, Utc::now()).await,
        Err(CredentialStoreError::InvalidTransition)
    );

    // Nonce lease timestamps are monotonic even when a caller supplies an
    // earlier clock value, and notification finalization is all-or-nothing.
    let monotonic_nonce = blake3::hash(Uuid::now_v7().as_bytes()).to_hex().to_string();
    let monotonic_first_expires_at = Utc::now() + Duration::minutes(10);
    issuer
        .issue_nonce(&NonceRecord {
            nonce_hash: monotonic_nonce.clone(),
            expires_at: monotonic_first_expires_at,
        })
        .await
        .unwrap();
    let monotonic_second_expires_at = Utc::now() + Duration::minutes(20);
    issuer
        .issue_nonce(&NonceRecord {
            nonce_hash: monotonic_nonce.clone(),
            expires_at: monotonic_second_expires_at,
        })
        .await
        .unwrap();
    let mut connection = get_conn(&pool).await.unwrap();
    let before_consume = sql_query(
        "SELECT created_at, expires_at, claim_id, claim_expires_at, consumed_at
         FROM openid4vci_nonces WHERE nonce_hash = $1",
    )
    .bind::<Text, _>(&monotonic_nonce)
    .get_result::<NonceStateRow>(&mut connection)
    .await
    .unwrap();
    assert_eq!(
        before_consume.expires_at.timestamp_micros(),
        monotonic_first_expires_at.timestamp_micros(),
        "duplicate issue_nonce must not extend or otherwise rewrite the original expiry"
    );
    assert!(before_consume.claim_id.is_none());
    assert!(before_consume.claim_expires_at.is_none());
    assert!(before_consume.consumed_at.is_none());
    drop(connection);
    assert!(
        issuer
            .consume_nonce(&monotonic_nonce, Utc::now() - Duration::minutes(1))
            .await
            .unwrap()
    );
    issuer
        .issue_nonce(&NonceRecord {
            nonce_hash: monotonic_nonce.clone(),
            expires_at: Utc::now() + Duration::minutes(30),
        })
        .await
        .unwrap();
    let mut connection = get_conn(&pool).await.unwrap();
    let after_consume = sql_query(
        "SELECT created_at, expires_at, claim_id, claim_expires_at, consumed_at
         FROM openid4vci_nonces WHERE nonce_hash = $1",
    )
    .bind::<Text, _>(&monotonic_nonce)
    .get_result::<NonceStateRow>(&mut connection)
    .await
    .unwrap();
    assert_eq!(
        after_consume.expires_at.timestamp_micros(),
        monotonic_first_expires_at.timestamp_micros()
    );
    let consumed_at = after_consume
        .consumed_at
        .expect("the first consumption must persist the terminal marker");
    assert!(consumed_at >= after_consume.created_at);
    assert!(after_consume.claim_id.is_none());
    assert!(after_consume.claim_expires_at.is_none());
    drop(connection);
    assert!(
        !issuer
            .consume_nonce(&monotonic_nonce, Utc::now())
            .await
            .unwrap()
    );

    let notification_nonce = blake3::hash(Uuid::now_v7().as_bytes()).to_hex().to_string();
    issuer
        .issue_nonce(&NonceRecord {
            nonce_hash: notification_nonce.clone(),
            expires_at: Utc::now() + Duration::minutes(10),
        })
        .await
        .unwrap();
    assert!(
        issuer
            .claim_nonce(&notification_nonce, "notification-owner", Utc::now())
            .await
            .unwrap()
    );
    let notification_handle = NotificationHandle {
        notification_id: format!("notification-boundary-{}", Uuid::now_v7()),
        token_id: access.token_id,
        expires_at: Utc::now() + Duration::minutes(10),
    };
    assert_eq!(
        issuer
            .finalize_nonce_with_notification(
                &notification_nonce,
                "wrong-owner",
                &notification_handle,
                Utc::now(),
            )
            .await,
        Err(CredentialStoreError::Unavailable),
        "a failed atomic nonce finalization must roll back the notification insert"
    );
    assert!(
        issuer
            .finalize_nonce_with_notification(
                &notification_nonce,
                "notification-owner",
                &notification_handle,
                Utc::now(),
            )
            .await
            .unwrap()
    );

    let response_nonce = blake3::hash(Uuid::now_v7().as_bytes()).to_hex().to_string();
    issuer
        .issue_nonce(&NonceRecord {
            nonce_hash: response_nonce.clone(),
            expires_at: Utc::now() + Duration::minutes(10),
        })
        .await
        .unwrap();
    assert!(
        issuer
            .claim_nonce(&response_nonce, "response-owner", Utc::now())
            .await
            .unwrap()
    );
    let response = StoredCredentialResponse {
        issuance_id: Uuid::now_v7(),
        token_id: access.token_id,
        request_digest: blake3::hash(b"boundary-response").to_hex().to_string(),
        body: br#"{"credentials":[]}"#.to_vec(),
        encoding: CredentialResponseEncoding::Json,
        status: 200,
        dpop_nonce: Some("boundary-dpop".to_owned()),
        expires_at: Utc::now() + Duration::minutes(10),
    };
    let response_handle = NotificationHandle {
        notification_id: format!("response-boundary-{}", Uuid::now_v7()),
        token_id: access.token_id,
        expires_at: Utc::now() + Duration::minutes(10),
    };
    assert_eq!(
        issuer
            .finalize_nonce_with_notification_and_response(
                &response_nonce,
                "wrong-owner",
                &response_handle,
                &response,
                Utc::now(),
            )
            .await,
        Err(CredentialStoreError::Unavailable)
    );
    assert!(
        issuer
            .finalize_nonce_with_notification_and_response(
                &response_nonce,
                "response-owner",
                &response_handle,
                &response,
                Utc::now(),
            )
            .await
            .unwrap()
    );
    let stored_response = issuer
        .find_response(
            response.issuance_id,
            response.token_id,
            &response.request_digest,
            Utc::now(),
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored_response.issuance_id, response.issuance_id);
    assert_eq!(stored_response.token_id, response.token_id);
    assert_eq!(stored_response.request_digest, response.request_digest);
    assert_eq!(stored_response.body, response.body);
    assert_eq!(stored_response.encoding, response.encoding);
    assert_eq!(stored_response.status, response.status);
    assert_eq!(stored_response.dpop_nonce, response.dpop_nonce);
    assert_eq!(
        stored_response.expires_at.timestamp_micros(),
        response.expires_at.timestamp_micros()
    );
    let invalid_response = StoredCredentialResponse {
        issuance_id: Uuid::now_v7(),
        status: u16::MAX,
        ..response.clone()
    };
    assert_eq!(
        issuer
            .store_response_with_notification(&response_handle, &invalid_response, Utc::now())
            .await,
        Err(CredentialStoreError::InvalidTransition)
    );
    assert!(
        issuer
            .store_response_with_notification(&response_handle, &response, Utc::now())
            .await
            .is_err(),
        "replaying the issuance response must not create a second notification"
    );

    let corrupt_response = StoredCredentialResponse {
        issuance_id: Uuid::now_v7(),
        request_digest: blake3::hash(b"corrupt-response").to_hex().to_string(),
        ..response.clone()
    };
    let corrupt_handle = NotificationHandle {
        notification_id: format!("corrupt-response-{}", Uuid::now_v7()),
        ..response_handle.clone()
    };
    issuer
        .store_response_with_notification(&corrupt_handle, &corrupt_response, Utc::now())
        .await
        .unwrap();
    let mut connection = get_conn(&pool).await.unwrap();
    sql_query(
        "UPDATE openid4vci_issuance_responses SET body_ciphertext = $2 WHERE issuance_id = $1",
    )
    .bind::<SqlUuid, _>(corrupt_response.issuance_id)
    .bind::<Binary, _>(vec![0_u8, 1, 2])
    .execute(&mut connection)
    .await
    .unwrap();
    drop(connection);
    assert_eq!(
        issuer
            .find_response(
                corrupt_response.issuance_id,
                corrupt_response.token_id,
                &corrupt_response.request_digest,
                Utc::now(),
            )
            .await,
        Err(CredentialStoreError::InvalidTransition)
    );

    let failure_handle = NotificationHandle {
        notification_id: format!("failure-notification-{}", Uuid::now_v7()),
        token_id: access.token_id,
        expires_at: Utc::now() + Duration::minutes(10),
    };
    issuer
        .issue_notification_handle(&failure_handle)
        .await
        .unwrap();
    let failure_notification = IssuanceNotification {
        notification_id: failure_handle.notification_id.clone(),
        token_id: access.token_id,
        event: NotificationEvent::CredentialFailure,
        description: Some("signing failed".to_owned()),
        occurred_at: Utc::now(),
    };
    assert!(
        issuer
            .record_notification(&failure_notification)
            .await
            .unwrap()
    );
    assert!(
        !issuer
            .record_notification(&failure_notification)
            .await
            .unwrap()
    );
    let deleted_handle = NotificationHandle {
        notification_id: format!("deleted-notification-{}", Uuid::now_v7()),
        token_id: access.token_id,
        expires_at: Utc::now() + Duration::minutes(10),
    };
    issuer
        .issue_notification_handle(&deleted_handle)
        .await
        .unwrap();
    assert!(
        issuer
            .record_notification(&IssuanceNotification {
                notification_id: deleted_handle.notification_id.clone(),
                token_id: access.token_id,
                event: NotificationEvent::CredentialDeleted,
                description: None,
                occurred_at: Utc::now(),
            })
            .await
            .unwrap()
    );
    let expired_handle = NotificationHandle {
        notification_id: format!("expired-notification-{}", Uuid::now_v7()),
        token_id: access.token_id,
        expires_at: Utc::now() + Duration::minutes(10),
    };
    issuer
        .issue_notification_handle(&expired_handle)
        .await
        .unwrap();
    assert!(
        !issuer
            .record_notification(&IssuanceNotification {
                notification_id: expired_handle.notification_id.clone(),
                token_id: access.token_id,
                event: NotificationEvent::CredentialAccepted,
                description: None,
                occurred_at: expired_handle.expires_at + Duration::seconds(1),
            })
            .await
            .unwrap()
    );

    // Exercise every deferred transition, including all transaction rollback
    // paths and the legacy ready-consume path.
    let deferred_ready_at = Utc::now() + Duration::seconds(10);
    let deferred = DeferredCredential {
        id: Uuid::now_v7(),
        transaction_hash: blake3::hash(b"boundary-deferred").to_hex().to_string(),
        access: access.clone(),
        configuration_id: "pid".to_owned(),
        format: CredentialFormat::SdJwtVc,
        holder_bindings: vec![serde_json::json!({"jwk":{"kid":"boundary"}})],
        payload_ciphertext: b"boundary-deferred-payload".to_vec(),
        ready_at: deferred_ready_at,
        expires_at: deferred_ready_at + Duration::minutes(10),
    };
    issuer.store_deferred(&deferred).await.unwrap();
    assert!(
        issuer
            .claim_ready_deferred(
                &deferred.transaction_hash,
                access.token_id,
                "not-ready",
                Utc::now(),
            )
            .await
            .unwrap()
            .is_none()
    );
    let consumed_deferred = issuer
        .consume_ready_deferred(
            &deferred.transaction_hash,
            access.token_id,
            deferred_ready_at,
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        consumed_deferred.payload_ciphertext,
        deferred.payload_ciphertext
    );
    assert!(
        issuer
            .consume_ready_deferred(
                &deferred.transaction_hash,
                access.token_id,
                deferred_ready_at,
            )
            .await
            .unwrap()
            .is_none()
    );

    let lease_deferred_ready_at = Utc::now() + Duration::seconds(10);
    let lease_deferred = DeferredCredential {
        id: Uuid::now_v7(),
        transaction_hash: blake3::hash(b"boundary-deferred-lease")
            .to_hex()
            .to_string(),
        access: access.clone(),
        configuration_id: "pid".to_owned(),
        format: CredentialFormat::SdJwtVc,
        holder_bindings: vec![serde_json::json!({"jwk":{"kid":"lease"}})],
        payload_ciphertext: b"lease-payload".to_vec(),
        ready_at: lease_deferred_ready_at,
        expires_at: lease_deferred_ready_at + Duration::minutes(10),
    };
    issuer.store_deferred(&lease_deferred).await.unwrap();
    let lease_claim = issuer
        .claim_ready_deferred(
            &lease_deferred.transaction_hash,
            access.token_id,
            "lease-owner",
            lease_deferred_ready_at,
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(lease_claim.claim_id, "lease-owner");
    assert!(
        issuer
            .release_deferred(
                &lease_deferred.transaction_hash,
                access.token_id,
                "lease-owner",
                lease_deferred_ready_at,
            )
            .await
            .unwrap()
    );
    assert!(
        issuer
            .claim_ready_deferred(
                &lease_deferred.transaction_hash,
                access.token_id,
                "lease-owner-2",
                lease_deferred_ready_at,
            )
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        issuer
            .finalize_deferred(
                &lease_deferred.transaction_hash,
                access.token_id,
                "lease-owner-2",
                lease_deferred_ready_at - Duration::seconds(1),
            )
            .await
            .unwrap()
    );
    assert!(
        !issuer
            .finalize_deferred(
                &lease_deferred.transaction_hash,
                access.token_id,
                "lease-owner-2",
                lease_deferred_ready_at,
            )
            .await
            .unwrap()
    );

    let atomic_nonce = blake3::hash(Uuid::now_v7().as_bytes()).to_hex().to_string();
    issuer
        .issue_nonce(&NonceRecord {
            nonce_hash: atomic_nonce.clone(),
            expires_at: Utc::now() + Duration::minutes(10),
        })
        .await
        .unwrap();
    assert!(
        issuer
            .claim_nonce(&atomic_nonce, "atomic-owner", Utc::now())
            .await
            .unwrap()
    );
    let atomic_deferred = DeferredCredential {
        id: Uuid::now_v7(),
        transaction_hash: blake3::hash(b"boundary-atomic-deferred")
            .to_hex()
            .to_string(),
        access: access.clone(),
        configuration_id: "pid".to_owned(),
        format: CredentialFormat::SdJwtVc,
        holder_bindings: vec![serde_json::json!({"jwk":{"kid":"atomic"}})],
        payload_ciphertext: b"atomic-payload".to_vec(),
        ready_at: Utc::now() + Duration::seconds(10),
        expires_at: Utc::now() + Duration::minutes(10),
    };
    // Keep the expiry after ready_at despite taking two clock samples above.
    let atomic_deferred = DeferredCredential {
        expires_at: atomic_deferred.ready_at + Duration::minutes(10),
        ..atomic_deferred
    };
    assert_eq!(
        issuer
            .store_deferred_and_finalize_nonce(
                &atomic_deferred,
                &atomic_nonce,
                "wrong-owner",
                Utc::now(),
            )
            .await,
        Err(CredentialStoreError::Unavailable)
    );
    issuer
        .store_deferred_and_finalize_nonce(
            &atomic_deferred,
            &atomic_nonce,
            "atomic-owner",
            atomic_deferred.ready_at,
        )
        .await
        .unwrap();
    assert!(
        !issuer
            .claim_nonce(&atomic_nonce, "atomic-replay", Utc::now())
            .await
            .unwrap()
    );

    let atomic_response_nonce = blake3::hash(Uuid::now_v7().as_bytes()).to_hex().to_string();
    issuer
        .issue_nonce(&NonceRecord {
            nonce_hash: atomic_response_nonce.clone(),
            expires_at: Utc::now() + Duration::minutes(10),
        })
        .await
        .unwrap();
    assert!(
        issuer
            .claim_nonce(&atomic_response_nonce, "atomic-response-owner", Utc::now())
            .await
            .unwrap()
    );
    let atomic_response = StoredCredentialResponse {
        issuance_id: Uuid::now_v7(),
        token_id: access.token_id,
        request_digest: blake3::hash(b"boundary-atomic-response")
            .to_hex()
            .to_string(),
        body: b"atomic-response".to_vec(),
        encoding: CredentialResponseEncoding::Jwt,
        status: 202,
        dpop_nonce: None,
        expires_at: Utc::now() + Duration::minutes(10),
    };
    let atomic_response_deferred = DeferredCredential {
        id: Uuid::now_v7(),
        transaction_hash: blake3::hash(b"boundary-atomic-response-deferred")
            .to_hex()
            .to_string(),
        access: access.clone(),
        configuration_id: "pid".to_owned(),
        format: CredentialFormat::SdJwtVc,
        holder_bindings: vec![serde_json::json!({"jwk":{"kid":"atomic-response"}})],
        payload_ciphertext: b"atomic-response-payload".to_vec(),
        ready_at: Utc::now() + Duration::seconds(10),
        expires_at: Utc::now() + Duration::minutes(10),
    };
    let atomic_response_deferred = DeferredCredential {
        expires_at: atomic_response_deferred.ready_at + Duration::minutes(10),
        ..atomic_response_deferred
    };
    assert_eq!(
        issuer
            .store_deferred_and_finalize_nonce_with_response(
                &atomic_response_deferred,
                &atomic_response_nonce,
                "wrong-owner",
                &atomic_response,
                Utc::now(),
            )
            .await,
        Err(CredentialStoreError::Unavailable)
    );
    issuer
        .store_deferred_and_finalize_nonce_with_response(
            &atomic_response_deferred,
            &atomic_response_nonce,
            "atomic-response-owner",
            &atomic_response,
            atomic_response_deferred.ready_at,
        )
        .await
        .unwrap();
    assert_eq!(
        issuer
            .find_response(
                atomic_response.issuance_id,
                access.token_id,
                &atomic_response.request_digest,
                Utc::now(),
            )
            .await
            .unwrap()
            .unwrap()
            .encoding,
        CredentialResponseEncoding::Jwt
    );

    let response_deferred = DeferredCredential {
        id: Uuid::now_v7(),
        transaction_hash: blake3::hash(b"boundary-deferred-response")
            .to_hex()
            .to_string(),
        access: access.clone(),
        configuration_id: "pid".to_owned(),
        format: CredentialFormat::SdJwtVc,
        holder_bindings: vec![serde_json::json!({"jwk":{"kid":"response"}})],
        payload_ciphertext: b"response-payload".to_vec(),
        ready_at: Utc::now() + Duration::seconds(10),
        expires_at: Utc::now() + Duration::minutes(10),
    };
    let response_deferred = DeferredCredential {
        expires_at: response_deferred.ready_at + Duration::minutes(10),
        ..response_deferred
    };
    let deferred_response = StoredCredentialResponse {
        issuance_id: Uuid::now_v7(),
        token_id: access.token_id,
        request_digest: blake3::hash(b"boundary-deferred-response-body")
            .to_hex()
            .to_string(),
        body: b"deferred-response".to_vec(),
        encoding: CredentialResponseEncoding::Json,
        status: 200,
        dpop_nonce: None,
        expires_at: Utc::now() + Duration::minutes(10),
    };
    issuer
        .store_deferred_with_response(&response_deferred, &deferred_response, Utc::now())
        .await
        .unwrap();
    assert_eq!(
        issuer
            .find_response(
                deferred_response.issuance_id,
                access.token_id,
                &deferred_response.request_digest,
                Utc::now(),
            )
            .await
            .unwrap()
            .unwrap()
            .body,
        deferred_response.body
    );

    let notification_deferred = DeferredCredential {
        id: Uuid::now_v7(),
        transaction_hash: blake3::hash(b"boundary-deferred-notification")
            .to_hex()
            .to_string(),
        access: access.clone(),
        configuration_id: "pid".to_owned(),
        format: CredentialFormat::SdJwtVc,
        holder_bindings: vec![serde_json::json!({"jwk":{"kid":"notification"}})],
        payload_ciphertext: b"notification-payload".to_vec(),
        ready_at: Utc::now() + Duration::seconds(10),
        expires_at: Utc::now() + Duration::minutes(10),
    };
    let notification_deferred = DeferredCredential {
        expires_at: notification_deferred.ready_at + Duration::minutes(10),
        ..notification_deferred
    };
    issuer.store_deferred(&notification_deferred).await.unwrap();
    issuer
        .claim_ready_deferred(
            &notification_deferred.transaction_hash,
            access.token_id,
            "notification-deferred-owner",
            notification_deferred.ready_at,
        )
        .await
        .unwrap()
        .unwrap();
    let deferred_handle = NotificationHandle {
        notification_id: format!("deferred-notification-{}", Uuid::now_v7()),
        token_id: access.token_id,
        expires_at: Utc::now() + Duration::minutes(10),
    };
    assert_eq!(
        issuer
            .finalize_deferred_with_notification(
                &notification_deferred.transaction_hash,
                access.token_id,
                "wrong-owner",
                &deferred_handle,
                Utc::now(),
            )
            .await,
        Err(CredentialStoreError::Unavailable)
    );
    assert!(
        issuer
            .finalize_deferred_with_notification(
                &notification_deferred.transaction_hash,
                access.token_id,
                "notification-deferred-owner",
                &deferred_handle,
                Utc::now(),
            )
            .await
            .unwrap()
    );

    let deferred_response_notification = DeferredCredential {
        id: Uuid::now_v7(),
        transaction_hash: blake3::hash(b"boundary-deferred-notification-response")
            .to_hex()
            .to_string(),
        access: access.clone(),
        configuration_id: "pid".to_owned(),
        format: CredentialFormat::SdJwtVc,
        holder_bindings: vec![serde_json::json!({"jwk":{"kid":"notification-response"}})],
        payload_ciphertext: b"notification-response-payload".to_vec(),
        ready_at: Utc::now() + Duration::seconds(10),
        expires_at: Utc::now() + Duration::minutes(10),
    };
    let deferred_response_notification = DeferredCredential {
        expires_at: deferred_response_notification.ready_at + Duration::minutes(10),
        ..deferred_response_notification
    };
    issuer
        .store_deferred(&deferred_response_notification)
        .await
        .unwrap();
    issuer
        .claim_ready_deferred(
            &deferred_response_notification.transaction_hash,
            access.token_id,
            "deferred-response-owner",
            deferred_response_notification.ready_at,
        )
        .await
        .unwrap()
        .unwrap();
    let deferred_response_handle = NotificationHandle {
        notification_id: format!("deferred-response-{}", Uuid::now_v7()),
        token_id: access.token_id,
        expires_at: Utc::now() + Duration::minutes(10),
    };
    let final_response = StoredCredentialResponse {
        issuance_id: Uuid::now_v7(),
        token_id: access.token_id,
        request_digest: blake3::hash(b"boundary-final-response")
            .to_hex()
            .to_string(),
        body: b"final-response".to_vec(),
        encoding: CredentialResponseEncoding::Jwt,
        status: 202,
        dpop_nonce: None,
        expires_at: Utc::now() + Duration::minutes(10),
    };
    assert_eq!(
        issuer
            .finalize_deferred_with_notification_and_response(
                &deferred_response_notification.transaction_hash,
                access.token_id,
                "wrong-owner",
                &deferred_response_handle,
                &final_response,
                Utc::now(),
            )
            .await,
        Err(CredentialStoreError::Unavailable)
    );
    assert!(
        issuer
            .finalize_deferred_with_notification_and_response(
                &deferred_response_notification.transaction_hash,
                access.token_id,
                "deferred-response-owner",
                &deferred_response_handle,
                &final_response,
                Utc::now(),
            )
            .await
            .unwrap()
    );

    let mut connection = get_conn(&pool).await.unwrap();
    sql_query("DELETE FROM openid4vci_nonces WHERE nonce_hash IN ($1,$2,$3,$4)")
        .bind::<Text, _>(&monotonic_nonce)
        .bind::<Text, _>(&notification_nonce)
        .bind::<Text, _>(&response_nonce)
        .bind::<Text, _>(&atomic_nonce)
        .execute(&mut connection)
        .await
        .unwrap();
    sql_query("DELETE FROM openid4vci_nonces WHERE nonce_hash = $1")
        .bind::<Text, _>(&atomic_response_nonce)
        .execute(&mut connection)
        .await
        .unwrap();
    sql_query("DELETE FROM openid4vci_offers WHERE id IN ($1,$2,$3,$4)")
        .bind::<SqlUuid, _>(pre_authorized_offer.id)
        .bind::<SqlUuid, _>(no_subject_offer.id)
        .bind::<SqlUuid, _>(expired_offer.id)
        .bind::<SqlUuid, _>(corrupt_offer.id)
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
