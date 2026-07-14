use std::{collections::HashMap, time::Duration};

use chrono::{TimeZone, Utc};
use fred::interfaces::{ClientLike, KeysInterface};
use fred::prelude::{Builder, Config};
use nazo_auth::{AuthorizationCodeState, CodePayload, ConsentPayload, PushedAuthorizationRequest};
use nazo_valkey::{AuthorizationCodeBegin, AuthorizationStore, ValkeyConnection};
use serde_json::json;

async fn setup() -> Option<(AuthorizationStore, fred::prelude::Client)> {
    let url = std::env::var("VALKEY_URL").ok()?;
    let connection = ValkeyConnection::connect(&url, Duration::from_secs(1))
        .await
        .expect("an explicitly configured Valkey must be available");
    let inspector = Builder::from_config(Config::from_url(&url).unwrap())
        .build()
        .unwrap();
    inspector
        .init()
        .await
        .expect("explicit Valkey must be available");
    Some((AuthorizationStore::new(&connection), inspector))
}

fn code_payload(code_id: &str) -> CodePayload {
    CodePayload {
        code_id: code_id.to_owned(),
        user_id: uuid::Uuid::from_u128(1),
        client_id: "client-a".to_owned(),
        redirect_uri: "https://client.example/cb".to_owned(),
        redirect_uri_was_supplied: true,
        scopes: vec!["openid".to_owned()],
        resource_indicators: vec![],
        authorization_details: json!([]),
        nonce: None,
        auth_time: 1_000,
        amr: vec!["password".to_owned()],
        oidc_sid: Some("sid".to_owned()),
        acr: None,
        userinfo_claims: vec![],
        userinfo_claim_requests: vec![],
        id_token_claims: vec![],
        id_token_claim_requests: vec![],
        code_challenge: None,
        code_challenge_method: None,
        dpop_jkt: None,
        mtls_x5t_s256: None,
        issued_at: Utc.timestamp_opt(1_000, 0).unwrap(),
        expires_at: Utc.timestamp_opt(1_030, 0).unwrap(),
    }
}

fn consent_payload(request_id: &str, user_id: uuid::Uuid) -> ConsentPayload {
    ConsentPayload {
        request_id: request_id.to_owned(),
        user_id,
        client_id: "client-a".to_owned(),
        client_name: "Client A".to_owned(),
        redirect_uri: "https://client.example/cb".to_owned(),
        redirect_uri_was_supplied: true,
        scopes: vec!["openid".to_owned()],
        resource_indicators: Vec::new(),
        authorization_details: json!([]),
        state: Some("state".to_owned()),
        response_mode: None,
        nonce: Some("nonce".to_owned()),
        auth_time: 1_000,
        amr: vec!["password".to_owned()],
        oidc_sid: Some("sid".to_owned()),
        acr: None,
        userinfo_claims: Vec::new(),
        userinfo_claim_requests: Vec::new(),
        id_token_claims: Vec::new(),
        id_token_claim_requests: Vec::new(),
        code_challenge: None,
        code_challenge_method: None,
        dpop_jkt: None,
        mtls_x5t_s256: None,
        pushed_request_uri: None,
        pushed_request_digest: None,
        issued_at: Utc.timestamp_opt(1_000, 0).unwrap(),
        expires_at: Utc.timestamp_opt(1_030, 0).unwrap(),
    }
}

#[tokio::test]
async fn par_preserves_exact_hashed_key_json_ttl_and_one_time_take() {
    let Some((store, inspector)) = setup().await else {
        return;
    };
    let request_uri = format!("urn:ietf:params:oauth:request_uri:{}", uuid::Uuid::now_v7());
    let key = format!(
        "oauth:par:{}",
        blake3::hash(request_uri.as_bytes()).to_hex()
    );
    let payload = PushedAuthorizationRequest {
        client_id: "client-a".to_owned(),
        params: HashMap::from([("scope".to_owned(), "openid".to_owned())]),
        dpop_jkt: None,
        mtls_x5t_s256: None,
        issued_at: Utc.timestamp_opt(1_000, 0).unwrap(),
        expires_at: Utc.timestamp_opt(1_030, 0).unwrap(),
    };

    store.store_par(&request_uri, &payload, 30).await.unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&inspector.get::<String, _>(&key).await.unwrap())
            .unwrap(),
        serde_json::to_value(&payload).unwrap()
    );
    assert!((1..=30).contains(&inspector.ttl::<i64, _>(&key).await.unwrap()));
    assert!(store.take_par(&request_uri).await.unwrap().is_some());
    assert!(store.take_par(&request_uri).await.unwrap().is_none());
}

#[tokio::test]
async fn concurrent_authorization_code_begin_has_one_consuming_winner() {
    let Some((store, _)) = setup().await else {
        return;
    };
    let code_hash = uuid::Uuid::now_v7().to_string();
    let pending = AuthorizationCodeState::Pending {
        payload: code_payload(&code_hash),
    };
    store
        .store_authorization_code_hash(&code_hash, &pending, 30)
        .await
        .unwrap();

    let (first, second) = tokio::join!(
        store.begin_authorization_code(&code_hash, Utc.timestamp_opt(1_001, 0).unwrap()),
        store.begin_authorization_code(&code_hash, Utc.timestamp_opt(1_001, 0).unwrap())
    );
    let results = [first.unwrap(), second.unwrap()];
    assert_eq!(
        results
            .iter()
            .filter(|r| matches!(r, AuthorizationCodeBegin::Consuming(_)))
            .count(),
        1
    );
    assert_eq!(
        results
            .iter()
            .filter(|r| matches!(r, AuthorizationCodeBegin::Busy))
            .count(),
        1
    );
}

#[tokio::test]
async fn concurrent_reauthentication_nonce_consumption_has_exactly_one_winner() {
    let Some((store, _)) = setup().await else {
        return;
    };
    let nonce = uuid::Uuid::now_v7().to_string();
    store.store_reauth_nonce(&nonce, 1_000, 30).await.unwrap();

    let (first, second) = tokio::join!(
        store.take_reauth_nonce(&nonce),
        store.take_reauth_nonce(&nonce),
    );
    let results = [first.unwrap(), second.unwrap()];
    assert_eq!(
        results
            .into_iter()
            .filter(|started_at| *started_at == Some(1_000))
            .count(),
        1
    );
    assert_eq!(results.into_iter().filter(Option::is_none).count(), 1);
}

#[tokio::test]
async fn consent_compare_delete_preserves_a_concurrent_replacement() {
    let Some((store, _)) = setup().await else {
        return;
    };
    let request_id = uuid::Uuid::now_v7().to_string();
    let observed = consent_payload(&request_id, uuid::Uuid::from_u128(1));
    let replacement = consent_payload(&request_id, uuid::Uuid::from_u128(2));
    store
        .store_consent(&request_id, &observed, 30)
        .await
        .unwrap();
    store
        .store_consent(&request_id, &replacement, 30)
        .await
        .unwrap();

    assert!(
        !store
            .compare_and_delete_consent(&request_id, &observed)
            .await
            .unwrap()
    );
    assert_eq!(
        store
            .load_consent(&request_id)
            .await
            .unwrap()
            .unwrap()
            .user_id,
        replacement.user_id
    );
}

#[tokio::test]
async fn concurrent_consent_compare_delete_has_exactly_one_winner() {
    let Some((store, _)) = setup().await else {
        return;
    };
    let request_id = uuid::Uuid::now_v7().to_string();
    let observed = consent_payload(&request_id, uuid::Uuid::from_u128(1));
    store
        .store_consent(&request_id, &observed, 30)
        .await
        .unwrap();

    let (first, second) = tokio::join!(
        store.compare_and_delete_consent(&request_id, &observed),
        store.compare_and_delete_consent(&request_id, &observed),
    );
    assert_eq!(
        [first.unwrap(), second.unwrap()]
            .into_iter()
            .filter(|consumed| *consumed)
            .count(),
        1
    );
}

#[tokio::test]
async fn par_compare_delete_preserves_a_concurrent_replacement() {
    let Some((store, _)) = setup().await else {
        return;
    };
    let request_uri = format!("urn:ietf:params:oauth:request_uri:{}", uuid::Uuid::now_v7());
    let observed = PushedAuthorizationRequest {
        client_id: "client-a".to_owned(),
        params: HashMap::from([("scope".to_owned(), "openid".to_owned())]),
        dpop_jkt: None,
        mtls_x5t_s256: None,
        issued_at: Utc.timestamp_opt(1_000, 0).unwrap(),
        expires_at: Utc.timestamp_opt(1_030, 0).unwrap(),
    };
    let mut replacement = observed.clone();
    replacement.client_id = "client-b".to_owned();
    store.store_par(&request_uri, &observed, 30).await.unwrap();
    store
        .store_par(&request_uri, &replacement, 30)
        .await
        .unwrap();

    assert!(
        !store
            .compare_and_delete_par(&request_uri, &observed)
            .await
            .unwrap()
    );
    assert_eq!(
        store
            .load_par(&request_uri)
            .await
            .unwrap()
            .unwrap()
            .client_id,
        replacement.client_id
    );
}

#[tokio::test]
async fn par_compare_delete_accepts_semantically_equal_reordered_multi_parameter_json() {
    let Some((store, inspector)) = setup().await else {
        return;
    };
    let request_uri = format!("urn:ietf:params:oauth:request_uri:{}", uuid::Uuid::now_v7());
    let observed = PushedAuthorizationRequest {
        client_id: "client-a".to_owned(),
        params: HashMap::from([
            (
                "redirect_uri".to_owned(),
                "https://client.example/cb".to_owned(),
            ),
            ("scope".to_owned(), "openid profile".to_owned()),
        ]),
        dpop_jkt: None,
        mtls_x5t_s256: None,
        issued_at: Utc.timestamp_opt(1_000, 0).unwrap(),
        expires_at: Utc.timestamp_opt(1_030, 0).unwrap(),
    };
    let key = format!(
        "oauth:par:{}",
        blake3::hash(request_uri.as_bytes()).to_hex()
    );
    let reordered = format!(
        r#"{{"expires_at":{},"params":{{"scope":{},"redirect_uri":{}}},"client_id":{},"issued_at":{}}}"#,
        serde_json::to_string(&observed.expires_at).unwrap(),
        serde_json::to_string(&observed.params["scope"]).unwrap(),
        serde_json::to_string(&observed.params["redirect_uri"]).unwrap(),
        serde_json::to_string(&observed.client_id).unwrap(),
        serde_json::to_string(&observed.issued_at).unwrap(),
    );
    inspector
        .set::<(), _, _>(&key, reordered, None, None, false)
        .await
        .unwrap();

    assert!(
        store
            .compare_and_delete_par(&request_uri, &observed)
            .await
            .unwrap()
    );
    assert!(!inspector.exists::<bool, _>(&key).await.unwrap());
}

#[tokio::test]
async fn consent_json_compare_is_nested_order_independent_but_preserves_array_object_types() {
    let Some((store, inspector)) = setup().await else {
        return;
    };
    let request_id = uuid::Uuid::now_v7().to_string();
    let key = format!("oauth:consent:{request_id}");
    let mut observed = consent_payload(&request_id, uuid::Uuid::from_u128(1));
    observed.authorization_details = json!([{
        "type": "payment_initiation",
        "actions": {"alpha": 1, "beta": 2}
    }]);
    let canonical = serde_json::to_string(&observed).unwrap();
    let reordered = canonical.replace(
        r#""actions":{"alpha":1,"beta":2}"#,
        r#""actions":{"beta":2,"alpha":1}"#,
    );
    assert_ne!(canonical, reordered);
    inspector
        .set::<(), _, _>(&key, reordered, None, None, false)
        .await
        .unwrap();
    assert!(
        store
            .compare_and_delete_consent(&request_id, &observed)
            .await
            .unwrap()
    );

    let array = consent_payload(&request_id, uuid::Uuid::from_u128(1));
    let object_replacement = serde_json::to_string(&array).unwrap().replace(
        r#""authorization_details":[]"#,
        r#""authorization_details":{}"#,
    );
    inspector
        .set::<(), _, _>(&key, object_replacement, None, None, false)
        .await
        .unwrap();
    assert!(
        !store
            .compare_and_delete_consent(&request_id, &array)
            .await
            .unwrap()
    );
    assert!(inspector.exists::<bool, _>(&key).await.unwrap());
}

#[tokio::test]
async fn malformed_json_compare_delete_fails_closed_without_deleting() {
    let Some((store, inspector)) = setup().await else {
        return;
    };
    let request_id = uuid::Uuid::now_v7().to_string();
    let key = format!("oauth:consent:{request_id}");
    let expected = consent_payload(&request_id, uuid::Uuid::from_u128(1));
    inspector
        .set::<(), _, _>(&key, "{", None, None, false)
        .await
        .unwrap();

    let error = store
        .compare_and_delete_consent(&request_id, &expected)
        .await
        .unwrap_err();
    assert_eq!(error.kind(), nazo_valkey::ErrorKind::CorruptData);
    assert!(inspector.exists::<bool, _>(&key).await.unwrap());
}
