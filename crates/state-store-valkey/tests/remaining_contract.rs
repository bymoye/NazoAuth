use std::time::Duration;

use fred::interfaces::{ClientLike, KeysInterface};
use fred::prelude::{Builder, Config};
use nazo_identity::ports::{
    EmailVerificationConsume, EmailVerificationStorePort, FederationStatePort, LoginSessionCreate,
    LoginSessionPort, PasskeyCeremonyPort, PasswordHashInput,
};
use nazo_identity::session::SessionRecord;
use nazo_valkey::{
    AuthenticationStore, LoginFailureDimension, RateDimension, RateLimitStore, TokenStateStore,
    ValkeyConnection,
};
use serde_json::json;

async fn setup() -> Option<(ValkeyConnection, fred::prelude::Client)> {
    let url = std::env::var("VALKEY_URL").ok()?;
    let connection = ValkeyConnection::connect(&url, Duration::from_secs(1))
        .await
        .unwrap();
    let inspector = Builder::from_config(Config::from_url(&url).unwrap())
        .build()
        .unwrap();
    inspector
        .init()
        .await
        .expect("explicit Valkey must be available");
    Some((connection, inspector))
}

#[tokio::test]
async fn authentication_short_state_preserves_exact_keys_and_one_time_semantics() {
    let Some((connection, inspector)) = setup().await else {
        return;
    };
    let store = AuthenticationStore::new(&connection);
    let suffix = uuid::Uuid::now_v7().to_string();
    let email = format!("{suffix}@example.com");
    let ceremony = format!("ceremony-{suffix}");
    assert!(store.reserve_email_send(&email, 30).await.unwrap());
    assert!(!store.reserve_email_send(&email, 30).await.unwrap());
    assert_eq!(
        inspector
            .get::<String, _>(format!("oauth:email_verify:send:{email}"))
            .await
            .unwrap(),
        "1"
    );
    store.store_email_code(&email, "123456", 30).await.unwrap();
    assert_eq!(
        store.load_email_code(&email).await.unwrap().as_deref(),
        Some("123456")
    );
    let payload = json!({"challenge":"opaque", "user_id": suffix});
    store
        .store_passkey_registration(&ceremony, &payload, 30)
        .await
        .unwrap();
    assert_eq!(
        store.take_passkey_registration(&ceremony).await.unwrap(),
        Some(payload)
    );
    assert!(
        store
            .take_passkey_registration(&ceremony)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn typed_passkey_ceremony_is_atomically_consumed_once_under_concurrency() {
    let Some((connection, _inspector)) = setup().await else {
        return;
    };
    let store = AuthenticationStore::new(&connection);
    let suffix = uuid::Uuid::now_v7();
    let ceremony_id = format!("typed-{suffix}");
    let stored: nazo_identity::StoredPasskeyRegistration = serde_json::from_value(json!({
        "tenant_id": nazo_identity::TenantId::new(uuid::Uuid::now_v7()).unwrap(),
        "user_id": nazo_identity::UserId::new(uuid::Uuid::now_v7()).unwrap(),
        "label": "Concurrent key",
        "state": {
            "challenge": vec![7_u8; 32],
            "user_id": vec![9_u8; 32],
            "created_at": 1,
        },
    }))
    .unwrap();
    PasskeyCeremonyPort::store_registration(&store, &ceremony_id, &stored, 30)
        .await
        .unwrap();

    let (left, right) = tokio::join!(
        PasskeyCeremonyPort::take_registration(&store, &ceremony_id),
        PasskeyCeremonyPort::take_registration(&store, &ceremony_id)
    );
    let consumed = [left.unwrap(), right.unwrap()]
        .into_iter()
        .filter(Option::is_some)
        .count();
    assert_eq!(
        consumed, 1,
        "GETDEL must publish the ceremony to one finisher"
    );
}

#[tokio::test]
async fn saml_assertion_replay_reservation_is_atomic() {
    let Some((connection, _inspector)) = setup().await else {
        return;
    };
    let store = AuthenticationStore::new(&connection);
    let signature = format!("saml-signature-{}", uuid::Uuid::now_v7());
    let (left, right) = tokio::join!(
        FederationStatePort::reserve_saml_replay(&store, &signature, 30),
        FederationStatePort::reserve_saml_replay(&store, &signature, 30)
    );
    assert_eq!(
        usize::from(left.unwrap()) + usize::from(right.unwrap()),
        1,
        "one SAML assertion must be accepted at most once"
    );
}

#[tokio::test]
async fn email_code_compare_delete_never_removes_a_newer_value() {
    let Some((connection, _inspector)) = setup().await else {
        return;
    };
    let store = AuthenticationStore::new(&connection);
    let email = format!("cas-{}@example.com", uuid::Uuid::now_v7());
    EmailVerificationStorePort::store_code(
        &store,
        &email,
        PasswordHashInput::new("first-code-hash").unwrap(),
        30,
    )
    .await
    .unwrap();
    let stale = EmailVerificationStorePort::load_code(&store, &email)
        .await
        .unwrap()
        .unwrap();
    store
        .store_email_code(&email, "newer-code-hash", 30)
        .await
        .unwrap();

    assert_eq!(
        EmailVerificationStorePort::consume_code(&store, &email, &stale)
            .await
            .unwrap(),
        EmailVerificationConsume::MissingOrChanged
    );
    assert_eq!(
        store.load_email_code(&email).await.unwrap().as_deref(),
        Some("newer-code-hash"),
        "a stale consumer must not delete a newer verification code"
    );

    let current = EmailVerificationStorePort::load_code(&store, &email)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        EmailVerificationStorePort::consume_code(&store, &email, &current)
            .await
            .unwrap(),
        EmailVerificationConsume::Consumed
    );
    assert!(store.load_email_code(&email).await.unwrap().is_none());
}

#[tokio::test]
async fn login_session_create_is_atomic_and_never_overwrites_a_collision() {
    let Some((connection, _inspector)) = setup().await else {
        return;
    };
    let sessions = nazo_valkey::SessionStore::new(&connection);
    let session_id = format!("login-collision-{}", uuid::Uuid::now_v7());
    let first = SessionRecord::new(
        nazo_identity::UserId::new(uuid::Uuid::now_v7()).unwrap(),
        1,
        vec!["password".to_owned()],
        false,
        Some("first-oidc-sid".to_owned()),
    );
    let second = SessionRecord::new(
        nazo_identity::UserId::new(uuid::Uuid::now_v7()).unwrap(),
        2,
        vec!["password".to_owned()],
        true,
        Some("second-oidc-sid".to_owned()),
    );

    assert_eq!(
        LoginSessionPort::create(&sessions, &session_id, &first, 30)
            .await
            .unwrap(),
        LoginSessionCreate::Created
    );
    assert_eq!(
        LoginSessionPort::create(&sessions, &session_id, &second, 30)
            .await
            .unwrap(),
        LoginSessionCreate::Collision
    );
    assert_eq!(
        sessions.load(&session_id).await.unwrap().unwrap().value(),
        &first
    );
}

#[tokio::test]
async fn login_session_replacement_atomically_invalidates_the_previous_session() {
    let Some((connection, inspector)) = setup().await else {
        return;
    };
    let sessions = nazo_valkey::SessionStore::new(&connection);
    let previous_id = format!("login-previous-{}", uuid::Uuid::now_v7());
    let collision_id = format!("login-collision-{}", uuid::Uuid::now_v7());
    let replacement_id = format!("login-replacement-{}", uuid::Uuid::now_v7());
    let previous = SessionRecord::new(
        nazo_identity::UserId::new(uuid::Uuid::now_v7()).unwrap(),
        1,
        vec!["password".to_owned()],
        false,
        Some("previous-oidc-sid".to_owned()),
    );
    let replacement = SessionRecord::new(
        nazo_identity::UserId::new(uuid::Uuid::now_v7()).unwrap(),
        2,
        vec!["password".to_owned()],
        true,
        Some("replacement-oidc-sid".to_owned()),
    );
    assert_eq!(
        LoginSessionPort::create(&sessions, &previous_id, &previous, 120)
            .await
            .unwrap(),
        LoginSessionCreate::Created
    );
    assert_eq!(
        LoginSessionPort::create(&sessions, &collision_id, &replacement, 120)
            .await
            .unwrap(),
        LoginSessionCreate::Created
    );
    assert_eq!(
        LoginSessionPort::create_replacing(
            &sessions,
            Some(&previous_id),
            &collision_id,
            &previous,
            60,
        )
        .await
        .unwrap(),
        LoginSessionCreate::Collision
    );
    assert_eq!(
        sessions.load(&previous_id).await.unwrap().unwrap().value(),
        &previous
    );
    assert_eq!(
        sessions.load(&collision_id).await.unwrap().unwrap().value(),
        &replacement
    );
    assert_eq!(
        LoginSessionPort::create_replacing(
            &sessions,
            Some(&previous_id),
            &replacement_id,
            &replacement,
            60,
        )
        .await
        .unwrap(),
        LoginSessionCreate::Created
    );
    assert!(sessions.load(&previous_id).await.unwrap().is_none());
    assert_eq!(
        sessions
            .load(&replacement_id)
            .await
            .unwrap()
            .unwrap()
            .value(),
        &replacement
    );
    assert!(
        (1..=60).contains(
            &inspector
                .ttl::<i64, _>(format!("oauth:session:{replacement_id}"))
                .await
                .unwrap()
        )
    );
}

#[tokio::test]
async fn concurrent_rate_counters_are_atomic_and_preserve_first_window_ttl() {
    let Some((connection, inspector)) = setup().await else {
        return;
    };
    let store = RateLimitStore::new(&connection);
    let subject = format!("subject-{}", uuid::Uuid::now_v7());
    let futures = (0..20).map(|_| store.increment(RateDimension::Token, &subject, 30));
    let results = futures_util::future::join_all(futures).await;
    let mut counts = results.into_iter().collect::<Result<Vec<_>, _>>().unwrap();
    counts.sort_unstable();
    assert_eq!(counts, (1..=20).collect::<Vec<_>>());
    let key = format!(
        "oauth:rate:token:{}",
        blake3::hash(subject.as_bytes()).to_hex()
    );
    assert!((1..=30).contains(&inspector.ttl::<i64, _>(&key).await.unwrap()));
    assert_eq!(
        store
            .login_failure_count(LoginFailureDimension::Email, &subject)
            .await
            .unwrap(),
        0
    );
}

#[tokio::test]
async fn token_state_preserves_subject_and_native_sso_key_contracts() {
    let Some((connection, inspector)) = setup().await else {
        return;
    };
    let store = TokenStateStore::new(&connection);
    let tenant = uuid::Uuid::from_u128(1);
    let user = uuid::Uuid::from_u128(2);
    let jti = format!("jti-{}", uuid::Uuid::now_v7());
    let secret = format!("secret-{}", uuid::Uuid::now_v7());
    store
        .store_access_token_subject(tenant, &jti, user, 30)
        .await
        .unwrap();
    assert_eq!(
        store.load_access_token_subject(tenant, &jti).await.unwrap(),
        Some(user)
    );
    let subject_key = format!(
        "oauth:access_token:subject:{tenant}:{}",
        blake3::hash(jti.as_bytes()).to_hex()
    );
    assert_eq!(
        inspector.get::<String, _>(&subject_key).await.unwrap(),
        user.to_string()
    );
    let payload = json!({"tenant_id":tenant,"user_id":user,"sid":"sid"});
    store.store_native_sso(&secret, &payload, 30).await.unwrap();
    assert_eq!(store.load_native_sso(&secret).await.unwrap(), Some(payload));
}
