use std::{sync::Arc, time::Duration};

use actix_web::web::Data;
use fred::{
    interfaces::{ClientLike, KeysInterface},
    prelude::{
        Builder as ValkeyBuilder, Config as ValkeyConfig, ConnectionConfig, PerformanceConfig,
    },
};
use nazo_http_actix::{
    AuthenticationRateLimit, AuthenticationRateLimitError, LocalRegistrationOperations,
};
use nazo_identity::{
    RegisterLocalAccountError, RegisterLocalAccountInput, SendVerificationCodeOutcome,
};
use uuid::Uuid;

use super::*;
use crate::{
    adapters::{
        email::normalize_email_address,
        security::{blake3_hex, hash_password, random_urlsafe_token},
    },
    config::ConfigSource,
    domain::TestAppState,
    settings::{EmailDelivery, Settings, SmtpEmailSettings, SmtpTlsMode},
    test_support::{
        registration_service,
        valkey::{valkey_get, valkey_set_ex},
    },
};

struct LiveFixture {
    state: Data<TestAppState>,
}

impl LiveFixture {
    async fn new() -> Option<Self> {
        let database_url = std::env::var("DATABASE_URL").ok()?;
        let valkey_url = std::env::var("VALKEY_URL").ok()?;
        let mut settings = Settings::from_config(&ConfigSource::default()).ok()?;
        settings.identity.email.delivery = EmailDelivery::Smtp(SmtpEmailSettings {
            host: "127.0.0.1".to_owned(),
            port: 1025,
            tls: SmtpTlsMode::None,
            username: None,
            password: None,
            from: "Nazo OAuth <no-reply@example.test>".parse().ok()?,
        });
        let mut builder = ValkeyBuilder::from_config(ValkeyConfig::from_url(&valkey_url).ok()?);
        builder.with_performance_config(|config: &mut PerformanceConfig| {
            config.default_command_timeout = Duration::from_secs(2);
        });
        builder.with_connection_config(|config: &mut ConnectionConfig| {
            config.connection_timeout = Duration::from_secs(2);
            config.internal_command_timeout = Duration::from_secs(2);
            config.max_command_attempts = 1;
        });
        let valkey = builder.build().ok()?;
        valkey.init().await.ok()?;
        Some(Self {
            state: Data::new(TestAppState {
                diesel_db: nazo_postgres::create_pool(database_url, 4).ok()?,
                valkey,
                settings: Arc::new(settings),
                keyset: crate::test_support::test_key_manager(),
            }),
        })
    }

    fn operations(
        &self,
    ) -> ServerLocalRegistrationOperations<
        nazo_postgres::UserRepository,
        nazo_valkey::AuthenticationStore,
        crate::bootstrap::RegistrationSecretHasher,
        crate::adapters::email::SmtpVerificationEmailDelivery,
    > {
        ServerLocalRegistrationOperations::new(
            registration_service(self.state.get_ref()).get_ref().clone(),
        )
    }

    async fn store_code(&self, email: &str, code: &str) {
        let email = normalize_email_address(email).unwrap();
        valkey_set_ex(
            &self.state.valkey,
            format!("oauth:email_verify:code:{email}"),
            hash_password(code).unwrap(),
            300,
        )
        .await
        .unwrap();
    }

    async fn key_exists(&self, key: &str) -> bool {
        valkey_get(&self.state.valkey, key).await.unwrap().is_some()
    }
}

#[actix_web::test]
async fn concurrent_registration_consumes_once_and_keeps_valkey_key_contract() {
    let Some(fixture) = LiveFixture::new().await else {
        return;
    };
    let email = format!("registration-boundary-{}@example.test", Uuid::now_v7());
    let verification_code = random_urlsafe_token();
    let password = random_urlsafe_token();
    fixture.store_code(&email, &verification_code).await;
    let input = || RegisterLocalAccountInput {
        email: email.clone(),
        verification_code: verification_code.clone(),
        password: password.clone(),
    };
    let first = fixture.operations();
    let second = fixture.operations();
    let (first, second) = tokio::join!(
        first.register_local_account(input()),
        second.register_local_account(input())
    );
    let outcomes = [first, second];
    assert_eq!(outcomes.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        outcomes
            .iter()
            .filter(|result| matches!(
                result,
                Err(RegisterLocalAccountError::InvalidVerificationCode)
                    | Err(RegisterLocalAccountError::Conflict)
            ))
            .count(),
        1
    );
    let registered = outcomes.into_iter().find_map(Result::ok).unwrap();
    assert_eq!(registered.email, email);

    let code_key = format!("oauth:email_verify:code:{email}");
    assert!(!fixture.key_exists(&code_key).await);

    let peer_subject = "203.0.113.77";
    assert_eq!(
        fixture
            .operations()
            .send_verification_code(&email, peer_subject)
            .await
            .unwrap(),
        SendVerificationCodeOutcome::Suppressed
    );
    let peer_key = format!("oauth:email_verify:peer_send:{}", blake3_hex(peer_subject));
    assert!(
        !fixture.key_exists(&peer_key).await,
        "existing-account suppression must not create peer cooldown state"
    );
}

#[actix_web::test]
async fn unavailable_valkey_rate_limit_fails_closed() {
    let mut builder = ValkeyBuilder::from_config(
        ValkeyConfig::from_url("redis://127.0.0.1:1").expect("URL should parse"),
    );
    builder.with_performance_config(|config: &mut PerformanceConfig| {
        config.default_command_timeout = Duration::from_millis(100);
    });
    builder.with_connection_config(|config: &mut ConnectionConfig| {
        config.connection_timeout = Duration::from_millis(100);
        config.internal_command_timeout = Duration::from_millis(100);
        config.max_command_attempts = 1;
    });
    let connection = nazo_valkey::ValkeyConnection::from_existing_client(
        builder.build().expect("client should build"),
    );
    let limiter =
        ServerAuthenticationRateLimit::new(nazo_valkey::RateLimitStore::new(&connection), 60, 10);
    assert_eq!(
        limiter.enforce("203.0.113.77").await,
        Err(AuthenticationRateLimitError::Unavailable)
    );
}

#[actix_web::test]
async fn live_rate_limit_is_atomic_and_preserves_key_and_ttl_contract() {
    let Some(fixture) = LiveFixture::new().await else {
        return;
    };
    let subject = format!("203.0.113.{}", Uuid::now_v7().as_bytes()[15]);
    let limiter = ServerAuthenticationRateLimit::new(
        nazo_valkey::RateLimitStore::new(&fixture.state.valkey_connection()),
        60,
        1,
    );
    let (first, second) = tokio::join!(limiter.enforce(&subject), limiter.enforce(&subject));
    let outcomes = [first, second];
    assert_eq!(outcomes.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        outcomes
            .iter()
            .filter(|result| matches!(
                result,
                Err(AuthenticationRateLimitError::Limited {
                    retry_after_seconds: 60
                })
            ))
            .count(),
        1
    );

    let key = format!("oauth:rate:auth:{}", blake3_hex(subject.trim()));
    assert_eq!(
        valkey_get(&fixture.state.valkey, &key)
            .await
            .unwrap()
            .as_deref(),
        Some("2")
    );
    let ttl: i64 = fixture.state.valkey.ttl(&key).await.unwrap();
    assert!((1..=60).contains(&ttl), "unexpected rate-limit TTL: {ttl}");
}
