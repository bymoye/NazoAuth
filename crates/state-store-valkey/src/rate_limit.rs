use crate::{Error, ValkeyConnection, command, keys};
const INCREMENT_SCRIPT: &str = r#"
local current = redis.call('GET', KEYS[1])
if not current then redis.call('SET', KEYS[1], '1', 'EX', ARGV[1]); return '1' end
local count = redis.call('INCR', KEYS[1])
if redis.call('TTL', KEYS[1]) == -1 then redis.call('EXPIRE', KEYS[1], ARGV[1]) end
return tostring(count)
"#;
#[derive(Clone, Copy, Debug)]
pub enum RateDimension {
    Auth,
    Token,
    TokenManagement,
}
impl RateDimension {
    fn name(self) -> &'static str {
        match self {
            Self::Auth => "auth",
            Self::Token => "token",
            Self::TokenManagement => "token_management",
        }
    }
}
#[derive(Clone, Copy, Debug)]
pub enum LoginFailureDimension {
    IpEmail,
}
impl LoginFailureDimension {
    fn name(self) -> &'static str {
        match self {
            Self::IpEmail => "ip_email",
        }
    }
}
#[derive(Clone, Debug)]
pub struct RateLimitStore {
    connection: ValkeyConnection,
}
impl RateLimitStore {
    pub fn new(connection: &ValkeyConnection) -> Self {
        Self {
            connection: connection.clone(),
        }
    }
    pub async fn increment(
        &self,
        dimension: RateDimension,
        subject: &str,
        window: u64,
    ) -> Result<u64, Error> {
        self.increment_key(keys::rate(dimension.name(), subject), window)
            .await
    }
    pub async fn increment_login_failure(
        &self,
        dimension: LoginFailureDimension,
        subject: &str,
        window: u64,
    ) -> Result<u64, Error> {
        self.increment_key(keys::login_failure(dimension.name(), subject), window)
            .await
    }
    pub async fn login_failure_count(
        &self,
        dimension: LoginFailureDimension,
        subject: &str,
    ) -> Result<u64, Error> {
        match command::get(
            &self.connection,
            keys::login_failure(dimension.name(), subject),
        )
        .await?
        {
            Some(raw) => raw
                .parse()
                .map_err(|e| Error::protocol(format!("invalid rate counter: {e}"))),
            None => Ok(0),
        }
    }
    pub async fn clear_login_failure(
        &self,
        dimension: LoginFailureDimension,
        subject: &str,
    ) -> Result<i64, Error> {
        command::delete(
            &self.connection,
            keys::login_failure(dimension.name(), subject),
        )
        .await
    }

    pub async fn increment_mfa_failure(&self, subject: &str, window: u64) -> Result<u64, Error> {
        self.increment_key(keys::mfa_failure(subject), window).await
    }

    pub async fn clear_mfa_failure(&self, subject: &str) -> Result<i64, Error> {
        command::delete(&self.connection, keys::mfa_failure(subject)).await
    }
    async fn increment_key(&self, key: String, window: u64) -> Result<u64, Error> {
        command::eval_string(
            &self.connection,
            INCREMENT_SCRIPT,
            vec![key],
            vec![window.to_string()],
        )
        .await?
        .parse()
        .map_err(|e| Error::protocol(format!("invalid rate counter: {e}")))
    }
}

impl nazo_identity::ports::LoginThrottlePort for RateLimitStore {
    fn failure_count<'a>(
        &'a self,
        email: &'a str,
        source_ip: &'a str,
    ) -> nazo_identity::ports::RepositoryFuture<'a, u64> {
        Box::pin(async move {
            let ip_email = format!("{source_ip}:{email}");
            self.login_failure_count(LoginFailureDimension::IpEmail, &ip_email)
                .await
                .map_err(crate::identity_repository_error)
        })
    }

    fn record_failure<'a>(
        &'a self,
        email: &'a str,
        source_ip: &'a str,
        window_seconds: u64,
    ) -> nazo_identity::ports::RepositoryFuture<'a, ()> {
        Box::pin(async move {
            self.increment_login_failure(
                LoginFailureDimension::IpEmail,
                &format!("{source_ip}:{email}"),
                window_seconds,
            )
            .await
            .map(|_| ())
            .map_err(crate::identity_repository_error)
        })
    }

    fn clear_failure<'a>(
        &'a self,
        email: &'a str,
        source_ip: &'a str,
    ) -> nazo_identity::ports::RepositoryFuture<'a, ()> {
        Box::pin(async move {
            self.clear_login_failure(
                LoginFailureDimension::IpEmail,
                &format!("{source_ip}:{email}"),
            )
            .await
            .map(|_| ())
            .map_err(crate::identity_repository_error)
        })
    }
}

impl nazo_identity::ports::MfaAttemptThrottlePort for RateLimitStore {
    fn reserve_attempt<'a>(
        &'a self,
        tenant_id: nazo_identity::TenantId,
        user_id: nazo_identity::UserId,
        session_id: &'a str,
        window_seconds: u64,
        max_attempts: u64,
    ) -> nazo_identity::ports::RepositoryFuture<'a, nazo_identity::ports::MfaAttemptThrottleDecision>
    {
        Box::pin(async move {
            let subject = format!("{}:{}:{session_id}", tenant_id.as_uuid(), user_id.as_uuid());
            let count = self
                .increment_mfa_failure(&subject, window_seconds)
                .await
                .map_err(crate::identity_repository_error)?;
            if count > max_attempts {
                Ok(nazo_identity::ports::MfaAttemptThrottleDecision::Limited {
                    retry_after_seconds: window_seconds,
                })
            } else {
                Ok(nazo_identity::ports::MfaAttemptThrottleDecision::Allowed)
            }
        })
    }

    fn clear_attempts<'a>(
        &'a self,
        tenant_id: nazo_identity::TenantId,
        user_id: nazo_identity::UserId,
        session_id: &'a str,
    ) -> nazo_identity::ports::RepositoryFuture<'a, ()> {
        Box::pin(async move {
            let subject = format!("{}:{}:{session_id}", tenant_id.as_uuid(), user_id.as_uuid());
            self.clear_mfa_failure(&subject)
                .await
                .map(|_| ())
                .map_err(crate::identity_repository_error)
        })
    }
}
