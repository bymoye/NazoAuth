use anyhow::bail;

use crate::config::ConfigSource;

#[derive(Clone)]
pub(crate) struct RateLimitSettings {
    pub(crate) window_seconds: u64,
    pub(crate) auth_max_requests: u64,
    pub(crate) token_max_requests: u64,
    pub(crate) token_management_max_requests: u64,
    pub(crate) login_failure_window_seconds: u64,
    pub(crate) login_failure_email_max_attempts: u64,
    pub(crate) login_failure_ip_email_max_attempts: u64,
}

impl RateLimitSettings {
    pub(super) fn from_config(config: &ConfigSource) -> anyhow::Result<Self> {
        let settings = Self {
            window_seconds: config.parse("RATE_LIMIT_WINDOW_SECONDS", 60)?,
            auth_max_requests: config.parse("AUTH_RATE_LIMIT_MAX_REQUESTS", 30)?,
            token_max_requests: config.parse("TOKEN_RATE_LIMIT_MAX_REQUESTS", 60)?,
            token_management_max_requests: config
                .parse("TOKEN_MANAGEMENT_RATE_LIMIT_MAX_REQUESTS", 120)?,
            login_failure_window_seconds: config.parse("LOGIN_FAILURE_WINDOW_SECONDS", 900)?,
            login_failure_email_max_attempts: config
                .parse("LOGIN_FAILURE_EMAIL_MAX_ATTEMPTS", 50)?,
            login_failure_ip_email_max_attempts: config
                .parse("LOGIN_FAILURE_IP_EMAIL_MAX_ATTEMPTS", 5)?,
        };
        if settings.window_seconds == 0 || settings.login_failure_window_seconds == 0 {
            bail!("rate limit windows must be greater than 0");
        }
        if settings.auth_max_requests == 0
            || settings.token_max_requests == 0
            || settings.token_management_max_requests == 0
            || settings.login_failure_email_max_attempts == 0
            || settings.login_failure_ip_email_max_attempts == 0
        {
            bail!("rate limit request caps must be greater than 0");
        }
        Ok(settings)
    }
}
