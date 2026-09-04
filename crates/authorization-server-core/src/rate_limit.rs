use std::{future::Future, pin::Pin, sync::Arc};

/// Stable request classes that must not share a fixed-window counter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestRateLimitBucket {
    Authentication,
    Token,
    TokenManagement,
}

/// An intentionally opaque dependency failure.
///
/// Callers must fail closed without exposing backend or protocol details.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequestRateLimitError;

impl std::fmt::Display for RequestRateLimitError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("request rate-limit dependency unavailable")
    }
}

impl std::error::Error for RequestRateLimitError {}

pub type RequestRateLimitFuture<'a> =
    Pin<Box<dyn Future<Output = Result<u64, RequestRateLimitError>> + Send + 'a>>;

/// Atomic fixed-window request counter.
///
/// The returned value is the post-increment count. The implementation owns
/// hashing, key layout, atomicity, and TTL repair; callers own policy thresholds
/// and response rendering.
pub trait RequestRateLimitPort: Send + Sync {
    fn increment<'a>(
        &'a self,
        bucket: RequestRateLimitBucket,
        subject: &'a str,
        window_seconds: u64,
    ) -> RequestRateLimitFuture<'a>;
}

impl<T> RequestRateLimitPort for Arc<T>
where
    T: RequestRateLimitPort + ?Sized,
{
    fn increment<'a>(
        &'a self,
        bucket: RequestRateLimitBucket,
        subject: &'a str,
        window_seconds: u64,
    ) -> RequestRateLimitFuture<'a> {
        self.as_ref().increment(bucket, subject, window_seconds)
    }
}

#[cfg(test)]
#[path = "../tests/unit/rate_limit.rs"]
mod tests;
