use std::sync::Arc;

use super::*;

struct CapturingLimiter;

impl RequestRateLimitPort for CapturingLimiter {
    fn increment<'a>(
        &'a self,
        bucket: RequestRateLimitBucket,
        _subject: &'a str,
        _window_seconds: u64,
    ) -> RequestRateLimitFuture<'a> {
        Box::pin(async move {
            assert_eq!(bucket, RequestRateLimitBucket::Authentication);
            Ok(7)
        })
    }
}

#[test]
fn arc_trait_object_forwards_to_rate_limit_port() {
    let limiter: Arc<dyn RequestRateLimitPort> = Arc::new(CapturingLimiter);

    assert_eq!(
        futures_executor::block_on(limiter.increment(
            RequestRateLimitBucket::Authentication,
            "subject",
            60,
        )),
        Ok(7)
    );
}
