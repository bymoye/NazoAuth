use std::time::Duration;

use crate::KeyManager;

impl KeyManager {
    pub async fn run_lifecycle(self) -> ! {
        let interval = refresh_interval(self.inner.settings.prepublish_window);
        loop {
            tokio::time::sleep(interval).await;
            if let Err(error) = self.refresh().await {
                tracing::error!(error = %error, "signing key lifecycle refresh failed; terminating process");
                #[cfg(test)]
                panic!("signing key lifecycle refresh failed: {error:#}");
                #[cfg(not(test))]
                std::process::abort();
            }
        }
    }
}

fn refresh_interval(prepublish_window: chrono::Duration) -> Duration {
    let seconds = (prepublish_window.num_seconds() / 2).clamp(1, 3_600);
    Duration::from_secs(seconds as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refresh_interval_is_bounded_by_prepublish_window() {
        assert_eq!(
            refresh_interval(chrono::Duration::seconds(86_400)),
            Duration::from_secs(3_600)
        );
        assert_eq!(
            refresh_interval(chrono::Duration::seconds(30)),
            Duration::from_secs(15)
        );
        assert_eq!(
            refresh_interval(chrono::Duration::seconds(1)),
            Duration::from_secs(1)
        );
    }
}
