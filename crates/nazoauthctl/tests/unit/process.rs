use super::*;

#[test]
fn timeout_kills_and_reaps_the_direct_child() {
    let started = std::time::Instant::now();
    let error = Process::new("sh")
        .args(["-c", "exec sleep 5"])
        .timeout(Duration::from_millis(25))
        .run_quiet()
        .unwrap_err();
    assert!(error.to_string().contains("timed out"));
    assert!(started.elapsed() < Duration::from_secs(1));
}
