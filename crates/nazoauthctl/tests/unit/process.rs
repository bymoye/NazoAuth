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

#[test]
fn authorization_rejection_requires_the_exact_closed_marker_and_nonzero_exit() {
    let rejected = Process::new("sh")
        .args([
            "-c",
            "cat >/dev/null; printf '%s\\n' 'nazoauth-operator-rejection=authorization' >&2; exit 17",
        ])
        .stdin_authorization_rejected(b"probe")
        .unwrap();
    assert!(rejected);

    let unrelated = Process::new("sh")
        .args([
            "-c",
            "cat >/dev/null; printf '%s\\n' 'prefix-nazoauth-operator-rejection=authorization' >&2; exit 17",
        ])
        .stdin_authorization_rejected(b"probe")
        .unwrap();
    assert!(!unrelated);

    let successful = Process::new("sh")
        .args([
            "-c",
            "cat >/dev/null; printf '%s\\n' 'nazoauth-operator-rejection=authorization' >&2; exit 0",
        ])
        .stdin_authorization_rejected(b"probe")
        .unwrap();
    assert!(!successful);
}
