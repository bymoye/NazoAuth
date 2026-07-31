use std::{fs, sync::Arc, thread};

use super::*;

fn temporary_directory() -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "nazoauth-operator-task-test-{}",
        rand::random::<u64>()
    ));
    fs::create_dir(&path).unwrap();
    path
}

#[test]
fn concurrent_replay_claims_are_idempotent_and_conflicts_are_rejected() {
    let directory = temporary_directory();
    for iteration in 0..64 {
        let path = Arc::new(directory.join(format!("request-{iteration}.sha256")));
        let threads = (0..16)
            .map(|_| {
                let path = Arc::clone(&path);
                thread::spawn(move || claim_request(&path, &"a".repeat(64)))
            })
            .collect::<Vec<_>>();
        for thread in threads {
            thread.join().unwrap().unwrap();
        }
        assert!(claim_request(&path, &"b".repeat(64)).is_err());
    }
    assert!(fs::read_dir(&directory).unwrap().all(|entry| {
        !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .ends_with(".tmp")
    }));
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn retry_after_kill_window_reuses_claim_and_atomically_finishes_receipt() {
    let directory = temporary_directory();
    let request = directory.join("request.sha256");
    let receipt = directory.join("request.receipt.jws");
    let digest = "c".repeat(64);
    claim_request(&request, &digest).unwrap();
    claim_request(&request, &digest).unwrap();
    fs::write(receipt.with_extension("receipt.jws.tmp"), b"partial").unwrap();
    write_receipt_atomic(&receipt, b"complete.receipt.value").unwrap();
    assert_eq!(
        fs::read_to_string(receipt).unwrap(),
        "complete.receipt.value"
    );
    fs::remove_dir_all(directory).unwrap();
}
