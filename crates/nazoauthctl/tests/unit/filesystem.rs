use std::fs;

use super::*;

#[test]
fn private_temporary_directory_is_unique_private_and_removed_on_drop() {
    let first = PrivateTempDir::new("nazoauthctl-filesystem-test").unwrap();
    let second = PrivateTempDir::new("nazoauthctl-filesystem-test").unwrap();
    assert_ne!(first.path(), second.path());
    assert!(first.path().is_dir());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(first.path()).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }

    let removed = first.path().to_owned();
    drop(first);
    assert!(!removed.exists());
}

#[test]
fn durable_file_helpers_round_trip_bytes_digest_and_absent_removal() {
    let work = PrivateTempDir::new("nazoauthctl-file-round-trip").unwrap();
    let source = work.path().join("nested/source");
    atomic_write(&source, b"abc", 0o640).unwrap();
    assert_eq!(fs::read(&source).unwrap(), b"abc");
    assert_eq!(
        sha256(&source).unwrap(),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );

    let copy = work.path().join("copied");
    copy_atomic(&source, &copy, 0o600).unwrap();
    assert_eq!(fs::read(&copy).unwrap(), b"abc");
    remove_file_durable(&copy).unwrap();
    remove_file_durable(&copy).unwrap();
    assert!(!copy.exists());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&source).unwrap().permissions().mode() & 0o777,
            0o640
        );
        set_mode(&source, 0o400).unwrap();
        assert_eq!(
            fs::metadata(&source).unwrap().permissions().mode() & 0o777,
            0o400
        );
    }
}

#[test]
fn persisted_secrets_are_stable_single_line_regular_files() {
    let work = PrivateTempDir::new("nazoauthctl-secret-test").unwrap();
    let path = work.path().join("secrets/value");
    let generated = generate_secret(&path).unwrap();
    assert_eq!(generated.len(), 64);
    assert!(
        generated
            .chars()
            .all(|character| character.is_ascii_hexdigit())
    );
    assert_eq!(generate_secret(&path).unwrap(), generated);

    #[cfg(unix)]
    set_mode(&path, 0o600).unwrap();
    fs::write(&path, "multiline\nsecret").unwrap();
    assert!(generate_secret(&path).is_err());
    fs::remove_file(&path).unwrap();
    fs::create_dir(&path).unwrap();
    assert!(generate_secret(&path).is_err());
}

#[test]
fn filesystem_helpers_fail_closed_without_clobbering_staging_or_non_files() {
    let work = PrivateTempDir::new("nazoauthctl-filesystem-errors").unwrap();
    let target = work.path().join("target");
    let staging = target.with_extension(format!("tmp-{}", std::process::id()));
    fs::write(&staging, "occupied").unwrap();
    assert!(atomic_write(&target, b"replacement", 0o600).is_err());
    assert!(!target.exists());
    assert_eq!(fs::read_to_string(&staging).unwrap(), "occupied");

    let directory = work.path().join("directory");
    fs::create_dir(&directory).unwrap();
    assert!(remove_file_durable(&directory).is_err());
    assert!(copy_atomic(&work.path().join("missing"), &target, 0o600).is_err());
    assert!(sha256(&work.path().join("missing")).is_err());
    assert!(
        PrivateTempDir::new(&format!("nazoauthctl-missing-{}/child", std::process::id())).is_err()
    );
}

#[cfg(unix)]
#[test]
fn symlink_activation_replaces_a_stale_staging_link() {
    use std::os::unix::fs::symlink;

    let work = PrivateTempDir::new("nazoauthctl-symlink-test").unwrap();
    let first = work.path().join("first");
    let second = work.path().join("second");
    fs::write(&first, "first").unwrap();
    fs::write(&second, "second").unwrap();
    let link = work.path().join("current");
    let staging = link.with_extension(format!("next-{}", std::process::id()));
    symlink(&first, &staging).unwrap();

    symlink_atomic(&second, &link).unwrap();
    assert_eq!(fs::read_link(&link).unwrap(), second);
    assert!(!staging.exists());
}
