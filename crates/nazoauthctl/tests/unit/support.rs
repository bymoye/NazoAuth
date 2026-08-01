use std::{
    fs,
    io::Write as _,
    os::unix::fs::PermissionsExt as _,
    path::Path,
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::{Duration, Instant},
};

static STAGING_SEQUENCE: AtomicU64 = AtomicU64::new(0);
const EXECUTABLE_READY_PROBE: &str = "__nazoauth_test_executable_ready__";
const EXECUTABLE_READY_TIMEOUT: Duration = Duration::from_secs(2);
const ETXTBSY_OS_ERROR: i32 = 26;

pub(crate) fn write_shell_executable(path: &Path, body: &str) {
    let sequence = STAGING_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let staging = path.with_extension(format!("tmp-{}-{sequence}", std::process::id()));
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&staging)
        .unwrap();
    file.write_all(
        format!(
            "#!/bin/sh\nset -eu\nif [ \"${{1-}}\" = {EXECUTABLE_READY_PROBE} ]; then exit 0; fi\n{body}\n"
        )
        .as_bytes(),
    )
    .unwrap();
    file.set_permissions(fs::Permissions::from_mode(0o700))
        .unwrap();
    file.sync_all().unwrap();
    drop(file);
    fs::rename(&staging, path).unwrap();
    fs::File::open(path.parent().unwrap())
        .unwrap()
        .sync_all()
        .unwrap();

    let deadline = Instant::now() + EXECUTABLE_READY_TIMEOUT;
    loop {
        match Command::new(path).arg(EXECUTABLE_READY_PROBE).status() {
            Ok(status) if status.success() => return,
            Ok(status) => panic!("executable readiness probe failed with {status}"),
            Err(error)
                if error.raw_os_error() == Some(ETXTBSY_OS_ERROR) && Instant::now() < deadline =>
            {
                thread::sleep(Duration::from_millis(1));
            }
            Err(error) => panic!("executable readiness probe failed: {error}"),
        }
    }
}
