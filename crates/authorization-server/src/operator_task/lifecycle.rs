use super::*;

pub(super) async fn acquire_task_lock(lock: std::fs::File) -> anyhow::Result<std::fs::File> {
    acquire_task_lock_with_timeout(lock, TASK_LOCK_TIMEOUT).await
}

pub(super) fn can_reenter_migration(operation: &TaskOperation, lifecycle: &TaskLifecycle) -> bool {
    matches!(
        (operation, lifecycle),
        (TaskOperation::MigrateApply, TaskLifecycle::Executing { .. })
    )
}

pub(super) async fn acquire_task_lock_with_timeout(
    lock: std::fs::File,
    timeout: Duration,
) -> anyhow::Result<std::fs::File> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        match lock.try_lock_exclusive() {
            Ok(()) => return Ok(lock),
            Err(error) if task_lock_is_contended(&error) => {
                if tokio::time::Instant::now() >= deadline {
                    bail!("operator task lock acquisition timed out");
                }
                tokio::time::sleep(TASK_LOCK_RETRY_INTERVAL).await;
            }
            Err(error) => return Err(error).context("failed to acquire operator task lock"),
        }
    }
}

pub(super) fn task_lock_is_contended(error: &std::io::Error) -> bool {
    error.kind() == std::io::ErrorKind::WouldBlock
        || cfg!(windows) && error.raw_os_error() == Some(33)
}

pub(super) fn claim_request(path: &Path, digest: &str) -> anyhow::Result<RequestClaim> {
    let parent = path
        .parent()
        .context("request claim has no state directory")?;
    let temporary = parent.join(format!(
        ".request-claim-{}-{:032x}.tmp",
        std::process::id(),
        rand::random::<u128>()
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    file.write_all(format!("{REQUEST_CLAIM_PREFIX}{digest}\n").as_bytes())?;
    file.sync_all()?;
    drop(file);

    let publish = fs::hard_link(&temporary, path);
    let cleanup = fs::remove_file(&temporary);
    if let Err(error) = cleanup {
        return Err(error).context("failed to remove temporary request claim");
    }
    match publish {
        Ok(()) => {
            sync_directory(parent)?;
            Ok(RequestClaim::Created)
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let claim = fs::read_to_string(path)?;
            if claim.trim() == format!("{REQUEST_CLAIM_PREFIX}{digest}") {
                Ok(RequestClaim::Current)
            } else if claim.trim() == digest {
                Ok(RequestClaim::Legacy)
            } else {
                bail!("request identifier was already claimed by a different envelope")
            }
        }
        Err(error) => Err(error.into()),
    }
}

pub(super) fn load_or_prepare_lifecycle(
    path: &Path,
    request_sha256: &str,
) -> anyhow::Result<TaskLifecycle> {
    let lifecycle = if regular_state_file_present(path, "operator task lifecycle")? {
        Some(read_lifecycle(path)?)
    } else {
        None
    };
    if let Some(ref lifecycle) = lifecycle {
        ensure_lifecycle_digest(lifecycle, request_sha256)?;
    }

    let temporary = lifecycle_temporary_path(path);
    if state_path_present(&temporary)? {
        regular_state_file_present(&temporary, "operator task lifecycle temporary")?;
        let temporary_lifecycle = read_lifecycle(&temporary)
            .context("operator task lifecycle has an incomplete durable transition")?;
        ensure_lifecycle_digest(&temporary_lifecycle, request_sha256)?;
        match lifecycle.as_ref() {
            Some(existing)
                if matches!(existing, TaskLifecycle::Prepared { .. })
                    && existing == &temporary_lifecycle =>
            {
                // A fully written duplicate of Prepared can only be left by
                // the create-new/hard-link publication window.  It crossed no
                // execution boundary, so remove the duplicate and continue.
                fs::remove_file(&temporary)?;
                sync_directory(
                    path.parent()
                        .context("operator task lifecycle has no state directory")?,
                )?;
            }
            None if matches!(temporary_lifecycle, TaskLifecycle::Prepared { .. }) => {
                // The process died before publishing the first Prepared
                // record.  Recreating that record is safe because execution
                // has not started.
                fs::remove_file(&temporary)?;
                sync_directory(
                    path.parent()
                        .context("operator task lifecycle has no state directory")?,
                )?;
            }
            _ => bail!(
                "operator task lifecycle has an incomplete durable transition; refusing recovery"
            ),
        }
    }

    if let Some(lifecycle) = lifecycle {
        return Ok(lifecycle);
    }

    let lifecycle = TaskLifecycle::Prepared {
        request_sha256: request_sha256.to_owned(),
    };
    write_initial_lifecycle(path, &lifecycle)?;
    Ok(lifecycle)
}

pub(super) fn read_lifecycle(path: &Path) -> anyhow::Result<TaskLifecycle> {
    serde_json::from_slice(&fs::read(path)?).context("operator task lifecycle is invalid")
}

pub(super) fn ensure_lifecycle_digest(
    lifecycle: &TaskLifecycle,
    request_sha256: &str,
) -> anyhow::Result<()> {
    let actual = match lifecycle {
        TaskLifecycle::Prepared { request_sha256 }
        | TaskLifecycle::Executing { request_sha256 }
        | TaskLifecycle::Completed { request_sha256 } => request_sha256,
    };
    if actual == request_sha256 {
        Ok(())
    } else {
        bail!("operator task lifecycle belongs to a different envelope")
    }
}

pub(super) fn ensure_current_claim(claim: RequestClaim) -> anyhow::Result<()> {
    if claim == RequestClaim::Legacy {
        bail!("legacy request claim has no runtime receipt; refusing unknown privileged outcome");
    }
    Ok(())
}

pub(super) fn mark_task_executing(
    path: &Path,
    lifecycle: &TaskLifecycle,
    request_sha256: &str,
) -> anyhow::Result<()> {
    ensure_lifecycle_digest(lifecycle, request_sha256)?;
    match lifecycle {
        TaskLifecycle::Prepared { .. } => write_lifecycle_atomic(
            path,
            &TaskLifecycle::Executing {
                request_sha256: request_sha256.to_owned(),
            },
        ),
        TaskLifecycle::Executing { .. } => bail!(
            "operator task may have executed without a receipt; refusing to replay privileged action"
        ),
        TaskLifecycle::Completed { .. } => {
            bail!("operator task completed without a receipt; refusing to replay privileged action")
        }
    }
}

pub(super) fn write_initial_lifecycle(
    path: &Path,
    lifecycle: &TaskLifecycle,
) -> anyhow::Result<()> {
    let parent = path
        .parent()
        .context("operator task lifecycle has no state directory")?;
    let temporary = lifecycle_temporary_path(path);
    if state_path_present(&temporary)? {
        bail!("operator task lifecycle has an incomplete durable transition; refusing recovery");
    }
    let bytes = serde_json::to_vec(lifecycle)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    drop(file);

    match fs::hard_link(&temporary, path) {
        Ok(()) => {
            fs::remove_file(&temporary)?;
            sync_directory(parent)
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            // This temporary file was completely written by this process and
            // has not crossed an execution boundary.  It is safe to remove;
            // unlike a pre-existing temporary file, it cannot conceal a
            // killed execution or receipt publication.
            fs::remove_file(&temporary)?;
            Err(error.into())
        }
        Err(error) => Err(error.into()),
    }
}

pub(super) fn write_lifecycle_atomic(path: &Path, lifecycle: &TaskLifecycle) -> anyhow::Result<()> {
    let parent = path
        .parent()
        .context("operator task lifecycle has no state directory")?;
    let temporary = lifecycle_temporary_path(path);
    if state_path_present(&temporary)? {
        bail!("operator task lifecycle has an incomplete durable transition; refusing recovery");
    }
    let bytes = serde_json::to_vec(lifecycle)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    drop(file);
    fs::rename(&temporary, path)?;
    sync_directory(parent)
}

pub(super) fn lifecycle_temporary_path(path: &Path) -> PathBuf {
    path.with_extension("lifecycle.json.tmp")
}
