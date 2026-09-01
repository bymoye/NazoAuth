use std::{
    fs::{File, OpenOptions},
    path::Path,
};

use anyhow::Context as _;
use fs2::FileExt as _;

pub(crate) async fn acquire_keyset_lock(keys_dir: &Path) -> anyhow::Result<File> {
    tokio::fs::create_dir_all(keys_dir)
        .await
        .with_context(|| format!("failed to create key directory {}", keys_dir.display()))?;
    let lock_path = keys_dir.join(".keyset.lock");
    tokio::task::spawn_blocking(move || -> anyhow::Result<File> {
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&lock_path)
            .with_context(|| format!("failed to open keyset lock {}", lock_path.display()))?;
        lock.lock_exclusive()
            .with_context(|| format!("failed to acquire keyset lock {}", lock_path.display()))?;
        Ok(lock)
    })
    .await
    .context("keyset lock task failed")?
}

#[cfg(test)]
#[path = "../tests/unit/lock.rs"]
mod tests;
