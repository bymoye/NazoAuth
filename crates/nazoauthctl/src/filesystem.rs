use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

use anyhow::{Context, bail};
use sha2::{Digest, Sha256};

pub(crate) struct PrivateTempDir {
    path: PathBuf,
}

impl PrivateTempDir {
    pub(crate) fn new(prefix: &str) -> anyhow::Result<Self> {
        let root = std::env::temp_dir();
        for _ in 0..32 {
            let suffix = hex(&rand::random::<[u8; 12]>());
            let path = root.join(format!("{prefix}.{suffix}"));
            match fs::create_dir(&path) {
                Ok(()) => {
                    set_mode(&path, 0o700)?;
                    return Ok(Self { path });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => {
                    return Err(error)
                        .with_context(|| format!("failed to create {}", path.display()));
                }
            }
        }
        bail!("failed to allocate a unique private temporary directory")
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for PrivateTempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

pub(crate) fn atomic_write(path: &Path, bytes: &[u8], mode: u32) -> anyhow::Result<()> {
    let parent = path
        .parent()
        .context("atomic-write target has no parent directory")?;
    fs::create_dir_all(parent).with_context(|| format!("failed to create {}", parent.display()))?;
    let temporary = path.with_extension(format!("tmp-{}", std::process::id()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    let mut file = options
        .open(&temporary)
        .with_context(|| format!("failed to create {}", temporary.display()))?;
    set_file_mode(&file, mode)?;
    file.write_all(bytes)
        .with_context(|| format!("failed to write {}", temporary.display()))?;
    file.sync_all()
        .with_context(|| format!("failed to persist {}", temporary.display()))?;
    fs::rename(&temporary, path)
        .with_context(|| format!("failed to activate {}", path.display()))?;
    sync_parent(path)?;
    Ok(())
}

pub(crate) fn remove_file_durable(path: &Path) -> anyhow::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => sync_parent(path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("failed to remove {}", path.display())),
    }
}

#[cfg(unix)]
fn sync_parent(path: &Path) -> anyhow::Result<()> {
    let parent = path.parent().context("path has no parent directory")?;
    File::open(parent)
        .with_context(|| format!("failed to open {} for synchronization", parent.display()))?
        .sync_all()
        .with_context(|| format!("failed to synchronize {}", parent.display()))
}

#[cfg(not(unix))]
fn sync_parent(_path: &Path) -> anyhow::Result<()> {
    Ok(())
}

pub(crate) fn copy_atomic(source: &Path, target: &Path, mode: u32) -> anyhow::Result<()> {
    let bytes = fs::read(source).with_context(|| format!("failed to read {}", source.display()))?;
    atomic_write(target, &bytes, mode)
}

pub(crate) fn generate_secret(path: &Path) -> anyhow::Result<String> {
    if path.exists() {
        let metadata = fs::symlink_metadata(path)
            .with_context(|| format!("failed to inspect persisted secret {}", path.display()))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            bail!("persisted secret is not a regular file: {}", path.display());
        }
        let value = fs::read_to_string(path)
            .with_context(|| format!("failed to read persisted secret {}", path.display()))?;
        if value.is_empty() || value.contains(['\n', '\r']) {
            bail!("persisted secret is invalid: {}", path.display());
        }
        return Ok(value);
    }
    let value = hex(&rand::random::<[u8; 32]>());
    atomic_write(path, value.as_bytes(), 0o440)?;
    Ok(value)
}

pub(crate) fn sha256(path: &Path) -> anyhow::Result<String> {
    let mut file =
        File::open(path).with_context(|| format!("failed to open {}", path.display()))?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .with_context(|| format!("failed to hash {}", path.display()))?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(hex(&digest.finalize()))
}

#[cfg(unix)]
pub(crate) fn set_mode(path: &Path, mode: u32) -> anyhow::Result<()> {
    let file = OpenOptions::new()
        .read(true)
        .open(path)
        .with_context(|| format!("failed to open {}", path.display()))?;
    set_file_mode(&file, mode)
}

#[cfg(not(unix))]
pub(crate) fn set_mode(_path: &Path, _mode: u32) -> anyhow::Result<()> {
    Ok(())
}

fn set_file_mode(file: &File, mode: u32) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(mode))
            .context("failed to set file permissions")?;
    }
    #[cfg(not(unix))]
    let _ = (file, mode);
    Ok(())
}

pub(crate) fn symlink_atomic(target: &Path, link: &Path) -> anyhow::Result<()> {
    let next = link.with_extension(format!("next-{}", std::process::id()));
    if next.exists() || next.is_symlink() {
        fs::remove_file(&next)
            .with_context(|| format!("failed to clear stale symlink {}", next.display()))?;
    }
    create_symlink(target, &next)?;
    fs::rename(&next, link)
        .with_context(|| format!("failed to activate symlink {}", link.display()))?;
    sync_parent(link)
}

#[cfg(unix)]
fn create_symlink(target: &Path, link: &Path) -> anyhow::Result<()> {
    std::os::unix::fs::symlink(target, link)
        .with_context(|| format!("failed to create symlink {}", link.display()))
}

#[cfg(windows)]
fn create_symlink(target: &Path, link: &Path) -> anyhow::Result<()> {
    if target.is_dir() {
        std::os::windows::fs::symlink_dir(target, link)
    } else {
        std::os::windows::fs::symlink_file(target, link)
    }
    .with_context(|| format!("failed to create symlink {}", link.display()))
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    output
}
