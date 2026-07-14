use std::{
    io,
    path::{Path, PathBuf},
    sync::Arc,
};

use nazo_identity::{
    AvatarContentType, AvatarObject, UserId,
    ports::{AvatarStorageError, AvatarStorageFuture, AvatarStoragePort},
};
use serde::{Deserialize, Serialize};
use tokio::{
    fs::{self, OpenOptions},
    io::AsyncWriteExt,
    sync::{Mutex, OwnedMutexGuard},
};

const AVATAR_FILE_NAME: &str = "avatar.bin";
const METADATA_FILE_NAME: &str = "meta.json";
const LOCK_STRIPES: usize = 256;

#[derive(Clone)]
pub(crate) struct LocalAvatarStorage {
    root: Arc<PathBuf>,
    locks: Arc<Vec<Arc<Mutex<()>>>>,
}

pub(crate) struct LocalAvatarMutation {
    user_id: UserId,
    revision: String,
    _guard: OwnedMutexGuard<()>,
}

#[derive(Deserialize, Serialize)]
struct AvatarMetadata {
    content_type: String,
    version: String,
}

pub(crate) struct AvatarPromotion {
    pub(crate) avatar_file_path: PathBuf,
    pub(crate) avatar_meta_file_path: PathBuf,
    pub(crate) avatar_backup_path: PathBuf,
    pub(crate) avatar_meta_backup_path: PathBuf,
    pub(crate) avatar_backup_exists: bool,
    pub(crate) avatar_meta_backup_exists: bool,
}

impl LocalAvatarStorage {
    pub(crate) fn new(root: PathBuf) -> Self {
        let locks = (0..LOCK_STRIPES)
            .map(|_| Arc::new(Mutex::new(())))
            .collect();
        Self {
            root: Arc::new(root),
            locks: Arc::new(locks),
        }
    }

    fn user_dir(&self, user_id: UserId) -> PathBuf {
        self.root.join(user_id.as_uuid().to_string())
    }

    fn lock(&self, user_id: UserId) -> Arc<Mutex<()>> {
        let raw_user_id = user_id.as_uuid();
        let bytes = raw_user_id.as_bytes();
        let index = bytes.iter().fold(0usize, |value, byte| {
            value.wrapping_mul(31) ^ usize::from(*byte)
        }) % self.locks.len();
        self.locks[index].clone()
    }

    async fn ensure_user_dir(&self, user_id: UserId) -> Result<PathBuf, AvatarStorageError> {
        fs::create_dir_all(self.root.as_ref())
            .await
            .map_err(unavailable)?;
        reject_symlink(&self.root).await?;
        let user_dir = self.user_dir(user_id);
        match fs::create_dir(&user_dir).await {
            Ok(()) => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt as _;
                    fs::set_permissions(&user_dir, std::fs::Permissions::from_mode(0o700))
                        .await
                        .map_err(unavailable)?;
                }
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                reject_symlink(&user_dir).await?;
                let metadata = fs::metadata(&user_dir).await.map_err(unavailable)?;
                if !metadata.is_dir() {
                    return Err(AvatarStorageError::InvalidState);
                }
            }
            Err(error) => return Err(unavailable(error)),
        }
        Ok(user_dir)
    }

    async fn current_metadata(
        &self,
        user_dir: &Path,
    ) -> Result<Option<AvatarMetadata>, AvatarStorageError> {
        let path = user_dir.join(METADATA_FILE_NAME);
        reject_symlink_if_present(&path).await?;
        match fs::read(&path).await {
            Ok(raw) => serde_json::from_slice(&raw)
                .map(Some)
                .map_err(|_| AvatarStorageError::InvalidState),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(unavailable(error)),
        }
    }

    async fn read_object(
        &self,
        avatar_path: &Path,
        metadata_path: &Path,
        expected_version: &str,
    ) -> Result<AvatarObject, AvatarStorageError> {
        reject_symlink_if_present(metadata_path).await?;
        let raw = fs::read(metadata_path).await.map_err(|error| {
            if error.kind() == io::ErrorKind::NotFound {
                AvatarStorageError::Missing
            } else {
                unavailable(error)
            }
        })?;
        let metadata: AvatarMetadata =
            serde_json::from_slice(&raw).map_err(|_| AvatarStorageError::InvalidState)?;
        if metadata.version != expected_version {
            return Err(AvatarStorageError::InvalidState);
        }
        reject_symlink_if_present(avatar_path).await?;
        let bytes = fs::read(avatar_path).await.map_err(|error| {
            if error.kind() == io::ErrorKind::NotFound {
                AvatarStorageError::Missing
            } else {
                unavailable(error)
            }
        })?;
        let detected = AvatarContentType::detect(&bytes).ok_or(AvatarStorageError::InvalidState)?;
        if let Some(declared) = AvatarContentType::parse(&metadata.content_type)
            && declared != detected
        {
            return Err(AvatarStorageError::InvalidState);
        }
        Ok(AvatarObject {
            bytes,
            content_type: detected,
            version: metadata.version,
        })
    }

    async fn read_backup(
        &self,
        user_dir: &Path,
        expected_version: &str,
    ) -> Result<Option<AvatarObject>, AvatarStorageError> {
        let mut entries = fs::read_dir(user_dir).await.map_err(unavailable)?;
        let mut matched = None;
        while let Some(entry) = entries.next_entry().await.map_err(unavailable)? {
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            let Some(revision) = name
                .strip_prefix("meta-")
                .and_then(|name| name.strip_suffix(".bak"))
            else {
                continue;
            };
            let metadata_path = entry.path();
            let avatar_path = user_dir.join(format!("avatar-{revision}.bak"));
            match self
                .read_object(&avatar_path, &metadata_path, expected_version)
                .await
            {
                Ok(avatar) if matched.is_none() => matched = Some(avatar),
                Ok(_) => return Err(AvatarStorageError::InvalidState),
                Err(AvatarStorageError::Missing | AvatarStorageError::InvalidState) => {}
                Err(error) => return Err(error),
            }
        }
        Ok(matched)
    }

    async fn verify_expected_version(
        &self,
        user_dir: &Path,
        expected_version: Option<&str>,
    ) -> Result<(), AvatarStorageError> {
        let current = self.current_metadata(user_dir).await?;
        if current.as_ref().map(|metadata| metadata.version.as_str()) != expected_version {
            return Err(AvatarStorageError::Conflict);
        }
        let avatar_exists = path_exists_without_symlink(&user_dir.join(AVATAR_FILE_NAME)).await?;
        if current.is_some() != avatar_exists {
            return Err(AvatarStorageError::InvalidState);
        }
        Ok(())
    }

    async fn promotion_for(&self, mutation: &LocalAvatarMutation) -> AvatarPromotion {
        let user_dir = self.user_dir(mutation.user_id);
        let avatar_backup_path = user_dir.join(format!("avatar-{}.bak", mutation.revision));
        let avatar_meta_backup_path = user_dir.join(format!("meta-{}.bak", mutation.revision));
        AvatarPromotion {
            avatar_file_path: user_dir.join(AVATAR_FILE_NAME),
            avatar_meta_file_path: user_dir.join(METADATA_FILE_NAME),
            avatar_backup_exists: fs::try_exists(&avatar_backup_path).await.unwrap_or(true),
            avatar_meta_backup_exists: fs::try_exists(&avatar_meta_backup_path)
                .await
                .unwrap_or(true),
            avatar_backup_path,
            avatar_meta_backup_path,
        }
    }
}

impl AvatarStoragePort for LocalAvatarStorage {
    type Mutation = LocalAvatarMutation;

    fn begin_replace<'a>(
        &'a self,
        user_id: UserId,
        expected_version: Option<&'a str>,
        avatar: AvatarObject,
    ) -> AvatarStorageFuture<'a, Self::Mutation> {
        Box::pin(async move {
            let guard = self.lock(user_id).lock_owned().await;
            let user_dir = self
                .ensure_user_dir(user_id)
                .await
                .map_err(as_preparation_failure)?;
            self.verify_expected_version(&user_dir, expected_version)
                .await?;
            let mutation = LocalAvatarMutation {
                user_id,
                revision: avatar.version.clone(),
                _guard: guard,
            };
            let avatar_tmp_path = user_dir.join(format!("avatar-{}.tmp", avatar.version));
            let metadata_tmp_path = user_dir.join(format!("meta-{}.tmp", avatar.version));
            if let Err(error) = write_new_file(&avatar_tmp_path, &avatar.bytes).await {
                cleanup_avatar_temps(&avatar_tmp_path, &metadata_tmp_path).await;
                return Err(as_preparation_failure(error));
            }
            let metadata = serde_json::to_vec(&AvatarMetadata {
                content_type: avatar.content_type.as_str().to_owned(),
                version: avatar.version.clone(),
            })
            .map_err(|error| AvatarStorageError::PreparationFailed(error.to_string()))?;
            if let Err(error) = write_new_file(&metadata_tmp_path, &metadata).await {
                cleanup_avatar_temps(&avatar_tmp_path, &metadata_tmp_path).await;
                return Err(as_preparation_failure(error));
            }
            if let Err(error) = promote_avatar_files(
                &avatar_tmp_path,
                &metadata_tmp_path,
                user_dir.join(AVATAR_FILE_NAME),
                user_dir.join(METADATA_FILE_NAME),
                &avatar.version,
            )
            .await
            {
                return Err(unavailable(error));
            }
            Ok(mutation)
        })
    }

    fn begin_delete<'a>(
        &'a self,
        user_id: UserId,
        expected_version: Option<&'a str>,
        revision: &'a str,
    ) -> AvatarStorageFuture<'a, Self::Mutation> {
        Box::pin(async move {
            let guard = self.lock(user_id).lock_owned().await;
            let user_dir = self.ensure_user_dir(user_id).await?;
            self.verify_expected_version(&user_dir, expected_version)
                .await?;
            let mutation = LocalAvatarMutation {
                user_id,
                revision: revision.to_owned(),
                _guard: guard,
            };
            let avatar_path = user_dir.join(AVATAR_FILE_NAME);
            let metadata_path = user_dir.join(METADATA_FILE_NAME);
            let avatar_backup = user_dir.join(format!("avatar-{revision}.bak"));
            let metadata_backup = user_dir.join(format!("meta-{revision}.bak"));
            let avatar_exists = rename_avatar_file_if_exists(&avatar_path, &avatar_backup)
                .await
                .map_err(unavailable)?;
            if let Err(error) = rename_avatar_file_if_exists(&metadata_path, &metadata_backup).await
            {
                restore_avatar_backup(&avatar_backup, &avatar_path, avatar_exists).await;
                return Err(unavailable(error));
            }
            Ok(mutation)
        })
    }

    fn commit<'a>(&'a self, mutation: &'a Self::Mutation) -> AvatarStorageFuture<'a, ()> {
        Box::pin(async move {
            let promotion = self.promotion_for(mutation).await;
            finish_avatar_promotion(&promotion).await;
            let user_dir = self.user_dir(mutation.user_id);
            if !fs::try_exists(user_dir.join(AVATAR_FILE_NAME))
                .await
                .unwrap_or(true)
                && !fs::try_exists(user_dir.join(METADATA_FILE_NAME))
                    .await
                    .unwrap_or(true)
            {
                match fs::remove_dir(&user_dir).await {
                    Ok(()) => {}
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(error) => {
                        tracing::warn!(%error, "failed to remove empty avatar directory");
                    }
                }
            }
            Ok(())
        })
    }

    fn rollback<'a>(&'a self, mutation: &'a Self::Mutation) -> AvatarStorageFuture<'a, ()> {
        Box::pin(async move {
            let promotion = self.promotion_for(mutation).await;
            rollback_avatar_promotion(&promotion).await;
            Ok(())
        })
    }

    fn read<'a>(
        &'a self,
        user_id: UserId,
        expected_version: &'a str,
    ) -> AvatarStorageFuture<'a, AvatarObject> {
        Box::pin(async move {
            let _guard = self.lock(user_id).lock_owned().await;
            let user_dir = self.user_dir(user_id);
            reject_symlink(&self.root).await?;
            reject_symlink(&user_dir).await?;
            let result = self
                .read_object(
                    &user_dir.join(AVATAR_FILE_NAME),
                    &user_dir.join(METADATA_FILE_NAME),
                    expected_version,
                )
                .await;
            match result {
                Ok(avatar) => Ok(avatar),
                Err(primary @ (AvatarStorageError::Missing | AvatarStorageError::InvalidState)) => {
                    self.read_backup(&user_dir, expected_version)
                        .await?
                        .ok_or(primary)
                }
                Err(error) => Err(error),
            }
        })
    }
}

async fn write_new_file(path: &Path, bytes: &[u8]) -> Result<(), AvatarStorageError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .await
        .map_err(unavailable)?;
    file.write_all(bytes).await.map_err(unavailable)?;
    file.flush().await.map_err(unavailable)?;
    file.sync_all().await.map_err(unavailable)
}

async fn reject_symlink(path: &Path) -> Result<(), AvatarStorageError> {
    let metadata = fs::symlink_metadata(path).await.map_err(unavailable)?;
    if metadata.file_type().is_symlink() {
        Err(AvatarStorageError::InvalidState)
    } else {
        Ok(())
    }
}

async fn reject_symlink_if_present(path: &Path) -> Result<(), AvatarStorageError> {
    match fs::symlink_metadata(path).await {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(AvatarStorageError::InvalidState),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(unavailable(error)),
    }
}

async fn path_exists_without_symlink(path: &Path) -> Result<bool, AvatarStorageError> {
    match fs::symlink_metadata(path).await {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(AvatarStorageError::InvalidState),
        Ok(metadata) => Ok(metadata.is_file()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(unavailable(error)),
    }
}

fn unavailable(error: io::Error) -> AvatarStorageError {
    AvatarStorageError::Unavailable(error.to_string())
}

fn as_preparation_failure(error: AvatarStorageError) -> AvatarStorageError {
    match error {
        AvatarStorageError::Unavailable(message) => AvatarStorageError::PreparationFailed(message),
        error => error,
    }
}

pub(crate) async fn remove_avatar_file_if_exists(path: PathBuf) -> io::Result<()> {
    match fs::remove_file(path).await {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

pub(crate) async fn rename_avatar_file_if_exists(source: &Path, target: &Path) -> io::Result<bool> {
    match fs::rename(source, target).await {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

pub(crate) async fn cleanup_avatar_temps(avatar_tmp_path: &Path, avatar_meta_tmp_path: &Path) {
    let _ = fs::remove_file(avatar_tmp_path).await;
    let _ = fs::remove_file(avatar_meta_tmp_path).await;
}

pub(crate) async fn restore_avatar_backup(
    backup_path: &Path,
    final_path: &Path,
    backup_exists: bool,
) {
    if backup_exists
        && let Err(error) = fs::rename(backup_path, final_path).await
        && error.kind() != io::ErrorKind::NotFound
    {
        tracing::warn!(%error, "failed to restore previous avatar file");
    }
}

pub(crate) async fn rollback_avatar_promotion(promotion: &AvatarPromotion) {
    let _ = fs::remove_file(&promotion.avatar_file_path).await;
    let _ = fs::remove_file(&promotion.avatar_meta_file_path).await;
    restore_avatar_backup(
        &promotion.avatar_backup_path,
        &promotion.avatar_file_path,
        promotion.avatar_backup_exists,
    )
    .await;
    restore_avatar_backup(
        &promotion.avatar_meta_backup_path,
        &promotion.avatar_meta_file_path,
        promotion.avatar_meta_backup_exists,
    )
    .await;
}

pub(crate) async fn finish_avatar_promotion(promotion: &AvatarPromotion) {
    let _ = remove_avatar_file_if_exists(promotion.avatar_backup_path.clone()).await;
    let _ = remove_avatar_file_if_exists(promotion.avatar_meta_backup_path.clone()).await;
}

async fn rollback_avatar_promotion_attempt(
    avatar_tmp_path: &Path,
    avatar_meta_tmp_path: &Path,
    promotion: &AvatarPromotion,
) {
    cleanup_avatar_temps(avatar_tmp_path, avatar_meta_tmp_path).await;
    rollback_avatar_promotion(promotion).await;
}

pub(crate) async fn promote_avatar_files(
    avatar_tmp_path: &Path,
    avatar_meta_tmp_path: &Path,
    avatar_file_path: PathBuf,
    avatar_meta_file_path: PathBuf,
    version: &str,
) -> io::Result<AvatarPromotion> {
    let avatar_backup_path = avatar_file_path.with_file_name(format!("avatar-{version}.bak"));
    let avatar_meta_backup_path =
        avatar_meta_file_path.with_file_name(format!("meta-{version}.bak"));
    let avatar_backup_exists =
        rename_avatar_file_if_exists(&avatar_file_path, &avatar_backup_path).await?;
    let avatar_meta_backup_exists = match rename_avatar_file_if_exists(
        &avatar_meta_file_path,
        &avatar_meta_backup_path,
    )
    .await
    {
        Ok(value) => value,
        Err(error) => {
            restore_avatar_backup(&avatar_backup_path, &avatar_file_path, avatar_backup_exists)
                .await;
            cleanup_avatar_temps(avatar_tmp_path, avatar_meta_tmp_path).await;
            return Err(error);
        }
    };
    let promotion = AvatarPromotion {
        avatar_file_path,
        avatar_meta_file_path,
        avatar_backup_path,
        avatar_meta_backup_path,
        avatar_backup_exists,
        avatar_meta_backup_exists,
    };
    if let Err(error) = fs::rename(avatar_tmp_path, &promotion.avatar_file_path).await {
        rollback_avatar_promotion_attempt(avatar_tmp_path, avatar_meta_tmp_path, &promotion).await;
        return Err(error);
    }
    if let Err(error) = fs::rename(avatar_meta_tmp_path, &promotion.avatar_meta_file_path).await {
        rollback_avatar_promotion_attempt(avatar_tmp_path, avatar_meta_tmp_path, &promotion).await;
        return Err(error);
    }
    Ok(promotion)
}
