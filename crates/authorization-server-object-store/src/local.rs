use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use chrono::{DateTime, Utc};
use nazo_identity::{
    AvatarContentType, AvatarObject, TenantId,
    ports::{
        AvatarDirectUploadPort, AvatarStagedObject, AvatarStorageError, AvatarStorageFuture,
        AvatarUploadTarget,
    },
};
use nazo_oauth_server::bootstrap::{
    ServerAvatarObjectStoreProvider, ServerAvatarStorageCapability,
};
use tokio::fs;

const STAGING_DIRECTORY: &str = "staging";
const FINAL_DIRECTORY: &str = "final";
const OBJECT_FILE: &str = "object";
const CONTENT_TYPE_FILE: &str = "content-type";

/// Filesystem-backed object storage used when the server receives multipart
/// bytes itself. Browser-direct uploads deliberately remain unavailable.
#[derive(Clone)]
pub struct LocalAvatarObjectStore {
    root: Arc<PathBuf>,
}

impl LocalAvatarObjectStore {
    #[must_use]
    pub fn new(root: PathBuf) -> Self {
        Self {
            root: Arc::new(root),
        }
    }

    fn staging_path(&self, object_id: &str) -> Result<PathBuf, AvatarStorageError> {
        safe_object_id(object_id)?;
        Ok(self.root.join(STAGING_DIRECTORY).join(object_id))
    }

    fn final_path(&self, object_id: &str) -> Result<PathBuf, AvatarStorageError> {
        safe_object_id(object_id)?;
        Ok(self.root.join(FINAL_DIRECTORY).join(object_id))
    }
}

/// Composition provider for the existing server-multipart avatar path.
#[derive(Clone, Copy, Debug, Default)]
pub struct LocalAvatarObjectStoreProvider;

impl ServerAvatarObjectStoreProvider for LocalAvatarObjectStoreProvider {
    fn for_tenant(&self, _tenant_id: TenantId) -> ServerAvatarStorageCapability {
        ServerAvatarStorageCapability::Local
    }
}

impl AvatarDirectUploadPort for LocalAvatarObjectStore {
    fn authorize_upload<'a>(
        &'a self,
        _staging_object_id: &'a str,
        _max_bytes: usize,
        _expires_at: DateTime<Utc>,
    ) -> AvatarStorageFuture<'a, AvatarUploadTarget> {
        Box::pin(async { Err(AvatarStorageError::Unsupported) })
    }

    fn read_staged<'a>(
        &'a self,
        staging_object_id: &'a str,
        max_bytes: usize,
    ) -> AvatarStorageFuture<'a, AvatarStagedObject> {
        Box::pin(async move {
            let path = self.staging_path(staging_object_id)?;
            let bytes = read_bounded(&path, max_bytes).await?;
            Ok(AvatarStagedObject {
                version: version(&bytes),
                bytes,
            })
        })
    }

    fn publish_staged<'a>(
        &'a self,
        staging_object_id: &'a str,
        expected_version: &'a str,
        final_object_id: &'a str,
        content_type: AvatarContentType,
    ) -> AvatarStorageFuture<'a, ()> {
        Box::pin(async move {
            let staged_path = self.staging_path(staging_object_id)?;
            let bytes = read_unbounded(&staged_path).await?;
            if version(&bytes) != expected_version {
                return Err(AvatarStorageError::Conflict);
            }

            let final_path = self.final_path(final_object_id)?;
            fs::create_dir_all(
                final_path
                    .parent()
                    .expect("final object path always has a parent"),
            )
            .await
            .map_err(unavailable)?;
            match fs::create_dir(&final_path).await {
                Ok(()) => {
                    fs::write(final_path.join(OBJECT_FILE), &bytes)
                        .await
                        .map_err(unavailable)?;
                    fs::write(final_path.join(CONTENT_TYPE_FILE), content_type.as_str())
                        .await
                        .map_err(unavailable)
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    existing_final_matches(&final_path, &bytes, content_type).await
                }
                Err(error) => Err(unavailable(error)),
            }
        })
    }

    fn read_final<'a>(&'a self, final_object_id: &'a str) -> AvatarStorageFuture<'a, AvatarObject> {
        Box::pin(async move {
            let final_path = self.final_path(final_object_id)?;
            let bytes = read_unbounded(&final_path.join(OBJECT_FILE)).await?;
            let content_type = fs::read_to_string(final_path.join(CONTENT_TYPE_FILE))
                .await
                .map_err(map_read_error)
                .and_then(|value| {
                    AvatarContentType::parse(value.trim()).ok_or(AvatarStorageError::InvalidState)
                })?;
            Ok(AvatarObject {
                bytes,
                content_type,
                version: final_object_id.to_owned(),
            })
        })
    }

    fn delete_staging<'a>(&'a self, staging_object_id: &'a str) -> AvatarStorageFuture<'a, ()> {
        Box::pin(async move {
            let path = self.staging_path(staging_object_id)?;
            match fs::remove_file(path).await {
                Ok(()) => Ok(()),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(error) => Err(unavailable(error)),
            }
        })
    }

    fn delete_final<'a>(&'a self, final_object_id: &'a str) -> AvatarStorageFuture<'a, ()> {
        Box::pin(async move {
            let path = self.final_path(final_object_id)?;
            match fs::remove_dir_all(path).await {
                Ok(()) => Ok(()),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(error) => Err(unavailable(error)),
            }
        })
    }
}

async fn existing_final_matches(
    final_path: &Path,
    expected_bytes: &[u8],
    expected_content_type: AvatarContentType,
) -> Result<(), AvatarStorageError> {
    let bytes = read_unbounded(&final_path.join(OBJECT_FILE)).await?;
    let content_type = fs::read_to_string(final_path.join(CONTENT_TYPE_FILE))
        .await
        .map_err(map_read_error)
        .and_then(|value| {
            AvatarContentType::parse(value.trim()).ok_or(AvatarStorageError::InvalidState)
        })?;
    if bytes == expected_bytes && content_type == expected_content_type {
        Ok(())
    } else {
        Err(AvatarStorageError::Conflict)
    }
}

async fn read_bounded(path: &Path, max_bytes: usize) -> Result<Vec<u8>, AvatarStorageError> {
    let metadata = fs::metadata(path).await.map_err(map_read_error)?;
    if metadata.len() > max_bytes as u64 {
        return Err(AvatarStorageError::InvalidState);
    }
    read_unbounded(path).await
}

async fn read_unbounded(path: &Path) -> Result<Vec<u8>, AvatarStorageError> {
    fs::read(path).await.map_err(map_read_error)
}

fn map_read_error(error: std::io::Error) -> AvatarStorageError {
    if error.kind() == std::io::ErrorKind::NotFound {
        AvatarStorageError::Missing
    } else {
        unavailable(error)
    }
}

fn unavailable(error: std::io::Error) -> AvatarStorageError {
    AvatarStorageError::Unavailable(error.to_string())
}

fn safe_object_id(object_id: &str) -> Result<(), AvatarStorageError> {
    if object_id.is_empty()
        || !object_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(AvatarStorageError::InvalidState);
    }
    Ok(())
}

fn version(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}
