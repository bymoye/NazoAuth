use uuid::Uuid;

use crate::{
    AccountOverview, PublicAccount,
    ports::{
        AvatarRepositoryPort, AvatarStorageError, AvatarStoragePort, GrantSummaryRepositoryPort,
        RepositoryError,
    },
};

const AVATAR_URL_PREFIX: &str = "/auth/me/avatar?v=";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AvatarContentType {
    Png,
    Jpeg,
    Webp,
}

impl AvatarContentType {
    #[must_use]
    pub fn detect(bytes: &[u8]) -> Option<Self> {
        if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
            Some(Self::Png)
        } else if bytes.starts_with(b"\xff\xd8\xff") {
            Some(Self::Jpeg)
        } else if bytes.len() >= 12 && &bytes[..4] == b"RIFF" && &bytes[8..12] == b"WEBP" {
            Some(Self::Webp)
        } else {
            None
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Png => "image/png",
            Self::Jpeg => "image/jpeg",
            Self::Webp => "image/webp",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "image/png" => Some(Self::Png),
            "image/jpeg" => Some(Self::Jpeg),
            "image/webp" => Some(Self::Webp),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AvatarObject {
    pub bytes: Vec<u8>,
    pub content_type: AvatarContentType,
    pub version: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UploadAvatarError {
    TooLarge,
    UnsupportedContent,
    InvalidCurrentReference,
    ConcurrentChange,
    Storage(AvatarStorageError),
    Repository(RepositoryError),
    Overview(RepositoryError),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReadAvatarError {
    NotUploaded,
    InvalidReference,
    Storage(AvatarStorageError),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DeleteAvatarError {
    InvalidCurrentReference,
    ConcurrentChange,
    Storage(AvatarStorageError),
    Repository(RepositoryError),
    Overview(RepositoryError),
}

#[derive(Clone)]
pub struct AvatarService<R, G, S> {
    avatars: R,
    grants: G,
    storage: S,
    max_bytes: usize,
}

impl<R, G, S> AvatarService<R, G, S>
where
    R: AvatarRepositoryPort,
    G: GrantSummaryRepositoryPort,
    S: AvatarStoragePort,
{
    pub fn new(avatars: R, grants: G, storage: S, max_bytes: usize) -> Self {
        Self {
            avatars,
            grants,
            storage,
            max_bytes,
        }
    }

    #[must_use]
    pub const fn max_bytes(&self) -> usize {
        self.max_bytes
    }

    pub async fn upload(
        &self,
        account: &PublicAccount,
        bytes: Vec<u8>,
    ) -> Result<AccountOverview, UploadAvatarError> {
        if bytes.len() > self.max_bytes {
            return Err(UploadAvatarError::TooLarge);
        }
        let content_type =
            AvatarContentType::detect(&bytes).ok_or(UploadAvatarError::UnsupportedContent)?;
        let expected_url = account.profile.avatar_url.as_deref();
        let expected_version = expected_url
            .map(avatar_url_version)
            .transpose()
            .map_err(|()| UploadAvatarError::InvalidCurrentReference)?;
        let version = Uuid::now_v7().to_string();
        let mutation = self
            .storage
            .begin_replace(
                account.user_id(),
                expected_version,
                AvatarObject {
                    bytes,
                    content_type,
                    version: version.clone(),
                },
            )
            .await
            .map_err(map_upload_storage_error)?;
        let avatar_url = format!("{AVATAR_URL_PREFIX}{version}");
        let updated = self
            .avatars
            .compare_and_set_avatar(
                account.tenant().tenant_id,
                account.user_id(),
                expected_url,
                Some(avatar_url),
            )
            .await;
        let updated = match updated {
            Ok(Some(updated)) => updated,
            Ok(None) => {
                rollback_after_failed_write(&self.storage, &mutation).await;
                return Err(UploadAvatarError::ConcurrentChange);
            }
            Err(error) => {
                rollback_after_failed_write(&self.storage, &mutation).await;
                return Err(UploadAvatarError::Repository(error));
            }
        };
        self.storage
            .commit(&mutation)
            .await
            .map_err(UploadAvatarError::Storage)?;
        drop(mutation);
        self.overview(updated)
            .await
            .map_err(UploadAvatarError::Overview)
    }

    pub async fn read(&self, account: &PublicAccount) -> Result<AvatarObject, ReadAvatarError> {
        let avatar_url = account
            .profile
            .avatar_url
            .as_deref()
            .ok_or(ReadAvatarError::NotUploaded)?;
        let version =
            avatar_url_version(avatar_url).map_err(|()| ReadAvatarError::InvalidReference)?;
        self.storage
            .read(account.user_id(), version)
            .await
            .map_err(ReadAvatarError::Storage)
    }

    pub async fn delete(
        &self,
        account: &PublicAccount,
    ) -> Result<AccountOverview, DeleteAvatarError> {
        let expected_url = account.profile.avatar_url.as_deref();
        let expected_version = expected_url
            .map(avatar_url_version)
            .transpose()
            .map_err(|()| DeleteAvatarError::InvalidCurrentReference)?;
        let revision = Uuid::now_v7().to_string();
        let mutation = self
            .storage
            .begin_delete(account.user_id(), expected_version, &revision)
            .await
            .map_err(map_delete_storage_error)?;
        let updated = self
            .avatars
            .compare_and_set_avatar(
                account.tenant().tenant_id,
                account.user_id(),
                expected_url,
                None,
            )
            .await;
        let updated = match updated {
            Ok(Some(updated)) => updated,
            Ok(None) => {
                rollback_after_failed_write(&self.storage, &mutation).await;
                return Err(DeleteAvatarError::ConcurrentChange);
            }
            Err(error) => {
                rollback_after_failed_write(&self.storage, &mutation).await;
                return Err(DeleteAvatarError::Repository(error));
            }
        };
        self.storage
            .commit(&mutation)
            .await
            .map_err(DeleteAvatarError::Storage)?;
        drop(mutation);
        self.overview(updated)
            .await
            .map_err(DeleteAvatarError::Overview)
    }

    async fn overview(&self, account: PublicAccount) -> Result<AccountOverview, RepositoryError> {
        let authorized_application_count =
            self.grants.authorized_client_count(account.id()).await?;
        Ok(AccountOverview {
            account,
            authorized_application_count,
        })
    }
}

fn avatar_url_version(avatar_url: &str) -> Result<&str, ()> {
    avatar_url
        .strip_prefix(AVATAR_URL_PREFIX)
        .filter(|version| !version.is_empty() && !version.contains(['&', '#', '/', '?']))
        .ok_or(())
}

fn map_upload_storage_error(error: AvatarStorageError) -> UploadAvatarError {
    if error == AvatarStorageError::Conflict {
        UploadAvatarError::ConcurrentChange
    } else {
        UploadAvatarError::Storage(error)
    }
}

fn map_delete_storage_error(error: AvatarStorageError) -> DeleteAvatarError {
    if error == AvatarStorageError::Conflict {
        DeleteAvatarError::ConcurrentChange
    } else {
        DeleteAvatarError::Storage(error)
    }
}

async fn rollback_after_failed_write<S: AvatarStoragePort>(storage: &S, mutation: &S::Mutation) {
    // Persistence failure is already the primary operation error. Adapters retain
    // backup material when rollback cannot complete, allowing operator recovery.
    let _rollback_result = storage.rollback(mutation).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn avatar_reference_rejects_extra_query_or_path_components() {
        assert_eq!(avatar_url_version("/auth/me/avatar?v=v1"), Ok("v1"));
        assert!(avatar_url_version("/auth/me/avatar?v=v1&x=1").is_err());
        assert!(avatar_url_version("/auth/me/avatar?v=../x").is_err());
        assert!(avatar_url_version("https://example.com/avatar?v=v1").is_err());
    }

    #[test]
    fn content_detection_uses_file_signatures() {
        assert_eq!(
            AvatarContentType::detect(b"\x89PNG\r\n\x1a\nrest"),
            Some(AvatarContentType::Png)
        );
        assert_eq!(
            AvatarContentType::detect(b"\xff\xd8\xffrest"),
            Some(AvatarContentType::Jpeg)
        );
        assert_eq!(
            AvatarContentType::detect(b"RIFFxxxxWEBPrest"),
            Some(AvatarContentType::Webp)
        );
        assert_eq!(AvatarContentType::detect(b"not-an-image"), None);
    }
}
