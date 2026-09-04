use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use crate::{
    AccountOverview, PublicAccount,
    ports::{
        AvatarDirectUploadPort, AvatarRepositoryPort, AvatarStorageError, AvatarStoragePort,
        AvatarUploadAuthorization, AvatarUploadClaim, AvatarUploadStatePort, AvatarUploadTarget,
        GrantSummaryRepositoryPort, RepositoryError,
    },
};

const AVATAR_URL_PREFIX: &str = "/auth/me/avatar?v=";

fn avatar_url(final_object_id: &str) -> String {
    format!("{AVATAR_URL_PREFIX}{final_object_id}")
}

fn final_object_id(upload_id: &str, bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let encoded = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("{upload_id}-{encoded}")
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AvatarContentType {
    Png,
    Jpeg,
    Webp,
}

impl AvatarContentType {
    #[must_use]
    pub fn detect(bytes: &[u8]) -> Option<Self> {
        const MAX_DIMENSION: u32 = 4_096;
        let mut reader = image::ImageReader::new(std::io::Cursor::new(bytes));
        reader = reader.with_guessed_format().ok()?;
        let format = reader.format()?;
        let content_type = match format {
            image::ImageFormat::Png => Self::Png,
            image::ImageFormat::Jpeg => Self::Jpeg,
            image::ImageFormat::WebP => Self::Webp,
            _ => return None,
        };
        let mut limits = image::Limits::default();
        limits.max_image_width = Some(MAX_DIMENSION);
        limits.max_image_height = Some(MAX_DIMENSION);
        limits.max_alloc = Some(u64::from(MAX_DIMENSION) * u64::from(MAX_DIMENSION) * 4);
        reader.limits(limits);
        reader.decode().ok().map(|_| content_type)
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AvatarUploadStart {
    pub upload_id: String,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub target: AvatarUploadTarget,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DirectAvatarUploadError {
    InvalidContentLength,
    TooLarge,
    InvalidCurrentReference,
    Missing,
    Expired,
    Busy,
    ConcurrentChange,
    UnsupportedContent,
    Storage(AvatarStorageError),
    State(RepositoryError),
    Repository(RepositoryError),
    Overview(RepositoryError),
}

/// Direct-upload avatar flow. Object storage receives bytes only from the
/// browser; this service reads the bounded staged snapshot once to validate it
/// and asks the provider to publish that exact snapshot server-side.
#[derive(Clone)]
pub struct AvatarDirectUploadService {
    avatars: std::sync::Arc<dyn AvatarRepositoryPort>,
    grants: std::sync::Arc<dyn GrantSummaryRepositoryPort>,
    storage: std::sync::Arc<dyn AvatarDirectUploadPort>,
    state: std::sync::Arc<dyn AvatarUploadStatePort>,
    max_bytes: usize,
    upload_ttl_seconds: u64,
    claim_lease_seconds: u64,
}

impl AvatarDirectUploadService {
    pub fn from_ports(
        avatars: std::sync::Arc<dyn AvatarRepositoryPort>,
        grants: std::sync::Arc<dyn GrantSummaryRepositoryPort>,
        storage: std::sync::Arc<dyn AvatarDirectUploadPort>,
        state: std::sync::Arc<dyn AvatarUploadStatePort>,
        max_bytes: usize,
        upload_ttl_seconds: u64,
        claim_lease_seconds: u64,
    ) -> Self {
        Self {
            avatars,
            grants,
            storage,
            state,
            max_bytes,
            upload_ttl_seconds,
            claim_lease_seconds,
        }
    }

    #[must_use]
    pub const fn max_bytes(&self) -> usize {
        self.max_bytes
    }

    /// Starts one direct upload authorization for the exact request-body
    /// length supplied by the client.
    pub async fn begin_upload(
        &self,
        account: &PublicAccount,
        content_length: usize,
    ) -> Result<AvatarUploadStart, DirectAvatarUploadError> {
        if content_length == 0 {
            return Err(DirectAvatarUploadError::InvalidContentLength);
        }
        if content_length > self.max_bytes {
            return Err(DirectAvatarUploadError::TooLarge);
        }
        if account
            .profile
            .avatar_url
            .as_deref()
            .map(avatar_url_version)
            .transpose()
            .is_err()
        {
            return Err(DirectAvatarUploadError::InvalidCurrentReference);
        }
        let upload_id = Uuid::now_v7().to_string();
        let expires_at = chrono::Utc::now()
            + chrono::Duration::seconds(
                i64::try_from(self.upload_ttl_seconds)
                    .map_err(|_| DirectAvatarUploadError::Expired)?,
            );
        let authorization = AvatarUploadAuthorization {
            staging_object_id: upload_id.clone(),
            upload_id: upload_id.clone(),
            tenant_id: account.tenant().tenant_id,
            user_id: account.user_id(),
            expected_avatar_url: account.profile.avatar_url.clone(),
            expires_at,
        };
        let target = self
            .storage
            .authorize_upload(
                &authorization.staging_object_id,
                content_length,
                authorization.expires_at,
            )
            .await
            .map_err(DirectAvatarUploadError::Storage)?;
        self.state
            .create(&authorization, self.upload_ttl_seconds)
            .await
            .map_err(DirectAvatarUploadError::State)?;
        Ok(AvatarUploadStart {
            upload_id,
            expires_at,
            target,
        })
    }

    pub async fn complete_upload(
        &self,
        account: &PublicAccount,
        upload_id: &str,
    ) -> Result<AccountOverview, DirectAvatarUploadError> {
        let lease_until = chrono::Utc::now()
            + chrono::Duration::seconds(
                i64::try_from(self.claim_lease_seconds)
                    .map_err(|_| DirectAvatarUploadError::Expired)?,
            );
        let claim = self
            .state
            .claim(account.user_id(), upload_id, lease_until)
            .await
            .map_err(DirectAvatarUploadError::State)?;
        let (authorization, ownership_token, staged_version, candidate_id, staged_snapshot) =
            match claim {
                AvatarUploadClaim::Pending {
                    authorization,
                    ownership_token,
                } => {
                    if authorization.tenant_id != account.tenant().tenant_id
                        || authorization.user_id != account.user_id()
                    {
                        let _ = self
                            .state
                            .release(account.user_id(), upload_id, &ownership_token)
                            .await;
                        return Err(DirectAvatarUploadError::Missing);
                    }
                    if authorization.expires_at <= chrono::Utc::now() {
                        let _ = self
                            .state
                            .release(account.user_id(), upload_id, &ownership_token)
                            .await;
                        return Err(DirectAvatarUploadError::Expired);
                    }
                    let staged = match self
                        .storage
                        .read_staged(&authorization.staging_object_id, self.max_bytes)
                        .await
                    {
                        Ok(staged) => staged,
                        Err(error) => {
                            let _ = self
                                .state
                                .release(account.user_id(), upload_id, &ownership_token)
                                .await;
                            return Err(DirectAvatarUploadError::Storage(error));
                        }
                    };
                    let content_type = match AvatarContentType::detect(&staged.bytes) {
                        Some(content_type) => content_type,
                        None => {
                            let _ = self
                                .state
                                .release(account.user_id(), upload_id, &ownership_token)
                                .await;
                            return Err(DirectAvatarUploadError::UnsupportedContent);
                        }
                    };
                    let final_object_id = final_object_id(&authorization.upload_id, &staged.bytes);
                    let recorded = self
                        .state
                        .record_candidate(
                            account.user_id(),
                            upload_id,
                            &ownership_token,
                            &staged.version,
                            &final_object_id,
                        )
                        .await
                        .map_err(DirectAvatarUploadError::State)?;
                    if !recorded {
                        return Err(DirectAvatarUploadError::ConcurrentChange);
                    }
                    (
                        authorization,
                        ownership_token,
                        staged.version,
                        final_object_id,
                        Some((staged.bytes, content_type)),
                    )
                }
                AvatarUploadClaim::Publishing {
                    authorization,
                    ownership_token,
                    staged_version,
                    final_object_id,
                } => (
                    authorization,
                    ownership_token,
                    staged_version,
                    final_object_id,
                    None,
                ),
                AvatarUploadClaim::Completed { final_object_id } => {
                    return if account.profile.avatar_url.as_deref()
                        == Some(&avatar_url(&final_object_id))
                    {
                        self.overview(account.clone())
                            .await
                            .map_err(DirectAvatarUploadError::Overview)
                    } else {
                        Err(DirectAvatarUploadError::ConcurrentChange)
                    };
                }
                AvatarUploadClaim::Busy => return Err(DirectAvatarUploadError::Busy),
                AvatarUploadClaim::Missing => return Err(DirectAvatarUploadError::Missing),
            };

        if authorization.tenant_id != account.tenant().tenant_id
            || authorization.user_id != account.user_id()
            || authorization.expires_at <= chrono::Utc::now()
        {
            return Err(DirectAvatarUploadError::Expired);
        }
        if account.profile.avatar_url.as_deref() == Some(&avatar_url(&candidate_id)) {
            let completed = self
                .state
                .complete(
                    account.user_id(),
                    upload_id,
                    &ownership_token,
                    &candidate_id,
                )
                .await
                .map_err(DirectAvatarUploadError::State)?;
            if !completed {
                return Err(DirectAvatarUploadError::ConcurrentChange);
            }
            let _ = self
                .storage
                .delete_staging(&authorization.staging_object_id)
                .await;
            return self
                .overview(account.clone())
                .await
                .map_err(DirectAvatarUploadError::Overview);
        }

        let content_type = match staged_snapshot {
            Some((bytes, content_type)) => {
                if final_object_id(&authorization.upload_id, &bytes) != candidate_id {
                    return Err(DirectAvatarUploadError::ConcurrentChange);
                }
                content_type
            }
            None => {
                let staged = self
                    .storage
                    .read_staged(&authorization.staging_object_id, self.max_bytes)
                    .await
                    .map_err(DirectAvatarUploadError::Storage)?;
                if staged.version != staged_version
                    || final_object_id(&authorization.upload_id, &staged.bytes) != candidate_id
                {
                    return Err(DirectAvatarUploadError::ConcurrentChange);
                }
                AvatarContentType::detect(&staged.bytes)
                    .ok_or(DirectAvatarUploadError::UnsupportedContent)?
            }
        };
        self.storage
            .publish_staged(
                &authorization.staging_object_id,
                &staged_version,
                &candidate_id,
                content_type,
            )
            .await
            .map_err(DirectAvatarUploadError::Storage)?;
        let updated = self
            .avatars
            .compare_and_set_avatar(
                authorization.tenant_id,
                authorization.user_id,
                authorization.expected_avatar_url.as_deref(),
                Some(avatar_url(&candidate_id)),
            )
            .await;
        let updated = match updated {
            Ok(Some(updated)) => updated,
            Ok(None) => return Err(DirectAvatarUploadError::ConcurrentChange),
            Err(error) => return Err(DirectAvatarUploadError::Repository(error)),
        };
        let completed = self
            .state
            .complete(
                account.user_id(),
                upload_id,
                &ownership_token,
                &candidate_id,
            )
            .await
            .map_err(DirectAvatarUploadError::State)?;
        if !completed {
            return Err(DirectAvatarUploadError::ConcurrentChange);
        }
        let _ = self
            .storage
            .delete_staging(&authorization.staging_object_id)
            .await;
        self.overview(updated)
            .await
            .map_err(DirectAvatarUploadError::Overview)
    }

    pub async fn read(&self, account: &PublicAccount) -> Result<AvatarObject, ReadAvatarError> {
        let avatar_url = account
            .profile
            .avatar_url
            .as_deref()
            .ok_or(ReadAvatarError::NotUploaded)?;
        let final_object_id =
            avatar_url_version(avatar_url).map_err(|()| ReadAvatarError::InvalidReference)?;
        self.storage
            .read_final(final_object_id)
            .await
            .map_err(ReadAvatarError::Storage)
    }

    pub async fn delete(
        &self,
        account: &PublicAccount,
    ) -> Result<AccountOverview, DeleteAvatarError> {
        let expected_url = account.profile.avatar_url.as_deref();
        let final_object_id = expected_url
            .map(avatar_url_version)
            .transpose()
            .map_err(|()| DeleteAvatarError::InvalidCurrentReference)?;
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
            Ok(None) => return Err(DeleteAvatarError::ConcurrentChange),
            Err(error) => return Err(DeleteAvatarError::Repository(error)),
        };
        if let Some(final_object_id) = final_object_id {
            let _ = self.storage.delete_final(final_object_id).await;
        }
        self.overview(updated)
            .await
            .map_err(DeleteAvatarError::Overview)
    }

    async fn overview(&self, account: PublicAccount) -> Result<AccountOverview, RepositoryError> {
        let authorized_application_count = self
            .grants
            .authorized_client_count(account.tenant().tenant_id, account.id())
            .await?;
        Ok(AccountOverview {
            account,
            authorized_application_count,
        })
    }
}

#[derive(Clone)]
pub struct AvatarService<S> {
    avatars: std::sync::Arc<dyn AvatarRepositoryPort>,
    grants: std::sync::Arc<dyn GrantSummaryRepositoryPort>,
    storage: S,
    max_bytes: usize,
}

impl<S> AvatarService<S>
where
    S: AvatarStoragePort,
{
    pub fn new<R, G>(avatars: R, grants: G, storage: S, max_bytes: usize) -> Self
    where
        R: AvatarRepositoryPort + 'static,
        G: GrantSummaryRepositoryPort + 'static,
    {
        Self {
            avatars: std::sync::Arc::new(avatars),
            grants: std::sync::Arc::new(grants),
            storage,
            max_bytes,
        }
    }

    pub fn from_ports(
        avatars: std::sync::Arc<dyn AvatarRepositoryPort>,
        grants: std::sync::Arc<dyn GrantSummaryRepositoryPort>,
        storage: S,
        max_bytes: usize,
    ) -> Self {
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
        let authorized_application_count = self
            .grants
            .authorized_client_count(account.tenant().tenant_id, account.id())
            .await?;
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
#[path = "../tests/unit/avatar.rs"]
mod tests;
