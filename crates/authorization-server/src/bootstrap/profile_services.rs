//! Concrete identity application service bindings assembled by the server composition root.

pub(crate) type AccountProfileService = nazo_identity::AccountProfileService;

#[derive(Clone)]
pub(crate) enum AvatarProfileService {
    Local(nazo_identity::AvatarService<crate::adapters::avatar_files::LocalAvatarStorage>),
    Direct(nazo_identity::AvatarDirectUploadService),
}

impl AvatarProfileService {
    pub(crate) const fn max_bytes(&self) -> usize {
        match self {
            Self::Local(service) => service.max_bytes(),
            Self::Direct(service) => service.max_bytes(),
        }
    }

    pub(crate) async fn upload(
        &self,
        account: &nazo_identity::PublicAccount,
        bytes: Vec<u8>,
    ) -> Result<nazo_identity::AccountOverview, nazo_identity::UploadAvatarError> {
        match self {
            Self::Local(service) => service.upload(account, bytes).await,
            Self::Direct(_) => Err(nazo_identity::UploadAvatarError::Storage(
                nazo_identity::ports::AvatarStorageError::Unsupported,
            )),
        }
    }

    pub(crate) async fn begin_direct_upload(
        &self,
        account: &nazo_identity::PublicAccount,
        content_length: usize,
    ) -> Result<nazo_identity::AvatarUploadStart, nazo_identity::DirectAvatarUploadError> {
        match self {
            Self::Local(_) => Err(nazo_identity::DirectAvatarUploadError::Storage(
                nazo_identity::ports::AvatarStorageError::Unsupported,
            )),
            Self::Direct(service) => service.begin_upload(account, content_length).await,
        }
    }

    pub(crate) async fn complete_direct_upload(
        &self,
        account: &nazo_identity::PublicAccount,
        upload_id: &str,
    ) -> Result<nazo_identity::AccountOverview, nazo_identity::DirectAvatarUploadError> {
        match self {
            Self::Local(_) => Err(nazo_identity::DirectAvatarUploadError::Storage(
                nazo_identity::ports::AvatarStorageError::Unsupported,
            )),
            Self::Direct(service) => service.complete_upload(account, upload_id).await,
        }
    }

    pub(crate) async fn read(
        &self,
        account: &nazo_identity::PublicAccount,
    ) -> Result<nazo_identity::AvatarObject, nazo_identity::ReadAvatarError> {
        match self {
            Self::Local(service) => service.read(account).await,
            Self::Direct(service) => service.read(account).await,
        }
    }

    pub(crate) async fn delete(
        &self,
        account: &nazo_identity::PublicAccount,
    ) -> Result<nazo_identity::AccountOverview, nazo_identity::DeleteAvatarError> {
        match self {
            Self::Local(service) => service.delete(account).await,
            Self::Direct(service) => service.delete(account).await,
        }
    }
}

pub(crate) type ClientAccessProfileService =
    nazo_identity::ClientAccessService<std::sync::Arc<dyn nazo_identity::ports::DeliveryStorePort>>;

pub(crate) type FederationProfileService = nazo_identity::FederationLinksService;

pub(crate) type MtlsTrustAnchorService = dyn nazo_identity::ports::MtlsTrustAnchorStore;
