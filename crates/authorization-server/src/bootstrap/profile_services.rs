//! Concrete identity application service bindings assembled by the server composition root.

pub(crate) type AccountProfileService = nazo_identity::AccountProfileService;

pub(crate) type AvatarProfileService =
    nazo_identity::AvatarService<crate::adapters::avatar_files::LocalAvatarStorage>;

pub(crate) type ClientAccessProfileService =
    nazo_identity::ClientAccessService<nazo_valkey::DeliveryStore>;

pub(crate) type FederationProfileService = nazo_identity::FederationLinksService;

pub(crate) type MtlsTrustAnchorService = dyn nazo_identity::ports::MtlsTrustAnchorStore;
