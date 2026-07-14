//! Concrete identity application service bindings assembled by the server composition root.

pub(crate) type AccountProfileService = nazo_identity::AccountProfileService<
    nazo_postgres::UserRepository,
    nazo_postgres::GrantRepository,
    nazo_postgres::OAuthClientRepository,
>;

pub(crate) type AvatarProfileService = nazo_identity::AvatarService<
    nazo_postgres::UserRepository,
    nazo_postgres::GrantRepository,
    crate::adapters::avatar_files::LocalAvatarStorage,
>;

pub(crate) type ClientAccessProfileService = nazo_identity::ClientAccessService<
    nazo_postgres::AccessRequestRepository,
    nazo_valkey::DeliveryStore,
>;

pub(crate) type FederationProfileService =
    nazo_identity::FederationLinksService<nazo_postgres::FederationRepository>;
