#![forbid(unsafe_code)]

mod access_request;
mod admin;
mod audit;
pub mod authentication;
mod avatar;
pub mod email;
pub mod federation;
pub mod mfa;
mod mfa_service;
mod model;
pub mod passkey;
pub mod ports;
pub mod profile;
pub mod registration;
pub mod scim;
pub mod session;
pub mod tenancy;

pub use access_request::{AccessRequest, AccessRequestPage, AccessRequestStatus, NewAccessRequest};
pub use admin::{
    AdminPolicyError, AdminUserUpdateOutcome, ResolvedAdminUserUpdate, authorize_admin_update,
};
pub use audit::{
    IdentitySecurityEvent, IdentitySecurityEventType, IdentitySecurityOutcome,
    IdentitySecurityReason,
};
pub use authentication::{
    AuthenticatePasswordError, AuthenticatePasswordInput, AuthenticationService,
    AuthenticationServiceConfig, LoginSuccess, RememberedMfaProof,
};
pub use avatar::{
    AvatarContentType, AvatarObject, AvatarService, DeleteAvatarError, ReadAvatarError,
    UploadAvatarError,
};
pub use federation::{
    FederationAuditEvent, FederationError, FederationService, FederationServiceConfig,
    OidcFederationStart, OidcFederationState, SocialFederationStart, SocialFederationState,
    VerifiedExternalIdentity,
};
pub use mfa_service::{
    MfaService, MfaServiceError, MfaServiceErrorKind, PreparedTotpConfirmation,
    TotpConfirmationOutcome, TotpEnrollmentStart,
};
pub use model::{
    AccountIdentity, AuthMethod, AuthenticationContext, AuthenticationIdentity, IdentityModelError,
    LoginIdentity, PasswordHash, PostalAddress, Principal, PublicAccount, SubjectClaims,
    UserProfile, UserRole,
};
pub use passkey::{
    PasskeyAuditEvent, PasskeyError, PasskeyLoginBegin, PasskeyRegistrationBegin, PasskeyService,
    PasskeyServiceConfig, StoredPasskeyAuthentication, StoredPasskeyRegistration,
};
pub use profile::{
    AccessRequestListError, AccessRequestWithDelivery, AccountOverview, AccountProfileService,
    AccountProfileView, AuthorizedApplicationView, AuthorizedApplicationsView, AvailableDelivery,
    ClientAccessService, DeliveryReadError, FederationLinksService, NewAccessRequestInput,
    PendingMfaProfileView, ProfilePatch, ProfileValidationError, UpdateProfileError,
    access_delivery_token,
};
pub use registration::{
    RegisterLocalAccountError, RegisterLocalAccountInput, RegistrationService,
    RegistrationServiceConfig, SendVerificationCodeError, SendVerificationCodeOutcome,
};
pub use session::{
    CurrentSession, SessionId, SessionResolution, SessionRotation, SessionRotationOutcome,
    SessionService, SessionSnapshot, SessionVersion,
};
pub use tenancy::{OrganizationId, RealmId, TenantContext, TenantId, UserId};
