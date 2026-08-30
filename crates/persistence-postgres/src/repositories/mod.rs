mod access_requests;
mod admin_provision;
mod audit;
mod audit_ledger;
mod authorization;
mod authorization_flow;
pub(crate) mod clients;
mod controller_registry;
mod federation;
mod grants;
mod mfa;
mod mtls_trust;
mod openid4vc;
mod passkeys;
mod recovery_root;
mod runtime_modules;
mod scim;
mod scim_events;
mod tenancy;
mod tenant_resources;
mod token_issuance;
mod tokens;
mod users;
pub use access_requests::AccessRequestRepository;
pub use admin_provision::{
    AdminProvisionError, AdminProvisionReceipt, AdminProvisionRepository, AdminProvisionRequest,
};
pub use audit::AuditRepository;
pub use audit_ledger::{
    AuditLedgerRepository, FreshSecurityAuditReceipt, MAX_SECURITY_AUDIT_PAYLOAD_BYTES,
    SecurityAuditAnchorFreshness, SecurityAuditAnchorHealth, SecurityAuditEvent,
    SecurityAuditOutboxDelivery, SecurityAuditReceipt, append_fresh_security_audit_on_connection,
};
pub use authorization::AuthorizationRepository;
pub use authorization_flow::AuthorizationFlowRepository;
pub use clients::{
    OAuthClientRepository, active_public_client_id_on_connection, deactivate_client_on_connection,
    insert_client_on_connection,
};
pub use controller_registry::{
    AdmittedController, CONTROLLER_KEY_TTL_SECONDS, CommitWithApprovalError,
    ControllerIdentityAction, ControllerRegistryError, ControllerRegistryRepository,
    ControllerSlotStatus, ControllerSlotSummary, DEPLOYMENT_IDENTITY_LOCK_SEED,
    IDENTITY_APPROVAL_TTL_SECONDS, IdentityApprovalError, IssuedIdentityApproval,
    MAX_ACTIVE_CONTROLLER_SLOTS, NewControllerSlot, RotateControllerKey, StoredControllerSlot,
};
pub use federation::FederationRepository;
pub use grants::{GrantAuthorization, GrantRepository};
pub use mfa::MfaRepository;
pub use mtls_trust::{
    MtlsTrustAnchorRepository, OperatorManagedTrustAnchor,
    insert_operator_managed_trust_anchor_on_connection,
    revoke_operator_managed_trust_anchor_on_connection,
};
pub use openid4vc::{
    IssuedOpenid4vpVerificationEvidence, ManagedCredentialDataset, ManagedCredentialDatasetWrite,
    NewOpenid4vpVerificationAttachment, NewOpenid4vpVerificationEvidence,
    Openid4vciDatasetRepository, Openid4vciRepository, Openid4vpRepository,
    Openid4vpVerificationAttachmentState, PreparedOpenid4vpVerificationEvidence,
    StoredOpenid4vpVerificationAttachment, StoredOpenid4vpVerificationEvidence,
    delete_operator_managed_dataset_on_connection, protect_dataset_claims,
    unprotect_dataset_claims, upsert_operator_managed_dataset_on_connection,
};
pub use passkeys::PasskeyRepository;
pub use recovery_root::{
    AdmittedControllerSummary, IssuedRecoveryChallenge, MAX_RECOVERY_CHALLENGE_ATTEMPTS,
    NewRecoveryChallenge, NewRecoveryRoot, RECOVERY_CHALLENGE_TTL_SECONDS, RecoveredSlotCommit,
    RecoveryRootError, RecoveryRootRepository, RecoveryRootSummary, RecoveryRotationError,
    RecoverySubmission, StoredRecoveryRoot,
};
pub use runtime_modules::{RuntimeModuleEventPage, RuntimeModuleRepository};
pub use scim::ScimRepository;
pub use scim_events::ScimEventRepository;
pub use tenancy::ActiveTenantBoundaryRepository;
pub use tenant_resources::{
    NewStoredOpenid4vcTrustPolicy, NewTenantResourceBinding, Openid4vcTrustPolicyClientBind,
    Openid4vcTrustPolicyForClient, Openid4vcTrustPolicyRevoke, Openid4vcTrustPolicyWrite,
    StoredOpenid4vcTrustPolicy, TenantResourceBinding, TenantResourceBindingDeactivate,
    TenantResourceRepository, TenantResourceState, TenantResourceStateCas,
};
pub use token_issuance::TokenIssuanceRepository;
pub use tokens::{RecoveryInvalidation, TokenRepository};
pub use users::{
    UserInsert, UserRepository, disable_user_on_connection, insert_user_on_connection,
};
