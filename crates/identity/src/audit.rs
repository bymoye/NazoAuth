use std::time::SystemTime;

use crate::{TenantId, UserId};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentitySecurityEventType {
    MfaTotpAttempt,
    MfaBackupCodeAttempt,
    AdminUserUpdate,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentitySecurityOutcome {
    Success,
    Denied,
    InvalidCredential,
    Replay,
    Conflict,
    DependencyFailure,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentitySecurityReason {
    TotpAccepted,
    TotpInvalid,
    TotpReplay,
    BackupCodeAccepted,
    BackupCodeInvalid,
    BackupCodeReplay,
    AdminUpdated,
    TargetNotFound,
    ActorNotAuthorized,
    CrossTenant,
    SelfElevation,
    SelfDemotionOrDisable,
    TargetAtOrAboveActor,
    GrantAtOrAboveActor,
    InvalidRoleLevel,
    DependencyUnavailable,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdentitySecurityEvent {
    pub tenant_id: TenantId,
    pub event_type: IdentitySecurityEventType,
    pub outcome: IdentitySecurityOutcome,
    pub actor_id: Option<UserId>,
    pub target_user_id: Option<UserId>,
    pub reason: IdentitySecurityReason,
    pub occurred_at: SystemTime,
}
