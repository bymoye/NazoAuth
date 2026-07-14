/// How an administrator wants a runtime module's enabled state to be resolved.
#[derive(
    Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum DesiredMode {
    Inherit,
    Enabled,
    Disabled,
}

impl DesiredMode {
    /// Resolves this mode against the configured inherited default.
    #[must_use]
    pub const fn resolve(self, inherited: bool) -> bool {
        match self {
            Self::Inherit => inherited,
            Self::Enabled => true,
            Self::Disabled => false,
        }
    }
}

/// The actual lifecycle state of a runtime module on one instance.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ModuleState {
    Disabled,
    Starting,
    Enabled,
    Draining,
    Failed,
}

impl ModuleState {
    /// Returns whether this actual-state transition is legal.
    #[must_use]
    pub const fn can_transition_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Disabled, Self::Starting)
                | (
                    Self::Starting,
                    Self::Enabled | Self::Failed | Self::Disabled
                )
                | (Self::Enabled, Self::Draining | Self::Failed)
                | (Self::Draining, Self::Disabled | Self::Failed)
                | (Self::Failed, Self::Starting | Self::Disabled)
        )
    }
}

/// Closed identity catalog for all runtime-controllable modules.
#[derive(
    Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum ModuleId {
    DeviceAuthorization,
    TokenExchange,
    JwtBearerGrant,
    Ciba,
    DynamicClientRegistration,
    RequestObjects,
    Jarm,
    AuthorizationDetails,
    HttpMessageSignatures,
    Scim,
    NativeSso,
    FrontchannelLogout,
    SessionManagement,
}

impl ModuleId {
    pub const ALL: [Self; 13] = [
        Self::DeviceAuthorization,
        Self::TokenExchange,
        Self::JwtBearerGrant,
        Self::Ciba,
        Self::DynamicClientRegistration,
        Self::RequestObjects,
        Self::Jarm,
        Self::AuthorizationDetails,
        Self::HttpMessageSignatures,
        Self::Scim,
        Self::NativeSso,
        Self::FrontchannelLogout,
        Self::SessionManagement,
    ];
}

/// Closed audit-event catalog for desired and actual state changes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModuleEventType {
    DesiredStateChanged,
    TransitionStarted,
    TransitionCompleted,
    TransitionFailed,
    DrainStarted,
    DrainCompleted,
    StaleTransitionDiscarded,
}

impl ModuleEventType {
    pub const ALL: [Self; 7] = [
        Self::DesiredStateChanged,
        Self::TransitionStarted,
        Self::TransitionCompleted,
        Self::TransitionFailed,
        Self::DrainStarted,
        Self::DrainCompleted,
        Self::StaleTransitionDiscarded,
    ];
}
