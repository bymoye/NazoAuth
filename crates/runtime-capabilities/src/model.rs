/// Explicit administrator-selected runtime-module state.
#[derive(
    Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum DesiredMode {
    Enabled,
    Disabled,
}

impl DesiredMode {
    #[must_use]
    pub const fn is_enabled(self) -> bool {
        matches!(self, Self::Enabled)
    }
}

/// Desired-state spelling retained solely for parsing immutable pre-cutover
/// audit events. It must never appear in current commands or records.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HistoricalDesiredMode {
    Inherit,
    Enabled,
    Disabled,
}

impl From<DesiredMode> for HistoricalDesiredMode {
    fn from(value: DesiredMode) -> Self {
        match value {
            DesiredMode::Enabled => Self::Enabled,
            DesiredMode::Disabled => Self::Disabled,
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
    ScimSecurityEvents,
    NativeSso,
    FrontchannelLogout,
    SessionManagement,
    Openid4vciIssuer,
    Openid4vpVerifier,
}

impl ModuleId {
    pub const ALL: [Self; 16] = [
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
        Self::ScimSecurityEvents,
        Self::NativeSso,
        Self::FrontchannelLogout,
        Self::SessionManagement,
        Self::Openid4vciIssuer,
        Self::Openid4vpVerifier,
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
