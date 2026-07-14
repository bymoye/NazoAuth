#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecurityProfile {
    Baseline,
    Fapi2Security,
    Fapi2MessageSigning,
}

impl SecurityProfile {
    #[must_use]
    pub const fn requires_fapi2_security(self) -> bool {
        matches!(self, Self::Fapi2Security | Self::Fapi2MessageSigning)
    }
}
