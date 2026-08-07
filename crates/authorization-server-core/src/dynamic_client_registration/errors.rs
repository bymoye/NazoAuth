//! Protocol-facing errors produced while preparing or parsing registrations.

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DynamicRegistrationError {
    pub error: &'static str,
    pub description: String,
}

impl DynamicRegistrationError {
    #[must_use]
    pub fn new(error: &'static str, description: impl Into<String>) -> Self {
        Self {
            error,
            description: description.into(),
        }
    }

    #[must_use]
    pub fn invalid_client_metadata(description: impl Into<String>) -> Self {
        Self::new("invalid_client_metadata", description)
    }
}
