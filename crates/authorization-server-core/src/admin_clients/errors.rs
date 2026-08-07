use super::ports::AdminClientPortError;

/// Errors returned by the administrative client use cases.
#[derive(Debug)]
pub enum AdminClientError {
    InvalidRequest(String),
    NotFound,
    Repository(AdminClientPortError),
    Lookup(AdminClientPortError),
    Write(AdminClientPortError),
    Consistency(String),
}

impl std::fmt::Display for AdminClientError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidRequest(message) | Self::Consistency(message) => {
                formatter.write_str(message)
            }
            Self::NotFound => formatter.write_str("admin client not found"),
            Self::Repository(error) | Self::Lookup(error) | Self::Write(error) => {
                error.fmt(formatter)
            }
        }
    }
}

impl std::error::Error for AdminClientError {}
