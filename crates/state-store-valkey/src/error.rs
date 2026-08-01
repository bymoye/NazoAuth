#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorKind {
    Timeout,
    Unavailable,
    Protocol,
    CorruptData,
    UnexpectedResult,
}

#[derive(Debug, thiserror::Error)]
#[error("Valkey {kind:?}: {message}")]
pub struct Error {
    kind: ErrorKind,
    message: String,
    #[source]
    source: Option<fred::error::Error>,
}

impl Error {
    pub fn kind(&self) -> ErrorKind {
        self.kind
    }

    pub(crate) fn unexpected(message: impl Into<String>) -> Self {
        Self {
            kind: ErrorKind::UnexpectedResult,
            message: message.into(),
            source: None,
        }
    }

    pub(crate) fn protocol(message: impl Into<String>) -> Self {
        Self {
            kind: ErrorKind::Protocol,
            message: message.into(),
            source: None,
        }
    }

    pub(crate) fn corrupt_data(message: impl Into<String>) -> Self {
        Self {
            kind: ErrorKind::CorruptData,
            message: message.into(),
            source: None,
        }
    }

    pub(crate) fn from_fred(error: fred::error::Error) -> Self {
        use fred::error::ErrorKind as FredErrorKind;

        let kind = match error.kind() {
            FredErrorKind::Timeout | FredErrorKind::Canceled => ErrorKind::Timeout,
            FredErrorKind::Protocol | FredErrorKind::Parse | FredErrorKind::NotFound => {
                ErrorKind::Protocol
            }
            FredErrorKind::Auth
            | FredErrorKind::IO
            | FredErrorKind::Routing
            | FredErrorKind::Cluster
            | FredErrorKind::Sentinel
            | FredErrorKind::Backpressure => ErrorKind::Unavailable,
            _ => ErrorKind::Protocol,
        };
        Self {
            kind,
            message: error.to_string(),
            source: Some(error),
        }
    }
}

#[cfg(test)]
#[path = "../tests/unit/error.rs"]
mod tests;
