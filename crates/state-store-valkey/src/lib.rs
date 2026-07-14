//! Focused Valkey-backed storage mechanisms for NazoAuth.

mod authentication;
mod authorization;
mod authorization_state;
mod ciba;
mod command;
mod connection;
mod delivery;
mod device;
mod error;
mod keys;
mod rate_limit;
mod replay;
mod session;
#[doc(hidden)]
pub mod test_support;
mod token_issuance;
mod token_state;

pub use authentication::AuthenticationStore;
pub use authorization::{AuthorizationCodeBegin, AuthorizationStore, AuthorizationTransition};
pub use authorization_state::AuthorizationStateAdapter;
pub use ciba::{AtomicResult, CibaStore, StoredCibaRequest};
pub use connection::ValkeyConnection;
pub use delivery::{DeliveryConsume, DeliveryStore, StoredDelivery};
pub use device::{DeviceCreateResult, DeviceStore, StoredDeviceState};
pub use error::{Error, ErrorKind};

pub(crate) fn identity_repository_error(error: Error) -> nazo_identity::ports::RepositoryError {
    match error.kind() {
        ErrorKind::Timeout | ErrorKind::Unavailable => {
            nazo_identity::ports::RepositoryError::Unavailable
        }
        ErrorKind::CorruptData => {
            nazo_identity::ports::RepositoryError::Consistency(error.to_string())
        }
        ErrorKind::Protocol | ErrorKind::UnexpectedResult => {
            nazo_identity::ports::RepositoryError::Unexpected(error.to_string())
        }
    }
}
pub use rate_limit::{LoginFailureDimension, RateDimension, RateLimitStore};
pub use replay::ReplayStore;
pub use session::{SessionRotationResult, SessionStore, StoredSession};
pub use token_issuance::TokenIssuanceStateAdapter;
pub use token_state::TokenStateStore;
