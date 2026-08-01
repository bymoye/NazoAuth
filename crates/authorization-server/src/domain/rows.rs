//! Diesel query rows for auth/runtime tables pending Domain Task 5 extraction.
pub(crate) type ClientRow = nazo_auth::OAuthClient;

pub(crate) type TokenRow = nazo_auth::RefreshToken;
