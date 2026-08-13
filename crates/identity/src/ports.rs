//! Public persistence and capability contracts for the identity domain.
//!
//! The module is intentionally a facade: each child module owns one change
//! reason, while this surface keeps the historical identity::ports API stable
//! for adapters and callers.

mod account;
mod authentication;
mod authorization;
mod avatar;
mod common;
mod federation;
mod mfa;
mod passkey;
mod registration;
mod scim;
mod session;

pub use account::*;
pub use authentication::*;
pub use authorization::*;
pub use avatar::*;
pub use common::*;
pub use federation::*;
pub use mfa::*;
pub use passkey::*;
pub use registration::*;
pub use scim::*;
pub use session::*;
