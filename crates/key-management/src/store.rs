//! Keyset store façade.
//!
//! The implementation is grouped by its ownership boundary:
//!
//! - [`crate::lifecycle`] owns loading, creation, and signing-key rotation;
//! - [`crate::external`] and [`crate::local`] own registration workflows;
//! - [`crate::request_object_encryption`] owns the dedicated Request Object recipient key; and
//! - [`crate::serialization`] owns the persisted JSON schema and atomic file writes.
//!
//! This module intentionally contains only the crate-facing store surface.  Keeping the names
//! re-exported here preserves the existing `crate::store::*` call sites and unit-test boundary
//! while making ownership explicit in the implementation modules.

pub(crate) use crate::external::register_external_key;
#[cfg(any(test, feature = "test-support"))]
#[allow(unused_imports)]
pub(crate) use crate::lifecycle::{
    all_signing_purposes, create_new_keyset, create_prepublished_local_key_entry,
    maintain_keyset_lifecycle, timestamp,
};
pub(crate) use crate::lifecycle::{load_or_create_keyset, try_load_keyset};
pub(crate) use crate::local::register_local_key;
#[cfg(any(test, feature = "test-support"))]
#[allow(unused_imports)]
pub(crate) use crate::request_object_encryption::{
    REQUEST_OBJECT_ENCRYPTION_KEY_FILE, ensure_request_object_encryption_key,
    load_request_object_decryption_key, request_object_encryption_jwk,
};
pub(crate) use crate::serialization::list_keys;
#[cfg(any(test, feature = "test-support"))]
#[allow(unused_imports)]
pub(crate) use crate::serialization::{
    GeneratedKeyMaterial, der_to_pem, ed25519_pkcs8_private_der, ed25519_seed_from_pkcs8,
    external_public_jwk, generate_key_material, key_entry_algorithm, key_entry_backend,
    key_entry_created_at, key_entry_purposes, key_entry_retire_at, keyset_active_kid, keyset_keys,
    keyset_keys_mut, load_keyset_json, pem_to_der, public_jwk_from_private_der,
    reject_private_jwk_members, validate_keyset_json, write_json_atomic,
    write_private_key_pem_atomic,
};
pub use crate::serialization::{signing_algorithm_from_name, signing_algorithm_name};

#[cfg(test)]
use crate::model::{KeyRecordStatus, KeySettings};
#[cfg(test)]
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
#[cfg(test)]
use chrono::{DateTime, Utc};
#[cfg(test)]
use nazo_auth::SigningPurpose;
#[cfg(test)]
use serde_json::{Value, json};
#[cfg(test)]
use uuid::Uuid;

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
#[path = "../tests/unit/store.rs"]
mod tests;

#[cfg(test)]
#[path = "../tests/unit/store/keyset_store.rs"]
mod keyset_store_tests;
